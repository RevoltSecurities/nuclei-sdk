"""ScanEngine — async Python client for the nuclei-sdk bridge."""

from __future__ import annotations

import asyncio
import uuid
from typing import AsyncIterator, Callable, Dict, List, Optional, Any, Union

from ._bridge import BridgeError, BridgeProcess
from .models import (
    EngineConfig,
    LabeledResult,
    ScanOptions,
    ScanResult,
    TargetRequest,
    TemplateBytesEntry,
)
from .pool import ScanPool


class ScanEngine:
    """High-performance async scan engine backed by a Go subprocess.

    Initializes heavy resources once (templates, interactsh, rate limiter)
    and runs lightweight scans via the shared engine.

    Usage::

        engine = ScanEngine(rate_limit=100, timeout=10, no_interactsh=True)
        await engine.setup()

        async for result in engine.scan(targets=["https://example.com"], tags=["cve"]):
            print(f"[{result.severity}] {result.template_id}")

        await engine.close()

    Async context manager::

        async with ScanEngine(rate_limit=100) as engine:
            results = [r async for r in engine.scan(targets=["https://example.com"])]
    """

    def __init__(self, binary_path: Optional[str] = None, **config):
        self._bridge = BridgeProcess(binary_path)
        self._config = EngineConfig(**{
            k: v for k, v in config.items()
            if hasattr(EngineConfig, k)
        })
        self._is_setup = False

    async def setup(self) -> None:
        """Start the bridge process and initialize the scan engine.

        Performs one-time heavy initialization: protocol state, template
        loading, interactsh client, rate limiter, etc.
        """
        if self._is_setup:
            raise RuntimeError("Engine already set up")

        await self._bridge.start()

        await self._bridge.send_command({
            "cmd": "setup",
            "id": "setup",
            "config": self._config.to_dict(),
        })

        resp = await self._bridge.wait_response("setup", timeout=120)
        if resp.get("type") == "error":
            raise BridgeError(resp.get("error", "setup failed"))

        self._is_setup = True

    async def scan(
        self,
        targets: Optional[List[str]] = None,
        target_file: str = "",
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        protocol_types: str = "",
        template_ids: Optional[List[str]] = None,
        exclude_ids: Optional[List[str]] = None,
        authors: Optional[List[str]] = None,
        template_files: Optional[List[str]] = None,
        template_dirs: Optional[List[str]] = None,
        template_bytes: Optional[List[TemplateBytesEntry]] = None,
        result_severity_filter: Optional[List[str]] = None,
        request_response_targets: Optional[List[TargetRequest]] = None,
    ) -> AsyncIterator[ScanResult]:
        """Run a lightweight scan and yield results asynchronously.

        Args:
            targets: URLs, domains, IPs to scan.
            tags: Filter templates by tags.
            severities: Filter by severity (info, low, medium, high, critical).
            protocol_types: Filter by protocol (http, dns, ssl, network).
            template_bytes: Raw YAML templates as TemplateBytesEntry objects.
            result_severity_filter: Only return results matching these severities.
            request_response_targets: Full HTTP request targets for DAST fuzzing.
                When provided, nuclei preserves the method, headers, and body
                instead of defaulting to GET with no body.

        Yields:
            ScanResult for each finding.
        """
        self._ensure_setup()

        opts = ScanOptions(
            targets=targets or [],
            target_file=target_file,
            tags=tags or [],
            exclude_tags=exclude_tags or [],
            severities=severities or [],
            protocol_types=protocol_types,
            template_ids=template_ids or [],
            exclude_ids=exclude_ids or [],
            authors=authors or [],
            template_files=template_files or [],
            template_dirs=template_dirs or [],
            template_bytes=template_bytes or [],
            result_severity_filter=result_severity_filter or [],
            request_response_targets=request_response_targets or [],
        )

        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        await self._bridge.send_command({
            "cmd": "scan",
            "id": scan_id,
            "options": opts.to_dict(),
        })

        async for resp in self._bridge.iter_responses(scan_id):
            resp_type = resp.get("type", "")
            if resp_type == "result" and resp.get("data"):
                yield ScanResult.from_dict(resp["data"])
            elif resp_type == "error":
                err = resp.get("error", "unknown scan error")
                yield ScanResult(error=err)

    async def scan_collect(self, **kwargs) -> List[ScanResult]:
        """Run a scan and return all results as a list."""
        return [r async for r in self.scan(**kwargs)]

    async def scan_pool(
        self,
        workers: int = 10,
        on_result: Optional[Callable] = None,
    ) -> ScanPool:
        """Create a worker pool for continuous dynamic scanning.

        Args:
            workers: Number of concurrent scan workers.
            on_result: Optional async/sync callback invoked for each result.
                       Signature: ``(LabeledResult) -> None`` or ``async (LabeledResult) -> None``.
                       When set, results are dispatched to the callback
                       automatically — no need to iterate ``results()``.

        Returns:
            A ScanPool instance.
        """
        self._ensure_setup()
        pool = ScanPool(self._bridge, workers, on_result=on_result)
        await pool._create()
        return pool

    async def run_parallel(
        self,
        *scans: Dict[str, Any],
    ) -> AsyncIterator[LabeledResult]:
        """Run multiple scans concurrently and yield labeled results.

        Each scan dict must include a ``label`` key and standard scan
        parameters (targets, tags, template_files, etc.).

        Example::

            async for lr in engine.run_parallel(
                {"label": "cves", "targets": ["https://a.com"], "tags": ["cve"]},
                {"label": "misconfig", "targets": ["https://a.com"], "tags": ["misconfig"]},
            ):
                print(f"[{lr.label}] {lr.result.template_id}")

        Args:
            *scans: Dicts with ``label`` + scan keyword arguments.

        Yields:
            LabeledResult for each finding, tagged with its scan label.
        """
        self._ensure_setup()

        queue: asyncio.Queue[Optional[LabeledResult]] = asyncio.Queue()

        async def _run_scan(scan_def: Dict[str, Any]) -> None:
            label = scan_def.pop("label", "unlabeled")
            try:
                async for result in self.scan(**scan_def):
                    await queue.put(LabeledResult(label=label, result=result))
            except Exception as exc:
                await queue.put(
                    LabeledResult(label=label, result=ScanResult(error=str(exc)))
                )

        tasks = [asyncio.create_task(_run_scan(dict(s))) for s in scans]

        finished = 0
        total = len(tasks)

        def _on_task_done(_fut: asyncio.Task) -> None:
            nonlocal finished
            finished += 1
            if finished >= total:
                queue.put_nowait(None)

        for t in tasks:
            t.add_done_callback(_on_task_done)

        while True:
            item = await queue.get()
            if item is None:
                break
            yield item

    async def close(self) -> None:
        """Shut down the engine and bridge process."""
        if not self._bridge.is_alive:
            return
        try:
            await self._bridge.send_command({"cmd": "close", "id": "close"})
            await self._bridge.wait_response("close", timeout=30)
        except (BridgeError, Exception):
            pass
        finally:
            await self._bridge.stop()
            self._is_setup = False

    async def __aenter__(self) -> ScanEngine:
        await self.setup()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _ensure_setup(self) -> None:
        if not self._is_setup:
            raise RuntimeError("Engine not set up — call await setup() first")
