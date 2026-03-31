"""ScanPool — Async worker pool for continuous dynamic scanning."""

from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import Any, AsyncIterator, Callable, List, Optional

from ._bridge import BridgeError, BridgeProcess
from .models import (
    LabeledResult,
    PoolStats,
    ScanOptions,
    ScanResult,
    TemplateBytesEntry,
)


class ScanPool:
    """Async worker pool for submitting scan jobs dynamically.

    Jobs can be submitted at any time. Results stream through a unified
    async iterator, or are dispatched to an ``on_result`` callback.

    Iterator mode::

        pool = await engine.scan_pool(workers=5)

        await pool.submit("CVE-2024-1234", targets=["https://a.com"],
                          template_bytes=[TemplateBytesEntry("cve", yaml)])

        async for lr in pool.results():
            print(f"[{lr.label}] {lr.result.template_id}")

        await pool.close()

    Callback mode (no manual iteration needed)::

        async def handle(lr):
            print(f"[{lr.label}] {lr.result.severity}")

        pool = await engine.scan_pool(workers=5, on_result=handle)
        await pool.submit("CVE-2024-1234", targets=["https://a.com"], ...)
        await pool.close()
    """

    def __init__(
        self,
        bridge: BridgeProcess,
        workers: int,
        on_result: Optional[Callable] = None,
    ):
        self._bridge = bridge
        self._workers = workers
        self._on_result = on_result
        self._result_queue: asyncio.Queue[Optional[LabeledResult]] = asyncio.Queue()
        self._closed = False
        self._final_stats: Optional[PoolStats] = None

    async def _create(self) -> None:
        """Initialize the pool on the Go side (called by ScanEngine.scan_pool)."""
        self._bridge.set_pool_listener(self._on_pool_result)

        create_id = f"pool-create-{uuid.uuid4().hex[:8]}"
        await self._bridge.send_command({
            "cmd": "pool_create",
            "id": create_id,
            "workers": self._workers,
        })
        resp = await self._bridge.wait_response(create_id, timeout=30)
        if resp.get("type") == "error":
            raise BridgeError(resp.get("error", "pool creation failed"))

    async def submit(
        self,
        label: str,
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
    ) -> None:
        """Submit a labeled scan job to the pool.

        Args:
            label: Identifier for this job (e.g., CVE ID, scan type).
            targets: URLs/domains/IPs to scan.
            result_severity_filter: Only return results matching these severities.
            ... (same scan options as ScanEngine.scan)
        """
        if self._closed:
            raise RuntimeError("Pool is closed")

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
        )

        submit_id = f"pool-submit-{uuid.uuid4().hex[:8]}"
        await self._bridge.send_command({
            "cmd": "pool_submit",
            "id": submit_id,
            "label": label,
            "options": opts.to_dict(),
        })

        resp = await self._bridge.wait_response(submit_id, timeout=30)
        if resp.get("type") == "error":
            raise BridgeError(resp.get("error", "pool submit failed"))

    async def results(self, timeout: float = 600) -> AsyncIterator[LabeledResult]:
        """Iterate over pool results until the pool is closed.

        Blocks waiting for results. Stops when close() is called and
        all pending results have been yielded.

        Args:
            timeout: Max seconds to wait for each result before giving up.
        """
        while True:
            try:
                item = await asyncio.wait_for(
                    self._result_queue.get(), timeout=timeout
                )
            except asyncio.TimeoutError:
                break
            if item is None:  # sentinel from close()
                break
            yield item

    async def stats(self) -> PoolStats:
        """Get pool statistics. Safe to call before or after close()."""
        if self._final_stats is not None:
            return self._final_stats
        return await self._fetch_stats()

    async def _fetch_stats(self) -> PoolStats:
        stats_id = f"pool-stats-{uuid.uuid4().hex[:8]}"
        await self._bridge.send_command({
            "cmd": "pool_stats",
            "id": stats_id,
        })
        resp = await self._bridge.wait_response(stats_id, timeout=10)
        if resp.get("type") == "error":
            raise BridgeError(resp.get("error", "pool stats failed"))
        return PoolStats.from_dict(resp.get("data", {}))

    async def close(self) -> None:
        """Close the pool and wait for all pending jobs to complete."""
        if self._closed:
            return

        # Snapshot stats before Go side destroys the pool
        try:
            self._final_stats = await self._fetch_stats()
        except (BridgeError, Exception):
            self._final_stats = PoolStats()

        self._closed = True

        close_id = f"pool-close-{uuid.uuid4().hex[:8]}"
        await self._bridge.send_command({
            "cmd": "pool_close",
            "id": close_id,
        })
        await self._bridge.wait_response(close_id, timeout=600)

        # Signal the results iterator to stop
        await self._result_queue.put(None)

        # Unregister listener
        self._bridge.set_pool_listener(None)

    async def _on_pool_result(self, resp: dict) -> None:
        """Callback for pool_result responses from the bridge."""
        label = resp.get("label", "")
        data = resp.get("data", {})
        lr = LabeledResult.from_dict(label, data)

        # Dispatch to user callback if set
        if self._on_result is not None:
            try:
                result = self._on_result(lr)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                pass  # don't let callback errors kill the pool

        # Always enqueue for results() iterator too
        await self._result_queue.put(lr)
