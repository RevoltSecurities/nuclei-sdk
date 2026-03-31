"""Async subprocess bridge to the nuclei-sdk-bridge Go binary."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, AsyncIterator, Callable, Dict, Optional


class BridgeError(Exception):
    """Raised when the bridge process encounters an error."""


class BridgeProcess:
    """Manages the long-lived Go bridge subprocess with async JSON-line I/O.

    The bridge binary is spawned once. Commands are sent as JSON lines to stdin,
    and responses are read from stdout by a background asyncio task. Responses
    are routed to waiting callers by request ID, or to registered listeners.
    """

    def __init__(self, binary_path: Optional[str] = None):
        self._binary = binary_path or self._find_binary()
        self._process: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._write_lock = asyncio.Lock()
        self._alive = False

        # Response routing
        self._waiters: Dict[str, asyncio.Future] = {}
        self._streams: Dict[str, asyncio.Queue] = {}
        self._waiter_lock = asyncio.Lock()
        self._pool_listener: Optional[Callable[[dict], Any]] = None

    async def start(self) -> None:
        """Start the bridge subprocess."""
        if self._alive:
            return

        self._process = await asyncio.create_subprocess_exec(
            self._binary,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,  # 10MB line buffer (scan results can be large)
        )
        self._alive = True
        self._reader_task = asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        """Stop the bridge subprocess."""
        if not self._alive:
            return
        self._alive = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._process and self._process.stdin:
            try:
                self._process.stdin.close()
                await self._process.stdin.wait_closed()
            except (OSError, AttributeError):
                pass
        if self._process:
            try:
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            self._process = None

    async def send_command(self, cmd: dict) -> None:
        """Send a JSON command to the bridge."""
        if not self._alive or not self._process or not self._process.stdin:
            raise BridgeError("bridge process is not running")

        line = json.dumps(cmd, separators=(",", ":")) + "\n"
        async with self._write_lock:
            try:
                self._process.stdin.write(line.encode("utf-8"))
                await self._process.stdin.drain()
            except (OSError, BrokenPipeError, ConnectionResetError) as e:
                self._alive = False
                raise BridgeError(f"bridge write failed: {e}") from e

    async def wait_response(self, req_id: str, timeout: Optional[float] = None) -> dict:
        """Wait for a single response with the given ID."""
        fut = await self._get_or_create_waiter(req_id)
        try:
            return await asyncio.wait_for(fut, timeout=timeout or 300)
        except asyncio.TimeoutError:
            raise BridgeError(f"timeout waiting for response id={req_id}")
        finally:
            await self._remove_waiter(req_id)

    async def iter_responses(self, req_id: str, timeout: float = 600) -> AsyncIterator[dict]:
        """Iterate over streaming responses until scan_complete/error."""
        q = await self._get_or_create_stream(req_id)
        try:
            while True:
                try:
                    resp = await asyncio.wait_for(q.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    break

                resp_type = resp.get("type", "")
                if resp_type in ("scan_complete", "error", "closed", "pool_closed"):
                    if resp_type == "error":
                        yield resp
                    break
                yield resp
        finally:
            await self._remove_stream(req_id)

    def set_pool_listener(self, listener: Optional[Callable[[dict], Any]]) -> None:
        """Set a callback for pool_result responses."""
        self._pool_listener = listener

    @property
    def is_alive(self) -> bool:
        return (
            self._alive
            and self._process is not None
            and self._process.returncode is None
        )

    # --- Internal ---

    async def _read_loop(self) -> None:
        """Background task: reads JSON lines from stdout and routes them."""
        assert self._process and self._process.stdout
        try:
            while self._alive:
                raw_line = await self._process.stdout.readline()
                if not raw_line:
                    break
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    resp = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await self._route_response(resp)
        except asyncio.CancelledError:
            return
        finally:
            self._alive = False
            async with self._waiter_lock:
                err_resp = {"type": "error", "error": "bridge process exited"}
                for fut in self._waiters.values():
                    if not fut.done():
                        fut.set_result(err_resp)
                for q in self._streams.values():
                    await q.put(err_resp)

    async def _route_response(self, resp: dict) -> None:
        """Route a response to the appropriate waiter or listener."""
        resp_type = resp.get("type", "")

        # Pool results go to the pool listener
        if resp_type == "pool_result" and self._pool_listener:
            result = self._pool_listener(resp)
            if asyncio.iscoroutine(result):
                await result
            return

        # Route by ID
        resp_id = resp.get("id", "")
        if resp_id:
            async with self._waiter_lock:
                # Check futures first (single-response waiters)
                if resp_id in self._waiters:
                    fut = self._waiters[resp_id]
                    if not fut.done():
                        fut.set_result(resp)
                    return
                # Check streams (multi-response iterators)
                if resp_id in self._streams:
                    await self._streams[resp_id].put(resp)
                    return

        # Unrouted responses with known types go to empty-id waiter
        async with self._waiter_lock:
            if "" in self._waiters and not self._waiters[""].done():
                self._waiters[""].set_result(resp)
            elif "" in self._streams:
                await self._streams[""].put(resp)

    async def _get_or_create_waiter(self, req_id: str) -> asyncio.Future:
        """Get or create a Future for a single-response wait."""
        async with self._waiter_lock:
            if req_id not in self._waiters:
                loop = asyncio.get_running_loop()
                self._waiters[req_id] = loop.create_future()
            return self._waiters[req_id]

    async def _get_or_create_stream(self, req_id: str) -> asyncio.Queue:
        """Get or create a Queue for multi-response streaming."""
        async with self._waiter_lock:
            if req_id not in self._streams:
                self._streams[req_id] = asyncio.Queue()
            return self._streams[req_id]

    async def _remove_waiter(self, req_id: str) -> None:
        async with self._waiter_lock:
            self._waiters.pop(req_id, None)

    async def _remove_stream(self, req_id: str) -> None:
        async with self._waiter_lock:
            self._streams.pop(req_id, None)

    @staticmethod
    def _find_binary() -> str:
        """Find the nuclei-sdk-bridge binary, auto-installing if needed."""
        from ._installer import ensure_bridge
        return ensure_bridge()
