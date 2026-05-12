"""
Async JSON-RPC client with connection pooling, batch calls, and exponential-backoff retry.
All public methods are coroutines; use RPCClient as an async context manager.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

log = logging.getLogger(__name__)


class RPCError(Exception):
    """Raised when the JSON-RPC server returns an error object."""
    def __init__(self, error: Dict[str, Any]) -> None:
        self.code = error.get("code", -1)
        self.message = error.get("message", "unknown rpc error")
        super().__init__(f"RPC error {self.code}: {self.message}")


class RPCClient:
    """
    Async JSON-RPC 2.0 client.

    Usage:
        async with RPCClient(url) as client:
            code = await client.get_code("0x...")
    """

    def __init__(
        self,
        url: str,
        timeout: int = 30,
        max_retries: int = 4,
        max_connections: int = 20,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self._connector: Optional[aiohttp.TCPConnector] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._max_connections = max_connections
        self._id = 0

    async def __aenter__(self) -> "RPCClient":
        self._connector = aiohttp.TCPConnector(
            limit=self._max_connections,
            limit_per_host=self._max_connections,
            keepalive_timeout=60,
        )
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={"Content-Type": "application/json"},
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self._connector and not self._connector.closed:
            await self._connector.close()
        # Brief wait for underlying connections to actually close
        await asyncio.sleep(0.1)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _build_request(self, method: str, params: List[Any]) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._next_id(),
        }

    async def _post(self, payload: Any) -> Any:
        """Post one or more JSON-RPC requests with retry + backoff."""
        assert self._session is not None, "RPCClient must be used as async context manager"
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                async with self._session.post(self.url, json=payload) as resp:
                    resp.raise_for_status()
                    return await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError, aiohttp.ServerConnectionError) as exc:
                last_exc = exc
                wait = 2 ** attempt        # 1s, 2s, 4s, 8s
                log.debug("RPC attempt %d failed (%s), retrying in %ds", attempt + 1, exc, wait)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(wait)
        raise RuntimeError(f"RPC call failed after {self.max_retries} attempts: {last_exc}") from last_exc

    # ------------------------------------------------------------------
    # Single call
    # ------------------------------------------------------------------

    async def call(self, method: str, params: List[Any]) -> Any:
        """Make a single JSON-RPC call; raise RPCError if the server returns an error."""
        payload = self._build_request(method, params)
        data = await self._post(payload)
        if "error" in data and data["error"] is not None:
            raise RPCError(data["error"])
        return data.get("result")

    # ------------------------------------------------------------------
    # Batch call
    # ------------------------------------------------------------------

    async def batch(self, calls: List[Tuple[str, List[Any]]]) -> List[Any]:
        """
        Send multiple JSON-RPC calls in a single HTTP request.
        Returns results in the same order as *calls*.
        Items that errored individually are returned as None (logged as warning).
        """
        if not calls:
            return []
        payload = [self._build_request(m, p) for m, p in calls]
        id_to_index = {req["id"]: i for i, req in enumerate(payload)}
        data = await self._post(payload)
        if not isinstance(data, list):
            # Some nodes return a single object for single-item batches
            data = [data]
        results: List[Any] = [None] * len(calls)
        for item in data:
            idx = id_to_index.get(item.get("id"))
            if idx is None:
                continue
            if "error" in item and item["error"] is not None:
                log.warning("Batch item %d error: %s", idx, item["error"])
                results[idx] = None
            else:
                results[idx] = item.get("result")
        return results

    # ------------------------------------------------------------------
    # Convenience wrappers
    # ------------------------------------------------------------------

    async def get_code(self, address: str, block: str = "latest") -> str:
        """eth_getCode — returns hex bytecode string, e.g. '0x...' or '0x'."""
        result = await self.call("eth_getCode", [address, block])
        return result or "0x"

    async def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        """eth_getStorageAt — returns 32-byte hex string."""
        result = await self.call("eth_getStorageAt", [address, slot, block])
        return result or "0x" + "0" * 64

    async def eth_call(self, to: str, data: str, block: str = "latest") -> Optional[str]:
        """
        eth_call — static call, returns hex result or None on revert.
        Reverts are common when calling implementation() on non-proxies; we swallow them.
        """
        try:
            return await self.call("eth_call", [{"to": to, "data": data}, block])
        except RPCError as exc:
            if "revert" in exc.message.lower() or "execution reverted" in exc.message.lower():
                return None
            raise

    async def get_block_number(self) -> int:
        """eth_blockNumber — returns the current block number as int."""
        result = await self.call("eth_blockNumber", [])
        return int(result, 16)

    async def get_chain_id(self) -> int:
        """eth_chainId — returns chain ID as int."""
        result = await self.call("eth_chainId", [])
        return int(result, 16)

    # ------------------------------------------------------------------
    # Batch helpers for multiple addresses
    # ------------------------------------------------------------------

    async def batch_get_code(
        self, addresses: List[str], block: str = "latest"
    ) -> Dict[str, str]:
        """Fetch bytecode for many addresses in a single batch call."""
        calls = [("eth_getCode", [addr, block]) for addr in addresses]
        results = await self.batch(calls)
        return {
            addr: (res or "0x")
            for addr, res in zip(addresses, results)
        }

    async def batch_get_storage(
        self, address: str, slots: List[str], block: str = "latest"
    ) -> Dict[str, str]:
        """Fetch multiple storage slots for one address in a single batch."""
        calls = [("eth_getStorageAt", [address, slot, block]) for slot in slots]
        results = await self.batch(calls)
        return {
            slot: (res or "0x" + "0" * 64)
            for slot, res in zip(slots, results)
        }
