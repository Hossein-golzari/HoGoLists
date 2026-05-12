"""
Unit tests for rpc.py

We mock the aiohttp session so no real network calls are made.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from ..rpc import RPCClient, RPCError


class FakeResponse:
    """Minimal aiohttp response mock."""

    def __init__(self, data: dict | list, status: int = 200) -> None:
        self._data = data
        self.status = status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise Exception(f"HTTP {self.status}")

    async def json(self, content_type=None) -> dict | list:
        return self._data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


def _make_client() -> RPCClient:
    client = RPCClient("http://localhost:8545", timeout=5, max_retries=1)
    # Inject a mock session
    mock_session = MagicMock()
    mock_session.closed = False
    mock_session.close = AsyncMock()
    client._session = mock_session
    return client


def _set_response(client: RPCClient, data: dict | list) -> None:
    client._session.post.return_value = FakeResponse(data)


class TestRPCClient(unittest.IsolatedAsyncioTestCase):

    async def test_get_code_returns_hex(self):
        client = _make_client()
        _set_response(
            client,
            {"jsonrpc": "2.0", "id": 1, "result": "0xdeadbeef"},
        )
        result = await client.get_code("0xabc", "latest")
        self.assertEqual(result, "0xdeadbeef")

    async def test_get_code_empty_returns_0x(self):
        client = _make_client()
        _set_response(client, {"jsonrpc": "2.0", "id": 1, "result": "0x"})
        result = await client.get_code("0xabc", "latest")
        self.assertEqual(result, "0x")

    async def test_rpc_error_raises(self):
        client = _make_client()
        _set_response(
            client,
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution reverted"}},
        )
        with self.assertRaises(RPCError) as ctx:
            await client.call("eth_call", [{}])
        self.assertEqual(ctx.exception.code, -32000)

    async def test_eth_call_revert_returns_none(self):
        client = _make_client()
        _set_response(
            client,
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "execution reverted"}},
        )
        result = await client.eth_call("0xabc", "0x5c60da1b")
        self.assertIsNone(result)

    async def test_get_block_number(self):
        client = _make_client()
        _set_response(client, {"jsonrpc": "2.0", "id": 1, "result": "0x1312d00"})
        result = await client.get_block_number()
        self.assertEqual(result, 20_000_000)

    async def test_get_chain_id(self):
        client = _make_client()
        _set_response(client, {"jsonrpc": "2.0", "id": 1, "result": "0x1"})
        result = await client.get_chain_id()
        self.assertEqual(result, 1)

    async def test_batch_returns_ordered_results(self):
        client = _make_client()
        # Batch responses may come back in any order — we sort by id
        batch_response = [
            {"jsonrpc": "2.0", "id": 2, "result": "0xb"},
            {"jsonrpc": "2.0", "id": 1, "result": "0xa"},
        ]
        _set_response(client, batch_response)
        results = await client.batch([
            ("eth_getCode", ["0x1", "latest"]),
            ("eth_getCode", ["0x2", "latest"]),
        ])
        self.assertEqual(results[0], "0xa")
        self.assertEqual(results[1], "0xb")

    async def test_batch_with_error_item_returns_none(self):
        client = _make_client()
        batch_response = [
            {"jsonrpc": "2.0", "id": 1, "result": "0xa"},
            {"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "fail"}},
        ]
        _set_response(client, batch_response)
        results = await client.batch([
            ("eth_getCode", ["0x1", "latest"]),
            ("eth_getCode", ["0x2", "latest"]),
        ])
        self.assertEqual(results[0], "0xa")
        self.assertIsNone(results[1])

    async def test_get_storage_at_returns_padded(self):
        client = _make_client()
        slot_value = "0x" + "0" * 24 + "dead" * 5 + "00"
        _set_response(client, {"jsonrpc": "2.0", "id": 1, "result": slot_value})
        result = await client.get_storage_at("0xabc", "0x0", "latest")
        self.assertEqual(result, slot_value)


if __name__ == "__main__":
    unittest.main()
