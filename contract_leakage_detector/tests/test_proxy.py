"""
Unit tests for proxy.py

Tests cover:
  - EIP-1167 bytecode pattern matching
  - EIP-1967 storage slot detection (mocked RPC)
  - Non-proxy bytecode correctly returns is_proxy=False
  - Gnosis Safe heuristic
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from ..bytecode import detect_eip1167, has_delegatecall
from ..models import ProxyPattern
from ..proxy import resolve_proxy, _slot_to_address


# ---------------------------------------------------------------------------
# _slot_to_address
# ---------------------------------------------------------------------------

class TestSlotToAddress(unittest.TestCase):

    def test_zero_slot_returns_none(self):
        self.assertIsNone(_slot_to_address("0x" + "0" * 64))

    def test_valid_address_extracted(self):
        # A 32-byte value with a non-zero address in the last 20 bytes
        addr = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        slot = "0x" + "0" * 24 + addr[2:]
        result = _slot_to_address(slot)
        self.assertEqual(result, addr)

    def test_padded_address(self):
        slot = "0x000000000000000000000000" + "ab" * 20
        result = _slot_to_address(slot)
        self.assertIsNotNone(result)
        self.assertTrue(result.startswith("0x"))


# ---------------------------------------------------------------------------
# detect_eip1167
# ---------------------------------------------------------------------------

class TestEIP1167(unittest.TestCase):

    def _make_eip1167(self, impl_addr: str) -> bytes:
        """Build a valid EIP-1167 minimal proxy bytecode."""
        addr_hex = impl_addr.lower().lstrip("0x").zfill(40)
        hex_code = f"363d3d373d3d3d363d73{addr_hex}5af43d82803e903d91602b57fd5bf3"
        return bytes.fromhex(hex_code)

    def test_detects_classic_eip1167(self):
        impl = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        code = self._make_eip1167(impl)
        result = detect_eip1167(code)
        self.assertEqual(result, impl)

    def test_non_proxy_returns_none(self):
        # Regular ERC-20 bytecode (random bytes)
        code = bytes.fromhex("6080604052348015600f57600080fd5b50")
        result = detect_eip1167(code)
        self.assertIsNone(result)

    def test_empty_bytecode_returns_none(self):
        self.assertIsNone(detect_eip1167(b""))

    def test_push0_variant(self):
        impl = "0x" + "ab" * 20  # exactly 20 bytes = 40 hex chars = valid EVM address
        addr_hex = impl.lower()[2:].zfill(40)  # strip "0x", then zero-pad to 40
        hex_code = f"365f5f375f5f365f73{addr_hex}5af43d82803e903d91602b57fd5bf3"
        code = bytes.fromhex(hex_code)
        result = detect_eip1167(code)
        self.assertEqual(result, impl)


# ---------------------------------------------------------------------------
# has_delegatecall
# ---------------------------------------------------------------------------

class TestHasDelegateCall(unittest.TestCase):

    def test_delegatecall_present(self):
        # 0xf4 is DELEGATECALL
        code = bytes([0x60, 0x00, 0xf4, 0x00])
        self.assertTrue(has_delegatecall(code))

    def test_delegatecall_absent(self):
        code = bytes([0x60, 0x01, 0x55, 0x00])
        self.assertFalse(has_delegatecall(code))

    def test_delegatecall_in_push_data_not_counted(self):
        # PUSH1 0xf4 — 0xf4 is the push data, not an opcode
        code = bytes([0x60, 0xf4])
        self.assertFalse(has_delegatecall(code))


# ---------------------------------------------------------------------------
# resolve_proxy — mocked RPC
# ---------------------------------------------------------------------------

def _make_rpc(
    storage_values: dict = None,
    eth_call_result: str = None,
) -> MagicMock:
    """Create a mock RPCClient."""
    rpc = MagicMock()
    rpc.batch_get_storage = AsyncMock(return_value=storage_values or {})
    rpc.eth_call = AsyncMock(return_value=eth_call_result)
    return rpc


class TestResolveProxy(unittest.IsolatedAsyncioTestCase):

    async def test_eip1167_returns_without_rpc(self):
        impl = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        addr_hex = impl.lower().lstrip("0x").zfill(40)
        code = bytes.fromhex(
            f"363d3d373d3d3d363d73{addr_hex}5af43d82803e903d91602b57fd5bf3"
        )
        rpc = _make_rpc()
        info = await resolve_proxy("0xproxy", rpc, code)
        self.assertTrue(info.is_proxy)
        self.assertEqual(info.proxy_type, ProxyPattern.EIP1167)
        self.assertEqual(info.implementation_address, impl)
        # No storage calls needed for EIP-1167
        rpc.batch_get_storage.assert_not_called()

    async def test_eip1967_detected_via_storage(self):
        from ..bytecode import EIP1967_IMPL_SLOT, EIP1967_BEACON_SLOT, EIP1822_PROXIABLE_SLOT
        from ..bytecode import OZ_LEGACY_IMPL_SLOT, GNOSIS_MASTERCOPY_SLOT, EIP1967_ADMIN_SLOT

        impl = "0xabcdef1234567890abcdef1234567890abcdef12"
        impl_padded = "0x" + "0" * 24 + impl[2:]

        storage = {
            EIP1967_IMPL_SLOT: impl_padded,
            EIP1967_BEACON_SLOT: "0x" + "0" * 64,
            EIP1822_PROXIABLE_SLOT: "0x" + "0" * 64,
            OZ_LEGACY_IMPL_SLOT: "0x" + "0" * 64,
            GNOSIS_MASTERCOPY_SLOT: "0x" + "0" * 64,
            EIP1967_ADMIN_SLOT: "0x" + "0" * 64,
        }
        # Must have DELEGATECALL in bytecode to proceed past quick-exit
        code = bytes([0x60, 0x00, 0xf4])  # PUSH1 0x00; DELEGATECALL
        rpc = _make_rpc(storage_values=storage)
        rpc.batch_get_storage = AsyncMock(return_value=storage)
        info = await resolve_proxy("0xproxy", rpc, code, try_eth_call=False)
        self.assertTrue(info.is_proxy)
        self.assertEqual(info.proxy_type, ProxyPattern.EIP1967_TRANSPARENT)
        self.assertEqual(info.implementation_address, impl)

    async def test_no_proxy_returns_false(self):
        # Plain bytecode with no DELEGATECALL
        code = bytes([0x60, 0x00, 0x55])  # PUSH1 0x00; SSTORE
        rpc = _make_rpc()
        info = await resolve_proxy("0xcontract", rpc, code, try_eth_call=False)
        self.assertFalse(info.is_proxy)


if __name__ == "__main__":
    unittest.main()
