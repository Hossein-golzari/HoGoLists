"""
Unit tests for bytecode.py

Tests cover:
  - Selector extraction from realistic dispatch bytecode
  - PUSH4 value enumeration
  - EIP-1167 pattern matching
  - DELEGATECALL detection
  - Bytecode metadata
"""

from __future__ import annotations

import unittest

from ..bytecode import (
    bytecode_metadata,
    detect_eip1167,
    extract_all_push4_values,
    extract_selectors,
    has_delegatecall,
)


def _build_dispatch(selector_hex: str) -> bytes:
    """
    Build a minimal Solidity-style dispatch snippet for one selector:
      PUSH4 <sel>
      DUP1        (0x80)
      EQ          (0x14)
      PUSH2 dest  (0x61 0x00 0x10)
      JUMPI       (0x57)
    """
    sel_bytes = bytes.fromhex(selector_hex)
    return (
        bytes([0x63]) + sel_bytes   # PUSH4
        + bytes([0x80])             # DUP1
        + bytes([0x14])             # EQ
        + bytes([0x61, 0x00, 0x10]) # PUSH2 0x0010
        + bytes([0x57])             # JUMPI
    )


class TestExtractSelectors(unittest.TestCase):

    def test_single_selector(self):
        code = _build_dispatch("8da5cb5b")  # owner()
        result = extract_selectors(code)
        self.assertIn("0x8da5cb5b", result)

    def test_multiple_selectors(self):
        code = b"".join([
            _build_dispatch("8da5cb5b"),   # owner()
            _build_dispatch("f851a440"),   # admin()
            _build_dispatch("5c60da1b"),   # implementation()
        ])
        result = extract_selectors(code)
        self.assertIn("0x8da5cb5b", result)
        self.assertIn("0xf851a440", result)
        self.assertIn("0x5c60da1b", result)

    def test_empty_bytecode(self):
        self.assertEqual(extract_selectors(b""), set())

    def test_push_data_not_misinterpreted(self):
        # PUSH4 followed by data bytes that happen to be 0x63 (PUSH4 opcode)
        # The inner 0x63 is push data, not an opcode — must not produce spurious selectors
        code = bytes([0x63, 0x63, 0xab, 0xcd, 0xef, 0x14, 0x57])
        result = extract_selectors(code)
        # 0x63abcdef should be extracted (PUSH4 opcode = 0x63, data = 63 ab cd ef)
        self.assertIn("0x63abcdef", result)

    def test_non_dispatch_push4_not_included(self):
        # PUSH4 followed by bytes with no EQ or JUMPI nearby
        code = bytes([0x63, 0xde, 0xad, 0xbe, 0xef, 0x50, 0x50, 0x50])  # PUSH4 + POP POP POP
        result = extract_selectors(code)
        # 0xdeadbeef should NOT be included — no EQ/JUMPI nearby
        self.assertNotIn("0xdeadbeef", result)

    def test_extract_all_push4_is_superset(self):
        code = b"".join([
            _build_dispatch("8da5cb5b"),
            bytes([0x63, 0xde, 0xad, 0xbe, 0xef]),  # standalone PUSH4 (non-dispatch)
        ])
        dispatch_sels = extract_selectors(code)
        all_sels = extract_all_push4_values(code)
        # All dispatch selectors must be in the full set
        self.assertTrue(dispatch_sels.issubset(all_sels))
        # The non-dispatch value must be in all_push4 but may be absent from dispatch
        self.assertIn("0xdeadbeef", all_sels)


class TestHasDelegateCall(unittest.TestCase):

    def test_present(self):
        code = bytes([0x60, 0x00, 0xf4])  # PUSH1 0x00, DELEGATECALL
        self.assertTrue(has_delegatecall(code))

    def test_absent(self):
        code = bytes([0x60, 0x01, 0x55])  # PUSH1 0x01, SSTORE
        self.assertFalse(has_delegatecall(code))

    def test_in_push_data(self):
        # 0xf4 is a PUSH2 data byte, not an opcode
        code = bytes([0x61, 0xf4, 0x00])  # PUSH2 0xf400
        self.assertFalse(has_delegatecall(code))


class TestDetectEIP1167(unittest.TestCase):

    def _eip1167(self, addr: str) -> bytes:
        addr_hex = addr.lower().lstrip("0x").zfill(40)
        return bytes.fromhex(
            f"363d3d373d3d3d363d73{addr_hex}5af43d82803e903d91602b57fd5bf3"
        )

    def test_classic_pattern(self):
        addr = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
        code = self._eip1167(addr)
        self.assertEqual(detect_eip1167(code), addr)

    def test_random_bytecode(self):
        code = bytes.fromhex("6080604052600080fd")
        self.assertIsNone(detect_eip1167(code))

    def test_empty(self):
        self.assertIsNone(detect_eip1167(b""))


class TestBytecodeMetadata(unittest.TestCase):

    def test_empty_returns_is_empty(self):
        meta = bytecode_metadata(b"")
        self.assertTrue(meta["is_empty"])
        self.assertEqual(meta["size"], 0)

    def test_with_selectors(self):
        code = b"".join([
            _build_dispatch("8da5cb5b"),
            _build_dispatch("f851a440"),
        ])
        meta = bytecode_metadata(code)
        self.assertFalse(meta["is_empty"])
        self.assertEqual(meta["selector_count"], 2)
        self.assertFalse(meta["has_delegatecall"])

    def test_with_delegatecall(self):
        code = bytes([0x60, 0x00, 0xf4])
        meta = bytecode_metadata(code)
        self.assertTrue(meta["has_delegatecall"])


if __name__ == "__main__":
    unittest.main()
