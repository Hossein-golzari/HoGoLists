"""
EVM bytecode analysis.

Provides:
  - selector extraction from dispatch tables (PUSH4 + EQ + JUMPI patterns)
  - proxy pattern detection via bytecode prefix inspection
  - DELEGATECALL presence check (coarse proxy indicator)
  - SLOAD coverage check for high-value storage slots
  - minimal bytecode metadata (size, has-constructor-args indicator)

All functions operate on raw bytes and are pure / easily unit-testable.
"""

from __future__ import annotations

import re
from typing import FrozenSet, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# EVM opcode constants
# ---------------------------------------------------------------------------

# Push instructions: PUSH1 (0x60) through PUSH32 (0x7f)
_PUSH1 = 0x60
_PUSH32 = 0x7f
_PUSH4 = 0x63          # PUSH4 — used for 4-byte selectors
_EQ = 0x14             # EQ — used in dispatch to match selector
_JUMPI = 0x57          # JUMPI — conditional jump after selector match
_DELEGATECALL = 0xf4   # DELEGATECALL — present in most proxy contracts
_STATICCALL = 0xfa     # STATICCALL — view calls
_SLOAD = 0x54          # SLOAD — storage read
_RETURN = 0xf3
_REVERT = 0xfd
_STOP = 0x00
_CALLDATALOAD = 0x35
_DIV = 0x04
_SHR = 0x1c            # SHR — used to extract 4-byte selector (post-EVM EIP-145)

# ---------------------------------------------------------------------------
# Known proxy bytecode prefixes (hex strings, lowercase)
# ---------------------------------------------------------------------------

# EIP-1167 Minimal Proxy — classic pattern
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
# EIP-1167 with PUSH0 (post-EIP-3855 Shanghai)
_EIP1167_PUSH0_PREFIX = bytes.fromhex("365f5f375f5f365f73")
# Vyper minimal proxy variant
_VYPER_PROXY_PREFIX = bytes.fromhex("366000600037611000600036600073")

# GnosisSafe singleton proxy exact bytecode (v1.3.0)
_GNOSIS_PROXY_SIG = bytes.fromhex(
    "608060405273ffffffffffffffffffffffffffffffffffffffff"
    "600054167fa619486e00000000000000000000000000000000000000000000000000000000006000"
)


# ---------------------------------------------------------------------------
# Bytecode walking utility
# ---------------------------------------------------------------------------

class BytecodeWalker:
    """
    Simple forward-only EVM bytecode iterator.
    Skips push data so the opcode stream stays aligned.
    """

    def __init__(self, code: bytes) -> None:
        self.code = code
        self.pos = 0

    def __iter__(self):
        return self

    def __next__(self) -> Tuple[int, int, bytes]:
        """Yields (position, opcode, push_data_or_empty)."""
        if self.pos >= len(self.code):
            raise StopIteration
        op = self.code[self.pos]
        pos = self.pos
        if _PUSH1 <= op <= _PUSH32:
            size = op - _PUSH1 + 1
            data = self.code[self.pos + 1: self.pos + 1 + size]
            self.pos += 1 + size
            return pos, op, data
        self.pos += 1
        return pos, op, b""


# ---------------------------------------------------------------------------
# Selector extraction
# ---------------------------------------------------------------------------

def extract_selectors(bytecode: bytes) -> Set[str]:
    """
    Extract all 4-byte function selectors used in the dispatch table.

    Strategy: find PUSH4 <selector> followed by EQ within the next 8 bytes,
    which is the canonical Solidity dispatcher pattern.  We also collect all
    PUSH4 values that appear near a JUMPI within a 12-byte window as a
    secondary fallback for less-standard compilers.

    Returns a set of lowercase 0x-prefixed hex strings.
    """
    if not bytecode:
        return set()

    selectors: Set[str] = set()
    code = bytecode
    length = len(code)
    i = 0

    while i < length:
        op = code[i]

        if op == _PUSH4:
            if i + 5 > length:
                i += 1
                continue
            sel_bytes = code[i + 1: i + 5]
            sel = "0x" + sel_bytes.hex()

            # Look ahead up to 12 bytes for EQ or JUMPI (dispatch pattern)
            window_end = min(i + 5 + 12, length)
            window = code[i + 5: window_end]
            if _EQ in window or _JUMPI in window:
                selectors.add(sel)

            i += 5
        elif _PUSH1 <= op <= _PUSH32:
            size = op - _PUSH1 + 1
            i += 1 + size
        else:
            i += 1

    return selectors


def extract_all_push4_values(bytecode: bytes) -> Set[str]:
    """
    Return ALL PUSH4 values in the bytecode regardless of context.
    More permissive than extract_selectors — useful as a fallback when
    dispatch patterns are obfuscated or use non-standard compilers.
    """
    if not bytecode:
        return set()
    values: Set[str] = set()
    i = 0
    length = len(bytecode)
    while i < length:
        op = bytecode[i]
        if op == _PUSH4:
            if i + 5 <= length:
                values.add("0x" + bytecode[i + 1: i + 5].hex())
            i += 5
        elif _PUSH1 <= op <= _PUSH32:
            size = op - _PUSH1 + 1
            i += 1 + size
        else:
            i += 1
    return values


# ---------------------------------------------------------------------------
# Proxy pattern detection (bytecode-level)
# ---------------------------------------------------------------------------

def detect_eip1167(bytecode: bytes) -> Optional[str]:
    """
    If bytecode matches EIP-1167 minimal proxy pattern, return the embedded
    implementation address (0x-prefixed, lowercase).  Otherwise return None.
    """
    code_hex = bytecode.hex()

    # Classic minimal proxy: 363d3d373d3d3d363d73<20-byte-addr>5af43d82803e903d91602b57fd5bf3
    pattern = re.compile(
        r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3",
        re.IGNORECASE,
    )
    m = pattern.match(code_hex)
    if m:
        return "0x" + m.group(1)

    # PUSH0 variant (Shanghai+)
    pattern2 = re.compile(
        r"^365f5f375f5f365f73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3",
        re.IGNORECASE,
    )
    m2 = pattern2.match(code_hex)
    if m2:
        return "0x" + m2.group(1)

    # Vyper variant
    if bytecode[:len(_VYPER_PROXY_PREFIX)] == _VYPER_PROXY_PREFIX and len(bytecode) >= 55:
        addr_bytes = bytecode[len(_VYPER_PROXY_PREFIX): len(_VYPER_PROXY_PREFIX) + 20]
        return "0x" + addr_bytes.hex()

    return None


def has_delegatecall(bytecode: bytes) -> bool:
    """Return True if the bytecode contains a DELEGATECALL opcode."""
    i = 0
    length = len(bytecode)
    while i < length:
        op = bytecode[i]
        if op == _DELEGATECALL:
            return True
        if _PUSH1 <= op <= _PUSH32:
            i += op - _PUSH1 + 2
        else:
            i += 1
    return False


def is_likely_gnosis_proxy(bytecode: bytes) -> bool:
    """Heuristic: does bytecode look like a Gnosis Safe proxy?"""
    return (
        len(bytecode) < 200
        and _DELEGATECALL in bytecode
        and b"\x00" * 12 in bytecode  # padding for address storage
    )


# ---------------------------------------------------------------------------
# Storage-based proxy slot constants (for use in proxy.py)
# ---------------------------------------------------------------------------

# EIP-1967: keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

# EIP-1967: keccak256("eip1967.proxy.beacon") - 1
EIP1967_BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

# EIP-1967: keccak256("eip1967.proxy.admin") - 1
EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)

# EIP-1822 UUPS: keccak256("PROXIABLE")
EIP1822_PROXIABLE_SLOT = (
    "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
)

# Legacy OpenZeppelin (pre-1967) implementation slot: keccak256("org.zeppelinos.proxy.implementation")
OZ_LEGACY_IMPL_SLOT = (
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
)

# Gnosis Safe: masterCopy at slot 0 (storage slot 0x0)
GNOSIS_MASTERCOPY_SLOT = "0x" + "0" * 64


# ---------------------------------------------------------------------------
# Well-known function call selectors for proxy resolution via eth_call
# ---------------------------------------------------------------------------

IMPL_CALL_SELECTORS = [
    ("0x5c60da1b", "implementation()"),     # EIP-897 / EIP-1967 transparent
    ("0xaaf10f42", "getImplementation()"),  # some UUPS variants
    ("0xd784d426", "adminAddress()"),       # OpenZeppelin v2 proxy
    ("0xbb82aa5e", "_implementation()"),   # old OZ transparent proxy
]


# ---------------------------------------------------------------------------
# Bytecode metadata
# ---------------------------------------------------------------------------

def bytecode_metadata(bytecode: bytes) -> dict:
    """
    Extract high-level metadata from raw deployment bytecode.
    Returns a dict with: size, has_delegatecall, selector_count, is_empty.
    """
    size = len(bytecode)
    if size == 0:
        return {"size": 0, "has_delegatecall": False, "selector_count": 0, "is_empty": True}
    sels = extract_selectors(bytecode)
    return {
        "size": size,
        "has_delegatecall": has_delegatecall(bytecode),
        "selector_count": len(sels),
        "is_empty": False,
    }
