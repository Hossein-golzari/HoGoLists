"""
Proxy contract detection and implementation address resolution.

Detection order (cheapest first):
  1. EIP-1167 bytecode prefix match (no RPC needed beyond getCode)
  2. EIP-1967 storage slot reads (one batch call)
  3. EIP-1822 storage slot read
  4. Legacy OZ slot read
  5. Gnosis Safe slot-0 read
  6. eth_call on common implementation() selectors (last resort)
"""

from __future__ import annotations

import logging
from typing import Optional

from .bytecode import (
    GNOSIS_MASTERCOPY_SLOT,
    EIP1822_PROXIABLE_SLOT,
    EIP1967_ADMIN_SLOT,
    EIP1967_BEACON_SLOT,
    EIP1967_IMPL_SLOT,
    IMPL_CALL_SELECTORS,
    OZ_LEGACY_IMPL_SLOT,
    detect_eip1167,
    has_delegatecall,
    is_likely_gnosis_proxy,
)
from .models import ProxyInfo, ProxyPattern
from .rpc import RPCClient

log = logging.getLogger(__name__)

# Zero address — storage slot not set
_ZERO_ADDR = "0x" + "0" * 40
_ZERO_SLOT = "0x" + "0" * 64


def _slot_to_address(slot_value: str) -> Optional[str]:
    """
    Convert a 32-byte storage slot value to an address string.
    Returns None if the value is zero (slot not set).
    """
    raw = slot_value.lower().lstrip("0x").lstrip("0")
    if not raw or raw == "0":
        return None
    # Addresses are the last 20 bytes (40 hex chars)
    padded = slot_value.lower().lstrip("0x").zfill(64)
    addr_hex = padded[-40:]
    if addr_hex == "0" * 40:
        return None
    return "0x" + addr_hex


async def resolve_proxy(
    address: str,
    rpc: RPCClient,
    bytecode: bytes,
    block: str = "latest",
    try_eth_call: bool = True,
) -> ProxyInfo:
    """
    Attempt to detect whether *address* is a proxy and resolve its implementation.
    Returns a ProxyInfo with is_proxy=False when no proxy pattern is found.

    This function is designed to make as few RPC calls as possible.
    """
    # Step 1: EIP-1167 minimal proxy (bytecode-only, no extra RPC)
    impl = detect_eip1167(bytecode)
    if impl:
        log.debug("%s: EIP-1167 minimal proxy -> %s", address, impl)
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.EIP1167,
            implementation_address=impl,
        )

    # Quick exit: if no DELEGATECALL in bytecode, it's almost certainly not a proxy
    if not has_delegatecall(bytecode):
        return ProxyInfo(is_proxy=False)

    # Step 2: Batch EIP-1967 + EIP-1822 + OZ legacy + Gnosis slots in one call
    slots = [
        EIP1967_IMPL_SLOT,
        EIP1967_BEACON_SLOT,
        EIP1822_PROXIABLE_SLOT,
        OZ_LEGACY_IMPL_SLOT,
        GNOSIS_MASTERCOPY_SLOT,
        EIP1967_ADMIN_SLOT,
    ]
    try:
        storage = await rpc.batch_get_storage(address, slots, block)
    except Exception as exc:
        log.warning("Storage batch failed for %s: %s", address, exc)
        storage = {slot: _ZERO_SLOT for slot in slots}

    # EIP-1967 transparent proxy (implementation slot)
    impl_addr = _slot_to_address(storage.get(EIP1967_IMPL_SLOT, _ZERO_SLOT))
    if impl_addr:
        log.debug("%s: EIP-1967 transparent proxy -> %s", address, impl_addr)
        admin_addr = _slot_to_address(storage.get(EIP1967_ADMIN_SLOT, _ZERO_SLOT))
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.EIP1967_TRANSPARENT,
            implementation_address=impl_addr,
        )

    # EIP-1967 beacon proxy
    beacon_addr = _slot_to_address(storage.get(EIP1967_BEACON_SLOT, _ZERO_SLOT))
    if beacon_addr:
        log.debug("%s: EIP-1967 beacon proxy -> beacon %s", address, beacon_addr)
        # Resolve the beacon's implementation() via eth_call
        beacon_impl = None
        if try_eth_call:
            beacon_impl = await _call_implementation(beacon_addr, rpc, block)
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.EIP1967_BEACON,
            implementation_address=beacon_impl,
            beacon_address=beacon_addr,
        )

    # EIP-1822 UUPS (PROXIABLE slot stores implementation)
    uups_addr = _slot_to_address(storage.get(EIP1822_PROXIABLE_SLOT, _ZERO_SLOT))
    if uups_addr:
        log.debug("%s: EIP-1822 UUPS proxy -> %s", address, uups_addr)
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.EIP1822_UUPS,
            implementation_address=uups_addr,
        )

    # Legacy OZ proxy
    oz_addr = _slot_to_address(storage.get(OZ_LEGACY_IMPL_SLOT, _ZERO_SLOT))
    if oz_addr:
        log.debug("%s: OZ legacy proxy -> %s", address, oz_addr)
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.EIP1967_TRANSPARENT,  # treat as transparent
            implementation_address=oz_addr,
        )

    # Gnosis Safe (masterCopy at slot 0)
    gnosis_addr = _slot_to_address(storage.get(GNOSIS_MASTERCOPY_SLOT, _ZERO_SLOT))
    if gnosis_addr and is_likely_gnosis_proxy(bytecode):
        log.debug("%s: Gnosis Safe proxy -> %s", address, gnosis_addr)
        return ProxyInfo(
            is_proxy=True,
            proxy_type=ProxyPattern.GNOSIS_SAFE,
            implementation_address=gnosis_addr,
        )

    # Step 3: Fall back to eth_call on well-known selectors
    if try_eth_call:
        call_result = await _call_implementation(address, rpc, block)
        if call_result:
            log.debug("%s: generic proxy via eth_call -> %s", address, call_result)
            return ProxyInfo(
                is_proxy=True,
                proxy_type=ProxyPattern.GENERIC,
                implementation_address=call_result,
            )

    # Step 4: Has DELEGATECALL but we couldn't resolve — flag as unknown proxy
    # Only do this if the bytecode is small (typical proxy) to avoid false positives
    if len(bytecode) < 2000:
        log.debug("%s: unresolved proxy (has DELEGATECALL, small bytecode)", address)
        return ProxyInfo(is_proxy=True, proxy_type=ProxyPattern.GENERIC)

    return ProxyInfo(is_proxy=False)


async def _call_implementation(
    address: str, rpc: RPCClient, block: str
) -> Optional[str]:
    """
    Try calling known implementation() selectors on *address* via eth_call.
    Returns the first non-zero address result, or None.
    """
    for selector, name in IMPL_CALL_SELECTORS:
        try:
            result = await rpc.eth_call(address, selector, block)
            if result and len(result) >= 66:  # 0x + 64 hex chars (32 bytes)
                addr = _slot_to_address(result)
                if addr:
                    log.debug(
                        "  eth_call %s on %s -> %s", name, address, addr
                    )
                    return addr
        except Exception as exc:
            log.debug("eth_call %s on %s failed: %s", name, address, exc)
    return None
