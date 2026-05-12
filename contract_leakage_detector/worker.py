"""
Concurrent batch analysis engine.

Uses an asyncio worker pool (bounded by a semaphore) to analyse many
contracts in parallel while:
  - Sharing a single RPC connection pool
  - Respecting a configurable concurrency limit
  - Yielding incremental results as soon as they're ready (async generator)
  - Caching all intermediate artefacts to avoid repeat calls
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import AsyncIterator, List, Optional, Union

from .bytecode import (
    bytecode_metadata,
    extract_selectors,
)
from .cache import LocalCache, NullCache
from .dedup import merge_proxy_and_impl, sort_findings
from .heuristics import score_contract
from .models import ContractAnalysis, FunctionInfo, ProxyInfo, RiskLevel
from .proxy import resolve_proxy
from .rpc import RPCClient
from .selectors_db import lookup_selector

log = logging.getLogger(__name__)

CacheType = Union[LocalCache, NullCache]


# ---------------------------------------------------------------------------
# Single-contract analyser
# ---------------------------------------------------------------------------

async def analyse_contract(
    address: str,
    rpc: RPCClient,
    cache: CacheType,
    chain_id: int,
    block: str = "latest",
    resolve_proxy_flag: bool = True,
    block_number_int: Optional[int] = None,
) -> ContractAnalysis:
    """
    Full analysis pipeline for one contract address.
    Returns a ContractAnalysis regardless of errors (errors are stored in .error).
    """
    started = time.monotonic()
    address = address.lower()

    # ------------------------------------------------------------------
    # Cache check — skip full analysis if already done
    # ------------------------------------------------------------------
    cached_result = await cache.get_analysis(address, chain_id, block)
    if cached_result:
        log.debug("Cache hit for analysis: %s", address)
        # Reconstruct from dict — simplified, just return a minimal object
        # (Full round-trip deserialisation is left to the CLI layer)
        return _dict_to_analysis(cached_result)

    # ------------------------------------------------------------------
    # Step 1: Fetch bytecode
    # ------------------------------------------------------------------
    bytecode_hex = await cache.get_bytecode(address, chain_id, block)
    if bytecode_hex is None:
        try:
            bytecode_hex = await rpc.get_code(address, block)
            await cache.set_bytecode(address, chain_id, block, bytecode_hex)
        except Exception as exc:
            log.warning("get_code failed for %s: %s", address, exc)
            return ContractAnalysis(
                address=address,
                chain_id=chain_id,
                block_number=block_number_int,
                bytecode_hex=None,
                is_eoa=False,
                proxy_info=None,
                selectors=[],
                functions=[],
                findings=[],
                error=str(exc),
                duration_ms=(time.monotonic() - started) * 1000,
            )

    # EOA (externally owned account) — no bytecode
    if bytecode_hex in ("0x", "0x0", "", None):
        return ContractAnalysis(
            address=address,
            chain_id=chain_id,
            block_number=block_number_int,
            bytecode_hex="0x",
            is_eoa=True,
            proxy_info=None,
            selectors=[],
            functions=[],
            findings=[],
            error=None,
            duration_ms=(time.monotonic() - started) * 1000,
        )

    bytecode = bytes.fromhex(bytecode_hex.lstrip("0x") or "")

    # ------------------------------------------------------------------
    # Step 2: Proxy detection and resolution
    # ------------------------------------------------------------------
    proxy_info: Optional[ProxyInfo] = None
    if resolve_proxy_flag:
        cached_proxy = await cache.get_proxy(address, chain_id, block)
        if cached_proxy is not None:
            proxy_info = ProxyInfo(**cached_proxy)
        else:
            try:
                proxy_info = await resolve_proxy(
                    address, rpc, bytecode, block, try_eth_call=True
                )
                await cache.set_proxy(address, chain_id, block, {
                    "is_proxy": proxy_info.is_proxy,
                    "proxy_type": proxy_info.proxy_type,
                    "implementation_address": proxy_info.implementation_address,
                    "beacon_address": proxy_info.beacon_address,
                })
            except Exception as exc:
                log.warning("Proxy resolution failed for %s: %s", address, exc)
                proxy_info = ProxyInfo(is_proxy=False)

    # ------------------------------------------------------------------
    # Step 3: If proxy, fetch and analyse implementation bytecode too
    # ------------------------------------------------------------------
    impl_analysis: Optional[ContractAnalysis] = None
    if proxy_info and proxy_info.is_proxy and proxy_info.implementation_address:
        impl_addr = proxy_info.implementation_address
        impl_bytecode_hex = await cache.get_bytecode(impl_addr, chain_id, block)
        if impl_bytecode_hex is None:
            try:
                impl_bytecode_hex = await rpc.get_code(impl_addr, block)
                await cache.set_bytecode(impl_addr, chain_id, block, impl_bytecode_hex)
            except Exception as exc:
                log.warning("get_code for impl %s failed: %s", impl_addr, exc)
                impl_bytecode_hex = "0x"

        if impl_bytecode_hex not in ("0x", "", None):
            impl_bytecode = bytes.fromhex(impl_bytecode_hex.lstrip("0x") or "")
            impl_selectors = extract_selectors(impl_bytecode)
            impl_functions = _build_function_list(impl_selectors)
            impl_findings = score_contract(impl_functions, impl_addr, proxy_info)
            impl_analysis = ContractAnalysis(
                address=impl_addr,
                chain_id=chain_id,
                block_number=block_number_int,
                bytecode_hex=impl_bytecode_hex,
                is_eoa=False,
                proxy_info=None,
                selectors=sorted(impl_selectors),
                functions=impl_functions,
                findings=impl_findings,
                error=None,
                duration_ms=0,
            )

    # ------------------------------------------------------------------
    # Step 4: Extract selectors and build function list for the proxy itself
    # ------------------------------------------------------------------
    selectors = extract_selectors(bytecode)
    functions = _build_function_list(selectors)

    # ------------------------------------------------------------------
    # Step 5: Score with heuristics
    # ------------------------------------------------------------------
    proxy_findings = score_contract(functions, address, proxy_info)

    # Merge proxy + implementation findings
    if impl_analysis and proxy_info and proxy_info.implementation_address:
        merged = merge_proxy_and_impl(
            proxy_findings,
            impl_analysis.findings,
            proxy_address=address,
            impl_address=proxy_info.implementation_address,
        )
        final_findings = sort_findings(merged)
        # Use implementation's functions as primary (they have the real logic)
        all_functions = impl_analysis.functions or functions
        all_selectors = sorted(
            set(impl_analysis.selectors) | set(sorted(selectors))
        )
    else:
        final_findings = sort_findings(proxy_findings)
        all_functions = functions
        all_selectors = sorted(selectors)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    result = ContractAnalysis(
        address=address,
        chain_id=chain_id,
        block_number=block_number_int,
        bytecode_hex=bytecode_hex,
        is_eoa=False,
        proxy_info=proxy_info,
        selectors=all_selectors,
        functions=all_functions,
        findings=final_findings,
        error=None,
        duration_ms=(time.monotonic() - started) * 1000,
    )

    # Persist analysis to cache
    await cache.set_analysis(address, chain_id, block, result.to_dict())
    return result


def _build_function_list(selectors: set) -> List[FunctionInfo]:
    """
    Build FunctionInfo objects from a set of raw selectors.
    Names are filled in from the selector database where available.
    """
    functions: List[FunctionInfo] = []
    for sel in sorted(selectors):
        entry = lookup_selector(sel)
        if entry:
            # Parse sig to extract name and inputs
            sig = entry.get("sig", "")
            paren = sig.find("(")
            fn_name = sig[:paren] if paren >= 0 else sig
            inputs_str = sig[paren + 1:-1] if paren >= 0 and sig.endswith(")") else None
            fn = FunctionInfo(
                selector=sel,
                name=fn_name,
                inputs=inputs_str or None,
                outputs=None,          # we don't have return types in the simple DB
                state_mutability="view",
                visibility="public",
                source="db_match",
            )
        else:
            fn = FunctionInfo(
                selector=sel,
                name=None,
                inputs=None,
                outputs=None,
                state_mutability=None,
                visibility=None,
                source="bytecode",
            )
        functions.append(fn)
    return functions


def _dict_to_analysis(d: dict) -> ContractAnalysis:
    """Reconstruct a ContractAnalysis from its to_dict() output."""
    proxy_dict = d.get("proxy_info")
    proxy_info = ProxyInfo(**proxy_dict) if proxy_dict else None
    functions = [
        FunctionInfo(
            selector=f["selector"],
            name=f.get("name"),
            inputs=f.get("inputs"),
            outputs=f.get("outputs"),
            state_mutability=f.get("state_mutability"),
            visibility=f.get("visibility"),
            source=f.get("source", "bytecode"),
        )
        for f in d.get("functions", [])
    ]
    from .models import Finding
    findings = [
        Finding(
            contract_address=f["contract_address"],
            proxy_address=f.get("proxy_address"),
            implementation_address=f.get("implementation_address"),
            name=f.get("name"),
            selector=f.get("selector"),
            visibility=f.get("visibility"),
            type_info=f.get("type_info"),
            heuristic_reason=f["heuristic_reason"],
            risk_level=f["risk_level"],
            explanation=f["explanation"],
            source=f.get("source", "unknown"),
        )
        for f in d.get("findings", [])
    ]
    return ContractAnalysis(
        address=d["address"],
        chain_id=d["chain_id"],
        block_number=d.get("block_number"),
        bytecode_hex=d.get("bytecode_hex"),
        is_eoa=d.get("is_eoa", False),
        proxy_info=proxy_info,
        selectors=d.get("selectors", []),
        functions=functions,
        findings=findings,
        error=d.get("error"),
        duration_ms=d.get("duration_ms", 0.0),
        analyzed_at=d.get("analyzed_at", ""),
    )


# ---------------------------------------------------------------------------
# Batch scan engine (async generator for incremental results)
# ---------------------------------------------------------------------------

async def batch_scan(
    addresses: List[str],
    rpc: RPCClient,
    cache: CacheType,
    chain_id: int,
    block: str = "latest",
    block_number_int: Optional[int] = None,
    resolve_proxy_flag: bool = True,
    max_workers: int = 10,
) -> AsyncIterator[ContractAnalysis]:
    """
    Analyse many contracts concurrently.

    Yields ContractAnalysis objects as soon as they're ready — the caller
    does not need to wait for the full batch.

    max_workers controls the maximum number of simultaneous analyses
    (each of which may make several RPC calls).
    """
    semaphore = asyncio.Semaphore(max_workers)
    queue: asyncio.Queue[Optional[ContractAnalysis]] = asyncio.Queue()

    async def worker(addr: str) -> None:
        async with semaphore:
            result = await analyse_contract(
                address=addr,
                rpc=rpc,
                cache=cache,
                chain_id=chain_id,
                block=block,
                resolve_proxy_flag=resolve_proxy_flag,
                block_number_int=block_number_int,
            )
        await queue.put(result)

    # Launch all workers
    tasks = [asyncio.create_task(worker(addr)) for addr in addresses]

    completed = 0
    total = len(addresses)

    while completed < total:
        result = await queue.get()
        if result is not None:
            yield result
        completed += 1

    # Ensure all tasks are cleaned up
    for task in tasks:
        if not task.done():
            await task
