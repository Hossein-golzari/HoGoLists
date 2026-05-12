"""
Data models for the contract leakage detector.
All analysis outputs are typed dataclasses to make them easy to serialize and test.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class RiskLevel:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    ORDER = {"low": 0, "medium": 1, "high": 2}

    @classmethod
    def compare(cls, a: str, b: str) -> int:
        return cls.ORDER.get(a, 0) - cls.ORDER.get(b, 0)


# ---------------------------------------------------------------------------
# Proxy detection result
# ---------------------------------------------------------------------------

class ProxyPattern:
    """Known proxy patterns we detect."""
    EIP1167 = "EIP-1167 MinimalProxy"
    EIP1967_TRANSPARENT = "EIP-1967 Transparent"
    EIP1967_BEACON = "EIP-1967 Beacon"
    EIP1822_UUPS = "EIP-1822 UUPS"
    GNOSIS_SAFE = "GnosisSafe"
    EIP2535_DIAMOND = "EIP-2535 Diamond"
    GENERIC = "generic-delegatecall"


@dataclass
class ProxyInfo:
    is_proxy: bool
    proxy_type: Optional[str] = None
    implementation_address: Optional[str] = None   # checksummed hex, or None
    beacon_address: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-function information
# ---------------------------------------------------------------------------

@dataclass
class FunctionInfo:
    """Represents a single public/external function or getter."""
    selector: str                          # 0x-prefixed 4-byte hex
    name: Optional[str] = None             # human-readable name if known
    inputs: Optional[str] = None           # comma-separated input types
    outputs: Optional[str] = None          # comma-separated output types
    state_mutability: Optional[str] = None # view | pure | nonpayable | payable
    visibility: Optional[str] = None       # public | external
    source: str = "bytecode"               # "bytecode" | "db_match" | "abi"


# ---------------------------------------------------------------------------
# Individual finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single heuristic match flagging a potentially sensitive item."""
    contract_address: str
    proxy_address: Optional[str]
    implementation_address: Optional[str]
    name: Optional[str]
    selector: Optional[str]
    visibility: Optional[str]
    type_info: Optional[str]
    heuristic_reason: str
    risk_level: str                        # RiskLevel constant
    explanation: str
    source: str = "unknown"               # "name_match" | "type_match" | "selector_db" | "bytecode_pattern"

    def dedup_key(self) -> str:
        addr = (self.implementation_address or self.contract_address).lower()
        sel = (self.selector or "").lower()
        reason = self.heuristic_reason.lower().replace(" ", "_")
        return f"{addr}:{sel}:{reason}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_address": self.contract_address,
            "proxy_address": self.proxy_address,
            "implementation_address": self.implementation_address,
            "name": self.name,
            "selector": self.selector,
            "visibility": self.visibility,
            "type_info": self.type_info,
            "heuristic_reason": self.heuristic_reason,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# Full per-contract analysis result
# ---------------------------------------------------------------------------

@dataclass
class ContractAnalysis:
    """Complete analysis result for one contract address."""
    address: str
    chain_id: int
    block_number: Optional[int]
    bytecode_hex: Optional[str]            # raw bytecode, None if fetch failed
    is_eoa: bool                           # True when bytecode == "0x"
    proxy_info: Optional[ProxyInfo]
    selectors: List[str]                   # all extracted 4-byte selectors
    functions: List[FunctionInfo]          # enriched function list
    findings: List[Finding]
    error: Optional[str]                   # non-None means partial/failed analysis
    duration_ms: float = 0.0
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "chain_id": self.chain_id,
            "block_number": self.block_number,
            "is_eoa": self.is_eoa,
            "proxy_info": {
                "is_proxy": self.proxy_info.is_proxy,
                "proxy_type": self.proxy_info.proxy_type,
                "implementation_address": self.proxy_info.implementation_address,
                "beacon_address": self.proxy_info.beacon_address,
            } if self.proxy_info else None,
            "selectors": self.selectors,
            "functions": [
                {
                    "selector": f.selector,
                    "name": f.name,
                    "inputs": f.inputs,
                    "outputs": f.outputs,
                    "state_mutability": f.state_mutability,
                    "visibility": f.visibility,
                    "source": f.source,
                }
                for f in self.functions
            ],
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration_ms": round(self.duration_ms, 1),
            "analyzed_at": self.analyzed_at,
        }


# ---------------------------------------------------------------------------
# Batch scan summary
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """Aggregated report for a batch scan."""
    chain_id: int
    rpc_url: str
    block_number: Optional[int]
    total_contracts: int
    analyzed: int
    eoas_skipped: int
    errors: int
    total_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    results: List[ContractAnalysis]
    started_at: str
    finished_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "rpc_url": self.rpc_url,
            "block_number": self.block_number,
            "summary": {
                "total_contracts": self.total_contracts,
                "analyzed": self.analyzed,
                "eoas_skipped": self.eoas_skipped,
                "errors": self.errors,
                "total_findings": self.total_findings,
                "high": self.high_findings,
                "medium": self.medium_findings,
                "low": self.low_findings,
            },
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [r.to_dict() for r in self.results],
        }
