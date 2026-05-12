"""
Finding deduplication and merging.

When the same contract is a proxy, we analyse both the proxy address and the
implementation address separately, then merge — keeping only the highest-risk
version of each unique finding.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from .models import Finding, RiskLevel

log = logging.getLogger(__name__)

_RISK_ORDER: Dict[str, int] = {
    RiskLevel.HIGH: 2,
    RiskLevel.MEDIUM: 1,
    RiskLevel.LOW: 0,
}


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """
    Deduplicate a flat list of findings.

    Two findings are considered duplicates when they share the same:
      - effective address (implementation_address if set, else contract_address)
      - selector (normalised)
      - heuristic_reason (normalised)

    When duplicates exist, keep the one with the higher risk level.
    """
    best: Dict[str, Finding] = {}
    for f in findings:
        key = f.dedup_key()
        existing = best.get(key)
        if existing is None:
            best[key] = f
        else:
            # Keep the higher-risk one
            if _RISK_ORDER.get(f.risk_level, 0) > _RISK_ORDER.get(existing.risk_level, 0):
                best[key] = f
    return list(best.values())


def merge_proxy_and_impl(
    proxy_findings: List[Finding],
    impl_findings: List[Finding],
    proxy_address: str,
    impl_address: str,
) -> List[Finding]:
    """
    Merge findings from a proxy contract and its implementation.

    Implementation findings take precedence because the implementation holds
    the real logic. Proxy findings that duplicate an implementation finding
    (same selector + reason) are dropped to avoid noise.

    All surviving findings are annotated with both proxy_address and
    implementation_address for full traceability.
    """
    combined: List[Finding] = []

    # Annotate implementation findings with the proxy address
    for f in impl_findings:
        annotated = Finding(
            contract_address=f.contract_address,
            proxy_address=proxy_address,
            implementation_address=impl_address,
            name=f.name,
            selector=f.selector,
            visibility=f.visibility,
            type_info=f.type_info,
            heuristic_reason=f.heuristic_reason,
            risk_level=f.risk_level,
            explanation=f.explanation + f" [via proxy {proxy_address}]",
            source=f.source,
        )
        combined.append(annotated)

    # Add proxy findings not already covered by implementation findings
    impl_keys = {f.dedup_key() for f in combined}
    for f in proxy_findings:
        if f.dedup_key() not in impl_keys:
            combined.append(f)

    return deduplicate(combined)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort findings: high > medium > low, then alphabetically by name/selector."""
    return sorted(
        findings,
        key=lambda f: (
            -_RISK_ORDER.get(f.risk_level, 0),
            f.name or "",
            f.selector or "",
        ),
    )


def count_by_risk(findings: List[Finding]) -> Dict[str, int]:
    """Return a dict of {risk_level: count}."""
    counts: Dict[str, int] = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 0, RiskLevel.LOW: 0}
    for f in findings:
        if f.risk_level in counts:
            counts[f.risk_level] += 1
    return counts
