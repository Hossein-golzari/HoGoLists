"""
Rule-based heuristic engine for detecting potentially sensitive view/getter functions.

All scoring functions are pure Python — no RPC calls, no I/O.
Each rule returns a Finding or None; rules are composed in apply_all_rules().
"""

from __future__ import annotations

import logging
from typing import List, Optional

from .models import Finding, FunctionInfo, ProxyInfo, RiskLevel
from .selectors_db import (
    HIGH_RISK_KEYWORDS,
    MEDIUM_RISK_KEYWORDS,
    LOW_RISK_KEYWORDS,
    DEBUG_KEYWORDS,
    SENSITIVE_OUTPUT_TYPES,
    classify_name,
    classify_type,
    lookup_selector,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Individual rule functions
# ---------------------------------------------------------------------------

def rule_selector_db(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """Rule 1: selector present in the known sensitive selector database."""
    if fn.selector is None:
        return None
    entry = lookup_selector(fn.selector)
    if entry is None:
        return None
    # ERC standards at low risk are less interesting — still include them but keep low
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=entry.get("name") or fn.name,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason=entry.get("reason", "Known sensitive selector"),
        risk_level=entry.get("risk", RiskLevel.LOW),
        explanation=(
            f"Selector {fn.selector} matches known signature '{entry.get('sig', '')}'. "
            + entry.get("reason", "")
        ),
        source="selector_db",
    )


def rule_name_keyword(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """Rule 2: function/variable name contains a sensitive keyword."""
    name = fn.name
    if not name:
        return None
    classification = classify_name(name)
    if classification is None:
        return None
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=name,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason=classification["reason"],
        risk_level=classification["risk"],
        explanation=(
            f"Function '{name}' ({fn.selector or 'unknown selector'}) "
            f"matched keyword '{classification.get('matched_keyword', '')}'. "
            f"State mutability: {fn.state_mutability or 'unknown'}."
        ),
        source="name_match",
    )


def rule_sensitive_output_type(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 3: view/pure function returns a bytes or string type.
    Only flag when the function is also view/pure (not a state-mutating function
    that happens to return bytes).
    """
    if fn.state_mutability not in ("view", "pure", None):
        return None
    if fn.outputs is None:
        return None

    # Check each output type
    for output_type in fn.outputs.split(","):
        output_type = output_type.strip()
        classification = classify_type(output_type)
        if classification:
            return Finding(
                contract_address=contract_address,
                proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
                implementation_address=proxy_info.implementation_address if proxy_info else None,
                name=fn.name,
                selector=fn.selector,
                visibility=fn.visibility,
                type_info=fn.outputs,
                heuristic_reason=classification["reason"],
                risk_level=classification["risk"],
                explanation=(
                    f"Function '{fn.name or fn.selector}' returns '{output_type}', "
                    f"which can carry arbitrary byte data. "
                    f"{classification['reason']}. "
                    f"Inspect what data is actually returned."
                ),
                source="type_match",
            )
    return None


def rule_public_bytes32_variable(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 4: public state variable of type bytes32 — auto-generated getter.
    bytes32 is a common type for secrets, hashes, and keys stored on-chain.
    """
    if fn.outputs not in ("bytes32", "bytes"):
        return None
    if fn.visibility not in ("public", None):
        return None
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=fn.name,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason=f"Public {fn.outputs} variable/getter exposes raw byte data",
        risk_level=RiskLevel.MEDIUM,
        explanation=(
            f"'{fn.name or fn.selector}' is a public {fn.outputs} getter. "
            f"bytes32/bytes fields are commonly used to store hashes, keys, "
            f"or Merkle roots. Verify that the value is safe to expose publicly."
        ),
        source="type_match",
    )


def rule_struct_with_sensitive_fields(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 5: if we have ABI info and a function returns a tuple (struct),
    check if any output field name is sensitive.
    (Requires ABI-level info in fn.outputs as "tuple(field1,field2,...)")
    """
    outputs = fn.outputs or ""
    if not outputs.startswith("(") or fn.name is None:
        return None
    # Check each field name in the struct via the function name heuristic
    classification = classify_name(fn.name)
    if classification and classification["risk"] in (RiskLevel.HIGH, RiskLevel.MEDIUM):
        return Finding(
            contract_address=contract_address,
            proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
            implementation_address=proxy_info.implementation_address if proxy_info else None,
            name=fn.name,
            selector=fn.selector,
            visibility=fn.visibility,
            type_info=fn.outputs,
            heuristic_reason="Struct-returning function has sensitive name",
            risk_level=classification["risk"],
            explanation=(
                f"'{fn.name}' returns a struct and has a sensitive name. "
                f"Struct may bundle privileged addresses, keys, or config values."
            ),
            source="name_match",
        )
    return None


def rule_mapping_sensitive_value(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 6: public mapping whose value is bytes32/bytes/string — auto-generated getter
    exposes the value for any queried key.
    """
    outputs = fn.outputs or ""
    # Mapping getters typically just return the value type
    if outputs not in ("bytes32", "bytes", "string"):
        return None
    # Disambiguate from regular state vars: mappings usually have inputs
    if not fn.inputs:
        return None
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=fn.name,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason=f"Public mapping returns {outputs} — arbitrary key enumeration possible",
        risk_level=RiskLevel.MEDIUM,
        explanation=(
            f"Mapping getter '{fn.name or fn.selector}' returns raw {outputs} values. "
            f"Callers can query arbitrary keys. If values include credentials or keys, "
            f"this is a critical information leak."
        ),
        source="type_match",
    )


def rule_proxy_admin_exposure(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 7: function exposes proxy admin — upgradeability attack surface.
    """
    if fn.name is None:
        return None
    name_lower = fn.name.lower()
    if not any(kw in name_lower for kw in ("admin", "proxyadmin", "upgrader")):
        return None
    if fn.state_mutability not in ("view", "pure", None):
        return None
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=fn.name,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason="Admin/upgrader address exposed via view function",
        risk_level=RiskLevel.MEDIUM,
        explanation=(
            f"'{fn.name}' exposes an admin or upgrade-controller address. "
            f"Attackers can use this to identify and target the admin account."
        ),
        source="name_match",
    )


def rule_debug_or_internal_exposure(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 8: function name suggests debug/test access to internal state.
    """
    if fn.name is None:
        return None
    name_lower = fn.name.lower().replace("_", "").replace("-", "")
    for kw in DEBUG_KEYWORDS:
        if kw.replace("_", "").replace("-", "") in name_lower:
            return Finding(
                contract_address=contract_address,
                proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
                implementation_address=proxy_info.implementation_address if proxy_info else None,
                name=fn.name,
                selector=fn.selector,
                visibility=fn.visibility,
                type_info=fn.outputs,
                heuristic_reason=f"Debug/test function '{fn.name}' exposes internal state",
                risk_level=RiskLevel.MEDIUM,
                explanation=(
                    f"'{fn.name}' appears to be a debug or test helper that should not "
                    f"be publicly accessible in production. Verify this is intentional."
                ),
                source="name_match",
            )
    return None


# ---------------------------------------------------------------------------
# Bytecode-level (no name available) heuristics
# ---------------------------------------------------------------------------

def rule_unknown_selector_returns_bytes(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> Optional[Finding]:
    """
    Rule 9: Unknown selector (no name in DB) that appears to return bytes.
    Only applies when fn.name is None (pure bytecode mode).
    """
    if fn.name is not None:
        return None  # Already covered by name/type rules
    if fn.outputs not in ("bytes32", "bytes"):
        return None
    return Finding(
        contract_address=contract_address,
        proxy_address=None if not (proxy_info and proxy_info.is_proxy) else contract_address,
        implementation_address=proxy_info.implementation_address if proxy_info else None,
        name=None,
        selector=fn.selector,
        visibility=fn.visibility,
        type_info=fn.outputs,
        heuristic_reason="Unidentified view function returns raw bytes",
        risk_level=RiskLevel.LOW,
        explanation=(
            f"Selector {fn.selector} has no known name but appears to return bytes. "
            f"Manual review recommended to determine what data is exposed."
        ),
        source="bytecode_pattern",
    )


# ---------------------------------------------------------------------------
# Compose all rules
# ---------------------------------------------------------------------------

_RULES = [
    rule_selector_db,
    rule_name_keyword,
    rule_sensitive_output_type,
    rule_public_bytes32_variable,
    rule_struct_with_sensitive_fields,
    rule_mapping_sensitive_value,
    rule_proxy_admin_exposure,
    rule_debug_or_internal_exposure,
    rule_unknown_selector_returns_bytes,
]


def apply_all_rules(
    fn: FunctionInfo,
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> List[Finding]:
    """
    Apply every rule to *fn* and return all non-None findings.
    Duplicate findings (same selector + same heuristic_reason) are deduplicated here.
    """
    seen: set = set()
    findings: List[Finding] = []
    for rule in _RULES:
        try:
            finding = rule(fn, contract_address, proxy_info)
        except Exception as exc:
            log.debug("Rule %s raised for %s: %s", rule.__name__, fn.selector, exc)
            continue
        if finding is None:
            continue
        key = finding.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)
    return findings


def score_contract(
    functions: List[FunctionInfo],
    contract_address: str,
    proxy_info: Optional[ProxyInfo],
) -> List[Finding]:
    """
    Run heuristics across all functions and return deduplicated, priority-sorted findings.
    """
    all_findings: List[Finding] = []
    seen_keys: set = set()

    for fn in functions:
        for finding in apply_all_rules(fn, contract_address, proxy_info):
            key = finding.dedup_key()
            if key not in seen_keys:
                seen_keys.add(key)
                all_findings.append(finding)

    # Sort: high > medium > low, then by selector
    risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
    all_findings.sort(key=lambda f: (risk_order.get(f.risk_level, 3), f.selector or ""))
    return all_findings
