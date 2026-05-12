"""
Unit tests for dedup.py

Tests cover:
  - Basic deduplication of identical findings
  - Higher-risk version wins when duplicates exist
  - merge_proxy_and_impl annotates and deduplicates correctly
  - count_by_risk tallies correctly
  - sort_findings orders high > medium > low
"""

from __future__ import annotations

import unittest

from ..dedup import count_by_risk, deduplicate, merge_proxy_and_impl, sort_findings
from ..models import Finding, RiskLevel


_ADDR = "0x" + "ab" * 20
_IMPL = "0x" + "cd" * 20
_PROXY = "0x" + "ef" * 20


def _finding(
    contract=_ADDR,
    proxy=None,
    impl=None,
    name="owner",
    selector="0x8da5cb5b",
    risk=RiskLevel.LOW,
    reason="test reason",
) -> Finding:
    return Finding(
        contract_address=contract,
        proxy_address=proxy,
        implementation_address=impl,
        name=name,
        selector=selector,
        visibility="public",
        type_info=None,
        heuristic_reason=reason,
        risk_level=risk,
        explanation=f"Explanation for {name}",
        source="test",
    )


class TestDeduplicate(unittest.TestCase):

    def test_empty_list(self):
        self.assertEqual(deduplicate([]), [])

    def test_no_duplicates_unchanged(self):
        f1 = _finding(selector="0x11111111", reason="r1")
        f2 = _finding(selector="0x22222222", reason="r2")
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)

    def test_exact_duplicate_removed(self):
        f1 = _finding(selector="0x8da5cb5b", reason="reason")
        f2 = _finding(selector="0x8da5cb5b", reason="reason")
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)

    def test_higher_risk_wins(self):
        low = _finding(selector="0x8da5cb5b", reason="reason", risk=RiskLevel.LOW)
        high = _finding(selector="0x8da5cb5b", reason="reason", risk=RiskLevel.HIGH)
        result = deduplicate([low, high])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].risk_level, RiskLevel.HIGH)

    def test_higher_risk_wins_reverse_order(self):
        high = _finding(selector="0x8da5cb5b", reason="reason", risk=RiskLevel.HIGH)
        low = _finding(selector="0x8da5cb5b", reason="reason", risk=RiskLevel.LOW)
        result = deduplicate([high, low])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].risk_level, RiskLevel.HIGH)

    def test_different_reasons_both_kept(self):
        f1 = _finding(selector="0x8da5cb5b", reason="reason_one")
        f2 = _finding(selector="0x8da5cb5b", reason="reason_two")
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)

    def test_different_selectors_both_kept(self):
        f1 = _finding(selector="0x8da5cb5b", reason="reason")
        f2 = _finding(selector="0xf851a440", reason="reason")
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)


class TestMergeProxyAndImpl(unittest.TestCase):

    def test_impl_findings_annotated_with_proxy(self):
        impl_finding = _finding(
            contract=_IMPL, selector="0x452a9320", reason="guardian"
        )
        result = merge_proxy_and_impl(
            proxy_findings=[],
            impl_findings=[impl_finding],
            proxy_address=_PROXY,
            impl_address=_IMPL,
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].proxy_address, _PROXY)
        self.assertEqual(result[0].implementation_address, _IMPL)
        self.assertIn(_PROXY, result[0].explanation)

    def test_proxy_only_finding_included(self):
        proxy_finding = _finding(
            contract=_PROXY, selector="0x5c60da1b", reason="implementation exposed"
        )
        result = merge_proxy_and_impl(
            proxy_findings=[proxy_finding],
            impl_findings=[],
            proxy_address=_PROXY,
            impl_address=_IMPL,
        )
        self.assertEqual(len(result), 1)

    def test_duplicate_between_proxy_and_impl_deduplicated(self):
        # Same selector + reason in both proxy and impl findings
        proxy_finding = _finding(
            contract=_PROXY, impl=_IMPL, selector="0x8da5cb5b", reason="owner exposed"
        )
        impl_finding = _finding(
            contract=_IMPL, selector="0x8da5cb5b", reason="owner exposed"
        )
        result = merge_proxy_and_impl(
            proxy_findings=[proxy_finding],
            impl_findings=[impl_finding],
            proxy_address=_PROXY,
            impl_address=_IMPL,
        )
        self.assertEqual(len(result), 1)

    def test_different_findings_both_included(self):
        proxy_f = _finding(
            contract=_PROXY, selector="0x5c60da1b", reason="proxy impl"
        )
        impl_f = _finding(
            contract=_IMPL, selector="0x452a9320", reason="guardian"
        )
        result = merge_proxy_and_impl(
            proxy_findings=[proxy_f],
            impl_findings=[impl_f],
            proxy_address=_PROXY,
            impl_address=_IMPL,
        )
        self.assertEqual(len(result), 2)


class TestCountByRisk(unittest.TestCase):

    def test_empty(self):
        counts = count_by_risk([])
        self.assertEqual(counts[RiskLevel.HIGH], 0)
        self.assertEqual(counts[RiskLevel.MEDIUM], 0)
        self.assertEqual(counts[RiskLevel.LOW], 0)

    def test_mixed(self):
        findings = [
            _finding(risk=RiskLevel.HIGH),
            _finding(risk=RiskLevel.HIGH, selector="0x11111111"),
            _finding(risk=RiskLevel.MEDIUM, selector="0x22222222"),
            _finding(risk=RiskLevel.LOW, selector="0x33333333"),
        ]
        counts = count_by_risk(findings)
        self.assertEqual(counts[RiskLevel.HIGH], 2)
        self.assertEqual(counts[RiskLevel.MEDIUM], 1)
        self.assertEqual(counts[RiskLevel.LOW], 1)


class TestSortFindings(unittest.TestCase):

    def test_high_before_medium_before_low(self):
        findings = [
            _finding(risk=RiskLevel.LOW, selector="0x11111111"),
            _finding(risk=RiskLevel.HIGH, selector="0x22222222"),
            _finding(risk=RiskLevel.MEDIUM, selector="0x33333333"),
        ]
        sorted_f = sort_findings(findings)
        self.assertEqual(sorted_f[0].risk_level, RiskLevel.HIGH)
        self.assertEqual(sorted_f[1].risk_level, RiskLevel.MEDIUM)
        self.assertEqual(sorted_f[2].risk_level, RiskLevel.LOW)


if __name__ == "__main__":
    unittest.main()
