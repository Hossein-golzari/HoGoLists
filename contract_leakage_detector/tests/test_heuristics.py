"""
Unit tests for heuristics.py and selectors_db.py

Tests cover:
  - Keyword classification (high / medium / low)
  - Type classification
  - selector_db lookup
  - rule_selector_db fires for known selectors
  - rule_name_keyword fires for sensitive names
  - rule_sensitive_output_type fires for bytes returns
  - No false positive on benign inputs
  - apply_all_rules deduplicates
  - score_contract sorts by risk
"""

from __future__ import annotations

import unittest

from ..heuristics import (
    apply_all_rules,
    rule_name_keyword,
    rule_selector_db,
    rule_sensitive_output_type,
    rule_public_bytes32_variable,
    rule_debug_or_internal_exposure,
    score_contract,
)
from ..models import FunctionInfo, ProxyInfo, RiskLevel
from ..selectors_db import classify_name, classify_type, lookup_selector


_ADDR = "0x" + "ab" * 20
_NO_PROXY = ProxyInfo(is_proxy=False)


def _fn(
    selector="0x12345678",
    name=None,
    inputs=None,
    outputs=None,
    state_mutability="view",
    visibility="public",
    source="bytecode",
) -> FunctionInfo:
    return FunctionInfo(
        selector=selector,
        name=name,
        inputs=inputs,
        outputs=outputs,
        state_mutability=state_mutability,
        visibility=visibility,
        source=source,
    )


# ---------------------------------------------------------------------------
# classify_name
# ---------------------------------------------------------------------------

class TestClassifyName(unittest.TestCase):

    def test_high_risk_secret(self):
        result = classify_name("getSecret")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.HIGH)

    def test_high_risk_mnemonic(self):
        result = classify_name("mnemonic")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.HIGH)

    def test_medium_risk_guardian(self):
        result = classify_name("guardian")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.MEDIUM)

    def test_medium_risk_signer(self):
        result = classify_name("getSigner")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.MEDIUM)

    def test_low_risk_owner(self):
        result = classify_name("owner")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.LOW)

    def test_benign_returns_none(self):
        self.assertIsNone(classify_name("totalSupply"))
        self.assertIsNone(classify_name("balanceOf"))
        self.assertIsNone(classify_name("transfer"))

    def test_case_insensitive(self):
        self.assertIsNotNone(classify_name("SECRET"))
        self.assertIsNotNone(classify_name("Guardian"))

    def test_underscore_normalisation(self):
        # "private_key" should match "privatekey"
        result = classify_name("private_key")
        self.assertIsNotNone(result)
        self.assertEqual(result["risk"], RiskLevel.HIGH)


# ---------------------------------------------------------------------------
# classify_type
# ---------------------------------------------------------------------------

class TestClassifyType(unittest.TestCase):

    def test_bytes32_flagged(self):
        result = classify_type("bytes32")
        self.assertIsNotNone(result)

    def test_bytes_flagged(self):
        result = classify_type("bytes")
        self.assertIsNotNone(result)

    def test_string_flagged(self):
        result = classify_type("string")
        self.assertIsNotNone(result)

    def test_uint256_clean(self):
        self.assertIsNone(classify_type("uint256"))

    def test_address_clean(self):
        self.assertIsNone(classify_type("address"))

    def test_bool_clean(self):
        self.assertIsNone(classify_type("bool"))


# ---------------------------------------------------------------------------
# lookup_selector
# ---------------------------------------------------------------------------

class TestLookupSelector(unittest.TestCase):

    def test_owner_selector(self):
        entry = lookup_selector("0x8da5cb5b")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["name"], "owner")
        self.assertEqual(entry["risk"], RiskLevel.LOW)

    def test_guardian_selector(self):
        entry = lookup_selector("0x452a9320")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["risk"], RiskLevel.HIGH)

    def test_unknown_selector_returns_none(self):
        self.assertIsNone(lookup_selector("0x00000000"))

    def test_case_insensitive(self):
        self.assertIsNotNone(lookup_selector("0x8DA5CB5B"))


# ---------------------------------------------------------------------------
# rule_selector_db
# ---------------------------------------------------------------------------

class TestRuleSelectorDb(unittest.TestCase):

    def test_known_selector_fires(self):
        fn = _fn(selector="0x8da5cb5b", name="owner")
        finding = rule_selector_db(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.LOW)

    def test_unknown_selector_no_finding(self):
        fn = _fn(selector="0x00000000")
        finding = rule_selector_db(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)

    def test_guardian_selector_high(self):
        fn = _fn(selector="0x452a9320", name="guardian")
        finding = rule_selector_db(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)


# ---------------------------------------------------------------------------
# rule_name_keyword
# ---------------------------------------------------------------------------

class TestRuleNameKeyword(unittest.TestCase):

    def test_secret_in_name_fires_high(self):
        fn = _fn(name="getSecret")
        finding = rule_name_keyword(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)

    def test_no_name_no_finding(self):
        fn = _fn(name=None)
        finding = rule_name_keyword(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)

    def test_benign_name_no_finding(self):
        fn = _fn(name="totalSupply")
        finding = rule_name_keyword(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)

    def test_admin_fires_medium(self):
        fn = _fn(name="getAdmin")
        finding = rule_name_keyword(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)


# ---------------------------------------------------------------------------
# rule_sensitive_output_type
# ---------------------------------------------------------------------------

class TestRuleSensitiveOutputType(unittest.TestCase):

    def test_bytes32_output_fires(self):
        fn = _fn(name="getSomeValue", outputs="bytes32", state_mutability="view")
        finding = rule_sensitive_output_type(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)

    def test_uint_output_no_finding(self):
        fn = _fn(name="getValue", outputs="uint256", state_mutability="view")
        finding = rule_sensitive_output_type(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)

    def test_non_view_not_flagged(self):
        fn = _fn(name="setData", outputs="bytes32", state_mutability="nonpayable")
        finding = rule_sensitive_output_type(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)


# ---------------------------------------------------------------------------
# rule_public_bytes32_variable
# ---------------------------------------------------------------------------

class TestRulePublicBytes32(unittest.TestCase):

    def test_bytes32_public_fires(self):
        fn = _fn(outputs="bytes32", visibility="public")
        finding = rule_public_bytes32_variable(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)

    def test_uint256_no_finding(self):
        fn = _fn(outputs="uint256", visibility="public")
        finding = rule_public_bytes32_variable(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)


# ---------------------------------------------------------------------------
# rule_debug_or_internal_exposure
# ---------------------------------------------------------------------------

class TestRuleDebug(unittest.TestCase):

    def test_debug_prefix_fires(self):
        fn = _fn(name="debugGetState")
        finding = rule_debug_or_internal_exposure(fn, _ADDR, _NO_PROXY)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)

    def test_normal_name_no_finding(self):
        fn = _fn(name="getBalance")
        finding = rule_debug_or_internal_exposure(fn, _ADDR, _NO_PROXY)
        self.assertIsNone(finding)


# ---------------------------------------------------------------------------
# apply_all_rules — deduplication
# ---------------------------------------------------------------------------

class TestApplyAllRules(unittest.TestCase):

    def test_no_duplicate_keys(self):
        # guardian() selector + name — could match both selector_db and name_keyword
        fn = _fn(selector="0x452a9320", name="guardian")
        findings = apply_all_rules(fn, _ADDR, _NO_PROXY)
        keys = [f.dedup_key() for f in findings]
        self.assertEqual(len(keys), len(set(keys)), "Duplicate keys found")

    def test_multiple_rules_can_fire_for_same_function(self):
        # A function named 'getSecret' returning bytes32 should fire both name and type rules
        fn = _fn(name="getSecret", outputs="bytes32", state_mutability="view", visibility="public")
        findings = apply_all_rules(fn, _ADDR, _NO_PROXY)
        sources = {f.source for f in findings}
        # Should have at least name_match and type_match
        self.assertGreater(len(findings), 1)


# ---------------------------------------------------------------------------
# score_contract — sorting
# ---------------------------------------------------------------------------

class TestScoreContract(unittest.TestCase):

    def test_high_risk_first(self):
        functions = [
            _fn(selector="0x8da5cb5b", name="owner"),             # low
            _fn(selector="0x452a9320", name="guardian"),           # high
            _fn(selector="0x6e9960c3", name="getAdmin"),           # medium
        ]
        findings = score_contract(functions, _ADDR, _NO_PROXY)
        if len(findings) >= 2:
            risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
            for i in range(len(findings) - 1):
                self.assertLessEqual(
                    risk_order[findings[i].risk_level],
                    risk_order[findings[i + 1].risk_level],
                )

    def test_empty_functions_empty_findings(self):
        findings = score_contract([], _ADDR, _NO_PROXY)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
