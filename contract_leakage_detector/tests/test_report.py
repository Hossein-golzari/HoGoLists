"""
Unit tests for report.py

Tests cover:
  - JSON serialisation is valid and contains expected keys
  - Markdown contains contract address and findings
  - CSV contains header row and finding rows
  - console_summary includes HIGH findings
  - Empty scan (no findings) generates valid output
"""

from __future__ import annotations

import csv
import io
import json
import unittest
from datetime import datetime, timezone

from ..models import ContractAnalysis, Finding, ProxyInfo, RiskLevel, ScanReport
from ..report import console_summary, to_csv, to_json, to_markdown


_ADDR = "0x" + "ab" * 20
_IMPL = "0x" + "cd" * 20


def _make_finding(risk=RiskLevel.HIGH, selector="0x452a9320", name="guardian") -> Finding:
    return Finding(
        contract_address=_ADDR,
        proxy_address=None,
        implementation_address=None,
        name=name,
        selector=selector,
        visibility="public",
        type_info=None,
        heuristic_reason="Test reason",
        risk_level=risk,
        explanation="Test explanation",
        source="test",
    )


def _make_analysis(findings=None, is_eoa=False, error=None) -> ContractAnalysis:
    return ContractAnalysis(
        address=_ADDR,
        chain_id=1,
        block_number=19_000_000,
        bytecode_hex="0x" + "60" * 10,
        is_eoa=is_eoa,
        proxy_info=ProxyInfo(is_proxy=False),
        selectors=["0x8da5cb5b"],
        functions=[],
        findings=findings or [],
        error=error,
        duration_ms=42.5,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
    )


def _make_report(findings=None, is_eoa=False) -> ScanReport:
    analysis = _make_analysis(findings=findings, is_eoa=is_eoa)
    f_list = findings or []
    highs = sum(1 for f in f_list if f.risk_level == RiskLevel.HIGH)
    meds = sum(1 for f in f_list if f.risk_level == RiskLevel.MEDIUM)
    lows = sum(1 for f in f_list if f.risk_level == RiskLevel.LOW)
    return ScanReport(
        chain_id=1,
        rpc_url="http://localhost:8545",
        block_number=19_000_000,
        total_contracts=1,
        analyzed=0 if is_eoa else 1,
        eoas_skipped=1 if is_eoa else 0,
        errors=0,
        total_findings=len(f_list),
        high_findings=highs,
        medium_findings=meds,
        low_findings=lows,
        results=[analysis],
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

class TestToJSON(unittest.TestCase):

    def test_valid_json(self):
        report = _make_report()
        raw = to_json(report)
        data = json.loads(raw)  # must not raise
        self.assertIn("chain_id", data)
        self.assertIn("results", data)
        self.assertIn("summary", data)

    def test_findings_included(self):
        finding = _make_finding()
        report = _make_report(findings=[finding])
        data = json.loads(to_json(report))
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["summary"]["high"], 1)
        results = data["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]["findings"]), 1)
        self.assertEqual(results[0]["findings"][0]["risk_level"], RiskLevel.HIGH)

    def test_empty_report(self):
        report = _make_report(findings=[])
        data = json.loads(to_json(report))
        self.assertEqual(data["summary"]["total_findings"], 0)
        self.assertEqual(data["results"][0]["findings"], [])

    def test_eoa_report(self):
        report = _make_report(is_eoa=True)
        data = json.loads(to_json(report))
        self.assertTrue(data["results"][0]["is_eoa"])


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

class TestToMarkdown(unittest.TestCase):

    def test_contains_address(self):
        report = _make_report()
        md = to_markdown(report)
        self.assertIn(_ADDR, md)

    def test_contains_findings_table(self):
        finding = _make_finding()
        report = _make_report(findings=[finding])
        md = to_markdown(report)
        self.assertIn("guardian", md)
        self.assertIn("HIGH", md)
        self.assertIn("Test reason", md)

    def test_no_findings_shows_placeholder(self):
        report = _make_report(findings=[])
        md = to_markdown(report)
        self.assertIn("No findings", md)

    def test_summary_table_present(self):
        report = _make_report()
        md = to_markdown(report)
        self.assertIn("Chain ID", md)
        self.assertIn("Contracts scanned", md)

    def test_disclaimer_present(self):
        report = _make_report()
        md = to_markdown(report)
        self.assertIn("defensive review only", md)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

class TestToCSV(unittest.TestCase):

    def test_csv_header_present(self):
        report = _make_report()
        raw = to_csv(report)
        reader = csv.DictReader(io.StringIO(raw))
        self.assertIn("contract_address", reader.fieldnames)
        self.assertIn("risk_level", reader.fieldnames)
        self.assertIn("heuristic_reason", reader.fieldnames)

    def test_csv_finding_row(self):
        finding = _make_finding(risk=RiskLevel.MEDIUM, name="admin")
        report = _make_report(findings=[finding])
        raw = to_csv(report)
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["risk_level"], RiskLevel.MEDIUM)
        self.assertEqual(rows[0]["name"], "admin")

    def test_csv_no_findings_header_only(self):
        report = _make_report(findings=[])
        raw = to_csv(report)
        reader = csv.DictReader(io.StringIO(raw))
        rows = list(reader)
        self.assertEqual(rows, [])


# ---------------------------------------------------------------------------
# Console summary
# ---------------------------------------------------------------------------

class TestConsoleSummary(unittest.TestCase):

    def test_contains_counts(self):
        finding = _make_finding(risk=RiskLevel.HIGH)
        report = _make_report(findings=[finding])
        summary = console_summary(report)
        self.assertIn("1 HIGH", summary)

    def test_high_findings_listed(self):
        finding = _make_finding(risk=RiskLevel.HIGH, name="guardian")
        report = _make_report(findings=[finding])
        summary = console_summary(report)
        self.assertIn("guardian", summary)
        self.assertIn("HIGH-risk", summary)

    def test_no_high_findings_no_high_section(self):
        finding = _make_finding(risk=RiskLevel.LOW, name="owner")
        report = _make_report(findings=[finding])
        summary = console_summary(report)
        self.assertNotIn("HIGH-risk findings", summary)

    def test_chain_id_in_summary(self):
        report = _make_report()
        summary = console_summary(report)
        self.assertIn("chain 1", summary)


if __name__ == "__main__":
    unittest.main()
