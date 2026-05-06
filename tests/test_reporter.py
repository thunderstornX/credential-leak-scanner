"""Tests for the JSON reporter and AI-summary fallback."""
from __future__ import annotations

import json

import httpx
import respx

from scanner.aggregator import aggregate
from scanner.findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)
from scanner.reporter import (
    _ANTHROPIC_URL,
    _deterministic_summary,
    render_report,
)


def _sample_report():
    findings = [
        Finding(source="hibp_passwords", target="x",
                severity=FindingSeverity.CRITICAL,
                detail="appears in breach"),
    ]
    sources = [
        SourceReport(source="hibp_passwords", status=SourceStatus.OK,
                     findings=findings),
        SourceReport(source="github_dorks", status=SourceStatus.NO_KEY),
    ]
    return aggregate(domain="example.com", sources=sources)


def test_render_report_writes_valid_json(tmp_path):
    out = render_report(_sample_report(), output_path=tmp_path / "r.json")
    data = json.loads(out.read_text())
    assert data["domain"] == "example.com"
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["headline_severity"] == "critical"
    # Source enum should serialise to its .value string.
    assert data["sources"][1]["status"] == "no_key"


def test_deterministic_summary_uses_findings_only():
    report = _sample_report()
    text = _deterministic_summary(report)
    assert "example.com" in text
    assert "1 finding" in text or "1 critical" in text
    assert "deterministic mode" in text


def test_render_report_falls_back_when_no_anthropic_key(
        tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = _sample_report()
    out = render_report(report, output_path=tmp_path / "r.json",
                         ai_summary=True)
    data = json.loads(out.read_text())
    assert data["ai_summary"]
    assert "deterministic mode" in data["ai_summary"]


def test_render_report_uses_anthropic_when_key_present(tmp_path,
                                                         monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with respx.mock(assert_all_called=False) as router:
        router.post(_ANTHROPIC_URL).mock(return_value=httpx.Response(
            200,
            json={"content": [
                {"type": "text",
                 "text": "AI-generated brief: critical issue."}
            ]}))
        report = _sample_report()
        out = render_report(report, output_path=tmp_path / "r.json",
                             ai_summary=True)
    data = json.loads(out.read_text())
    assert data["ai_summary"] == "AI-generated brief: critical issue."


def test_render_report_falls_back_when_anthropic_5xx(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with respx.mock(assert_all_called=False) as router:
        router.post(_ANTHROPIC_URL).mock(return_value=httpx.Response(
            500, text="server error"))
        report = _sample_report()
        out = render_report(report, output_path=tmp_path / "r.json",
                             ai_summary=True)
    data = json.loads(out.read_text())
    assert "deterministic mode" in data["ai_summary"]
