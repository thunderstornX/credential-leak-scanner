"""Tests for the aggregator's summary roll-up."""
from __future__ import annotations

from scanner.aggregator import aggregate
from scanner.findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)


def _make_finding(sev: FindingSeverity, src: str = "x") -> Finding:
    return Finding(source=src, target="t", severity=sev, detail="...")


def test_aggregate_counts_severities():
    reports = [
        SourceReport(source="a", status=SourceStatus.OK, findings=[
            _make_finding(FindingSeverity.CRITICAL),
            _make_finding(FindingSeverity.MEDIUM),
        ]),
        SourceReport(source="b", status=SourceStatus.OK, findings=[
            _make_finding(FindingSeverity.HIGH),
        ]),
    ]
    out = aggregate(domain="example.com", sources=reports)
    s = out.summary
    assert s["total_findings"] == 3
    assert s["by_severity"] == {
        "critical": 1, "high": 1, "medium": 1, "low": 0,
    }
    assert s["headline_severity"] == "critical"


def test_aggregate_distinguishes_skipped_from_errored():
    reports = [
        SourceReport(source="a", status=SourceStatus.NO_KEY),
        SourceReport(source="b", status=SourceStatus.LOCAL_FILE_MISSING),
        SourceReport(source="c", status=SourceStatus.HTTP_ERROR),
        SourceReport(source="d", status=SourceStatus.NETWORK_ERROR),
        SourceReport(source="e", status=SourceStatus.NOT_FOUND),
        SourceReport(source="f", status=SourceStatus.OK,
                     findings=[_make_finding(FindingSeverity.LOW)]),
    ]
    out = aggregate(domain="x", sources=reports)
    s = out.summary
    assert s["sources_skipped"] == 2
    assert s["sources_errored"] == 2
    assert s["sources_run"] == 2  # NOT_FOUND + OK both count as 'ran'
    assert s["headline_severity"] == "low"


def test_aggregate_headline_none_when_empty():
    out = aggregate(domain="x", sources=[])
    assert out.summary["headline_severity"] == "none"
    assert out.summary["total_findings"] == 0
