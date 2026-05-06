"""Merge SourceReports into the final ScanReport, with risk scoring.

The aggregator deliberately does not "rank" sources against one another.
HIBP Pwned Passwords is structurally different from a GitHub dork hit —
the first measures *credential weakness*, the second measures
*credential leakage*. Folding them into one mega-score would hide that
distinction. Instead the aggregator records every source's outcome
side-by-side and computes a small set of tallies that the reporter and
the AI summary can both build on."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from .findings import (
    FindingSeverity,
    ScanReport,
    SourceReport,
    SourceStatus,
)


def _utcnow_iso() -> str:
    """ISO-8601 UTC, second precision — easy to grep across logs."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _summarise(sources: list[SourceReport]) -> dict:
    """Compute the `summary` block of the final report."""
    severity_counts: Counter[str] = Counter()
    for src in sources:
        for f in src.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            severity_counts[sev] += 1

    sources_run, sources_skipped, sources_errored = 0, 0, 0
    for src in sources:
        s = src.status
        if s in (SourceStatus.OK, SourceStatus.NOT_FOUND):
            sources_run += 1
        elif s in (SourceStatus.NO_KEY, SourceStatus.LOCAL_FILE_MISSING):
            sources_skipped += 1
        else:
            sources_errored += 1

    total = sum(severity_counts.values())
    return {
        "total_findings": total,
        "by_severity": {
            "critical": severity_counts.get(FindingSeverity.CRITICAL.value, 0),
            "high":     severity_counts.get(FindingSeverity.HIGH.value, 0),
            "medium":   severity_counts.get(FindingSeverity.MEDIUM.value, 0),
            "low":      severity_counts.get(FindingSeverity.LOW.value, 0),
        },
        "sources_run": sources_run,
        "sources_skipped": sources_skipped,
        "sources_errored": sources_errored,
        "headline_severity": _headline(severity_counts),
    }


def _headline(counts: Counter[str]) -> str:
    """Return the highest severity present, or 'none'."""
    for sev in (FindingSeverity.CRITICAL, FindingSeverity.HIGH,
                FindingSeverity.MEDIUM, FindingSeverity.LOW):
        if counts.get(sev.value, 0) > 0:
            return sev.value
    return "none"


def aggregate(
    *,
    domain: str,
    sources: list[SourceReport],
    started_at: str | None = None,
) -> ScanReport:
    """Build the final ScanReport from a list of SourceReports."""
    return ScanReport(
        domain=domain,
        started_at=started_at or _utcnow_iso(),
        finished_at=_utcnow_iso(),
        sources=sources,
        summary=_summarise(sources),
    )
