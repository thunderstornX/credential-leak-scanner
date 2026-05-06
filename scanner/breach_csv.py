"""Local synthetic breach CSV cross-reference.

Reads a CSV with columns ``email,sha1,source,breach_date`` and reports
any row whose ``email`` column matches one of the queried accounts. The
default fixture ships with 100 clearly-synthetic rows under
``tests/fixtures/sample_breach_data.csv`` — every email is at the
domain ``example.invalid`` (RFC 6761 reserved) and every SHA-1 is the
hash of a synthetic, non-real password label.

This module is here for two reasons:
  1. It demonstrates the cross-reference pattern that real defenders use
     when they have access to a paid breach corpus (DeHashed, IntelX,
     Constella) without the tool itself ever shipping real breach data.
  2. It gives the eval harness a deterministic source whose results
     don't depend on the network."""
from __future__ import annotations

import csv
import time
from pathlib import Path
from typing import Iterable

from config import Settings
from .findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)


_SOURCE = "breach_csv"


def _normalise(email: str) -> str:
    """Lower-case + strip — no Unicode normalisation needed for fixtures."""
    return email.strip().lower()


def scan_csv(
    settings: Settings,
    accounts: Iterable[str],
    *,
    csv_path: Path | None = None,
) -> SourceReport:
    """Look each account up in the local synthetic breach CSV."""
    path = Path(csv_path) if csv_path else settings.local_breach_csv
    if not path.exists():
        return SourceReport(
            source=_SOURCE,
            status=SourceStatus.LOCAL_FILE_MISSING,
            note=(f"skipped: local breach CSV not found at {path}. The "
                   "shipped fixture lives at "
                   "tests/fixtures/sample_breach_data.csv."),
        )

    started = time.perf_counter()
    targets = {_normalise(a) for a in accounts}
    findings: list[Finding] = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            email = _normalise(row.get("email", ""))
            if not email or email not in targets:
                continue
            findings.append(Finding(
                source=_SOURCE,
                target=email,
                # Local match is HIGH — we know exactly which corpus and
                # date the record came from, no ambiguity.
                severity=FindingSeverity.HIGH,
                detail=(
                    f"account {email!r} present in synthetic breach "
                    f"corpus {row.get('source', '?')!r} "
                    f"(BreachDate {row.get('breach_date', '?')})"),
                evidence={
                    "source_corpus": row.get("source"),
                    "breach_date": row.get("breach_date"),
                    "sha1_present": bool(row.get("sha1")),
                },
            ))

    return SourceReport(
        source=_SOURCE,
        status=SourceStatus.OK if findings else SourceStatus.NOT_FOUND,
        findings=findings,
        note=None,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
