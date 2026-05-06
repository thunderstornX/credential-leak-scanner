"""HIBP Breached-Accounts client (keyed endpoint, optional).

The endpoint at ``/api/v3/breachedaccount/{account}`` requires the
``hibp-api-key`` header and is rate-limited at one request per 1.5
seconds per HIBP's posted terms. Without a key, this module short-
circuits to ``SourceStatus.NO_KEY`` so the rest of the pipeline still
runs."""
from __future__ import annotations

import time
import urllib.parse
from typing import Iterable

import httpx

from config import Settings
from .findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)


_SOURCE = "hibp_accounts"


def _severity_for_breach(breach: dict) -> FindingSeverity:
    """Bump severity if the breach record self-reports as recent.

    HIBP records carry a ``BreachDate`` (YYYY-MM-DD). A breach within
    the last 24 months is marked CRITICAL because that is the window in
    which credential-stuffing tooling is still actively replaying the
    corpus; older breaches drop to HIGH because the password is almost
    certainly already on every wordlist."""
    date = breach.get("BreachDate") or ""
    year_str = date[:4]
    if not year_str.isdigit():
        return FindingSeverity.HIGH
    breach_year = int(year_str)
    # 2026 minus 2 == 2024; conservative recency threshold.
    if breach_year >= 2024:
        return FindingSeverity.CRITICAL
    return FindingSeverity.HIGH


def scan_accounts(
    settings: Settings,
    accounts: Iterable[str],
    *,
    client: httpx.Client | None = None,
) -> SourceReport:
    """Look each account up against HIBP's breached-account endpoint."""
    if not settings.hibp_api_key:
        return SourceReport(
            source=_SOURCE,
            status=SourceStatus.NO_KEY,
            note=("skipped: HIBP_API_KEY not set. Set it in .env to enable "
                  "the keyed breached-account lookup."),
        )

    findings: list[Finding] = []
    started = time.perf_counter()
    owns = client is None
    client = client or httpx.Client(timeout=15.0)
    headers = {
        "hibp-api-key": settings.hibp_api_key,
        "User-Agent": "credential-leak-scanner/0.1",
        "Accept": "application/json",
    }
    try:
        for acct in accounts:
            quoted = urllib.parse.quote(acct, safe="")
            url = f"{settings.hibp_accounts_base}/{quoted}"
            try:
                r = client.get(url, headers=headers,
                                params={"truncateResponse": "false"})
            except httpx.HTTPError as exc:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.NETWORK_ERROR,
                    findings=findings,
                    note=f"network: {exc.__class__.__name__}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )
            if r.status_code == 404:
                # Per HIBP docs: 404 means "not found in any breach".
                # That is a *clean* result, not an error.
                continue
            if r.status_code >= 400:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.HTTP_ERROR,
                    findings=findings,
                    note=f"HIBP returned HTTP {r.status_code}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )

            for breach in (r.json() or []):
                findings.append(Finding(
                    source=_SOURCE,
                    target=acct,
                    severity=_severity_for_breach(breach),
                    detail=(
                        f"account {acct!r} found in HIBP breach "
                        f"{breach.get('Name', '?')} "
                        f"(BreachDate {breach.get('BreachDate', '?')})"),
                    evidence={
                        "breach_name": breach.get("Name"),
                        "breach_date": breach.get("BreachDate"),
                        "data_classes": breach.get("DataClasses", []),
                    },
                ))
            # Politely sleep between calls per HIBP ToS.
            time.sleep(settings.hibp_polite_sleep_s)

        return SourceReport(
            source=_SOURCE,
            status=SourceStatus.OK if findings else SourceStatus.NOT_FOUND,
            findings=findings,
            note=None,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )
    finally:
        if owns:
            client.close()
