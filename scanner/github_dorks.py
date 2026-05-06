"""GitHub code-search dork scanner.

Runs a fixed list of credential-exposure dorks against GitHub's code
search API for a given target domain. The four dorks below are the same
patterns that defenders, security researchers, and the GitHub
secret-scanning team itself look for; what we add is structure and
rate-limit politeness.

GitHub's free-tier search cap is 10 req/min unauthenticated, 30 req/min
authenticated. We sleep ``github_polite_sleep_s`` (default 6.5s) between
calls so a four-dork sweep finishes in ~30s and stays well under both
ceilings."""
from __future__ import annotations

import time
from typing import Any

import httpx

from config import Settings
from .findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)


_SOURCE = "github_dorks"

# Each entry is (label, search_qualifier). The CLI passes the target
# domain in literally; GitHub treats it as a quoted phrase. Add to this
# list cautiously — every entry costs one rate-limited call.
_DORKS: list[tuple[str, str]] = [
    ("env_file",   'filename:.env'),
    ("password",   'password'),
    ("api_key",    'api_key'),
    ("secret",     'secret'),
]

# How many search results we keep per dork. GitHub returns up to 100 per
# page; 10 is plenty for a per-finding evidence trail without flooding
# the JSON report.
_PER_DORK_RESULT_CAP = 10


def _severity_for_dork(label: str, total_count: int) -> FindingSeverity:
    """High-impact dork (`env_file`) is HIGH; the others scale by hits."""
    if label == "env_file" and total_count > 0:
        return FindingSeverity.HIGH
    if total_count >= 10:
        return FindingSeverity.HIGH
    if total_count >= 1:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


def _build_query(domain: str, qualifier: str) -> str:
    """Combine domain and dork qualifier into a single GitHub search query."""
    return f'"{domain}" {qualifier}'


def scan_github(
    settings: Settings,
    domain: str,
    *,
    client: httpx.Client | None = None,
) -> SourceReport:
    """Run all four dorks against the GitHub code-search API."""
    if not settings.github_token:
        return SourceReport(
            source=_SOURCE,
            status=SourceStatus.NO_KEY,
            note=("skipped: GITHUB_TOKEN not set. A read-only PAT (no scopes "
                  "needed) is enough; the search index itself is public."),
        )

    findings: list[Finding] = []
    started = time.perf_counter()
    owns = client is None
    client = client or httpx.Client(timeout=20.0)
    headers = {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "credential-leak-scanner/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        for label, qualifier in _DORKS:
            q = _build_query(domain, qualifier)
            try:
                r = client.get(
                    settings.github_search_base,
                    headers=headers,
                    params={"q": q, "per_page": _PER_DORK_RESULT_CAP},
                )
            except httpx.HTTPError as exc:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.NETWORK_ERROR,
                    findings=findings,
                    note=f"network: {exc.__class__.__name__}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )
            if r.status_code == 403:
                # 403 on this endpoint usually means the secondary rate
                # limit. Stop scanning rather than burning more budget.
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.HTTP_ERROR,
                    findings=findings,
                    note=("GitHub returned 403 (likely secondary rate "
                          "limit); stopping. Re-run after the cool-off."),
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )
            if r.status_code >= 400:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.HTTP_ERROR,
                    findings=findings,
                    note=f"GitHub returned HTTP {r.status_code}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )

            data: dict[str, Any] = r.json() or {}
            total = int(data.get("total_count") or 0)
            items = data.get("items") or []
            if total > 0:
                evidence_urls = [
                    it.get("html_url") for it in items[:_PER_DORK_RESULT_CAP]
                    if isinstance(it.get("html_url"), str)
                ]
                findings.append(Finding(
                    source=_SOURCE,
                    target=domain,
                    severity=_severity_for_dork(label, total),
                    detail=(
                        f"GitHub dork {label!r} returned {total} hits "
                        f"for {domain!r}; first {len(evidence_urls)} "
                        "URL(s) attached"),
                    evidence={
                        "dork": label,
                        "query": q,
                        "total_count": total,
                        "sample_urls": evidence_urls,
                    },
                ))

            time.sleep(settings.github_polite_sleep_s)

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
