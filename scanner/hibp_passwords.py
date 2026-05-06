"""HIBP Pwned Passwords k-anonymity client.

The endpoint is at ``https://api.pwnedpasswords.com/range/{prefix}`` where
``prefix`` is the first **5 hex characters** of the candidate password's
SHA-1 hash. The server replies with one line per matching suffix:

    003D68EB55068C33ACE09247EE4C639306B:3
    011A8D4234E1F49C8C7B3F2C9F9D80F89E6:1
    ...

Only the prefix leaves the machine; the actual password (and its full
hash) never does. This is the same protocol the HIBP browser extension and
1Password's "Watchtower" use. No API key needed — the endpoint is rate-
unlimited per HIBP's posted FAQ for the password range API.

A real measurable run on the labelled top-100 most-common passwords list
takes ~10–20 seconds end-to-end on a residential connection."""
from __future__ import annotations

import hashlib
import time
from typing import Iterable

import httpx

from config import Settings
from .findings import (
    Finding,
    FindingSeverity,
    SourceReport,
    SourceStatus,
)


_SOURCE = "hibp_passwords"


def _sha1_hex(s: str) -> str:
    """SHA-1 of the candidate password, uppercase hex.

    SHA-1 is used here because that is the algorithm HIBP's Pwned
    Passwords endpoint indexes on — not as a recommendation for password
    storage. The choice is dictated by the upstream API."""
    # SHA-1 is required by the HIBP k-anonymity protocol; this is not a
    # password-hashing primitive in our codebase.
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    return hashlib.sha1(  # nosec B324  # noqa: S324
        s.encode("utf-8")).hexdigest().upper()


def _parse_range_response(body: str) -> dict[str, int]:
    """Parse the line-based response into ``{suffix: count}``.

    Response is ASCII text, one ``SUFFIX:COUNT`` pair per line, terminated
    by ``\\r\\n``. We are deliberately generous about whitespace because
    the upstream has used both LF and CRLF over the years."""
    out: dict[str, int] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        try:
            out[suffix.upper()] = int(count.strip())
        except ValueError:
            continue
    return out


def _severity_for_count(count: int) -> FindingSeverity:
    """Map breach-count to a qualitative severity band.

    The thresholds are deliberately conservative. A password that has
    appeared in *any* breach is, by HIBP's definition, no longer suitable
    for use; we still raise the band when the count is high enough that
    it is almost certainly on every credential-stuffing wordlist."""
    if count >= 100_000:
        return FindingSeverity.CRITICAL
    if count >= 1_000:
        return FindingSeverity.HIGH
    if count >= 1:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


def check_password(
    settings: Settings,
    password: str,
    *,
    client: httpx.Client | None = None,
) -> tuple[int, float]:
    """Look up one password against the k-anonymity endpoint.

    Returns ``(count, elapsed_ms)`` where ``count`` is the number of
    breach corpora the password has been seen in (0 = clean) and
    ``elapsed_ms`` is wall-clock latency for telemetry. Raises
    ``httpx.HTTPError`` on transport failure so the caller can decide
    whether to record a NETWORK_ERROR or an HTTP_ERROR."""
    digest = _sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    url = f"{settings.hibp_passwords_base}/{prefix}"

    owns = client is None
    client = client or httpx.Client(timeout=10.0)
    started = time.perf_counter()
    try:
        r = client.get(url, headers={"User-Agent": "credential-leak-scanner/0.1"})
        r.raise_for_status()
        suffixes = _parse_range_response(r.text)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return suffixes.get(suffix, 0), elapsed_ms
    finally:
        if owns:
            client.close()


def scan_passwords(
    settings: Settings,
    passwords: Iterable[str],
    *,
    client: httpx.Client | None = None,
) -> SourceReport:
    """Run the k-anonymity check across an iterable of candidate passwords.

    Each password produces zero or one ``Finding``: zero if the breach
    count is 0 (clean), one with severity proportional to the count
    otherwise. Latency for the *whole* run is recorded on the report;
    per-call latency is preserved on each Finding's ``evidence`` dict so
    the eval harness can compute mean/p95 without re-running."""
    findings: list[Finding] = []
    started = time.perf_counter()
    owns = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        for pw in passwords:
            try:
                count, elapsed = check_password(
                    settings, pw, client=client)
            except httpx.HTTPStatusError as exc:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.HTTP_ERROR,
                    findings=findings,
                    note=f"HIBP responded {exc.response.status_code}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )
            except httpx.HTTPError as exc:
                return SourceReport(
                    source=_SOURCE,
                    status=SourceStatus.NETWORK_ERROR,
                    findings=findings,
                    note=f"network: {exc.__class__.__name__}",
                    elapsed_ms=(time.perf_counter() - started) * 1000.0,
                )

            if count > 0:
                findings.append(Finding(
                    source=_SOURCE,
                    target=f"<password redacted, sha1[:5]={_sha1_hex(pw)[:5]}>",
                    severity=_severity_for_count(count),
                    detail=(
                        f"candidate password appears in {count:,} public "
                        "breaches (HIBP Pwned Passwords)"),
                    evidence={
                        "breach_count": count,
                        "elapsed_ms": round(elapsed, 2),
                    },
                ))

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
