"""Tests for the HIBP Pwned Passwords k-anonymity client.

We mock the upstream with the ``respx`` library because it is strictly
more accurate than ``unittest.mock.patch`` for HTTP — the calling code
still has to compose a real URL, real headers, and parse a real (mocked)
response body."""
from __future__ import annotations

import httpx
import pytest
import respx

from scanner.findings import FindingSeverity, SourceStatus
from scanner.hibp_passwords import (
    _parse_range_response,
    _severity_for_count,
    _sha1_hex,
    check_password,
    scan_passwords,
)


# Reference value: SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_sha1_hex_uppercase():
    assert _sha1_hex("password") == PASSWORD_SHA1


def test_parse_range_response_handles_crlf_and_lf():
    body = "AAAAA:1\r\nBBBBB:42\r\nCCCCC:0\n"
    parsed = _parse_range_response(body)
    assert parsed == {"AAAAA": 1, "BBBBB": 42, "CCCCC": 0}


def test_parse_range_response_skips_garbage():
    body = "AAAAA:1\n\nnotvalid\nBBBBB:notanumber\nCCCCC:7\n"
    assert _parse_range_response(body) == {"AAAAA": 1, "CCCCC": 7}


@pytest.mark.parametrize("count,expected", [
    (0, FindingSeverity.LOW),
    (1, FindingSeverity.MEDIUM),
    (999, FindingSeverity.MEDIUM),
    (1_000, FindingSeverity.HIGH),
    (99_999, FindingSeverity.HIGH),
    (100_000, FindingSeverity.CRITICAL),
    (10_000_000, FindingSeverity.CRITICAL),
])
def test_severity_thresholds(count, expected):
    assert _severity_for_count(count) == expected


def test_check_password_returns_breach_count(settings_no_keys):
    prefix, suffix = PASSWORD_SHA1[:5], PASSWORD_SHA1[5:]
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{settings_no_keys.hibp_passwords_base}/{prefix}").mock(
            return_value=httpx.Response(
                200,
                text=f"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n{suffix}:9876543\n",
            )
        )
        count, elapsed_ms = check_password(settings_no_keys, "password")
    assert count == 9_876_543
    assert elapsed_ms >= 0


def test_check_password_zero_when_suffix_absent(settings_no_keys):
    prefix = PASSWORD_SHA1[:5]
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{settings_no_keys.hibp_passwords_base}/{prefix}").mock(
            return_value=httpx.Response(
                200, text="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:7\n",
            )
        )
        count, _ = check_password(settings_no_keys, "password")
    assert count == 0


def test_scan_passwords_aggregates_findings(settings_no_keys):
    # Both candidate passwords seed the same prefix endpoint with their
    # corresponding suffix line.
    with respx.mock(assert_all_called=False) as router:
        for pw, ct in (("password", 9_876_543), ("hunter2", 12)):
            digest = _sha1_hex(pw)
            router.get(
                f"{settings_no_keys.hibp_passwords_base}/{digest[:5]}"
            ).mock(return_value=httpx.Response(
                200, text=f"{digest[5:]}:{ct}\n"))
        report = scan_passwords(settings_no_keys, ["password", "hunter2"])
    assert report.status == SourceStatus.OK
    assert report.hits == 2
    sevs = sorted(f.severity.value for f in report.findings)
    assert sevs == ["critical", "medium"]


def test_scan_passwords_clean_yields_not_found(settings_no_keys):
    digest = _sha1_hex("CorrectHorseBatteryStaple-uniq-001")
    with respx.mock(assert_all_called=False) as router:
        router.get(
            f"{settings_no_keys.hibp_passwords_base}/{digest[:5]}"
        ).mock(return_value=httpx.Response(
            200, text="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n"))
        report = scan_passwords(
            settings_no_keys, ["CorrectHorseBatteryStaple-uniq-001"])
    assert report.status == SourceStatus.NOT_FOUND
    assert report.hits == 0


def test_scan_passwords_records_http_error(settings_no_keys):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r".*").mock(
            return_value=httpx.Response(429, text="rate-limited"))
        report = scan_passwords(settings_no_keys, ["anything"])
    assert report.status == SourceStatus.HTTP_ERROR
    assert "429" in (report.note or "")


def test_scan_passwords_records_network_error(settings_no_keys):
    with respx.mock(assert_all_called=False) as router:
        router.get(url__regex=r".*").mock(
            side_effect=httpx.ConnectError("simulated DNS failure"))
        report = scan_passwords(settings_no_keys, ["anything"])
    assert report.status == SourceStatus.NETWORK_ERROR
    assert "ConnectError" in (report.note or "")
