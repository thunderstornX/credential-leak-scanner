"""Tests for the HIBP breached-account client."""
from __future__ import annotations

import urllib.parse

import httpx
import respx

from scanner.findings import FindingSeverity, SourceStatus
from scanner.hibp_accounts import scan_accounts


def test_scan_accounts_skips_when_no_key(settings_no_keys):
    report = scan_accounts(settings_no_keys, ["alice@example.com"])
    assert report.status == SourceStatus.NO_KEY
    assert "HIBP_API_KEY" in (report.note or "")
    assert report.hits == 0


def test_scan_accounts_finds_breach(settings_with_keys):
    acct = "alice@example.com"
    url = (f"{settings_with_keys.hibp_accounts_base}/"
            f"{urllib.parse.quote(acct, safe='')}")
    with respx.mock(assert_all_called=False) as router:
        router.get(url).mock(return_value=httpx.Response(200, json=[
            {"Name": "MegaBreach", "BreachDate": "2024-08-15",
             "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "VintageBreach", "BreachDate": "2017-01-01",
             "DataClasses": ["Email addresses"]},
        ]))
        report = scan_accounts(settings_with_keys, [acct])
    assert report.status == SourceStatus.OK
    assert report.hits == 2
    sevs = sorted(f.severity.value for f in report.findings)
    # 2024 -> CRITICAL, 2017 -> HIGH
    assert sevs == ["critical", "high"]


def test_scan_accounts_404_means_clean(settings_with_keys):
    acct = "clean@example.com"
    url = (f"{settings_with_keys.hibp_accounts_base}/"
            f"{urllib.parse.quote(acct, safe='')}")
    with respx.mock(assert_all_called=False) as router:
        router.get(url).mock(return_value=httpx.Response(404))
        report = scan_accounts(settings_with_keys, [acct])
    assert report.status == SourceStatus.NOT_FOUND
    assert report.hits == 0


def test_scan_accounts_records_http_error(settings_with_keys):
    acct = "alice@example.com"
    url = (f"{settings_with_keys.hibp_accounts_base}/"
            f"{urllib.parse.quote(acct, safe='')}")
    with respx.mock(assert_all_called=False) as router:
        router.get(url).mock(return_value=httpx.Response(503,
                                                            text="server failure"))
        report = scan_accounts(settings_with_keys, [acct])
    assert report.status == SourceStatus.HTTP_ERROR
    assert "503" in (report.note or "")


def test_scan_accounts_severity_for_undated_breach(settings_with_keys):
    """A breach record with no BreachDate should still produce HIGH."""
    acct = "alice@example.com"
    url = (f"{settings_with_keys.hibp_accounts_base}/"
            f"{urllib.parse.quote(acct, safe='')}")
    with respx.mock(assert_all_called=False) as router:
        router.get(url).mock(return_value=httpx.Response(200, json=[
            {"Name": "UndatedBreach", "DataClasses": []},
        ]))
        report = scan_accounts(settings_with_keys, [acct])
    assert report.status == SourceStatus.OK
    assert report.findings[0].severity == FindingSeverity.HIGH
