"""Tests for the GitHub code-search dork module."""
from __future__ import annotations

import httpx
import respx

from scanner.findings import FindingSeverity, SourceStatus
from scanner.github_dorks import _DORKS, scan_github


def test_scan_github_skips_when_no_token(settings_no_keys):
    report = scan_github(settings_no_keys, "example.com")
    assert report.status == SourceStatus.NO_KEY
    assert "GITHUB_TOKEN" in (report.note or "")


def test_scan_github_records_findings_per_dork(settings_with_keys):
    """First dork (env_file) returns hits, others return zero."""
    responses_iter = iter([
        httpx.Response(200, json={
            "total_count": 5,
            "items": [{"html_url": "https://github.com/x/y/blob/m/.env"}],
        }),
        httpx.Response(200, json={"total_count": 0, "items": []}),
        httpx.Response(200, json={"total_count": 0, "items": []}),
        httpx.Response(200, json={"total_count": 0, "items": []}),
    ])

    with respx.mock(assert_all_called=False) as router:
        router.get(settings_with_keys.github_search_base).mock(
            side_effect=lambda req: next(responses_iter)
        )
        report = scan_github(settings_with_keys, "example.com")

    assert report.status == SourceStatus.OK
    assert report.findings[0].severity == FindingSeverity.HIGH
    assert report.findings[0].evidence["dork"] == _DORKS[0][0]


def test_scan_github_no_hits_yields_not_found(settings_with_keys):
    with respx.mock(assert_all_called=False) as router:
        router.get(settings_with_keys.github_search_base).mock(
            return_value=httpx.Response(
                200, json={"total_count": 0, "items": []})
        )
        report = scan_github(settings_with_keys, "example.com")
    assert report.status == SourceStatus.NOT_FOUND
    assert report.hits == 0


def test_scan_github_403_secondary_rate_limit(settings_with_keys):
    with respx.mock(assert_all_called=False) as router:
        router.get(settings_with_keys.github_search_base).mock(
            return_value=httpx.Response(403, text="rate limited"))
        report = scan_github(settings_with_keys, "example.com")
    assert report.status == SourceStatus.HTTP_ERROR
    assert "403" in (report.note or "")


def test_scan_github_500_other_http_error(settings_with_keys):
    with respx.mock(assert_all_called=False) as router:
        router.get(settings_with_keys.github_search_base).mock(
            return_value=httpx.Response(500, text="server error"))
        report = scan_github(settings_with_keys, "example.com")
    assert report.status == SourceStatus.HTTP_ERROR
    assert "500" in (report.note or "")
