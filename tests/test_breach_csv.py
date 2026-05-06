"""Tests for the local synthetic CSV cross-reference module."""
from __future__ import annotations

from pathlib import Path

from scanner.breach_csv import scan_csv
from scanner.findings import FindingSeverity, SourceStatus


def test_scan_csv_returns_local_file_missing(settings_no_keys, tmp_path):
    missing = tmp_path / "no_such.csv"
    report = scan_csv(settings_no_keys, ["alice@example.com"],
                      csv_path=missing)
    assert report.status == SourceStatus.LOCAL_FILE_MISSING
    assert "tests/fixtures/sample_breach_data.csv" in (report.note or "")


def test_scan_csv_finds_known_synthetic_account(settings_no_keys):
    # Row 0 of the fixture is "alice00@example.invalid".
    report = scan_csv(settings_no_keys, ["alice00@example.invalid"])
    assert report.status == SourceStatus.OK
    assert report.hits == 1
    assert report.findings[0].severity == FindingSeverity.HIGH
    assert (report.findings[0].evidence["source_corpus"]
            == "SyntheticCorpus2023")


def test_scan_csv_case_insensitive(settings_no_keys):
    report = scan_csv(settings_no_keys, ["ALICE00@EXAMPLE.INVALID"])
    assert report.hits == 1


def test_scan_csv_returns_not_found_when_no_match(settings_no_keys):
    report = scan_csv(settings_no_keys, ["nobody@example.invalid"])
    assert report.status == SourceStatus.NOT_FOUND
    assert report.hits == 0


def test_scan_csv_handles_multiple_targets(settings_no_keys):
    report = scan_csv(settings_no_keys, [
        "alice00@example.invalid",
        "bob.dev01@example.invalid",
        "nobody@example.invalid",
    ])
    assert report.status == SourceStatus.OK
    # Two matches, third target is not in the fixture.
    assert report.hits == 2


def test_fixture_emails_all_use_reserved_domain():
    """Belt-and-braces: prove the fixture only contains example.invalid."""
    repo = Path(__file__).resolve().parent.parent
    csv_path = repo / "tests" / "fixtures" / "sample_breach_data.csv"
    text = csv_path.read_text(encoding="utf-8").splitlines()
    # Skip header.
    for line in text[1:]:
        email = line.split(",", 1)[0]
        assert email.endswith("@example.invalid"), (
            f"non-reserved-domain row in fixture: {email!r}")
