"""``credential-scan`` — Click entry point.

Examples
--------
Scan a domain you own using whichever sources have keys configured:

    python -m cli.main --domain example.com --output report.json

Add candidate passwords to check against HIBP Pwned Passwords:

    python -m cli.main --domain example.com \\
        --password 'CorrectHorseBatteryStaple' --password 'hunter2' \\
        --output report.json

Add an executive summary (LLM if ANTHROPIC_API_KEY is set, deterministic
fallback if not):

    python -m cli.main --domain example.com --output report.json --ai-summary
"""
from __future__ import annotations

from pathlib import Path

import click

from config import load_settings
from scanner.aggregator import aggregate, _utcnow_iso
from scanner.breach_csv import scan_csv
from scanner.github_dorks import scan_github
from scanner.hibp_accounts import scan_accounts
from scanner.hibp_passwords import scan_passwords
from scanner.reporter import render_report


def _emit_source_status(reports) -> None:
    """One-line status per source so the operator sees coverage gaps."""
    for r in reports:
        sym = {
            "ok": "+",
            "not_found": "·",
            "no_key": "○",
            "local_file_missing": "○",
            "http_error": "x",
            "network_error": "x",
        }.get(r.status.value, "?")
        line = f"  [{sym}] {r.source:<16} {r.status.value:<20}"
        if r.note:
            line += f"  ({r.note})"
        elif r.findings:
            line += f"  hits={len(r.findings)}"
        click.echo(line)


@click.command()
@click.option("--domain", required=True, help="Target domain (you must "
               "own it or have written authorisation).")
@click.option("--output", "output_path", required=True,
              type=click.Path(dir_okay=False, path_type=Path),
              help="Path to write the JSON report to.")
@click.option("--account", "-a", "accounts", multiple=True,
              help="Account/email to look up. Can be passed multiple times.")
@click.option("--password", "-p", "passwords", multiple=True,
              help="Candidate password to check against HIBP Pwned "
                   "Passwords. Can be passed multiple times.")
@click.option("--csv", "csv_path", type=click.Path(path_type=Path),
              help="Override the local breach CSV path.")
@click.option("--ai-summary", is_flag=True, default=False,
              help="Append a four-sentence executive summary to the "
                   "report (Claude if ANTHROPIC_API_KEY is set, "
                   "deterministic fallback otherwise).")
@click.option("--skip-github", is_flag=True, default=False,
              help="Skip the GitHub dork sweep even if GITHUB_TOKEN is "
                   "set (useful for offline runs).")
def main(
    domain: str,
    output_path: Path,
    accounts: tuple[str, ...],
    passwords: tuple[str, ...],
    csv_path: Path | None,
    ai_summary: bool,
    skip_github: bool,
) -> None:
    """Run the multi-source credential exposure scan."""
    settings = load_settings()

    started_at = _utcnow_iso()
    click.echo(f"[*] credential-scan starting for {domain!r} at {started_at}")

    reports = []

    # Pwned Passwords (no key needed). Skipped if no candidates given.
    if passwords:
        click.echo(f"[*] hibp_passwords: checking {len(passwords)} "
                   "candidate password(s)")
        reports.append(scan_passwords(settings, passwords))
    else:
        click.echo("[*] hibp_passwords: no --password flags given; "
                   "skipping module")

    # Breached accounts (key optional).
    if accounts:
        click.echo(f"[*] hibp_accounts: checking {len(accounts)} account(s)")
        reports.append(scan_accounts(settings, accounts))
        click.echo(f"[*] breach_csv: cross-referencing {len(accounts)} "
                    "account(s) against local CSV")
        reports.append(scan_csv(settings, accounts, csv_path=csv_path))
    else:
        click.echo("[*] hibp_accounts / breach_csv: no --account flags; "
                    "skipping both")

    # GitHub dorks (token optional).
    if skip_github:
        click.echo("[*] github_dorks: --skip-github set; skipping")
    else:
        click.echo("[*] github_dorks: running 4-dork sweep")
        reports.append(scan_github(settings, domain))

    click.echo("[*] source status:")
    _emit_source_status(reports)

    report = aggregate(domain=domain, sources=reports, started_at=started_at)
    out = render_report(report, output_path=output_path,
                        ai_summary=ai_summary)
    click.echo(f"[+] wrote report to {out}")
    click.echo(f"[+] headline severity: "
               f"{report.summary.get('headline_severity')}")


if __name__ == "__main__":
    main()  # pragma: no cover
