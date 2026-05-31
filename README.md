<!-- markdownlint-disable MD033 MD041 -->

```
   ██████╗██████╗ ███████╗██████╗      ██╗     ███████╗ █████╗ ██╗  ██╗
  ██╔════╝██╔══██╗██╔════╝██╔══██╗     ██║     ██╔════╝██╔══██╗██║ ██╔╝
  ██║     ██████╔╝█████╗  ██║  ██║     ██║     █████╗  ███████║█████╔╝
  ██║     ██╔══██╗██╔══╝  ██║  ██║     ██║     ██╔══╝  ██╔══██║██╔═██╗
  ╚██████╗██║  ██║███████╗██████╔╝     ███████╗███████╗██║  ██║██║  ██╗
   ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
                ─── multi-source passive credential exposure ───
```

[![Tests](https://img.shields.io/badge/pytest-40%2F40%20passing-brightgreen)](#testing)
[![Bandit](https://img.shields.io/badge/bandit-0%20issues-brightgreen)](results/security_scan.md)
[![pip-audit](https://img.shields.io/badge/pip--audit-0%20vulns-brightgreen)](results/security_scan.md)
[![Semgrep](https://img.shields.io/badge/semgrep-0%20findings-brightgreen)](results/security_scan.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20480452.svg)](https://doi.org/10.5281/zenodo.20480452)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Zenodo](https://img.shields.io/badge/zenodo-DOI%20pending-9cf)](.zenodo.json)

`credential-leak-scanner` is a small Python pipeline that combines four
structurally different passive sources into a single defensive
credential-exposure report:

1. **HIBP Pwned Passwords** k-anonymity endpoint (no API key required) —
   the only thing that leaves the machine is the first 5 hex chars of
   the password's SHA-1.
2. **HIBP Breached Accounts** v3 endpoint (key optional, gracefully
   skipped when absent).
3. **GitHub code-search dorks** for `.env`, `password`, `api_key`,
   `secret` against a target domain (token optional).
4. **Local synthetic breach CSV** for cross-reference (100 fake rows
   shipped, all `@example.invalid` per RFC 6761).

If a key is missing, the relevant module emits a first-class
`SOURCE_UNAVAILABLE` status into the report instead of silently
dropping out — a defender can see exactly which sources contributed
and which did not. We call this property *graceful API degradation*
and the [paper](paper/paper.tex) makes the design explicit.

## Quick start

```bash
git clone https://github.com/thunderstornX/credential-leak-scanner.git
cd credential-leak-scanner

python -m venv .venv
.venv/bin/pip install -r requirements.txt

# Bare run (no keys at all). Pwned Passwords endpoint runs; HIBP
# breached-accounts and GitHub dork modules report `no_key`.
.venv/bin/python -m cli.main \
    --domain example.com \
    --password 'CorrectHorseBatteryStaple' \
    --password 'hunter2' \
    --output report.json

# With every key set: copy .env.example to .env and fill it in.
.venv/bin/python -m cli.main \
    --domain my-org.com \
    --account 'soc@my-org.com' \
    --account 'webmaster@my-org.com' \
    --password 'leaked-on-stage-2018' \
    --output report.json --ai-summary
```

The CLI prints a per-source status line so coverage gaps are visible
even before opening the JSON:

```
[*] credential-scan starting for 'example.com' at 2026-05-06T12:34:56+00:00
[*] hibp_passwords: checking 2 candidate password(s)
[*] hibp_accounts: no --account flags given; skipping module
[*] github_dorks: --skip-github set; skipping
[*] source status:
  [+] hibp_passwords  ok                    hits=2
  [○] hibp_accounts   no_key                (skipped: HIBP_API_KEY not set …)
[+] wrote report to /tmp/report.json
[+] headline severity: critical
```

## Architecture

```
                 ┌─────────────────────┐
                 │ hibp_passwords      │  k-anonymity, no key required
                 ├─────────────────────┤
                 │ hibp_accounts       │  keyed (optional, graceful skip)
                 ├─────────────────────┤  ──► aggregator ──► reporter ──► report.json
                 │ github_dorks        │  PAT (optional, graceful skip)
                 ├─────────────────────┤
                 │ breach_csv          │  local synthetic fixture
                 └─────────────────────┘
```

Each scanner module returns a `SourceReport` carrying one of six
`SourceStatus` values:

| Status                | Meaning                                             |
|-----------------------|-----------------------------------------------------|
| `ok`                  | ran, returned at least one finding                  |
| `not_found`           | ran, returned a clean result                        |
| `no_key`              | skipped because the relevant API key is unset       |
| `local_file_missing`  | skipped because the local breach CSV isn't present  |
| `http_error`          | upstream replied 4xx/5xx                            |
| `network_error`       | DNS / TLS / timeout failure                         |

Folding any of those four "skipped" / "errored" states into an empty
findings list is exactly the kind of silent drop-out a defender
cannot afford. Every test in `tests/` exercises one of these states
explicitly.

## Reproducing the eval

```bash
.venv/bin/python eval/run_eval.py
```

The harness queries the live HIBP Pwned Passwords endpoint with 25
labelled candidates (15 known-breached "common" passwords, 10
synthesised "unique" strings) and writes:

* `results/eval_summary.json` — accuracy, precision, recall, F1,
  latency mean / median / p95 / max, total wall-clock.
* `results/eval_raw.csv` — per-call observations.

**Latest measured numbers** (2026-05-06, residential connection):

| Metric          | Value      |
|-----------------|-----------:|
| n               | 25         |
| accuracy        | 1.0000     |
| precision       | 1.0000     |
| recall          | 1.0000     |
| F1              | 1.0000     |
| latency mean    | 286.06 ms  |
| latency p95     | 281.72 ms  |
| latency max     | 786.32 ms  |
| wall-clock      | 12.34 s    |
| upstream errors | 0          |

The "common" candidates resolved with breach counts ranging from
1,406,394 (`letmein`) to 209,972,844 (`123456`). All "unique"
candidates resolved with breach count 0. See
[results/README.md](results/README.md) for the full per-call CSV
and the explicit list of what this eval does *not* claim.

## Testing

```bash
.venv/bin/pytest -q
```

40 tests across the four scanner modules, the aggregator, and the
reporter. HTTP is mocked with [`respx`](https://lundberg.github.io/respx/)
which is strictly more accurate than `unittest.mock.patch` for httpx —
every test still composes a real URL, real headers, and parses a real
response body.

| Module               | Tests |
|----------------------|------:|
| `hibp_passwords.py`  | 16    |
| `hibp_accounts.py`   | 5     |
| `github_dorks.py`    | 5     |
| `breach_csv.py`      | 6     |
| `aggregator.py`      | 3     |
| `reporter.py`        | 5     |
| **Total**            | **40** |

(`hibp_passwords` includes 7 parameterised severity-band cases.)

## Security posture

| Gate       | Findings | Notes                                            |
|-----------:|:--------:|--------------------------------------------------|
| Bandit     | 0        | 1 documented suppression (B324, HIBP protocol)   |
| pip-audit  | 0        | -                                                |
| Semgrep    | 0        | 1 documented suppression (sha1, HIBP protocol)   |

See [results/security_scan.md](results/security_scan.md) for the full
report. The single suppression is on the SHA-1 call site in
`scanner/hibp_passwords.py:46`; SHA-1 is required by the HIBP Pwned
Passwords k-anonymity protocol and is not used as a password-storage
primitive anywhere in this codebase.

## Ethical use

See [ETHICAL_USE.md](ETHICAL_USE.md). Short version: only scan a
domain you own or have written authorisation for. The tool is
strictly passive — no auth probes, no credential stuffing, no scraping
of paste sites or dark-web markets, no account creation.

## Citing

If you use this software in academic work, please cite the
[CITATION.cff](CITATION.cff) record. The companion [IEEE
paper](paper/paper.tex) describes the design and reports the live
measurements.

## License

MIT. See [LICENSE](LICENSE).
