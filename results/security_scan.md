# DevSecOps gate report

Run on 2026-05-06 against the release tree (commit at HEAD of `main`).

## Bandit (medium and above severity)

```
$ bandit -r scanner cli config.py eval -ll
Total issues (by severity):
    Undefined: 0
    Low:       0
    Medium:    0
    High:      0
```

The single high-severity finding (B324, weak SHA-1 hash algorithm) is
suppressed via `# nosec B324` in `scanner/hibp_passwords.py:46`. SHA-1
is required by the HIBP Pwned Passwords k-anonymity protocol and is
not used as a password-storage primitive anywhere in this codebase.

## pip-audit (transitive vulnerability scan)

```
$ pip-audit --skip-editable --strict
No known vulnerabilities found
```

The previously flagged `pytest 8.4.2` (GHSA-6w46-j5rx-g56g) and three
`setuptools 59.6.0` advisories were cleared by pinning `pytest>=9.0.3`
and `setuptools>=78.1.1` in `requirements.txt`.

## Semgrep (`p/python`, `p/security-audit`)

```
$ semgrep --config p/python --config p/security-audit --error --quiet \
    scanner cli config.py eval
exit=0
```

The same SHA-1 finding is suppressed inline with a
`# nosemgrep:` directive on the same line as the Bandit suppression.

## Summary

| Gate       | Findings | Suppressed (with rationale) |
|-----------:|:--------:|:---------------------------:|
| Bandit     | 0        | 1 (B324, HIBP protocol)     |
| pip-audit  | 0        | 0                           |
| Semgrep    | 0        | 1 (sha1, HIBP protocol)     |

All gates are blocking on `--error`; `exit=0` across the board.
