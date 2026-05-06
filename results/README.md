# Eval results

Live numbers from running `python eval/run_eval.py` against the public
HIBP Pwned Passwords k-anonymity endpoint
(`https://api.pwnedpasswords.com/range/{prefix}`).

## Test set

`eval/test_passwords.json` contains 25 candidates split into two
labelled classes:

* **15 "common"** passwords (`password`, `123456`, `qwerty`,
  `letmein`, `abc123`, `monkey`, `dragon`, `iloveyou`, `111111`,
  `welcome`, `sunshine`, `princess`, `qwerty123`, `admin`, `trustno1`)
  carry `expected_in_breach: true`. These are the iconic
  always-on-the-list-of-worst-passwords entries.
* **10 "unique"** passwords are crafted strings of the form
  `credlk-eval-uniq-26-05-06-<random8>` whose chance of appearing in
  any public breach corpus is negligible. They carry
  `expected_in_breach: false`.

The split is small on purpose: the eval is a sanity check on the
client, not a benchmark of HIBP's own coverage.

## Reproducing

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python eval/run_eval.py
```

Re-running on a residential connection takes ~12 seconds.

## Latest measured numbers (25 candidates, run 2026-05-06)

| Metric            | Value     |
| ----------------- | --------- |
| n                 | 25        |
| accuracy          | 1.0000    |
| precision         | 1.0000    |
| recall            | 1.0000    |
| F1                | 1.0000    |
| true positives    | 15        |
| true negatives    | 10        |
| false positives   | 0         |
| false negatives   | 0         |
| latency mean      | 286.06 ms |
| latency p95       | 281.72 ms |
| latency max       | 786.32 ms |
| wall-clock total  | 12.34 s   |
| upstream errors   | 0         |

All 15 "common" passwords resolved with breach counts ranging from
1,406,394 (`letmein`) to 209,972,844 (`123456`). All 10 "unique"
passwords resolved with breach count 0. Per-call latency is dominated
by network round-trip; the endpoint itself is consistently sub-300ms
even from a residential link.

The full per-call CSV is at `results/eval_raw.csv`.

## Caveats

* These numbers measure *the client's correctness*, not the upstream's
  ground-truth coverage. HIBP's own positive-class recall is whatever
  fraction of the world's breach corpora they happen to have indexed
  — by definition unknowable from the outside.
* The "unique" class achieves recall by construction: the strings have
  never been used as anyone's password before this commit. Anyone who
  reads this README and starts using one of them invalidates that
  property; please don't.
* Latency measurements are wall-clock from the calling host. They
  bundle DNS, TLS, transit, and HIBP-side processing. Different
  geographies will see different numbers.

## What this eval does *not* claim

* It does not benchmark the keyed HIBP breached-account endpoint
  (`hibp_accounts`). That endpoint requires a paid API key; the
  pipeline supports it but no measured numbers are in this release.
* It does not benchmark the GitHub dork sweep (`github_dorks`). Doing
  so would require a confederate-domain test set, which is out of
  scope for a reproducible evaluation.
* It does not benchmark the local CSV cross-reference
  (`breach_csv`) — that path is fully covered by `pytest` and is
  deterministic, so an empirical eval would be theatre.
