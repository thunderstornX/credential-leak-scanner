"""End-to-end eval of the HIBP Pwned Passwords k-anonymity client.

Reads ``eval/test_passwords.json``, queries the live HIBP endpoint for
each candidate, and writes:

  * ``results/eval_summary.json``  -- aggregate metrics
  * ``results/eval_raw.csv``       -- per-call raw measurements

The eval is intentionally small (25 candidates by default) because the
endpoint, while polite to consume, is still a third-party service we
should not abuse. Anyone re-running this should expect ~10–25 seconds
end-to-end on a residential connection.

The test set is split into a "common" positive class and a "unique"
negative class, so we can compute precision / recall / accuracy
without any hand labelling beyond the JSON itself."""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from pathlib import Path

import httpx

# Allow `python eval/run_eval.py` from the repo root.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from config import load_settings  # noqa: E402
from scanner.hibp_passwords import _sha1_hex, check_password  # noqa: E402


def _short(p: Path) -> str:
    """Display path relative to repo if possible, absolute otherwise."""
    try:
        return str(p.relative_to(_REPO))
    except ValueError:
        return str(p)


def _load_test_set(path: Path) -> list[dict]:
    raw = json.loads(path.read_text())
    rows: list[dict] = []
    rows.extend(raw.get("common", []))
    rows.extend(raw.get("unique", []))
    return rows


def _summarise(rows: list[dict]) -> dict:
    """Compute precision/recall/accuracy over the labelled rows.

    The "positive class" here is "the password is in breach". A row
    where the API replies count > 0 is the positive prediction.
    Latency is summarised across all rows (positives and negatives)."""
    tp = fp = fn = tn = 0
    for r in rows:
        actual = bool(r["expected_in_breach"])
        predicted = bool(r["observed_count"] > 0)
        if actual and predicted:
            tp += 1
        elif (not actual) and predicted:
            fp += 1
        elif actual and (not predicted):
            fn += 1
        else:
            tn += 1
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
           if (precision + recall) else 0.0)

    elapsed_ms = [r["elapsed_ms"] for r in rows]
    return {
        "n": total,
        "true_positives":  tp,
        "false_positives": fp,
        "true_negatives":  tn,
        "false_negatives": fn,
        "accuracy":  round(accuracy, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "latency_ms": {
            "mean":   round(statistics.fmean(elapsed_ms), 2),
            "median": round(statistics.median(elapsed_ms), 2),
            "p95":    round(_percentile(elapsed_ms, 95), 2),
            "min":    round(min(elapsed_ms), 2),
            "max":    round(max(elapsed_ms), 2),
        },
    }


def _percentile(values: list[float], pct: float) -> float:
    """Pure-python percentile so we don't pull numpy into a tiny tool."""
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-set", type=Path,
                         default=_REPO / "eval" / "test_passwords.json")
    parser.add_argument("--output-dir", type=Path,
                         default=_REPO / "results")
    parser.add_argument("--sleep-s", type=float, default=0.2,
                         help="Polite sleep between calls (HIBP password "
                              "range API has no documented per-second "
                              "limit, but 0.2s is a courteous default).")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    settings = load_settings()
    rows = _load_test_set(args.test_set)
    if not rows:
        sys.exit(f"empty test set at {args.test_set}")

    print(f"[eval] loaded {len(rows)} candidate(s) from "
          f"{_short(args.test_set)}")
    print(f"[eval] querying {settings.hibp_passwords_base} ...")

    started = time.perf_counter()
    with httpx.Client(timeout=10.0) as client:
        for r in rows:
            digest = _sha1_hex(r["password"])
            try:
                count, elapsed = check_password(
                    settings, r["password"], client=client)
                r["observed_count"] = count
                r["elapsed_ms"] = elapsed
                r["sha1_prefix"] = digest[:5]
                r["error"] = None
            except httpx.HTTPError as exc:
                r["observed_count"] = -1
                r["elapsed_ms"] = 0.0
                r["sha1_prefix"] = digest[:5]
                r["error"] = exc.__class__.__name__
                print(f"[eval]   ! {r['label']}: {exc.__class__.__name__}")
            time.sleep(args.sleep_s)

    total_elapsed_s = time.perf_counter() - started

    valid = [r for r in rows if r["error"] is None]
    summary = _summarise(valid)
    summary["wall_clock_s"] = round(total_elapsed_s, 2)
    summary["errors"] = sum(1 for r in rows if r["error"] is not None)
    summary["dataset_path"] = _short(args.test_set)

    summary_path = args.output_dir / "eval_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))

    raw_path = args.output_dir / "eval_raw.csv"
    fieldnames = ["label", "expected_in_breach", "observed_count",
                   "sha1_prefix", "elapsed_ms", "error"]
    with raw_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fieldnames})

    print(f"[eval] wrote {_short(summary_path)}")
    print(f"[eval] wrote {_short(raw_path)}")
    print(f"[eval] accuracy={summary['accuracy']:.4f} "
          f"precision={summary['precision']:.4f} "
          f"recall={summary['recall']:.4f} "
          f"f1={summary['f1']:.4f}")
    print(f"[eval] latency mean={summary['latency_ms']['mean']:.1f}ms "
          f"p95={summary['latency_ms']['p95']:.1f}ms")


if __name__ == "__main__":
    main()
