"""Render the final ScanReport as JSON; optionally synthesise an
executive summary.

The "executive summary" is intentionally cheap. If the user passes
``--ai-summary`` and an Anthropic key is configured we forward the
structured findings to Claude and let it write a 4-sentence brief. If
the key is *not* set we fall back to a deterministic template so the
``--ai-summary`` flag still produces something useful in air-gapped
runs. We do not crash on missing keys — the whole point of this tool is
to remain useful when external dependencies are absent."""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from .findings import ScanReport


_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


def _deterministic_summary(report: ScanReport) -> str:
    """Build a four-sentence summary from the structured findings only.

    Used as both the no-key fallback and the test-time stub. Reads as
    naturally as a human-written brief if we resist the urge to pad."""
    s = report.summary
    sev = s.get("by_severity", {})
    parts: list[str] = []
    parts.append(
        f"Scanned domain {report.domain!r} across "
        f"{s.get('sources_run', 0)} active sources "
        f"({s.get('sources_skipped', 0)} skipped, "
        f"{s.get('sources_errored', 0)} errored).")
    total = s.get("total_findings", 0)
    if total == 0:
        parts.append("No credential exposure was observed in the active "
                     "sources.")
    else:
        parts.append(
            f"{total} finding(s) total: "
            f"{sev.get('critical', 0)} critical, "
            f"{sev.get('high', 0)} high, "
            f"{sev.get('medium', 0)} medium, "
            f"{sev.get('low', 0)} low.")
    headline = s.get("headline_severity", "none")
    if headline in ("critical", "high"):
        parts.append("Recommended next step: rotate the impacted "
                     "credential set and review the affected source URLs.")
    elif headline == "medium":
        parts.append("Recommended next step: confirm whether any matched "
                     "candidate is in active use; rotate if so.")
    else:
        parts.append("Recommended next step: re-scan on a quarterly "
                     "cadence to catch newly-disclosed breach corpora.")
    parts.append("This summary was generated from the structured findings "
                 "without an LLM call (deterministic mode).")
    return " ".join(parts)


def _ai_summary_via_claude(
    report: ScanReport, api_key: str
) -> str | None:
    """Synthesise an executive summary via the Claude Messages API."""
    body = {
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 256,
        "messages": [
            {"role": "user", "content": (
                "You are a defensive-security assistant. Summarise the "
                "following credential-exposure scan in four short "
                "sentences for a non-technical executive. Stay factual; "
                "do not invent details that are not in the JSON.\n\n"
                f"```json\n{json.dumps(report.to_dict(), indent=2)}\n```"
            )},
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    try:
        with httpx.Client(timeout=20.0) as client:
            r = client.post(_ANTHROPIC_URL, json=body, headers=headers)
            if r.status_code >= 400:
                return None
            data = r.json()
            block = (data.get("content") or [{}])[0]
            text = block.get("text")
            return text if isinstance(text, str) and text.strip() else None
    except httpx.HTTPError:
        return None


def render_report(
    report: ScanReport,
    *,
    output_path: Path,
    ai_summary: bool = False,
) -> Path:
    """Write the JSON report to disk; populate AI summary if requested.

    Returns the resolved output path so the caller can echo it without
    having to re-resolve."""
    if ai_summary:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if api_key:
            summary = _ai_summary_via_claude(report, api_key)
            report.ai_summary = summary or _deterministic_summary(report)
        else:
            report.ai_summary = _deterministic_summary(report)

    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output_path
