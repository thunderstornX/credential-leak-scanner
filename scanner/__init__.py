"""credential-leak-scanner: passive multi-source credential exposure scanning.

Submodules:
    hibp_passwords  -- HIBP Pwned Passwords k-anonymity endpoint (no key)
    hibp_accounts   -- HIBP breached-account v3 endpoint (key optional)
    github_dorks    -- GitHub code-search dork queries (token optional)
    breach_csv      -- local synthetic breach CSV cross-reference
    aggregator      -- merge, dedupe, risk-score findings
    reporter        -- structured JSON output (+ optional AI summary)
    findings        -- dataclasses for the cross-module finding model
"""
from .findings import (
    Finding,
    FindingSeverity,
    SourceStatus,
    SourceReport,
    ScanReport,
)

__all__ = [
    "Finding",
    "FindingSeverity",
    "SourceStatus",
    "SourceReport",
    "ScanReport",
]
