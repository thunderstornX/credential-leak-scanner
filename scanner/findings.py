"""Cross-module dataclasses for credential-leak findings.

Every scanner emits ``Finding`` objects through a ``SourceReport`` wrapper.
The wrapper exists because "we ran the scanner and got zero hits" and "we
did not run the scanner because no key was configured" are *very* different
states for a defender — the first is reassuring, the second is a coverage
gap. We make that distinction explicit instead of conflating both into an
empty list."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class FindingSeverity(str, Enum):
    """Severity buckets used by the aggregator's risk-scoring rule.

    Inspired by, but not identical to, the qualitative bands in NIST SP
    800-30 Rev. 1 (LOW / MEDIUM / HIGH / CRITICAL). We keep CRITICAL for
    findings where a credential is both confirmed-real *and* recently
    breached (last 24 months); MEDIUM is the safe default."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceStatus(str, Enum):
    """Why a source produced (or did not produce) a result this run."""
    OK = "ok"                            # ran and returned a result
    NO_KEY = "no_key"                    # skipped: no API key configured
    HTTP_ERROR = "http_error"            # ran, upstream replied >=400
    NETWORK_ERROR = "network_error"      # connection / timeout / DNS
    NOT_FOUND = "not_found"              # ran, returned no breach (clean)
    LOCAL_FILE_MISSING = "local_file_missing"  # local CSV not on disk


@dataclass
class Finding:
    """One concrete piece of evidence that a credential is exposed."""
    source: str                # "hibp_passwords", "github_dorks", etc.
    target: str                # the candidate password / account / domain
    severity: FindingSeverity
    detail: str                # human-readable one-liner
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceReport:
    """A scanner module's full account of what happened on this run."""
    source: str
    status: SourceStatus
    findings: list[Finding] = field(default_factory=list)
    note: str | None = None         # operator-facing explanation
    elapsed_ms: float = 0.0

    @property
    def hits(self) -> int:
        return len(self.findings)


@dataclass
class ScanReport:
    """The whole-run report the CLI writes to disk."""
    domain: str
    started_at: str             # ISO-8601 UTC
    finished_at: str
    sources: list[SourceReport] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    ai_summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output. Enums become their .value strings."""
        d = asdict(self)
        for src in d["sources"]:
            src["status"] = src["status"].value if hasattr(
                src["status"], "value") else src["status"]
            for f in src["findings"]:
                f["severity"] = f["severity"].value if hasattr(
                    f["severity"], "value") else f["severity"]
        return d
