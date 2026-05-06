"""Shared fixtures: a hermetic Settings object and the synthetic CSV path."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from config import Settings  # noqa: E402


@pytest.fixture
def fixtures_dir() -> Path:
    return _REPO / "tests" / "fixtures"


@pytest.fixture
def settings_no_keys(fixtures_dir, monkeypatch) -> Settings:
    """A Settings instance whose keys are guaranteed unset.

    We monkeypatch HIBP_API_KEY/GITHUB_TOKEN/ANTHROPIC_API_KEY to empty
    *before* constructing Settings so a stray real key in the operator's
    shell can never leak into a test."""
    for var in ("HIBP_API_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return Settings(
        hibp_api_key=None,
        github_token=None,
        anthropic_api_key=None,
        # Tighten polite sleeps to keep the test suite snappy.
        hibp_polite_sleep_s=0.0,
        github_polite_sleep_s=0.0,
        local_breach_csv=fixtures_dir / "sample_breach_data.csv",
    )


@pytest.fixture
def settings_with_keys(fixtures_dir) -> Settings:
    """Same as settings_no_keys but with placeholder keys set so the
    keyed code paths execute."""
    return Settings(
        hibp_api_key="test-hibp-key",
        github_token="test-gh-token",
        anthropic_api_key="test-anthropic-key",
        hibp_polite_sleep_s=0.0,
        github_polite_sleep_s=0.0,
        local_breach_csv=fixtures_dir / "sample_breach_data.csv",
    )
