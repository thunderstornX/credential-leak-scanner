"""Settings loaded from environment / .env.

Every external credential is *optional*. The CLI never refuses to start when
a key is missing — the relevant scanner module just notes "skipped, no key"
and the aggregator records a SOURCE_UNAVAILABLE entry instead of a finding.
That keeps `credential-scan` useful in air-gapped or freshly-cloned setups
without making the operator manually disable each module."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


_REPO = Path(__file__).resolve().parent
_DEFAULT_CSV = _REPO / "tests" / "fixtures" / "sample_breach_data.csv"


class Settings(BaseSettings):
    """Process configuration. Pulled from env, .env, or constructor args."""

    # Optional credentials.
    hibp_api_key: str | None = None
    github_token: str | None = None
    anthropic_api_key: str | None = None

    # Endpoints — pinned here so tests can override without monkey-patching
    # module-level constants.
    hibp_passwords_base: str = "https://api.pwnedpasswords.com/range"
    hibp_accounts_base: str = "https://haveibeenpwned.com/api/v3/breachedaccount"
    github_search_base: str = "https://api.github.com/search/code"

    # HIBP terms-of-service: one request per 1.5 seconds for the keyed
    # account endpoint. We default to that exact value so reading the code
    # makes the policy obvious.
    hibp_polite_sleep_s: float = 1.5

    # GitHub free tier: 10 search requests / minute, unauthenticated; 30 with
    # a token. Sleep 6.5 s between calls to stay safely under the auth limit.
    github_polite_sleep_s: float = 6.5

    # Local synthetic breach CSV for cross-reference.
    local_breach_csv: Path = _DEFAULT_CSV

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


def load_settings(**overrides) -> Settings:
    """Construct Settings, accepting test-time overrides as kwargs."""
    return Settings(**overrides)
