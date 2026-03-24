"""Centralized configuration for Seraph.

Loads from .seraph/config.toml -> env vars -> defaults.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, fields
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class TimeoutConfig:
    """Timeout settings for subprocess calls (seconds)."""

    mutation_per_file: int = 120
    static_analysis: int = 60
    baseline_per_run: int = 120
    diff: int = 30
    mutmut_results: int = 30


@dataclass(frozen=True)
class ScoringConfig:
    """Scoring weights, thresholds, and constants."""

    # Dimension weights (must sum to 1.0)
    mutation_weight: float = 0.25
    static_weight: float = 0.20
    baseline_weight: float = 0.10
    sentinel_risk_weight: float = 0.20
    co_change_weight: float = 0.10
    security_weight: float = 0.15

    # Grade thresholds (A >= t1, B >= t2, C >= t3, D >= t4, F < t4)
    grade_a: float = 90.0
    grade_b: float = 75.0
    grade_c: float = 60.0
    grade_d: float = 40.0

    # Deduction constants
    baseline_deduction_per_flaky: float = 10.0
    risk_deduction_per_pitfall: float = 5.0
    risk_deduction_per_missing_co_change: float = 3.0
    risk_hot_file_churn_divisor: float = 5.0
    risk_hot_file_max_deduction: float = 10.0
    static_issue_threshold: float = 10.0  # issues_per_file at which score = 50%

    # Severity weights
    severity_critical: int = 10
    severity_high: int = 5
    severity_medium: int = 2
    severity_low: int = 1
    severity_info: int = 0

    # Security analysis thresholds
    security_issue_threshold: float = 5.0

    @property
    def dimension_weights(self) -> dict[str, float]:
        return {
            "mutation": self.mutation_weight,
            "static": self.static_weight,
            "baseline": self.baseline_weight,
            "sentinel_risk": self.sentinel_risk_weight,
            "co_change": self.co_change_weight,
            "security": self.security_weight,
        }

    @property
    def severity_weights(self) -> dict[str, int]:
        return {
            "critical": self.severity_critical,
            "high": self.severity_high,
            "medium": self.severity_medium,
            "low": self.severity_low,
            "info": self.severity_info,
        }

    @property
    def grade_thresholds(self) -> tuple[float, float, float, float]:
        return (self.grade_a, self.grade_b, self.grade_c, self.grade_d)


@dataclass(frozen=True)
class SecurityConfig:
    """Security analysis settings."""

    timeout: int = 120
    bandit_enabled: bool = True
    semgrep_enabled: bool = True
    detect_secrets_enabled: bool = True
    semgrep_rules: str = "auto"
    # Glob patterns to exclude from detect-secrets scanning
    detect_secrets_exclude: tuple[str, ...] = (
        "tests/", "test_*", "**/alembic/versions/", "**/migrations/",
    )
    # Bandit test IDs to skip entirely — B101 (assert) and B110
    # (try/except/pass) are informational noise in nearly all codebases
    bandit_skip: tuple[str, ...] = ("B101", "B110")


@dataclass(frozen=True)
class PipelineConfig:
    """Pipeline behavior settings."""

    baseline_runs: int = 3
    max_output_chars: int = 16_000
    db_dir: str = ".seraph"
    db_name: str = "seraph.db"


@dataclass(frozen=True)
class RetentionConfig:
    """Data retention settings."""

    retention_days: int = 90
    auto_prune: bool = False


@dataclass(frozen=True)
class LogConfig:
    """Logging configuration."""

    level: str = "WARNING"
    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    file: str = ""


@dataclass(frozen=True)
class SeraphConfig:
    """Top-level Seraph configuration."""

    timeouts: TimeoutConfig = TimeoutConfig()
    scoring: ScoringConfig = ScoringConfig()
    security: SecurityConfig = SecurityConfig()
    pipeline: PipelineConfig = PipelineConfig()
    retention: RetentionConfig = RetentionConfig()
    logging: LogConfig = LogConfig()

    @classmethod
    def load(cls, repo_path: str | Path) -> SeraphConfig:
        """Load config from .seraph/config.toml, env vars, and defaults.

        Priority: env vars > TOML file > defaults.
        """
        repo = Path(repo_path).resolve()
        config_file = repo / ".seraph" / "config.toml"

        toml_data: dict = {}
        if config_file.exists():
            with open(config_file, "rb") as f:
                toml_data = tomllib.load(f)

        return cls(
            timeouts=_build_section(TimeoutConfig, toml_data.get("timeouts", {}), "SERAPH_TIMEOUT"),
            scoring=_build_section(ScoringConfig, toml_data.get("scoring", {}), "SERAPH_SCORING"),
            security=_build_section(SecurityConfig, toml_data.get("security", {}), "SERAPH_SECURITY"),
            pipeline=_build_section(PipelineConfig, toml_data.get("pipeline", {}), "SERAPH_PIPELINE"),
            retention=_build_section(RetentionConfig, toml_data.get("retention", {}), "SERAPH_RETENTION"),
            logging=_build_section(LogConfig, toml_data.get("logging", {}), "SERAPH_LOG"),
        )


def _build_section(cls: type, toml_dict: dict, env_prefix: str):
    """Build a config section from TOML dict + env var overrides."""
    kwargs = {}
    for f in fields(cls):
        env_key = f"{env_prefix}_{f.name}".upper()
        env_val = os.environ.get(env_key)

        if env_val is not None:
            coerced = _coerce(env_val, f.type, env_key)
            if coerced is not None:
                kwargs[f.name] = coerced
        elif f.name in toml_dict:
            val = toml_dict[f.name]
            # TOML arrays arrive as lists; coerce to tuple for frozen dataclasses
            if isinstance(val, list) and "tuple" in str(f.type):
                val = tuple(val)
            kwargs[f.name] = val
        # else: use dataclass default

    return cls(**kwargs)


def _coerce(value: str, type_hint: str, env_key: str = ""):
    """Coerce a string env var value to the appropriate type."""
    if type_hint == "bool":
        return value.lower() in ("true", "1", "yes")
    if type_hint == "int":
        try:
            return int(value)
        except (ValueError, TypeError):
            logger.warning("Invalid int for %s: %r — ignoring env override", env_key, value)
            return None  # caller will fall through to TOML/default
    if type_hint == "float":
        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning("Invalid float for %s: %r — ignoring env override", env_key, value)
            return None
    return value
