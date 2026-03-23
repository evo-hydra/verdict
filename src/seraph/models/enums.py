"""Enums used across the Seraph system."""

from __future__ import annotations

from enum import Enum


class Grade(str, Enum):
    """Assessment grade for a scoring dimension."""

    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"
    VACUOUS = "VACUOUS"

    @classmethod
    def from_score(
        cls, score: float, thresholds: tuple[float, float, float, float] | None = None
    ) -> Grade:
        a, b, c, d = thresholds or (90.0, 75.0, 60.0, 40.0)
        if score >= a:
            return cls.A
        if score >= b:
            return cls.B
        if score >= c:
            return cls.C
        if score >= d:
            return cls.D
        return cls.F


class Severity(str, Enum):
    """Severity of a static analysis finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalyzerType(str, Enum):
    """Type of static analyzer."""

    RUFF = "ruff"
    MYPY = "mypy"
    BANDIT = "bandit"
    SEMGREP = "semgrep"
    DETECT_SECRETS = "detect-secrets"


class FeedbackOutcome(str, Enum):
    """Outcome of feedback on an assessment."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MODIFIED = "modified"


class MutantStatus(str, Enum):
    """Status of a mutation test result."""

    KILLED = "killed"
    SURVIVED = "survived"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"
