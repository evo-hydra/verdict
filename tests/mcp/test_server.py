"""Tests for MCP server formatters."""

from __future__ import annotations

from seraph.mcp.formatters import (
    MAX_OUTPUT_CHARS,
    _truncate,
    format_assessment,
    format_feedback_response,
    format_history,
    format_mutations,
)
from seraph.models.assessment import MutationResult, StoredAssessment
from seraph.models.enums import MutantStatus


class TestFormatAssessment:
    def test_basic_format(self):
        report = {
            "id": "abc12345",
            "overall_grade": "B",
            "overall_score": 78.5,
            "files_changed": ["foo.py", "bar.py"],
            "dimensions": [
                {"name": "Mutation Score", "grade": "A", "raw_score": 95.0, "details": "10/10 killed"},
            ],
            "gaps": ["Static: C (55%) — 3 ruff issues"],
            "created_at": "2026-01-01 00:00:00",
        }
        output = format_assessment(report)
        assert "## Seraph Assessment: B" in output
        assert "78.5/100" in output
        assert "Mutation Score" in output
        assert "abc12345" in output

    def test_empty_report(self):
        output = format_assessment({"overall_grade": "?", "overall_score": 0})
        assert "## Seraph Assessment" in output

    def test_unevaluated_dimensions(self):
        report = {
            "overall_grade": "B",
            "overall_score": 75,
            "dimensions": [
                {"name": "Mutation Score", "grade": "A", "raw_score": 90.0, "details": "9/10", "evaluated": True},
                {"name": "Static", "evaluated": False},
            ],
        }
        output = format_assessment(report)
        assert "Mutation Score" in output
        assert "90.0%" in output
        assert "N/A (not evaluated)" in output

    def test_vacuous_returns_error_message(self):
        report = {
            "id": "vac12345",
            "is_vacuous": True,
            "overall_grade": "VACUOUS",
            "overall_score": 0.0,
            "files_changed": [],
            "evaluated_count": 0,
            "dimension_count": 6,
        }
        output = format_assessment(report)
        assert "VACUOUS" in output
        assert "0 dimensions evaluated" in output
        assert "SERAPH_UNAVAILABLE" in output
        assert "vac12345" in output
        # Should NOT contain normal grade card elements
        assert "Score:" not in output
        assert "### Dimensions" not in output

    def test_non_vacuous_shows_normal_card(self):
        report = {
            "id": "ok12345",
            "is_vacuous": False,
            "overall_grade": "B",
            "overall_score": 78.0,
            "files_changed": ["foo.py"],
            "dimensions": [],
        }
        output = format_assessment(report)
        assert "## Seraph Assessment: B" in output
        assert "78.0/100" in output

    def test_malformed_dimension_uses_defaults(self):
        report = {
            "overall_grade": "?",
            "overall_score": 0,
            "dimensions": [{}],
        }
        output = format_assessment(report)
        assert "?" in output


class TestFormatHistory:
    def test_empty(self):
        assert format_history([]) == "No assessments found."

    def test_with_entries(self):
        entries = [
            StoredAssessment(
                id="abc12345",
                grade="A",
                mutation_score=95.0,
                static_issues=0,
                files_changed=["foo.py"],
                created_at="2026-01-01",
            )
        ]
        output = format_history(entries)
        assert "abc12345" in output
        assert "A" in output

    def test_zero_values_not_hidden(self):
        entries = [
            StoredAssessment(
                id="abc12345",
                grade="F",
                mutation_score=0.0,
                static_issues=0,
                files_changed=[],
                created_at="2026-01-01",
            )
        ]
        output = format_history(entries)
        assert "0.0%" in output
        assert "0 issues" in output


class TestFormatMutations:
    def test_no_mutations(self):
        output = format_mutations([], 100.0)
        assert "100%" in output

    def test_with_mutations(self):
        muts = [
            MutationResult(file_path="foo.py", line_number=5, operator="negate", status=MutantStatus.SURVIVED),
            MutationResult(file_path="foo.py", line_number=10, operator="remove", status=MutantStatus.KILLED),
        ]
        output = format_mutations(muts, 50.0)
        assert "50.0%" in output
        assert "Survived" in output or "survived" in output.lower()


class TestFormatFeedback:
    def test_format(self):
        output = format_feedback_response("abc12345678", "accepted")
        assert "accepted" in output
        assert "abc12345" in output


class TestTruncate:
    def test_short_text_unchanged(self):
        text = "hello world"
        assert _truncate(text) == text

    def test_exact_limit_unchanged(self):
        text = "x" * MAX_OUTPUT_CHARS
        assert _truncate(text) == text

    def test_over_limit_truncated(self):
        text = "x" * (MAX_OUTPUT_CHARS + 100)
        result = _truncate(text)
        assert len(result) <= MAX_OUTPUT_CHARS
        assert result.endswith("... (output truncated)")
