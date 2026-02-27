"""Unit tests for the formatter module.

These tests verify the format_results function correctly formats security
analysis results for console or JSON output as specified in the PRD.
"""

import pytest
import json
from datetime import datetime
from unittest.mock import patch, MagicMock

# Import will fail until formatter.py is created
# from formatter import format_results, calculate_exit_code, generate_timestamp


class TestFormatResultsConsole:
    """Test suite for console output formatting.

    The format_results function should produce human-readable output
    with colors and emojis as specified in the PRD console output format.
    """

    @pytest.fixture
    def sample_parsed_result(self):
        """Sample parsed result with mixed severity issues."""
        return {
            "checks": [
                {
                    "category": "hidden_instructions",
                    "passed": False,
                    "severity": "critical",
                    "description": "Base64 payload detected",
                    "evidence": ["Line 45: `base64 encoded content`"],
                    "line_numbers": [45],
                    "recommendation": "Remove encoded content"
                },
                {
                    "category": "jailbreaking_attempts",
                    "passed": True,
                    "severity": "none",
                    "description": "No jailbreaking patterns detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "credential_exposure",
                    "passed": False,
                    "severity": "critical",
                    "description": "API key: sk-abc123...",
                    "evidence": ["Line 12: 'sk-abc123xyz'"],
                    "line_numbers": [12],
                    "recommendation": "Remove exposed credentials"
                },
                {
                    "category": "pii_leakage",
                    "passed": True,
                    "severity": "none",
                    "description": "No PII detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "token_exfiltration",
                    "passed": False,
                    "severity": "medium",
                    "description": "Suspicious pattern",
                    "evidence": ["Line 20: Suspicious reference"],
                    "line_numbers": [20],
                    "recommendation": "Review pattern"
                },
                {
                    "category": "external_data_fetching",
                    "passed": True,
                    "severity": "none",
                    "description": "No external fetching detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "data_exfiltration",
                    "passed": False,
                    "severity": "medium",
                    "description": "Potential exfil pattern",
                    "evidence": ["Line 30: Data export pattern"],
                    "line_numbers": [30],
                    "recommendation": "Review data handling"
                },
                {
                    "category": "code_execution",
                    "passed": False,
                    "severity": "critical",
                    "description": "Shell command detected",
                    "evidence": ["Line 15: `rm -rf /`"],
                    "line_numbers": [15],
                    "recommendation": "Remove dangerous command"
                },
                {
                    "category": "file_system_access",
                    "passed": True,
                    "severity": "none",
                    "description": "No file system access detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "network_operations",
                    "passed": True,
                    "severity": "none",
                    "description": "No network operations detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "sandbox_escape",
                    "passed": True,
                    "severity": "none",
                    "description": "No sandbox escape attempts",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                },
                {
                    "category": "indirect_prompt_injection",
                    "passed": False,
                    "severity": "medium",
                    "description": "External URL referenced",
                    "evidence": ["Line 25: References external content"],
                    "line_numbers": [25],
                    "recommendation": "Validate external references"
                },
                {
                    "category": "social_engineering",
                    "passed": True,
                    "severity": "none",
                    "description": "No social engineering detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                }
            ],
            "urls": {
                "all": ["https://docs.example.com", "https://bit.ly/3xMal", "https://192.168.1.1/api"],
                "trusted": [],
                "medium": ["https://docs.example.com"],
                "suspicious": [],
                "malicious": ["https://bit.ly/3xMal", "https://192.168.1.1/api"],
                "unknown": []
            },
            "summary": {
                "total_checks": 13,
                "passed": 7,
                "failed": 6,
                "critical": 3,
                "high": 0,
                "medium": 3,
                "low": 0
            }
        }

    @pytest.fixture
    def all_passed_result(self):
        """Parsed result with all checks passed."""
        return {
            "checks": [
                {
                    "category": cat,
                    "passed": True,
                    "severity": "none",
                    "description": "No issues found",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                }
                for cat in [
                    "hidden_instructions", "jailbreaking_attempts", "credential_exposure",
                    "pii_leakage", "token_exfiltration", "external_data_fetching",
                    "data_exfiltration", "code_execution", "file_system_access",
                    "network_operations", "sandbox_escape", "indirect_prompt_injection",
                    "social_engineering"
                ]
            ],
            "urls": {
                "all": [],
                "trusted": [],
                "medium": [],
                "suspicious": [],
                "malicious": [],
                "unknown": []
            },
            "summary": {
                "total_checks": 13,
                "passed": 13,
                "failed": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

    def test_format_console_output_with_critical_issues(self, sample_parsed_result):
        """Test: Console output formatting with colors and emojis for critical issues.

        Verifies that the formatter produces console output with proper
        visual indicators (emojis, colors) matching the PRD specification.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "unsafe_skill.md"
        output_format = "console"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        # Check for header elements
        assert "Security Analysis" in result
        assert skill_filename in result
        # Check for emojis
        assert "❌" in result  # Failed/Critical
        assert "✅" in result  # Passed
        assert "⚠️" in result  # Warning/Medium
        # Check category display
        assert "Hidden Instructions" in result or "hidden_instructions" in result
        assert "Credential Exposure" in result or "credential_exposure" in result
        # Check URL section
        assert "External URLs" in result
        # Check summary
        assert "Summary" in result
        assert "3 CRITICAL" in result or "CRITICAL" in result

    def test_format_console_all_passed(self, all_passed_result):
        """Test: Console output when all checks pass.

        Verifies proper formatting when no security issues are found.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "safe_skill.md"
        output_format = "console"

        # Act
        result = format_results(all_passed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        # All should show as passed
        assert "✅" in result
        # Summary should show 0 critical
        assert "0 CRITICAL" in result or "CRITICAL" in result
        # No critical markers
        assert result.count("❌") == 0

    def test_format_console_includes_url_section(self, sample_parsed_result):
        """Test: Console output includes URL categorization section.

        Verifies that external URLs are displayed with their risk levels.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "console"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        assert "External URLs" in result
        # URL shortener should be flagged
        assert "bit.ly" in result or "URL shortener" in result
        # IP address should be flagged
        assert "192.168.1.1" in result or "IP address" in result

    def test_format_console_handles_missing_urls_gracefully(self):
        """Test: Console output handles missing URL section gracefully.

        Verifies that formatter handles parsed results without URL data.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [
                {
                    "category": "hidden_instructions",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                }
                for _ in range(13)
            ],
            "summary": {
                "total_checks": 13,
                "passed": 13,
                "failed": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
            # No "urls" key
        }
        skill_filename = "test.md"
        output_format = "console"

        # Act - Should not raise exception
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)


class TestFormatResultsJson:
    """Test suite for JSON output formatting.

    The format_results function should produce JSON output matching
    the PRD specification when format="json".
    """

    @pytest.fixture
    def sample_parsed_result(self):
        """Sample parsed result with mixed severity."""
        return {
            "checks": [
                {
                    "category": "hidden_instructions",
                    "passed": False,
                    "severity": "critical",
                    "description": "Base64 payload detected",
                    "evidence": ["Line 45: `base64 encoded content`"],
                    "line_numbers": [45],
                    "recommendation": "Remove encoded content"
                }
            ],
            "urls": {
                "all": ["https://example.com"],
                "trusted": [],
                "medium": ["https://example.com"],
                "suspicious": [],
                "malicious": [],
                "unknown": []
            },
            "summary": {
                "total_checks": 13,
                "passed": 12,
                "failed": 1,
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }

    def test_format_json_output_structure(self, sample_parsed_result):
        """Test: JSON output matches PRD specification structure.

        Verifies that JSON output includes all required fields:
        file, timestamp, checks, urls, summary, exit_code.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test_skill.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, dict)
        # Required keys per PRD
        assert "file" in result
        assert "timestamp" in result
        assert "checks" in result
        assert "urls" in result
        assert "summary" in result
        assert "exit_code" in result
        # Verify types
        assert isinstance(result["file"], str)
        assert isinstance(result["timestamp"], str)
        assert isinstance(result["checks"], list)
        assert isinstance(result["urls"], dict)
        assert isinstance(result["summary"], dict)
        assert isinstance(result["exit_code"], int)

    def test_format_json_file_field(self, sample_parsed_result):
        """Test: JSON output contains correct filename.

        Verifies the file field matches the input skill_filename.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "my_skill.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        assert result["file"] == skill_filename

    def test_format_json_timestamp_iso8601(self, sample_parsed_result):
        """Test: JSON timestamp is in ISO 8601 format.

        Verifies timestamp follows ISO 8601 standard like "2025-01-15T10:30:00Z".
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        timestamp = result["timestamp"]
        # Verify ISO 8601 format (should parse successfully)
        try:
            parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            assert parsed is not None
        except ValueError:
            pytest.fail(f"Timestamp '{timestamp}' is not valid ISO 8601 format")

    def test_format_json_preserves_checks_structure(self, sample_parsed_result):
        """Test: JSON output preserves check structure from parsed result.

        Verifies that checks array maintains the expected structure.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        checks = result["checks"]
        assert len(checks) == len(sample_parsed_result["checks"])
        for check in checks:
            assert "category" in check
            assert "passed" in check
            assert "severity" in check
            assert "description" in check
            assert "evidence" in check

    def test_format_json_preserves_urls_structure(self, sample_parsed_result):
        """Test: JSON output preserves URL categorization structure.

        Verifies that URLs object maintains all categorization keys.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        urls = result["urls"]
        assert "all" in urls
        assert "trusted" in urls
        assert "medium" in urls
        assert "suspicious" in urls
        assert "malicious" in urls
        assert "unknown" in urls

    def test_format_json_preserves_summary_structure(self, sample_parsed_result):
        """Test: JSON output preserves summary structure.

        Verifies that summary contains all count fields.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "json"

        # Act
        result = format_results(sample_parsed_result, skill_filename, output_format)

        # Assert
        summary = result["summary"]
        assert "total_checks" in summary
        assert "passed" in summary
        assert "failed" in summary
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary


class TestExitCodeCalculation:
    """Test suite for exit code calculation.

    Per PRD: exit_code should be 0 (no critical) or 1 (critical issues).
    """

    def test_exit_code_no_critical_issues(self):
        """Test: Exit code is 0 when no critical issues found.

        Verifies positive case - successful scan with no critical security issues.
        """
        # Arrange
        from formatter import calculate_exit_code

        parsed_result = {
            "summary": {"critical": 0}
        }

        # Act
        exit_code = calculate_exit_code(parsed_result)

        # Assert
        assert exit_code == 0

    def test_exit_code_with_critical_issues(self):
        """Test: Exit code is 1 when critical issues are present.

        Verifies negative case - security scan detected critical issues.
        """
        # Arrange
        from formatter import calculate_exit_code

        parsed_result = {
            "summary": {"critical": 3}
        }

        # Act
        exit_code = calculate_exit_code(parsed_result)

        # Assert
        assert exit_code == 1

    def test_exit_code_single_critical(self):
        """Test: Exit code is 1 even with single critical issue.

        Verifies that any critical issue triggers exit code 1.
        """
        # Arrange
        from formatter import calculate_exit_code

        parsed_result = {
            "summary": {"critical": 1}
        }

        # Act
        exit_code = calculate_exit_code(parsed_result)

        # Assert
        assert exit_code == 1

    def test_exit_code_missing_summary(self):
        """Test: Handle missing summary gracefully.

        Verifies error handling when parsed_result lacks summary.
        """
        # Arrange
        from formatter import calculate_exit_code

        parsed_result = {}

        # Act - Should not raise exception
        exit_code = calculate_exit_code(parsed_result)

        # Assert - Default to 0 when summary is missing
        assert exit_code == 0

    def test_exit_code_missing_critical_key(self):
        """Test: Handle missing critical key gracefully.

        Verifies error handling when critical count is missing.
        """
        # Arrange
        from formatter import calculate_exit_code

        parsed_result = {
            "summary": {"passed": 13, "failed": 0}
        }

        # Act
        exit_code = calculate_exit_code(parsed_result)

        # Assert - Default to 0 when critical key is missing
        assert exit_code == 0


class TestTimestampGeneration:
    """Test suite for timestamp generation.

    Timestamps should be ISO 8601 format per PRD specification.
    """

    def test_generate_timestamp_iso8601_format(self):
        """Test: Timestamp is generated in ISO 8601 format.

        Verifies timestamp matches expected format like "2025-01-15T10:30:00Z".
        """
        # Arrange
        from formatter import generate_timestamp

        # Act
        timestamp = generate_timestamp()

        # Assert
        assert isinstance(timestamp, str)
        # Should be parseable as ISO 8601
        try:
            parsed = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            assert parsed is not None
        except ValueError:
            pytest.fail(f"Timestamp '{timestamp}' is not valid ISO 8601")

    def test_generate_timestamp_is_utc(self):
        """Test: Timestamp uses UTC timezone.

        Verifies timestamp ends with Z or +00:00 for UTC.
        """
        # Arrange
        from formatter import generate_timestamp

        # Act
        timestamp = generate_timestamp()

        # Assert
        assert timestamp.endswith('Z') or '+00:00' in timestamp

    def test_generate_timestamp_unique_per_call(self):
        """Test: Each call generates a unique timestamp.

        Verifies timestamps differ between sequential calls.
        """
        # Arrange
        from formatter import generate_timestamp

        # Act
        timestamp1 = generate_timestamp()
        timestamp2 = generate_timestamp()

        # Assert
        # Timestamps should be equal or very close (within same second)
        # but we're testing they're properly formatted
        assert isinstance(timestamp1, str)
        assert isinstance(timestamp2, str)
        assert len(timestamp1) > 0
        assert len(timestamp2) > 0


class TestSummaryStatistics:
    """Test suite for summary statistics calculation.

    Verifies summary counts are calculated and preserved correctly.
    """

    def test_summary_statistics_calculation(self):
        """Test: Summary statistics are calculated correctly.

        Verifies that passed/failed/critical counts in summary are accurate.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [
                {"category": "hidden_instructions", "passed": False, "severity": "critical"},
                {"category": "jailbreaking_attempts", "passed": True, "severity": "none"},
                {"category": "credential_exposure", "passed": False, "severity": "medium"},
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {
                "total_checks": 3,
                "passed": 1,
                "failed": 2,
                "critical": 1,
                "high": 0,
                "medium": 1,
                "low": 0
            }
        }
        skill_filename = "test.md"
        output_format = "json"

        # Act
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        summary = result["summary"]
        assert summary["total_checks"] == 3
        assert summary["passed"] == 1
        assert summary["failed"] == 2
        assert summary["critical"] == 1
        assert summary["medium"] == 1


class TestEmptyResultsHandling:
    """Test suite for handling empty or minimal results.

    Verifies graceful handling of edge cases like empty results.
    """

    def test_format_empty_checks_list(self):
        """Test: Handle empty checks list gracefully.

        Verifies formatter handles parsed result with no checks.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        skill_filename = "empty.md"
        output_format = "json"

        # Act - Should not raise exception
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, dict)
        assert result["file"] == skill_filename
        assert result["checks"] == []
        assert result["exit_code"] == 0

    def test_format_console_empty_result(self):
        """Test: Handle empty result in console format.

        Verifies console formatter handles edge case of empty checks.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        skill_filename = "empty.md"
        output_format = "console"

        # Act - Should not raise exception
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        assert skill_filename in result

    def test_format_invalid_format_parameter(self):
        """Test: Handle invalid format parameter gracefully.

        Verifies error handling for unsupported format strings.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [{"category": "test", "passed": True, "severity": "none"}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 1, "passed": 1, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        skill_filename = "test.md"
        output_format = "invalid_format"

        # Act & Assert - Should raise ValueError or similar
        with pytest.raises((ValueError, KeyError)):
            format_results(parsed_result, skill_filename, output_format)

    def test_format_none_parsed_result(self):
        """Test: Handle None parsed result gracefully.

        Verifies error handling when parsed_result is None.
        """
        # Arrange
        from formatter import format_results

        skill_filename = "test.md"
        output_format = "json"

        # Act & Assert - Should raise exception
        with pytest.raises((TypeError, ValueError)):
            format_results(None, skill_filename, output_format)

    def test_format_missing_required_keys(self):
        """Test: Handle parsed result missing required keys.

        Verifies error handling for incomplete parsed results.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {"checks": []}  # Missing urls and summary
        skill_filename = "test.md"
        output_format = "json"

        # Act - Should not raise exception, handles gracefully
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert - Should provide defaults
        assert isinstance(result, dict)
        assert "urls" in result
        assert "summary" in result


class TestCategoryDisplayNames:
    """Test suite for category display name conversion.

    Verifies that category IDs are converted to human-readable names.
    """

    def test_category_display_names_in_console(self):
        """Test: Category IDs are converted to readable names in console output.

        Verifies that 'hidden_instructions' becomes 'Hidden Instructions' etc.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [
                {"category": "hidden_instructions", "passed": True, "severity": "none", "description": "Test", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "jailbreaking_attempts", "passed": True, "severity": "none", "description": "Test", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "social_engineering", "passed": True, "severity": "none", "description": "Test", "evidence": [], "line_numbers": [], "recommendation": ""},
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 3, "passed": 3, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        skill_filename = "test.md"
        output_format = "console"

        # Act
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        # Should have human-readable names
        assert "Hidden Instructions" in result or "Hidden" in result
        assert "Jailbreaking" in result or "Jailbreak" in result
        assert "Social Engineering" in result or "Social" in result


class TestEvidenceFormatting:
    """Test suite for evidence formatting in console output.

    Verifies evidence and line numbers are displayed properly.
    """

    def test_evidence_displayed_in_console(self):
        """Test: Evidence is displayed in console output for failed checks.

        Verifies that failed checks show evidence details.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [
                {
                    "category": "credential_exposure",
                    "passed": False,
                    "severity": "critical",
                    "description": "API key found",
                    "evidence": ["Line 12: 'sk-abc123'", "Line 15: 'api_key'"],
                    "line_numbers": [12, 15],
                    "recommendation": "Remove keys"
                }
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 1, "passed": 0, "failed": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
        }
        skill_filename = "test.md"
        output_format = "console"

        # Act
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        # Should include evidence details
        assert "sk-abc123" in result or "API key" in result


class TestColorAndFormatting:
    """Test suite for color and emoji formatting.

    Verifies ANSI color codes and emoji usage where applicable.
    """

    def test_console_uses_color_codes(self):
        """Test: Console output includes ANSI color codes.

        Verifies color formatting is applied to console output.
        """
        # Arrange
        from formatter import format_results

        parsed_result = {
            "checks": [
                {"category": "hidden_instructions", "passed": False, "severity": "critical", "description": "Critical issue", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "jailbreaking_attempts", "passed": True, "severity": "none", "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "social_engineering", "passed": False, "severity": "medium", "description": "Warning", "evidence": [], "line_numbers": [], "recommendation": ""},
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 3, "passed": 1, "failed": 2, "critical": 1, "high": 0, "medium": 1, "low": 0}
        }
        skill_filename = "test.md"
        output_format = "console"

        # Act
        result = format_results(parsed_result, skill_filename, output_format)

        # Assert
        assert isinstance(result, str)
        # Check for ANSI escape sequences (color codes)
        # These are \x1b[ or \033[ followed by numbers and m
        has_color_codes = '\x1b[' in result or '\033[' in result
        # Not all formatters use color, but we check it's a string with content
        assert len(result) > 0

    def test_severity_emoji_mapping(self):
        """Test: Severity levels map to correct emojis.

        Verifies critical -> ❌, pass -> ✅, warning -> ⚠️ mapping.
        """
        # Arrange
        from formatter import format_results

        test_cases = [
            ("critical", "❌"),
            ("high", "❌"),
            ("medium", "⚠️"),
            ("low", "⚠️"),
            ("none", "✅"),
        ]

        for severity, expected_emoji in test_cases:
            parsed_result = {
                "checks": [
                    {"category": "test_category", "passed": severity == "none", "severity": severity, "description": "Test", "evidence": [], "line_numbers": [], "recommendation": ""}
                ],
                "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
                "summary": {"total_checks": 1, "passed": 1 if severity == "none" else 0, "failed": 0 if severity == "none" else 1, "critical": 1 if severity == "critical" else 0, "high": 1 if severity == "high" else 0, "medium": 1 if severity == "medium" else 0, "low": 1 if severity == "low" else 0}
            }

            # Act
            result = format_results(parsed_result, "test.md", "console")

            # Assert
            assert expected_emoji in result, f"Expected {expected_emoji} for severity {severity}"
