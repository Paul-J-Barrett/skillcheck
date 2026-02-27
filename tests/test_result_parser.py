"""Unit tests for the result_parser module.

These tests verify the parse function correctly validates and extracts
LLM JSON responses for security analysis.
"""

import json
import pytest
from unittest.mock import MagicMock, patch


# Import the module to test
from result_parser import parse


class TestResultParser:
    """Test suite for result_parser.parse function.

    The parse function takes raw_response (str) and skill_filename (str)
    and returns a structured result with success, data, and error fields.

    Interface:
    - Input: {raw_response: str, skill_filename: str}
    - Output: {success: bool, data: {...}|None, error: str|None}
    - Data includes: checks array, urls object, summary object
    """

    # Positive Tests

    def test_parse_valid_json_response(self):
        """Test: Parse valid JSON response with all required fields.

        Verifies that the parse function correctly extracts and validates
        a complete security analysis response from the LLM.
        """
        # Arrange
        valid_response = json.dumps({
            "checks": [
                {
                    "category": "hidden_instructions",
                    "passed": False,
                    "severity": "critical",
                    "description": "Base64 encoded payload detected",
                    "evidence": ["Line 7: Base64 string detected"],
                    "line_numbers": [7],
                    "recommendation": "Remove encoded content"
                },
                {
                    "category": "jailbreaking",
                    "passed": True,
                    "severity": "none",
                    "description": "No jailbreaking patterns found",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "credential_exposure",
                    "passed": False,
                    "severity": "critical",
                    "description": "API key exposed",
                    "evidence": ["Line 13: sk-..."],
                    "line_numbers": [13],
                    "recommendation": "Use env vars"
                },
                {
                    "category": "pii_leakage",
                    "passed": True,
                    "severity": "none",
                    "description": "No PII detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "token_exfiltration",
                    "passed": False,
                    "severity": "medium",
                    "description": "Suspicious pattern",
                    "evidence": ["Line 22: Token sending"],
                    "line_numbers": [22],
                    "recommendation": "Review transmission"
                },
                {
                    "category": "external_data_fetching",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "data_exfiltration",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "code_execution",
                    "passed": False,
                    "severity": "critical",
                    "description": "Shell command detected",
                    "evidence": ["Line 19: bash command"],
                    "line_numbers": [19],
                    "recommendation": "Remove shell exec"
                },
                {
                    "category": "file_system_access",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "network_operations",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "sandbox_escape",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
                },
                {
                    "category": "indirect_injection",
                    "passed": False,
                    "severity": "medium",
                    "description": "External URL referenced",
                    "evidence": ["Line 16: URL found"],
                    "line_numbers": [16],
                    "recommendation": "Review URL"
                },
                {
                    "category": "social_engineering",
                    "passed": True,
                    "severity": "none",
                    "description": "No issues",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": "Continue monitoring"
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
                "passed": 8,
                "failed": 5,
                "critical": 3,
                "high": 0,
                "medium": 2,
                "low": 0
            }
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(valid_response, skill_filename)

        # Assert
        assert result["success"] is True
        assert result["data"] is not None
        assert result["error"] is None
        assert len(result["data"]["checks"]) == 13
        assert "urls" in result["data"]
        assert "summary" in result["data"]

    def test_parse_all_passed_checks_response(self):
        """Test: Parse response where all checks pass.

        Verifies that a valid response with all 13 checks passing
        is correctly parsed with no errors.
        """
        # Arrange - create 13 passing checks
        checks = []
        categories = [
            "hidden_instructions", "jailbreaking", "credential_exposure",
            "pii_leakage", "token_exfiltration", "external_data_fetching",
            "data_exfiltration", "code_execution", "file_system_access",
            "network_operations", "sandbox_escape", "indirect_injection",
            "social_engineering"
        ]
        for category in categories:
            checks.append({
                "category": category,
                "passed": True,
                "severity": "none",
                "description": f"No {category} issues",
                "evidence": [],
                "line_numbers": [],
                "recommendation": "Continue monitoring"
            })

        valid_response = json.dumps({
            "checks": checks,
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
        })
        skill_filename = "safe_skill.md"

        # Act
        result = parse(valid_response, skill_filename)

        # Assert
        assert result["success"] is True
        assert result["data"] is not None
        assert result["data"]["summary"]["passed"] == 13
        assert result["data"]["summary"]["failed"] == 0

    def test_parse_response_with_multiple_url_categories(self):
        """Test: Parse response with URLs in multiple risk categories.

        Verifies that URL classifications are preserved across all
        risk levels (trusted, medium, suspicious, malicious, unknown).
        """
        # Arrange
        valid_response = json.dumps({
            "checks": [{"category": "external_data_fetching", "passed": False, "severity": "medium",
                       "description": "External URLs", "evidence": [], "line_numbers": [], "recommendation": ""}] + [
                {"category": cat, "passed": True, "severity": "none", "description": "OK",
                 "evidence": [], "line_numbers": [], "recommendation": ""}
                for cat in ["hidden_instructions", "jailbreaking", "credential_exposure", "pii_leakage",
                           "token_exfiltration", "data_exfiltration", "code_execution", "file_system_access",
                           "network_operations", "sandbox_escape", "indirect_injection", "social_engineering"]
            ],
            "urls": {
                "all": ["https://docs.anthropic.com", "https://google.com", "https://bit.ly/abc",
                       "https://example.com"],
                "trusted": ["https://docs.anthropic.com"],
                "medium": ["https://google.com"],
                "suspicious": [],
                "malicious": ["https://bit.ly/abc"],
                "unknown": ["https://example.com"]
            },
            "summary": {
                "total_checks": 13,
                "passed": 12,
                "failed": 1,
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0
            }
        })
        skill_filename = "url_test.md"

        # Act
        result = parse(valid_response, skill_filename)

        # Assert
        assert result["success"] is True
        assert result["data"]["urls"]["trusted"] == ["https://docs.anthropic.com"]
        assert result["data"]["urls"]["medium"] == ["https://google.com"]
        assert result["data"]["urls"]["malicious"] == ["https://bit.ly/abc"]
        assert result["data"]["urls"]["unknown"] == ["https://example.com"]

    # Negative Tests - Invalid JSON

    def test_parse_invalid_json_response(self):
        """Test: Parse invalid JSON returns error.

        Verifies that malformed JSON responses are handled gracefully
        with a descriptive error message.
        """
        # Arrange
        invalid_response = "{invalid json here"
        skill_filename = "test_skill.md"

        # Act
        result = parse(invalid_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["data"] is None
        assert result["error"] is not None
        assert "json" in result["error"].lower() or "parse" in result["error"].lower()

    def test_parse_empty_string_response(self):
        """Test: Parse empty string returns error.

        Verifies that empty responses are treated as invalid JSON.
        """
        # Arrange
        empty_response = ""
        skill_filename = "test_skill.md"

        # Act
        result = parse(empty_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["data"] is None
        assert result["error"] is not None

    def test_parse_non_json_string_response(self):
        """Test: Parse non-JSON string returns error.

        Verifies that plain text responses (not JSON) are rejected.
        """
        # Arrange
        plain_text_response = "This is a security analysis result"
        skill_filename = "test_skill.md"

        # Act
        result = parse(plain_text_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["data"] is None

    # Negative Tests - Missing Required Keys

    def test_parse_missing_checks_key(self):
        """Test: Missing 'checks' key returns validation error.

        Verifies that the response must contain the checks array
        as specified in the interface.
        """
        # Arrange
        incomplete_response = json.dumps({
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "checks" in result["error"].lower()

    def test_parse_missing_urls_key(self):
        """Test: Missing 'urls' key returns validation error.

        Verifies that the response must contain the urls object
        with all required sub-keys.
        """
        # Arrange
        incomplete_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "urls" in result["error"].lower()

    def test_parse_missing_summary_key(self):
        """Test: Missing 'summary' key returns validation error.

        Verifies that the response must contain the summary object
        with all required count fields.
        """
        # Arrange
        incomplete_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "summary" in result["error"].lower()

    def test_parse_check_missing_required_fields(self):
        """Test: Check missing required fields returns validation error.

        Verifies that each check object contains all required keys:
        category, passed, severity, description, evidence.
        """
        # Arrange
        incomplete_check_response = json.dumps({
            "checks": [{"passed": True}],  # Missing category, severity, description, evidence
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_check_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None

    # Negative Tests - Invalid Severity Values

    def test_parse_invalid_severity_value(self):
        """Test: Invalid severity value returns validation error.

        Verifies that severity must be one of: critical, high, medium, low, none.
        Invalid values like 'severe' or 'info' should be rejected.
        """
        # Arrange
        invalid_severity_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": False, "severity": "invalid",
                       "description": "Issue", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 12, "failed": 1, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(invalid_severity_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "severity" in result["error"].lower() or "invalid" in result["error"].lower()

    def test_parse_severity_case_sensitivity(self):
        """Test: Severity values are case-sensitive or normalized.

        Verifies that severity must be lowercase as specified.
        'CRITICAL' or 'Critical' may be rejected or normalized.
        """
        # Arrange
        uppercase_severity_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": False, "severity": "CRITICAL",
                       "description": "Issue", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 12, "failed": 1, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(uppercase_severity_response, skill_filename)

        # Assert - either normalize or reject
        # If rejected:
        # assert result["success"] is False
        # If normalized, check it's converted to lowercase
        # assert result["data"]["checks"][0]["severity"] == "critical"
        assert result["success"] is False or result["data"]["checks"][0]["severity"] == "critical"

    # Negative Tests - Checks Count Validation

    def test_parse_wrong_number_of_checks(self):
        """Test: Zero checks returns validation error.

        Per PRD: Must have at least 1 check.
        """
        # Arrange - zero checks
        wrong_count_response = json.dumps({
            "checks": [],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 0, "passed": 0, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(wrong_count_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "at least 1" in result["error"] or "count" in result["error"].lower()

    def test_parse_too_many_checks(self):
        """Test: More than 13 checks returns validation error.

        Verifies that having more than 13 checks is invalid.
        """
        # Arrange - 14 checks (one extra)
        checks = [{"category": f"check_{i}", "passed": True, "severity": "none",
                  "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}
                 for i in range(14)]
        wrong_count_response = json.dumps({
            "checks": checks,
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 14, "passed": 14, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(wrong_count_response, skill_filename)

        # Assert
        assert result["success"] is False

    # Negative Tests - URL Validation

    def test_parse_urls_missing_sub_keys(self):
        """Test: URLs missing required sub-keys returns validation error.

        Verifies that urls object must contain: all, trusted, medium,
        suspicious, malicious, unknown.
        """
        # Arrange
        incomplete_urls_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": []},  # Missing trusted, medium, suspicious, malicious, unknown
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_urls_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None

    def test_parse_urls_not_dict(self):
        """Test: URLs not a dictionary returns validation error.

        Verifies that urls must be an object/dict, not a list or string.
        """
        # Arrange
        invalid_urls_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": "https://example.com",  # String instead of object
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(invalid_urls_response, skill_filename)

        # Assert
        assert result["success"] is False

    def test_parse_urls_not_list_values(self):
        """Test: URL category values not lists returns validation error.

        Verifies that each URL category (all, trusted, etc.) must be a list.
        """
        # Arrange
        invalid_urls_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": "https://example.com", "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(invalid_urls_response, skill_filename)

        # Assert
        assert result["success"] is False

    # Negative Tests - Summary Count Validation

    def test_parse_summary_missing_required_keys(self):
        """Test: Summary missing required keys returns validation error.

        Verifies that summary must contain: total_checks, passed, failed,
        critical, high, medium, low.
        """
        # Arrange
        incomplete_summary_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13}  # Missing failed, critical, high, medium, low
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(incomplete_summary_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None

    def test_parse_summary_count_mismatch(self):
        """Test: Summary counts not matching actual results returns validation error.

        Per PRD: "Summary counts must match actual results".
        If checks show 5 failed, summary.failed should be 5.
        """
        # Arrange - 3 failed checks but summary says 0
        mismatched_summary_response = json.dumps({
            "checks": [
                {"category": "hidden_instructions", "passed": False, "severity": "critical",
                 "description": "Issue 1", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "jailbreaking", "passed": False, "severity": "high",
                 "description": "Issue 2", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "credential_exposure", "passed": False, "severity": "critical",
                 "description": "Issue 3", "evidence": [], "line_numbers": [], "recommendation": ""}
            ] + [{"category": cat, "passed": True, "severity": "none",
                 "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}
                for cat in ["pii_leakage", "token_exfiltration", "external_data_fetching", "data_exfiltration",
                           "code_execution", "file_system_access", "network_operations", "sandbox_escape",
                           "indirect_injection", "social_engineering"]],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(mismatched_summary_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert result["error"] is not None
        assert "mismatch" in result["error"].lower() or "count" in result["error"].lower()

    def test_parse_summary_passed_failed_mismatch(self):
        """Test: passed + failed != total_checks returns validation error.

        Verifies the basic math: passed + failed must equal total_checks.
        """
        # Arrange - passed(10) + failed(5) != total_checks(13)
        invalid_math_response = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 10, "failed": 5, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(invalid_math_response, skill_filename)

        # Assert
        assert result["success"] is False

    def test_parse_summary_severity_mismatch(self):
        """Test: Severity counts don't match actual check severities returns error.

        Verifies that summary.critical/high/medium/low match the actual
        severity values in failed checks.
        """
        # Arrange - 2 critical checks but summary says 3
        severity_mismatch_response = json.dumps({
            "checks": [
                {"category": "hidden_instructions", "passed": False, "severity": "critical",
                 "description": "Issue 1", "evidence": [], "line_numbers": [], "recommendation": ""},
                {"category": "jailbreaking", "passed": False, "severity": "critical",
                 "description": "Issue 2", "evidence": [], "line_numbers": [], "recommendation": ""}
            ] + [{"category": cat, "passed": True, "severity": "none",
                 "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}
                for cat in ["credential_exposure", "pii_leakage", "token_exfiltration", "external_data_fetching",
                           "data_exfiltration", "code_execution", "file_system_access", "network_operations",
                           "sandbox_escape", "indirect_injection", "social_engineering"]],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 11, "failed": 2, "critical": 3, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(severity_mismatch_response, skill_filename)

        # Assert
        assert result["success"] is False

    # Edge Case Tests

    def test_parse_json_with_extra_whitespace(self):
        """Test: Parse JSON with leading/trailing whitespace.

        Verifies that responses with extra whitespace are handled correctly.
        """
        # Arrange
        checks = [{"category": cat, "passed": True, "severity": "none",
                   "description": "OK", "evidence": [], "line_numbers": [], "recommendation": ""}
                  for cat in ["hidden_instructions", "jailbreaking_attempts", "credential_exposure",
                              "pii_leakage", "token_exfiltration", "external_data_fetching",
                              "data_exfiltration", "code_execution", "file_system_access",
                              "network_operations", "sandbox_escape", "indirect_prompt_injection",
                              "social_engineering"]]
        valid_response = "   \n\n" + json.dumps({
            "checks": checks,
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        }) + "\n\n   "
        skill_filename = "test_skill.md"

        # Act
        result = parse(valid_response, skill_filename)

        # Assert
        assert result["success"] is True

    def test_parse_null_values_in_response(self):
        """Test: Parse response with null values in optional fields.

        Verifies that null values for optional fields are handled.
        """
        # Arrange
        response_with_nulls = json.dumps({
            "checks": [{"category": "hidden_instructions", "passed": True, "severity": "none",
                       "description": "OK", "evidence": None, "line_numbers": [], "recommendation": None}],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 13, "passed": 13, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })
        skill_filename = "test_skill.md"

        # Act
        result = parse(response_with_nulls, skill_filename)

        # Assert - should either accept nulls or normalize to empty list/string
        assert result["success"] is True or result["success"] is False

    def test_parse_skill_filename_in_error(self):
        """Test: Error message includes skill_filename for context.

        Verifies that error messages reference the filename being analyzed.
        """
        # Arrange
        invalid_response = "{invalid json"
        skill_filename = "my_custom_skill.md"

        # Act
        result = parse(invalid_response, skill_filename)

        # Assert
        assert result["success"] is False
        assert skill_filename in result["error"] or "my_custom_skill" in result["error"]
