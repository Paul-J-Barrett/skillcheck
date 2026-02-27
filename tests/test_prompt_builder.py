"""Unit tests for the prompt_builder module.

These tests verify the build_analysis_prompt function correctly formats
security analysis prompts for LLM consumption.
"""

import pytest
from prompt_builder import build_analysis_prompt


class TestBuildAnalysisPrompt:
    """Test suite for build_analysis_prompt function.

    The build_analysis_prompt function takes skill_content (str) and
    skill_filename (str) and returns a formatted prompt string for LLM
    security analysis.
    """

    # Positive Tests

    def test_build_prompt_with_simple_content(self):
        """Test: Build prompt with simple skill content.

        Verifies that the function correctly formats a basic skill file
        into a complete security analysis prompt with proper structure.
        """
        # Arrange
        skill_content = "# Test Skill\n\nThis is a simple test skill."
        skill_filename = "test_skill.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert isinstance(result, str)
        assert skill_filename in result
        assert skill_content in result
        assert "SECURITY CHECK CATEGORIES" in result
        assert "Analyze the skill file for the following 14 security categories" in result

    def test_build_prompt_with_complex_markdown(self):
        """Test: Build prompt with complex markdown content.

        Verifies that the function handles complex markdown including
        code blocks, headers, lists, and special characters correctly.
        """
        # Arrange
        skill_content = """# Complex Skill

## Description
This skill does something useful.

### Usage
```python
def example():
    return "Hello, World!"
```

## Links
- [Documentation](https://example.com)
- See also: `code snippet`

> Note: This is a blockquote with special chars: <>&"'
"""
        skill_filename = "complex_skill.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert isinstance(result, str)
        assert skill_filename in result
        assert skill_content in result
        assert "```markdown" in result
        assert "```python" in result  # Code blocks preserved
        assert "https://example.com" in result  # URLs preserved

    def test_build_prompt_contains_skill_content(self):
        """Test: Output prompt contains the original skill content.

        Verifies that the formatted prompt includes the raw skill content
        within markdown code blocks for LLM analysis.
        """
        # Arrange
        skill_content = "Custom skill content with special chars: $@!%"
        skill_filename = "custom.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert skill_content in result
        # Verify content is wrapped in markdown code block
        assert "```markdown" in result

    def test_build_prompt_returns_string_type(self):
        """Test: Function returns string type as specified in interface.

        Verifies that the return type matches the interface specification:
        Output: str (formatted prompt string for LLM)
        """
        # Arrange
        skill_content = "Test content"
        skill_filename = "test.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert type(result) is str

    # Negative/Edge Case Tests

    def test_build_prompt_with_empty_content(self):
        """Test: Build prompt with empty skill content.

        Verifies that the function handles empty content gracefully
        and still returns a valid prompt structure. This is a pure
        function with no error handling, so it should return output.
        """
        # Arrange
        skill_content = ""
        skill_filename = "empty_skill.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert isinstance(result, str)
        assert skill_filename in result
        # Empty content should still be wrapped in markdown block
        assert "```markdown" in result
        assert "```" in result

    def test_build_prompt_preserves_newlines_and_formatting(self):
        """Test: Preserves newlines and formatting in skill content.

        Verifies that multiline content with proper formatting is
        preserved exactly as input.
        """
        # Arrange
        skill_content = "Line 1\nLine 2\n\nLine 3 (after blank)"
        skill_filename = "multiline.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert skill_content in result
        assert "Line 1" in result
        assert "Line 2" in result
        assert "Line 3 (after blank)" in result

    def test_build_prompt_with_special_characters_in_filename(self):
        """Test: Handle special characters in filename.

        Verifies that filenames with spaces, dots, and special chars
        are handled correctly.
        """
        # Arrange
        skill_content = "Test content"
        skill_filename = "my skill file v1.2.3.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert skill_filename in result

    def test_build_prompt_includes_all_security_categories(self):
        """Test: Prompt includes all 13 security check categories.

        Verifies that the prompt structure includes all security categories
        as defined in the PRD specification.
        """
        # Arrange
        skill_content = "Test"
        skill_filename = "test.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        # Check for key security categories
        assert "HIDDEN_INSTRUCTIONS" in result
        assert "JAILBREAKING_ATTEMPTS" in result
        assert "CREDENTIAL_EXPOSURE" in result
        assert "PII_LEAKAGE" in result
        assert "TOKEN_EXFILTRATION" in result
        assert "EXTERNAL_DATA_FETCHING" in result
        assert "DATA_EXFILTRATION" in result
        assert "CODE_EXECUTION" in result
        assert "FILE_SYSTEM_ACCESS" in result
        assert "NETWORK_OPERATIONS" in result
        assert "SANDBOX_ESCAPE" in result
        assert "INDIRECT_PROMPT_INJECTION" in result
        assert "SOCIAL_ENGINEERING" in result

    def test_build_prompt_includes_json_output_format(self):
        """Test: Prompt includes JSON output format specification.

        Verifies that the prompt instructs the LLM to return JSON
        with the expected structure.
        """
        # Arrange
        skill_content = "Test"
        skill_filename = "test.md"

        # Act
        result = build_analysis_prompt(skill_content, skill_filename)

        # Assert
        assert "OUTPUT FORMAT" in result
        assert '"checks"' in result
        assert '"urls"' in result
        assert '"summary"' in result


class TestHelperFunctions:
    """Test suite for helper functions in prompt_builder module."""

    def test_get_categories_returns_list(self):
        """Test: get_categories returns list of strings."""
        from prompt_builder import get_categories

        categories = get_categories()

        assert isinstance(categories, list)
        assert len(categories) == 14
        assert all(isinstance(cat, str) for cat in categories)

    def test_get_severity_levels_returns_list(self):
        """Test: get_severity_levels returns list of strings."""
        from prompt_builder import get_severity_levels

        levels = get_severity_levels()

        assert isinstance(levels, list)
        assert len(levels) == 5
        assert all(isinstance(level, str) for level in levels)
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels
        assert "none" in levels


class TestValidateResponseStructure:
    """Test suite for validate_response_structure function."""

    def test_validate_response_with_valid_structure(self):
        """Test: Valid response structure passes validation.
        """
        from prompt_builder import validate_response_structure

        valid_response = {
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

        is_valid, error = validate_response_structure(valid_response)

        assert is_valid is True
        assert error == ""

    def test_validate_response_missing_required_key(self):
        """Test: Missing required key fails validation.
        """
        from prompt_builder import validate_response_structure

        invalid_response = {
            "checks": [],
            "urls": {}
            # Missing "summary"
        }

        is_valid, error = validate_response_structure(invalid_response)

        assert is_valid is False
        assert "Missing required key: summary" in error

    def test_validate_response_invalid_checks_type(self):
        """Test: Invalid checks type fails validation.
        """
        from prompt_builder import validate_response_structure

        invalid_response = {
            "checks": "not a list",
            "urls": {},
            "summary": {}
        }

        is_valid, error = validate_response_structure(invalid_response)

        assert is_valid is False
        assert "'checks' must be a list" in error
