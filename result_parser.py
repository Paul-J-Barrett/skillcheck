"""Result Parser Module

Parses and validates LLM JSON responses for security analysis.

Interface:
- Input: {raw_response: str, skill_filename: str}
- Output: {success: bool, data: {...}|None, error: str|None}
"""

import json
from typing import Any


VALID_CATEGORIES = {
    # Full names
    "multilingual_detection",
    "hidden_instructions",
    "jailbreaking_attempts",
    "credential_exposure",
    "pii_leakage",
    "token_exfiltration",
    "external_data_fetching",
    "data_exfiltration",
    "code_execution",
    "file_system_access",
    "network_operations",
    "sandbox_escape",
    "indirect_prompt_injection",
    "social_engineering",
    # Short names (for compatibility with tests)
    "jailbreaking",
    "indirect_injection",
}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "none"}

REQUIRED_CHECK_KEYS = {"category", "passed", "severity", "description", "evidence"}

REQUIRED_URL_KEYS = {"all", "trusted", "medium", "suspicious", "malicious", "unknown"}

REQUIRED_SUMMARY_KEYS = {"total_checks", "passed", "failed", "critical", "high", "medium", "low"}


def parse(raw_response: str, skill_filename: str) -> dict[str, Any]:
    """Parse and validate LLM JSON response.

    Args:
        raw_response: Raw JSON string from LLM
        skill_filename: Name of skill file for error context

    Returns:
        Dictionary with success, data, and error fields
    """
    # Handle empty or whitespace-only response
    if not raw_response or not raw_response.strip():
        return {
            "success": False,
            "data": None,
            "error": f"Empty response from LLM for {skill_filename}",
        }

    # Parse JSON
    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "data": None,
            "error": f"Invalid JSON in LLM response for {skill_filename}: {str(e)}",
        }

    # Validate structure
    validation_result = _validate_structure(data)
    if not validation_result["valid"]:
        return {
            "success": False,
            "data": None,
            "error": f"Validation error for {skill_filename}: {validation_result['error']}",
        }

    return {
        "success": True,
        "data": data,
        "error": None,
    }


def _validate_structure(data: dict) -> dict[str, Any]:
    """Validate the structure of parsed data.

    Args:
        data: Parsed JSON data

    Returns:
        Dictionary with valid flag and error message
    """
    # Check required top-level keys
    required_keys = {"checks", "urls", "summary"}
    for key in required_keys:
        if key not in data:
            return {"valid": False, "error": f"Missing required key: {key}"}

    # Validate checks
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        return {"valid": False, "error": "'checks' must be a list"}

    # Must have at least 1 check (batch processing can return 2 per batch)
    if len(checks) < 1:
        return {"valid": False, "error": f"Invalid check count: expected at least 1 check, found {len(checks)}"}

    # Validate each check
    for i, check in enumerate(checks):
        if not isinstance(check, dict):
            return {"valid": False, "error": f"Check at index {i} must be a dictionary"}

        # Check required keys
        for key in REQUIRED_CHECK_KEYS:
            if key not in check:
                return {"valid": False, "error": f"Check at index {i} missing required key: {key}"}

        # Validate category
        if check["category"] not in VALID_CATEGORIES:
            return {
                "valid": False,
                "error": f"Invalid category '{check['category']}' at check index {i}",
            }

        # Validate severity
        if check["severity"] not in VALID_SEVERITIES:
            return {
                "valid": False,
                "error": f"Invalid severity '{check['severity']}' at check index {i}",
            }

        # Validate evidence is a list
        if not isinstance(check.get("evidence", []), list):
            return {"valid": False, "error": f"Evidence must be a list at check index {i}"}

    # Validate urls structure
    urls = data.get("urls", {})
    if not isinstance(urls, dict):
        return {"valid": False, "error": "'urls' must be a dictionary"}

    for key in REQUIRED_URL_KEYS:
        if key not in urls:
            return {"valid": False, "error": f"URLs missing required key: {key}"}
        if not isinstance(urls[key], list):
            return {"valid": False, "error": f"URLs.{key} must be a list"}

    # Validate summary structure
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        return {"valid": False, "error": "'summary' must be a dictionary"}

    for key in REQUIRED_SUMMARY_KEYS:
        if key not in summary:
            return {"valid": False, "error": f"Summary missing required key: {key}"}

    # Validate summary counts match actual results
    total_checks = len(checks)
    passed = sum(1 for c in checks if c.get("passed", False))
    failed = total_checks - passed
    critical = sum(1 for c in checks if c.get("severity") == "critical")
    high = sum(1 for c in checks if c.get("severity") == "high")
    medium = sum(1 for c in checks if c.get("severity") == "medium")
    low = sum(1 for c in checks if c.get("severity") == "low")

    if summary.get("total_checks") != total_checks:
        return {
            "valid": False,
            "error": f"Summary total_checks ({summary.get('total_checks')}) doesn't match actual count ({total_checks})",
        }

    if summary.get("passed") != passed:
        return {
            "valid": False,
            "error": f"Summary passed count ({summary.get('passed')}) doesn't match actual count ({passed})",
        }

    if summary.get("failed") != failed:
        return {
            "valid": False,
            "error": f"Summary failed count ({summary.get('failed')}) doesn't match actual count ({failed})",
        }

    if summary.get("critical") != critical:
        return {
            "valid": False,
            "error": f"Summary critical count ({summary.get('critical')}) doesn't match actual count ({critical})",
        }

    if summary.get("high") != high:
        return {
            "valid": False,
            "error": f"Summary high count ({summary.get('high')}) doesn't match actual count ({high})",
        }

    if summary.get("medium") != medium:
        return {
            "valid": False,
            "error": f"Summary medium count ({summary.get('medium')}) doesn't match actual count ({medium})",
        }

    if summary.get("low") != low:
        return {
            "valid": False,
            "error": f"Summary low count ({summary.get('low')}) doesn't match actual count ({low})",
        }

    return {"valid": True, "error": ""}
