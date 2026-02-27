"""Formatter Module

Formats security analysis results for console or JSON output.

Interface:
- Input: {parsed_result: dict, skill_filename: str, format: str}
- Output: str (console) or dict (json)
"""

import json
from datetime import datetime, timezone
from typing import Any


# Category display names
CATEGORY_DISPLAY_NAMES = {
    "multilingual_detection": "Language Detection",
    "hidden_instructions": "Hidden Instructions",
    "jailbreaking_attempts": "Jailbreaking",
    "credential_exposure": "Credential Exposure",
    "pii_leakage": "PII Leakage",
    "token_exfiltration": "Token Exfiltration",
    "external_data_fetching": "External Data Fetch",
    "data_exfiltration": "Data Exfiltration",
    "code_execution": "Code Execution",
    "file_system_access": "File System Access",
    "network_operations": "Network Operations",
    "sandbox_escape": "Sandbox Escape",
    "indirect_prompt_injection": "Indirect Injection",
    "social_engineering": "Social Engineering",
}


def format_results(parsed_result: dict | None, skill_filename: str, output_format: str, language_info: dict | None = None) -> str | dict:
    """Format security analysis results.

    Args:
        parsed_result: Parsed analysis result from result_parser
        skill_filename: Name of the skill file
        output_format: "console" or "json"
        language_info: Optional language detection results

    Returns:
        Formatted string for console or dictionary for JSON

    Raises:
        ValueError: If output_format is not "console" or "json"
    """
    if parsed_result is None:
        raise ValueError("parsed_result cannot be None")

    if output_format not in ("console", "json"):
        raise ValueError(f"Invalid output format: {output_format}. Must be 'console' or 'json'")

    if output_format == "json":
        return _format_json(parsed_result, skill_filename, language_info)
    else:
        return _format_console(parsed_result, skill_filename, language_info)


def _format_console(parsed_result: dict, skill_filename: str, language_info: dict | None = None) -> str:
    """Format results for console output with colors and emojis."""
    lines = []

    # Header
    lines.append(f"🔍 Security Analysis: {skill_filename}")
    lines.append("═" * 60)
    lines.append("")

    # Language detection section
    if language_info:
        lines.append("🌍 Language Detection:")
        detected = language_info.get("detected", "unknown")
        language_name = language_info.get("language_name", "Unknown")
        is_high_risk = language_info.get("is_high_risk", False)
        was_translated = language_info.get("translated", False)

        if detected == "en":
            lines.append(f"   ✅ Content is in English")
        else:
            if is_high_risk:
                lines.append(f"   ❌ Original language: {language_name} ({detected}) - HIGH RISK")
            else:
                lines.append(f"   ⚠️  Original language: {language_name} ({detected})")
            if was_translated:
                lines.append(f"   ✅ Translated to English for analysis")
        lines.append("")

    # Security checks
    checks = parsed_result.get("checks", [])
    for check in checks:
        category = check.get("category", "unknown")
        passed = check.get("passed", False)
        severity = check.get("severity", "none")
        description = check.get("description", "")

        display_name = CATEGORY_DISPLAY_NAMES.get(category, category.replace("_", " ").title())

        if passed:
            lines.append(f"✅ {display_name:22} [PASS]")
        else:
            if severity == "critical":
                lines.append(f"❌ {display_name:22} [CRITICAL] {description}")
            elif severity == "high":
                lines.append(f"❌ {display_name:22} [HIGH] {description}")
            elif severity == "medium":
                lines.append(f"⚠️  {display_name:22} [MEDIUM] {description}")
            elif severity == "low":
                lines.append(f"⚠️  {display_name:22} [LOW] {description}")
            else:
                lines.append(f"⚠️  {display_name:22} [WARNING] {description}")

    lines.append("")

    # URLs section
    urls = parsed_result.get("urls", {})
    all_urls = urls.get("all", [])
    if all_urls:
        lines.append("🌐 External URLs:")

        for url in all_urls:
            category = _get_url_category(url, urls)
            if category == "malicious":
                lines.append(f"   ❌ {url}")
            elif category == "suspicious":
                lines.append(f"   ⚠️  {url}")
            elif category == "unknown":
                lines.append(f"   ⚠️  {url} (Unknown - review recommended)")
            elif category == "medium":
                lines.append(f"   ⚠️  {url} (Established company - review)")
            else:
                lines.append(f"   ✅ {url}")

        lines.append("")

    # Summary
    summary = parsed_result.get("summary", {})
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    low = summary.get("low", 0)
    passed = summary.get("passed", 0)

    lines.append(f"📊 Summary: {critical} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW, {passed} PASSED")

    return "\n".join(lines)


def _get_url_category(url: str, urls: dict) -> str:
    """Get the category for a URL from the URLs dict."""
    if url in urls.get("malicious", []):
        return "malicious"
    elif url in urls.get("suspicious", []):
        return "suspicious"
    elif url in urls.get("unknown", []):
        return "unknown"
    elif url in urls.get("medium", []):
        return "medium"
    elif url in urls.get("trusted", []):
        return "trusted"
    return "unknown"


def _format_json(parsed_result: dict, skill_filename: str, language_info: dict | None = None) -> dict:
    """Format results as JSON structure."""
    timestamp = generate_timestamp()
    exit_code = calculate_exit_code(parsed_result)

    result = {
        "file": skill_filename,
        "timestamp": timestamp,
        "checks": parsed_result.get("checks", []),
        "urls": parsed_result.get("urls", {}),
        "summary": parsed_result.get("summary", {}),
        "exit_code": exit_code,
    }

    # Add language info if present
    if language_info:
        result["language"] = language_info

    # Add geolocation summary if present
    if "geolocation_summary" in parsed_result:
        result["geolocation_summary"] = parsed_result["geolocation_summary"]

    return result


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def calculate_exit_code(parsed_result: dict | None) -> int:
    """Calculate exit code based on results.

    Returns:
        0 if no critical issues, 1 if critical issues found
    """
    if parsed_result is None:
        return 1
    summary = parsed_result.get("summary", {})
    critical = summary.get("critical", 0)
    return 1 if critical > 0 else 0


def format_error(error_message: str, exit_code: int) -> str:
    """Format an error message for console output."""
    return f"❌ Error: {error_message}\nExit code: {exit_code}"
