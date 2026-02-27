"""Main CLI entry point for Skill Security Scanner with progress indicators.

Usage:
    python main.py <skill_file_path> [options]

Options:
    --format         Output format (console or json, default: console)
    --host           Ollama host URL (overrides env vars)
    --model          Model name (overrides env vars)
    --openai         Use OpenAI API instead of Ollama
    --threads        Number of parallel threads (default: 2)
    --no-translate   Skip translation of non-English content
    --verbose        Show detailed progress

Environment Variables:
    OLLAMA_API_BASE  Full URL for Ollama API (default: http://127.0.0.1:11434)
    OLLAMA_HOST      Hostname only (used if API_BASE not set)
    OLLAMA_MODEL     Model name (default: kimi-k2.5:cloud)
    OPENAI_API_KEY   OpenAI API key (required for --openai)
    OPENAI_MODEL     OpenAI model (default: gpt-4o-mini)
    OPENAI_BASE_URL  Custom OpenAI-compatible API base URL

Exit Codes:
    0    Success - no critical issues found
    1    Critical security issues detected
    2    File not found or read error
    3    Ollama connection failed
    4    Invalid arguments
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from analyzer import analyze_parallel
from formatter import calculate_exit_code, format_error, format_results
from language_detector import check_multilingual, translate_content
from prompt_builder import build_analysis_prompt
from result_parser import parse
from url_classifier import classify_urls


# Default configuration
DEFAULT_OLLAMA_MODEL = "kimi-k2.5:cloud"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"

# Progress indicator
VERBOSE = False


def log(message: str, important: bool = False) -> None:
    """Print progress message if verbose mode is enabled."""
    if VERBOSE or important:
        prefix = "🔹" if not important else "▶️"
        print(f"{prefix} {message}", file=sys.stderr)


def get_ollama_config(args: argparse.Namespace) -> tuple[str, str]:
    """Get Ollama host and model from environment or CLI arguments.

    Priority order:
    1. CLI arguments (--host, --model)
    2. OLLAMA_API_BASE env var
    3. OLLAMA_HOST env var
    4. OLLAMA_MODEL env var
    5. Defaults
    """
    # Get host
    host: str = DEFAULT_OLLAMA_HOST
    if args.host:
        host = args.host
    elif os.getenv("OLLAMA_API_BASE"):
        api_base = os.getenv("OLLAMA_API_BASE")
        if api_base:
            host = api_base
    elif os.getenv("OLLAMA_HOST"):
        ollama_host = os.getenv("OLLAMA_HOST")
        if ollama_host:
            host = f"http://{ollama_host}:11434"

    # Get model
    model: str = DEFAULT_OLLAMA_MODEL
    if args.model:
        model = args.model
    elif os.getenv("OLLAMA_MODEL"):
        ollama_model = os.getenv("OLLAMA_MODEL")
        if ollama_model:
            model = ollama_model

    return host, model


def get_openai_config(args: argparse.Namespace) -> tuple[str | None, str, str | None]:
    """Get OpenAI configuration from environment or CLI arguments.

    Returns:
        Tuple of (api_key, model, base_url)
    """
    api_key = os.getenv("OPENAI_API_KEY")

    # Get model
    model = os.getenv("OPENAI_MODEL") or DEFAULT_OPENAI_MODEL

    # Get custom base URL
    base_url = os.getenv("OPENAI_BASE_URL")

    return api_key, model, base_url


def read_skill_file(file_path: str) -> tuple[str | None, str | None]:
    """Read skill file content.

    Args:
        file_path: Path to skill file

    Returns:
        Tuple of (content, error_message)
    """
    try:
        path = Path(file_path)
        if not path.exists():
            return None, f"File not found: {file_path}"
        if not path.is_file():
            return None, f"Path is not a file: {file_path}"

        content = path.read_text(encoding="utf-8")
        return content, None
    except PermissionError:
        return None, f"Permission denied: {file_path}"
    except UnicodeDecodeError:
        return None, f"File encoding error: {file_path} is not valid UTF-8"
    except Exception as e:
        return None, f"Error reading file: {str(e)}"


def extract_and_output_translations(file_path: str, content: str, filename: str) -> int:
    """Extract non-English content and output as JSON with translations.
    
    Args:
        file_path: Path to the skill file
        content: File content
        filename: Name of the skill file
        
    Returns:
        Exit code (always 0 for successful extraction)
    """
    import re
    
    log("Extracting non-English content...")
    
    # Find all non-English text blocks (Cyrillic, CJK, Arabic, etc.)
    translations = []
    
    # Cyrillic text (Russian, etc.)
    cyrillic_pattern = re.compile(r'([\u0400-\u04ff\u0500-\u052f\u2de0-\u2dff\ua640-\ua69f]+)', re.UNICODE)
    for match in cyrillic_pattern.finditer(content):
        original = match.group(1)
        # Simple translation placeholder - in production this would use actual translation
        translations.append({
            "original": original,
            "translated": f"[TRANSLATED FROM RUSSIAN: {original}]",
            "language": "ru",
            "line": content[:match.start()].count('\n') + 1
        })
    
    # CJK text (Chinese, Japanese, Korean)
    cjk_pattern = re.compile(r'([\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]+)', re.UNICODE)
    for match in cjk_pattern.finditer(content):
        original = match.group(1)
        translations.append({
            "original": original,
            "translated": f"[TRANSLATED FROM CJK: {original}]",
            "language": "zh/jp/ko",
            "line": content[:match.start()].count('\n') + 1
        })
    
    # Arabic/Persian text
    arabic_pattern = re.compile(r'([\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff]+)', re.UNICODE)
    for match in arabic_pattern.finditer(content):
        original = match.group(1)
        translations.append({
            "original": original,
            "translated": f"[TRANSLATED FROM ARABIC/PERSIAN: {original}]",
            "language": "ar/fa",
            "line": content[:match.start()].count('\n') + 1
        })
    
    output = {
        "file": filename,
        "file_path": file_path,
        "total_non_english_segments": len(translations),
        "translations": translations
    }
    
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="skillcheck",
        description="Security scanner for AI skill files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py tests/unsafe_skill.md
  python main.py tests/safe_skill.md --format=json
  python main.py skill.md --host http://192.168.1.100:11434
  python main.py skill.md --model llama3.2
  export OPENAI_API_KEY=sk-xxx
  python main.py skill.md --openai
  python main.py skill.md --threads=4
  python main.py skill.md --no-translate
  python main.py skill.md --verbose
        """,
    )

    parser.add_argument(
        "skill_file",
        help="Path to skill.md file to analyze",
    )

    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console)",
    )

    parser.add_argument(
        "--host",
        help="Ollama host URL (overrides OLLAMA_API_BASE env var)",
    )

    parser.add_argument(
        "--model",
        help="Model name (overrides OLLAMA_MODEL env var)",
    )

    parser.add_argument(
        "--openai",
        action="store_true",
        help="Use OpenAI API instead of Ollama (requires OPENAI_API_KEY env var)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=3,
        help="Number of parallel threads for analysis (default: 3)",
    )

    parser.add_argument(
        "--no-translate",
        action="store_true",
        help="Skip translation of non-English content",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed progress indicators",
    )

    parser.add_argument(
        "--force-pass",
        action="store_true",
        help="Always exit with code 0, even if issues are found (alerts user to run manually if needed)",
    )

    parser.add_argument(
        "--translate",
        action="store_true",
        help="Extract non-English content and output as JSON with original/translated text (does not run security analysis)",
    )

    return parser.parse_args()


def aggregate_batch_results(responses: list[str], skill_filename: str, multilingual_check: dict[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate results from multiple batch responses.

    Args:
        responses: List of JSON response strings from LLM
        skill_filename: Name of the skill file
        multilingual_check: Optional multilingual check result to include first

    Returns:
        Aggregated result dictionary
    """
    all_checks = []

    # Add multilingual check result first if provided
    if multilingual_check:
        all_checks.append(multilingual_check)
        log("Added multilingual detection check to results")

    all_urls = {
        "all": [],
        "trusted": [],
        "medium": [],
        "suspicious": [],
        "malicious": [],
        "unknown": [],
    }

    # Parse each response
    log(f"Aggregating {len(responses)} batch responses...")
    for i, response in enumerate(responses):
        log(f"Processing batch {i+1}/{len(responses)}...")
        parse_result = parse(response, skill_filename)
        if parse_result["success"]:
            data = parse_result["data"]
            all_checks.extend(data.get("checks", []))

            # Merge URLs
            urls = data.get("urls", {})
            for key in ["all", "trusted", "medium", "suspicious", "malicious", "unknown"]:
                if key in urls and isinstance(urls[key], list):
                    all_urls[key].extend(urls[key])
        else:
            log(f"Warning: Failed to parse batch {i+1}: {parse_result['error']}")

    # Calculate summary
    total_checks = len(all_checks)
    passed = sum(1 for c in all_checks if c.get("passed", False))
    failed = total_checks - passed
    critical = sum(1 for c in all_checks if c.get("severity") == "critical")
    high = sum(1 for c in all_checks if c.get("severity") == "high")
    medium = sum(1 for c in all_checks if c.get("severity") == "medium")
    low = sum(1 for c in all_checks if c.get("severity") == "low")

    log(f"Aggregated {total_checks} checks: {passed} passed, {failed} failed")

    return {
        "checks": all_checks,
        "urls": all_urls,
        "summary": {
            "total_checks": total_checks,
            "passed": passed,
            "failed": failed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
    }


def main() -> int:
    """Main entry point.

    Returns:
        Exit code (0-4)
    """
    global VERBOSE

    # Parse CLI arguments
    try:
        args = parse_arguments()
        VERBOSE = args.verbose
    except SystemExit as e:
        # argparse exits with code 2 for invalid arguments
        return 4

    log("Starting Skill Security Scanner...", important=True)

    # Read skill file
    log(f"Reading skill file: {args.skill_file}")
    skill_content, error = read_skill_file(args.skill_file)
    if error:
        print(format_error(error, 2), file=sys.stderr)
        return 2

    # Ensure skill_content is not None before proceeding
    if skill_content is None:
        print(format_error("Failed to read skill file content", 2), file=sys.stderr)
        return 2

    skill_filename = Path(args.skill_file).name

    log(f"Loaded {len(skill_content)} characters from {skill_filename}")

    # Handle --translate mode: extract and output non-English content only
    if args.translate:
        log("Running in translation extraction mode...", important=True)
        return extract_and_output_translations(args.skill_file, skill_content, skill_filename)

    # Configure provider before translation check
    if args.openai:
        provider = "openai"
        api_key, model, base_url = get_openai_config(args)
        host = None
        log(f"Using OpenAI provider with model: {model}", important=True)

        if not api_key:
            print(
                format_error(
                    "OPENAI_API_KEY environment variable not set. Required for --openai flag.",
                    4,
                ),
                file=sys.stderr,
            )
            return 4
    else:
        provider = "ollama"
        host, model = get_ollama_config(args)
        api_key = None
        base_url = None
        log(f"Using Ollama provider at {host} with model: {model}", important=True)

    # Language detection and translation
    language_info = None
    is_translation = False
    multilingual_check_result = None

    if not args.no_translate:
        log("Checking for multilingual content...")
        # Check if content is multilingual
        multilingual_check_result = check_multilingual(skill_content)

        if multilingual_check_result and not multilingual_check_result.get("passed", True):
            language_info = {
                "detected": multilingual_check_result.get("original_language"),
                "language_name": multilingual_check_result.get("language_name"),
                "is_high_risk": multilingual_check_result.get("is_high_risk_language", False),
            }

            log(f"Detected language: {language_info['language_name']} ({language_info['detected']})", important=True)
            if language_info["is_high_risk"]:
                log("⚠️  WARNING: High-risk language detected!")

            # Translate content if needed
            if multilingual_check_result.get("translated_content"):
                log("Translating content to English...")
                translation = translate_content(skill_content)
                if translation["success"]:
                    skill_content = translation["translated_content"]
                    is_translation = True
                    language_info["translated"] = True
                    log("Translation complete. Analyzing translated content...")
                else:
                    log(f"Translation failed: {translation.get('error', 'Unknown error')}")
                    log("Proceeding with original content...")
        else:
            log("Content is in English - no translation needed")
            # Still include the passed check in results
            multilingual_check_result = check_multilingual(skill_content)
    else:
        log("Skipping translation (--no-translate flag set)")

    # Run parallel analysis
    log(f"Starting parallel analysis with {args.threads} threads...", important=True)
    log(f"Processing 7 batches of security checks...")

    start_time = time.time()

    analysis_result = analyze_parallel(
        skill_content=skill_content,
        skill_filename=skill_filename,
        provider=provider,
        model=model,
        host=host,
        api_key=api_key,
        base_url=base_url,
        max_workers=args.threads,
        is_translation=is_translation,
    )

    elapsed_time = time.time() - start_time
    log(f"Analysis completed in {elapsed_time:.2f} seconds")

    if not analysis_result["success"]:
        error_msg = analysis_result["error"]
        # Check if it's a connection error
        if "connection" in error_msg.lower() or "connect" in error_msg.lower():
            print(format_error(error_msg, 3), file=sys.stderr)
            return 3
        print(format_error(error_msg, 1), file=sys.stderr)
        return 1

    log(f"Successfully completed {analysis_result.get('batches_completed', 0)} batches")

    # Aggregate results from all batches
    responses = analysis_result.get("responses", [])
    if not responses:
        print(format_error("No analysis results received", 1), file=sys.stderr)
        return 1

    log("Aggregating results from all batches...")
    parsed_data = aggregate_batch_results(responses, skill_filename, multilingual_check_result)

    # Classify URLs if present
    urls = parsed_data.get("urls", {}).get("all", [])
    if urls:
        log(f"Classifying {len(urls)} URLs...")
        classification_result = classify_urls(urls, check_geolocation=True)
        # Update parsed data with classified URLs
        parsed_data["urls"] = classification_result["classified_urls"]
        # Add geolocation summary
        if classification_result.get("geolocation_summary", {}).get("high_risk_count", 0) > 0:
            parsed_data["geolocation_summary"] = classification_result["geolocation_summary"]
            log(f"⚠️  Found {classification_result['geolocation_summary']['high_risk_count']} high-risk IPs from: {', '.join(classification_result['geolocation_summary']['high_risk_countries'])}")

    # Format output
    log("Formatting results...")
    output = format_results(parsed_data, skill_filename, args.format, language_info)

    # Print results
    if args.format == "json":
        print(json.dumps(output, indent=2))
    else:
        print(output)

    # Return appropriate exit code
    exit_code = calculate_exit_code(parsed_data)
    
    # Handle --force-pass flag
    if exit_code != 0 and args.force_pass:
        log("⚠️  Issues detected, but --force-pass flag is set. Forcing exit code 0.", important=True)
        log("⚠️  Alert: This skill file has the following issues that require manual review:", important=True)
        
        # List the specific reasons for failure
        critical_checks = [c for c in parsed_data.get("checks", []) if c.get("severity") == "critical" and not c.get("passed", False)]
        high_checks = [c for c in parsed_data.get("checks", []) if c.get("severity") == "high" and not c.get("passed", False)]
        
        if critical_checks:
            log(f"   ❌ {len(critical_checks)} CRITICAL issue(s) detected:", important=True)
            for check in critical_checks:
                log(f"      - {check.get('category', 'Unknown')}: {check.get('description', 'No description')}", important=True)
        
        if high_checks:
            log(f"   ⚠️  {len(high_checks)} HIGH severity issue(s) detected:", important=True)
            for check in high_checks:
                log(f"      - {check.get('category', 'Unknown')}: {check.get('description', 'No description')}", important=True)
        
        log("⚠️  To see full details, run without --force-pass flag.", important=True)
        exit_code = 0
    
    log(f"Exit code: {exit_code}", important=True)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
