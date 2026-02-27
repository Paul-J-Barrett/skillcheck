"""Analyzer module for interfacing with LLM providers (Ollama and OpenAI).

This module provides a unified interface for sending analysis prompts to
LLM providers and handling their responses.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

from prompt_builder import build_batch_prompt, ANALYSIS_BATCHES


# Constants
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
OLLAMA_API_PATH = "/api/chat"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds


def _extract_json_from_markdown(content: str) -> str | None:
    """Extract JSON from markdown code blocks if present.

    Args:
        content: Raw response content that may contain markdown code blocks

    Returns:
        Extracted JSON string or None if no markdown blocks found
    """
    import re

    # Look for JSON code blocks
    json_pattern = r'```(?:json)?\s*\n?(.*?)\n?```'
    matches = re.findall(json_pattern, content, re.DOTALL)

    if matches:
        # Return the first match (should be the JSON content)
        return matches[0].strip()

    return None


def analyze(
    prompt: str,
    provider: str,
    model: str,
    host: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Analyze skill content using LLM provider.

    Args:
        prompt: Analysis prompt from prompt_builder
        provider: "ollama" or "openai"
        model: Model name (e.g., "kimi-k2.5:cloud", "gpt-4o-mini")
        host: Ollama host URL (for Ollama provider)
        api_key: OpenAI API key (for OpenAI provider)
        base_url: Optional custom base URL

    Returns:
        Dictionary with success, response, and error fields
    """
    # Validate required parameters
    if not prompt:
        return {
            "success": True,
            "response": '{"checks": [], "urls": {}, "summary": {}}',
            "error": None,
        }

    # Validate provider
    if provider not in ("ollama", "openai"):
        return {
            "success": False,
            "response": None,
            "error": f"Invalid provider '{provider}'. Supported providers: 'ollama', 'openai'",
        }

    # Provider-specific validation and setup
    if provider == "openai":
        if not api_key:
            return {
                "success": False,
                "response": None,
                "error": "Missing required parameter: api_key is required for OpenAI provider",
            }
        return _analyze_openai(prompt, model, api_key, base_url)
    else:  # provider == "ollama"
        return _analyze_ollama(prompt, model, host)


def _analyze_ollama(
    prompt: str,
    model: str,
    host: str | None = None,
) -> dict[str, Any]:
    """Send analysis request to Ollama API with retry logic.

    Args:
        prompt: Analysis prompt
        model: Ollama model name
        host: Ollama host URL (defaults to localhost)

    Returns:
        Response dictionary with success, response, error fields
    """
    ollama_host = host or DEFAULT_OLLAMA_HOST
    api_url = f"{ollama_host}{OLLAMA_API_PATH}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }

    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                api_url,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()
            content = data.get("message", {}).get("content", "")

            # Extract JSON from markdown code blocks if present
            # The LLM might wrap JSON in ```json ... ``` blocks
            extracted_content = _extract_json_from_markdown(content)
            
            if extracted_content:
                content = extracted_content

            # Validate response is valid JSON
            try:
                json.loads(content)
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "response": None,
                    "error": f"Invalid response: LLM returned malformed JSON that could not be parsed. Error: {str(e)[:100]}",
                }

            return {
                "success": True,
                "response": content,
                "error": None,
            }

        except requests.exceptions.ConnectionError as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": f"Connection failed: Unable to connect to Ollama at {ollama_host}. Please check if Ollama is running.",
            }

        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": "Request timed out: The LLM request exceeded the timeout limit. Consider using a smaller model or reducing prompt size.",
            }

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, "response") and e.response else 0

            if status_code == 404:
                return {
                    "success": False,
                    "response": None,
                    "error": "API endpoint not found (404): The LLM endpoint is unavailable. Please check the host URL.",
                }
            elif status_code == 500:
                return {
                    "success": False,
                    "response": None,
                    "error": "Server error (500): The LLM provider encountered an internal error. Please try again later.",
                }
            else:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                return {
                    "success": False,
                    "response": None,
                    "error": f"HTTP error ({status_code}): Request failed.",
                }

        except requests.exceptions.RequestException as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": f"Request failed: {str(e)}",
            }

    # Should not reach here, but handle just in case
    return {
        "success": False,
        "response": None,
        "error": f"Connection failed after {MAX_RETRIES} retries",
    }


def _analyze_openai(
    prompt: str,
    model: str,
    api_key: str,
    base_url: str | None = None,
) -> dict[str, Any]:
    """Send analysis request to OpenAI API.

    Args:
        prompt: Analysis prompt
        model: OpenAI model name
        api_key: OpenAI API key
        base_url: Optional custom base URL

    Returns:
        Response dictionary with success, response, error fields
    """
    api_url = base_url or OPENAI_API_URL

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }

    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                api_url,
                headers=headers,
                json=payload,
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

            # Validate response is valid JSON
            try:
                json.loads(content)
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "response": None,
                    "error": "Invalid response: LLM returned malformed JSON that could not be parsed.",
                }

            return {
                "success": True,
                "response": content,
                "error": None,
            }

        except requests.exceptions.ConnectionError as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": f"Connection failed: Unable to connect to OpenAI API at {api_url}. Please check your network connection.",
            }

        except requests.exceptions.Timeout as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": "Request timed out: The LLM request exceeded the timeout limit. Consider using a smaller model or reducing prompt size.",
            }

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if hasattr(e, "response") and e.response else 0

            if status_code == 401:
                return {
                    "success": False,
                    "response": None,
                    "error": "Authentication failed: Invalid OpenAI API key. Please check your OPENAI_API_KEY environment variable.",
                }
            elif status_code == 404:
                return {
                    "success": False,
                    "response": None,
                    "error": "API endpoint not found (404): The OpenAI endpoint is unavailable. Please check the base URL.",
                }
            elif status_code == 500:
                return {
                    "success": False,
                    "response": None,
                    "error": "Server error (500): The LLM provider encountered an internal error. Please try again later.",
                }
            else:
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                return {
                    "success": False,
                    "response": None,
                    "error": f"HTTP error ({status_code}): Request failed.",
                }

        except requests.exceptions.RequestException as e:
            last_error = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
                continue
            return {
                "success": False,
                "response": None,
                "error": f"Request failed: {str(e)}",
            }

    # Should not reach here, but handle just in case
    return {
        "success": False,
        "response": None,
        "error": f"Connection failed after {MAX_RETRIES} retries",
    }


def analyze_batch(
    skill_content: str,
    skill_filename: str,
    categories: list[str],
    provider: str,
    model: str,
    host: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    is_translation: bool = False,
) -> dict[str, Any]:
    """Analyze a single batch of categories.

    Args:
        skill_content: The skill file content
        skill_filename: Name of the skill file
        categories: List of categories to check
        provider: "ollama" or "openai"
        model: Model name
        host: Ollama host URL
        api_key: OpenAI API key
        base_url: Custom base URL
        is_translation: Whether this is analyzing translated content

    Returns:
        Dictionary with success, response, error, and categories fields
    """
    # Build batch-specific prompt
    prompt = build_batch_prompt(skill_content, skill_filename, categories, is_translation)

    # Analyze
    result = analyze(
        prompt=prompt,
        provider=provider,
        model=model,
        host=host,
        api_key=api_key,
        base_url=base_url,
    )

    result["categories"] = categories
    return result


def analyze_parallel(
    skill_content: str,
    skill_filename: str,
    provider: str,
    model: str,
    host: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    max_workers: int = 2,
    is_translation: bool = False,
) -> dict[str, Any]:
    """Analyze skill content using parallel batch processing.

    Args:
        skill_content: The skill file content
        skill_filename: Name of the skill file
        provider: "ollama" or "openai"
        model: Model name
        host: Ollama host URL
        api_key: OpenAI API key
        base_url: Custom base URL
        max_workers: Number of parallel threads
        is_translation: Whether this is analyzing translated content

    Returns:
        Dictionary with success, responses, errors, and aggregated results
    """
    results = []
    errors = []
    successful_responses = []

    # Use ThreadPoolExecutor for parallel processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all batches
        future_to_batch = {}
        for batch in ANALYSIS_BATCHES:
            future = executor.submit(
                analyze_batch,
                skill_content,
                skill_filename,
                batch,
                provider,
                model,
                host,
                api_key,
                base_url,
                is_translation,
            )
            future_to_batch[future] = batch

        # Collect results as they complete
        for future in as_completed(future_to_batch):
            batch = future_to_batch[future]
            try:
                result = future.result()
                results.append(result)

                if result["success"]:
                    successful_responses.append(result["response"])
                else:
                    errors.append(f"Batch {batch}: {result['error']}")
            except Exception as e:
                errors.append(f"Batch {batch}: {str(e)}")

    # Aggregate results
    if not successful_responses:
        return {
            "success": False,
            "responses": [],
            "error": "; ".join(errors) if errors else "All batches failed",
            "batches_completed": 0,
        }

    return {
        "success": True,
        "responses": successful_responses,
        "error": "; ".join(errors) if errors else None,
        "batches_completed": len(successful_responses),
    }
