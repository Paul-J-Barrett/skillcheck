"""Comprehensive unit tests for the analyzer module.

These tests verify the analyze function correctly interfaces with LLM providers
(Ollama and OpenAI) and handles various error scenarios using mocked HTTP requests.

Test Coverage:
- Positive Tests: Successful Ollama/OpenAI calls, custom configurations, retry success
- Negative Tests: Connection errors, timeouts, invalid responses, auth errors, input validation
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import analyze


class TestAnalyzeOllamaSuccess(unittest.TestCase):
    """Test suite for successful Ollama provider interactions.

    These tests verify that the analyze function correctly calls the Ollama API
    and returns successful responses with proper structure.
    """

    def test_successful_ollama_analysis(self):
        """Test: Successfully analyze with Ollama provider.

        Verifies that the analyze function correctly calls the Ollama API
        with proper parameters and returns a successful response containing
        valid JSON that can be parsed.

        Relates to: Successful Ollama API call with mocked response (Objective #1)
        """
        # Arrange
        expected_response = json.dumps({
            "checks": [
                {
                    "category": "hidden_instructions",
                    "passed": True,
                    "severity": "none",
                    "description": "No hidden instructions detected",
                    "evidence": [],
                    "line_numbers": [],
                    "recommendation": ""
                }
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 1, "passed": 1, "failed": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        })

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "message": {"content": expected_response}
        }
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze this skill file for security issues",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["response"])
        self.assertIsNone(result["error"])

        # Verify response can be parsed as JSON
        parsed = json.loads(result["response"])
        self.assertIn("checks", parsed)
        self.assertIn("urls", parsed)
        self.assertIn("summary", parsed)

        # Verify the API was called with correct URL
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("http://127.0.0.1:11434/api/chat", call_args[0])

    def test_ollama_with_custom_host(self):
        """Test: Ollama analysis with custom host URL.

        Verifies that the analyze function correctly uses a custom host
        URL when provided instead of the default localhost.

        Relates to: Ollama configuration with custom host
        """
        # Arrange
        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": expected_response}}
        mock_response.raise_for_status.return_value = None

        custom_host = "http://192.168.1.100:11434"

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host=custom_host,
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])
        self.assertEqual(result["response"], expected_response)
        self.assertIsNone(result["error"])

        # Verify the custom host was used
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("192.168.1.100:11434", call_args[0][0])

    def test_ollama_with_different_model(self):
        """Test: Ollama analysis with different model name.

        Verifies that the analyze function correctly uses the specified
        model name in the request payload.

        Relates to: Model parameter handling
        """
        # Arrange
        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": expected_response}}
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="llama3.2",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])

        # Verify the model was included in the request
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs["json"]["model"], "llama3.2")


class TestAnalyzeOpenAISuccess(unittest.TestCase):
    """Test suite for successful OpenAI provider interactions.

    These tests verify that the analyze function correctly calls the OpenAI API
    with proper authentication and returns successful responses.
    """

    def test_successful_openai_analysis(self):
        """Test: Successfully analyze with OpenAI provider.

        Verifies that the analyze function correctly calls the OpenAI API
        with proper authentication (API key in headers) and parameters,
        returning a successful response that can be parsed as JSON.

        Relates to: Successful OpenAI API call with mocked response (Objective #2)
        """
        # Arrange
        expected_response = json.dumps({
            "checks": [
                {
                    "category": "credential_exposure",
                    "passed": False,
                    "severity": "critical",
                    "description": "API key found in file",
                    "evidence": ["Line 5: sk-abc123"],
                    "line_numbers": [5],
                    "recommendation": "Remove hardcoded credentials"
                }
            ],
            "urls": {"all": [], "trusted": [], "medium": [], "suspicious": [], "malicious": [], "unknown": []},
            "summary": {"total_checks": 1, "passed": 0, "failed": 1, "critical": 1, "high": 0, "medium": 0, "low": 0}
        })

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": expected_response}}]
        }
        mock_response.raise_for_status.return_value = None

        api_key = "sk-test123"

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze this skill file for security issues",
                provider="openai",
                model="gpt-4o-mini",
                host=None,
                api_key=api_key,
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["response"])
        self.assertIsNone(result["error"])

        # Verify response structure
        parsed = json.loads(result["response"])
        self.assertIn("checks", parsed)
        self.assertIn("urls", parsed)
        self.assertIn("summary", parsed)

        # Verify Authorization header was set correctly
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertIn("Authorization", call_kwargs["headers"])
        self.assertIn("Bearer sk-test123", call_kwargs["headers"]["Authorization"])

    def test_openai_with_custom_base_url(self):
        """Test: OpenAI analysis with custom base URL.

        Verifies that the analyze function correctly uses a custom base URL
        for OpenAI-compatible APIs (e.g., Azure, local LLM servers).

        Relates to: Custom base URL for OpenAI (Objective #9)
        """
        # Arrange
        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": expected_response}}]
        }
        mock_response.raise_for_status.return_value = None

        custom_base_url = "https://custom.openai.api.com/v1/chat/completions"
        api_key = "sk-test456"

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze security",
                provider="openai",
                model="gpt-4",
                host=None,
                api_key=api_key,
                base_url=custom_base_url
            )

        # Assert
        self.assertTrue(result["success"])
        self.assertEqual(result["response"], expected_response)

        # Verify custom base URL was used
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("custom.openai.api.com", call_args[0][0])

    def test_openai_with_different_model(self):
        """Test: OpenAI analysis with different model.

        Verifies that the analyze function correctly uses the specified
        OpenAI model in the request payload.

        Relates to: OpenAI model parameter handling
        """
        # Arrange
        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": expected_response}}]
        }
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze security",
                provider="openai",
                model="gpt-4",
                host=None,
                api_key="sk-test789",
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])

        # Verify the model was included in the request
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs["json"]["model"], "gpt-4")


class TestAnalyzeErrorHandling(unittest.TestCase):
    """Test suite for error handling scenarios.

    These tests verify that the analyze function gracefully handles various
    error conditions and returns appropriate error messages.
    """

    def test_connection_error_handling(self):
        """Test: Handle connection errors with retry.

        Verifies that when the LLM provider is unreachable (connection refused),
        the function returns a proper error response with a retry suggestion.

        Relates to: Connection error handling with retry (Objective #3)
        """
        # Arrange
        import requests

        # Create a mock that will raise ConnectionError
        def mock_post(*args, **kwargs):
            raise requests.ConnectionError("Connection refused")

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("connection", result["error"].lower())

    def test_timeout_error_handling(self):
        """Test: Handle timeout errors gracefully.

        Verifies that when the LLM request times out, the function returns
        a proper error response with a timeout message suggesting alternatives.

        Relates to: Timeout error handling (Objective #4)
        """
        # Arrange
        import requests

        def mock_post(*args, **kwargs):
            raise requests.Timeout("Request timed out")

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("timeout", result["error"].lower())
        self.assertIn("smaller model", result["error"].lower())

    def test_invalid_response_format_handling(self):
        """Test: Handle invalid/malformed LLM responses.

        Verifies that when the LLM returns invalid or unparseable JSON,
        the function returns a proper error response indicating parsing failure.

        Relates to: Invalid response format handling (Objective #5)
        """
        # Arrange
        # Malformed JSON response
        invalid_response = "This is not valid JSON {"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": invalid_response}}
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("invalid", result["error"].lower())

    def test_authentication_error_handling(self):
        """Test: Handle authentication errors for OpenAI.

        Verifies that when the OpenAI API key is invalid,
        the function returns a proper authentication error response.

        Relates to: Authentication error handling
        """
        # Arrange
        import requests

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        def mock_post(*args, **kwargs):
            error = requests.HTTPError("401 Client Error: Unauthorized")
            error.response = mock_response
            raise error

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="openai",
                model="gpt-4o-mini",
                host=None,
                api_key="invalid-key",
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("authentication", result["error"].lower())

    def test_http_error_404_handling(self):
        """Test: Handle HTTP 404 errors.

        Verifies that when the LLM endpoint returns 404 Not Found,
        the function returns a proper error response.
        """
        # Arrange
        import requests

        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"

        def mock_post(*args, **kwargs):
            error = requests.HTTPError("404 Client Error: Not Found")
            error.response = mock_response
            raise error

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])
        self.assertIn("404", result["error"])

    def test_http_error_500_handling(self):
        """Test: Handle HTTP 500 errors.

        Verifies that when the LLM provider returns 500 Internal Server Error,
        the function returns a proper error response.

        Relates to: Server error handling
        """
        # Arrange
        import requests

        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"

        def mock_post(*args, **kwargs):
            error = requests.HTTPError("500 Server Error: Internal Server Error")
            error.response = mock_response
            raise error

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="openai",
                model="gpt-4o-mini",
                host=None,
                api_key="sk-test",
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNotNone(result["error"])
        self.assertIn("500", result["error"])


class TestAnalyzeRetryLogic(unittest.TestCase):
    """Test suite for retry behavior.

    These tests verify that the analyze function implements proper retry logic
    for transient failures to improve reliability.
    """

    def test_retry_on_transient_failures(self):
        """Test: Retry on temporary connection failures.

        Verifies that the analyze function retries transient failures
        before giving up, improving reliability.

        Relates to: Retry logic on transient failures (Objective #10)
        """
        # Arrange
        import requests

        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_success_response = Mock()
        mock_success_response.status_code = 200
        mock_success_response.json.return_value = {"message": {"content": expected_response}}
        mock_success_response.raise_for_status.return_value = None

        # First two calls fail, third succeeds
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise requests.ConnectionError("Temporary failure")
            return mock_success_response

        # Act
        with patch("analyzer.requests.post", side_effect=side_effect):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertTrue(result["success"])
        self.assertEqual(result["response"], expected_response)
        self.assertEqual(call_count[0], 3)  # Should have retried 3 times

    def test_retry_exhaustion(self):
        """Test: Fail after max retries exhausted.

        Verifies that the analyze function gives up after maximum
        retry attempts and returns an appropriate error message.

        Relates to: Retry logic on transient failures (Objective #10)
        """
        # Arrange
        import requests

        # Always fail
        def mock_post(*args, **kwargs):
            raise requests.ConnectionError("Persistent failure")

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host="http://127.0.0.1:11434",
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("connection", result["error"].lower())


class TestAnalyzeInputValidation(unittest.TestCase):
    """Test suite for input parameter validation.

    These tests verify that the analyze function handles various input scenarios
    including edge cases and invalid inputs.
    """

    def test_empty_prompt_handling(self):
        """Test: Handle empty prompt gracefully.

        Verifies that the analyze function handles empty prompts appropriately.

        Relates to: Empty prompt handling (Objective #6)
        """
        # Arrange - empty prompt
        # Act
        result = analyze(
            prompt="",
            provider="ollama",
            model="kimi-k2.5:cloud",
            host=None,
            api_key=None,
            base_url=None
        )

        # Assert
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["response"])
        # Verify response is valid JSON
        parsed = json.loads(result["response"])
        self.assertIn("checks", parsed)

    def test_invalid_provider_name(self):
        """Test: Handle invalid provider name.

        Verifies that the analyze function handles unknown provider names
        by returning an error with supported providers listed.

        Relates to: Invalid provider name (Objective #8)
        """
        # Arrange
        # Act
        result = analyze(
            prompt="Analyze security",
            provider="unknown_provider",
            model="some-model",
            host=None,
            api_key=None,
            base_url=None
        )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("provider", result["error"].lower())
        self.assertIn("ollama", result["error"].lower())
        self.assertIn("openai", result["error"].lower())

    def test_missing_api_key_for_openai(self):
        """Test: Handle missing API key for OpenAI provider.

        Verifies that the analyze function returns an error when
        OpenAI provider is used without an API key.

        Relates to: Missing API key for OpenAI (Objective #7)
        """
        # Arrange
        # Act
        result = analyze(
            prompt="Analyze security",
            provider="openai",
            model="gpt-4o-mini",
            host=None,
            api_key=None,  # Missing
            base_url=None
        )

        # Assert
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIn("api_key", result["error"].lower())


class TestAnalyzeOutputStructure(unittest.TestCase):
    """Test suite for output structure validation.

    These tests verify that the analyze function always returns a consistent
    output structure regardless of success or failure.
    """

    def test_output_structure_success(self):
        """Test: Verify successful response structure matches interface.

        Verifies that successful responses have the correct structure
        as specified in the PRD.
        """
        # Arrange
        expected_keys = {"success", "response", "error"}

        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": expected_response}}
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response):
            result = analyze(
                prompt="Test",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host=None,
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertEqual(set(result.keys()), expected_keys)
        self.assertTrue(result["success"])
        self.assertIsInstance(result["response"], str)
        self.assertIsNone(result["error"])

    def test_output_structure_failure(self):
        """Test: Verify failure response structure matches interface.

        Verifies that failure responses have the correct structure
        as specified in the PRD.
        """
        # Arrange
        expected_keys = {"success", "response", "error"}

        import requests

        def mock_post(*args, **kwargs):
            raise requests.ConnectionError("Test error")

        # Act
        with patch("analyzer.requests.post", side_effect=mock_post):
            result = analyze(
                prompt="Test",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host=None,
                api_key=None,
                base_url=None
            )

        # Assert
        self.assertEqual(set(result.keys()), expected_keys)
        self.assertFalse(result["success"])
        self.assertIsNone(result["response"])
        self.assertIsNotNone(result["error"])
        self.assertIsInstance(result["error"], str)

    def test_missing_host_uses_default(self):
        """Test: Handle missing host for Ollama provider.

        Verifies that the analyze function uses the default host when
        not provided for Ollama provider.

        Relates to: Default parameter handling
        """
        # Arrange
        expected_response = '{"checks": [], "urls": {}, "summary": {}}'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": {"content": expected_response}}
        mock_response.raise_for_status.return_value = None

        # Act
        with patch("analyzer.requests.post", return_value=mock_response) as mock_post:
            result = analyze(
                prompt="Analyze security",
                provider="ollama",
                model="kimi-k2.5:cloud",
                host=None,  # Will use default
                api_key=None,
                base_url=None
            )

        # Assert - should succeed with default host
        self.assertTrue(result["success"])

        # Verify default host was used
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("127.0.0.1:11434", call_args[0][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
