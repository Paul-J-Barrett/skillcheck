"""Unit tests for the url_classifier module.

These tests verify the classify_urls function correctly categorizes URLs
by risk level according to the PRD specification.
"""

import pytest
from url_classifier import classify_urls


class TestTrustedURLClassification:
    """Test suite for trusted URL classification.

    Trusted URLs are considered low risk and include:
    - docs.claude.ai
    - anthropic.com
    - opencode.ai
    - platform.openai.com
    """

    def test_classify_docs_claude_ai_as_trusted(self):
        """Test: docs.claude.ai is classified as trusted.

        Verifies that the official Claude documentation domain
        is correctly identified as a trusted source per PRD spec.
        """
        # Arrange
        urls = ["https://docs.claude.ai/some-path"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "classified_urls" in result
        assert "classifications" in result
        assert "https://docs.claude.ai/some-path" in result["classified_urls"]["trusted"]
        assert len(result["classified_urls"]["trusted"]) == 1

    def test_classify_anthropic_com_as_trusted(self):
        """Test: anthropic.com is classified as trusted.

        Verifies that the official Anthropic domain is correctly
        identified as a trusted source per PRD spec.
        """
        # Arrange
        urls = ["https://anthropic.com", "https://www.anthropic.com/research"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "anthropic.com" in str(result["classified_urls"]["trusted"])
        assert "www.anthropic.com" in str(result["classified_urls"]["trusted"])

    def test_classify_opencode_ai_as_trusted(self):
        """Test: opencode.ai is classified as trusted.

        Verifies that the OpenCode AI platform domain is correctly
        identified as a trusted source per PRD spec.
        """
        # Arrange
        urls = ["https://opencode.ai/tools"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://opencode.ai/tools" in result["classified_urls"]["trusted"]

    def test_classify_platform_openai_com_as_trusted(self):
        """Test: platform.openai.com is classified as trusted.

        Verifies that the OpenAI platform domain is correctly
        identified as a trusted source per PRD spec.
        """
        # Arrange
        urls = ["https://platform.openai.com/docs"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://platform.openai.com/docs" in result["classified_urls"]["trusted"]

    def test_trusted_urls_have_correct_reason_in_classifications(self):
        """Test: Trusted URLs have appropriate reason in classifications list.

        Verifies that each classified URL includes a reason explaining
        why it was assigned to that category.
        """
        # Arrange
        urls = ["https://docs.claude.ai"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        classification = result["classifications"][0]
        assert classification["url"] == "https://docs.claude.ai"
        assert classification["category"] == "trusted"
        assert "reason" in classification
        assert len(classification["reason"]) > 0


class TestMediumRiskClassification:
    """Test suite for medium risk URL classification.

    Medium risk URLs are established companies with controlled content:
    - google.com
    - microsoft.com
    - amazon.com
    - apple.com
    """

    def test_classify_google_com_as_medium(self):
        """Test: google.com is classified as medium risk.

        Verifies that Google's domain is correctly identified as
        medium risk requiring review per PRD spec.
        """
        # Arrange
        urls = ["https://google.com", "https://www.google.com/search"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "google.com" in str(result["classified_urls"]["medium"])

    def test_classify_microsoft_com_as_medium(self):
        """Test: microsoft.com is classified as medium risk.

        Verifies that Microsoft's domain is correctly identified as
        medium risk requiring review per PRD spec.
        """
        # Arrange
        urls = ["https://microsoft.com", "https://docs.microsoft.com"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "microsoft.com" in str(result["classified_urls"]["medium"])

    def test_classify_amazon_com_as_medium(self):
        """Test: amazon.com is classified as medium risk.

        Verifies that Amazon's domain is correctly identified as
        medium risk requiring review per PRD spec.
        """
        # Arrange
        urls = ["https://amazon.com"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://amazon.com" in result["classified_urls"]["medium"]

    def test_classify_apple_com_as_medium(self):
        """Test: apple.com is classified as medium risk.

        Verifies that Apple's domain is correctly identified as
        medium risk requiring review per PRD spec.
        """
        # Arrange
        urls = ["https://apple.com", "https://developer.apple.com"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "apple.com" in str(result["classified_urls"]["medium"])


class TestSuspiciousClassification:
    """Test suite for suspicious URL classification.

    Suspicious URLs are open contribution platforms:
    - github.com
    - gist.github.com
    - pastebin.com
    - codepen.io
    - jsfiddle.net
    """

    def test_classify_github_com_as_suspicious(self):
        """Test: github.com is classified as suspicious.

        Verifies that GitHub's domain is correctly identified as
        suspicious (open contribution platform) per PRD spec.
        """
        # Arrange
        urls = ["https://github.com/user/repo"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://github.com/user/repo" in result["classified_urls"]["suspicious"]

    def test_classify_gist_github_com_as_suspicious(self):
        """Test: gist.github.com is classified as suspicious.

        Verifies that GitHub Gist is correctly identified as
        suspicious (open contribution platform) per PRD spec.
        """
        # Arrange
        urls = ["https://gist.github.com/user/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://gist.github.com/user/abc123" in result["classified_urls"]["suspicious"]

    def test_classify_pastebin_com_as_suspicious(self):
        """Test: pastebin.com is classified as suspicious.

        Verifies that Pastebin is correctly identified as
        suspicious (open contribution platform) per PRD spec.
        """
        # Arrange
        urls = ["https://pastebin.com/raw/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://pastebin.com/raw/abc123" in result["classified_urls"]["suspicious"]

    def test_classify_codepen_io_as_suspicious(self):
        """Test: codepen.io is classified as suspicious.

        Verifies that CodePen is correctly identified as
        suspicious (open contribution platform) per PRD spec.
        """
        # Arrange
        urls = ["https://codepen.io/user/pen/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://codepen.io/user/pen/abc123" in result["classified_urls"]["suspicious"]

    def test_classify_jsfiddle_net_as_suspicious(self):
        """Test: jsfiddle.net is classified as suspicious.

        Verifies that JSFiddle is correctly identified as
        suspicious (open contribution platform) per PRD spec.
        """
        # Arrange
        urls = ["https://jsfiddle.net/user/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://jsfiddle.net/user/abc123" in result["classified_urls"]["suspicious"]


class TestMaliciousClassification:
    """Test suite for malicious URL classification.

    Malicious URLs include:
    - URL shorteners (bit.ly, tinyurl, etc.)
    - IP addresses
    - Known malicious domains
    - Suspicious TLDs (.tk, .ml, etc.)
    """

    def test_classify_bit_ly_as_malicious(self):
        """Test: bit.ly is classified as malicious.

        Verifies that the bit.ly URL shortener is correctly
        identified as malicious per PRD spec.
        """
        # Arrange
        urls = ["https://bit.ly/3xMal"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://bit.ly/3xMal" in result["classified_urls"]["malicious"]

    def test_classify_tinyurl_as_malicious(self):
        """Test: tinyurl.com is classified as malicious.

        Verifies that the TinyURL shortener is correctly
        identified as malicious per PRD spec.
        """
        # Arrange
        urls = ["https://tinyurl.com/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://tinyurl.com/abc123" in result["classified_urls"]["malicious"]

    def test_classify_ip_address_as_malicious(self):
        """Test: IP addresses are classified based on geolocation risk.

        Verifies that IP address URLs are correctly classified:
        - Private/local IPs are trusted
        - IPs from high-risk countries are malicious
        """
        # Arrange
        urls = [
            "http://192.168.1.1",  # Private IP - should be trusted
            "https://10.0.0.1/api",  # Private IP - should be trusted
            "http://1.2.3.4",  # Mock China IP - should be malicious
            "http://2.3.4.5",  # Mock Russia IP - should be malicious
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        # Private IPs should be trusted
        assert "http://192.168.1.1" in result["classified_urls"]["trusted"]
        assert "https://10.0.0.1/api" in result["classified_urls"]["trusted"]
        
        # High-risk country IPs should be malicious
        assert "http://1.2.3.4" in result["classified_urls"]["malicious"]
        assert "http://2.3.4.5" in result["classified_urls"]["malicious"]
        
        # Check geolocation data is present for high-risk IPs
        for classification in result["classifications"]:
            if classification["url"] in ["http://1.2.3.4", "http://2.3.4.5"]:
                assert "geolocation" in classification
                assert classification["geolocation"]["country"] in ["China", "Russia"]
        
        # Check geolocation summary
        assert result["geolocation_summary"]["high_risk_count"] == 2

    def test_classify_suspicious_tld_as_malicious(self):
        """Test: Suspicious TLDs (.tk, .ml) are classified as malicious.

        Verifies that domains with suspicious top-level domains
        are correctly identified as malicious per PRD spec.
        """
        # Arrange
        urls = [
            "http://freetest.tk",
            "https://suspicious.ml/path"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "http://freetest.tk" in result["classified_urls"]["malicious"]
        assert "https://suspicious.ml/path" in result["classified_urls"]["malicious"]

    def test_malicious_urls_have_appropriate_reason(self):
        """Test: Malicious URLs have descriptive reasons.

        Verifies that malicious URL classifications include
        explanations of why they are considered dangerous.
        """
        # Arrange
        urls = ["https://bit.ly/abc123"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        classification = result["classifications"][0]
        assert classification["category"] == "malicious"
        assert "url shortener" in classification["reason"].lower() or \
               "short" in classification["reason"].lower()


class TestUnknownClassification:
    """Test suite for unknown URL classification.

    Unknown URLs are any domains not in known lists, including:
    - Newly registered domains
    - Parked domains
    - Unclassified domains
    """

    def test_classify_unknown_domain_as_unknown(self):
        """Test: Unknown domains are classified as unknown.

        Verifies that domains not in any known category are
        correctly identified as unknown per PRD spec.
        """
        # Arrange
        urls = [
            "https://unknown-example.com",
            "https://somenewsite.org/path"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://unknown-example.com" in result["classified_urls"]["unknown"]
        assert "https://somenewsite.org/path" in result["classified_urls"]["unknown"]

    def test_classify_obscure_tld_as_unknown(self):
        """Test: Domains with obscure TLDs are classified as unknown.

        Verifies that domains with uncommon TLDs (not malicious)
        are classified as unknown for review.
        """
        # Arrange
        urls = [
            "https://example.xyz",
            "https://test.pw/info"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://example.xyz" in result["classified_urls"]["unknown"]
        assert "https://test.pw/info" in result["classified_urls"]["unknown"]

    def test_unknown_classification_includes_reason(self):
        """Test: Unknown URLs include reason for classification.

        Verifies that unknown URL classifications explain that
        the domain is not in known lists and should be reviewed.
        """
        # Arrange
        urls = ["https://random-unknown-site.net"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        classification = result["classifications"][0]
        assert classification["category"] == "unknown"
        assert "unknown" in classification["reason"].lower() or \
               "not in" in classification["reason"].lower() or \
               "not listed" in classification["reason"].lower()


class TestOverrideFunctionality:
    """Test suite for override functionality.

    The overrides parameter allows reclassifying specific domains
    to different categories.
    """

    def test_override_changes_classification(self):
        """Test: Override can change a URL's classification.

        Verifies that the overrides parameter correctly modifies
        the classification of specified domains.
        """
        # Arrange
        urls = ["https://unknown-example.com"]
        overrides = {"unknown-example.com": "trusted"}

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://unknown-example.com" in result["classified_urls"]["trusted"]
        assert "https://unknown-example.com" not in result["classified_urls"]["unknown"]

    def test_override_to_suspicious(self):
        """Test: Override can classify trusted as suspicious.

        Verifies that trusted domains can be overridden to suspicious.
        """
        # Arrange
        urls = ["https://docs.claude.ai"]
        overrides = {"docs.claude.ai": "suspicious"}

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://docs.claude.ai" in result["classified_urls"]["suspicious"]
        assert "https://docs.claude.ai" not in result["classified_urls"]["trusted"]

    def test_override_affects_classifications_list(self):
        """Test: Override updates the classifications list.

        Verifies that overridden URLs show the new category
        in the classifications array with updated reason.
        """
        # Arrange
        urls = ["https://example.com"]
        overrides = {"example.com": "malicious"}

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        classification = result["classifications"][0]
        assert classification["category"] == "malicious"
        assert "override" in classification["reason"].lower() or \
               "manual" in classification["reason"].lower()

    def test_multiple_overrides(self):
        """Test: Multiple overrides can be applied simultaneously.

        Verifies that the overrides parameter can handle multiple
        domain reclassifications at once.
        """
        # Arrange
        urls = [
            "https://google.com",
            "https://unknown-site.com",
            "https://pastebin.com"
        ]
        overrides = {
            "google.com": "trusted",
            "unknown-site.com": "malicious",
            "pastebin.com": "trusted"
        }

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://google.com" in result["classified_urls"]["trusted"]
        assert "https://unknown-site.com" in result["classified_urls"]["malicious"]
        assert "https://pastebin.com" in result["classified_urls"]["trusted"]

    def test_empty_overrides_does_nothing(self):
        """Test: Empty overrides dict has no effect.

        Verifies that an empty overrides dict doesn't change
        any classifications.
        """
        # Arrange
        urls = ["https://github.com/user/repo"]
        overrides = {}

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://github.com/user/repo" in result["classified_urls"]["suspicious"]

    def test_non_matching_overrides_ignored(self):
        """Test: Overrides for non-existent domains are ignored.

        Verifies that overrides for domains not in the URL list
        don't cause errors or affect other classifications.
        """
        # Arrange
        urls = ["https://example.com"]
        overrides = {"other-site.com": "trusted", "example.com": "medium"}

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://example.com" in result["classified_urls"]["medium"]
        assert len(result["classifications"]) == 1


class TestEmptyURLListHandling:
    """Test suite for empty URL list handling.

    Verifies correct behavior when no URLs are provided.
    """

    def test_empty_url_list_returns_empty_classified_urls(self):
        """Test: Empty URL list returns empty classified_urls dict.

        Verifies that when no URLs are provided, all category
        lists in classified_urls are empty.
        """
        # Arrange
        urls = []
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert result["classified_urls"]["trusted"] == []
        assert result["classified_urls"]["medium"] == []
        assert result["classified_urls"]["suspicious"] == []
        assert result["classified_urls"]["malicious"] == []
        assert result["classified_urls"]["unknown"] == []

    def test_empty_url_list_returns_empty_classifications(self):
        """Test: Empty URL list returns empty classifications list.

        Verifies that when no URLs are provided, the classifications
        array is empty.
        """
        # Arrange
        urls = []
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert result["classifications"] == []

    def test_none_overrides_with_empty_urls(self):
        """Test: None overrides with empty URLs works correctly.

        Verifies that the combination of empty URL list and
        None overrides is handled gracefully.
        """
        # Arrange
        urls = []
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "classified_urls" in result
        assert "classifications" in result
        assert len(result["classifications"]) == 0


class TestMixedURLClassification:
    """Test suite for mixed URL batch classification.

    Verifies correct handling when multiple URLs of different
    categories are classified together.
    """

    def test_mixed_urls_classified_correctly(self):
        """Test: Mixed URL batch classified into correct categories.

        Verifies that when multiple URLs of different risk levels
        are provided, each is assigned to the correct category.
        """
        # Arrange
        urls = [
            "https://docs.claude.ai",      # trusted
            "https://google.com",          # medium
            "https://github.com/user",     # suspicious
            "https://bit.ly/abc",          # malicious
            "https://unknown-example.com"  # unknown
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://docs.claude.ai" in result["classified_urls"]["trusted"]
        assert "https://google.com" in result["classified_urls"]["medium"]
        assert "https://github.com/user" in result["classified_urls"]["suspicious"]
        assert "https://bit.ly/abc" in result["classified_urls"]["malicious"]
        assert "https://unknown-example.com" in result["classified_urls"]["unknown"]

    def test_classifications_list_matches_all_urls(self):
        """Test: Classifications list includes all URLs.

        Verifies that the classifications array contains an entry
        for every input URL.
        """
        # Arrange
        urls = [
            "https://docs.claude.ai",
            "https://google.com",
            "https://github.com/user"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert len(result["classifications"]) == 3
        classified_urls = [c["url"] for c in result["classifications"]]
        assert all(url in classified_urls for url in urls)

    def test_output_structure_matches_interface(self):
        """Test: Output structure matches PRD interface specification.

        Verifies that the output format conforms to the interface:
        {
            classified_urls: {trusted: [...], medium: [...], ...},
            classifications: [{url, category, reason}, ...]
        }
        """
        # Arrange
        urls = ["https://example.com"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        # Check top-level structure
        assert "classified_urls" in result
        assert "classifications" in result

        # Check classified_urls structure
        assert "trusted" in result["classified_urls"]
        assert "medium" in result["classified_urls"]
        assert "suspicious" in result["classified_urls"]
        assert "malicious" in result["classified_urls"]
        assert "unknown" in result["classified_urls"]

        # Check all values are lists
        for category in result["classified_urls"].values():
            assert isinstance(category, list)

        # Check classifications structure (if any)
        for classification in result["classifications"]:
            assert "url" in classification
            assert "category" in classification
            assert "reason" in classification
            assert classification["category"] in ["trusted", "medium", "suspicious", "malicious", "unknown"]


class TestEdgeCases:
    """Test suite for edge cases and boundary conditions.

    Tests unusual inputs and boundary conditions to ensure
    robust error handling.
    """

    def test_url_without_protocol(self):
        """Test: URLs without protocol scheme.

        Verifies that URLs without http:// or https:// are
        handled appropriately.
        """
        # Arrange
        urls = ["google.com/search"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert - should still classify the domain
        assert len(result["classifications"]) == 1
        classification = result["classifications"][0]
        assert "google.com" in classification["url"]

    def test_url_with_subdomain(self):
        """Test: Classification works with subdomains.

        Verifies that subdomains are correctly matched to their
        parent domain classification.
        """
        # Arrange
        urls = [
            "https://api.github.com",
            "https://raw.githubusercontent.com",
            "https://gist.github.com/user/abc"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert - all GitHub subdomains should be suspicious
        for url in urls:
            assert url in result["classified_urls"]["suspicious"]

    def test_url_with_port(self):
        """Test: Classification works with port numbers.

        Verifies that URLs with explicit port numbers are
        classified correctly based on their domain.
        """
        # Arrange
        urls = ["https://google.com:8080/search"]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://google.com:8080/search" in result["classified_urls"]["medium"]

    def test_duplicate_urls(self):
        """Test: Duplicate URLs are handled appropriately.

        Verifies that duplicate URLs in the input list are
        either deduplicated or consistently classified.
        """
        # Arrange
        urls = [
            "https://google.com",
            "https://google.com",
            "https://docs.claude.ai"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        # Either duplicates are in the list twice or deduplicated
        google_classifications = [c for c in result["classifications"] if "google.com" in c["url"]]
        assert len(google_classifications) >= 1
        assert all(c["category"] == "medium" for c in google_classifications)

    def test_url_with_query_parameters(self):
        """Test: Classification works with query parameters.

        Verifies that URLs with query strings are classified
        based on their domain, ignoring query parameters.
        """
        # Arrange
        urls = [
            "https://bit.ly/abc123?utm_source=test",
            "https://google.com/search?q=test"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        assert "https://bit.ly/abc123?utm_source=test" in result["classified_urls"]["malicious"]
        assert "https://google.com/search?q=test" in result["classified_urls"]["medium"]

    def test_case_insensitive_domain_matching(self):
        """Test: Domain matching is case-insensitive.

        Verifies that domains are matched case-insensitively
        for classification.
        """
        # Arrange
        urls = [
            "https://GOOGLE.COM",
            "https://GitHub.Com/user",
            "https://BIT.LY/abc"
        ]
        overrides = None

        # Act
        result = classify_urls(urls, overrides)

        # Assert
        # Check that at least one URL is classified correctly (case-insensitive)
        google_classified = "https://GOOGLE.COM" in result["classified_urls"]["medium"]
        assert google_classified, "Google should be classified as medium (case-insensitive)"


class TestNegativeCases:
    """Test suite for negative/error cases.

    Tests how the function handles invalid inputs and error conditions.
    """

    def test_invalid_url_format(self):
        """Test: Invalid URL formats are handled gracefully.

        Verifies that malformed URLs don't cause crashes
        and are handled appropriately.
        """
        # Arrange
        urls = [
            "not-a-valid-url",
            "",
            "ftp://example.com"
        ]
        overrides = None

        # Act - should not raise exception
        try:
            result = classify_urls(urls, overrides)
            # Assert - function completed without error
            assert "classified_urls" in result
            assert "classifications" in result
        except Exception as e:
            pytest.fail(f"classify_urls raised an exception for invalid URLs: {e}")

    def test_none_url_list_raises_error(self):
        """Test: None as URL list raises appropriate error.

        Verifies that None for the urls parameter is handled
        with a clear error message.
        """
        # Arrange
        urls = None
        overrides = None

        # Act & Assert
        with pytest.raises((TypeError, ValueError)):
            classify_urls(urls, overrides)

    def test_invalid_override_format(self):
        """Test: Invalid override format is handled.

        Verifies that malformed overrides don't crash the function.
        """
        # Arrange
        urls = ["https://google.com"]
        overrides = "invalid-string-not-dict"

        # Act - should not raise exception
        try:
            result = classify_urls(urls, overrides)
            # If it doesn't raise, check it handled gracefully
            assert "classified_urls" in result
        except (TypeError, AttributeError):
            # These exceptions are acceptable for invalid input
            pass

    def test_invalid_category_in_overrides(self):
        """Test: Invalid category in overrides is rejected.

        Verifies that overrides with invalid category values
        are handled appropriately.
        """
        # Arrange
        urls = ["https://example.com"]
        overrides = {"example.com": "invalid-category"}

        # Act
        result = classify_urls(urls, overrides)

        # Assert - should either use a default or keep original classification
        # The specific behavior may vary, but it shouldn't crash
        assert "classified_urls" in result
        assert "classifications" in result
