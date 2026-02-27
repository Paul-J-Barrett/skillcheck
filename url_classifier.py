"""URL Classifier Module

Categorizes URLs by risk level with support for manual overrides and IP geolocation.

Interface:
- Input: {urls: list[str], overrides: dict|None}
- Output: {classified_urls: {trusted, medium, suspicious, malicious, unknown}, classifications: [{url, category, reason, geolocation}], geolocation_summary}
"""

import re
from urllib.parse import urlparse
from typing import Any

from ip_geolocation import lookup_ip_geolocation, is_ip_address, extract_ip_from_url, get_geolocation_cache


# Domain lists by category
TRUSTED_DOMAINS = {
    "docs.claude.ai",
    "anthropic.com",
    "www.anthropic.com",
    "opencode.ai",
    "www.opencode.ai",
    "platform.openai.com",
}

MEDIUM_RISK_DOMAINS = {
    "google.com",
    "www.google.com",
    "microsoft.com",
    "www.microsoft.com",
    "docs.microsoft.com",
    "amazon.com",
    "www.amazon.com",
    "apple.com",
    "www.apple.com",
    "developer.apple.com",
}

SUSPICIOUS_DOMAINS = {
    "github.com",
    "www.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "pastebin.com",
    "www.pastebin.com",
    "codepen.io",
    "www.codepen.io",
    "jsfiddle.net",
    "www.jsfiddle.net",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq"}

VALID_CATEGORIES = {"trusted", "medium", "suspicious", "malicious", "unknown"}


def _extract_domain(url: str) -> str:
    """Extract the domain from a URL, handling various formats."""
    # Handle URLs without protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]

        return domain
    except Exception:
        # Fallback: extract domain-like pattern
        match = re.search(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9.]+)', url)
        if match:
            return match.group(1).lower()
        return url.lower()


def _is_ip_address(domain: str) -> bool:
    """Check if the domain is an IP address."""
    # IPv4 pattern
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(domain):
        return True

    # IPv6 pattern (simplified)
    if re.match(r'^[\da-fA-F:]+$', domain) and ':' in domain:
        return True

    return False


def _has_suspicious_tld(domain: str) -> bool:
    """Check if domain has a suspicious TLD."""
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False


def _is_url_shortener(domain: str) -> bool:
    """Check if domain is a URL shortener."""
    return domain in URL_SHORTENERS


def _classify_domain(domain: str) -> tuple[str, str]:
    """Classify a domain into a category and provide a reason.

    Returns:
        tuple: (category, reason)
    """
    # Check for IP addresses first
    if _is_ip_address(domain):
        return "malicious", "IP addresses are classified as potentially malicious"

    # Check for URL shorteners
    if _is_url_shortener(domain):
        return "malicious", f"URL shortener detected - {domain} hides the final destination"

    # Check for suspicious TLDs
    if _has_suspicious_tld(domain):
        return "malicious", f"Suspicious TLD detected in domain - {domain}"

    # Check trusted domains
    if domain in TRUSTED_DOMAINS:
        return "trusted", f"Trusted domain - {domain} is in trusted list"

    # Check medium risk domains
    if domain in MEDIUM_RISK_DOMAINS:
        return "medium", f"Established company domain - {domain} requires review"

    # Check suspicious domains
    if domain in SUSPICIOUS_DOMAINS:
        return "suspicious", f"Open contribution platform - {domain} can host user-generated content"

    # Check parent domain for subdomains
    parts = domain.split('.')
    if len(parts) >= 2:
        parent_domain = '.'.join(parts[-2:])

        if parent_domain in [d.replace('www.', '') for d in TRUSTED_DOMAINS]:
            return "trusted", f"Trusted subdomain - {domain} is under trusted parent"

        if parent_domain in [d.replace('www.', '') for d in MEDIUM_RISK_DOMAINS]:
            return "medium", f"Established company subdomain - {domain} requires review"

        if parent_domain in [d.replace('www.', '') for d in SUSPICIOUS_DOMAINS]:
            return "suspicious", f"Open contribution platform subdomain - {domain} can host user content"

    # Unknown domain
    return "unknown", f"Unknown domain - {domain} is not in known lists, manual review recommended"


def classify_urls(urls: list[str], overrides: dict | None = None, check_geolocation: bool = True) -> dict[str, Any]:
    """Classify URLs by risk level with optional overrides and IP geolocation.

    Args:
        urls: List of URLs to classify
        overrides: Optional dict mapping domains to desired categories
        check_geolocation: Whether to perform IP geolocation lookups

    Returns:
        Dict with classified_urls (by category), classifications list, and geolocation summary
    """
    if urls is None:
        raise TypeError("urls parameter cannot be None")

    # Initialize result structure
    result = {
        "classified_urls": {
            "trusted": [],
            "medium": [],
            "suspicious": [],
            "malicious": [],
            "unknown": [],
        },
        "classifications": [],
        "geolocation_summary": {
            "high_risk_count": 0,
            "high_risk_countries": [],
        },
    }

    # Handle empty list
    if not urls:
        return result

    # Get geolocation cache
    cache = get_geolocation_cache() if check_geolocation else None

    # Normalize overrides
    overrides = overrides or {}

    for url in urls:
        # Skip empty strings
        if not url:
            continue

        domain = _extract_domain(url)

        # Check for override
        if domain in overrides:
            category = overrides[domain]
            # Validate category is valid, fallback to actual classification if not
            if category not in VALID_CATEGORIES:
                category, reason = _classify_domain(domain)
            else:
                reason = f"Manual override - classified as {category}"
            geolocation = None
        else:
            category, reason = _classify_domain(domain)
            geolocation = None

            # If it's an IP address, check geolocation
            if check_geolocation and _is_ip_address(domain):
                geo_result = lookup_ip_geolocation(domain, cache)
                if geo_result["success"] and geo_result["risk_level"]:
                    # Update category based on geolocation
                    category = geo_result["risk_level"]
                    reason = geo_result["reason"]
                    geolocation = {
                        "country": geo_result["country"],
                        "country_code": geo_result["country_code"],
                        "city": geo_result["city"],
                        "region": geo_result["region"],
                    }

                    # Update geolocation summary
                    if category == "malicious":
                        result["geolocation_summary"]["high_risk_count"] += 1
                        if geo_result["country"] and geo_result["country"] not in result["geolocation_summary"]["high_risk_countries"]:
                            result["geolocation_summary"]["high_risk_countries"].append(geo_result["country"])

        # Add to classified_urls
        if url not in result["classified_urls"][category]:
            result["classified_urls"][category].append(url)

        # Add to classifications list
        classification: dict[str, Any] = {
            "url": url,
            "category": category,
            "reason": reason,
        }
        if geolocation:
            classification["geolocation"] = geolocation
        result["classifications"].append(classification)

    return result
