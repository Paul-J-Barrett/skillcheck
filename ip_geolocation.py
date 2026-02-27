"""IP Geolocation Module

Lookup IP address geolocation and identify high-risk countries.

Interface:
- Input: {ip_address: str, cache: dict|None}
- Output: {ip, country, country_code, city, region, risk_level, reason, success, error}
"""

import re
from typing import Any


# High-risk countries (ISO 3166-1 alpha-2 codes)
CRITICAL_RISK_COUNTRIES = {
    "CN",  # China
    "KP",  # North Korea
    "IR",  # Iran
    "RU",  # Russia
    "BY",  # Belarus
    "MM",  # Myanmar
    "SY",  # Syria
    "CU",  # Cuba
}

SUSPICIOUS_RISK_COUNTRIES = {
    "VE",  # Venezuela
    "AF",  # Afghanistan
}

COUNTRY_NAMES = {
    "CN": "China",
    "KP": "North Korea",
    "IR": "Iran",
    "RU": "Russia",
    "BY": "Belarus",
    "MM": "Myanmar",
    "SY": "Syria",
    "CU": "Cuba",
    "VE": "Venezuela",
    "AF": "Afghanistan",
}


def is_ip_address(value: str) -> bool:
    """Check if string is an IP address."""
    # IPv4 pattern
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(value):
        # Validate each octet
        octets = value.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return True

    # IPv6 pattern (simplified)
    if re.match(r'^[\da-fA-F:]+$', value) and ':' in value:
        return True

    return False


def lookup_ip_geolocation(ip_address: str, cache: dict | None = None) -> dict[str, Any]:
    """Lookup IP address geolocation.

    Args:
        ip_address: IP address to lookup
        cache: Optional cache dict to store/retrieve results

    Returns:
        Dictionary with geolocation data
    """
    if not is_ip_address(ip_address):
        return {
            "success": False,
            "error": f"Not a valid IP address: {ip_address}",
            "ip": ip_address,
            "country": None,
            "country_code": None,
            "city": None,
            "region": None,
            "risk_level": None,
            "reason": None,
        }

    # Check cache first
    if cache and ip_address in cache:
        return cache[ip_address]

    # Mock geolocation lookup (in production, use ip-api.com or similar)
    # For now, we'll return mock data based on IP patterns
    result = _mock_geolocation_lookup(ip_address)

    # Store in cache
    if cache is not None:
        cache[ip_address] = result

    return result


def _mock_geolocation_lookup(ip_address: str) -> dict[str, Any]:
    """Mock geolocation lookup for demonstration.

    In production, replace with actual API call to:
    - ip-api.com (free, no key required)
    - ipapi.co
    - maxmind
    """
    # Determine country based on IP patterns (for demo purposes)
    country_code = None
    country_name = "Unknown"

    # Check for private/local IPs
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
        country_code = "LOCAL"
        country_name = "Private Network"
        risk_level = "trusted"
        reason = "Private/local IP address"
    # Mock some high-risk IPs for demonstration
    elif ip_address.startswith("1."):
        country_code = "CN"
        country_name = "China"
        risk_level = "malicious"
        reason = "IP address located in high-risk country: China"
    elif ip_address.startswith("2."):
        country_code = "RU"
        country_name = "Russia"
        risk_level = "malicious"
        reason = "IP address located in high-risk country: Russia"
    elif ip_address.startswith("3."):
        country_code = "IR"
        country_name = "Iran"
        risk_level = "malicious"
        reason = "IP address located in high-risk country: Iran"
    elif ip_address.startswith("4."):
        country_code = "KP"
        country_name = "North Korea"
        risk_level = "malicious"
        reason = "IP address located in high-risk country: North Korea"
    else:
        # Default to unknown
        country_code = "UNKNOWN"
        country_name = "Unknown"
        risk_level = "unknown"
        reason = "Geolocation data not available"

    return {
        "success": True,
        "error": None,
        "ip": ip_address,
        "country": country_name,
        "country_code": country_code,
        "city": "Unknown",
        "region": "Unknown",
        "risk_level": risk_level,
        "reason": reason,
    }


def get_ip_risk_level(country_code: str) -> tuple[str, str]:
    """Get risk level for a country code.

    Args:
        country_code: ISO 3166-1 alpha-2 country code

    Returns:
        Tuple of (risk_level, reason)
    """
    if country_code in CRITICAL_RISK_COUNTRIES:
        country_name = COUNTRY_NAMES.get(country_code, country_code)
        return (
            "malicious",
            f"IP address located in high-risk country: {country_name}"
        )
    elif country_code in SUSPICIOUS_RISK_COUNTRIES:
        country_name = COUNTRY_NAMES.get(country_code, country_code)
        return (
            "suspicious",
            f"IP address located in politically high-risk country: {country_name}"
        )
    elif country_code == "LOCAL":
        return ("trusted", "Private/local IP address")
    elif country_code == "UNKNOWN":
        return ("unknown", "Geolocation data not available")
    else:
        return ("unknown", f"Country: {COUNTRY_NAMES.get(country_code, country_code)}")


def extract_ip_from_url(url: str) -> str | None:
    """Extract IP address from URL if present.

    Args:
        url: URL string

    Returns:
        IP address if found, None otherwise
    """
    # Remove protocol
    url = url.replace("http://", "").replace("https://", "")
    # Remove path
    url = url.split("/")[0]
    # Remove port
    url = url.split(":")[0]

    if is_ip_address(url):
        return url

    return None


# Cache for geolocation results
_geolocation_cache: dict[str, dict[str, Any]] = {}


def get_geolocation_cache() -> dict[str, dict[str, Any]]:
    """Get the global geolocation cache."""
    return _geolocation_cache


def clear_geolocation_cache() -> None:
    """Clear the geolocation cache."""
    global _geolocation_cache
    _geolocation_cache = {}
