"""IP Geolocation Module

Lookup IP address geolocation and identify high-risk countries.

This module works without external API dependencies by:
1. Accurately detecting private/local IP addresses (RFC 1918, loopback, etc.)
2. Using optional local MaxMind GeoLite2 database if available
3. Returning "unknown" for public IPs when no database is available

Interface:
- Input: {ip_address: str, cache: dict|None}
- Output: {ip, country, country_code, city, region, risk_level, reason, success, error}
"""

import ipaddress
import re
from pathlib import Path
from typing import Any

# Optional MaxMind GeoLite2 support
GEOIP2_AVAILABLE = False
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    pass


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
    """Check if string is a valid IP address using standard library."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(ip_address: str) -> tuple[bool, str]:
    """Check if IP is private/local using ipaddress module.
    
    Returns:
        Tuple of (is_private, reason)
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        
        if ip.is_loopback:
            return True, "Loopback address"
        elif ip.is_private:
            if ip_address.startswith("192.168."):
                return True, "Private network (RFC 1918 Class C)"
            elif ip_address.startswith("10."):
                return True, "Private network (RFC 1918 Class A)"
            elif ip_address.startswith("172."):
                # Check for 172.16.0.0/12
                second_octet = int(ip_address.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True, "Private network (RFC 1918 Class B)"
            return True, "Private/local IP address"
        elif ip.is_link_local:
            return True, "Link-local address"
        elif ip.is_multicast:
            return True, "Multicast address"
        elif ip.is_reserved:
            return True, "Reserved address"
        
        return False, "Public IP address"
    except ValueError:
        return False, "Invalid IP address"


def _get_geolite2_database_path() -> Path | None:
    """Find local MaxMind GeoLite2 database if available.
    
    Searches for GeoLite2-City.mmdb in common locations:
    - /usr/share/GeoIP/
    - /var/lib/GeoIP/
    - /usr/local/share/GeoIP/
    - Current directory
    - GeoLite2 directory relative to this file
    """
    possible_paths = [
        Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
        Path("/usr/share/GeoIP/GeoLite2-Country.mmdb"),
        Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
        Path("/var/lib/GeoIP/GeoLite2-Country.mmdb"),
        Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"),
        Path("/usr/local/share/GeoIP/GeoLite2-Country.mmdb"),
        Path("GeoLite2-City.mmdb"),
        Path("GeoLite2-Country.mmdb"),
        Path(__file__).parent.parent / "data" / "GeoLite2-City.mmdb",
        Path(__file__).parent.parent / "data" / "GeoLite2-Country.mmdb",
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    return None


def _lookup_with_maxmind(ip_address: str, db_path: Path) -> dict[str, Any] | None:
    """Lookup IP using MaxMind GeoLite2 database.
    
    Args:
        ip_address: IP to lookup
        db_path: Path to GeoLite2 database
        
    Returns:
        Geo data dict or None if lookup fails
    """
    if not GEOIP2_AVAILABLE:
        return None
    
    try:
        import geoip2.database
        import geoip2.errors
        
        with geoip2.database.Reader(str(db_path)) as reader:
            try:
                response = reader.city(ip_address)
                country_code = response.country.iso_code
                country_name = response.country.name or "Unknown"
                city = response.city.name or "Unknown"
                region = response.subdivisions.most_specific.name or "Unknown"
                
                return {
                    "country_code": country_code,
                    "country": country_name,
                    "city": city,
                    "region": region,
                }
            except geoip2.errors.AddressNotFoundError:
                return None
    except Exception:
        return None


def lookup_ip_geolocation(ip_address: str, cache: dict | None = None) -> dict[str, Any]:
    """Lookup IP address geolocation without external API dependencies.

    Works in three modes:
    1. Private/local IPs: Accurately detected using ipaddress module (RFC 1918, loopback, etc.)
    2. MaxMind GeoLite2: If available locally, provides full geolocation
    3. Unknown: Public IPs return "unknown" when no database available (no external API calls)

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

    # First, check if it's a private/local IP
    is_private, private_reason = is_private_ip(ip_address)
    if is_private:
        result = {
            "success": True,
            "error": None,
            "ip": ip_address,
            "country": "Private Network",
            "country_code": "LOCAL",
            "city": "N/A",
            "region": "N/A",
            "risk_level": "trusted",
            "reason": private_reason,
        }
        if cache is not None:
            cache[ip_address] = result
        return result

    # Try MaxMind GeoLite2 if available (local database, no API dependency)
    db_path = _get_geolite2_database_path()
    if db_path:
        geo_data = _lookup_with_maxmind(ip_address, db_path)
        if geo_data:
            country_code = geo_data.get("country_code", "UNKNOWN")
            risk_level, reason = get_ip_risk_level(country_code)
            
            result = {
                "success": True,
                "error": None,
                "ip": ip_address,
                "country": geo_data.get("country", "Unknown"),
                "country_code": country_code,
                "city": geo_data.get("city", "Unknown"),
                "region": geo_data.get("region", "Unknown"),
                "risk_level": risk_level,
                "reason": reason,
            }
            if cache is not None:
                cache[ip_address] = result
            return result

    # No external API - return unknown for public IPs
    result = {
        "success": True,
        "error": None,
        "ip": ip_address,
        "country": "Unknown",
        "country_code": "UNKNOWN",
        "city": "Unknown",
        "region": "Unknown",
        "risk_level": "unknown",
        "reason": "Install MaxMind GeoLite2 database for geolocation (no external API calls)",
    }
    if cache is not None:
        cache[ip_address] = result
    return result


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
