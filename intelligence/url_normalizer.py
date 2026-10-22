"""
KhmerShield-AI - URL Normalization, Validation, and SSRF Protection.

Safely parses, validates, normalizes, and sanitizes input URLs.
Enforces strict SSRF protection by disallowing private IPs, loopbacks,
cloud metadata addresses (e.g., 169.254.169.254), and unsupported schemes.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse


ALLOWED_SCHEMES = {"http", "https"}
DANGEROUS_SCHEMES = {"file", "ftp", "gopher", "data", "javascript", "blob", "chrome", "about"}
MAX_URL_LENGTH = 4096
DEFAULT_PORTS = {80: "http", 443: "https"}

# Cloud metadata IP and common reserved prefixes
CLOUD_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

# Sensitive query parameters to redact from logs/history
SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "auth", "key", "api_key", "apikey",
    "secret", "password", "passwd", "pwd", "session", "sessionid",
    "jwt", "code", "refresh_token", "oauth_token", "sig", "signature"
}


class URLValidationError(ValueError):
    """Raised when a URL is invalid, unsafe, or violates policy."""
    pass


def is_ip_address(host: str) -> bool:
    """Check if the given host string is a valid IPv4 or IPv6 address."""
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_private_or_restricted_ip(ip_str: str) -> bool:
    """
    Check if an IP address belongs to private, loopback, link-local,
    reserved, or cloud metadata addresses (SSRF prevention).
    """
    clean_ip = ip_str.strip("[]")
    try:
        addr = ipaddress.ip_address(clean_ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or str(addr) in CLOUD_METADATA_IPS
        ):
            return True
        # Explicitly guard 0.0.0.0/8 and 100.64.0.0/10 (Carrier-Grade NAT)
        if addr.version == 4:
            first_octet = int(str(addr).split(".")[0])
            if first_octet == 0:
                return True
        return False
    except ValueError:
        return False


def validate_and_normalize_url(raw_url: str) -> dict[str, Any]:
    """
    Validate and normalize input URL.

    Returns a structured dictionary with:
      - is_valid (bool)
      - error (str | None)
      - raw_url (str)
      - normalized_url (str)
      - sanitized_url (str, with credentials/tokens redacted)
      - scheme (str)
      - domain (str, ascii/punycode)
      - unicode_domain (str, decoded IDN)
      - is_punycode (bool)
      - is_ip (bool)
      - ip_address (str | None)
      - is_private_ip (bool)
      - port (int | None)
      - path (str)
      - query (str)
      - has_credentials (bool)
      - ssrf_risk (bool)
    """
    if not raw_url or not isinstance(raw_url, str):
        return {
            "is_valid": False,
            "error": "URL cannot be empty.",
            "raw_url": str(raw_url or ""),
        }

    raw_url = raw_url.strip()

    if len(raw_url) > MAX_URL_LENGTH:
        return {
            "is_valid": False,
            "error": f"URL length ({len(raw_url)}) exceeds maximum limit of {MAX_URL_LENGTH} characters.",
            "raw_url": raw_url[:100] + "...",
        }

    # Check for missing scheme and auto-prefix http:// if it looks like a domain or URL
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        # Prevent javascript: or data: pseudo schemes masquerading without //
        lowered = raw_url.lower()
        for dangerous in DANGEROUS_SCHEMES:
            if lowered.startswith(f"{dangerous}:"):
                return {
                    "is_valid": False,
                    "error": f"Dangerous URI scheme '{dangerous}' is not allowed.",
                    "raw_url": raw_url,
                    "ssrf_risk": True,
                }
        parsed_target = "http://" + raw_url
    else:
        parsed_target = raw_url

    try:
        parsed = urlparse(parsed_target)
    except Exception as exc:
        return {
            "is_valid": False,
            "error": f"Malformed URL syntax: {exc}",
            "raw_url": raw_url,
        }

    scheme = (parsed.scheme or "").lower()
    if scheme in DANGEROUS_SCHEMES:
        return {
            "is_valid": False,
            "error": f"Dangerous URL scheme '{scheme}' is forbidden.",
            "raw_url": raw_url,
            "ssrf_risk": True,
        }

    if scheme not in ALLOWED_SCHEMES:
        return {
            "is_valid": False,
            "error": f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted.",
            "raw_url": raw_url,
        }

    # Extract user info / credentials
    has_credentials = bool(parsed.username or parsed.password)

    # Normalize hostname
    hostname = parsed.hostname
    if not hostname:
        return {
            "is_valid": False,
            "error": "URL missing a valid hostname or domain.",
            "raw_url": raw_url,
        }

    # Strip trailing dots from hostname (FQDN notation)
    hostname = hostname.rstrip(".").lower()

    # Localhost string detection
    is_localhost = hostname in {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}

    # IDN / Punycode handling
    is_punycode = "xn--" in hostname
    try:
        # Convert to ASCII (punycode)
        ascii_domain = hostname.encode("idna").decode("ascii")
        # Convert to Unicode for display
        unicode_domain = hostname.encode("utf-8").decode("idna")
    except Exception:
        ascii_domain = hostname
        unicode_domain = hostname

    # IP detection & SSRF check
    is_ip = is_ip_address(hostname)
    ip_addr: str | None = None
    is_private_ip = False
    ssrf_risk = False

    if is_ip:
        ip_addr = hostname.strip("[]")
        is_private_ip = is_private_or_restricted_ip(ip_addr)
        if is_private_ip:
            ssrf_risk = True

    if is_localhost:
        is_private_ip = True
        ssrf_risk = True

    # Port normalization
    port = parsed.port
    if port and port in DEFAULT_PORTS and DEFAULT_PORTS[port] == scheme:
        netloc_port = ""
    elif port:
        netloc_port = f":{port}"
    else:
        netloc_port = ""

    # Path normalization: collapse double slashes and ensure leading slash
    path = parsed.path or "/"
    path = re.sub(r"/+", "/", path)

    # Build normalized netloc (no credentials, normalized hostname and port)
    normalized_netloc = f"{ascii_domain}{netloc_port}"
    normalized_url = urlunparse((
        scheme,
        normalized_netloc,
        path,
        parsed.params,
        parsed.query,
        ""  # Exclude fragment from normalized URL for consistent scanning
    ))

    # Build sanitized URL for history/display (redact sensitive query tokens)
    sanitized_url = redact_sensitive_params(normalized_url)

    return {
        "is_valid": True,
        "error": None,
        "raw_url": raw_url,
        "normalized_url": normalized_url,
        "sanitized_url": sanitized_url,
        "scheme": scheme,
        "domain": ascii_domain,
        "unicode_domain": unicode_domain,
        "is_punycode": is_punycode,
        "is_ip": is_ip,
        "ip_address": ip_addr,
        "is_private_ip": is_private_ip,
        "is_localhost": is_localhost,
        "port": port,
        "path": path,
        "query": parsed.query,
        "has_credentials": has_credentials,
        "ssrf_risk": ssrf_risk,
    }


def redact_sensitive_params(url_str: str) -> str:
    """Redact sensitive query parameters (tokens, passwords, keys) from URL."""
    try:
        parsed = urlparse(url_str)
        if not parsed.query:
            return url_str

        params = parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_params = []
        for key, value in params:
            if key.lower() in SENSITIVE_PARAM_NAMES:
                sanitized_params.append((key, "[REDACTED]"))
            else:
                sanitized_params.append((key, value))

        new_query = urlencode(sanitized_params)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    except Exception:
        return url_str
