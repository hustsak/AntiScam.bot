import re
import ipaddress
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)


def extract_urls(text: str) -> list[str]:
    return sorted(set(URL_PATTERN.findall(text)))


def extract_ips(text: str) -> list[str]:
    candidates = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    valid_ips = []

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            valid_ips.append(candidate)
        except ValueError:
            pass

    return sorted(set(valid_ips))


def extract_domains(text: str) -> list[str]:
    domains = set()

    for match in DOMAIN_PATTERN.findall(text):
        domain = match.lower().rstrip(".,;:!?")

        # Ignore obvious local/example values
        if domain in {
            "localhost.local",
            "example.com",
            "example.org",
            "example.net",
        }:
            continue

        domains.add(domain)

    return sorted(domains)


def extract_indicators(text: str) -> dict:
    urls = extract_urls(text)
    ips = extract_ips(text)
    domains = extract_domains(text)

    # Domains contained inside URLs are already known.
    for url in urls:
        try:
            hostname = urlparse(url).hostname
            if hostname and not re.match(
                r"^\d{1,3}(?:\.\d{1,3}){3}$",
                hostname
            ):
                domains.append(hostname.lower())
        except Exception:
            pass

    return {
        "urls": sorted(set(urls)),
        "domains": sorted(set(domains)),
        "ips": sorted(set(ips)),
    }