"""
KhmerShield-AI - Comprehensive URL & Phishing Intelligence Test Suite.

Tests all required scenarios with harmless simulated fixtures:
1. Valid HTTPS URL
2. Valid HTTP URL
3. Invalid / malformed URL
4. Missing scheme auto-prefix
5. Localhost URL rejection (SSRF)
6. Private IPv4 URL rejection (SSRF)
7. IPv6 URL handling
8. Punycode / IDN domain detection
9. Suspicious login & credential lure URL
10. URL with heavy percent-encoded parameters
11. Provider timeout resilience (mocked)
12. Provider API failure / error resilience (mocked)
13. Unknown reputation / unresolvable domain
14. Risk score boundaries and levels
15. Telegram bot scan command parsing and formatting
16. API response schema validation
"""

from __future__ import annotations

import unittest
from unittest.mock import patch
import requests

from intelligence.url_normalizer import validate_and_normalize_url, is_private_or_restricted_ip
from intelligence.domain_analyzer import analyze_domain
from intelligence.phishing_detector import analyze_phishing_indicators
from intelligence.reputation import check_dns, check_google_safe_browsing, check_virustotal
from intelligence.risk_scorer import calculate_url_risk
from intelligence.url_scanner import scan_url
from bot.telegram_bot import format_url_result
from api.schemas import URLScanResponse


class TestURLIntelligence(unittest.TestCase):

    # 1. Valid HTTPS URL
    def test_valid_https_url(self):
        norm = validate_and_normalize_url("https://example.com/about?lang=en")
        self.assertTrue(norm["is_valid"])
        self.assertEqual(norm["scheme"], "https")
        self.assertEqual(norm["domain"], "example.com")
        self.assertFalse(norm["ssrf_risk"])

    # 2. Valid HTTP URL
    def test_valid_http_url(self):
        norm = validate_and_normalize_url("http://example.org:80/index.html")
        self.assertTrue(norm["is_valid"])
        self.assertEqual(norm["scheme"], "http")
        self.assertEqual(norm["domain"], "example.org")

    # 3. Invalid URL / Malformed
    def test_invalid_url(self):
        norm = validate_and_normalize_url("javascript:alert(1)")
        self.assertFalse(norm["is_valid"])
        self.assertIn("Dangerous", norm["error"])

    # 4. Missing Scheme (Auto-prefix)
    def test_missing_scheme(self):
        norm = validate_and_normalize_url("safe-example.com/test")
        self.assertTrue(norm["is_valid"])
        self.assertEqual(norm["scheme"], "http")
        self.assertEqual(norm["domain"], "safe-example.com")

    # 5. Localhost URL (SSRF Prevention)
    def test_localhost_ssrf(self):
        norm = validate_and_normalize_url("http://localhost:8080/admin")
        self.assertTrue(norm["is_valid"])
        self.assertTrue(norm["ssrf_risk"])
        findings = analyze_phishing_indicators(norm)
        ssrf_flags = [f for f in findings if "SSRF" in f["finding"]]
        self.assertTrue(len(ssrf_flags) > 0)

    # 6. Private IP URL (SSRF Prevention)
    def test_private_ip_ssrf(self):
        self.assertTrue(is_private_or_restricted_ip("192.168.1.1"))
        self.assertTrue(is_private_or_restricted_ip("10.0.0.1"))
        self.assertTrue(is_private_or_restricted_ip("169.254.169.254"))  # Cloud metadata
        norm = validate_and_normalize_url("http://10.20.30.40/secret")
        self.assertTrue(norm["ssrf_risk"])

    # 7. IPv6 URL Handling
    def test_ipv6_url(self):
        norm = validate_and_normalize_url("http://[2606:4700:4700::1111]/dns-query")
        self.assertTrue(norm["is_valid"])
        self.assertTrue(norm["is_ip"])
        self.assertFalse(norm["ssrf_risk"])  # Cloudflare public DNS is not private

    # 8. Punycode / IDN Domain Detection
    def test_punycode_domain(self):
        norm = validate_and_normalize_url("https://xn--e1afmkfd.xn--p1ai")
        self.assertTrue(norm["is_valid"])
        self.assertTrue(norm["is_punycode"])
        domain_findings = analyze_domain(norm["domain"], is_ip=False, unicode_domain=norm.get("unicode_domain"))
        punycode_matches = [f for f in domain_findings if "Punycode" in f["finding"]]
        self.assertTrue(len(punycode_matches) > 0)

    # 9. Suspicious Login & Brand Impersonation Lure
    def test_suspicious_login_lure(self):
        norm = validate_and_normalize_url("https://aba-bank-login-verify.xyz/account/auth")
        domain_findings = analyze_domain(norm["domain"], is_ip=False)
        phishing_findings = analyze_phishing_indicators(norm)
        all_findings = domain_findings + phishing_findings

        # Must flag brand impersonation and login keywords
        brand_flags = [f for f in all_findings if "ABA Bank" in f["finding"]]
        login_flags = [f for f in all_findings if "Credential" in f["finding"] or "Harvesting" in f["finding"]]
        self.assertTrue(len(brand_flags) > 0)
        self.assertTrue(len(login_flags) > 0)

    # 10. Heavy Percent-Encoded Parameters
    def test_encoded_parameters(self):
        norm = validate_and_normalize_url("https://test.com/path?q=%20%2f%2e%3d%26%2b%23%25")
        findings = analyze_phishing_indicators(norm)
        encoding_flags = [f for f in findings if "Percent-Encoding" in f["finding"]]
        self.assertTrue(len(encoding_flags) > 0)

    # 11. Provider Timeout Resilience (Mocked)
    @patch("intelligence.reputation.GOOGLE_SAFE_BROWSING_API_KEY", "test_key_123")
    @patch("requests.post", side_effect=requests.Timeout)
    def test_provider_timeout(self, mock_post):
        gsb = check_google_safe_browsing("https://example.com")
        self.assertEqual(gsb["status"], "timeout")
        self.assertFalse(gsb["threat_detected"])

    # 12. Provider API Failure (Mocked)
    @patch("intelligence.reputation.VIRUSTOTAL_API_KEY", "test_key_123")
    @patch("requests.get", side_effect=requests.RequestException("Mocked connection reset"))
    def test_provider_failure(self, mock_get):
        vt = check_virustotal("https://example.com")
        self.assertEqual(vt["status"], "error")
        self.assertFalse(vt["threat_detected"])

    # 13. Unknown Reputation / Unresolvable Domain
    def test_unknown_reputation(self):
        dns = check_dns("this-domain-surely-does-not-exist-123456789.xyz")
        self.assertFalse(dns["has_dns"])
        risk = calculate_url_risk(
            findings=[],
            reputation={"dns": dns, "google_safe_browsing": {}, "virustotal": {}},
            is_valid=True
        )
        self.assertEqual(risk["verdict"], "UNKNOWN")

    # 14. Risk Score Boundaries
    def test_risk_score_boundaries(self):
        # Clean
        risk_clean = calculate_url_risk(findings=[], reputation={}, is_valid=True)
        self.assertEqual(risk_clean["level"], "LOW")
        self.assertEqual(risk_clean["verdict"], "NO_KNOWN_THREAT")

        # Medium
        med_findings = [{"finding": "Medium Heuristic", "severity": "medium", "score_contribution": 25}]
        risk_med = calculate_url_risk(findings=med_findings, reputation={}, is_valid=True)
        self.assertEqual(risk_med["level"], "MEDIUM")
        self.assertEqual(risk_med["verdict"], "SUSPICIOUS")

        # Critical
        crit_findings = [{"finding": "Critical Spoof", "severity": "critical", "score_contribution": 85}]
        risk_crit = calculate_url_risk(findings=crit_findings, reputation={}, is_valid=True)
        self.assertEqual(risk_crit["level"], "CRITICAL")
        self.assertEqual(risk_crit["verdict"], "MALICIOUS")

    # 15. Telegram URL Command Formatting
    def test_telegram_format_report(self):
        scan_result = scan_url("https://example.com")
        report = format_url_result(scan_result)
        self.assertIn("KHMERSHIELD URL SECURITY REPORT", report)
        self.assertIn("example.com", report)
        self.assertIn("Score:", report)

    # 16. API Response Schema Validation
    def test_api_response_schema(self):
        scan_result = scan_url("https://example.com")
        # Validate through Pydantic
        validated = URLScanResponse(**scan_result)
        self.assertEqual(validated.domain, "example.com")
        self.assertTrue(validated.scan_id.startswith("KS-URL-"))
        self.assertIn(validated.risk_level, {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
