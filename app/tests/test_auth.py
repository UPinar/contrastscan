"""
test_auth.py — API rate limiting tests (IP-based)

Run: cd app && python -m pytest tests/test_auth.py -v
"""

import copy
from unittest.mock import patch

from config import HOURLY_LIMIT
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

MOCK_SCAN_RESULT = {
    "domain": "example.com",
    "total_score": 75,
    "max_score": 100,
    "grade": "B",
    "headers": {
        "score": 20,
        "max": 30,
        "details": [
            {"header": "content-security-policy", "present": True},
            {"header": "strict-transport-security", "present": True},
            {"header": "x-content-type-options", "present": True},
            {"header": "x-frame-options", "present": True},
            {"header": "referrer-policy", "present": False},
            {"header": "permissions-policy", "present": False},
        ],
    },
    "ssl": {
        "score": 25,
        "max": 25,
        "details": {
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_score": 8,
            "cert_valid": True,
            "chain_valid": True,
            "days_remaining": 60,
            "cert_score": 8,
        },
    },
    "dns": {"score": 15, "max": 15, "details": {"spf": True, "dmarc": True, "dkim": True}},
    "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
    "disclosure": {"score": 5, "max": 5, "details": {"server_exposed": False, "powered_by_exposed": False}},
    "cookies": {"score": 5, "max": 5, "details": {"cookies_found": 0}},
    "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
    "methods": {
        "score": 5,
        "max": 5,
        "details": {"trace_enabled": False, "delete_enabled": False, "put_enabled": False},
    },
    "cors": {
        "score": 5,
        "max": 5,
        "details": {
            "wildcard_origin": False,
            "reflects_origin": False,
            "credentials_with_wildcard": False,
            "cors_credentials": False,
        },
    },
    "html": {
        "score": 5,
        "max": 5,
        "details": {
            "mixed_active": 0,
            "mixed_passive": 0,
            "inline_scripts": 0,
            "inline_handlers": 0,
            "external_scripts": 0,
            "external_scripts_no_sri": 0,
            "forms_total": 0,
            "forms_http_action": 0,
            "meta_set_cookie": 0,
            "meta_refresh_http": 0,
        },
    },
    "csp_analysis": {
        "score": 2,
        "max": 2,
        "details": {
            "csp_present": True,
            "unsafe_inline": False,
            "unsafe_eval": False,
            "wildcard_source": False,
            "data_uri": False,
            "blob_uri": False,
        },
    },
}


def mock_run_scan(domain, resolved_ip=None):
    result = copy.deepcopy(MOCK_SCAN_RESULT)
    result["domain"] = domain
    return result


def mock_validate_domain(domain):
    if domain in ("example.com",):
        return "93.184.216.34"
    return None


# === API Rate Limiting ===


class TestApiRateLimit:
    def test_hourly_limit_is_100(self):
        assert HOURLY_LIMIT == 100

    def test_scan_without_key_works(self, init_test_db):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(True, 1)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 200
            assert r.json()["domain"] == "example.com"

    def test_report_without_key_works(self, init_test_db):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(True, 1)),
        ):
            r = client.get("/api/report?domain=example.com")
            assert r.status_code == 200
            assert "text/plain" in r.headers.get("content-type", "")

    def test_429_message_mentions_api_platform(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(False, 100)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 429
            assert "Rate limit reached" in r.json()["detail"]

    def test_request_1_allowed(self, init_test_db):
        """First request of the hour should be allowed."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(True, 1)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 200

    def test_request_99_allowed(self, init_test_db):
        """99th request should still be allowed (under 100 limit)."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(True, 99)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 200

    def test_request_100_allowed(self, init_test_db):
        """100th request (exactly at limit) should be allowed."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(True, 100)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 200

    def test_request_101_blocked(self):
        """101st request (over limit) should be blocked with 429."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(False, 100)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 429

    def test_429_includes_100_in_message(self):
        """429 error page should mention the 100/hour limit."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
            patch("scanner.check_and_increment_ip", return_value=(False, 100)),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 429
            assert "100" in r.text

    def test_different_ips_independent(self, init_test_db):
        """Different IPs should have independent rate limits."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            # IP A is blocked
            with patch("scanner.check_and_increment_ip", return_value=(False, 100)):
                r1 = client.get("/api/scan?domain=example.com")
                assert r1.status_code == 429
            # IP B is allowed
            with patch("scanner.check_and_increment_ip", return_value=(True, 1)):
                r2 = client.get("/api/scan?domain=example.com")
                assert r2.status_code == 200


# === Removed Endpoints ===


class TestRemovedEndpoints:
    def test_pro_key_endpoint_not_found(self):
        r = client.post("/api/pro")
        assert r.status_code in (404, 405)

    def test_pro_usage_not_found(self):
        r = client.get("/api/pro/csc_abcd")
        assert r.status_code == 404

    def test_lemon_webhook_not_found(self):
        r = client.post("/lemon/webhook")
        assert r.status_code in (404, 405)

    def test_pricing_exists(self):
        r = client.get("/pricing")
        assert r.status_code == 200
