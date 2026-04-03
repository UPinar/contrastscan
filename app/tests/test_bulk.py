"""
test_bulk.py — Pro bulk scan endpoint tests

Run: cd app && python -m pytest tests/test_bulk.py -v
"""

import copy
from unittest.mock import patch

import pytest
from config import BULK_MAX_DOMAINS, PRO_HOURLY_LIMIT
from db import create_api_key, get_db, revoke_api_key, validate_api_key
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
    if domain in ("invalid-domain-xyz.invalid",):
        return None
    return "93.184.216.34"


@pytest.fixture
def api_key():
    """Create a test API key and return the raw key."""
    return create_api_key("test@example.com", "pro")


@pytest.fixture
def api_key_header(api_key):
    """Return headers dict with valid API key."""
    return {"X-API-Key": api_key}


# === API Key Management ===


class TestApiKeyManagement:
    def test_create_key_format(self):
        key = create_api_key("test@example.com")
        assert key.startswith("cs_")
        assert len(key) == 51  # cs_ + 48 hex

    def test_validate_valid_key(self):
        key = create_api_key("test@example.com")
        data = validate_api_key(key)
        assert data is not None
        assert data["email"] == "test@example.com"
        assert data["tier"] == "pro"
        assert data["revoked"] == 0

    def test_validate_invalid_key(self):
        assert validate_api_key("cs_" + "a" * 48) is None

    def test_validate_revoked_key(self):
        key = create_api_key("test@example.com")
        data = validate_api_key(key)
        revoke_api_key(data["id"])
        assert validate_api_key(key) is None

    def test_key_hash_stored_not_raw(self):
        key = create_api_key("test@example.com")
        # Raw key should NOT be stored — only HMAC hash
        with get_db() as con:
            row = con.execute("SELECT key_hash FROM api_keys ORDER BY id DESC LIMIT 1").fetchone()
            assert row is not None
            assert row[0] != key  # not stored as plaintext
            assert len(row[0]) == 64  # SHA-256 hex digest length


# === Bulk Endpoint Auth ===


class TestBulkAuth:
    def test_no_api_key_returns_401(self):
        r = client.post("/api/v1/bulk", json={"domains": ["example.com"]})
        assert r.status_code == 401
        assert "Missing" in r.json()["detail"]

    def test_invalid_key_returns_401(self):
        r = client.post(
            "/api/v1/bulk",
            json={"domains": ["example.com"]},
            headers={"X-API-Key": "cs_" + "a" * 48},
        )
        assert r.status_code == 401

    def test_bad_format_key_returns_401(self):
        r = client.post(
            "/api/v1/bulk",
            json={"domains": ["example.com"]},
            headers={"X-API-Key": "bad_key"},
        )
        assert r.status_code == 401
        assert "format" in r.json()["detail"]

    def test_revoked_key_returns_401(self, api_key):
        data = validate_api_key(api_key)
        revoke_api_key(data["id"])
        r = client.post(
            "/api/v1/bulk",
            json={"domains": ["example.com"]},
            headers={"X-API-Key": api_key},
        )
        assert r.status_code == 401


# === Bulk Scan Endpoint ===


class TestBulkScan:
    def test_single_domain(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com"]},
                headers=api_key_header,
            )
            assert r.status_code == 200
            data = r.json()
            assert data["total"] == 1
            assert data["successful"] == 1
            assert data["results"][0]["grade"] == "B"
            assert data["results"][0]["domain"] == "example.com"

    def test_multiple_domains(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            domains = ["a.com", "b.com", "c.com"]
            r = client.post(
                "/api/v1/bulk",
                json={"domains": domains},
                headers=api_key_header,
            )
            assert r.status_code == 200
            data = r.json()
            assert data["total"] == 3
            assert data["successful"] == 3

    def test_one_failure_others_continue(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            domains = ["example.com", "invalid-domain-xyz.invalid", "b.com"]
            r = client.post(
                "/api/v1/bulk",
                json={"domains": domains},
                headers=api_key_header,
            )
            assert r.status_code == 200
            data = r.json()
            assert data["total"] == 3
            assert data["successful"] == 2
            failed = [d for d in data["results"] if "error" in d]
            assert len(failed) == 1

    def test_empty_domains_returns_422(self, api_key_header):
        r = client.post(
            "/api/v1/bulk",
            json={"domains": []},
            headers=api_key_header,
        )
        assert r.status_code == 422

    def test_too_many_domains_returns_422(self, api_key_header):
        domains = [f"d{i}.com" for i in range(BULK_MAX_DOMAINS + 1)]
        r = client.post(
            "/api/v1/bulk",
            json={"domains": domains},
            headers=api_key_header,
        )
        assert r.status_code == 422

    def test_max_domains_allowed(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            domains = [f"d{i}.com" for i in range(BULK_MAX_DOMAINS)]
            r = client.post(
                "/api/v1/bulk",
                json={"domains": domains},
                headers=api_key_header,
            )
            assert r.status_code == 200
            assert r.json()["total"] == BULK_MAX_DOMAINS

    def test_missing_body_returns_422(self, api_key_header):
        r = client.post("/api/v1/bulk", headers=api_key_header)
        assert r.status_code == 422

    def test_result_contains_scan_id(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com"]},
                headers=api_key_header,
            )
            result = r.json()["results"][0]
            assert "scan_id" in result
            assert len(result["scan_id"]) == 32

    def test_result_contains_score(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com"]},
                headers=api_key_header,
            )
            result = r.json()["results"][0]
            assert "score" in result
            assert result["score"] == 75


# === Pro Rate Limit ===


class TestProRateLimit:
    def test_config_values(self):
        assert PRO_HOURLY_LIMIT == 1000
        assert BULK_MAX_DOMAINS == 50

    def test_pro_rate_limit_blocks_at_limit(self, api_key):
        from db import check_pro_rate_limit, log_api_usage

        data = validate_api_key(api_key)
        # Simulate PRO_HOURLY_LIMIT usages
        for _ in range(PRO_HOURLY_LIMIT):
            log_api_usage(data["id"], "/api/v1/bulk", "test.com")
        allowed, usage = check_pro_rate_limit(data["id"])
        assert not allowed
        assert usage >= PRO_HOURLY_LIMIT

    def test_pro_rate_limit_checks_domain_count(self, api_key):
        """Rate limit should consider bulk domain count, not just 1."""
        from db import check_pro_rate_limit, log_api_usage

        data = validate_api_key(api_key)
        # Fill up to 980
        for _ in range(980):
            log_api_usage(data["id"], "/api/v1/bulk", "test.com")
        # Requesting 50 more should fail (980 + 50 > 1000)
        allowed, _usage = check_pro_rate_limit(data["id"], count=50)
        assert not allowed
        # Requesting 20 should succeed (980 + 20 = 1000)
        allowed, _usage = check_pro_rate_limit(data["id"], count=20)
        assert allowed

    def test_pro_rate_limit_429_response(self, api_key, api_key_header):
        with patch("auth.check_pro_rate_limit", return_value=(False, 1000)):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com"]},
                headers=api_key_header,
            )
            assert r.status_code == 429
            assert "1000" in r.json()["detail"]

    def test_bulk_rate_limit_considers_domain_count(self, api_key, api_key_header):
        """Endpoint should pass len(domains) to rate limit check."""
        from db import log_api_usage

        data = validate_api_key(api_key)
        for _ in range(990):
            log_api_usage(data["id"], "/api/v1/bulk", "test.com")
        # 990 + 20 domains > 1000 → 429
        r = client.post(
            "/api/v1/bulk",
            json={"domains": [f"d{i}.com" for i in range(20)]},
            headers=api_key_header,
        )
        assert r.status_code == 429


# === Dedup & Recon ===


class TestBulkDedup:
    def test_duplicate_domains_deduped(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com", "example.com", "example.com"]},
                headers=api_key_header,
            )
            assert r.status_code == 200
            data = r.json()
            # Should only scan once despite 3 duplicates
            assert data["total"] == 1
            assert data["successful"] == 1

    def test_duplicates_dont_waste_quota(self, api_key):
        """Duplicates should reserve quota for unique count only, not raw count."""
        from db import log_api_usage

        data = validate_api_key(api_key)
        # Fill 999 usage
        for _ in range(999):
            log_api_usage(data["id"], "/api/v1/bulk", "test.com")
        # 3 duplicates = 1 unique → should fit (999 + 1 = 1000)
        headers = {"X-API-Key": api_key}
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["a.com", "a.com", "a.com"]},
                headers=headers,
            )
            assert r.status_code == 200

    def test_empty_string_domains_rejected(self, api_key_header):
        r = client.post(
            "/api/v1/bulk",
            json={"domains": ["", "", ""]},
            headers=api_key_header,
        )
        assert r.status_code == 400
        assert "No valid domains" in r.json()["detail"]

    def test_case_insensitive_dedup(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["Example.COM", "example.com", "EXAMPLE.COM"]},
                headers=api_key_header,
            )
            assert r.status_code == 200
            assert r.json()["total"] == 1

    def test_no_resolved_ip_in_response(self, api_key_header):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/api/v1/bulk",
                json={"domains": ["example.com"]},
                headers=api_key_header,
            )
            result = r.json()["results"][0]["result"]
            assert "resolved_ip" not in result


# === Cleanup ===


@pytest.fixture(autouse=True)
def cleanup_api_keys():
    """Clean up API keys and usage after each test."""
    yield
    try:
        with get_db() as con:
            con.execute("DELETE FROM api_keys")
            con.execute("DELETE FROM api_usage")
    except Exception:
        pass
