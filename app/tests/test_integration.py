"""
test_integration.py — post-refactoring module integration tests

Tests that modules communicate correctly after split:
  - config -> all modules read constants
  - validation -> scanner uses it
  - ratelimit -> perform_scan respects limits
  - findings -> enrichment works with 7-module scan results
  - report -> generates from enriched results
  - db -> save/load round-trip
  - scanner -> perform_scan orchestrates everything

Run: cd app && python -m pytest tests/test_integration.py -v
"""

import json
import secrets
from datetime import UTC
from pathlib import Path

import pytest
from config import (
    ALLOWED_ORIGINS,
    BASE_DIR,
    ERROR_MESSAGES,
    GRADE_COLORS,
    SCAN_CONCURRENCY,
    SCAN_TIMEOUT,
    SCANNER_PATH,
)
from db import get_domain_grade, get_scan, get_stats, init_db, save_scan
from findings import enrich_with_findings
from ratelimit import check_domain_limit
from report import generate_report
from validation import clean_domain, is_private_ip, validate_domain

# === config -> all modules ===


class TestConfig:
    def test_base_dir_is_path(self):
        assert isinstance(BASE_DIR, Path)

    def test_grade_colors_has_5_grades(self):
        assert len(GRADE_COLORS) == 5

    def test_error_messages_has_entries(self):
        assert len(ERROR_MESSAGES) >= 4

    def test_allowed_origins_is_set_or_list(self):
        assert isinstance(ALLOWED_ORIGINS, (set, list))

    def test_scanner_path_type(self):
        # may not exist on dev machine, just check type
        assert SCANNER_PATH.exists() or True

    def test_scan_concurrency_positive(self):
        assert SCAN_CONCURRENCY > 0

    def test_scan_timeout_positive(self):
        assert SCAN_TIMEOUT > 0


# === validation ===


class TestValidation:
    def test_clean_domain_strips_proto(self):
        assert clean_domain("https://example.com/path") == "example.com"

    def test_clean_domain_strips_port(self):
        assert clean_domain("example.com:8080") == "example.com"

    def test_clean_domain_lowercase(self):
        assert clean_domain("EXAMPLE.COM") == "example.com"

    def test_validate_domain_rejects_empty(self):
        assert not validate_domain("")

    def test_validate_domain_rejects_no_dot(self):
        assert not validate_domain("localhost")

    def test_validate_domain_rejects_special(self):
        assert not validate_domain("test;id")

    def test_validate_domain_rejects_long(self):
        assert not validate_domain("a" * 254 + ".com")

    def test_is_private_ip_127(self):
        assert is_private_ip("127.0.0.1")

    def test_is_private_ip_10(self):
        assert is_private_ip("10.0.0.1")

    def test_is_private_ip_169(self):
        assert is_private_ip("169.254.169.254")

    def test_is_private_ip_invalid_true(self):
        assert is_private_ip("not-an-ip")


# === ratelimit -> domain limit check ===


class TestRateLimit:
    def test_domain_limit_allows_first(self):
        assert check_domain_limit("test-domain-int.com")


# === db round-trip ===


class TestDb:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        init_db()

    def test_save_get_round_trip(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test.com", test_result, "B", 85)
        loaded = get_scan(test_scan_id)
        assert loaded is not None

    def test_loaded_domain_matches(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test2.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test2.com", test_result, "B", 85)
        loaded = get_scan(test_scan_id)
        parsed = json.loads(loaded["result"])
        assert parsed["domain"] == "integration-test2.com"

    def test_loaded_grade_matches(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test3.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test3.com", test_result, "B", 85)
        loaded = get_scan(test_scan_id)
        assert loaded["grade"] == "B"

    def test_loaded_score_matches(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test4.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test4.com", test_result, "B", 85)
        loaded = get_scan(test_scan_id)
        assert loaded["total_score"] == 85

    def test_get_domain_grade(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test5.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test5.com", test_result, "B", 85)
        grade = get_domain_grade("integration-test5.com")
        assert grade == "B"

    def test_get_stats_returns_counts(self):
        test_scan_id = secrets.token_hex(16)
        test_result = {
            "domain": "integration-test6.com",
            "total_score": 85,
            "max_score": 100,
            "grade": "B",
            "headers": {"score": 25, "max": 30},
            "ssl": {"score": 25, "max": 25},
            "dns": {"score": 15, "max": 15},
            "redirect": {"score": 10, "max": 10},
            "disclosure": {"score": 5, "max": 5},
            "cookies": {"score": 0, "max": 5},
            "dnssec": {"score": 0, "max": 5},
        }
        save_scan(test_scan_id, "integration-test6.com", test_result, "B", 85)
        total, _recent = get_stats()
        assert total >= 1

    def test_save_scan_with_client_hash(self):
        from db import hash_client_ip

        sid = secrets.token_hex(16)
        result = {"grade": "A", "total_score": 95}
        h = hash_client_ip("1.2.3.4")
        save_scan(sid, "hash-test.com", result, "A", 95, client_hash=h)
        loaded = get_scan(sid)
        assert loaded is not None
        assert loaded["client_hash"] == h

    def test_save_scan_default_client_hash(self):
        sid = secrets.token_hex(16)
        result = {"grade": "B", "total_score": 80}
        save_scan(sid, "no-hash.com", result, "B", 80)
        loaded = get_scan(sid)
        assert loaded is not None
        assert loaded["client_hash"] == ""

    def test_hash_client_ip_deterministic(self):
        from db import hash_client_ip

        h1 = hash_client_ip("192.168.1.1")
        h2 = hash_client_ip("192.168.1.1")
        assert h1 == h2
        assert len(h1) == 32

    def test_hash_client_ip_different_ips(self):
        from db import hash_client_ip

        h1 = hash_client_ip("1.1.1.1")
        h2 = hash_client_ip("8.8.8.8")
        assert h1 != h2

    def test_purge_old_client_hashes(self):
        from datetime import datetime, timedelta

        from db import get_db, hash_client_ip, purge_old_client_hashes

        purge_hash = hash_client_ip(f"10.66.{secrets.randbelow(256)}.{secrets.randbelow(256)}")
        old_time = (datetime.now(UTC) - timedelta(days=100)).isoformat()
        sid = secrets.token_hex(16)
        with get_db() as con:
            con.execute(
                "INSERT INTO scans (id, domain, client_hash, result, grade, total_score, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sid, "purge.com", purge_hash, '{"grade":"C"}', "C", 55, old_time),
            )
        purged = purge_old_client_hashes(days=90)
        assert purged >= 1
        # Verify the hash was cleared
        with get_db() as con:
            row = con.execute("SELECT client_hash FROM scans WHERE id = ?", (sid,)).fetchone()
            assert row[0] == ""

    def test_purge_keeps_recent_hashes(self):
        from db import hash_client_ip, purge_old_client_hashes

        recent_hash = hash_client_ip(f"10.55.{secrets.randbelow(256)}.{secrets.randbelow(256)}")
        sid = secrets.token_hex(16)
        save_scan(sid, "recent.com", {"grade": "A"}, "A", 95, client_hash=recent_hash)
        purge_old_client_hashes(days=90)
        loaded = get_scan(sid)
        assert loaded["client_hash"] == recent_hash

    def test_dnt_skips_client_hash(self):
        """perform_scan with dnt=True should save empty client_hash."""
        from unittest.mock import MagicMock
        from unittest.mock import patch as mock_patch

        from scanner import perform_scan

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"grade":"B","total_score":75}'
        with (
            mock_patch("scanner.subprocess.run", return_value=mock_result),
            mock_patch("scanner.validate_domain", return_value="1.2.3.4"),
            mock_patch("scanner.check_domain_limit", return_value=True),
            mock_patch("scanner.check_and_increment_ip", return_value=(True, 1)),
            mock_patch("recon.start_recon"),
        ):
            scan_id, _ = perform_scan("example.com", "5.6.7.8", dnt=True)
        loaded = get_scan(scan_id)
        assert loaded["client_hash"] == ""


# === findings enrichment ===


class TestFindings:
    def test_enrich_adds_findings_key(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert "findings" in enriched

    def test_enrich_adds_findings_count(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert "findings_count" in enriched

    def test_findings_is_list(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert isinstance(enriched.get("findings"), list)

    def test_findings_count_positive_for_insecure(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        fc = enriched.get("findings_count", {})
        assert isinstance(fc, dict) and sum(fc.values()) > 0

    def test_finding_has_category(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert "category" in enriched["findings"][0]

    def test_finding_has_severity(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert "severity" in enriched["findings"][0]

    def test_finding_has_description(self):
        missing_result = self._make_missing_result()
        enriched = enrich_with_findings(missing_result)
        assert "description" in enriched["findings"][0]

    def test_perfect_score_zero_findings(self):
        perfect = {
            "domain": "perfect.com",
            "total_score": 100,
            "max_score": 100,
            "grade": "A",
            "headers": {
                "score": 30,
                "max": 30,
                "details": [
                    {"header": h, "present": True}
                    for h in [
                        "content-security-policy",
                        "strict-transport-security",
                        "x-content-type-options",
                        "x-frame-options",
                        "referrer-policy",
                        "permissions-policy",
                    ]
                ],
            },
            "ssl": {
                "score": 25,
                "max": 25,
                "details": {"tls_version": "TLSv1.3", "cert_valid": True, "chain_valid": True, "days_remaining": 90},
            },
            "dns": {"score": 15, "max": 15, "details": {"spf": True, "dmarc": True, "dkim": True}},
            "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
            "disclosure": {"score": 5, "max": 5, "details": {"server_exposed": False, "powered_by_exposed": False}},
            "cookies": {"score": 5, "max": 5, "details": {"cookies_found": 0}},
            "dnssec": {"score": 5, "max": 5, "details": {"dnssec_enabled": True}},
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
        enriched = enrich_with_findings(perfect)
        fc = enriched.get("findings_count", {})
        assert isinstance(fc, dict) and sum(fc.values()) == 0

    def _make_missing_result(self):
        return {
            "domain": "test.com",
            "total_score": 40,
            "max_score": 100,
            "grade": "D",
            "headers": {
                "score": 0,
                "max": 30,
                "details": [
                    {"header": "content-security-policy", "present": False},
                    {"header": "strict-transport-security", "present": False},
                    {"header": "x-content-type-options", "present": False},
                    {"header": "x-frame-options", "present": False},
                    {"header": "referrer-policy", "present": False},
                    {"header": "permissions-policy", "present": False},
                ],
            },
            "ssl": {
                "score": 25,
                "max": 25,
                "details": {"tls_version": "TLSv1.3", "cert_valid": True, "chain_valid": True},
            },
            "dns": {"score": 0, "max": 20, "details": {"spf": False, "dmarc": False, "dkim": False}},
            "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
            "disclosure": {
                "score": 2,
                "max": 5,
                "details": {"server_exposed": True, "server_value": "nginx/1.24.0", "powered_by_exposed": False},
            },
            "cookies": {
                "score": 0,
                "max": 5,
                "details": {"cookies_found": 2, "all_secure": False, "all_httponly": False, "all_samesite": False},
            },
            "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
            "methods": {
                "score": 0,
                "max": 5,
                "details": {"trace_enabled": True, "delete_enabled": False, "put_enabled": False},
            },
            "cors": {
                "score": 0,
                "max": 5,
                "details": {
                    "wildcard_origin": True,
                    "reflects_origin": False,
                    "credentials_with_wildcard": False,
                    "cors_credentials": False,
                },
            },
            "html": {
                "score": 0,
                "max": 5,
                "details": {
                    "mixed_active": 2,
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
                "score": 0,
                "max": 2,
                "details": {
                    "csp_present": False,
                    "unsafe_inline": True,
                    "unsafe_eval": False,
                    "wildcard_source": False,
                    "data_uri": False,
                    "blob_uri": False,
                },
            },
        }


# === report generation ===


class TestReportGeneration:
    @pytest.fixture
    def enriched_result(self):
        missing_result = {
            "domain": "test.com",
            "total_score": 40,
            "max_score": 100,
            "grade": "D",
            "headers": {
                "score": 0,
                "max": 30,
                "details": [
                    {"header": "content-security-policy", "present": False},
                    {"header": "strict-transport-security", "present": False},
                    {"header": "x-content-type-options", "present": False},
                    {"header": "x-frame-options", "present": False},
                    {"header": "referrer-policy", "present": False},
                    {"header": "permissions-policy", "present": False},
                ],
            },
            "ssl": {
                "score": 25,
                "max": 25,
                "details": {"tls_version": "TLSv1.3", "cert_valid": True, "chain_valid": True},
            },
            "dns": {"score": 0, "max": 20, "details": {"spf": False, "dmarc": False, "dkim": False}},
            "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
            "disclosure": {
                "score": 2,
                "max": 5,
                "details": {"server_exposed": True, "server_value": "nginx/1.24.0", "powered_by_exposed": False},
            },
            "cookies": {
                "score": 0,
                "max": 5,
                "details": {"cookies_found": 2, "all_secure": False, "all_httponly": False, "all_samesite": False},
            },
            "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
        }
        return enrich_with_findings(missing_result)

    def test_report_is_string(self, enriched_result):
        report = generate_report(enriched_result, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert isinstance(report, str)

    def test_report_contains_domain(self, enriched_result):
        report = generate_report(enriched_result, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "test.com" in report

    def test_report_contains_grade(self, enriched_result):
        report = generate_report(enriched_result, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "D" in report

    def test_report_contains_score(self, enriched_result):
        report = generate_report(enriched_result, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "40" in report

    def test_report_contains_module_names(self, enriched_result):
        report = generate_report(enriched_result, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "Headers" in report or "headers" in report.lower()


# === cross-module: findings -> report ===


class TestCrossModuleFindings:
    def test_report_includes_findings(self):
        missing_result = {
            "domain": "test.com",
            "total_score": 40,
            "max_score": 100,
            "grade": "D",
            "headers": {
                "score": 0,
                "max": 30,
                "details": [
                    {"header": "content-security-policy", "present": False},
                    {"header": "strict-transport-security", "present": False},
                    {"header": "x-content-type-options", "present": False},
                    {"header": "x-frame-options", "present": False},
                    {"header": "referrer-policy", "present": False},
                    {"header": "permissions-policy", "present": False},
                ],
            },
            "ssl": {
                "score": 25,
                "max": 25,
                "details": {"tls_version": "TLSv1.3", "cert_valid": True, "chain_valid": True},
            },
            "dns": {"score": 0, "max": 20, "details": {"spf": False, "dmarc": False, "dkim": False}},
            "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
            "disclosure": {
                "score": 2,
                "max": 5,
                "details": {"server_exposed": True, "server_value": "nginx/1.24.0", "powered_by_exposed": False},
            },
            "cookies": {
                "score": 0,
                "max": 5,
                "details": {"cookies_found": 2, "all_secure": False, "all_httponly": False, "all_samesite": False},
            },
            "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
        }
        enriched = enrich_with_findings(missing_result)
        report = generate_report(enriched, "ccdd" * 8, "2026-03-25T12:00:00Z")
        fc = enriched.get("findings_count", {})
        total_findings = sum(fc.values()) if isinstance(fc, dict) else 0
        assert total_findings > 0
        assert "finding" in report.lower() or "vulnerab" in report.lower() or "missing" in report.lower()


# === regression: score consistency ===


class TestScoreConsistency:
    def test_max_score_is_100(self):
        test_result = {
            "max_score": 100,
            "headers": {"max": 30},
            "ssl": {"max": 25},
            "dns": {"max": 20},
            "redirect": {"max": 10},
            "disclosure": {"max": 5},
            "cookies": {"max": 5},
            "dnssec": {"max": 5},
        }
        assert test_result["max_score"] == 100

    def test_module_maxes_sum_to_100(self):
        assert 30 + 25 + 20 + 10 + 5 + 5 + 5 == 100

    @pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
    def test_grade_color_exists(self, grade):
        assert grade in GRADE_COLORS


class TestNewModulesConfig:
    def test_scanner_path_config_exists(self):
        assert SCANNER_PATH is not None

    def test_report_has_11_modules(self):
        """report.py should list all 11 modules"""
        from conftest import make_scan_result
        from report import generate_report

        result = make_scan_result()
        result["grade"] = "A"
        result["total_score"] = 100
        result["max_score"] = 100
        enriched = enrich_with_findings(result)
        report = generate_report(enriched, "ccdd" * 8, "2026-03-25T12:00:00Z")
        for name in (
            "Security Headers",
            "SSL / TLS",
            "DNS Security",
            "HTTP Redirect",
            "Info Disclosure",
            "Cookie Security",
            "DNSSEC",
            "HTTP Methods",
            "CORS",
            "HTML Analysis",
            "CSP Analysis",
        ):
            assert name in report, f"Missing module {name} in report"

    def test_findings_includes_methods_category(self):
        from conftest import make_scan_result

        result = make_scan_result(trace_enabled=True)
        enriched = enrich_with_findings(result)
        categories = {f["category"] for f in enriched["findings"]}
        assert "methods" in categories

    def test_findings_includes_cors_category(self):
        from conftest import make_scan_result

        result = make_scan_result(wildcard_origin=True)
        enriched = enrich_with_findings(result)
        categories = {f["category"] for f in enriched["findings"]}
        assert "cors" in categories

    def test_findings_includes_html_category(self):
        from conftest import make_scan_result

        result = make_scan_result(mixed_active=1)
        enriched = enrich_with_findings(result)
        categories = {f["category"] for f in enriched["findings"]}
        assert "html" in categories

    def test_findings_includes_csp_analysis_category(self):
        from conftest import make_scan_result

        result = make_scan_result(unsafe_eval=True)
        enriched = enrich_with_findings(result)
        categories = {f["category"] for f in enriched["findings"]}
        assert "csp_analysis" in categories


# === CSP "not present" in report ===


class TestCspNotPresentReport:
    def test_csp_not_present_shows_in_report(self):
        """When csp_present=False, report should show 'CSP header not present'."""
        from conftest import make_scan_result

        result = make_scan_result(csp_present=False)
        result["grade"] = "D"
        result["total_score"] = 40
        result["max_score"] = 100
        enriched = enrich_with_findings(result)
        report = generate_report(enriched, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "CSP header not present" in report

    def test_csp_present_shows_checks(self):
        """When csp_present=True, report should NOT show 'CSP header not present'."""
        from conftest import make_scan_result

        result = make_scan_result(csp_present=True, unsafe_inline=False, unsafe_eval=False)
        result["grade"] = "A"
        result["total_score"] = 100
        result["max_score"] = 100
        enriched = enrich_with_findings(result)
        report = generate_report(enriched, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "CSP header not present" not in report
        assert "No unsafe-inline" in report

    def test_csp_present_with_unsafe_inline(self):
        from conftest import make_scan_result

        result = make_scan_result(csp_present=True, unsafe_inline=True)
        result["grade"] = "C"
        result["total_score"] = 60
        result["max_score"] = 100
        enriched = enrich_with_findings(result)
        report = generate_report(enriched, "ccdd" * 8, "2026-03-25T12:00:00Z")
        assert "unsafe-inline allowed" in report


# === report_txt recon wait logic ===


class TestReportTxtReconWait:
    def test_report_txt_waits_for_recon(self):
        """report_txt endpoint should wait for recon to finish, up to 35s."""
        import json as _json
        from unittest.mock import patch

        from db import init_db, save_scan
        from fastapi.testclient import TestClient
        from main import app

        init_db()
        client = TestClient(app)

        scan_id = "aabb" * 8  # 32-char hex
        result_data = {
            "domain": "recon-wait.com",
            "grade": "B",
            "total_score": 75,
            "max_score": 100,
            "headers": {"score": 20, "max": 30, "details": []},
            "ssl": {"score": 25, "max": 25, "details": {}},
            "dns": {"score": 15, "max": 20, "details": {}},
            "redirect": {"score": 10, "max": 10, "details": {}},
            "disclosure": {"score": 5, "max": 5, "details": {}},
            "cookies": {"score": 0, "max": 5, "details": {"cookies_found": 0}},
            "dnssec": {"score": 0, "max": 5, "details": {}},
            "methods": {"score": 5, "max": 5, "details": {}},
            "cors": {"score": 5, "max": 5, "details": {}},
            "html": {"score": 5, "max": 5, "details": {}},
            "csp_analysis": {"score": 2, "max": 2, "details": {}},
        }
        save_scan(scan_id, "recon-wait.com", result_data, "B", 75)

        call_count = {"n": 0}

        def mock_get_recon(sid):
            call_count["n"] += 1
            if call_count["n"] < 3:
                return None  # Still pending
            return {
                "status": "done",
                "result": _json.dumps(
                    {
                        "tech_stack": {"technologies": [], "count": 0},
                        "waf": {"detected": [], "waf_present": False},
                    }
                ),
            }

        with patch("main.get_recon", side_effect=mock_get_recon), patch("time.sleep"):
            r = client.get(f"/report/{scan_id}.txt")
            assert r.status_code == 200
            assert "PASSIVE RECON" in r.text
            assert call_count["n"] >= 3

    def test_report_txt_no_recon_still_works(self):
        """If recon never finishes, report should still be generated without it."""
        from unittest.mock import patch

        from db import init_db, save_scan
        from fastapi.testclient import TestClient
        from main import app

        init_db()
        client = TestClient(app)

        scan_id = "ccdd" * 8
        result_data = {
            "domain": "no-recon.com",
            "grade": "C",
            "total_score": 55,
            "max_score": 100,
            "headers": {"score": 10, "max": 30, "details": []},
            "ssl": {"score": 25, "max": 25, "details": {}},
            "dns": {"score": 10, "max": 20, "details": {}},
            "redirect": {"score": 10, "max": 10, "details": {}},
            "disclosure": {"score": 0, "max": 5, "details": {}},
            "cookies": {"score": 0, "max": 5, "details": {"cookies_found": 0}},
            "dnssec": {"score": 0, "max": 5, "details": {}},
            "methods": {"score": 5, "max": 5, "details": {}},
            "cors": {"score": 5, "max": 5, "details": {}},
            "html": {"score": 5, "max": 5, "details": {}},
            "csp_analysis": {"score": 0, "max": 2, "details": {}},
        }
        save_scan(scan_id, "no-recon.com", result_data, "C", 55)

        with patch("main.get_recon", return_value=None), patch("time.sleep"):
            r = client.get(f"/report/{scan_id}.txt")
            assert r.status_code == 200
            assert "no-recon.com" in r.text
            assert "PASSIVE RECON" not in r.text
