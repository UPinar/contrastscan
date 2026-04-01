"""Tests for hardening.py — server hardening recommendations engine"""

from conftest import make_scan_result
from hardening import generate_hardening


# === SSL/TLS recommendations ===

def test_ssl_error_recommends_install_cert():
    result = make_scan_result(ssl_error="connection refused")
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert len(ssl_recs) >= 1
    assert ssl_recs[0]["priority"] == "critical"
    assert "certbot" in str(ssl_recs[0]["commands"])


def test_deprecated_tls_recommends_upgrade():
    result = make_scan_result(tls_version="TLSv1.1")
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert any(r["priority"] == "high" for r in ssl_recs)
    assert any("TLSv1.2" in str(r["commands"]) for r in ssl_recs)


def test_tls12_suggests_13():
    result = make_scan_result(tls_version="TLSv1.2")
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert any("TLS 1.3" in r["title"] for r in ssl_recs)
    assert all(r["priority"] == "low" for r in ssl_recs)


def test_tls13_no_ssl_recommendation():
    result = make_scan_result(tls_version="TLSv1.3")
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert len(ssl_recs) == 0


def test_weak_cipher_recommends_upgrade():
    result = make_scan_result(cipher="DES-CBC3-SHA", cipher_score=2)
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert any("Cipher" in r["title"] for r in ssl_recs)


def test_cert_expiring_soon():
    result = make_scan_result(days_remaining=10, cert_valid=False)
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert any("Renew" in r["title"] for r in ssl_recs)


def test_cert_expired():
    result = make_scan_result(days_remaining=-5, cert_valid=False)
    recs = generate_hardening(result)
    ssl_recs = [r for r in recs if r["category"] == "SSL/TLS"]
    assert any(r["priority"] == "critical" for r in ssl_recs)
    assert any("Expired" in r["title"] for r in ssl_recs)


# === Header recommendations ===

def test_missing_headers_recommends_add():
    result = make_scan_result(headers_missing=["strict-transport-security", "content-security-policy"])
    recs = generate_hardening(result)
    hdr_recs = [r for r in recs if r["category"] == "Security Headers"]
    assert len(hdr_recs) == 1
    assert "(2)" in hdr_recs[0]["title"]
    assert "nginx" in hdr_recs[0]["commands"]
    assert "apache" in hdr_recs[0]["commands"]


def test_all_headers_present_no_recommendation():
    result = make_scan_result(headers_missing=[])
    recs = generate_hardening(result)
    hdr_recs = [r for r in recs if r["category"] == "Security Headers"]
    assert len(hdr_recs) == 0


def test_header_recommendation_has_diagram():
    result = make_scan_result(headers_missing=["strict-transport-security"])
    recs = generate_hardening(result)
    hdr_recs = [r for r in recs if r["category"] == "Security Headers"]
    assert hdr_recs[0].get("diagram")


def test_header_priority_escalation():
    """Missing HSTS (high) should make the overall rec high priority."""
    result = make_scan_result(headers_missing=["strict-transport-security"])
    recs = generate_hardening(result)
    hdr_recs = [r for r in recs if r["category"] == "Security Headers"]
    assert hdr_recs[0]["priority"] == "high"


def test_low_priority_headers_only():
    """Missing only low-priority headers."""
    result = make_scan_result(headers_missing=["referrer-policy", "permissions-policy"])
    recs = generate_hardening(result)
    hdr_recs = [r for r in recs if r["category"] == "Security Headers"]
    assert hdr_recs[0]["priority"] == "low"


# === Redirect recommendations ===

def test_no_redirect_recommends_fix():
    result = make_scan_result(redirects_to_https=False)
    recs = generate_hardening(result)
    redir_recs = [r for r in recs if r["category"] == "HTTP Redirect"]
    assert len(redir_recs) == 1
    assert redir_recs[0]["priority"] == "high"


def test_redirect_present_no_recommendation():
    result = make_scan_result(redirects_to_https=True)
    recs = generate_hardening(result)
    redir_recs = [r for r in recs if r["category"] == "HTTP Redirect"]
    assert len(redir_recs) == 0


# === Disclosure recommendations ===

def test_server_exposed_recommends_hide():
    result = make_scan_result(server_exposed=True, server_value="nginx/1.18")
    recs = generate_hardening(result)
    disc_recs = [r for r in recs if r["category"] == "Info Disclosure"]
    assert len(disc_recs) == 1
    assert "server_tokens off" in str(disc_recs[0]["commands"])


def test_nothing_exposed_no_recommendation():
    result = make_scan_result(server_exposed=False, powered_by_exposed=False)
    recs = generate_hardening(result)
    disc_recs = [r for r in recs if r["category"] == "Info Disclosure"]
    assert len(disc_recs) == 0


# === HTTP Methods recommendations ===

def test_trace_enabled_recommends_disable():
    result = make_scan_result(trace_enabled=True)
    recs = generate_hardening(result)
    meth_recs = [r for r in recs if r["category"] == "HTTP Methods"]
    assert len(meth_recs) == 1
    assert meth_recs[0]["priority"] == "high"


def test_put_delete_enabled():
    result = make_scan_result(put_enabled=True, delete_enabled=True)
    recs = generate_hardening(result)
    meth_recs = [r for r in recs if r["category"] == "HTTP Methods"]
    assert len(meth_recs) == 1
    assert "DELETE" in meth_recs[0]["title"]
    assert "PUT" in meth_recs[0]["title"]


def test_safe_methods_no_recommendation():
    result = make_scan_result(trace_enabled=False, delete_enabled=False, put_enabled=False)
    recs = generate_hardening(result)
    meth_recs = [r for r in recs if r["category"] == "HTTP Methods"]
    assert len(meth_recs) == 0


# === DNS recommendations ===

def test_missing_spf_dmarc_recommends_add():
    result = make_scan_result(spf=False, dmarc=False, dkim=True)
    recs = generate_hardening(result)
    dns_recs = [r for r in recs if r["category"] == "DNS Security"]
    assert len(dns_recs) == 1
    assert "SPF" in dns_recs[0]["title"]
    assert "DMARC" in dns_recs[0]["title"]
    assert dns_recs[0].get("diagram")


def test_all_dns_present_no_recommendation():
    result = make_scan_result(spf=True, dmarc=True, dkim=True)
    recs = generate_hardening(result)
    dns_recs = [r for r in recs if r["category"] == "DNS Security"]
    assert len(dns_recs) == 0


# === Cookie recommendations ===

def test_cookies_missing_flags():
    result = make_scan_result(cookies_found=3, all_secure=False, all_httponly=True, all_samesite=False)
    recs = generate_hardening(result)
    cookie_recs = [r for r in recs if r["category"] == "Cookie Security"]
    assert len(cookie_recs) == 1
    assert "Secure" in cookie_recs[0]["title"]
    assert "SameSite" in cookie_recs[0]["title"]


def test_no_cookies_no_recommendation():
    result = make_scan_result(cookies_found=0)
    recs = generate_hardening(result)
    cookie_recs = [r for r in recs if r["category"] == "Cookie Security"]
    assert len(cookie_recs) == 0


# === CORS recommendations ===

def test_cors_credentials_wildcard():
    result = make_scan_result(credentials_with_wildcard=True)
    recs = generate_hardening(result)
    cors_recs = [r for r in recs if r["category"] == "CORS"]
    assert len(cors_recs) == 1
    assert cors_recs[0]["priority"] == "critical"
    assert cors_recs[0].get("diagram")


def test_cors_reflects_origin():
    result = make_scan_result(reflects_origin=True)
    recs = generate_hardening(result)
    cors_recs = [r for r in recs if r["category"] == "CORS"]
    assert len(cors_recs) == 1
    assert cors_recs[0]["priority"] == "high"


def test_cors_safe_no_recommendation():
    result = make_scan_result(wildcard_origin=False, reflects_origin=False, credentials_with_wildcard=False)
    recs = generate_hardening(result)
    cors_recs = [r for r in recs if r["category"] == "CORS"]
    assert len(cors_recs) == 0


# === Kernel & Rate Limit recommendations (grade-based) ===

def test_low_grade_gets_kernel_recs():
    result = make_scan_result(ssl_error="no ssl", headers_missing=[
        "content-security-policy", "strict-transport-security",
        "x-content-type-options", "x-frame-options",
    ], redirects_to_https=False, spf=False, dmarc=False, dkim=False)
    result["grade"] = "F"
    result["total_score"] = 20
    recs = generate_hardening(result)
    kernel_recs = [r for r in recs if r["category"] == "Kernel Hardening"]
    assert len(kernel_recs) == 1
    assert "syncookies" in str(kernel_recs[0]["commands"])


def test_high_grade_no_kernel_recs():
    result = make_scan_result()
    result["grade"] = "A"
    result["total_score"] = 95
    recs = generate_hardening(result)
    kernel_recs = [r for r in recs if r["category"] == "Kernel Hardening"]
    assert len(kernel_recs) == 0


def test_low_grade_gets_rate_limit_recs():
    result = make_scan_result()
    result["grade"] = "D"
    recs = generate_hardening(result)
    rl_recs = [r for r in recs if r["category"] == "Rate Limiting"]
    assert len(rl_recs) == 1
    assert "limit_req" in str(rl_recs[0]["commands"])


# === Sorting ===

def test_recommendations_sorted_by_priority():
    result = make_scan_result(
        ssl_error="no ssl",
        headers_missing=["referrer-policy"],
        redirects_to_https=False,
    )
    result["grade"] = "F"
    recs = generate_hardening(result)
    priorities = [r["priority"] for r in recs]
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    numeric = [priority_order[p] for p in priorities]
    assert numeric == sorted(numeric)


# === Perfect score = no recommendations ===

def test_perfect_score_no_recommendations():
    result = make_scan_result()
    result["grade"] = "A"
    result["total_score"] = 100
    recs = generate_hardening(result)
    assert len(recs) == 0
