"""
test_new_features.py — tests for features:
  - Sitemap entries

Run: cd app && python -m pytest tests/test_new_features.py -v
"""

import copy

from db import init_db
from fastapi.testclient import TestClient
from main import app

# init test DB
init_db()

client = TestClient(app)

CSRF_HEADERS = {"Origin": "https://contrastcyber.com"}

# --- Mock helpers ---

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
    if domain in ("example.com", "google.com", "test1.com", "test2.com"):
        return "93.184.216.34"
    return None
