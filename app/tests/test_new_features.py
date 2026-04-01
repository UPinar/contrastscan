"""
test_new_features.py — tests for features:
  - Bulk scan (page + API)
  - OpenAPI / ai-plugin.json
  - Sitemap entries

Run: cd app && python -m pytest tests/test_new_features.py -v
"""

import copy
import json
from unittest.mock import patch

from fastapi.testclient import TestClient
from main import app
from db import init_db

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
  "headers": {"score": 20, "max": 30, "details": [
    {"header": "content-security-policy", "present": True},
    {"header": "strict-transport-security", "present": True},
    {"header": "x-content-type-options", "present": True},
    {"header": "x-frame-options", "present": True},
    {"header": "referrer-policy", "present": False},
    {"header": "permissions-policy", "present": False},
  ]},
  "ssl": {"score": 25, "max": 25, "details": {
    "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
    "cipher_score": 8, "cert_valid": True, "chain_valid": True,
    "days_remaining": 60, "cert_score": 8,
  }},
  "dns": {"score": 15, "max": 15, "details": {"spf": True, "dmarc": True, "dkim": True}},
  "redirect": {"score": 10, "max": 10, "details": {"redirects_to_https": True}},
  "disclosure": {"score": 5, "max": 5, "details": {"server_exposed": False, "powered_by_exposed": False}},
  "cookies": {"score": 5, "max": 5, "details": {"cookies_found": 0}},
  "dnssec": {"score": 0, "max": 5, "details": {"dnssec_enabled": False}},
  "methods": {"score": 5, "max": 5, "details": {"trace_enabled": False, "delete_enabled": False, "put_enabled": False}},
  "cors": {"score": 5, "max": 5, "details": {"wildcard_origin": False, "reflects_origin": False, "credentials_with_wildcard": False}},
  "html": {"score": 5, "max": 5, "details": {"mixed_active": 0, "mixed_passive": 0, "inline_scripts": 0, "inline_handlers": 0, "external_scripts": 0, "external_scripts_no_sri": 0, "forms_total": 0, "forms_http_action": 0}},
  "csp_analysis": {"score": 2, "max": 2, "details": {"csp_present": True, "unsafe_inline": False, "unsafe_eval": False, "wildcard_source": False, "data_uri": False, "blob_uri": False}},
}


def mock_run_scan(domain, resolved_ip=None):
  result = copy.deepcopy(MOCK_SCAN_RESULT)
  result["domain"] = domain
  return result


def mock_validate_domain(domain):
  if domain in ("example.com", "google.com", "test1.com", "test2.com"):
    return "93.184.216.34"
  return None


# === OpenAPI ===

class TestOpenApi:
  def test_openapi_json_status(self):
    r = client.get("/openapi.json")
    assert r.status_code == 200

  def test_openapi_has_scan_domain_operation(self):
    r = client.get("/openapi.json")
    data = r.json()
    # Check that scan_domain operation_id exists somewhere in paths
    found = False
    for path_data in data.get("paths", {}).values():
      for method_data in path_data.values():
        if isinstance(method_data, dict) and method_data.get("operationId") == "scan_domain":
          found = True
          break
    assert found, "operation_id 'scan_domain' not found in openapi.json"


# === AI plugin ===

class TestAiPlugin:
  def test_ai_plugin_status(self):
    r = client.get("/.well-known/ai-plugin.json")
    assert r.status_code == 200

  def test_ai_plugin_has_schema_version(self):
    r = client.get("/.well-known/ai-plugin.json")
    data = r.json()
    assert data["schema_version"] == "v1"

  def test_ai_plugin_has_name(self):
    r = client.get("/.well-known/ai-plugin.json")
    data = r.json()
    assert "contrastscan" in data["name_for_model"]

  def test_ai_plugin_has_openapi_url(self):
    r = client.get("/.well-known/ai-plugin.json")
    data = r.json()
    assert data["api"]["url"] == "https://contrastcyber.com/openapi.json"


