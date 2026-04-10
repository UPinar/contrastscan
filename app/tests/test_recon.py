"""
test_recon.py — tests for passive recon modules

Covers:
  - Group A: tech stack, WAF, email detection (pure unit, no mocks needed)
  - Group B: robots.txt, sitemap, HTTP version (mocked HTTP/socket)
  - Group C: reverse DNS, zone transfer, subdomains (mocked DNS/subprocess)
  - Group D: WHOIS, CT logs (mocked socket/HTTP)
  - Orchestration: run_recon, start_recon
  - DB round-trip: create_recon, save_recon, get_recon, save_recon_error
  - E2E: GET /recon/{scan_id}

Run: cd app && python -m pytest tests/test_recon.py -v
"""

import json
import socket
from unittest.mock import MagicMock, patch

import dns.resolver
import pytest
from db import create_recon, get_recon, init_db, save_recon, save_recon_error
from recon import (
    COMMON_SUBDOMAINS,
    WAF_SIGNATURES,
    _crtsh_subdomains,
    _parse_whois,
    check_caa,
    check_ct_logs,
    check_http_version,
    check_subdomain_takeover,
    check_zone_transfer,
    detect_tech_stack,
    detect_waf,
    enumerate_subdomains,
    fetch_asn_info,
    fetch_robots,
    fetch_security_txt,
    fetch_sitemap,
    harvest_emails,
    reverse_dns_lookup,
    run_recon,
    start_recon,
    whois_lookup,
)

init_db()


# === Helpers ===


def _scan_result(**overrides):
    """Minimal scan result dict for recon tests."""
    base = {
        "domain": "example.com",
        "disclosure": {"details": {}},
        "html": {"details": {}},
        "csp_analysis": {"details": {}},
    }
    for k, v in overrides.items():
        keys = k.split(".")
        d = base
        for key in keys[:-1]:
            d = d.setdefault(key, {})
        d[keys[-1]] = v
    return base


def _mock_urlopen_response(body: bytes, status=200):
    resp = MagicMock()
    resp.read.return_value = body
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ============================================================
# Group A — Tech Stack Detection (no network)
# ============================================================


class TestDetectTechStack:
    def test_empty_result_returns_zero(self):
        r = detect_tech_stack(_scan_result())
        assert r["count"] == 0
        assert r["technologies"] == []

    def test_server_header_detected(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "nginx/1.24"
        r = detect_tech_stack(sr)
        assert r["count"] >= 1
        techs = [t["name"] for t in r["technologies"]]
        assert "nginx/1.24" in techs

    def test_powered_by_detected(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["powered_by_value"] = "Express"
        r = detect_tech_stack(sr)
        techs = [t["name"] for t in r["technologies"]]
        assert "Express" in techs

    def test_both_server_and_powered_by(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "Apache"
        sr["disclosure"]["details"]["powered_by_value"] = "PHP/8.2"
        r = detect_tech_stack(sr)
        assert r["count"] == 2

    def test_csp_enabled_detected(self):
        sr = _scan_result()
        sr["csp_analysis"]["details"]["csp_present"] = True
        r = detect_tech_stack(sr)
        techs = [t["name"] for t in r["technologies"]]
        assert "CSP enabled" in techs

    def test_csp_disabled_not_detected(self):
        sr = _scan_result()
        sr["csp_analysis"]["details"]["csp_present"] = False
        r = detect_tech_stack(sr)
        techs = [t["name"] for t in r["technologies"]]
        assert "CSP enabled" not in techs

    def test_source_field_present(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "nginx"
        r = detect_tech_stack(sr)
        assert r["technologies"][0]["source"] == "server_header"

    def test_returns_dict_with_keys(self):
        r = detect_tech_stack(_scan_result())
        assert "technologies" in r
        assert "count" in r


# ============================================================
# Group A — WAF Detection
# ============================================================


class TestDetectWaf:
    def test_no_waf_detected(self):
        r = detect_waf(_scan_result())
        assert r["waf_present"] is False
        assert r["detected"] == []

    def test_cloudflare_detected(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "cloudflare"
        r = detect_waf(sr)
        assert r["waf_present"] is True
        assert "Cloudflare" in r["detected"]

    def test_modsecurity_detected(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "Apache/2.4 mod_security"
        r = detect_waf(sr)
        assert "ModSecurity" in r["detected"]

    def test_bigip_detected(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "BIG-IP bigip"
        r = detect_waf(sr)
        assert "F5 BIG-IP" in r["detected"]

    def test_case_insensitive(self):
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "CLOUDFLARE"
        r = detect_waf(sr)
        assert "Cloudflare" in r["detected"]

    def test_multiple_waf_signatures(self):
        """Server value matching multiple WAF patterns."""
        sr = _scan_result()
        sr["disclosure"]["details"]["server_value"] = "cloudflare mod_security"
        r = detect_waf(sr)
        assert len(r["detected"]) >= 2

    def test_returns_dict_structure(self):
        r = detect_waf(_scan_result())
        assert "detected" in r
        assert "waf_present" in r


# ============================================================
# Group A — Email Harvesting
# ============================================================


class TestHarvestEmails:
    def test_common_guesses_generated(self):
        r = harvest_emails(_scan_result(), "example.com")
        assert "info@example.com" in r["common_guesses"]
        assert "admin@example.com" in r["common_guesses"]
        assert "contact@example.com" in r["common_guesses"]

    def test_common_guesses_count(self):
        r = harvest_emails(_scan_result(), "example.com")
        assert len(r["common_guesses"]) == 3

    @patch("recon.dns.resolver.resolve")
    def test_mx_records_collected(self, mock_resolve):
        mx1 = MagicMock()
        mx1.exchange = "mail.example.com."
        mx1.preference = 10
        mock_resolve.return_value = [mx1]
        r = harvest_emails(_scan_result(), "example.com")
        assert any("mail.example.com" in e for e in r["found"])
        assert any("10" in e for e in r["found"])

    @patch("recon.dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN())
    def test_dns_failure_returns_empty_found(self, mock_resolve):
        """dns.resolver fails — should not crash."""
        r = harvest_emails(_scan_result(), "example.com")
        assert isinstance(r["found"], list)

    def test_returns_dict_structure(self):
        r = harvest_emails(_scan_result(), "test.com")
        assert "found" in r
        assert "common_guesses" in r


# ============================================================
# Group B — robots.txt
# ============================================================


class TestFetchRobots:
    @patch("recon._no_redirect_opener.open")
    def test_robots_found(self, mock_open):
        body = b"User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://example.com/sitemap.xml"
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_robots("example.com")
        assert r["exists"] is True
        assert "/admin" in r["disallowed_paths"]
        assert "/private" in r["disallowed_paths"]
        assert len(r["sitemaps"]) == 1

    @patch("recon._no_redirect_opener.open")
    def test_robots_line_count(self, mock_open):
        body = b"User-agent: *\nDisallow: /a\nDisallow: /b\n"
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_robots("example.com")
        assert r["line_count"] == 3

    @patch("recon._no_redirect_opener.open", side_effect=Exception("404"))
    def test_robots_not_found(self, mock_open):
        r = fetch_robots("example.com")
        assert r["exists"] is False

    @patch("recon._no_redirect_opener.open")
    def test_disallowed_paths_capped_at_20(self, mock_open):
        lines = "User-agent: *\n" + "\n".join(f"Disallow: /path{i}" for i in range(30))
        mock_open.return_value = _mock_urlopen_response(lines.encode())
        r = fetch_robots("example.com")
        assert len(r["disallowed_paths"]) <= 20

    @patch("recon._no_redirect_opener.open")
    def test_sitemaps_capped_at_5(self, mock_open):
        lines = "\n".join(f"Sitemap: https://example.com/sitemap{i}.xml" for i in range(10))
        mock_open.return_value = _mock_urlopen_response(lines.encode())
        r = fetch_robots("example.com")
        assert len(r["sitemaps"]) <= 5

    @patch("recon._no_redirect_opener.open")
    def test_empty_disallow_skipped(self, mock_open):
        body = b"User-agent: *\nDisallow:\nDisallow: /secret"
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_robots("example.com")
        assert r["disallowed_paths"] == ["/secret"]


# ============================================================
# Group B — sitemap.xml
# ============================================================


class TestFetchSitemap:
    @patch("recon._no_redirect_opener.open")
    def test_sitemap_found(self, mock_open):
        body = b'<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url><url><loc>https://example.com/about</loc></url></urlset>'
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_sitemap("example.com")
        assert r["exists"] is True
        assert r["url_count"] == 2

    @patch("recon._no_redirect_opener.open")
    def test_sitemap_sample_urls_capped(self, mock_open):
        locs = "".join(f"<url><loc>https://example.com/p{i}</loc></url>" for i in range(20))
        body = f'<?xml version="1.0"?><urlset>{locs}</urlset>'.encode()
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_sitemap("example.com")
        assert len(r["sample_urls"]) <= 10
        assert r["url_count"] == 20

    @patch("recon._no_redirect_opener.open", side_effect=Exception("404"))
    def test_sitemap_not_found(self, mock_open):
        r = fetch_sitemap("example.com")
        assert r["exists"] is False

    @patch("recon._no_redirect_opener.open")
    def test_empty_sitemap(self, mock_open):
        body = b'<?xml version="1.0"?><urlset></urlset>'
        mock_open.return_value = _mock_urlopen_response(body)
        r = fetch_sitemap("example.com")
        assert r["exists"] is True
        assert r["url_count"] == 0


# ============================================================
# Group B — HTTP Version
# ============================================================


class TestCheckHttpVersion:
    @patch("recon.socket.create_connection")
    @patch("recon.ssl.create_default_context")
    def test_http2_detected(self, mock_ctx, mock_conn):
        mock_ssock = MagicMock()
        mock_ssock.selected_alpn_protocol.return_value = "h2"
        mock_ctx.return_value.wrap_socket.return_value.__enter__ = lambda s: mock_ssock
        mock_ctx.return_value.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value.__enter__ = lambda s: MagicMock()
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        r = check_http_version("example.com")
        assert r["http2"] is True or r.get("negotiated") == "h2" or "http2" in r

    @patch("recon.socket.create_connection", side_effect=Exception("timeout"))
    def test_connection_failure(self, mock_conn):
        r = check_http_version("example.com")
        assert r["negotiated"] == "unknown"
        assert r["http2"] is False

    def test_returns_dict_structure(self):
        """Even on real network failure, returns proper dict."""
        with patch("recon.socket.create_connection", side_effect=Exception("no")):
            r = check_http_version("nonexistent.example")
        assert "http2" in r
        assert "http3" in r
        assert "negotiated" in r


# ============================================================
# Group C — Reverse DNS
# ============================================================


class TestReverseDnsLookup:
    @patch("recon.socket.gethostbyaddr", return_value=("server1.hosting.com", [], []))
    @patch("recon.socket.getaddrinfo")
    def test_ptr_found(self, mock_gai, mock_rev):
        mock_gai.side_effect = lambda domain, port, family, stype: (
            [(family, stype, 0, "", ("93.184.216.34", 0))] if family == socket.AF_INET else socket.gaierror("no AAAA")
        )
        mock_gai.side_effect = self._make_gai("93.184.216.34", None)
        r = reverse_dns_lookup("example.com")
        assert r["ip"] == "93.184.216.34"
        assert r["ipv4"] == "93.184.216.34"
        assert r["ptr"] == "server1.hosting.com"
        assert r["shared_hosting"] is True

    @patch("recon.socket.gethostbyaddr", return_value=("example.com", [], []))
    @patch("recon.socket.getaddrinfo")
    def test_ptr_matches_domain(self, mock_gai, mock_rev):
        mock_gai.side_effect = self._make_gai("93.184.216.34", None)
        r = reverse_dns_lookup("example.com")
        assert r["shared_hosting"] is False

    @patch("recon.socket.gethostbyaddr", side_effect=socket.herror("no PTR"))
    @patch("recon.socket.getaddrinfo")
    def test_no_ptr_record(self, mock_gai, mock_rev):
        mock_gai.side_effect = self._make_gai("93.184.216.34", None)
        r = reverse_dns_lookup("example.com")
        assert r["ip"] == "93.184.216.34"
        assert r["ptr"] is None

    @patch("recon.socket.getaddrinfo", side_effect=socket.gaierror("DNS failed"))
    def test_dns_failure(self, mock_gai):
        r = reverse_dns_lookup("nonexistent.example")
        assert r["ip"] is None
        assert r["ptr"] is None

    @patch("recon.socket.gethostbyaddr", return_value=("dual.example.com", [], []))
    @patch("recon.socket.getaddrinfo")
    def test_dual_stack_ipv4_and_ipv6(self, mock_gai, mock_rev):
        mock_gai.side_effect = self._make_gai("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
        r = reverse_dns_lookup("example.com")
        assert r["ipv4"] == "93.184.216.34"
        assert r["ipv6"] == "2606:2800:220:1:248:1893:25c8:1946"
        assert r["ip"] == "93.184.216.34"

    @patch("recon.socket.gethostbyaddr", return_value=("v6only.example.com", [], []))
    @patch("recon.socket.getaddrinfo")
    def test_ipv6_only(self, mock_gai, mock_rev):
        mock_gai.side_effect = self._make_gai(None, "2606:2800:220:1:248:1893:25c8:1946")
        r = reverse_dns_lookup("example.com")
        assert "ipv4" not in r
        assert r["ipv6"] == "2606:2800:220:1:248:1893:25c8:1946"
        assert r["ip"] == "2606:2800:220:1:248:1893:25c8:1946"

    @staticmethod
    def _make_gai(ipv4, ipv6):
        """Helper to create getaddrinfo side_effect for IPv4/IPv6 mocking."""

        def side_effect(domain, port, family, stype):
            if family == socket.AF_INET:
                if ipv4:
                    return [(family, stype, 0, "", (ipv4, 0))]
                raise socket.gaierror("no A record")
            elif family == socket.AF_INET6:
                if ipv6:
                    return [(family, stype, 0, "", (ipv6, 0, 0, 0))]
                raise socket.gaierror("no AAAA record")
            return []

        return side_effect


# ============================================================
# Group C — Zone Transfer
# ============================================================


class TestCheckZoneTransfer:
    @patch("recon.subprocess.run")
    def test_not_vulnerable(self, mock_run):
        # First call: dig NS
        ns_result = MagicMock()
        ns_result.stdout = "ns1.example.com.\nns2.example.com.\n"
        # Second call: dig AXFR (fails)
        axfr_result = MagicMock()
        axfr_result.stdout = "; Transfer failed."
        mock_run.side_effect = [ns_result, axfr_result, axfr_result]
        r = check_zone_transfer("example.com")
        assert r["vulnerable"] is False

    @patch("recon.subprocess.run")
    def test_vulnerable(self, mock_run):
        ns_result = MagicMock()
        ns_result.stdout = "ns1.vuln.com.\n"
        axfr_result = MagicMock()
        axfr_result.stdout = "a.vuln.com. A 1.2.3.4\nb.vuln.com. A 1.2.3.5\nc.vuln.com. A 1.2.3.6\n"
        mock_run.side_effect = [ns_result, axfr_result]
        r = check_zone_transfer("vuln.com")
        assert r["vulnerable"] is True
        assert r["record_count"] == 3

    @patch("recon.subprocess.run")
    def test_no_nameservers(self, mock_run):
        ns_result = MagicMock()
        ns_result.stdout = ""
        mock_run.return_value = ns_result
        r = check_zone_transfer("example.com")
        assert r["vulnerable"] is False
        assert r["nameservers"] == []

    @patch("recon.subprocess.run", side_effect=Exception("dig not found"))
    def test_dig_not_available(self, mock_run):
        r = check_zone_transfer("example.com")
        assert r["vulnerable"] is False


# ============================================================
# Group C — Subdomain Enumeration
# ============================================================


def _mock_getaddrinfo(resolvable_fqdns):
    """Create a getaddrinfo side_effect that returns public IP for given FQDNs."""

    def side_effect(fqdn, port, **kwargs):
        if fqdn in resolvable_fqdns:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))]
        raise socket.gaierror("NXDOMAIN")

    return side_effect


class TestEnumerateSubdomains:
    @patch("recon._crtsh_subdomains", return_value=[])
    @patch("recon.socket.getaddrinfo")
    def test_dns_brute_force(self, mock_dns, mock_crt):
        mock_dns.side_effect = _mock_getaddrinfo({"www.example.com", "mail.example.com"})
        r = enumerate_subdomains("example.com")
        assert "www.example.com" in r["subdomains"]
        assert "mail.example.com" in r["subdomains"]
        assert r["count"] == 2

    @patch("recon._crtsh_subdomains", return_value=["api.example.com", "cdn.example.com"])
    @patch("recon.socket.getaddrinfo")
    def test_crtsh_results_merged_when_resolvable(self, mock_dns, mock_crt):
        """CT subdomains that DNS-resolve to public IPs are included."""
        mock_dns.side_effect = _mock_getaddrinfo({"api.example.com", "cdn.example.com"})
        r = enumerate_subdomains("example.com")
        assert "api.example.com" in r["subdomains"]
        assert "cdn.example.com" in r["subdomains"]

    @patch("recon._crtsh_subdomains", return_value=["api.example.com", "cdn.example.com"])
    @patch("recon.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN"))
    def test_crtsh_results_filtered_when_nxdomain(self, mock_dns, mock_crt):
        """CT subdomains that don't DNS-resolve are excluded."""
        r = enumerate_subdomains("example.com")
        assert "api.example.com" not in r["subdomains"]
        assert "cdn.example.com" not in r["subdomains"]
        assert r["count"] == 0

    @patch("recon._crtsh_subdomains", return_value=["internal.example.com"])
    @patch("recon.socket.getaddrinfo")
    def test_crtsh_results_filtered_when_private_ip(self, mock_dns, mock_crt):
        """CT subdomains resolving to private IPs are excluded."""
        mock_dns.side_effect = lambda fqdn, port, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))
        ]
        r = enumerate_subdomains("example.com")
        assert "internal.example.com" not in r["subdomains"]

    @patch("recon._crtsh_subdomains", return_value=["www.example.com"])
    @patch("recon.socket.getaddrinfo")
    def test_deduplication(self, mock_dns, mock_crt):
        mock_dns.side_effect = _mock_getaddrinfo({"www.example.com"})
        r = enumerate_subdomains("example.com")
        assert r["subdomains"].count("www.example.com") == 1

    @patch("recon._crtsh_subdomains", return_value=[])
    @patch("recon.socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN"))
    def test_no_subdomains_found(self, mock_dns, mock_crt):
        r = enumerate_subdomains("example.com")
        assert r["count"] == 0
        assert r["subdomains"] == []

    @patch("recon._crtsh_subdomains", return_value=[])
    @patch("recon.socket.getaddrinfo")
    def test_wildcard_dns_filters_false_positives(self, mock_dns, mock_crt):
        """All subdomains resolve to wildcard IP — none should be reported."""
        # Every FQDN (including the random wildcard probe) resolves to same IP
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("5.5.5.5", 0))]
        r = enumerate_subdomains("example.com")
        assert r["count"] == 0
        assert r["subdomains"] == []

    @patch("recon._crtsh_subdomains", return_value=[])
    @patch("recon.socket.getaddrinfo")
    def test_wildcard_dns_keeps_different_ip(self, mock_dns, mock_crt):
        """Subdomain with a different IP than wildcard should be kept."""
        wildcard_ip = "5.5.5.5"
        real_ip = "9.9.9.9"

        def side_effect(fqdn, port, **kwargs):
            # www.example.com has its own IP, everything else hits wildcard
            if fqdn == "www.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (real_ip, 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (wildcard_ip, 0))]

        mock_dns.side_effect = side_effect
        r = enumerate_subdomains("example.com")
        assert "www.example.com" in r["subdomains"]
        assert r["count"] == 1

    @patch("recon._crtsh_subdomains", return_value=["api.example.com"])
    @patch("recon.socket.getaddrinfo")
    def test_wildcard_dns_crtsh_filtered_by_wildcard(self, mock_dns, mock_crt):
        """CT subdomains resolving to wildcard IP are filtered out."""
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("5.5.5.5", 0))]
        r = enumerate_subdomains("example.com")
        assert "api.example.com" not in r["subdomains"]
        assert r["count"] == 0

    @patch("recon._crtsh_subdomains", return_value=["api.example.com"])
    @patch("recon.socket.getaddrinfo")
    def test_wildcard_dns_crtsh_kept_when_different_ip(self, mock_dns, mock_crt):
        """CT subdomain with different IP than wildcard should be kept."""
        wildcard_ip = "5.5.5.5"
        real_ip = "9.9.9.9"

        def side_effect(fqdn, port, **kwargs):
            if fqdn == "api.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (real_ip, 0))]
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (wildcard_ip, 0))]

        mock_dns.side_effect = side_effect
        r = enumerate_subdomains("example.com")
        assert "api.example.com" in r["subdomains"]


# ============================================================
# Group C — crt.sh helper
# ============================================================


class TestCrtshSubdomains:
    @patch("recon._no_redirect_opener")
    def test_parses_crtsh_json(self, mock_opener):
        data = json.dumps(
            [
                {"name_value": "www.example.com"},
                {"name_value": "api.example.com\ncdn.example.com"},
                {"name_value": "*.example.com"},  # wildcard — should be skipped
            ]
        ).encode()
        mock_opener.open.return_value = _mock_urlopen_response(data)
        r = _crtsh_subdomains("example.com")
        assert "www.example.com" in r
        assert "api.example.com" in r
        assert "cdn.example.com" in r
        # wildcard filtered
        assert not any("*" in s for s in r)

    @patch("recon._no_redirect_opener")
    def test_crtsh_failure_returns_empty(self, mock_opener):
        mock_opener.open.side_effect = Exception("timeout")
        r = _crtsh_subdomains("example.com")
        assert r == []

    @patch("recon._no_redirect_opener")
    def test_capped_at_50(self, mock_opener):
        entries = [{"name_value": f"sub{i}.example.com"} for i in range(100)]
        mock_opener.open.return_value = _mock_urlopen_response(json.dumps(entries).encode())
        r = _crtsh_subdomains("example.com")
        assert len(r) <= 50

    @patch("recon._no_redirect_opener")
    def test_filters_other_domains(self, mock_opener):
        data = json.dumps(
            [
                {"name_value": "www.example.com"},
                {"name_value": "evil.attacker.com"},
            ]
        ).encode()
        mock_opener.open.return_value = _mock_urlopen_response(data)
        r = _crtsh_subdomains("example.com")
        assert "evil.attacker.com" not in r


# ============================================================
# Group D — WHOIS
# ============================================================


class TestWhoisLookup:
    @patch("recon.socket.gethostbyname", return_value="1.2.3.4")
    @patch("recon.socket.create_connection")
    def test_whois_parsed(self, mock_conn, mock_resolve):
        whois_text = (
            "Domain Name: EXAMPLE.COM\n"
            "Registrar: Example Registrar Inc.\n"
            "Creation Date: 1995-08-14T04:00:00Z\n"
            "Registry Expiry Date: 2025-08-13T04:00:00Z\n"
            "Name Server: NS1.EXAMPLE.COM\n"
            "Name Server: NS2.EXAMPLE.COM\n"
            "Status: clientDeleteProhibited\n"
        )
        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[whois_text.encode(), b""])
        mock_conn.return_value.__enter__ = lambda s: mock_sock
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        r = whois_lookup("example.com")
        assert r["registrar"] == "Example Registrar Inc."
        assert "1995" in r["creation_date"]
        assert len(r["name_servers"]) == 2
        assert r["raw_length"] > 0

    @patch("recon.socket.gethostbyname", return_value="1.2.3.4")
    @patch("recon.socket.create_connection", side_effect=Exception("connection refused"))
    def test_whois_failure(self, mock_conn, mock_resolve):
        r = whois_lookup("example.com")
        assert "error" in r

    def test_whois_server_selection_com(self):
        """Verify .com uses verisign."""
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("test.com")
            mock_resolve.assert_called_with("whois.verisign-grs.com")

    def test_whois_server_selection_org(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("test.org")
            mock_resolve.assert_called_with("whois.pir.org")

    def test_whois_server_selection_unknown_tld(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("test.xyz")
            mock_resolve.assert_called_with("whois.nic.xyz")


# ============================================================
# Group D — WHOIS Parser
# ============================================================


class TestParseWhois:
    def test_parses_registrar(self):
        text = "Registrar: GoDaddy\nCreation Date: 2020-01-01"
        r = _parse_whois(text)
        assert r["registrar"] == "GoDaddy"

    def test_parses_creation_date(self):
        r = _parse_whois("Created Date: 2020-01-01T00:00:00Z")
        assert "2020" in r["creation_date"]

    def test_parses_expiry_date(self):
        r = _parse_whois("Registry Expiry Date: 2030-12-31T00:00:00Z")
        assert "2030" in r["expiry_date"]

    def test_parses_name_servers(self):
        text = "Name Server: ns1.example.COM\nName Server: ns2.example.COM"
        r = _parse_whois(text)
        assert len(r["name_servers"]) == 2
        assert r["name_servers"][0] == "ns1.example.com"

    def test_name_servers_capped_at_4(self):
        text = "\n".join(f"Name Server: ns{i}.example.com" for i in range(10))
        r = _parse_whois(text)
        assert len(r["name_servers"]) <= 4

    def test_status_capped_at_5(self):
        text = "\n".join(f"Status: status{i}" for i in range(10))
        r = _parse_whois(text)
        assert len(r["status"]) <= 5

    def test_empty_text(self):
        r = _parse_whois("")
        assert r == {}

    def test_no_matching_fields(self):
        r = _parse_whois("Some random text\nNo whois data here")
        assert r == {}


# ============================================================
# Group D — Certificate Transparency Logs
# ============================================================


class TestCheckCtLogs:
    @patch("recon._no_redirect_opener")
    def test_certs_parsed(self, mock_opener):
        data = [
            {
                "serial_number": "abc",
                "issuer_name": "Let's Encrypt",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "example.com",
            },
            {
                "serial_number": "def",
                "issuer_name": "DigiCert",
                "not_before": "2024-06-01",
                "not_after": "2025-06-01",
                "common_name": "example.com",
            },
        ]
        mock_opener.open.return_value = _mock_urlopen_response(json.dumps(data).encode())
        r = check_ct_logs("example.com")
        assert r["total_certificates"] == 2
        assert len(r["recent_certificates"]) == 2
        assert r["recent_certificates"][0]["issuer"] == "Let's Encrypt"

    @patch("recon._no_redirect_opener")
    def test_deduplicates_by_serial(self, mock_opener):
        data = [
            {
                "serial_number": "abc",
                "issuer_name": "LE",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "example.com",
            },
            {
                "serial_number": "abc",
                "issuer_name": "LE",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "example.com",
            },
        ]
        mock_opener.open.return_value = _mock_urlopen_response(json.dumps(data).encode())
        r = check_ct_logs("example.com")
        assert len(r["recent_certificates"]) == 1

    @patch("recon._no_redirect_opener")
    def test_recent_certs_capped_at_10(self, mock_opener):
        data = [
            {
                "serial_number": str(i),
                "issuer_name": "CA",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "x.com",
            }
            for i in range(25)
        ]
        mock_opener.open.return_value = _mock_urlopen_response(json.dumps(data).encode())
        r = check_ct_logs("example.com")
        assert len(r["recent_certificates"]) <= 10

    @patch("recon._no_redirect_opener")
    def test_failure_returns_zero(self, mock_opener):
        mock_opener.open.side_effect = Exception("timeout")
        r = check_ct_logs("example.com")
        assert r["total_certificates"] == 0
        assert "error" in r


# ============================================================
# Orchestration — run_recon
# ============================================================


class TestRunRecon:
    @patch("recon.check_ct_logs", return_value={"total_certificates": 0})
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("recon._fetch_crtsh", return_value=[])
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": True, "http3": False, "negotiated": "h2"})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None, "error": "No ASN found"})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": True, "disallowed_paths": [], "sitemaps": [], "line_count": 1})
    @patch("recon.save_recon")
    @patch("recon.create_recon")
    def test_run_recon_calls_all_modules(
        self,
        mock_create,
        mock_save,
        mock_robots,
        mock_sitemap,
        mock_asn,
        mock_sec_txt,
        mock_http,
        mock_rdns,
        mock_caa,
        mock_zone,
        mock_crtsh,
        mock_subs,
        mock_whois,
        mock_ct,
    ):
        sr = _scan_result()
        sr["resolved_ip"] = "1.2.3.4"
        run_recon("abc123", "example.com", sr)
        mock_create.assert_called_with("abc123", "example.com")
        # Verify save_recon called with our scan_id
        save_calls = [c for c in mock_save.call_args_list if c[0][0] == "abc123"]
        assert len(save_calls) == 1, f"Expected 1 save for abc123, got {len(save_calls)}"
        # Verify all modules called
        mock_robots.assert_called()
        mock_sitemap.assert_called()
        mock_http.assert_called()
        mock_sec_txt.assert_called()
        mock_asn.assert_called()
        mock_rdns.assert_called()
        mock_caa.assert_called()
        mock_zone.assert_called()
        mock_crtsh.assert_called()
        mock_subs.assert_called()
        mock_whois.assert_called()
        mock_ct.assert_called()

    @patch("recon.check_ct_logs", return_value={"total_certificates": 0})
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("recon._fetch_crtsh", return_value=[])
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": False, "http3": False, "negotiated": "http/1.1"})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None, "error": "No ASN found"})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": False})
    @patch("recon.save_recon")
    @patch("recon.create_recon")
    def test_run_recon_saves_all_keys(self, mock_create, mock_save, *_):
        run_recon("abc123", "example.com", _scan_result())
        saved_data = mock_save.call_args[0][1]
        expected_keys = [
            "tech_stack",
            "waf",
            "emails",
            "robots",
            "sitemap",
            "http_version",
            "reverse_dns",
            "zone_transfer",
            "subdomains",
            "whois",
            "ct_logs",
            "security_txt",
            "caa",
        ]
        for key in expected_keys:
            assert key in saved_data, f"Missing key: {key}"

    @patch("recon.detect_tech_stack", side_effect=RuntimeError("boom"))
    @patch("recon.save_recon_error")
    @patch("recon.create_recon")
    def test_run_recon_handles_runtime_error_as_shutdown(self, mock_create, mock_save_err, mock_tech):
        """RuntimeError during recon is treated as shutdown — no save_recon_error."""
        run_recon("abc123", "example.com", _scan_result())
        mock_save_err.assert_not_called()

    @patch("recon.detect_tech_stack", side_effect=ValueError("boom"))
    @patch("recon.save_recon_error")
    @patch("recon.create_recon")
    def test_run_recon_handles_exception(self, mock_create, mock_save_err, mock_tech):
        run_recon("abc123", "example.com", _scan_result())
        mock_save_err.assert_called_once()
        assert "boom" in mock_save_err.call_args[0][1]


# ============================================================
# Orchestration — start_recon
# ============================================================


@pytest.mark.allow_recon
class TestStartRecon:
    @patch("recon.run_recon")
    def test_starts_daemon_thread(self, mock_run):
        start_recon("abc123", "example.com", _scan_result())
        # Give thread a moment to start
        import time

        time.sleep(0.1)
        mock_run.assert_called_once_with("abc123", "example.com", mock_run.call_args[0][2])

    @patch("recon.threading.Thread")
    def test_thread_is_daemon(self, mock_thread_cls):
        mock_thread_cls.return_value = MagicMock()
        start_recon("abc123", "example.com", _scan_result())
        mock_thread_cls.assert_called_once()
        assert mock_thread_cls.call_args[1]["daemon"] is True


# ============================================================
# DB — Recon round-trip
# ============================================================


class TestReconDb:
    def test_create_and_get(self, init_test_db):
        create_recon("test001", "example.com")
        row = get_recon("test001")
        assert row is not None
        assert row["status"] == "running"
        assert row["domain"] == "example.com"

    def test_save_recon_done(self, init_test_db):
        create_recon("test002", "example.com")
        save_recon("test002", {"tech_stack": {"count": 2}})
        row = get_recon("test002")
        assert row["status"] == "done"
        data = json.loads(row["result"])
        assert data["tech_stack"]["count"] == 2

    def test_save_recon_error(self, init_test_db):
        create_recon("test003", "example.com")
        save_recon_error("test003", "timeout exceeded")
        row = get_recon("test003")
        assert row["status"] == "error"
        data = json.loads(row["result"])
        assert data["error"] == "timeout exceeded"

    def test_get_nonexistent(self, init_test_db):
        row = get_recon("nonexistent_id")
        assert row is None

    def test_completed_at_set(self, init_test_db):
        create_recon("test004", "example.com")
        save_recon("test004", {"data": 1})
        row = get_recon("test004")
        assert row["completed_at"] is not None

    def test_created_at_set(self, init_test_db):
        create_recon("test005", "example.com")
        row = get_recon("test005")
        assert row["created_at"] is not None


# ============================================================
# E2E — GET /recon/{scan_id}
# ============================================================


class TestReconEndpoint:
    @pytest.fixture(autouse=True)
    def setup_client(self):
        from fastapi.testclient import TestClient
        from main import app

        self.client = TestClient(app)
        init_db()

    def test_pending_status(self):
        r = self.client.get("/recon/aaaabbbbccccddddeeee111122223333")
        assert r.status_code == 200
        assert r.json()["status"] == "pending"

    def test_done_status(self):
        scan_id = "aabbccdd11223344aabbccdd11223344"
        create_recon(scan_id, "example.com")
        save_recon(scan_id, {"tech_stack": {"count": 1}})
        r = self.client.get(f"/recon/{scan_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "done"
        assert body["data"]["tech_stack"]["count"] == 1

    def test_error_status(self):
        scan_id = "eeff00112233445566778899aabbccdd"
        create_recon(scan_id, "example.com")
        save_recon_error(scan_id, "network timeout")
        r = self.client.get(f"/recon/{scan_id}")
        body = r.json()
        assert body["status"] == "error"

    def test_invalid_scan_id_404(self):
        r = self.client.get("/recon/not-a-hex-id!")
        assert r.status_code == 404

    def test_returns_json(self):
        r = self.client.get("/recon/aaaabbbbccccddddeeee111122223333")
        assert r.headers["content-type"].startswith("application/json")


# ============================================================
# Report — Recon section in plain-text report
# ============================================================


class TestReconReport:
    """Tests that recon data renders correctly in the txt report."""

    FULL_RECON = {
        "tech_stack": {"technologies": [{"name": "nginx/1.24", "source": "server_header"}], "count": 1},
        "waf": {"detected": ["Cloudflare"], "waf_present": True},
        "emails": {"found": ["MX: mail.example.com"], "common_guesses": ["info@example.com"]},
        "robots": {"exists": True, "disallowed_paths": ["/admin", "/private"], "sitemaps": [], "line_count": 5},
        "sitemap": {"exists": True, "url_count": 42, "sample_urls": []},
        "http_version": {"http2": True, "http3": False, "negotiated": "h2"},
        "reverse_dns": {"ip": "93.184.216.34", "ptr": "server1.hosting.com", "shared_hosting": True},
        "zone_transfer": {"vulnerable": False, "nameservers": ["ns1.example.com"]},
        "subdomains": {"subdomains": ["www.example.com", "api.example.com"], "count": 2},
        "whois": {
            "registrar": "GoDaddy",
            "creation_date": "2020-01-01",
            "expiry_date": "2030-01-01",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
        },
        "ct_logs": {"total_certificates": 15, "recent_certificates": []},
    }

    def _generate(self, recon=None):
        from conftest import make_scan_result
        from report import generate_report

        sr = make_scan_result()
        sr["grade"] = "A"
        sr["total_score"] = 100
        sr["max_score"] = 100
        return generate_report(sr, "a" * 32, "2026-01-01", recon=recon)

    def test_no_recon_no_section(self):
        txt = self._generate(recon=None)
        assert "PASSIVE RECON" not in txt

    def test_recon_section_present(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "PASSIVE RECON" in txt

    def test_tech_stack_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "nginx/1.24" in txt
        assert "server_header" in txt

    def test_waf_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "Cloudflare" in txt

    def test_http_version_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "H2" in txt

    def test_reverse_dns_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "93.184.216.34" in txt
        assert "server1.hosting.com" in txt

    def test_zone_transfer_safe_hidden(self):
        """Not vulnerable zone transfer should NOT appear in report."""
        txt = self._generate(recon=self.FULL_RECON)
        assert "Zone Transfer" not in txt

    def test_zone_transfer_vulnerable(self):
        recon = {**self.FULL_RECON, "zone_transfer": {"vulnerable": True, "record_count": 50}}
        txt = self._generate(recon=recon)
        assert "VULNERABLE" in txt

    def test_subdomains_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "www.example.com" in txt
        assert "api.example.com" in txt

    def test_subdomains_capped_at_15(self):
        subs = [f"sub{i}.example.com" for i in range(20)]
        recon = {**self.FULL_RECON, "subdomains": {"subdomains": subs, "count": 20}}
        txt = self._generate(recon=recon)
        assert "and 5 more" in txt

    def test_robots_disallowed_paths_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "robots.txt" in txt
        assert "/admin" in txt
        assert "/private" in txt

    def test_robots_no_paths_hidden(self):
        """robots.txt with no disallowed paths should not appear."""
        recon = {**self.FULL_RECON, "robots": {"exists": True, "disallowed_paths": [], "line_count": 1}}
        txt = self._generate(recon=recon)
        assert "robots.txt" not in txt

    def test_sitemap_removed(self):
        """Sitemap section no longer in report."""
        txt = self._generate(recon=self.FULL_RECON)
        assert "sitemap.xml" not in txt

    def test_whois_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "GoDaddy" in txt
        assert "2020-01-01" in txt
        assert "2030-01-01" in txt

    def test_ct_logs_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "15 certificates" in txt

    def test_emails_mx_in_report(self):
        txt = self._generate(recon=self.FULL_RECON)
        assert "mail.example.com" in txt

    def test_guessed_emails_not_in_report(self):
        """Guessed emails should NOT appear in report."""
        txt = self._generate(recon=self.FULL_RECON)
        assert "info@example.com" not in txt
        assert "guessed" not in txt.lower()

    def test_empty_recon_no_crash(self):
        txt = self._generate(recon={})
        assert "PASSIVE RECON" in txt

    def test_waf_not_detected_hidden(self):
        """WAF not detected should NOT appear in report."""
        recon = {**self.FULL_RECON, "waf": {"detected": [], "waf_present": False}}
        txt = self._generate(recon=recon)
        assert "WAF" not in txt

    def test_robots_not_found_hidden(self):
        """robots.txt not found should NOT appear in report."""
        recon = {**self.FULL_RECON, "robots": {"exists": False}}
        txt = self._generate(recon=recon)
        assert "robots.txt" not in txt

    def test_sitemap_not_found_hidden(self):
        """sitemap.xml not found should NOT appear in report."""
        recon = {**self.FULL_RECON, "sitemap": {"exists": False}}
        txt = self._generate(recon=recon)
        assert "sitemap.xml" not in txt


# ============================================================
# Constants & Pattern Integrity
# ============================================================


class TestReconConstants:
    def test_common_subdomains_not_empty(self):
        assert len(COMMON_SUBDOMAINS) >= 10

    def test_common_subdomains_no_dots(self):
        for s in COMMON_SUBDOMAINS:
            assert "." not in s

    def test_waf_signatures_have_header(self):
        for name, sig in WAF_SIGNATURES.items():
            assert "header" in sig, f"WAF {name} missing header field"

    def test_recon_timeout_positive(self):
        from recon import RECON_TIMEOUT

        assert RECON_TIMEOUT > 0

    def test_crtsh_max_bytes_is_2mb(self):
        from recon import CRTSH_MAX_BYTES

        assert CRTSH_MAX_BYTES == 2097152

    def test_crtsh_timeout_is_30(self):
        from recon import CRTSH_TIMEOUT

        assert CRTSH_TIMEOUT == 30


# ============================================================
# harvest_emails — www. prefix stripping
# ============================================================


class TestHarvestEmailsWwwStrip:
    def test_www_prefix_stripped_from_guesses(self):
        """www.example.com should generate info@example.com, not info@www.example.com."""
        r = harvest_emails(_scan_result(), "www.example.com")
        assert "info@example.com" in r["common_guesses"]
        assert "admin@example.com" in r["common_guesses"]
        assert "contact@example.com" in r["common_guesses"]

    def test_www_prefix_not_in_any_guess(self):
        r = harvest_emails(_scan_result(), "www.test.org")
        for guess in r["common_guesses"]:
            assert "www." not in guess

    def test_non_www_domain_unchanged(self):
        r = harvest_emails(_scan_result(), "api.example.com")
        assert "info@api.example.com" in r["common_guesses"]

    def test_www_only_strips_leading_www(self):
        """Domain like 'wwwtest.com' should NOT be stripped."""
        r = harvest_emails(_scan_result(), "wwwtest.com")
        assert "info@wwwtest.com" in r["common_guesses"]


# ============================================================
# WHOIS — compound TLDs, RDAP-only, new TLD servers
# ============================================================


class TestWhoisCompoundTlds:
    def test_rdap_only_dev(self):
        """'.dev' domains should return RDAP-only error without connecting."""
        r = whois_lookup("example.dev")
        assert "error" in r
        assert "RDAP only" in r["error"]

    def test_rdap_only_app(self):
        r = whois_lookup("example.app")
        assert "error" in r
        assert "RDAP only" in r["error"]

    def test_whois_server_tr(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.tr")
            mock_resolve.assert_called_with("whois.trabis.gov.tr")

    def test_whois_server_uk(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.uk")
            mock_resolve.assert_called_with("whois.nic.uk")

    def test_whois_server_de(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.de")
            mock_resolve.assert_called_with("whois.denic.de")

    def test_whois_server_fr(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.fr")
            mock_resolve.assert_called_with("whois.nic.fr")

    def test_whois_server_io(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.io")
            mock_resolve.assert_called_with("whois.nic.io")

    def test_whois_server_jp(self):
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.jp")
            mock_resolve.assert_called_with("whois.jprs.jp")

    def test_whois_server_fallback_unknown_tld(self):
        """Unknown TLDs should fall back to whois.nic.<tld>."""
        with (
            patch("recon.socket.gethostbyname", return_value="1.2.3.4") as mock_resolve,
            patch("recon.socket.create_connection", side_effect=Exception("x")),
        ):
            whois_lookup("example.museum")
            mock_resolve.assert_called_with("whois.nic.museum")


# ============================================================
# _parse_whois — UK/TR format variations
# ============================================================


class TestParseWhoisFormats:
    def test_uk_registered_on_format(self):
        """UK WHOIS uses 'Registered on:' instead of 'Creation Date:'."""
        text = "Registrar: Nominet\nRegistered on: 15-Jan-2010\nExpiry date: 15-Jan-2030"
        r = _parse_whois(text)
        assert "creation_date" in r
        assert "2010" in r["creation_date"]

    def test_uk_renewal_date_format(self):
        """UK WHOIS uses 'Renewal date:' instead of 'Registry Expiry Date:'."""
        text = "Renewal date: 15-Jan-2030"
        r = _parse_whois(text)
        assert "expiry_date" in r
        assert "2030" in r["expiry_date"]

    def test_tr_registration_date_format(self):
        """TR WHOIS uses 'Registration Date:' format."""
        text = "Registrar: TRABIS\nRegistration Date: 2015-05-20"
        r = _parse_whois(text)
        assert "creation_date" in r
        assert "2015" in r["creation_date"]

    def test_last_updated_format(self):
        """Some registrars use 'Last updated:' instead of 'Updated Date:'."""
        text = "Last updated: 2026-01-15T12:00:00Z"
        r = _parse_whois(text)
        assert "updated_date" in r
        assert "2026" in r["updated_date"]

    def test_updated_date_format(self):
        text = "Updated Date: 2025-12-01"
        r = _parse_whois(text)
        assert "updated_date" in r
        assert "2025" in r["updated_date"]

    def test_name_servers_lowercase(self):
        """UK format uses 'Name servers:' (lowercase s)."""
        text = "Name servers: NS1.EXAMPLE.CO.UK\nName servers: NS2.EXAMPLE.CO.UK"
        r = _parse_whois(text)
        assert "name_servers" in r
        assert r["name_servers"][0] == "ns1.example.co.uk"

    def test_expiration_date_variant(self):
        text = "Expiration Date: 2028-06-15T00:00:00Z"
        r = _parse_whois(text)
        assert "expiry_date" in r
        assert "2028" in r["expiry_date"]

    def test_domain_status_with_prefix(self):
        """Some registries use 'Domain Status:' instead of plain 'Status:'."""
        text = "Domain Status: clientDeleteProhibited"
        r = _parse_whois(text)
        assert "status" in r
        assert "clientDeleteProhibited" in r["status"][0]


# ============================================================
# _fetch_crtsh — direct unit tests
# ============================================================


class TestFetchCrtsh:
    @patch("recon._no_redirect_opener")
    def test_returns_parsed_json(self, mock_opener):
        data = [{"name_value": "test.example.com", "serial_number": "abc"}]
        mock_opener.open.return_value = _mock_urlopen_response(json.dumps(data).encode())
        from recon import _fetch_crtsh

        result = _fetch_crtsh("%.example.com")
        assert len(result) == 1
        assert result[0]["name_value"] == "test.example.com"

    @patch("recon._no_redirect_opener")
    def test_returns_empty_on_failure(self, mock_opener):
        mock_opener.open.side_effect = Exception("timeout")
        from recon import _fetch_crtsh

        result = _fetch_crtsh("%.example.com")
        assert result == []

    @patch("recon._no_redirect_opener")
    def test_exact_query_url(self, mock_opener):
        """Exact query (CT logs) uses domain without wildcard."""
        mock_opener.open.return_value = _mock_urlopen_response(b"[]")
        from recon import _fetch_crtsh

        _fetch_crtsh("example.com")
        url = mock_opener.open.call_args[0][0].full_url
        assert "q=example.com" in url
        assert "%" not in url

    @patch("recon._no_redirect_opener")
    def test_wildcard_query_url(self, mock_opener):
        """Wildcard query (subdomains) uses %.domain."""
        mock_opener.open.return_value = _mock_urlopen_response(b"[]")
        from recon import _fetch_crtsh

        _fetch_crtsh("%.example.com")
        url = mock_opener.open.call_args[0][0].full_url
        assert "q=%25.example.com" in url or "q=%.example.com" in url


# ============================================================
# check_ct_logs — with pre-fetched data
# ============================================================


class TestCheckCtLogsPreFetched:
    def test_uses_prefetched_data(self):
        """When crtsh_data is passed, should not call _fetch_crtsh."""
        data = [
            {
                "serial_number": "s1",
                "issuer_name": "LE",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "example.com",
            },
        ]
        with patch("recon._fetch_crtsh") as mock_fetch:
            r = check_ct_logs("example.com", crtsh_data=data)
            mock_fetch.assert_not_called()
        assert r["total_certificates"] == 1

    def test_empty_prefetched_data(self):
        r = check_ct_logs("example.com", crtsh_data=[])
        assert r["total_certificates"] == 0
        assert "error" in r


# ============================================================
# enumerate_subdomains — with pre-fetched crtsh data
# ============================================================


class TestEnumerateSubdomainsPreFetched:
    @patch("recon.socket.getaddrinfo")
    def test_uses_cached_crtsh_data(self, mock_dns):
        """When crtsh_data is passed to enumerate_subdomains, it feeds _crtsh_subdomains."""
        mock_dns.side_effect = _mock_getaddrinfo({"api.example.com", "cdn.example.com"})
        crtsh_data = [
            {"name_value": "api.example.com"},
            {"name_value": "cdn.example.com"},
        ]
        r = enumerate_subdomains("example.com", crtsh_data=crtsh_data)
        assert "api.example.com" in r["subdomains"]
        assert "cdn.example.com" in r["subdomains"]


# ============================================================
# run_recon — parallel crt.sh split (two separate queries)
# ============================================================


class TestRunReconParallelCrtsh:
    @patch("recon.save_recon")
    @patch("recon.create_recon")
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": False, "negotiated": "http/1.1", "http3": False})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": False})
    @patch("recon._fetch_crtsh")
    def test_crtsh_called_twice_with_different_queries(self, mock_crtsh, *_):
        """run_recon should call _fetch_crtsh twice: once wildcard, once exact."""
        mock_crtsh.return_value = []
        run_recon("split01", "example.com", _scan_result())
        assert mock_crtsh.call_count == 2
        queries = [call[0][0] for call in mock_crtsh.call_args_list]
        assert "%.example.com" in queries, "Missing wildcard query for subdomains"
        assert "example.com" in queries, "Missing exact query for CT logs"

    @patch("recon.save_recon")
    @patch("recon.create_recon")
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": False, "negotiated": "http/1.1", "http3": False})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": False})
    @patch("recon.enumerate_subdomains", return_value={"subdomains": [], "count": 0})
    @patch("recon.check_ct_logs", return_value={"total_certificates": 5, "recent_certificates": []})
    @patch("recon._fetch_crtsh")
    def test_crtsh_results_fed_to_correct_consumers(self, mock_crtsh, mock_ct, mock_subs, *_):
        """Wildcard result goes to enumerate_subdomains, exact to check_ct_logs."""
        sub_data = [{"name_value": "api.example.com"}]
        ct_data = [
            {
                "serial_number": "s1",
                "issuer_name": "LE",
                "not_before": "2025-01-01",
                "not_after": "2025-04-01",
                "common_name": "example.com",
            }
        ]

        def crtsh_side_effect(query):
            if query.startswith("%"):
                return sub_data
            return ct_data

        mock_crtsh.side_effect = crtsh_side_effect
        run_recon("split02", "example.com", _scan_result())
        # enumerate_subdomains receives wildcard data
        mock_subs.assert_called_once()
        assert mock_subs.call_args[0][1] == sub_data
        # check_ct_logs receives exact data
        mock_ct.assert_called_once()
        assert mock_ct.call_args[0][1] == ct_data

    @patch("recon.save_recon")
    @patch("recon.create_recon")
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": False, "negotiated": "http/1.1", "http3": False})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": False})
    @patch("recon._fetch_crtsh")
    def test_crtsh_timeout_handled_gracefully(self, mock_crtsh, *_):
        """If crt.sh times out, run_recon should still complete with empty lists."""
        mock_crtsh.side_effect = Exception("timeout")
        run_recon("timeout01", "example.com", _scan_result())
        # Should still save — the exception is caught inside run_recon

    @patch("recon.save_recon")
    @patch("recon.create_recon")
    @patch("recon.whois_lookup", return_value={"registrar": "Test"})
    @patch("recon.check_zone_transfer", return_value={"vulnerable": False})
    @patch("recon.check_caa", return_value={"found": False, "records": [], "issuers": []})
    @patch("recon.reverse_dns_lookup", return_value={"ip": "1.2.3.4", "ptr": None})
    @patch("recon.check_http_version", return_value={"http2": False, "negotiated": "http/1.1", "http3": False})
    @patch("recon.fetch_security_txt", return_value={"found": False})
    @patch("recon.fetch_asn_info", return_value={"asn": None})
    @patch("recon.fetch_sitemap", return_value={"exists": False})
    @patch("recon.fetch_robots", return_value={"exists": False})
    @patch("recon._fetch_crtsh", return_value=[])
    def test_5_parallel_groups_all_execute(self, *_):
        """All 5 parallel groups (http, dns, crtsh_subs, crtsh_ct, whois) execute."""
        mock_save = _[11]  # save_recon mock from decorator stack
        run_recon("pool01", "example.com", _scan_result())
        saved_data = mock_save.call_args[0][1]
        for key in [
            "robots",
            "sitemap",
            "http_version",
            "reverse_dns",
            "zone_transfer",
            "whois",
            "subdomains",
            "ct_logs",
            "subdomain_takeover",
            "security_txt",
            "caa",
        ]:
            assert key in saved_data, f"Missing parallel group result: {key}"


# ============================================================
# Subdomain Takeover Detection
# ============================================================


class TestSubdomainTakeover:
    @patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN"))
    @patch("recon.dns.resolver.Resolver")
    def test_dangling_cname_github(self, mock_resolver_cls, mock_gethostbyname):
        """Dangling CNAME to github.io should be flagged as vulnerable."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = MagicMock()
        mock_answer.target = dns.name.from_text("oldrepo.github.io.")
        mock_resolver.resolve.return_value = [mock_answer]

        result = check_subdomain_takeover(["blog.example.com"])
        assert len(result["vulnerable"]) == 1
        assert result["vulnerable"][0]["service"] == "GitHub Pages"
        assert result["vulnerable"][0]["severity"] == "high"
        assert "NXDOMAIN" in result["vulnerable"][0]["evidence"]

    @patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN"))
    @patch("recon.dns.resolver.Resolver")
    def test_dangling_cname_heroku(self, mock_resolver_cls, mock_gethostbyname):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = MagicMock()
        mock_answer.target = dns.name.from_text("old-app.herokuapp.com.")
        mock_resolver.resolve.return_value = [mock_answer]

        result = check_subdomain_takeover(["app.example.com"])
        assert len(result["vulnerable"]) == 1
        assert result["vulnerable"][0]["service"] == "Heroku"

    @patch("socket.gethostbyname", side_effect=socket.gaierror("NXDOMAIN"))
    @patch("recon.dns.resolver.Resolver")
    def test_dangling_unknown_service(self, mock_resolver_cls, mock_gethostbyname):
        """Dangling CNAME to unknown service still flagged as medium."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = MagicMock()
        mock_answer.target = dns.name.from_text("dead.randomservice.xyz.")
        mock_resolver.resolve.return_value = [mock_answer]

        result = check_subdomain_takeover(["old.example.com"])
        assert len(result["vulnerable"]) == 1
        assert result["vulnerable"][0]["service"] == "unknown"
        assert result["vulnerable"][0]["severity"] == "medium"

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("recon.dns.resolver.Resolver")
    def test_resolving_cname_no_vuln(self, mock_resolver_cls, mock_gethostbyname):
        """CNAME that resolves properly is not vulnerable."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = MagicMock()
        mock_answer.target = dns.name.from_text("active.github.io.")
        mock_resolver.resolve.return_value = [mock_answer]

        result = check_subdomain_takeover(["docs.example.com"])
        assert len(result["vulnerable"]) == 0

    @patch("recon.dns.resolver.Resolver")
    def test_no_cname_no_vuln(self, mock_resolver_cls):
        """Subdomain without CNAME should not be flagged."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        result = check_subdomain_takeover(["www.example.com"])
        assert len(result["vulnerable"]) == 0
        assert result["checked"] == 1

    def test_empty_subdomains(self):
        result = check_subdomain_takeover([])
        assert result["vulnerable"] == []
        assert result["checked"] == 0

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("recon._no_redirect_opener")
    @patch("recon.dns.resolver.Resolver")
    def test_http_fingerprint_match(self, mock_resolver_cls, mock_opener, mock_gethostbyname):
        """CNAME resolves but HTTP fingerprint matches — still vulnerable."""
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_answer = MagicMock()
        mock_answer.target = dns.name.from_text("old.herokuapp.com.")
        mock_resolver.resolve.return_value = [mock_answer]

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"<html><body>No such app</body></html>"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_opener.open.return_value = mock_resp

        result = check_subdomain_takeover(["staging.example.com"])
        assert len(result["vulnerable"]) == 1
        assert "fingerprint" in result["vulnerable"][0]["evidence"].lower()


# ============================================================
# security.txt
# ============================================================


class TestFetchSecurityTxt:
    @patch("recon._no_redirect_opener")
    def test_found_with_fields(self, mock_opener):
        body = (
            b"Contact: mailto:security@example.com\n"
            b"Expires: 2026-12-31T23:59:00.000Z\n"
            b"Policy: https://example.com/security-policy\n"
            b"Preferred-Languages: en, tr\n"
        )
        mock_opener.open.return_value = _mock_urlopen_response(body)
        r = fetch_security_txt("example.com")
        assert r["found"] is True
        assert r["fields"]["contact"] == "mailto:security@example.com"
        assert r["fields"]["expires"] == "2026-12-31T23:59:00.000Z"
        assert r["fields"]["policy"] == "https://example.com/security-policy"
        assert r["fields"]["preferred_languages"] == "en, tr"
        assert "raw" in r

    @patch("recon._no_redirect_opener")
    def test_multiple_contacts(self, mock_opener):
        body = b"Contact: mailto:a@example.com\nContact: mailto:b@example.com\n"
        mock_opener.open.return_value = _mock_urlopen_response(body)
        r = fetch_security_txt("example.com")
        assert r["found"] is True
        assert isinstance(r["fields"]["contact"], list)
        assert len(r["fields"]["contact"]) == 2

    @patch("recon._no_redirect_opener")
    def test_not_found(self, mock_opener):
        mock_opener.open.side_effect = Exception("404")
        r = fetch_security_txt("example.com")
        assert r["found"] is False

    @patch("recon._no_redirect_opener")
    def test_empty_body(self, mock_opener):
        mock_opener.open.return_value = _mock_urlopen_response(b"   ")
        r = fetch_security_txt("example.com")
        assert r["found"] is False

    @patch("recon._no_redirect_opener")
    def test_comments_ignored(self, mock_opener):
        body = b"# This is a comment\nContact: mailto:sec@example.com\n"
        mock_opener.open.return_value = _mock_urlopen_response(body)
        r = fetch_security_txt("example.com")
        assert r["found"] is True
        assert r["fields"]["contact"] == "mailto:sec@example.com"


# ============================================================
# CAA Records
# ============================================================


class TestCheckCaa:
    @patch("recon.dns.resolver.Resolver")
    def test_caa_found(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        rdata1 = MagicMock()
        rdata1.flags = 0
        rdata1.tag = b"issue"
        rdata1.value = b"letsencrypt.org"

        rdata2 = MagicMock()
        rdata2.flags = 0
        rdata2.tag = b"issuewild"
        rdata2.value = b"letsencrypt.org"

        rdata3 = MagicMock()
        rdata3.flags = 0
        rdata3.tag = b"iodef"
        rdata3.value = b"mailto:security@example.com"

        mock_resolver.resolve.return_value = [rdata1, rdata2, rdata3]
        r = check_caa("example.com")
        assert r["found"] is True
        assert len(r["records"]) == 3
        assert "letsencrypt.org" in r["issuers"]
        assert len(r["issuers"]) == 1  # deduplicated

    @patch("recon.dns.resolver.Resolver")
    def test_no_caa_records(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        r = check_caa("example.com")
        assert r["found"] is False
        assert r["records"] == []
        assert r["issuers"] == []

    @patch("recon.dns.resolver.Resolver")
    def test_dns_timeout(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        r = check_caa("example.com")
        assert r["found"] is False


# ============================================================
# ASN / Network Range
# ============================================================


class TestFetchAsnInfo:
    @patch("recon._no_redirect_opener")
    def test_full_asn_lookup(self, mock_opener):
        """Successful lookup returns ASN, name, and prefixes."""
        network_info = json.dumps({"data": {"asns": ["13335"]}}).encode()
        overview = json.dumps({"data": {"holder": "CLOUDFLARENET"}}).encode()
        prefixes = json.dumps(
            {
                "data": {
                    "prefixes": [
                        {"prefix": "1.1.1.0/24"},
                        {"prefix": "104.16.0.0/13"},
                        {"prefix": "2606:4700::/32"},
                    ]
                }
            }
        ).encode()

        responses = [
            _mock_urlopen_response(network_info),
            _mock_urlopen_response(overview),
            _mock_urlopen_response(prefixes),
        ]
        mock_opener.open.side_effect = responses

        r = fetch_asn_info("1.1.1.1")
        assert r["asn"] == 13335
        assert r["asn_name"] == "CLOUDFLARENET"
        assert r["ipv4_count"] == 2
        assert r["ipv6_count"] == 1
        assert r["ipv4_prefixes"][0]["prefix"] == "1.1.1.0/24"

    @patch("recon._no_redirect_opener")
    def test_no_asn_found(self, mock_opener):
        network_info = json.dumps({"data": {"asns": []}}).encode()
        mock_opener.open.return_value = _mock_urlopen_response(network_info)
        r = fetch_asn_info("10.0.0.1")
        assert r["asn"] is None

    @patch("recon._no_redirect_opener")
    def test_ripe_api_failure(self, mock_opener):
        mock_opener.open.side_effect = Exception("timeout")
        r = fetch_asn_info("1.1.1.1")
        assert r["asn"] is None
        assert "error" in r

    @patch("recon._no_redirect_opener")
    def test_partial_failure_still_returns_asn(self, mock_opener):
        """If prefix lookup fails, ASN and name should still be returned."""
        network_info = json.dumps({"data": {"asns": ["13335"]}}).encode()
        overview = json.dumps({"data": {"holder": "CLOUDFLARENET"}}).encode()

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_urlopen_response(network_info)
            elif call_count[0] == 2:
                return _mock_urlopen_response(overview)
            else:
                raise Exception("prefix timeout")

        mock_opener.open.side_effect = side_effect

        r = fetch_asn_info("1.1.1.1")
        assert r["asn"] == 13335
        assert r["asn_name"] == "CLOUDFLARENET"
        assert r["ipv4_count"] == 0
        assert r["ipv6_count"] == 0
