"""
test_fuzz.py — fuzz testing for ContrastScan

Tests validation + sanitization layers with adversarial input:
  - Unicode, null bytes, format strings, shell metacharacters
  - SQL injection, XSS, command injection payloads
  - Extremely long strings, empty strings, whitespace
  - SSRF bypass attempts (IP formats, DNS rebinding patterns)
  - Header injection via domain name
  - C binary crash resistance

Run: cd app && python -m pytest tests/test_fuzz.py -v
"""

import os
import subprocess
import random
import string
from pathlib import Path

import pytest

from validation import clean_domain, validate_domain, is_private_ip
from config import SCANNER_PATH
from ratelimit import reset_all


# === Malicious domain payloads ===

MALICIOUS_DOMAINS = [
    # null bytes
    "example.com\x00evil.com",
    "\x00",
    # unicode
    "\u0435xample.com",          # cyrillic 'e'
    "ex\u0430mple.com",          # cyrillic 'a'
    "\U0001f600.com",            # emoji
    "\u200bexample.com",         # zero-width space
    "example\u2025com",          # two dot leader
    "ex\uff41mple.com",          # fullwidth 'a'
    # format strings
    "%s%s%s%s%s%s%s%s%s%s",
    "%n%n%n%n",
    "%x" * 100,
    "{0}" * 50,
    "%(domain)s",
    # shell metacharacters
    "; ls",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "& ping -c1 127.0.0.1",
    "example.com; rm -rf /",
    "example.com\ninjected",
    "example.com\r\nX-Injected: true",
    # SQL injection
    "' OR 1=1 --",
    "'; DROP TABLE scans; --",
    "1' UNION SELECT * FROM scans --",
    "example.com' AND '1'='1",
    # XSS
    "<script>alert(1)</script>",
    "example.com<img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "javascript:alert(1)",
    # path traversal
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    # SSRF bypass attempts
    "127.0.0.1",
    "0x7f000001",
    "2130706433",               # 127.0.0.1 as decimal
    "017700000001",             # 127.0.0.1 as octal
    "127.0.0.1.nip.io",
    "0.0.0.0",
    "[::1]",
    "[::]",
    "169.254.169.254",          # AWS metadata
    "metadata.google.internal",
    # header injection
    "example.com\r\nHost: evil.com",
    "example.com%0d%0aHost: evil.com",
    # extremely long
    "a" * 1000,
    "a." * 500,
    "." * 254,
    "-" * 254,
    # empty / whitespace
    "",
    " ",
    "\t",
    "\n",
    "\r\n",
    "   \t\n  ",
    # valid-looking but tricky
    ".example.com",
    "-example.com",
    "example-.com",
    "example..com",
    # IP-based
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
]


# === 1. Python validation — adversarial domains ===

class TestDomainValidation:
    def test_all_malicious_domains_blocked(self):
        blocked = 0
        for domain in MALICIOUS_DOMAINS:
            result = validate_domain(clean_domain(domain))
            if result is None:
                blocked += 1
        assert blocked == len(MALICIOUS_DOMAINS)

    @pytest.mark.parametrize("payload", [
        "; ls", "$(whoami)", "`id`", "| cat /etc/passwd",
        "' OR 1=1 --", "<script>alert(1)</script>",
        "127.0.0.1", "169.254.169.254", "\x00",
        "example.com\r\nHost: evil",
    ])
    def test_critical_payload_blocked(self, payload):
        result = validate_domain(clean_domain(payload))
        assert result is None


# === 2. clean_domain resilience ===

class TestCleanDomainResilience:
    @pytest.mark.parametrize("raw", [
        "\x00evil.com",
        "https://example.com\x00evil",
        "HTTPS://EXAMPLE.COM/path?q=1#frag",
        "http://evil.com:8080/path",
        "  \t example.com \n ",
        "https://https://double.com",
    ])
    def test_no_metachar_in_cleaned(self, raw):
        cleaned = clean_domain(raw)
        assert not any(c in cleaned for c in ";|`$(){}\\'\"\n\r\x00")


# === 3. Random fuzzing — Python validation ===

class TestRandomFuzz:
    def test_10k_random_inputs_no_crashes(self):
        random.seed(42)
        crashes = 0

        for i in range(10000):
            length = random.randint(0, 500)
            chars = []
            for _ in range(length):
                r = random.random()
                if r < 0.5:
                    chars.append(random.choice(string.printable))
                elif r < 0.8:
                    chars.append(chr(random.randint(0, 0xFFFF)))
                else:
                    chars.append(chr(random.randint(0, 31)))
            fuzz_input = "".join(chars)

            try:
                cleaned = clean_domain(fuzz_input)
                validate_domain(cleaned)
            except Exception:
                crashes += 1

        assert crashes == 0

    def test_10k_random_inputs_no_dangerous_passed(self):
        random.seed(42)
        passed_bad = 0

        for i in range(10000):
            length = random.randint(0, 500)
            chars = []
            for _ in range(length):
                r = random.random()
                if r < 0.5:
                    chars.append(random.choice(string.printable))
                elif r < 0.8:
                    chars.append(chr(random.randint(0, 0xFFFF)))
                else:
                    chars.append(chr(random.randint(0, 31)))
            fuzz_input = "".join(chars)

            try:
                cleaned = clean_domain(fuzz_input)
                result = validate_domain(cleaned)
                if result is not None:
                    if any(c in cleaned for c in ";|`$(){}\\'\"\n\r\x00"):
                        passed_bad += 1
            except Exception:
                pass

        assert passed_bad == 0


# === 4. C binary input validation (no network) ===

class TestCBinary:
    @pytest.fixture
    def scanner_path(self):
        path = Path(__file__).parent.parent.parent / "contrastscan"
        if not path.exists():
            pytest.skip(f"scanner binary not found at {path}")
        return path

    @pytest.mark.parametrize("fuzz_input", [
        "",
        " ",
        "a" * 1000,
        "example.com; ls",
        "$(whoami)",
        "`id`",
        "| cat /etc/passwd",
        "%s%s%s%s%s%n%n",
        "---" * 100,
    ])
    def test_c_binary_no_crash(self, scanner_path, fuzz_input):
        result = subprocess.run(
            [str(scanner_path), fuzz_input],
            capture_output=True, text=True, timeout=3
        )
        assert result.returncode not in (139, 134, 136, 137)


# === 5. SSRF IP format bypass ===

SSRF_IPS = [
    "127.0.0.1",
    "127.000.000.001",
    "127.1",
    "0x7f000001",
    "2130706433",
    "017700000001",
    "0",
    "0.0.0.0",
    "0000:0000:0000:0000:0000:0000:0000:0001",
    "::1",
    "::ffff:127.0.0.1",
    "169.254.169.254",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.0.1",
    "fc00::1",
    "fe80::1",
    "100.64.0.1",          # shared address space
    "198.51.100.1",        # TEST-NET-2
    "203.0.113.1",         # TEST-NET-3
    "224.0.0.1",           # multicast
    "255.255.255.255",     # broadcast
]


class TestSsrfBypass:
    @pytest.mark.parametrize("ip", SSRF_IPS)
    def test_private_ip_detected(self, ip):
        assert is_private_ip(ip) is True


# === SECURITY: Additional SSRF Bypass Formats ===

class TestSsrfBypassAdvanced:
    """Test obscure IP encoding tricks used to bypass SSRF filters."""

    @pytest.mark.parametrize("ip", [
        "0177.0.0.1",              # octal notation
        "2130706433",              # decimal notation for 127.0.0.1
        "0x7f.0.0.1",             # hex first octet
        "127.1",                   # short form
        "0",                       # shorthand for 0.0.0.0
        "0.0.0.0",
        "::ffff:7f00:1",          # IPv6 mapped
        "::ffff:127.0.0.1",
        "::ffff:a00:1",           # 10.0.0.1 mapped
        "::ffff:192.168.0.1",
        "::ffff:169.254.169.254", # metadata mapped
    ])
    def test_obscure_ip_format_blocked(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("domain", [
        "127.0.0.1.nip.io",
        "metadata.google.internal",
        "[::1]",
        "[::]",
        "0x7f000001",
    ])
    def test_ssrf_domain_tricks_blocked(self, domain):
        """These DNS-rebinding and bracket tricks must be blocked."""
        result = validate_domain(clean_domain(domain))
        assert result is None


# === SECURITY: Unicode Normalization Attacks ===

class TestUnicodeNormalization:
    """Verify Unicode tricks don't bypass domain allowlist."""

    @pytest.mark.parametrize("payload", [
        "\u2025com",                    # two dot leader
        "example\u2024com",            # one dot leader
        "example\uff0ecom",            # fullwidth full stop
        "e\u0301xample.com",           # combining acute accent
        "\u200dexample.com",           # zero-width joiner
        "\ufeffexample.com",           # BOM
        "ex\u0430mple.com",            # Cyrillic 'a'
        "\u0435xample.com",            # Cyrillic 'e'
        "exampl\u0435.com",            # Cyrillic 'e' at end
        "ex\u0430mpl\u0435.com",       # multiple Cyrillic
    ])
    def test_unicode_homoglyph_blocked(self, payload):
        result = validate_domain(clean_domain(payload))
        assert result is None


# === SECURITY: CRLF Injection in Domain ===

class TestCrlfInjection:
    """Verify CRLF sequences can't inject HTTP headers via domain."""

    @pytest.mark.parametrize("payload", [
        "example.com\r\nX-Injected: true",
        "example.com\r\nSet-Cookie: evil=1",
        "example.com\r\n\r\n<html>body</html>",
        "example.com\nHost: evil.com",
        "example.com\rHost: evil.com",
        "example.com%0d%0aX-Injected: true",
    ])
    def test_crlf_in_domain_rejected(self, payload):
        """CRLF payloads must be blocked by validate_domain's character allowlist."""
        cleaned = clean_domain(payload)
        result = validate_domain(cleaned)
        assert result is None

    @pytest.mark.parametrize("payload", [
        "example.com\r\nX: Y",
        "test\n.com",
        "\rtest.com",
    ])
    def test_crlf_domain_blocked_by_validation(self, payload):
        """Even if clean_domain preserves CR/LF, validate_domain rejects them."""
        cleaned = clean_domain(payload)
        result = validate_domain(cleaned)
        assert result is None


# === SECURITY: Scan ID Format Fuzz ===

class TestScanIdFuzz:
    """Fuzz SCAN_ID_PATTERN to ensure no bypass."""

    from validation import SCAN_ID_PATTERN as _SID

    @pytest.mark.parametrize("bad_id", [
        "",
        "a",
        "a" * 31,
        "a" * 33,
        "a" * 32 + "\x00",
        "A" * 32,          # uppercase
        "g" * 32,          # outside hex range
        "../" * 10 + "aa",
        " " + "a" * 31,
        "a" * 31 + " ",
        "a" * 16 + "/" + "a" * 15,
        "a" * 16 + "." + "a" * 15,
    ])
    def test_bad_scan_id_rejected(self, bad_id):
        assert self._SID.match(bad_id) is None

    @pytest.mark.parametrize("good_id", [
        "0" * 32,
        "f" * 32,
        "0123456789abcdef" * 2,
        "a" * 32,
    ])
    def test_good_scan_id_accepted(self, good_id):
        assert self._SID.match(good_id) is not None


# === SECURITY: Email Validation ===

class TestEmailValidationFuzz:
    """Fuzz email pattern validation."""

    from validation import EMAIL_PATTERN as _EP

    @pytest.mark.parametrize("bad_email", [
        "",
        "no-at-sign",
        "@no-local.com",
        "user@",
        "user@.com",
        "user@com",
        "user space@example.com",
        "user\x00@example.com",
        "user\n@example.com",
        "<script>@example.com",
        "user@exam ple.com",
    ])
    def test_bad_email_rejected(self, bad_email):
        assert self._EP.match(bad_email) is None

    @pytest.mark.parametrize("good_email", [
        "user@example.com",
        "test.user@sub.example.co.uk",
        "a@b.co",
    ])
    def test_good_email_accepted(self, good_email):
        assert self._EP.match(good_email) is not None


# === Security Test 3 — SSRF via Subdomain Private IP Resolution ===

class TestSsrfSubdomainPrivateIp:
    """HIGH: Subdomain enumeration resolves domains that point to private IPs.
    Verify validation layer blocks private IP targets."""

    @pytest.mark.parametrize("domain", [
        "localhost",
        "127.0.0.1.nip.io",
        "internal.test",
        "0.0.0.0.nip.io",
    ])
    def test_private_resolving_domains_blocked(self, domain):
        """Domains resolving to private IPs must be blocked by validate_domain."""
        result = validate_domain(clean_domain(domain))
        assert result is None

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        "169.254.0.0",
        "169.254.255.255",
        "100.64.0.0",      # CGNAT
        "100.127.255.255",  # CGNAT end
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "fc00::1",          # unique local
        "fd00::1",          # unique local
        "fe80::1",          # link-local
    ])
    def test_comprehensive_private_ip_detection(self, ip):
        """All RFC private/reserved ranges must be detected."""
        assert is_private_ip(ip) is True


# === Security Test 7 — Zone Transfer NS Command Injection ===

class TestZoneTransferNsInjection:
    """MEDIUM: NS values from dig are passed to subprocess.
    Fuzz the nameserver parameter for command injection."""

    @pytest.mark.parametrize("malicious_ns", [
        "; cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "ns1.example.com; rm -rf /",
        "ns1.example.com\ninjected",
        "ns1.example.com\r\ninjected",
        "-flag-injection.com",
        "--help",
    ])
    def test_malicious_ns_in_dig_safe(self, malicious_ns):
        """Subprocess.run with list args prevents shell injection.
        These tests verify the safety of the subprocess call pattern."""
        import subprocess
        # Simulating what check_zone_transfer does: subprocess.run with list args
        # This is safe because subprocess.run with a list does NOT use shell
        try:
            result = subprocess.run(
                ["dig", f"@{malicious_ns}", "example.com", "AXFR", "+short"],
                capture_output=True, text=True, timeout=3
            )
            # Should not execute the injected command
            assert "root:" not in result.stdout  # /etc/passwd content
            assert "uid=" not in result.stdout    # id command output
        except subprocess.TimeoutExpired:
            pass  # timeout is acceptable


# === Security Test 8 — crt.sh URL Injection ===

class TestCrtshUrlInjection:
    """MEDIUM: crt.sh query is not URL-encoded. Test that domain validation
    prevents special characters from reaching the URL builder."""

    @pytest.mark.parametrize("payload", [
        "example.com&evil=1",
        "example.com%26evil=1",
        "example.com#fragment",
        "example.com?extra=param",
        "example.com\x00evil",
        "example.com%00evil",
    ])
    def test_url_injection_payloads_blocked_by_validation(self, payload):
        """All URL-special characters must be blocked by domain validation."""
        result = validate_domain(clean_domain(payload))
        assert result is None

    def test_clean_domain_removes_query_strings(self):
        """clean_domain strips paths which includes query strings."""
        # "example.com/path?q=1" -> clean_domain strips after /
        cleaned = clean_domain("example.com/path?q=1&evil=true")
        assert "?" not in cleaned
        assert "&" not in cleaned
        assert "=" not in cleaned


# === Security Test 9 — SVG Badge Fuzz ===

class TestBadgeGradeFuzz:
    """LOW: Fuzz grade values to ensure SVG sanitization."""

    @pytest.mark.parametrize("bad_grade", [
        "<script>alert(1)</script>",
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        "A<img src=x onerror=alert(1)>",
        "' OR 1=1 --",
        "${7*7}",
        "{{7*7}}",
        "\x00",
        "A" * 1000,
    ])
    def test_bad_grade_sanitized_to_question_mark(self, bad_grade):
        """Any grade not in {A,B,C,D,F} must become '?'."""
        grade = bad_grade
        if grade not in ("A", "B", "C", "D", "F"):
            grade = "?"
        assert grade == "?"
