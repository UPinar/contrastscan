/*
 * test_scoring.c — unit tests for contrastscan scoring and parsing functions
 *
 * Tests functions with no network dependency:
 *   - calc_grade()         — score → grade conversion
 *   - header_callback()    — HTTP header line parsing
 *   - header scoring       — score based on found header count
 *   - SSL scoring          — TLS version, cipher, cert scoring
 *
 * Derleme:
 *   gcc -Wall -Wextra -o test_scoring tests/test_scoring.c -lcjson
 *
 * Run:
 *   ./test_scoring
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ======================================
 *  Functions under test are copied here
 *  (excluding those with network dependency)
 * ====================================== */

/* --- calc_grade --- */

static const char *calc_grade(int score, int max)
{
  int pct = (score * 100) / max;
  if (pct >= 90) return "A";
  if (pct >= 75) return "B";
  if (pct >= 60) return "C";
  if (pct >= 40) return "D";
  return "F";
}

/* --- header_callback (simulated) --- */

static const char *security_headers[] = {
  "content-security-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy"
};
#define NUM_HEADERS 6

static int hdr_found[NUM_HEADERS] = {0};

static size_t header_callback(char *buffer, size_t size, size_t nitems,
                              void *userdata)
{
  (void)userdata;
  size_t total = size * nitems;
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    size_t len = strlen(security_headers[i]);
    if (total > len + 1 &&
        strncasecmp(buffer, security_headers[i], len) == 0 &&
        buffer[len] == ':')
    {
      hdr_found[i] = 1;
    }
  }
  return total;
}

/* --- header scoring --- */

static int calc_header_score(int found_count)
{
  return found_count * 5;
}

/* --- SSL/TLS scoring helpers --- */

static int calc_tls_score(const char *tls_version)
{
  if (strcmp(tls_version, "TLSv1.3") == 0) return 9;
  if (strcmp(tls_version, "TLSv1.2") == 0) return 6;
  if (strcmp(tls_version, "TLSv1.1") == 0) return 2;
  return 0;
}

static int calc_cert_score(int cert_valid, int days_remaining)
{
  if (cert_valid && days_remaining > 30) return 8;
  if (cert_valid && days_remaining > 7)  return 5;
  if (cert_valid)                        return 2;
  return 0;
}

/* mirrors the combined logic in contrastscan.c:
 * cert_valid = (days_remaining > 0 && chain_valid) ? 1 : 0 */
static int calc_cert_valid(int days_remaining, int chain_valid)
{
  return (days_remaining > 0 && chain_valid) ? 1 : 0;
}

static int calc_cipher_score(const char *cipher)
{
  if (!cipher) return 0;
  if (strstr(cipher, "AES256") || strstr(cipher, "AES_256") ||
      strstr(cipher, "CHACHA20"))
    return 8;
  if (strstr(cipher, "AES128") || strstr(cipher, "AES_128"))
    return 6;
  return 2;
}

/* ======================================
 *  TEST FRAMEWORK (minimal)
 * ====================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
  tests_run++; \
  printf("  %-50s ", name); \
} while(0)

#define PASS() do { \
  tests_passed++; \
  printf("\033[32mPASS\033[0m\n"); \
} while(0)

#define FAIL(msg) do { \
  tests_failed++; \
  printf("\033[31mFAIL\033[0m — %s\n", msg); \
} while(0)

#define ASSERT_STR_EQ(a, b) do { \
  if (strcmp(a, b) != 0) { FAIL("expected " #b); return; } \
} while(0)

#define ASSERT_INT_EQ(a, b) do { \
  if ((a) != (b)) { \
    char _msg[128]; \
    snprintf(_msg, sizeof(_msg), "expected %d, got %d", (b), (a)); \
    FAIL(_msg); return; \
  } \
} while(0)

/* ======================================
 *  TESTS: calc_grade
 * ====================================== */

void test_grade_boundaries(void)
{
  TEST("calc_grade: A at 90%");
  ASSERT_STR_EQ(calc_grade(90, 100), "A"); PASS();

  TEST("calc_grade: A at 100%");
  ASSERT_STR_EQ(calc_grade(99, 99), "A"); PASS();

  TEST("calc_grade: A at 91/100");
  ASSERT_STR_EQ(calc_grade(91, 100), "A"); PASS();

  TEST("calc_grade: B at 89/100");
  ASSERT_STR_EQ(calc_grade(89, 100), "B"); PASS();

  TEST("calc_grade: B at 75%");
  ASSERT_STR_EQ(calc_grade(75, 100), "B"); PASS();

  TEST("calc_grade: B at 89%");
  ASSERT_STR_EQ(calc_grade(89, 100), "B"); PASS();

  TEST("calc_grade: C at 60%");
  ASSERT_STR_EQ(calc_grade(60, 100), "C"); PASS();

  TEST("calc_grade: C at 74%");
  ASSERT_STR_EQ(calc_grade(74, 100), "C"); PASS();

  TEST("calc_grade: D at 40%");
  ASSERT_STR_EQ(calc_grade(40, 100), "D"); PASS();

  TEST("calc_grade: D at 59%");
  ASSERT_STR_EQ(calc_grade(59, 100), "D"); PASS();

  TEST("calc_grade: F at 39%");
  ASSERT_STR_EQ(calc_grade(39, 100), "F"); PASS();

  TEST("calc_grade: F at 0%");
  ASSERT_STR_EQ(calc_grade(0, 100), "F"); PASS();

  TEST("calc_grade: F at 0/99 (real max)");
  ASSERT_STR_EQ(calc_grade(0, 99), "F"); PASS();

  TEST("calc_grade: score > max");
  ASSERT_STR_EQ(calc_grade(150, 99), "A"); PASS();

  TEST("calc_grade: negative score");
  ASSERT_STR_EQ(calc_grade(-10, 99), "F"); PASS();

  TEST("calc_grade: boundary 89/99 → B (int div: 89)");
  ASSERT_STR_EQ(calc_grade(89, 99), "B"); PASS();

  TEST("calc_grade: boundary 90/99 → A (int div: 90)");
  ASSERT_STR_EQ(calc_grade(90, 99), "A"); PASS();

  TEST("calc_grade: max=1, score=1 → A");
  ASSERT_STR_EQ(calc_grade(1, 1), "A"); PASS();

  TEST("calc_grade: max=1, score=0 → F");
  ASSERT_STR_EQ(calc_grade(0, 1), "F"); PASS();
}

void test_grade_real_scores(void)
{
  /* Real scan results */
  TEST("calc_grade: contrastcyber.com 95/100");
  ASSERT_STR_EQ(calc_grade(95, 100), "A"); PASS();

  TEST("calc_grade: good site 80/100");
  ASSERT_STR_EQ(calc_grade(80, 100), "B"); PASS();

  TEST("calc_grade: google.com 48/100");
  ASSERT_STR_EQ(calc_grade(48, 100), "D"); PASS();

  TEST("calc_grade: expired.badssl.com 15/100");
  ASSERT_STR_EQ(calc_grade(15, 100), "F"); PASS();

  TEST("calc_grade: nonexistent 0/100");
  ASSERT_STR_EQ(calc_grade(0, 100), "F"); PASS();
}

/* ======================================
 *  TESTS: header_callback
 * ====================================== */

static void reset_found(void)
{
  memset(hdr_found, 0, sizeof(hdr_found));
}

void test_header_callback_basic(void)
{
  reset_found();

  TEST("header_callback: exact match lowercase");
  char h1[] = "content-security-policy: default-src 'self'\r\n";
  header_callback(h1, 1, strlen(h1), NULL);
  ASSERT_INT_EQ(hdr_found[0], 1); PASS();

  TEST("header_callback: case insensitive");
  reset_found();
  char h2[] = "Strict-Transport-Security: max-age=31536000\r\n";
  header_callback(h2, 1, strlen(h2), NULL);
  ASSERT_INT_EQ(hdr_found[1], 1); PASS();

  TEST("header_callback: ALL CAPS");
  reset_found();
  char h3[] = "X-FRAME-OPTIONS: DENY\r\n";
  header_callback(h3, 1, strlen(h3), NULL);
  ASSERT_INT_EQ(hdr_found[3], 1); PASS();

  TEST("header_callback: x-content-type-options");
  reset_found();
  char h4[] = "X-Content-Type-Options: nosniff\r\n";
  header_callback(h4, 1, strlen(h4), NULL);
  ASSERT_INT_EQ(hdr_found[2], 1); PASS();
}

void test_header_callback_edge_cases(void)
{
  TEST("header_callback: no colon → no match");
  reset_found();
  char h1[] = "content-security-policy default-src\r\n";
  header_callback(h1, 1, strlen(h1), NULL);
  ASSERT_INT_EQ(hdr_found[0], 0); PASS();

  TEST("header_callback: HTTP status line → no match");
  reset_found();
  char h2[] = "HTTP/1.1 200 OK\r\n";
  header_callback(h2, 1, strlen(h2), NULL);
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    if (hdr_found[i]) { FAIL("matched status line"); return; }
  }
  PASS();

  TEST("header_callback: empty string");
  reset_found();
  char h3[] = "";
  header_callback(h3, 1, 0, NULL);
  ASSERT_INT_EQ(hdr_found[0], 0); PASS();

  TEST("header_callback: just colon");
  reset_found();
  char h4[] = ":\r\n";
  header_callback(h4, 1, strlen(h4), NULL);
  ASSERT_INT_EQ(hdr_found[0], 0); PASS();

  TEST("header_callback: partial header name");
  reset_found();
  char h5[] = "content-security: value\r\n";
  header_callback(h5, 1, strlen(h5), NULL);
  ASSERT_INT_EQ(hdr_found[0], 0); PASS();

  TEST("header_callback: header name with extra prefix");
  reset_found();
  char h6[] = "x-content-security-policy: value\r\n";
  header_callback(h6, 1, strlen(h6), NULL);
  ASSERT_INT_EQ(hdr_found[0], 0); PASS();

  TEST("header_callback: exact header name only, no value");
  reset_found();
  char h7[] = "referrer-policy:\r\n";
  header_callback(h7, 1, strlen(h7), NULL);
  ASSERT_INT_EQ(hdr_found[4], 1); PASS();

  TEST("header_callback: multiple calls accumulate");
  reset_found();
  char a[] = "content-security-policy: x\r\n";
  char b[] = "x-frame-options: DENY\r\n";
  char c[] = "referrer-policy: no-referrer\r\n";
  header_callback(a, 1, strlen(a), NULL);
  header_callback(b, 1, strlen(b), NULL);
  header_callback(c, 1, strlen(c), NULL);
  ASSERT_INT_EQ(hdr_found[0], 1);
  ASSERT_INT_EQ(hdr_found[1], 0); /* strict-transport-security not sent */
  ASSERT_INT_EQ(hdr_found[3], 1);
  ASSERT_INT_EQ(hdr_found[4], 1);
  PASS();

  TEST("header_callback: size=2, nitems=half");
  reset_found();
  char h8[] = "permissions-policy: geolocation=()\r\n";
  header_callback(h8, 2, strlen(h8) / 2, NULL);
  ASSERT_INT_EQ(hdr_found[5], 1); PASS();

  TEST("header_callback: return value equals total");
  char h9[] = "x-frame-options: SAMEORIGIN\r\n";
  size_t ret = header_callback(h9, 1, strlen(h9), NULL);
  ASSERT_INT_EQ((int)ret, (int)strlen(h9)); PASS();
}

void test_header_callback_missing(void)
{
  TEST("header_callback: duplicate header → still 1");
  reset_found();
  char d1[] = "x-frame-options: DENY\r\n";
  char d2[] = "x-frame-options: SAMEORIGIN\r\n";
  header_callback(d1, 1, strlen(d1), NULL);
  header_callback(d2, 1, strlen(d2), NULL);
  ASSERT_INT_EQ(hdr_found[3], 1); PASS();

  TEST("header_callback: space before colon → no match");
  reset_found();
  char s1[] = "x-frame-options : DENY\r\n";
  header_callback(s1, 1, strlen(s1), NULL);
  ASSERT_INT_EQ(hdr_found[3], 0); PASS();

  TEST("header_callback: total == len+1 boundary → no match");
  reset_found();
  /* "x-frame-options" = 15 chars, total must be > 16 to match */
  /* send exactly 16 bytes: "x-frame-options:" */
  char b1[] = "x-frame-options:";
  header_callback(b1, 1, strlen(b1), NULL); /* strlen = 16, > 15+1=16 is false */
  ASSERT_INT_EQ(hdr_found[3], 0); PASS();

  TEST("header_callback: total == len+2 → match");
  reset_found();
  char b2[] = "x-frame-options: ";  /* 17 bytes, > 16 → true */
  header_callback(b2, 1, strlen(b2), NULL);
  ASSERT_INT_EQ(hdr_found[3], 1); PASS();

  TEST("header_callback: all 6 headers found");
  reset_found();
  char ha[] = "content-security-policy: x\r\n";
  char hb[] = "strict-transport-security: x\r\n";
  char hc[] = "x-content-type-options: nosniff\r\n";
  char hd[] = "x-frame-options: DENY\r\n";
  char he[] = "referrer-policy: no-referrer\r\n";
  char hf[] = "permissions-policy: geolocation=()\r\n";
  header_callback(ha, 1, strlen(ha), NULL);
  header_callback(hb, 1, strlen(hb), NULL);
  header_callback(hc, 1, strlen(hc), NULL);
  header_callback(hd, 1, strlen(hd), NULL);
  header_callback(he, 1, strlen(he), NULL);
  header_callback(hf, 1, strlen(hf), NULL);
  for (int i = 0; i < NUM_HEADERS; i++)
  {
    if (!hdr_found[i]) { FAIL("not all headers found"); return; }
  }
  PASS();

  TEST("header_callback: very long header line");
  reset_found();
  char long_hdr[1024];
  snprintf(long_hdr, sizeof(long_hdr), "content-security-policy: %0*d\r\n", 900, 0);
  header_callback(long_hdr, 1, strlen(long_hdr), NULL);
  ASSERT_INT_EQ(hdr_found[0], 1); PASS();
}

/* ======================================
 *  TESTS: header scoring
 * ====================================== */

void test_header_scoring(void)
{
  TEST("header_score: 0 found → 0");
  ASSERT_INT_EQ(calc_header_score(0), 0); PASS();

  TEST("header_score: 1 found → 5");
  ASSERT_INT_EQ(calc_header_score(1), 5); PASS();

  TEST("header_score: 2 found → 10");
  ASSERT_INT_EQ(calc_header_score(2), 10); PASS();

  TEST("header_score: 3 found → 15");
  ASSERT_INT_EQ(calc_header_score(3), 15); PASS();

  TEST("header_score: 4 found → 20");
  ASSERT_INT_EQ(calc_header_score(4), 20); PASS();

  TEST("header_score: 5 found → 25");
  ASSERT_INT_EQ(calc_header_score(5), 25); PASS();

  TEST("header_score: 6 found → 30 (full)");
  ASSERT_INT_EQ(calc_header_score(6), 30); PASS();
}

/* ======================================
 *  TESTS: TLS version scoring
 * ====================================== */

void test_tls_scoring(void)
{
  TEST("tls_score: TLSv1.3 → 9");
  ASSERT_INT_EQ(calc_tls_score("TLSv1.3"), 9); PASS();

  TEST("tls_score: TLSv1.2 → 6");
  ASSERT_INT_EQ(calc_tls_score("TLSv1.2"), 6); PASS();

  TEST("tls_score: TLSv1.1 → 2");
  ASSERT_INT_EQ(calc_tls_score("TLSv1.1"), 2); PASS();

  TEST("tls_score: TLSv1 → 0");
  ASSERT_INT_EQ(calc_tls_score("TLSv1"), 0); PASS();

  TEST("tls_score: SSLv3 → 0");
  ASSERT_INT_EQ(calc_tls_score("SSLv3"), 0); PASS();

  TEST("tls_score: empty string → 0");
  ASSERT_INT_EQ(calc_tls_score(""), 0); PASS();

  TEST("tls_score: unknown → 0");
  ASSERT_INT_EQ(calc_tls_score("TLSv1.4"), 0); PASS();
}

/* ======================================
 *  TESTS: certificate scoring
 * ====================================== */

void test_cert_scoring(void)
{
  TEST("cert_score: valid, 365 days → 8");
  ASSERT_INT_EQ(calc_cert_score(1, 365), 8); PASS();

  TEST("cert_score: valid, 31 days → 8");
  ASSERT_INT_EQ(calc_cert_score(1, 31), 8); PASS();

  TEST("cert_score: valid, 30 days (boundary) → 5");
  ASSERT_INT_EQ(calc_cert_score(1, 30), 5); PASS();

  TEST("cert_score: valid, 8 days → 5");
  ASSERT_INT_EQ(calc_cert_score(1, 8), 5); PASS();

  TEST("cert_score: valid, 7 days (boundary) → 2");
  ASSERT_INT_EQ(calc_cert_score(1, 7), 2); PASS();

  TEST("cert_score: valid, 1 day → 2");
  ASSERT_INT_EQ(calc_cert_score(1, 1), 2); PASS();

  TEST("cert_score: expired (0 days) → 0");
  ASSERT_INT_EQ(calc_cert_score(0, 0), 0); PASS();

  TEST("cert_score: expired negative days → 0");
  ASSERT_INT_EQ(calc_cert_score(0, -3999), 0); PASS();

  TEST("cert_score: invalid but positive days → 0");
  ASSERT_INT_EQ(calc_cert_score(0, 100), 0); PASS();

  TEST("cert_score: valid, exactly 0 days → 2");
  ASSERT_INT_EQ(calc_cert_score(1, 0), 2); PASS();
}

void test_cert_chain_validation(void)
{
  TEST("cert_valid: chain valid + 90 days → valid");
  ASSERT_INT_EQ(calc_cert_valid(90, 1), 1); PASS();

  TEST("cert_valid: chain valid + 0 days → invalid (expired)");
  ASSERT_INT_EQ(calc_cert_valid(0, 1), 0); PASS();

  TEST("cert_valid: chain valid + negative days → invalid");
  ASSERT_INT_EQ(calc_cert_valid(-100, 1), 0); PASS();

  TEST("cert_valid: chain INVALID + 90 days → invalid (self-signed)");
  ASSERT_INT_EQ(calc_cert_valid(90, 0), 0); PASS();

  TEST("cert_valid: chain INVALID + 0 days → invalid");
  ASSERT_INT_EQ(calc_cert_valid(0, 0), 0); PASS();

  TEST("cert_valid: chain valid + 1 day → valid");
  ASSERT_INT_EQ(calc_cert_valid(1, 1), 1); PASS();

  /* combined: self-signed cert with valid expiry → score 0 */
  TEST("cert_chain: self-signed 90d → cert_valid=0 → score 0");
  int cv = calc_cert_valid(90, 0);
  ASSERT_INT_EQ(calc_cert_score(cv, 90), 0); PASS();

  /* combined: trusted cert with valid expiry → score 8 */
  TEST("cert_chain: trusted 90d → cert_valid=1 → score 8");
  cv = calc_cert_valid(90, 1);
  ASSERT_INT_EQ(calc_cert_score(cv, 90), 8); PASS();

  /* combined: trusted cert expiring soon → score 5 */
  TEST("cert_chain: trusted 10d → cert_valid=1 → score 5");
  cv = calc_cert_valid(10, 1);
  ASSERT_INT_EQ(calc_cert_score(cv, 10), 5); PASS();

  /* combined: trusted cert expired → score 0 */
  TEST("cert_chain: trusted expired → cert_valid=0 → score 0");
  cv = calc_cert_valid(-5, 1);
  ASSERT_INT_EQ(calc_cert_score(cv, -5), 0); PASS();
}

/* ======================================
 *  TESTS: cipher scoring
 * ====================================== */

void test_cipher_scoring(void)
{
  TEST("cipher_score: TLS_AES_256_GCM_SHA384 → 8");
  ASSERT_INT_EQ(calc_cipher_score("TLS_AES_256_GCM_SHA384"), 8); PASS();

  TEST("cipher_score: ECDHE-RSA-AES256-GCM-SHA384 → 8");
  ASSERT_INT_EQ(calc_cipher_score("ECDHE-RSA-AES256-GCM-SHA384"), 8); PASS();

  TEST("cipher_score: TLS_CHACHA20_POLY1305_SHA256 → 8");
  ASSERT_INT_EQ(calc_cipher_score("TLS_CHACHA20_POLY1305_SHA256"), 8); PASS();

  TEST("cipher_score: TLS_AES_128_GCM_SHA256 → 6");
  ASSERT_INT_EQ(calc_cipher_score("TLS_AES_128_GCM_SHA256"), 6); PASS();

  TEST("cipher_score: ECDHE-RSA-AES128-SHA → 6");
  ASSERT_INT_EQ(calc_cipher_score("ECDHE-RSA-AES128-SHA"), 6); PASS();

  TEST("cipher_score: DES-CBC3-SHA (weak) → 2");
  ASSERT_INT_EQ(calc_cipher_score("DES-CBC3-SHA"), 2); PASS();

  TEST("cipher_score: RC4-SHA (weak) → 2");
  ASSERT_INT_EQ(calc_cipher_score("RC4-SHA"), 2); PASS();

  TEST("cipher_score: NULL → 0");
  ASSERT_INT_EQ(calc_cipher_score(NULL), 0); PASS();

  TEST("cipher_score: empty string → 2");
  ASSERT_INT_EQ(calc_cipher_score(""), 2); PASS();

  TEST("cipher_score: contains both AES128 and AES256 → 8 (AES256 wins)");
  ASSERT_INT_EQ(calc_cipher_score("AES256-AES128-COMBO"), 8); PASS();

  TEST("cipher_score: lowercase aes256 → 2 (strstr case-sensitive)");
  ASSERT_INT_EQ(calc_cipher_score("aes256-gcm"), 2); PASS();

  TEST("cipher_score: CHACHA200 substring → 8 (strstr matches CHACHA20 prefix)");
  ASSERT_INT_EQ(calc_cipher_score("CHACHA200"), 8); PASS();

  TEST("cipher_score: AES2560 substring → 8 (strstr matches AES256 prefix)");
  ASSERT_INT_EQ(calc_cipher_score("AES2560"), 8); PASS();
}

/* ======================================
 *  TESTS: DNS scoring
 * ====================================== */

static int calc_dns_score(int has_spf, int has_dmarc, int has_dkim)
{
  return (has_spf ? 7 : 0) + (has_dmarc ? 6 : 0) + (has_dkim ? 7 : 0);
}

void test_dns_scoring(void)
{
  TEST("dns_score: all present → 20");
  ASSERT_INT_EQ(calc_dns_score(1, 1, 1), 20); PASS();

  TEST("dns_score: none → 0");
  ASSERT_INT_EQ(calc_dns_score(0, 0, 0), 0); PASS();

  TEST("dns_score: SPF only → 7");
  ASSERT_INT_EQ(calc_dns_score(1, 0, 0), 7); PASS();

  TEST("dns_score: DMARC only → 6");
  ASSERT_INT_EQ(calc_dns_score(0, 1, 0), 6); PASS();

  TEST("dns_score: DKIM only → 7");
  ASSERT_INT_EQ(calc_dns_score(0, 0, 1), 7); PASS();

  TEST("dns_score: SPF + DMARC → 13");
  ASSERT_INT_EQ(calc_dns_score(1, 1, 0), 13); PASS();

  TEST("dns_score: SPF + DKIM → 14");
  ASSERT_INT_EQ(calc_dns_score(1, 0, 1), 14); PASS();

  TEST("dns_score: DMARC + DKIM → 13");
  ASSERT_INT_EQ(calc_dns_score(0, 1, 1), 13); PASS();
}

/* ======================================
 *  TESTS: combined SSL scoring
 * ====================================== */

void test_ssl_combined(void)
{
  TEST("ssl_combined: TLS1.3 + AES256 + valid 90d → 25");
  int score = calc_tls_score("TLSv1.3") + calc_cert_score(1, 90) + calc_cipher_score("TLS_AES_256_GCM_SHA384");
  ASSERT_INT_EQ(score, 25); PASS();

  TEST("ssl_combined: TLS1.2 + AES128 + valid 10d → 17");
  score = calc_tls_score("TLSv1.2") + calc_cert_score(1, 10) + calc_cipher_score("TLS_AES_128_GCM_SHA256");
  ASSERT_INT_EQ(score, 17); PASS();

  TEST("ssl_combined: TLS1.1 + weak + expired → 4");
  score = calc_tls_score("TLSv1.1") + calc_cert_score(0, -100) + calc_cipher_score("RC4-SHA");
  ASSERT_INT_EQ(score, 4); PASS();

  TEST("ssl_combined: TLS1.3 + AES256 + expired → 17");
  score = calc_tls_score("TLSv1.3") + calc_cert_score(0, -1) + calc_cipher_score("TLS_AES_256_GCM_SHA384");
  ASSERT_INT_EQ(score, 17); PASS();

  TEST("ssl_combined: all zero → 0");
  score = calc_tls_score("SSLv3") + calc_cert_score(0, 0) + calc_cipher_score(NULL);
  ASSERT_INT_EQ(score, 0); PASS();
}

/* ======================================
 *  TESTS: full grade integration
 * ====================================== */

void test_full_grade(void)
{
  TEST("full: perfect score 100/100 → A");
  int total = 30 + 25 + 20 + 10 + 5 + 5 + 5;
  ASSERT_STR_EQ(calc_grade(total, 100), "A"); PASS();

  TEST("full: headers=30 + ssl=25 + dns=0 + rest=20 → B");
  total = 30 + 25 + 0 + 10 + 5 + 5 + 0;
  ASSERT_STR_EQ(calc_grade(total, 100), "B"); PASS();

  TEST("full: headers=5 + ssl=25 + dns=14 + rest=10 → D");
  total = 5 + 25 + 14 + 10 + 0 + 0 + 0;
  ASSERT_STR_EQ(calc_grade(total, 100), "D"); PASS();

  TEST("full: all zero → F");
  ASSERT_STR_EQ(calc_grade(0, 100), "F"); PASS();

  TEST("full: headers=25 + ssl=25 + dns=20 + rest=20 → A");
  total = 25 + 25 + 20 + 10 + 5 + 5 + 0;
  ASSERT_STR_EQ(calc_grade(total, 100), "A"); PASS();
}

/* ======================================
 *  TESTS: redirect scoring
 * ====================================== */

static int calc_redirect_score(int redirects_to_https)
{
  return redirects_to_https ? 10 : 0;
}

void test_redirect_scoring(void)
{
  TEST("redirect_score: redirects → 10");
  ASSERT_INT_EQ(calc_redirect_score(1), 10); PASS();

  TEST("redirect_score: no redirect → 0");
  ASSERT_INT_EQ(calc_redirect_score(0), 0); PASS();
}

/* ======================================
 *  TESTS: disclosure scoring
 * ====================================== */

static int calc_disclosure_score(int server_exposed, int server_is_cdn,
                                 int powered_by_exposed)
{
  int score = 5;
  if (powered_by_exposed)
    score = 0;
  else if (server_exposed && !server_is_cdn)
    score = 2;
  return score;
}

/* --- CDN/bare-name detection (mirrors contrastscan.c logic) --- */

static int is_cdn_name(const char *server_value)
{
  const char *cdn_names[] = {"cloudflare", "fastly", "akamai", "varnish",
                              "cloudfront", "vercel", "netlify", "nginx",
                              "apache", "lighttpd", "litespeed", NULL};
  char lower[256];
  size_t slen = strlen(server_value);
  if (slen >= sizeof(lower)) slen = sizeof(lower) - 1;
  for (size_t i = 0; i < slen; i++)
    lower[i] = (server_value[i] >= 'A' && server_value[i] <= 'Z')
               ? server_value[i] + 32 : server_value[i];
  lower[slen] = '\0';

  for (int i = 0; cdn_names[i]; i++)
    if (strstr(lower, cdn_names[i]) && !strchr(lower, '/'))
      return 1;
  return 0;
}

void test_disclosure_scoring(void)
{
  TEST("disclosure: nothing exposed → 5");
  ASSERT_INT_EQ(calc_disclosure_score(0, 0, 0), 5); PASS();

  TEST("disclosure: server exposed (not CDN) → 2");
  ASSERT_INT_EQ(calc_disclosure_score(1, 0, 0), 2); PASS();

  TEST("disclosure: server exposed (CDN) → 5");
  ASSERT_INT_EQ(calc_disclosure_score(1, 1, 0), 5); PASS();

  TEST("disclosure: powered_by exposed → 0");
  ASSERT_INT_EQ(calc_disclosure_score(0, 0, 1), 0); PASS();

  TEST("disclosure: both exposed → 0");
  ASSERT_INT_EQ(calc_disclosure_score(1, 0, 1), 0); PASS();

  TEST("disclosure: both exposed + CDN → 0");
  ASSERT_INT_EQ(calc_disclosure_score(1, 1, 1), 0); PASS();
}

void test_cdn_name_matching(void)
{
  /* original CDN names */
  TEST("cdn_match: cloudflare → yes");
  ASSERT_INT_EQ(is_cdn_name("cloudflare"), 1); PASS();

  TEST("cdn_match: Cloudflare (mixed case) → yes");
  ASSERT_INT_EQ(is_cdn_name("Cloudflare"), 1); PASS();

  TEST("cdn_match: CLOUDFLARE (upper) → yes");
  ASSERT_INT_EQ(is_cdn_name("CLOUDFLARE"), 1); PASS();

  TEST("cdn_match: fastly → yes");
  ASSERT_INT_EQ(is_cdn_name("fastly"), 1); PASS();

  TEST("cdn_match: akamai → yes");
  ASSERT_INT_EQ(is_cdn_name("akamai"), 1); PASS();

  TEST("cdn_match: varnish → yes");
  ASSERT_INT_EQ(is_cdn_name("varnish"), 1); PASS();

  TEST("cdn_match: cloudfront → yes");
  ASSERT_INT_EQ(is_cdn_name("cloudfront"), 1); PASS();

  TEST("cdn_match: vercel → yes");
  ASSERT_INT_EQ(is_cdn_name("vercel"), 1); PASS();

  TEST("cdn_match: netlify → yes");
  ASSERT_INT_EQ(is_cdn_name("netlify"), 1); PASS();

  /* newly added bare server names */
  TEST("cdn_match: nginx → yes");
  ASSERT_INT_EQ(is_cdn_name("nginx"), 1); PASS();

  TEST("cdn_match: Nginx (mixed case) → yes");
  ASSERT_INT_EQ(is_cdn_name("Nginx"), 1); PASS();

  TEST("cdn_match: NGINX (upper) → yes");
  ASSERT_INT_EQ(is_cdn_name("NGINX"), 1); PASS();

  TEST("cdn_match: nginx/1.28.2 (with version) → no (version exposed)");
  ASSERT_INT_EQ(is_cdn_name("nginx/1.28.2"), 0); PASS();

  TEST("cdn_match: apache → yes");
  ASSERT_INT_EQ(is_cdn_name("apache"), 1); PASS();

  TEST("cdn_match: Apache/2.4.57 (with version) → no (version exposed)");
  ASSERT_INT_EQ(is_cdn_name("Apache/2.4.57"), 0); PASS();

  TEST("cdn_match: lighttpd → yes");
  ASSERT_INT_EQ(is_cdn_name("lighttpd"), 1); PASS();

  TEST("cdn_match: litespeed → yes");
  ASSERT_INT_EQ(is_cdn_name("litespeed"), 1); PASS();

  TEST("cdn_match: LiteSpeed (mixed case) → yes");
  ASSERT_INT_EQ(is_cdn_name("LiteSpeed"), 1); PASS();

  /* should NOT match */
  TEST("cdn_match: custom-server → no");
  ASSERT_INT_EQ(is_cdn_name("custom-server"), 0); PASS();

  TEST("cdn_match: gunicorn → no");
  ASSERT_INT_EQ(is_cdn_name("gunicorn"), 0); PASS();

  TEST("cdn_match: Microsoft-IIS/10.0 → no");
  ASSERT_INT_EQ(is_cdn_name("Microsoft-IIS/10.0"), 0); PASS();

  TEST("cdn_match: empty string → no");
  ASSERT_INT_EQ(is_cdn_name(""), 0); PASS();

  TEST("cdn_match: openresty → no");
  ASSERT_INT_EQ(is_cdn_name("openresty"), 0); PASS();

  /* integrated: nginx exposed → is_cdn=1 → disclosure score 5 */
  TEST("disclosure+cdn: nginx exposed → 5 (no penalty)");
  int cdn = is_cdn_name("nginx");
  ASSERT_INT_EQ(calc_disclosure_score(1, cdn, 0), 5); PASS();

  TEST("disclosure+cdn: Apache/2.4 exposed → 2 (version penalty)");
  cdn = is_cdn_name("Apache/2.4.57");
  ASSERT_INT_EQ(calc_disclosure_score(1, cdn, 0), 2); PASS();

  TEST("disclosure+cdn: gunicorn exposed → 2 (penalty)");
  cdn = is_cdn_name("gunicorn");
  ASSERT_INT_EQ(calc_disclosure_score(1, cdn, 0), 2); PASS();

  TEST("disclosure+cdn: nginx + powered_by → 0 (powered_by overrides)");
  cdn = is_cdn_name("nginx");
  ASSERT_INT_EQ(calc_disclosure_score(1, cdn, 1), 0); PASS();
}

/* ======================================
 *  TESTS: cookie scoring
 * ====================================== */

static int calc_cookie_score(int count, int total_flags)
{
  if (count == 0) return 5;
  int max_flags = count * 3;
  return (total_flags * 5) / max_flags;
}

void test_cookie_scoring(void)
{
  TEST("cookie: no cookies → 5");
  ASSERT_INT_EQ(calc_cookie_score(0, 0), 5); PASS();

  TEST("cookie: 1 cookie, all 3 flags → 5");
  ASSERT_INT_EQ(calc_cookie_score(1, 3), 5); PASS();

  TEST("cookie: 1 cookie, 0 flags → 0");
  ASSERT_INT_EQ(calc_cookie_score(1, 0), 0); PASS();

  TEST("cookie: 1 cookie, 2 flags → 3");
  ASSERT_INT_EQ(calc_cookie_score(1, 2), 3); PASS();

  TEST("cookie: 1 cookie, 1 flag → 1");
  ASSERT_INT_EQ(calc_cookie_score(1, 1), 1); PASS();

  TEST("cookie: 2 cookies, all 6 flags → 5");
  ASSERT_INT_EQ(calc_cookie_score(2, 6), 5); PASS();

  TEST("cookie: 2 cookies, 3 flags → 2");
  ASSERT_INT_EQ(calc_cookie_score(2, 3), 2); PASS();

  TEST("cookie: 2 cookies, 1 flag → 0");
  ASSERT_INT_EQ(calc_cookie_score(2, 1), 0); PASS();

  TEST("cookie: 3 cookies, 0 flags → 0");
  ASSERT_INT_EQ(calc_cookie_score(3, 0), 0); PASS();

  TEST("cookie: 3 cookies, all 9 flags → 5");
  ASSERT_INT_EQ(calc_cookie_score(3, 9), 5); PASS();

  TEST("cookie: 3 cookies, 5 flags → 2");
  ASSERT_INT_EQ(calc_cookie_score(3, 5), 2); PASS();

  /* MAX_COOKIES boundary (16) */
  TEST("cookie: 16 cookies, all 48 flags → 5");
  ASSERT_INT_EQ(calc_cookie_score(16, 48), 5); PASS();

  TEST("cookie: 16 cookies, 0 flags → 0");
  ASSERT_INT_EQ(calc_cookie_score(16, 0), 0); PASS();
}

/* ======================================
 *  TESTS: DNSSEC scoring
 * ====================================== */

static int calc_dnssec_score(int has_dnssec)
{
  return has_dnssec ? 5 : 0;
}

void test_dnssec_scoring(void)
{
  TEST("dnssec: enabled → 5");
  ASSERT_INT_EQ(calc_dnssec_score(1), 5); PASS();

  TEST("dnssec: disabled → 0");
  ASSERT_INT_EQ(calc_dnssec_score(0), 0); PASS();
}

/* ======================================
 *  TESTS: methods scoring
 * ====================================== */

static int calc_methods_score(int trace, int delete, int put)
{
  int dangerous = trace + delete + put;
  if (dangerous == 0) return 5;
  if (dangerous == 1) return 3;
  if (dangerous == 2) return 1;
  return 0;
}

void test_methods_scoring(void)
{
  TEST("methods: none dangerous → 5");
  ASSERT_INT_EQ(calc_methods_score(0, 0, 0), 5); PASS();

  TEST("methods: trace only → 3");
  ASSERT_INT_EQ(calc_methods_score(1, 0, 0), 3); PASS();

  TEST("methods: delete only → 3");
  ASSERT_INT_EQ(calc_methods_score(0, 1, 0), 3); PASS();

  TEST("methods: put only → 3");
  ASSERT_INT_EQ(calc_methods_score(0, 0, 1), 3); PASS();

  TEST("methods: trace + delete → 1");
  ASSERT_INT_EQ(calc_methods_score(1, 1, 0), 1); PASS();

  TEST("methods: trace + put → 1");
  ASSERT_INT_EQ(calc_methods_score(1, 0, 1), 1); PASS();

  TEST("methods: delete + put → 1");
  ASSERT_INT_EQ(calc_methods_score(0, 1, 1), 1); PASS();

  TEST("methods: all three → 0");
  ASSERT_INT_EQ(calc_methods_score(1, 1, 1), 0); PASS();
}

/* ======================================
 *  TESTS: CORS scoring
 * ====================================== */

static int calc_cors_score(int wildcard, int reflects, int creds_wildcard)
{
  int score = 5;
  if (creds_wildcard) score = 0;
  else if (reflects) score = 1;
  else if (wildcard) score = 3;
  return score;
}

void test_cors_scoring(void)
{
  TEST("cors: clean → 5");
  ASSERT_INT_EQ(calc_cors_score(0, 0, 0), 5); PASS();

  TEST("cors: wildcard origin → 3");
  ASSERT_INT_EQ(calc_cors_score(1, 0, 0), 3); PASS();

  TEST("cors: reflects origin → 1");
  ASSERT_INT_EQ(calc_cors_score(0, 1, 0), 1); PASS();

  TEST("cors: credentials with wildcard → 0");
  ASSERT_INT_EQ(calc_cors_score(0, 0, 1), 0); PASS();

  TEST("cors: all bad → 0 (creds_wildcard takes priority)");
  ASSERT_INT_EQ(calc_cors_score(1, 1, 1), 0); PASS();

  TEST("cors: wildcard + reflects → 1 (reflects takes priority)");
  ASSERT_INT_EQ(calc_cors_score(1, 1, 0), 1); PASS();
}

/* ======================================
 *  TESTS: HTML scoring
 * ====================================== */

static int calc_html_score(int mixed_active, int mixed_passive,
                           int no_sri, int http_forms,
                           int meta_set_cookie, int meta_refresh_http)
{
  int deductions = 0;
  if (mixed_active > 0) deductions += 2;
  if (mixed_passive > 0) deductions += 1;
  if (no_sri > 0) deductions += 1;
  if (http_forms > 0) deductions += 2;
  if (meta_set_cookie > 0) deductions += 1;
  if (meta_refresh_http > 0) deductions += 1;
  int score = 5 - deductions;
  return score < 0 ? 0 : score;
}

void test_html_scoring(void)
{
  TEST("html: clean → 5");
  ASSERT_INT_EQ(calc_html_score(0, 0, 0, 0, 0, 0), 5); PASS();

  TEST("html: mixed_active → 3");
  ASSERT_INT_EQ(calc_html_score(1, 0, 0, 0, 0, 0), 3); PASS();

  TEST("html: mixed_passive → 4");
  ASSERT_INT_EQ(calc_html_score(0, 1, 0, 0, 0, 0), 4); PASS();

  TEST("html: no_sri → 4");
  ASSERT_INT_EQ(calc_html_score(0, 0, 1, 0, 0, 0), 4); PASS();

  TEST("html: http_forms → 3");
  ASSERT_INT_EQ(calc_html_score(0, 0, 0, 1, 0, 0), 3); PASS();

  TEST("html: meta_set_cookie → 4");
  ASSERT_INT_EQ(calc_html_score(0, 0, 0, 0, 1, 0), 4); PASS();

  TEST("html: meta_refresh_http → 4");
  ASSERT_INT_EQ(calc_html_score(0, 0, 0, 0, 0, 1), 4); PASS();

  TEST("html: all bad → 0 (clamped)");
  ASSERT_INT_EQ(calc_html_score(5, 3, 2, 1, 1, 1), 0); PASS();

  TEST("html: mixed_active + http_forms → 1");
  ASSERT_INT_EQ(calc_html_score(1, 0, 0, 1, 0, 0), 1); PASS();
}

/* ======================================
 *  TESTS: CSP deep scoring
 * ====================================== */

static int calc_csp_deep_score(int csp_present, int unsafe_inline,
                                int unsafe_eval, int wildcard_src,
                                int data_uri)
{
  if (!csp_present) return 0;
  int deductions = 0;
  if (unsafe_inline) deductions++;
  if (unsafe_eval) deductions++;
  if (wildcard_src) deductions++;
  if (data_uri) deductions++;
  int score = 2 - deductions;
  return score < 0 ? 0 : score;
}

void test_csp_deep_scoring(void)
{
  TEST("csp_deep: clean CSP → 2");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 0, 0, 0, 0), 2); PASS();

  TEST("csp_deep: no CSP → 0");
  ASSERT_INT_EQ(calc_csp_deep_score(0, 0, 0, 0, 0), 0); PASS();

  TEST("csp_deep: unsafe-inline → 1");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 1, 0, 0, 0), 1); PASS();

  TEST("csp_deep: unsafe-eval → 1");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 0, 1, 0, 0), 1); PASS();

  TEST("csp_deep: wildcard source → 1");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 0, 0, 1, 0), 1); PASS();

  TEST("csp_deep: data_uri → 1");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 0, 0, 0, 1), 1); PASS();

  TEST("csp_deep: inline + eval → 0");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 1, 1, 0, 0), 0); PASS();

  TEST("csp_deep: all bad → 0 (clamped)");
  ASSERT_INT_EQ(calc_csp_deep_score(1, 1, 1, 1, 1), 0); PASS();

  TEST("csp_deep: no CSP + all bad flags → 0");
  ASSERT_INT_EQ(calc_csp_deep_score(0, 1, 1, 1, 1), 0); PASS();
}

/* ======================================
 *  TESTS: full grade with 11 modules
 * ====================================== */

void test_full_grade_11_modules(void)
{
  TEST("full_11: perfect 100/100 → A");
  int total = 25 + 20 + 15 + 8 + 5 + 5 + 5 + 5 + 5 + 5 + 2;
  ASSERT_INT_EQ(total, 100);
  ASSERT_STR_EQ(calc_grade(total, 100), "A"); PASS();

  TEST("full_11: all modules zero → F");
  ASSERT_STR_EQ(calc_grade(0, 100), "F"); PASS();

  TEST("full_11: headers + ssl only → D");
  total = 25 + 20 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0 + 0;
  ASSERT_STR_EQ(calc_grade(total, 100), "D"); PASS();
}

/* ======================================
 *  MAIN
 * ====================================== */

int main(void)
{
  printf("\n=== contrastscan unit tests ===\n\n");

  printf("[calc_grade]\n");
  test_grade_boundaries();
  test_grade_real_scores();

  printf("\n[header_callback]\n");
  test_header_callback_basic();
  test_header_callback_edge_cases();
  test_header_callback_missing();

  printf("\n[header_scoring]\n");
  test_header_scoring();

  printf("\n[tls_scoring]\n");
  test_tls_scoring();

  printf("\n[cert_scoring]\n");
  test_cert_scoring();

  printf("\n[cert_chain_validation]\n");
  test_cert_chain_validation();

  printf("\n[cipher_scoring]\n");
  test_cipher_scoring();

  printf("\n[dns_scoring]\n");
  test_dns_scoring();

  printf("\n[ssl_combined]\n");
  test_ssl_combined();

  printf("\n[full_grade]\n");
  test_full_grade();

  printf("\n[redirect_scoring]\n");
  test_redirect_scoring();

  printf("\n[disclosure_scoring]\n");
  test_disclosure_scoring();

  printf("\n[cdn_name_matching]\n");
  test_cdn_name_matching();

  printf("\n[cookie_scoring]\n");
  test_cookie_scoring();

  printf("\n[dnssec_scoring]\n");
  test_dnssec_scoring();

  printf("\n[methods_scoring]\n");
  test_methods_scoring();

  printf("\n[cors_scoring]\n");
  test_cors_scoring();

  printf("\n[html_scoring]\n");
  test_html_scoring();

  printf("\n[csp_deep_scoring]\n");
  test_csp_deep_scoring();

  printf("\n[full_grade_11_modules]\n");
  test_full_grade_11_modules();

  printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
  if (tests_failed > 0)
    printf(", \033[31m%d FAILED\033[0m", tests_failed);
  printf(" ===\n\n");

  return tests_failed > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
