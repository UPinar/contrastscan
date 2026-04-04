"""
Blog posts — data-driven articles for SEO and authority building.
Each post targets specific keywords and includes structured content.
"""

BLOG_POSTS = [
    {
        "slug": "nginx-security-headers-guide",
        "title": "From F to A+: The Complete Nginx Security Headers Guide",
        "description": "Step-by-step guide to configure all essential HTTP security headers in Nginx. Copy-paste configs included.",
        "date": "2026-04-02",
        "category": "Guide",
        "tags": ["nginx", "security-headers", "configuration"],
        "read_time": 8,
        "content": [
            {
                "type": "intro",
                "text": "Your website just got an F on a security scan. The good news? You can fix it in under 10 minutes. This guide walks you through every HTTP security header your Nginx server needs, with copy-paste configurations that actually work.",
            },
            {
                "type": "heading",
                "text": "Why Security Headers Matter",
            },
            {
                "type": "paragraph",
                "text": "HTTP security headers tell browsers how to behave when handling your site's content. Without them, browsers use permissive defaults that leave your users vulnerable to cross-site scripting (XSS), clickjacking, MIME-type confusion, and protocol downgrade attacks. Adding headers costs nothing — no code changes, no dependencies, just server configuration.",
            },
            {
                "type": "heading",
                "text": "The 7 Essential Headers",
            },
            {
                "type": "subheading",
                "text": "1. Strict-Transport-Security (HSTS)",
            },
            {
                "type": "paragraph",
                "text": "Forces browsers to use HTTPS for all future connections. Without it, users typing <code>http://yoursite.com</code> are vulnerable to SSL stripping attacks on public Wi-Fi.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
            },
            {
                "type": "tip",
                "text": "Start with <code>max-age=86400</code> (1 day) and increase after confirming HTTPS works on all subdomains.",
            },
            {
                "type": "subheading",
                "text": "2. Content-Security-Policy (CSP)",
            },
            {
                "type": "paragraph",
                "text": "The most powerful header. Controls exactly which resources can load on your page. Stops XSS attacks by blocking unauthorized scripts.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'\" always;",
            },
            {
                "type": "tip",
                "text": "Use <code>Content-Security-Policy-Report-Only</code> first to find what breaks before enforcing.",
            },
            {
                "type": "subheading",
                "text": "3. X-Content-Type-Options",
            },
            {
                "type": "paragraph",
                "text": "Prevents browsers from guessing (sniffing) the MIME type of a response. Without it, an attacker could trick the browser into executing a malicious file as JavaScript.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header X-Content-Type-Options "nosniff" always;',
            },
            {
                "type": "subheading",
                "text": "4. X-Frame-Options",
            },
            {
                "type": "paragraph",
                "text": "Prevents your site from being loaded in an iframe, protecting against clickjacking attacks where an attacker overlays an invisible frame on a decoy page.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header X-Frame-Options "DENY" always;',
            },
            {
                "type": "subheading",
                "text": "5. Referrer-Policy",
            },
            {
                "type": "paragraph",
                "text": "Controls how much URL information is sent when a user clicks a link from your site. Protects sensitive URL parameters from leaking to third parties.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            },
            {
                "type": "subheading",
                "text": "6. Permissions-Policy",
            },
            {
                "type": "paragraph",
                "text": "Controls which browser features (camera, microphone, geolocation) your site and embedded iframes can access. Reduces the attack surface.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()" always;',
            },
            {
                "type": "subheading",
                "text": "7. X-XSS-Protection",
            },
            {
                "type": "paragraph",
                "text": "Legacy header for older browsers. Modern browsers use CSP instead, but it's still good practice for backward compatibility.",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header X-XSS-Protection "1; mode=block" always;',
            },
            {
                "type": "heading",
                "text": "Complete Nginx Configuration",
            },
            {
                "type": "paragraph",
                "text": "Add all headers at once. Put this in your <code>server</code> block or a separate file included via <code>include /etc/nginx/snippets/security-headers.conf;</code>",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": """# /etc/nginx/snippets/security-headers.conf
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), interest-cohort=()" always;
add_header X-XSS-Protection "1; mode=block" always;""",
            },
            {
                "type": "paragraph",
                "text": "After saving, test and reload Nginx:",
            },
            {
                "type": "code",
                "lang": "bash",
                "text": "nginx -t && systemctl reload nginx",
            },
            {
                "type": "heading",
                "text": "Verify Your Headers",
            },
            {
                "type": "paragraph",
                "text": "Check with curl:",
            },
            {
                "type": "code",
                "lang": "bash",
                "text": "curl -sI https://yourdomain.com | grep -iE '(strict|content-security|x-content|x-frame|referrer|permissions|x-xss)'",
            },
            {
                "type": "paragraph",
                "text": "Or scan your site with ContrastScan for a full security grade:",
            },
            {
                "type": "cta",
                "text": "Scan Your Website Free",
                "url": "/",
            },
            {
                "type": "heading",
                "text": "Common Mistakes",
            },
            {
                "type": "list",
                "entries": [
                    "Missing the <code>always</code> keyword — without it, Nginx only sends headers on 2xx responses, leaving error pages unprotected",
                    "Using <code>unsafe-inline</code> and <code>unsafe-eval</code> in CSP — defeats the entire purpose of having a CSP",
                    "Setting headers in <code>http</code> block but overriding them in <code>server</code> block — Nginx replaces, not merges",
                    "Adding <code>preload</code> to HSTS before testing — the preload list is permanent and very hard to undo",
                    "Forgetting to include headers on all locations — add them at the <code>server</code> level, not inside individual <code>location</code> blocks",
                ],
            },
        ],
    },
    {
        "slug": "best-website-security-scanners-2026",
        "title": "Best Free Website Security Scanners in 2026: Honest Comparison",
        "description": "We compared 5 popular free website security scanners. Here's what each one checks, misses, and how they stack up.",
        "date": "2026-04-02",
        "category": "Comparison",
        "tags": ["security-scanner", "tools", "comparison"],
        "read_time": 10,
        "content": [
            {
                "type": "intro",
                "text": "There are dozens of free website security scanners. Most check different things, and none of them catch everything. We compared 5 popular scanners to see what each one covers and where they fall short.",
            },
            {
                "type": "heading",
                "text": "What We Tested",
            },
            {
                "type": "paragraph",
                "text": "We compared what security checks each tool performs, how they present results, scan speed, and whether they offer an API.",
            },
            {
                "type": "heading",
                "text": "The Scanners",
            },
            {
                "type": "subheading",
                "text": "1. ContrastScan",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> SSL/TLS, security headers (7 headers), DNS (SPF, DKIM, DMARC, DNSSEC), cookies, CORS, HTTP methods, HTML security, redirect chain, server info disclosure. 11 modules, 100-point scoring with A-F grade.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Covers headers, SSL, DNS, and HTML in one pass. Open source. API available. Fast (under 30 seconds).",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> No port scanning, no active vulnerability testing (SQL injection, XSS probing), no malware detection.",
            },
            {
                "type": "subheading",
                "text": "2. SecurityHeaders.com",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> HTTP security headers only (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). A-F grade based on header presence.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Fast, clean UI, widely referenced. Created by Scott Helme.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> Headers only — no SSL, no DNS, no cookie checks.",
            },
            {
                "type": "subheading",
                "text": "3. SSL Labs (Qualys)",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> Deep SSL/TLS analysis — certificate chain, protocol versions, cipher suites, key exchange, known vulnerabilities (Heartbleed, POODLE, etc.).",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Industry standard for SSL testing. Most detailed certificate analysis available.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> SSL only — no headers, no DNS, no HTML. Slow (60-90 seconds).",
            },
            {
                "type": "subheading",
                "text": "4. Mozilla HTTP Observatory",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> HTTP headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CORP), redirects, cookies. Redesigned and moved to MDN in 2024.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Detailed CSP analysis, modernized interface, v2 API available. Open source. Good educational documentation on MDN.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> No SSL analysis (third-party integrations removed in 2024). No DNS checks. Headers and redirects only.",
            },
            {
                "type": "subheading",
                "text": "5. Sucuri SiteCheck",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> Malware, blacklisting status (9 authorities including Google Safe Browsing), outdated software, injected spam, defacement. Also checks basic security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP).",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Good at detecting if your site is already compromised. Now includes basic header checks. Minimal/Low/Medium/High/Critical risk rating.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> Header checks are basic (presence only). No SSL config analysis, no DNS security. Full server-level scanning requires paid plan.",
            },
            {
                "type": "heading",
                "text": "Comparison Table",
            },
            {
                "type": "table",
                "headers": ["Feature", "ContrastScan", "SecurityHeaders", "SSL Labs", "Mozilla Obs.", "Sucuri"],
                "rows": [
                    ["Security Headers", "Yes (7)", "Yes (6)", "No", "Yes (6+CORP)", "Basic (4)"],
                    ["SSL/TLS", "Yes", "No", "Yes (deep)", "No", "Basic"],
                    ["DNS Security", "Yes (SPF/DKIM/DMARC/DNSSEC)", "No", "No", "No", "No"],
                    ["Cookie Security", "Yes", "No", "No", "Yes", "No"],
                    ["CORS Check", "Yes", "No", "No", "No", "No"],
                    ["Malware Detection", "No", "No", "No", "No", "Yes"],
                    ["API Available", "Yes (free)", "No", "Yes (free)", "Yes (v2)", "No"],
                    ["Open Source", "Yes", "No", "No", "Yes", "No"],
                    ["Scan Speed", "~10s", "~3s", "60-90s", "~15s", "~10s"],
                    ["Grade System", "A-F (100pt)", "A-F", "A-F", "A-F (105pt)", "Risk level"],
                ],
            },
            {
                "type": "heading",
                "text": "Which Scanner Should You Use?",
            },
            {
                "type": "list",
                "entries": [
                    "<strong>For a quick overall check:</strong> ContrastScan — covers headers, SSL, and DNS in one scan",
                    "<strong>For deep SSL analysis:</strong> SSL Labs — unmatched certificate and cipher suite testing",
                    "<strong>For CSP fine-tuning:</strong> Mozilla Observatory (now on MDN) — best CSP analysis and recommendations",
                    "<strong>For malware detection:</strong> Sucuri — detects existing compromises",
                    "<strong>Best approach:</strong> Use 2-3 scanners together for full coverage",
                ],
            },
            {
                "type": "cta",
                "text": "Try ContrastScan — Free, No Signup",
                "url": "/",
            },
        ],
    },
    {
        "slug": "turkey-top-websites-security-report-2026",
        "title": "We Scanned Turkey's Top 100 Websites — Only 3 Got an A",
        "description": "Banks, e-commerce, government, news, education -- we scanned 100 Turkish websites. Average score: 70/100. 70% have no CSP header.",
        "date": "2026-04-02",
        "category": "Research",
        "tags": ["turkey", "security-audit", "data", "research"],
        "read_time": 12,
        "content": [
            {
                "type": "intro",
                "text": "We scanned 100 of Turkey's most visited websites with ContrastScan. Banks, e-commerce platforms, government portals, news sites, universities -- all tested against the same 11 security modules, 100-point scoring system. The results: <strong>only 3 sites scored an A.</strong>",
            },
            {
                "type": "heading",
                "text": "Methodology",
            },
            {
                "type": "paragraph",
                "text": "Each site was scanned with ContrastScan's 11 security modules: SSL/TLS, HTTP security headers (7 headers), DNS (SPF, DKIM, DMARC, DNSSEC), cookie security, CORS, HTTP methods, HTML security, redirect chain, server info disclosure, and CSP analysis. Each module contributes to a 100-point total, graded A through F.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Important note:</strong> This scan only analyzes publicly visible HTTP responses. WAF/CDN configurations may affect results. Sites behind Cloudflare or Akamai may have headers added or masked at the CDN level. DKIM scanning checks only 10 common selectors -- sites using custom selectors may show as 'DKIM missing'. 6 sites (Yapikredi, TEB, BTK, Turkish Airlines, Hacettepe, Izlesene) timed out during scanning.",
            },
            {
                "type": "heading",
                "text": "Overall Results",
            },
            {
                "type": "table",
                "headers": ["Grade", "Count", "Percentage"],
                "rows": [
                    ["A (90-100)", "3", "3%"],
                    ["B (75-89)", "32", "34%"],
                    ["C (60-74)", "43", "46%"],
                    ["D (40-59)", "15", "16%"],
                    ["F (0-39)", "1", "1%"],
                    ["Timeout", "6", "--"],
                ],
            },
            {
                "type": "paragraph",
                "text": "<strong>Average score: 70/100 (C).</strong> More than half of Turkey's top 100 websites are missing basic security headers.",
            },
            {
                "type": "heading",
                "text": "Results by Category",
            },
            {
                "type": "table",
                "headers": ["Category", "Avg Score", "Best Grade", "Sites"],
                "rows": [
                    ["Airlines & Travel", "80", "B", "6"],
                    ["E-Commerce", "76", "A", "14"],
                    ["Tech & Services", "74", "B", "11"],
                    ["Banks", "73", "A", "13"],
                    ["Government", "72", "B", "12"],
                    ["Social & Entertainment", "72", "B", "7"],
                    ["News & Media", "64", "C", "16"],
                    ["Telecom", "62", "B", "5"],
                    ["Education", "62", "B", "10"],
                ],
            },
            {
                "type": "paragraph",
                "text": "<strong>Best:</strong> Airlines & travel sites (avg 80). <strong>Worst:</strong> Telecom and education (both avg 62), followed by news sites (avg 64). These sectors are seriously behind on web security.",
            },
            {
                "type": "heading",
                "text": "Top 10 Most Common Security Issues",
            },
            {
                "type": "table",
                "headers": ["#", "Issue", "Affected Sites", "Rate"],
                "rows": [
                    ["1", "Missing CSP header", "66", "70%"],
                    ["2", "Missing X-Content-Type-Options", "42", "45%"],
                    ["3", "Missing X-Frame-Options (clickjacking risk)", "41", "44%"],
                    ["4", "Missing HSTS (HTTPS downgrade risk)", "41", "44%"],
                    ["5", "No DKIM record found*", "32", "34%"],
                    ["6", "Excessive inline JavaScript", "32", "34%"],
                    ["7", "CSP allows unsafe-eval", "19", "20%"],
                    ["8", "CSP allows unsafe-inline", "19", "20%"],
                    ["9", "Cookie missing Secure/HttpOnly/SameSite", "17", "18%"],
                    ["10", "No HTTP to HTTPS redirect", "14", "15%"],
                ],
            },
            {
                "type": "tip",
                "text": "* DKIM scanning checks only 10 common selectors (default, google, selector1, k1, etc.). Sites using custom selectors may appear as 'DKIM missing'. This is common with enterprise mail services.",
            },
            {
                "type": "heading",
                "text": "Only 3 Sites Scored an A",
            },
            {
                "type": "paragraph",
                "text": "Out of 94 successfully scanned sites, only 3 achieved an A grade: <strong>Papara</strong> (91), <strong>Ciceksepeti</strong> (90), and <strong>LC Waikiki</strong> (90). These sites have all essential security headers properly configured, strong SSL/TLS setup, and DNS security records (SPF, DMARC) in place.",
            },
            {
                "type": "heading",
                "text": "Sector Analysis",
            },
            {
                "type": "subheading",
                "text": "Banks (Avg 74/100)",
            },
            {
                "type": "paragraph",
                "text": "Turkish banks score B-C on average (73/100, 13 sites scanned, 2 timed out). Most have CSP headers but use <code>unsafe-eval</code> and <code>unsafe-inline</code> -- which largely defeats the purpose of CSP. Cookie security flags are commonly missing. On the positive side: SSL/TLS configurations are generally strong.",
            },
            {
                "type": "subheading",
                "text": "Government (Avg 72/100)",
            },
            {
                "type": "paragraph",
                "text": "The national e-Government portal (turkiye.gov.tr) scored B, and the Digital Transformation Office (uab.gov.tr) scored the highest among government sites with B (87). However, other .gov.tr sites generally fall in the C-D range. Most common issue: missing CSP and HSTS headers. Some government sites still don't set X-Frame-Options.",
            },
            {
                "type": "subheading",
                "text": "News & Media (Avg 65/100)",
            },
            {
                "type": "paragraph",
                "text": "None of the 16 news sites scored above C -- all rated C or D. Ad networks and third-party scripts make CSP implementation difficult for these sites. Excessive inline JavaScript is the most common finding. News and telecom are tied as Turkey's weakest sectors for web security.",
            },
            {
                "type": "subheading",
                "text": "Education (Avg 57/100)",
            },
            {
                "type": "paragraph",
                "text": "With 10 universities scanned, education is the second-lowest category (avg 62). 1 site got F, 3 sites got D. Many university websites implement none of the basic security headers. HSTS, CSP, X-Frame-Options -- all missing. Gazi University stands out as the best performer with a B (85). Education institutions urgently need to invest in web security.",
            },
            {
                "type": "heading",
                "text": "Possible False Positives",
            },
            {
                "type": "paragraph",
                "text": "This scan was performed with an automated tool. Some results may not fully reflect the actual security posture:",
            },
            {
                "type": "list",
                "entries": [
                    "<strong>DKIM 'missing' warning:</strong> The scanner checks 10 common DKIM selectors (default, google, selector1, k1, etc.). If an organization uses a custom selector (e.g. <code>corp2026._domainkey</code>), it won't be detected. Large banks and telecoms often use custom selectors.",
                    "<strong>Headers behind CDN/WAF:</strong> Sites using Cloudflare, Akamai, or Imperva may have headers added at the CDN level. The scanner may not see CDN-injected headers, or may report the CDN's own headers.",
                    "<strong>Cookie flags:</strong> Some cookies are set via JavaScript and don't need the <code>HttpOnly</code> flag. The scanner checks <code>Set-Cookie</code> headers in HTTP responses -- it can't see JS-set cookies.",
                    "<strong>Server header:</strong> Some sites return <code>Server: nginx</code> or <code>Server: AkamaiGHost</code>. This is reported as information disclosure, but for CDN-fronted sites this is the CDN's default behavior, not actual server info.",
                    "<strong>Timed-out sites:</strong> Yapikredi, TEB, BTK, Turkish Airlines, Hacettepe, and Izlesene timed out during scanning. These sites likely use aggressive WAF/rate limiting -- a sign of strict protection, not a vulnerability.",
                ],
            },
            {
                "type": "heading",
                "text": "How to Fix These Issues",
            },
            {
                "type": "paragraph",
                "text": "Most issues can be fixed by adding a few lines to your server configuration. Here are fixes for the top 3 problems:",
            },
            {
                "type": "subheading",
                "text": "1. Add a CSP Header",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\" always;",
            },
            {
                "type": "subheading",
                "text": "2. Enable HSTS",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
            },
            {
                "type": "subheading",
                "text": "3. Essential Security Headers",
            },
            {
                "type": "code",
                "lang": "nginx",
                "text": 'add_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "DENY" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            },
            {
                "type": "paragraph",
                "text": "For a complete guide: <a href='/blog/nginx-security-headers-guide'>Nginx Security Headers -- Complete Guide</a>",
            },
            {
                "type": "heading",
                "text": "Conclusion",
            },
            {
                "type": "paragraph",
                "text": "Turkey's top 100 websites average a security score of 70/100. 70% have no CSP header, 44% lack clickjacking protection, and 44% have no HTTPS downgrade protection. Telecom, education, and news sites need urgent attention. The good news: most of these issues can be fixed with a few lines of server configuration.",
            },
            {
                "type": "cta",
                "text": "Scan Your Website Free",
                "url": "/",
            },
        ],
    },
]

# Index by slug for quick lookup
_blog_by_slug = {p["slug"]: p for p in BLOG_POSTS}
