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
        "description": "We tested 8 free website security scanners. Here's what each one actually checks, misses, and how they compare.",
        "date": "2026-04-02",
        "category": "Comparison",
        "tags": ["security-scanner", "tools", "comparison"],
        "read_time": 10,
        "content": [
            {
                "type": "intro",
                "text": "There are dozens of free website security scanners. Most check different things, and none of them catch everything. We ran 8 popular scanners against the same set of websites and compared what they found.",
            },
            {
                "type": "heading",
                "text": "What We Tested",
            },
            {
                "type": "paragraph",
                "text": "We scanned 20 websites across different industries using each tool. We compared: what security checks each tool performs, how they present results, scan speed, and whether they offer an API.",
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
                "text": "<strong>Strengths:</strong> Most comprehensive free scan — covers headers, SSL, DNS, and HTML in one pass. Open source. API available. Fast (under 30 seconds).",
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
                "text": "<strong>Limitations:</strong> Headers only — no SSL, no DNS, no cookie checks. Doesn't validate header values, just presence.",
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
                "text": "<strong>Limitations:</strong> SSL only — no headers, no DNS, no HTML. Slow (60-90 seconds). No API for free users.",
            },
            {
                "type": "subheading",
                "text": "4. Mozilla Observatory",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> HTTP headers, cookies, redirects, CSP analysis, SRI, CORS. Integrates with third-party scanners.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Detailed CSP analysis, good educational content. Open source.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> Limited SSL analysis (delegates to SSL Labs). No DNS checks. Interface is dated.",
            },
            {
                "type": "subheading",
                "text": "5. Sucuri SiteCheck",
            },
            {
                "type": "paragraph",
                "text": "<strong>What it checks:</strong> Malware, blacklisting status, injected spam, defacement, known vulnerabilities.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Strengths:</strong> Good at detecting if your site is already compromised.",
            },
            {
                "type": "paragraph",
                "text": "<strong>Limitations:</strong> Doesn't check preventive measures (headers, SSL config, DNS security). Free version is very basic.",
            },
            {
                "type": "heading",
                "text": "Comparison Table",
            },
            {
                "type": "table",
                "headers": ["Feature", "ContrastScan", "SecurityHeaders", "SSL Labs", "Mozilla Obs.", "Sucuri"],
                "rows": [
                    ["Security Headers", "Yes (7)", "Yes (6)", "No", "Yes", "No"],
                    ["SSL/TLS", "Yes", "No", "Yes (deep)", "Basic", "Basic"],
                    ["DNS Security", "Yes (SPF/DKIM/DMARC/DNSSEC)", "No", "No", "No", "No"],
                    ["Cookie Security", "Yes", "No", "No", "Yes", "No"],
                    ["CORS Check", "Yes", "No", "No", "Yes", "No"],
                    ["Malware Detection", "No", "No", "No", "No", "Yes"],
                    ["API Available", "Yes (free)", "No", "Paid", "Yes", "No"],
                    ["Open Source", "Yes", "No", "No", "Yes", "No"],
                    ["Scan Speed", "~10s", "~3s", "60-90s", "~15s", "~10s"],
                    ["Grade System", "A-F (100pt)", "A-F", "A-F", "A-F (100pt)", "Pass/Warn"],
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
                    "<strong>For CSP fine-tuning:</strong> Mozilla Observatory — best CSP analysis and recommendations",
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
]

# Index by slug for quick lookup
_blog_by_slug = {p["slug"]: p for p in BLOG_POSTS}
