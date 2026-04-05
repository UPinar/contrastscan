"""
Blog posts — data-driven articles for SEO and authority building.
Each post targets specific keywords and includes structured content.
"""

BLOG_POSTS = [
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
                "text": "<strong>Important note:</strong> This scan only analyzes publicly visible HTTP responses. WAF/CDN configurations may affect results. Sites behind Cloudflare or Akamai may have headers added or masked at the CDN level. DKIM scanning checks only 10 common selectors -- sites using custom selectors may show as 'DKIM missing'. 6 sites timed out during scanning (likely due to aggressive WAF/rate limiting).",
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
                "text": "Out of 94 successfully scanned sites, only 3 achieved an A grade -- two e-commerce platforms and one fintech company. These sites have all essential security headers properly configured, strong SSL/TLS setup, and DNS security records (SPF, DMARC) in place.",
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
                "text": "The national e-Government portal scored B, and the Digital Transformation Office scored the highest among government sites with B (87). However, other .gov.tr sites generally fall in the C-D range. Most common issue: missing CSP and HSTS headers. Some government sites still don't set X-Frame-Options.",
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
                "text": "With 10 universities scanned, education is the second-lowest category (avg 62). 1 site got F, 3 sites got D. Many university websites implement none of the basic security headers. HSTS, CSP, X-Frame-Options -- all missing. The best-performing university scored B (85). Education institutions urgently need to invest in web security.",
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
                    "<strong>Timed-out sites:</strong> 6 sites (across banking, telecom, education, and entertainment sectors) timed out during scanning. These sites likely use aggressive WAF/rate limiting -- a sign of strict protection, not a vulnerability.",
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
    {
        "slug": "germany-top-websites-security-report-2026",
        "title": "We Scanned Germany's Top 100 Websites — Only 3 Got an A",
        "description": "Banks, e-commerce, government, news, education -- we scanned 100 German websites. Average score: 74/100. 51% have no CSP header.",
        "date": "2026-04-04",
        "category": "Research",
        "tags": ["germany", "security-audit", "data", "research"],
        "read_time": 12,
        "content": [
            {
                "type": "intro",
                "text": "We scanned 100 of Germany's most visited websites with ContrastScan. Banks, online shops, federal agencies, news outlets, universities -- all tested against the same 11 security modules, 100-point scoring system. The results: <strong>only 3 sites scored an A.</strong>",
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
                "text": "<strong>Important note:</strong> This scan only analyzes publicly visible HTTP responses. WAF/CDN configurations may affect results. Sites behind Cloudflare or Akamai may have headers added or masked at the CDN level. DKIM scanning checks only 10 common selectors -- sites using custom selectors may show as 'DKIM missing'.",
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
                    ["B (75-89)", "48", "48%"],
                    ["C (60-74)", "45", "45%"],
                    ["D (40-59)", "3", "3%"],
                    ["F (0-39)", "1", "1%"],
                ],
            },
            {
                "type": "paragraph",
                "text": "<strong>Average score: 74/100 (C).</strong> Nearly half of Germany's top 100 websites fall in the B range, but another 45% sit at C. Only 3 sites earned an A.",
            },
            {
                "type": "heading",
                "text": "Results by Category",
            },
            {
                "type": "table",
                "headers": ["Category", "Avg Score", "Best Grade", "Sites"],
                "rows": [
                    ["E-Commerce", "77", "B", "14"],
                    ["News & Media", "76", "A", "13"],
                    ["Banks & Finance", "75", "A", "13"],
                    ["Social & Entertainment", "75", "B", "10"],
                    ["Telecom & Tech", "73", "B", "8"],
                    ["Education", "73", "B", "11"],
                    ["Airlines & Travel", "72", "A", "8"],
                    ["Tech & Services", "72", "B", "11"],
                    ["Government", "70", "B", "12"],
                ],
            },
            {
                "type": "paragraph",
                "text": "<strong>Best:</strong> E-commerce sites (avg 77) and news outlets (avg 76). <strong>Worst:</strong> Government sites (avg 70), followed by tech services and travel sites (both avg 72).",
            },
            {
                "type": "heading",
                "text": "Top 10 Most Common Security Issues",
            },
            {
                "type": "table",
                "headers": ["#", "Issue", "Affected Sites", "Rate"],
                "rows": [
                    ["1", "Missing X-Frame-Options (clickjacking risk)", "56", "56%"],
                    ["2", "Missing CSP header", "51", "51%"],
                    ["3", "Missing X-Content-Type-Options", "42", "42%"],
                    ["4", "No DKIM record found*", "37", "37%"],
                    ["5", "Missing HSTS (HTTPS downgrade risk)", "27", "27%"],
                    ["6", "Excessive inline JavaScript", "25", "25%"],
                    ["7", "CSP allows unsafe-inline", "21", "21%"],
                    ["8", "CSP allows data: URIs", "20", "20%"],
                    ["9", "CSP allows unsafe-eval", "19", "19%"],
                    ["10", "Cookie missing SameSite flag", "9", "9%"],
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
                "text": "Out of 100 scanned sites, only 3 achieved an A grade -- a major news outlet (94), an airline (92), and a banking group (90). These sites have all essential security headers properly configured, strong SSL/TLS setup, and DNS security records (SPF, DMARC) in place.",
            },
            {
                "type": "heading",
                "text": "Sector Analysis",
            },
            {
                "type": "subheading",
                "text": "Banks & Finance (Avg 75/100)",
            },
            {
                "type": "paragraph",
                "text": "German banks score B on average (75/100, 13 sites). Most have strong SSL/TLS configurations. Neobanks and fintech companies perform well in the B range. However, one of Germany's largest traditional banks scored D (59) -- missing HSTS, no HTTPS redirect, and no CSP. Cookie security flags are commonly missing across the sector.",
            },
            {
                "type": "subheading",
                "text": "Government (Avg 70/100)",
            },
            {
                "type": "paragraph",
                "text": "The weakest sector, averaging C (70/100). Most notably, <strong>Germany's federal cyber security agency scored 35/100 (F)</strong> -- the lowest score in the entire dataset. The agency that publishes security guidelines for the country is missing CSP, HSTS, X-Frame-Options, and X-Content-Type-Options on its own website. Tax portals and employment agency sites sit in the C range. German government websites need significant security investment.",
            },
            {
                "type": "subheading",
                "text": "News & Media (Avg 76/100)",
            },
            {
                "type": "paragraph",
                "text": "German news sites score surprisingly well. The top-scoring news site leads the entire dataset with A (94). Most major national newspapers score B. The weakest is a tech news site at D (59) -- excessive inline JavaScript and missing security headers. Ad networks and third-party scripts make CSP implementation difficult for media sites.",
            },
            {
                "type": "subheading",
                "text": "Education (Avg 73/100)",
            },
            {
                "type": "paragraph",
                "text": "11 universities scanned, all in B-C range. German universities generally implement basic headers but skip CSP and HSTS. No university scored an A. Most common issues: missing Content-Security-Policy and X-Frame-Options headers.",
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
                "text": "Germany's top 100 websites average a security score of 74/100. 51% have no CSP header, 56% lack clickjacking protection, and 27% have no HTTPS downgrade protection. Government and travel sites need urgent attention. The good news: most of these issues can be fixed with a few lines of server configuration.",
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
