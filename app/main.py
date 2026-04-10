"""
contrastscan — Security Score as a Service

Routes only — business logic split into modules:
  config.py     — constants, paths, error messages
  db.py         — SQLite operations
  validation.py — domain/IP validation, CSRF
  ratelimit.py  — thread-safe rate limiting
  findings.py   — vulnerability analysis, enterprise detection
  report.py     — plain-text report generation
  scanner.py    — C binary execution, scan orchestration
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from blog_posts import BLOG_POSTS, _blog_by_slug
from config import (
    BADGE_CACHE_MAX_AGE,
    BADGE_GRADE_WIDTH,
    BADGE_LABEL_WIDTH,
    BASE_DIR,
    ERROR_MESSAGES,
    GRADE_COLORS,
    MAX_DOMAIN_LENGTH,
)
from db import get_domain_grade, get_recon, get_scan, get_stats, get_stats_detailed, init_db
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from learn_pages import LEARN_PAGES
from report import generate_report, report_response
from starlette.concurrency import run_in_threadpool
from validation import SCAN_ID_PATTERN, check_csrf, clean_domain, get_client_ip

from scanner import perform_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("contrastscan")


@asynccontextmanager
async def lifespan(app):
    import asyncio

    from db import cleanup_api_usage, cleanup_ip_limits, purge_old_client_hashes

    init_db()

    async def _periodic_cleanup():
        cycles = 0
        while True:
            await asyncio.sleep(3600)
            cycles += 1
            try:
                deleted = cleanup_ip_limits()
                if deleted:
                    logger.info("IP limits cleanup: %d stale rows removed", deleted)
            except Exception as e:
                logger.warning("IP limits cleanup failed: %s", e)
            try:
                deleted = cleanup_api_usage()
                if deleted:
                    logger.info("API usage cleanup: %d stale rows removed", deleted)
            except Exception as e:
                logger.warning("API usage cleanup failed: %s", e)
            # Purge old client hashes daily (every 24 cycles)
            if cycles % 24 == 0:
                try:
                    purged = purge_old_client_hashes(days=90)
                    if purged:
                        logger.info("Client hash purge: %d rows anonymized", purged)
                except Exception as e:
                    logger.warning("Client hash purge failed: %s", e)

    task = asyncio.create_task(_periodic_cleanup())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="ContrastScan",
    description="Free security scanner — SSL/TLS, headers, DNS (SPF/DKIM/DMARC). Returns A-F grade out of 100 points.",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.exception_handler(HTTPException)
async def custom_error_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/recon/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    title, message = ERROR_MESSAGES.get(exc.status_code, ("Error", "Something went wrong."))
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": exc.status_code,
            "title": title,
            "message": message,
        },
        status_code=exc.status_code,
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    """Catch-all — never leak stack traces or internal paths."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    if request.url.path.startswith("/recon/"):
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "status_code": 500,
            "title": "Error",
            "message": "Something went wrong.",
        },
        status_code=500,
    )


# === Pages ===


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request):
    total_scans, recent_scans = get_stats()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "total_scans": total_scans,
            "recent_scans": recent_scans,
        },
    )


@app.get("/stats", response_class=HTMLResponse, include_in_schema=False)
def stats_page(request: Request):
    data = get_stats_detailed()

    grades = []
    for letter in ["A", "B", "C", "D", "F"]:
        count = data["grade_counts"].get(letter, 0)
        pct = round(count * 100 / data["unique"]) if data["unique"] > 0 else 0
        grades.append(
            {
                "letter": letter,
                "pct": pct,
                "color": GRADE_COLORS.get(letter, "#ef4444"),
            }
        )

    return templates.TemplateResponse(
        request,
        "stats.html",
        {
            "avg_score": data["avg_score"],
            "grades": grades,
        },
    )


# === Scan ===


def _wants_dnt(request: Request) -> bool:
    """Check if the client sent Do Not Track or Global Privacy Control headers."""
    return request.headers.get("dnt") == "1" or request.headers.get("sec-gpc") == "1"


@app.post("/scan", include_in_schema=False)
async def scan(request: Request, domain: str = Form(...)):
    check_csrf(request)
    client_ip = get_client_ip(request)
    dnt = _wants_dnt(request)
    scan_id, _ = await run_in_threadpool(perform_scan, domain, client_ip, dnt=dnt)
    return RedirectResponse(url=f"/result/{scan_id}", status_code=303)


@app.get("/result/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def result(request: Request, scan_id: str):
    if not SCAN_ID_PATTERN.match(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        result_data = json.loads(scan_data["result"])
    except (json.JSONDecodeError, TypeError) as exc:
        logger.error("Corrupted scan result for %s: %s", scan_id, exc)
        raise HTTPException(status_code=500, detail="Corrupted scan result") from exc
    grade = result_data.get("grade", "F")

    response = templates.TemplateResponse(
        request,
        "result.html",
        {
            "scan": scan_data,
            "scan_id": scan_id,
            "result": result_data,
            "grade_color": GRADE_COLORS.get(grade, "#ef4444"),
        },
    )
    response.headers["Cache-Control"] = "private, no-store"
    return response


# === Reports ===


@app.get("/report/{scan_id}.txt", include_in_schema=False)
async def report_txt(scan_id: str):
    """Downloadable plain-text report by scan ID — waits for recon to finish"""
    import asyncio

    if not SCAN_ID_PATTERN.match(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        r = json.loads(scan_data["result"])
    except (json.JSONDecodeError, TypeError) as exc:
        logger.error("Corrupted scan result for %s: %s", scan_id, exc)
        raise HTTPException(status_code=500, detail="Corrupted scan result") from exc

    # Wait up to 10s for recon (non-blocking async sleep)
    recon = None
    for _ in range(20):
        recon_row = get_recon(scan_id)
        if recon_row and recon_row.get("status") in ("done", "error"):
            recon = json.loads(recon_row["result"]) if recon_row.get("result") else None
            break
        await asyncio.sleep(0.5)

    text = generate_report(r, scan_id, scan_data.get("created_at", "N/A"), recon=recon)
    return report_response(text, r.get("domain", "unknown"))


# === Recon ===


@app.get(
    "/recon/{scan_id}",
    tags=["scan"],
    summary="Poll passive recon results",
    operation_id="get_recon",
    include_in_schema=False,
)
def get_recon_data(scan_id: str):
    """Poll recon results — returns status + data when ready."""
    if not SCAN_ID_PATTERN.match(scan_id):
        raise HTTPException(status_code=404, detail="Invalid scan ID")
    recon = get_recon(scan_id)
    if not recon:
        return {"status": "pending"}
    status = recon["status"]
    data = None
    if recon.get("result"):
        try:
            data = json.loads(recon["result"])
        except (json.JSONDecodeError, TypeError):
            logger.warning("Invalid recon JSON for %s", scan_id)
    return {"status": status, "data": data}


# === Badge ===


@app.get("/badge/{domain}.svg", include_in_schema=False)
def badge_svg(domain: str):
    """Dynamic SVG grade badge"""
    domain = clean_domain(domain)
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid domain")

    grade = get_domain_grade(domain)
    if not grade:
        raise HTTPException(status_code=404, detail="No scan found for this domain")

    if grade not in ("A", "B", "C", "D", "F"):
        grade = "?"

    color = GRADE_COLORS.get(grade, "#71717a")
    label_w, grade_w = BADGE_LABEL_WIDTH, BADGE_GRADE_WIDTH
    total_w = label_w + grade_w

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="c"><rect width="{total_w}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#c)">
    <rect width="{label_w}" height="20" fill="#27272a"/>
    <rect x="{label_w}" width="{grade_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="monospace" font-size="11">
    <text x="{label_w // 2}" y="14">security</text>
    <text x="{label_w + grade_w // 2}" y="14" font-weight="bold">{grade}</text>
  </g>
</svg>'''
    return Response(
        content=svg, media_type="image/svg+xml", headers={"Cache-Control": f"public, max-age={BADGE_CACHE_MAX_AGE}"}
    )


# === Legal & Pricing ===


@app.get("/terms", response_class=HTMLResponse, include_in_schema=False)
def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html")


@app.get("/privacy", response_class=HTMLResponse, include_in_schema=False)
def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html")


@app.get("/pricing", response_class=HTMLResponse, include_in_schema=False)
def pricing_page(request: Request):
    return templates.TemplateResponse(request, "pricing.html")


# === Learn (Programmatic SEO) ===


_learn_by_slug = {p["slug"]: p for p in LEARN_PAGES}


@app.get("/learn", response_class=HTMLResponse, include_in_schema=False)
def learn_index(request: Request):
    return templates.TemplateResponse(request, "learn_index.html", {"pages": LEARN_PAGES})


@app.get("/learn/{slug}", response_class=HTMLResponse, include_in_schema=False)
def learn_page(request: Request, slug: str):
    page = _learn_by_slug.get(slug)
    if not page:
        return templates.TemplateResponse(request, "error.html", status_code=404)
    related = [p for p in LEARN_PAGES if p["category"] == page["category"] and p["slug"] != slug][:3]
    return templates.TemplateResponse(request, "learn.html", {"page": page, "related": related})


# === Blog ===


@app.get("/blog", response_class=HTMLResponse, include_in_schema=False)
def blog_index(request: Request):
    posts = sorted(BLOG_POSTS, key=lambda p: p["date"], reverse=True)
    return templates.TemplateResponse(request, "blog_index.html", {"posts": posts})


@app.get("/blog/{slug}", response_class=HTMLResponse, include_in_schema=False)
def blog_post(request: Request, slug: str):
    post = _blog_by_slug.get(slug)
    if not post:
        return templates.TemplateResponse(request, "error.html", status_code=404)
    return templates.TemplateResponse(request, "blog.html", {"post": post})


# === SEO ===


@app.get("/llms.txt", include_in_schema=False)
def llms_txt():
    p = Path(__file__).parent / "static" / "llms.txt"
    return PlainTextResponse(p.read_text())


@app.get("/robots.txt", include_in_schema=False)
def robots_txt():
    return PlainTextResponse(
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /result/\n"
        "\n"
        "# AI search bots — allowed\n"
        "User-agent: OAI-SearchBot\n"
        "Allow: /\n"
        "\n"
        "User-agent: Applebot-Extended\n"
        "Allow: /\n"
        "\n"
        "User-agent: PerplexityBot\n"
        "Allow: /\n"
        "\n"
        "# AI training scrapers — blocked\n"
        "User-agent: GPTBot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: CCBot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: Google-Extended\n"
        "Disallow: /\n"
        "\n"
        "User-agent: anthropic-ai\n"
        "Disallow: /\n"
        "\n"
        "User-agent: ClaudeBot\n"
        "Disallow: /\n"
        "\n"
        "Sitemap: https://contrastcyber.com/sitemap.xml\n"
    )


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml():
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    learn_urls = "\n".join(
        f"  <url><loc>https://contrastcyber.com/learn/{p['slug']}</loc><lastmod>2026-03-25</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>"
        for p in LEARN_PAGES
    )
    blog_urls = "\n".join(
        f"  <url><loc>https://contrastcyber.com/blog/{p['slug']}</loc><lastmod>{p['date']}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>"
        for p in BLOG_POSTS
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://contrastcyber.com/</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://contrastcyber.com/stats</loc><lastmod>{today}</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>
  <url><loc>https://contrastcyber.com/learn</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://contrastcyber.com/blog</loc><lastmod>{today}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
{learn_urls}
{blog_urls}
</urlset>"""
    return Response(content=xml, media_type="application/xml")


@app.get("/.well-known/security.txt", include_in_schema=False)
def security_txt():
    expires = (datetime.now(UTC) + timedelta(days=365)).strftime("%Y-%m-%dT00:00:00.000Z")
    return PlainTextResponse(
        f"Contact: mailto:contact@contrastcyber.com\n"
        f"Expires: {expires}\n"
        f"Preferred-Languages: en, tr\n"
        f"Canonical: https://contrastcyber.com/.well-known/security.txt\n"
    )
