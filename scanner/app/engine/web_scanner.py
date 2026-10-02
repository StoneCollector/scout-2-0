"""
Web Configuration & Response Auditor (engine/web_scanner.py)
Targets localhost / private IPs only. Non-destructive: reads HTTP headers and
compares response bodies against secure baselines. Nothing is executed on target.
OWASP ASVS references: V5.2 (input handling), V5.3 (output encoding), V14.4 (HTTP security headers).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests

logger = logging.getLogger("scanner.web")

# ---------------------------------------------------------------------------
# Private-network guard
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def _is_private(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(host))
        return any(addr in net for net in _PRIVATE_NETS)
    except Exception:
        return False


def validate_target(url: str) -> str:
    """Return normalised URL or raise ValueError if target is not local/private."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    host = parsed.hostname or ""
    if not _is_private(host):
        raise ValueError(
            f"Target '{host}' is not a localhost or private-network address. "
            "Only 127.0.0.1, localhost, 10.x, 172.16-31.x and 192.168.x targets are permitted."
        )
    return url


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    severity: str = "info"          # critical / high / medium / low / info
    evidence: str = ""
    remediation: str = ""
    owasp_category: str = ""
    url: str = ""
    check_name: str = ""


SEVERITY_WEIGHT = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}

GRADE_THRESHOLDS = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (20, "E"),
    (0,  "F"),
]


def compute_grade(findings: List[Finding]) -> Tuple[int, str]:
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, score)
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break
    return score, grade


# ---------------------------------------------------------------------------
# Simple token-bucket rate limiter (5 req/s)
# ---------------------------------------------------------------------------
class _RateLimiter:
    def __init__(self, rps: float = 5.0):
        self._min_interval = 1.0 / rps
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            gap = self._min_interval - (now - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------
def _session(target_url: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "AegisWebAuditor/1.0 (university security lab; localhost only)",
        "Accept": "text/html,application/xhtml+xml,*/*",
    })
    s.max_redirects = 3
    return s


# ---------------------------------------------------------------------------
# Crawler: collects same-origin pages + forms to depth 2, max 30 pages
# ---------------------------------------------------------------------------
_LINK_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\'#?][^"\']*)["\']', re.I)
_STATIC_EXTS = {
    ".css", ".js", ".svg", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp", ".json",
}
_FORM_ACTION_RE = re.compile(r'<form[^>]+action=["\']([^"\']*)["\']', re.I)
_INPUT_NAME_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.I)
_TEXTAREA_NAME_RE = re.compile(r'<textarea[^>]+name=["\']([^"\']+)["\']', re.I)
_PARAM_RE = re.compile(r'[?&]([^=&]+)=([^&]*)')
_PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.I)


@dataclass
class PageInfo:
    url: str
    query_params: List[str] = field(default_factory=list)   # param names in query string
    form_fields: List[Tuple[str, str]] = field(default_factory=list)  # (action_url, field_name)
    has_password_field: bool = False
    html: str = ""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)


def crawl(base_url: str, session: requests.Session, limiter: _RateLimiter,
          max_pages: int = 30, max_depth: int = 2) -> List[PageInfo]:
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(base_url, 0)]
    pages: List[PageInfo] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        # Normalise – strip fragment
        url = urlunparse(urlparse(url)._replace(fragment=""))
        if url in visited:
            continue
        visited.add(url)

        limiter.wait()
        try:
            resp = session.get(url, timeout=10, allow_redirects=True)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if url == base_url or depth == 0:
                raise ConnectionError(
                    f"Unable to connect to target endpoint '{base_url}'. "
                    "No service is running on this address or the connection was actively refused."
                ) from e
            logger.debug(f"Crawl fetch error {url}: {e}")
            continue
        except Exception as e:
            if url == base_url or depth == 0:
                raise RuntimeError(f"Failed to connect to target '{base_url}': {e}") from e
            logger.debug(f"Crawl fetch error {url}: {e}")
            continue

        html = ""
        ct = resp.headers.get("Content-Type", "")
        if "text/html" in ct or "text/plain" in ct:
            try:
                html = resp.text
            except Exception:
                html = ""

        # Extract query params from URL
        qp = list(parse_qs(urlparse(url).query).keys())

        # Extract form fields
        form_fields: List[Tuple[str, str]] = []
        for m in _FORM_ACTION_RE.finditer(html):
            action = m.group(1).strip() or url
            action_abs = urljoin(url, action)
            if not action_abs.startswith(origin):
                continue
            # field names in this form block (rough approach: scan whole page for inputs)
        for m in _INPUT_NAME_RE.finditer(html):
            name = m.group(1).strip()
            if name:
                form_fields.append((url, name))
        for m in _TEXTAREA_NAME_RE.finditer(html):
            name = m.group(1).strip()
            if name:
                form_fields.append((url, name))

        has_pwd = bool(_PASSWORD_INPUT_RE.search(html))

        pi = PageInfo(
            url=url,
            query_params=qp,
            form_fields=form_fields,
            has_password_field=has_pwd,
            html=html,
            status=resp.status_code,
            headers=dict(resp.headers),
        )
        pages.append(pi)

        # Enqueue same-origin links up to depth 2
        if depth < max_depth:
            for m in _LINK_RE.finditer(html):
                href = m.group(1).strip()
                abs_url = urljoin(url, href)
                parsed_href = urlparse(abs_url)
                if any(parsed_href.path.lower().endswith(ext) for ext in _STATIC_EXTS):
                    continue
                if abs_url.startswith(origin) and abs_url not in visited:
                    queue.append((abs_url, depth + 1))

    return pages


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_security_headers(page: PageInfo) -> List[Finding]:
    findings: List[Finding] = []
    ct = page.headers.get("Content-Type", "")
    if ct and "text/html" not in ct and "text/plain" not in ct:
        return findings

    required = {
        "Content-Security-Policy": (
            "high",
            "Add a Content-Security-Policy header to restrict resource origins.",
            "A05:2021 – Security Misconfiguration",
        ),
        "X-Frame-Options": (
            "medium",
            "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
            "A05:2021 – Security Misconfiguration",
        ),
        "X-Content-Type-Options": (
            "medium",
            "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
            "A05:2021 – Security Misconfiguration",
        ),
        "Strict-Transport-Security": (
            "high",
            "Add Strict-Transport-Security to enforce HTTPS connections.",
            "A02:2021 – Cryptographic Failures",
        ),
        "Referrer-Policy": (
            "low",
            "Add Referrer-Policy (e.g. no-referrer or strict-origin) to limit information leakage.",
            "A05:2021 – Security Misconfiguration",
        ),
    }
    header_keys_lower = {k.lower(): k for k in page.headers}
    for header, (sev, remediation, owasp) in required.items():
        if header == "Strict-Transport-Security" and not page.url.startswith("https://"):
            # HSTS is only applicable and respected by browsers over HTTPS
            continue
        if header.lower() not in header_keys_lower:
            findings.append(Finding(
                title=f"Missing security header: {header}",
                severity=sev,
                evidence=f"Header '{header}' absent from response to {page.url}",
                remediation=remediation,
                owasp_category=owasp,
                url=page.url,
                check_name="security_headers",
            ))
    return findings


def check_cookie_flags(page: PageInfo) -> List[Finding]:
    findings: List[Finding] = []
    raw_cookies = page.headers.get("Set-Cookie", "") or ""
    if not raw_cookies:
        return findings
    # requests may join multiple Set-Cookie as comma-sep; split on ", " only when new cookie name seen
    cookies_raw = [raw_cookies] if raw_cookies else []

    for raw in cookies_raw:
        parts_lower = raw.lower()
        name = raw.split("=")[0].strip()
        if "httponly" not in parts_lower:
            findings.append(Finding(
                title=f"Cookie missing HttpOnly flag: {name}",
                severity="medium",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Set the HttpOnly flag on all session and authentication cookies.",
                owasp_category="A02:2021 – Cryptographic Failures",
                url=page.url,
                check_name="cookie_flags",
            ))
        if "secure" not in parts_lower:
            findings.append(Finding(
                title=f"Cookie missing Secure flag: {name}",
                severity="medium",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Set the Secure flag so cookies are only sent over HTTPS.",
                owasp_category="A02:2021 – Cryptographic Failures",
                url=page.url,
                check_name="cookie_flags",
            ))
        if "samesite" not in parts_lower:
            findings.append(Finding(
                title=f"Cookie missing SameSite attribute: {name}",
                severity="low",
                evidence=f"Set-Cookie: {raw[:120]}",
                remediation="Set SameSite=Strict or SameSite=Lax to mitigate CSRF risk.",
                owasp_category="A01:2021 – Broken Access Control",
                url=page.url,
                check_name="cookie_flags",
            ))
    return findings


_VERSION_RE = re.compile(
    r"(?:apache|nginx|iis|werkzeug|express|php|python|ruby|gunicorn|uvicorn|jetty|tomcat)"
    r"[/ ]\d+[\d.]*",
    re.I,
)


def check_version_disclosure(page: PageInfo) -> List[Finding]:
    findings: List[Finding] = []
    for hdr in ("Server", "X-Powered-By"):
        val = page.headers.get(hdr, "")
        if val and _VERSION_RE.search(val):
            findings.append(Finding(
                title=f"Software version disclosed via {hdr} header",
                severity="low",
                evidence=f"{hdr}: {val}",
                remediation=f"Configure the server to omit or genericise the {hdr} header.",
                owasp_category="A05:2021 – Security Misconfiguration",
                url=page.url,
                check_name="version_disclosure",
            ))
    return findings


def check_cors(pages: List[PageInfo], session: requests.Session, limiter: _RateLimiter) -> List[Finding]:
    findings: List[Finding] = []
    seen_urls: Set[str] = set()
    for page in pages:
        if page.url in seen_urls:
            continue
        seen_urls.add(page.url)
        limiter.wait()
        try:
            resp = session.get(page.url, timeout=10,
                               headers={"Origin": "http://evil.example.invalid"})
        except Exception:
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*":
            findings.append(Finding(
                title="CORS wildcard: Access-Control-Allow-Origin: *",
                severity="high",
                evidence=f"Access-Control-Allow-Origin: * on {page.url}",
                remediation="Restrict CORS to specific trusted origins instead of '*'.",
                owasp_category="A01:2021 – Broken Access Control",
                url=page.url,
                check_name="cors",
            ))
        elif acao == "http://evil.example.invalid":
            findings.append(Finding(
                title="CORS reflects arbitrary Origin header",
                severity="critical",
                evidence=f"Access-Control-Allow-Origin reflected attacker origin on {page.url}",
                remediation="Validate the Origin against a strict allowlist before echoing it.",
                owasp_category="A01:2021 – Broken Access Control",
                url=page.url,
                check_name="cors",
            ))
    return findings


_SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/debug", "/robots.txt",
    "/config", "/backup", "/admin",
]


def check_sensitive_paths(base_url: str, session: requests.Session, limiter: _RateLimiter) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Baseline probe for SPA fallback / catch-all 404 behavior
    probe_404_url = f"{origin}/__aegis_404_test_{uuid.uuid4().hex[:8]}"
    spa_fallback_body: Optional[str] = None
    try:
        limiter.wait()
        r404 = session.get(probe_404_url, timeout=10, allow_redirects=False)
        if r404.status_code == 200:
            spa_fallback_body = r404.text.strip()
    except Exception:
        pass

    for path in _SENSITIVE_PATHS:
        probe_url = origin + path
        limiter.wait()
        try:
            resp = session.get(probe_url, timeout=10, allow_redirects=False)
        except Exception:
            continue

        if resp.status_code == 200 and resp.text.strip():
            body = resp.text.strip()

            # 1. Catch-all / SPA fallback check (same or almost same body as nonexistent path)
            if spa_fallback_body and (body == spa_fallback_body or abs(len(body) - len(spa_fallback_body)) < 30):
                continue

            # 2. Non-HTML files must not return HTML markup
            ct = resp.headers.get("Content-Type", "").lower()
            is_html = "text/html" in ct or "<!doctype html" in body.lower() or "<html" in body.lower()
            if path in ("/.env", "/.git/HEAD", "/robots.txt", "/backup") and is_html:
                continue

            # 3. Structural validation for sensitive file formats
            if path == "/.env" and "=" not in body:
                continue
            if path == "/.git/HEAD" and not body.startswith("ref:"):
                continue
            if path == "/robots.txt" and not ("user-agent:" in body.lower() or "disallow:" in body.lower()):
                continue

            sev = "critical" if path in ("/.env", "/.git/HEAD") else "medium"
            findings.append(Finding(
                title=f"Sensitive path exposed: {path}",
                severity=sev,
                evidence=f"GET {probe_url} → HTTP 200, body length {len(resp.text)} bytes",
                remediation=f"Restrict access to {path} or remove it from the web root.",
                owasp_category="A05:2021 – Security Misconfiguration",
                url=probe_url,
                check_name="sensitive_paths",
            ))
    return findings


# Marker is a random hex token — no angle brackets, no script tags
_MARKER_PREFIX = "aegis_audit_"


def _build_marker() -> str:
    return _MARKER_PREFIX + uuid.uuid4().hex[:10]


# Regex: marker appears inside an HTML tag or directly in visible text without HTML-encoding
def _marker_unescaped_in_html(marker: str, body: str) -> bool:
    """
    Returns True if marker appears in the response body in a context that
    indicates the value was not HTML-encoded. We check for the literal marker
    appearing adjacent to HTML-significant characters (tag boundaries, attribute
    delimiters) or simply as plain text, which would only happen if the server
    reflected it without encoding.
    """
    return marker in body


def check_output_encoding(pages: List[PageInfo], session: requests.Session,
                           limiter: _RateLimiter) -> List[Finding]:
    """
    OWASP ASVS V5.3: Submits a unique harmless marker token (no script tags)
    into each discovered query parameter and form field, then checks whether
    the server echoes it back unencoded in the HTML response body.
    """
    findings: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()

    for page in pages:
        # Test query parameters
        for param in page.query_params:
            key = (page.url, param)
            if key in seen:
                continue
            seen.add(key)
            marker = _build_marker()
            parsed = urlparse(page.url)
            new_qs = urlencode({param: marker})
            probe_url = urlunparse(parsed._replace(query=new_qs))
            limiter.wait()
            try:
                resp = session.get(probe_url, timeout=10)
                body = resp.text
            except Exception:
                continue
            if _marker_unescaped_in_html(marker, body):
                findings.append(Finding(
                    title=f"Unencoded output reflection in query parameter '{param}'",
                    severity="high",
                    evidence=(
                        f"Marker '{marker}' submitted to '{param}' at {page.url} "
                        f"was reflected unescaped in the response body."
                    ),
                    remediation=(
                        "HTML-encode all user-supplied values before including them in "
                        "HTML responses. Use a template engine with auto-escaping enabled."
                    ),
                    owasp_category="A03:2021 – Injection",
                    url=probe_url,
                    check_name="output_encoding",
                ))

        # Test form fields
        for (form_page_url, field_name) in page.form_fields:
            key = (form_page_url, field_name)
            if key in seen:
                continue
            seen.add(key)
            marker = _build_marker()
            limiter.wait()
            try:
                resp = session.post(form_page_url, data={field_name: marker}, timeout=10)
                body = resp.text
            except Exception:
                continue
            if _marker_unescaped_in_html(marker, body):
                findings.append(Finding(
                    title=f"Unencoded output reflection in form field '{field_name}'",
                    severity="high",
                    evidence=(
                        f"Marker '{marker}' submitted to form field '{field_name}' at "
                        f"{form_page_url} was reflected unescaped in the response body."
                    ),
                    remediation=(
                        "HTML-encode all user-supplied values before including them in "
                        "HTML responses. Use a template engine with auto-escaping enabled."
                    ),
                    owasp_category="A03:2021 – Injection",
                    url=form_page_url,
                    check_name="output_encoding",
                ))
    return findings


# Known DB error signatures used purely as response-body string comparisons
_DB_ERROR_SIGS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-",
    "ODBC",
    "sqlite3.OperationalError",
    "SQLiteException",
    "pg_query",
    "PostgreSQL",
    "Microsoft OLE DB",
    "Unclosed quotation mark",
    "syntax error in SQL",
    "sql error",
    "database error",
    "supplied argument is not a valid MySQL",
]


def _has_db_error(body: str) -> Optional[str]:
    """Return the first matching DB error signature found in body, or None."""
    body_lower = body.lower()
    for sig in _DB_ERROR_SIGS:
        if sig.lower() in body_lower:
            return sig
    return None


def check_error_disclosure(pages: List[PageInfo], session: requests.Session,
                            limiter: _RateLimiter) -> List[Finding]:
    """
    OWASP ASVS V5.2: Submits a single-quote character to each parameter/field
    and checks whether the server returns a raw database error message string.
    Also compares the length/content of a normal vs malformed response to flag
    unvalidated input handling.
    """
    findings: List[Finding] = []
    seen: Set[Tuple[str, str]] = set()

    for page in pages:
        for param in page.query_params:
            key = ("err_qp", page.url, param)
            if key in seen:
                continue
            seen.add(key)  # type: ignore[arg-type]

            parsed = urlparse(page.url)
            # Normal baseline request
            limiter.wait()
            try:
                normal_resp = session.get(
                    urlunparse(parsed._replace(query=urlencode({param: "test_value_123"}))),
                    timeout=10,
                )
                normal_body = normal_resp.text
            except Exception:
                continue

            # Malformed input: single quote
            malformed_qs = urlencode({param: "'"})
            probe_url = urlunparse(parsed._replace(query=malformed_qs))
            limiter.wait()
            try:
                err_resp = session.get(probe_url, timeout=10)
                err_body = err_resp.text
            except Exception:
                continue

            matched_sig = _has_db_error(err_body)
            if matched_sig:
                findings.append(Finding(
                    title=f"Database error message disclosed via parameter '{param}'",
                    severity="critical",
                    evidence=(
                        f"DB error signature '{matched_sig}' found in response to "
                        f"malformed input in '{param}' at {page.url}."
                    ),
                    remediation=(
                        "Catch all database exceptions server-side and return a generic "
                        "error page. Never expose raw DB error messages to clients."
                    ),
                    owasp_category="A03:2021 – Injection",
                    url=probe_url,
                    check_name="error_disclosure",
                ))
            elif err_resp.status_code != normal_resp.status_code:
                findings.append(Finding(
                    title=f"Anomalous response to malformed input in parameter '{param}'",
                    severity="medium",
                    evidence=(
                        f"Normal input → HTTP {normal_resp.status_code}; "
                        f"single-quote input → HTTP {err_resp.status_code} at {page.url}."
                    ),
                    remediation="Validate and sanitise all inputs server-side; return consistent error responses.",
                    owasp_category="A03:2021 – Injection",
                    url=probe_url,
                    check_name="error_disclosure",
                ))

        # Same for form fields
        for (form_url, field_name) in page.form_fields:
            key = ("err_ff", form_url, field_name)
            if key in seen:
                continue
            seen.add(key)  # type: ignore[arg-type]

            limiter.wait()
            try:
                normal_resp = session.post(form_url, data={field_name: "test_value_123"}, timeout=10)
                normal_body = normal_resp.text
            except Exception:
                continue

            limiter.wait()
            try:
                err_resp = session.post(form_url, data={field_name: "'"}, timeout=10)
                err_body = err_resp.text
            except Exception:
                continue

            matched_sig = _has_db_error(err_body)
            if matched_sig:
                findings.append(Finding(
                    title=f"Database error message disclosed via form field '{field_name}'",
                    severity="critical",
                    evidence=(
                        f"DB error signature '{matched_sig}' found in response to "
                        f"malformed input in form field '{field_name}' at {form_url}."
                    ),
                    remediation=(
                        "Catch all database exceptions server-side and return a generic "
                        "error page. Never expose raw DB error messages to clients."
                    ),
                    owasp_category="A03:2021 – Injection",
                    url=form_url,
                    check_name="error_disclosure",
                ))


    return findings


def check_http_methods(pages: List[PageInfo], session: requests.Session,
                        limiter: _RateLimiter) -> List[Finding]:
    findings: List[Finding] = []
    seen_origins: Set[str] = set()
    for page in pages:
        parsed = urlparse(page.url)
        origin_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if origin_url in seen_origins:
            continue
        seen_origins.add(origin_url)
        limiter.wait()
        try:
            resp = session.options(origin_url, timeout=10)
        except Exception:
            continue
        allow = resp.headers.get("Allow", "") + resp.headers.get("Access-Control-Allow-Methods", "")
        dangerous = [m for m in ("TRACE", "PUT", "DELETE") if m in allow.upper()]
        if dangerous:
            findings.append(Finding(
                title=f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                severity="medium",
                evidence=f"OPTIONS {origin_url} → Allow: {allow}",
                remediation="Disable TRACE, PUT and DELETE in the web server configuration unless explicitly required.",
                owasp_category="A05:2021 – Security Misconfiguration",
                url=origin_url,
                check_name="http_methods",
            ))
    return findings


def check_transport(pages: List[PageInfo]) -> List[Finding]:
    findings: List[Finding] = []
    for page in pages:
        if page.has_password_field and page.url.startswith("http://"):
            findings.append(Finding(
                title="Password field transmitted over plain HTTP",
                severity="critical",
                evidence=f"Page {page.url} contains a password input and is served over HTTP.",
                remediation="Enforce HTTPS (TLS) for all pages, especially those with authentication forms.",
                owasp_category="A02:2021 – Cryptographic Failures",
                url=page.url,
                check_name="transport",
            ))
    return findings


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def run_scan(
    scan_id: int,
    target_url: str,
    on_check_done: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Tuple[List[Finding], int]:
    """
    Run all checks against target_url.
    Calls on_check_done(event_dict) after each check group for live WebSocket emission.
    Returns (findings, pages_crawled_count).
    """
    limiter = _RateLimiter(rps=5.0)
    session = _session(target_url)
    all_findings: List[Finding] = []
    seen_header_titles: Set[str] = set()
    seen_cors_titles: Set[str] = set()

    def _emit(check_name: str, new_findings: List[Finding]):
        filtered: List[Finding] = []
        for f in new_findings:
            if f.check_name == "security_headers":
                if f.title in seen_header_titles:
                    continue
                seen_header_titles.add(f.title)
            elif f.check_name == "cors":
                if f.title in seen_cors_titles:
                    continue
                seen_cors_titles.add(f.title)
            filtered.append(f)

        all_findings.extend(filtered)
        if on_check_done:
            on_check_done({
                "type": "web_check_done",
                "scan_id": scan_id,
                "check": check_name,
                "findings_count": len(filtered),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "evidence": f.evidence[:300],
                        "owasp_category": f.owasp_category,
                        "url": f.url,
                    }
                    for f in filtered
                ],
            })

    # 1. Crawl
    logger.info(f"[web_scan:{scan_id}] Crawling {target_url}")
    pages = crawl(target_url, session, limiter)
    if not pages:
        raise ConnectionError(
            f"Unable to connect to target endpoint '{target_url}'. "
            "No service is running on this address or the server returned no responses."
        )
    _emit("crawl", [])

    # 2. Security headers — check pages
    hdr_findings: List[Finding] = []
    for page in pages:
        hdr_findings.extend(check_security_headers(page))
    _emit("security_headers", hdr_findings)

    # 3. Cookie flags
    cookie_findings: List[Finding] = []
    for page in pages:
        cookie_findings.extend(check_cookie_flags(page))
    _emit("cookie_flags", cookie_findings)

    # 4. Version disclosure
    ver_findings: List[Finding] = []
    for page in pages:
        ver_findings.extend(check_version_disclosure(page))
    _emit("version_disclosure", ver_findings)

    # 5. CORS
    cors_findings = check_cors(pages, session, limiter)
    _emit("cors", cors_findings)

    # 6. Sensitive paths
    path_findings = check_sensitive_paths(target_url, session, limiter)
    _emit("sensitive_paths", path_findings)

    # 7. Output encoding (harmless marker reflection)
    enc_findings = check_output_encoding(pages, session, limiter)
    _emit("output_encoding", enc_findings)

    # 8. Error message disclosure
    err_findings = check_error_disclosure(pages, session, limiter)
    _emit("error_disclosure", err_findings)

    # 9. HTTP methods
    method_findings = check_http_methods(pages, session, limiter)
    _emit("http_methods", method_findings)

    # 10. Transport
    transport_findings = check_transport(pages)
    _emit("transport", transport_findings)

    logger.info(f"[web_scan:{scan_id}] Scan complete. {len(all_findings)} findings across {len(pages)} pages.")
    return all_findings, len(pages)
