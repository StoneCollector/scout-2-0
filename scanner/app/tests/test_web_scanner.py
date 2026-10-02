"""
tests/test_web_scanner.py

Spins up a small in-process HTTP server that deliberately:
  1. Returns a page with no security headers.
  2. Echoes a query parameter unencoded into an HTML response.
  3. Returns a fake database error string when it receives a single-quote input.

Asserts that the web scanner's check functions detect all three findings.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from typing import List

import pytest

from engine.web_scanner import (
    Finding,
    PageInfo,
    _RateLimiter,
    _session,
    check_security_headers,
    check_output_encoding,
    check_error_disclosure,
    _build_marker,
    _marker_unescaped_in_html,
    _has_db_error,
    validate_target,
)


# ---------------------------------------------------------------------------
# Minimal mock HTTP server
# ---------------------------------------------------------------------------

class _MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):          # silence server logs during tests
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path

        if path == "/noheaders":
            # Page 1: deliberately missing all security headers
            body = b"<html><body>No headers here.</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/echo":
            # Page 2: echoes the 'q' param unescaped into HTML
            q = qs.get("q", [""])[0]
            raw_body = f"<html><body><p>You searched for: {q}</p></body></html>"
            body = raw_body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/sqlerr":
            # Page 3: returns a fake DB error string when q contains a single quote
            q = qs.get("q", [""])[0]
            if "'" in q:
                raw_body = (
                    "<html><body>sqlite3.OperationalError: near \"'\": syntax error</body></html>"
                )
            else:
                raw_body = "<html><body>OK</body></html>"
            body = raw_body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        qs = parse_qs(raw)
        # Mirror same logic as GET /echo and /sqlerr for form-field tests
        body = b"<html><body>POST OK</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_mock_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)   # port 0 → OS picks free port
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_server():
    server, base = _start_mock_server()
    yield base
    server.shutdown()


@pytest.fixture(scope="module")
def limiter():
    return _RateLimiter(rps=50.0)   # high rate for fast tests


@pytest.fixture(scope="module")
def http_session(mock_server):
    return _session(mock_server)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_validate_target_private():
    assert validate_target("http://127.0.0.1:9000")
    assert validate_target("http://localhost:8000")
    assert validate_target("http://192.168.1.1")


def test_validate_target_rejects_public():
    with pytest.raises(ValueError, match="not a localhost"):
        validate_target("http://example.com")


def test_missing_security_headers(mock_server, http_session, limiter):
    """Page /noheaders must trigger findings for every required header."""
    import requests
    resp = http_session.get(mock_server + "/noheaders", timeout=5)
    page = PageInfo(
        url=mock_server + "/noheaders",
        status=resp.status_code,
        headers=dict(resp.headers),
        html=resp.text,
    )
    findings: List[Finding] = check_security_headers(page)

    titles = [f.title for f in findings]
    assert any("Content-Security-Policy" in t for t in titles), \
        "Expected CSP missing finding"
    assert any("X-Frame-Options" in t for t in titles), \
        "Expected X-Frame-Options missing finding"
    assert any("X-Content-Type-Options" in t for t in titles), \
        "Expected X-Content-Type-Options missing finding"
    assert len(findings) >= 3


def test_output_encoding_finding(mock_server, http_session, limiter):
    """
    /echo?q=<marker> returns the marker unescaped — check_output_encoding
    must detect it as an unencoded reflection finding.
    """
    # Build a synthetic PageInfo that lists 'q' as a query parameter
    page = PageInfo(
        url=mock_server + "/echo?q=test",
        query_params=["q"],
        html="<html></html>",
        status=200,
        headers={},
    )
    findings = check_output_encoding([page], http_session, limiter)
    assert findings, "Expected at least one output-encoding finding"
    assert any("q" in f.title for f in findings), \
        f"Expected finding mentioning 'q', got: {[f.title for f in findings]}"


def test_error_disclosure_finding(mock_server, http_session, limiter):
    """
    /sqlerr?q=' triggers a fake sqlite3.OperationalError response —
    check_error_disclosure must detect the DB error signature.
    """
    page = PageInfo(
        url=mock_server + "/sqlerr?q=ok",
        query_params=["q"],
        html="<html></html>",
        status=200,
        headers={},
    )
    findings = check_error_disclosure([page], http_session, limiter)
    assert findings, "Expected at least one error-disclosure finding"
    assert any("database error" in f.title.lower() or "sqlite" in f.evidence.lower()
               for f in findings), \
        f"Expected DB-error finding, got: {[(f.title, f.evidence) for f in findings]}"


def test_marker_detection():
    """Unit test for the marker reflection helper."""
    marker = _build_marker()
    assert _marker_unescaped_in_html(marker, f"<p>{marker}</p>")
    assert not _marker_unescaped_in_html(marker, "<p>nothing here</p>")


def test_db_error_detection():
    """Unit test for the DB error signature helper."""
    assert _has_db_error("Error: sqlite3.OperationalError near quote") == "sqlite3.OperationalError"
    assert _has_db_error("SQL syntax error near 'DROP'") == "SQL syntax"
    assert _has_db_error("Everything went fine") is None


def test_offline_endpoint_raises_connection_error():
    """Scanning an offline / closed port must raise ConnectionError instead of reporting safe."""
    import socket
    from engine.web_scanner import run_scan
    
    # Pick a port that is guaranteed closed
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    closed_port = s.getsockname()[1]
    s.close()
    
    with pytest.raises(ConnectionError, match="Unable to connect to target endpoint"):
        run_scan(999, f"http://127.0.0.1:{closed_port}")

