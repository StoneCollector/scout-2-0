"""
app.py - "El Banco" Intentionally Vulnerable Banking Target
Used for Web Application Security testing with Scout Web Scanner.
Zero external dependencies (uses Python standard library http.server).
Runs by default on http://127.0.0.1:5000
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
from urllib.parse import parse_qs, urlparse


PORT = 5000
HOST = "127.0.0.1"


class VulnerableBankHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Unix) OpenSSL/1.1.1d"
    sys_version = ""

    def log_message(self, format, *args):
        # Print concise request log
        sys.stdout.write(f"[El Banco] {self.command} {self.path} -> {args[1]}\n")
        sys.stdout.flush()

    def _send_common_headers(self, content_type="text/html; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # Deliberately permissive CORS
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, TRACE, PUT")
        self.send_header("Access-Control-Allow-Headers", "*")
        # Insecure cookie: missing HttpOnly, Secure, and SameSite
        self.send_header("Set-Cookie", "banco_session=usr_token_991823ab; Path=/")
        # Deliberately omitting CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE, PUT")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, TRACE, PUT")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # 1. Sensitive path: /.env
        if path == "/.env":
            self._send_common_headers(content_type="text/plain; charset=utf-8")
            self.end_headers()
            env_content = (
                "# El Banco Internal Configuration\n"
                "DB_USER=banco_db_admin\n"
                "DB_PASSWORD=SuperSecretBankAdmin123!\n"
                "JWT_SECRET=banco_live_secret_key_84920481\n"
                "STRIPE_API_KEY=sk_live_51M0xDemoKeyNotReal\n"
            )
            self.wfile.write(env_content.encode("utf-8"))
            return

        # 2. Sensitive path: /robots.txt
        if path == "/robots.txt":
            self._send_common_headers(content_type="text/plain; charset=utf-8")
            self.end_headers()
            robots_content = "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n"
            self.wfile.write(robots_content.encode("utf-8"))
            return

        # 3. Sensitive path: /admin
        if path == "/admin":
            self._send_common_headers()
            self.end_headers()
            html = """<!DOCTYPE html>
<html>
<head><title>El Banco - Admin Portal</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem;">
  <h1>El Banco Admin Console</h1>
  <p style="color: #ef4444;">WARNING: Unauthenticated access permitted.</p>
  <ul>
    <li>Total Customer Accounts: 1,420</li>
    <li>Ledger Balance: $42,500,000.00</li>
  </ul>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # 4. Sensitive path: /config or /backup
        if path in ("/config", "/backup", "/debug"):
            self._send_common_headers(content_type="text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Internal configuration dump for {path}\nDEBUG_MODE=True\n".encode("utf-8"))
            return

        # 5. Search page: Reflected XSS parameter (Output encoding failure)
        if path == "/search":
            q = qs.get("q", [""])[0]
            self._send_common_headers()
            self.end_headers()
            html = f"""<!DOCTYPE html>
<html>
<head><title>El Banco - Transaction Search</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem;">
  <h1>Transaction Search</h1>
  <form action="/search" method="GET">
    <input type="text" name="q" value="{q}" placeholder="Search transactions..." style="padding: 8px;" />
    <button type="submit" style="padding: 8px 16px;">Search</button>
  </form>
  <div style="margin-top: 1.5rem; padding: 1rem; background: #1e293b; border-radius: 8px;">
    <h3>Search Results for: {q}</h3>
    <p>No transactions matched your query.</p>
  </div>
  <p><a href="/" style="color: #38bdf8;">&larr; Back to Home</a></p>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # 6. Login page: Password input over plain HTTP
        if path == "/login":
            self._send_common_headers()
            self.end_headers()
            html = """<!DOCTYPE html>
<html>
<head><title>El Banco - Sign In</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem;">
  <h2>Account Sign In</h2>
  <form action="/login" method="POST" style="display: flex; flex-direction: column; max-width: 320px; gap: 12px;">
    <input type="text" name="username" placeholder="Account Number or Username" style="padding: 8px;" />
    <input type="password" name="password" placeholder="Password" style="padding: 8px;" />
    <button type="submit" style="padding: 10px; background: #2563eb; color: white; border: none; border-radius: 4px;">Sign In</button>
  </form>
  <p><a href="/" style="color: #38bdf8;">&larr; Back to Home</a></p>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # 7. Transfer page: SQL error message disclosure
        if path == "/transfer":
            acc = qs.get("account", [""])[0]
            err_msg = ""
            if "'" in acc or "DROP" in acc.upper():
                err_msg = f'<div style="color: #f87171; background: #450a0a; padding: 12px; margin-top: 10px; font-family: monospace;">sqlite3.OperationalError: near "\'": syntax error in SELECT * FROM accounts WHERE id = \'{acc}\'</div>'

            self._send_common_headers()
            self.end_headers()
            html = f"""<!DOCTYPE html>
<html>
<head><title>El Banco - Wire Transfer</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem;">
  <h2>Instant Wire Transfer</h2>
  <form action="/transfer" method="GET" style="display: flex; flex-direction: column; max-width: 360px; gap: 12px;">
    <input type="text" name="account" value="{acc}" placeholder="Recipient Account ID" style="padding: 8px;" />
    <input type="text" name="amount" placeholder="Amount ($USD)" style="padding: 8px;" />
    <button type="submit" style="padding: 10px; background: #059669; color: white; border: none; border-radius: 4px;">Send Wire</button>
  </form>
  {err_msg}
  <p><a href="/" style="color: #38bdf8;">&larr; Back to Home</a></p>
</body>
</html>"""
            self.wfile.write(html.encode("utf-8"))
            return

        # Default: Homepage (links to all demo pages)
        self._send_common_headers()
        self.end_headers()
        html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>El Banco - Digital Banking</title>
</head>
<body style="font-family: system-ui, -apple-system, sans-serif; background: #090d16; color: #e2e8f0; margin: 0; padding: 2rem;">
  <div style="max-width: 720px; margin: 0 auto;">
    <div style="display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #1e293b; padding-bottom: 1rem;">
      <div style="font-size: 2rem;">🏦</div>
      <div>
        <h1 style="margin: 0; color: #38bdf8; font-size: 1.5rem;">El Banco Digital</h1>
        <p style="margin: 0; color: #94a3b8; font-size: 0.85rem;">Test Target Environment</p>
      </div>
    </div>

    <div style="margin-top: 1.5rem; background: #1e293b; padding: 1.25rem; border-radius: 8px; border: 1px solid #334155;">
      <h3 style="margin-top: 0; color: #f1f5f9;">Active Endpoints</h3>
      <ul style="line-height: 1.8;">
        <li><a href="/login" style="color: #38bdf8;">Sign In Portal</a> (Password input over plain HTTP)</li>
        <li><a href="/search?q=test" style="color: #38bdf8;">Transaction Search</a> (Output encoding probe)</li>
        <li><a href="/transfer?account=ACC100" style="color: #38bdf8;">Funds Transfer</a> (SQL injection error disclosure)</li>
        <li><a href="/admin" style="color: #38bdf8;">Internal Admin Portal</a> (Unprotected sensitive route)</li>
        <li><a href="/.env" style="color: #38bdf8;">Environment Secrets File</a> (Information disclosure)</li>
      </ul>
    </div>
  </div>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length).decode("utf-8")
        parsed_post = parse_qs(post_data)

        # For transfer or login POSTs, trigger SQL error if single quote is present
        err_msg = ""
        for field, values in parsed_post.items():
            for val in values:
                if "'" in val:
                    err_msg = f"sqlite3.OperationalError: near '{val}': syntax error"
                    break

        self._send_common_headers()
        self.end_headers()
        if err_msg:
            resp = f"<html><body><p>{err_msg}</p></body></html>"
        else:
            resp = "<html><body><p>Request processed successfully.</p></body></html>"
        self.wfile.write(resp.encode("utf-8"))


def run():
    server = HTTPServer((HOST, PORT), VulnerableBankHandler)
    print(f"============================================================")
    print(f"  El Banco Test Target")
    print(f"  Listening on: http://{HOST}:{PORT}")
    print(f"  Ready for Scout Web Scanner")
    print(f"============================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down test server.")
        server.server_close()


if __name__ == "__main__":
    run()
