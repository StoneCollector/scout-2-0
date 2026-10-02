# Aegis Security Suite — Technical Architecture & Audit Summary

**Product:** Aegis Enterprise Security Workstation (Malware Triage & OWASP Web Auditor)  
**Environment:** Windows 10/11 Architecture (Isolated Analysis VM)  
**Stack:** Python 3.10+, FastAPI, React 18, TypeScript 5, Vite, Tailwind CSS, SQLite, ClamAV, YARA  

---

## 1. Executive Summary

**Aegis** is an automated dual-vector security analysis workstation built for high-throughput static binary triage and web application vulnerability auditing. It provides security operations teams and vulnerability analysts with two core workflows unified under a dark-mode telemetry console:

1. **Configurable Ingestion & Static Binary Triage:** An automated analysis engine that monitors any local directory (defaulting to `inbox/` with dynamic runtime folder selection). Untrusted executables and installers are classified across 6 inspection layers without executing untrusted binaries.
2. **OWASP ASVS Web Security Auditor:** A lightweight, target-agnostic HTTP configuration and response auditor that crawls same-origin private web applications (e.g., `localhost`, RFC-1918 subnets) with anti-false-positive Single Page Application (SPA) detection, evaluating security headers, cookie flags, CORS policies, sensitive paths, output encoding (OWASP ASVS V5.3), and SQL error disclosure (V5.2).
3. **Consolidated Security Intelligence Reports:** A unified reporting engine delivering high-level surface metrics first, followed by detected entities ranked from highest to lowest severity, with complete Markdown, JSON, and print-ready export capabilities.

---

## 2. Core Architecture & Design Principles

```
                              ┌──────────────────────────────────────────────┐
                              │            AEGIS DASHBOARD (React+TS)        │
                              │   WebSockets  │  REST API  │  Real-time UI   │
                              └──────────────────────┬───────────────────────┘
                                                     │ HTTP / WS (:8000)
                                                     ▼
                              ┌──────────────────────────────────────────────┐
                              │            FASTAPI APPLICATION CORE          │
                              │ Dynamic Watcher │ Router │  WebSocket Bus    │
                              └──────┬───────────────────────────────┬───────┘
                                     │                               │
            ┌────────────────────────┴────────┐      ┌───────────────┴───────────────┐
            │   STATIC FILE ANALYSIS PIPELINE │      │    WEB APPLICATION AUDITOR    │
            │   (Non-Destructive Inspection)  │      │  (RFC1918 / Localhost Only)   │
            └────────────────┬────────────────┘      └───────────────┬───────────────┘
                             │                                       │
     ┌───────────────────────┼───────────────────────┐               │
     ▼                       ▼                       ▼               ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐   ┌───────────────────────┐
│ Authenticode │     │ ClamAV & YARA│     │  PE Entropy  │   │  OWASP ASVS Probes    │
│  & PKCS#7    │     │  Signatures  │     │   & Imports  │   │ Headers, CORS, XSS,   │
└──────────────┘     └──────────────┘     └──────────────┘   │ Paths, Cookie Flags   │
                                                             └───────────────────────┘
```

### Safety & Guardrails
- **Dynamic Ingestion Control:** Users can change the monitored folder at runtime from the dashboard (or reset back to `inbox/`).
- **Zero-Execution Policy:** Scanned binary files are never executed, loaded into memory spaces, or launched via child processes. All inspection is strictly structural (PE parsing, PKCS#7 certificate stream extraction, YARA pattern matching, clamd TCP streaming).
- **Target Restriction Guard:** The web scanner strictly refuses to scan public Internet domains. Target hostnames and IPs must resolve strictly to `127.0.0.1`, `localhost`, or private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Rate-Limited Probes:** Web probes are capped at 5 requests/sec with 10-second timeouts to prevent local service degradation.

---

## 3. Component Deep Dive

### Pillar A: Static Malware Analysis Pipeline

The file analysis pipeline monitors the designated watch folder and routes binaries through 6 discrete verification checkers:

| Checker | Method & Mechanism | Detection Capabilities |
| :--- | :--- | :--- |
| **`SignatureChecker`** | Sysinternals `sigcheck.exe` + `pefile` / `olefile` + `asn1crypto` | Authenticode signature verification, signer identity, digest algorithm (SHA-256 vs legacy SHA-1), and allowlisted publisher matching. |
| **`VendorHashChecker`** | SHA-256 streaming with local 24h cached vendor feeds | Cryptographic matching against official vendor checksums (VirtualBox, OWASP ZAP, Wireshark, LibreOffice). |
| **`ReputationChecker`** | MalwareBazaar API (abuse.ch) query | Global SHA-256 reputation lookup, signature tagging, intelligence delivery. |
| **`ClamAvChecker`** | Daemon TCP socket (`127.0.0.1:3310`) via `pyclamd` | Antivirus engine signature detection with background daemon auto-recovery. |
| **`YaraChecker`** | Compiled Neo23x0 `signature-base` rules | Detection of known malware families, hacktools, shellcodes, and suspicious strings. |
| **`PeStaticChecker`** | PE structure parsing via `pefile` | High section entropy (packed/compressed code), suspicious imports (`VirtualAlloc`, `WriteProcessMemory`), debug timestamp anomalies. |

#### Threat Scoring & Verdicts
- Aggregated multi-factor score determines the automated verdict:
  - **`PASS` (Score < 25):** File moved to `clean/`.
  - **`REVIEW` (Score 25–59):** File moved to `review/` pending analyst review.
  - **`BLOCK` (Score ≥ 60):** File quarantined to `quarantine/` with access restricted.

---

### Pillar B: Web Application Security Auditor

Engineered for automated vulnerability scanning of local target applications (such as the included "El Banco" target):

1. **Intelligent Crawler:**
   - Crawls same-origin HTML hyperlinks (`<a href="...">`) up to depth 2 (max 30 pages).
   - Automatically filters out static assets (`.css`, `.js`, `.svg`, `.png`, `.ico`) to eliminate false positives.
   - Extracts URL query parameters, form actions, input names, and password field markers.

2. **False-Positive Elimination Engine (SPA & Catch-All Awareness):**
   - Emits a baseline 404 probe before checking sensitive paths. When testing Single Page Applications (React, Vite, FastAPI) that return `index.html` with status 200 for missing pages, Aegis suppresses false alarms on `/.env`, `/.git/HEAD`, `/admin`, and `/backup`.
   - Verifies structural file content (e.g., `KEY=VALUE` for `.env`, `ref:` for `.git/HEAD`).

3. **10 Security Audit Checkpoints:**
   - **Security Headers:** Audits CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
   - **HSTS Enforcement:** Enforces HSTS only on `https://` contexts, ignoring plain HTTP development targets.
   - **Cookie Hardening:** Checks all `Set-Cookie` headers for `HttpOnly`, `Secure`, and `SameSite` flags.
   - **Version Disclosure:** Identifies software banners in `Server` and `X-Powered-By` headers.
   - **CORS Misconfigurations:** Flags wildcard `Access-Control-Allow-Origin: *` and dangerous origin reflection with credentials.
   - **Sensitive Paths:** Discovers real leaked configuration files and unprotected admin portals.
   - **Output Encoding (OWASP ASVS V5.3):** Injects non-destructive unique hex markers (`aegis_audit_<hex>`) into query parameters and form fields to verify contextual HTML escaping.
   - **Database Error Disclosure (OWASP ASVS V5.2):** Tests parameter error handling for raw SQL/database error leakages (SQLite, MySQL, Postgres, MSSQL, Oracle).
   - **Transport Security:** Flags password inputs served over unencrypted HTTP.
   - **Dangerous HTTP Methods:** Detects active `TRACE`, `PUT`, or `DELETE` capabilities via `OPTIONS` requests.

---

### Pillar C: Consolidated Reporting Architecture

1. **Unified Security Intelligence Report (`/tasks`):**
   - **Surface-Level Metrics:** Total Executables Audited, Quarantined Threats, Flagged for Review, Certified Clean, Fleet Threat Ratio.
   - **Entities Ordered by Severity (High to Low):** Quarantined threats displayed first, followed by suspicious binaries, then verified clean applications.
   - **Per-Entity Findings (High to Low):** ClamAV detections, YARA rules, untrusted certificates, section entropy warnings, and vendor checksum matches.
   - **Export Capabilities:** 1-click JSON export, CSV export, and Print-ready stylesheet.

2. **Executive Web Audit Report:**
   - Available directly inside the Web Auditor detail panel.
   - Executive target evaluation, coverage metrics, severity distribution matrix, and high-to-low remediation breakdown.
   - Exportable to GitHub-flavored Markdown (`.md`), raw JSON data (`.json`), or printable PDF.

---

## 4. Test Suite & Verification

The suite includes 38 comprehensive pytest unit and integration tests:

```
============================= test session starts =============================
platform win32 -- Python 3.10.0, pytest-9.1.1
collected 38 items

tests\test_api.py ....                                                   [ 10%]
tests\test_db.py .                                                       [ 13%]
tests\test_pe_static.py ...                                              [ 21%]
tests\test_reputation.py ......                                          [ 36%]
tests\test_scoring_pipeline.py ..                                        [ 42%]
tests\test_signature.py .....                                            [ 55%]
tests\test_vendor_hash.py ........                                       [ 76%]
tests\test_vulns.py ..                                                   [ 81%]
tests\test_web_scanner.py .......                                        [100%]

======================= 38 passed, 1 warning in 18.41s ========================
```
