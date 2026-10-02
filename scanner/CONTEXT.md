# CONTEXT
Demo malware scanner for a university project. Python 3.11, runs in a Windows VM. Never execute scanned files.
Layout (inside "C:\SEM VII\WAS\Project\scanner\app" # use "" to enclose the path):
  engine/  models.py config.py db.py checkers/ scoring.py pipeline.py watcher.py vulns.py
  api/main.py        (FastAPI, port 8000, CORS for http://localhost:5173)
  web/               (React+TS+Vite+Tailwind+shadcn/ui+Recharts)
  config.yaml        (paths, allowlisted signers, vendor hash sources)
  data/scanner.db    (SQLite)
Folders: "C:\SEM VII\WAS\Project\scanner\inbox", processing, clean, review, quarantine
Tools: "C:\SEM VII\WAS\Project\scanner\tools\sigcheck.exe", "C:\SEM VII\WAS\Project\scanner\rules\signature-base", clamd at 127.0.0.1:3310
Secrets from "C:\SEM VII\WAS\Project\scanner\.env": ABUSECH_KEY, NVD_KEY
Core types (engine/models.py):
  Result(checker:str, status:Literal["pass","warn","fail","skip"], score:int, details:dict)
  Checker base class: name:str; check(path:Path, ctx:dict)->Result
  Verdict: "pass"|"review"|"block"
Rules: type hints, small functions, no extra docs, no unrequested features. Every checker catches its own exceptions and returns status "skip" with the error in details.

# PACKAGING
Target: PyInstaller --onedir, Windows. Final folder ScannerApp\ with: ScannerApp.exe, _internal\, config.yaml, tools\ (sigcheck.exe, clamav\), rules\signature-base\, data\, inbox\ processing\ clean\ review\ quarantine\.
Two path roots: BUNDLE_DIR (read-only bundled files: web\dist, default config) = sys._MEIPASS when frozen, else project root. APP_DIR (writable: data, folders, tools, rules, .env, config.yaml) = directory of the exe when frozen, else project root.
FastAPI serves the built dashboard from BUNDLE_DIR\web\dist on the same port 8000. Single process serves everything.