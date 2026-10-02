<div align="center">

# 🛡️ Scout Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Tests](https://img.shields.io/badge/Tests-39%2F39%20Passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)]()

<p align="center">
  Unified binary triage engine and automated OWASP ASVS web security operations platform.
</p>

</div>

---

## 📁 Repository Structure

- [`scanner/`](./scanner) — **Scout**: The core file monitor, binary analysis pipeline, and OWASP web vulnerability auditor.
- [`dummy_bank/`](./dummy_bank) — **El Banco**: A standalone demonstration vulnerable banking application running on port 5000 for web auditing tests.
- [`UI_DESIGN_GUIDELINES.md`](./UI_DESIGN_GUIDELINES.md) — Reusable minimalist UI/UX design specifications and copywriting standards.

---

## ⚡ Quick Start

### 1. Run Scout
No Node.js or npm is required to run Scout—the frontend is precompiled into `scanner/app/web/dist/` and served directly by FastAPI.

```powershell
cd scanner
python -m venv .venv
.\.venv\Scripts\activate
pip install -r app/requirements.txt
.\run.bat
```
Visit **http://localhost:8000** in your browser.

### 2. (Optional) Run Vulnerable Test Target
In a second terminal:
```powershell
cd dummy_bank
.\run.bat
```
Starts "El Banco" on **http://127.0.0.1:5000**. You can test Scout's Web Auditor against this endpoint.

---

## 📦 Standalone Deployment Note

This repository is optimized for quick cloning and deployment (~262 MB footprint):
- **Precompiled Frontend**: React SPA bundle is served directly from `scanner/app/web/dist/` by FastAPI.
- **Embedded Engines**: Includes offline ClamAV binaries & virus definitions, YARA rules, and Windows Authenticode extractors.
- **Zero Extraneous Bloat**: Development compilation artifacts (`.pdb` debug databases, C/Rust static libraries, and sample installers) have been stripped from the repository.

---

## 🧪 Testing

To run the automated test suite (39 tests):
```powershell
cd scanner
.\.venv\Scripts\python -m pytest app\tests -o pythonpath=app -v
```

---

## 📄 Documentation

- [Detailed Scout Architecture & Pipeline Documentation](./scanner/README.md)
- [System Architecture Summary](./scanner/summary.md)
- [UI/UX Design Standards](./UI_DESIGN_GUIDELINES.md)
