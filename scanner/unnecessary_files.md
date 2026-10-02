# Scout Scanner — Unnecessary Files & Space Optimization Audit

> **Audit Date**: 2026-10-02  
> **Current Scanner Directory Size**: **2032.46 MB** (2,131,187,644 bytes)  
> **Total Unnecessary / Reducible Size**: **1770.90 MB** (1,856,925,544 bytes)  
> **Projected Post-Cleanup Size**: **261.56 MB** (274,262,100 bytes)  
> **Total Reduction**: **87.1% space saved**  

---

## Executive Summary

| # | Category | Files | Size (MB) | Size (Bytes) | Safety Level |
|:---|:---|---:|---:|---:|:---|
| 1 | **Test Sample Installers (Third-Party Binaries)** | 4 | 703.60 MB | 737,779,690 bytes | `Safe to Archive / Delete` |
| 2 | **ClamAV Debug Symbols (.pdb)** | 14 | 466.16 MB | 488,808,448 bytes | `100% Safe to Delete` |
| 3 | **ClamAV Development Static Libraries (.lib / .exp)** | 6 | 292.11 MB | 306,297,890 bytes | `100% Safe to Delete` |
| 4 | **ClamAV Unused Auxiliary Binaries** | 5 | 56.27 MB | 59,002,368 bytes | `100% Safe to Delete` |
| 5 | **ClamAV Offline User Manual (HTML/JS/CSS)** | 123 | 8.86 MB | 9,287,552 bytes | `100% Safe to Delete` |
| 6 | **Signature-Base Upstream Git History (.git)** | 36 | 84.79 MB | 88,906,133 bytes | `100% Safe to Delete` |
| 7 | **Frontend Build Dependencies (app/web/node_modules/)** | 13,924 | 158.92 MB | 166,638,452 bytes | `Safe to Remove in Production` |
| 8 | **Python & Test Execution Caches (__pycache__, .pytest_cache)** | 40 | 0.16 MB | 163,779 bytes | `100% Safe to Delete` |
| 9 | **Temporary Scratch Files & Ephemeral Caches** | 6 | 0.04 MB | 41,232 bytes | `100% Safe to Delete` |
| | **TOTAL REDUCIBLE** | **14,158** | **1770.90 MB** | **1,856,925,544 bytes** | **87.1% Reducible** |

---

## Category Breakdown & Itemized Details

### 1. Test Sample Installers (Third-Party Binaries)
- **Safety Level**: `Safe to Archive / Delete`
- **Total Items**: 4
- **Total Size**: **703.60 MB** (737,779,690 bytes)
- **Rationale**: Massive third-party installation binaries placed in samples/ during early manual testing. Not required for Scout operation.

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `samples/LibreOffice_26.8.0_Win_x86-64.msi` | 357.54 MB | 374,906,880 bytes |
| `samples/ZAP_2.17.0_Linux.tar.gz` | 232.60 MB | 243,895,361 bytes |
| `samples/Wireshark-4.6.8-x64.exe` | 94.35 MB | 98,934,936 bytes |
| `samples/Oracle_VirtualBox_Extension_Pack-7.2.20.vbox-extpack` | 19.11 MB | 20,042,513 bytes |

### 2. ClamAV Debug Symbols (.pdb)
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 14
- **Total Size**: **466.16 MB** (488,808,448 bytes)
- **Rationale**: MSVC Program Database debug symbol files bundled in the Windows ClamAV distribution. Only used for C++ debugging; completely unused during runtime.

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `clamav/libclamav.pdb` | 117.53 MB | 123,236,352 bytes |
| `clamav/sigtool.pdb` | 111.37 MB | 116,781,056 bytes |
| `clamav/libfreshclam.pdb` | 111.34 MB | 116,748,288 bytes |
| `clamav/clambc.pdb` | 111.09 MB | 116,486,144 bytes |
| `clamav/libclamunrar.pdb` | 3.25 MB | 3,411,968 bytes |
| `clamav/clamd.pdb` | 1.56 MB | 1,634,304 bytes |
| `clamav/clamscan.pdb` | 1.54 MB | 1,609,728 bytes |
| `clamav/clamdscan.pdb` | 1.50 MB | 1,568,768 bytes |
| `clamav/freshclam.pdb` | 1.43 MB | 1,503,232 bytes |
| `clamav/clamsubmit.pdb` | 1.32 MB | 1,380,352 bytes |
| `clamav/clamdtop.pdb` | 1.31 MB | 1,372,160 bytes |
| `clamav/clamconf.pdb` | 1.20 MB | 1,257,472 bytes |
| `clamav/libclamunrar_iface.pdb` | 0.90 MB | 946,176 bytes |
| `clamav/libclammspack.pdb` | 0.83 MB | 872,448 bytes |

### 3. ClamAV Development Static Libraries (.lib / .exp)
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 6
- **Total Size**: **292.11 MB** (306,297,890 bytes)
- **Rationale**: Compile-time C/Rust linking libraries bundled with ClamAV. Scout only invokes executables (clamd.exe, clamscan.exe) and never links against these.

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `clamav/clamav_rust.lib` | 291.60 MB | 305,767,286 bytes |
| `clamav/clamav.lib` | 0.25 MB | 259,290 bytes |
| `clamav/clamunrar.lib` | 0.23 MB | 243,530 bytes |
| `clamav/clammspack.lib` | 0.01 MB | 13,718 bytes |
| `clamav/freshclam.lib` | 0.01 MB | 9,752 bytes |
| `clamav/clamunrar_iface.lib` | 0.00 MB | 4,314 bytes |

### 4. ClamAV Unused Auxiliary Binaries
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 5
- **Total Size**: **56.27 MB** (59,002,368 bytes)
- **Rationale**: Standalone signature generation and bytecode development utilities bundled with ClamAV. Never invoked by Scout pipeline.

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `clamav/sigtool.exe` | 27.89 MB | 29,249,536 bytes |
| `clamav/clambc.exe` | 27.74 MB | 29,089,792 bytes |
| `clamav/clamdtop.exe` | 0.23 MB | 238,592 bytes |
| `clamav/clamsubmit.exe` | 0.21 MB | 219,648 bytes |
| `clamav/clamconf.exe` | 0.20 MB | 204,800 bytes |

### 5. ClamAV Offline User Manual (HTML/JS/CSS)
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 123
- **Total Size**: **8.86 MB** (9,287,552 bytes)
- **Rationale**: Static offline HTML/JS/CSS user manual bundled in clamav/UserManual/. Never served or accessed by Scout.

*(Showing top 15 largest files out of 123 total files)*

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `clamav/UserManual/mermaid-eefea253.min.js` | 2.54 MB | 2,667,011 bytes |
| `clamav/UserManual/searchindex-f120d447.js` | 1.80 MB | 1,887,203 bytes |
| `clamav/UserManual/print.html` | 0.65 MB | 682,520 bytes |
| `clamav/UserManual/ace-2a3cd908.js` | 0.35 MB | 371,590 bytes |
| `clamav/UserManual/images/clamav-git-workflow.png` | 0.14 MB | 145,717 bytes |
| `clamav/UserManual/highlight-abc7f01d.js` | 0.13 MB | 137,537 bytes |
| `clamav/UserManual/images/create-a-fork.png` | 0.13 MB | 131,552 bytes |
| `clamav/UserManual/images/clone-your-fork.png` | 0.12 MB | 130,737 bytes |
| `clamav/UserManual/images/change-fork-name.png` | 0.07 MB | 76,591 bytes |
| `clamav/UserManual/images/fork-is-behind.png` | 0.07 MB | 73,982 bytes |
| `clamav/UserManual/fonts/source-code-pro-v11-all-charsets-500-2bdd9410.woff2` | 0.06 MB | 59,140 bytes |
| `clamav/UserManual/manual/Signatures/PhishSigs.html` | 0.05 MB | 53,455 bytes |
| `clamav/UserManual/manual/Installing/Docker.html` | 0.05 MB | 52,889 bytes |
| `clamav/UserManual/manual/Development/Contribute.html` | 0.05 MB | 51,570 bytes |
| `clamav/UserManual/manual/Signatures/LogicalSignatures.html` | 0.05 MB | 49,894 bytes |
| *... and 108 additional files* | *2.59 MB* | *2,716,164 bytes* |

### 6. Signature-Base Upstream Git History (.git)
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 36
- **Total Size**: **84.79 MB** (88,906,133 bytes)
- **Rationale**: Full Git history and pack files from cloning Neo23x0/signature-base. Only the extracted .yar/.yara rule files are compiled and used by YARA.

*(Showing top 15 largest files out of 36 total files)*

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `rules/signature-base/.git/objects/pack/pack-8883483f1400b229c7632cdd046e65aba3968f0a.pack` | 41.90 MB | 43,932,247 bytes |
| `rules/signature-base/.git/objects/pack/pack-3e13d59f93f5ddc71a7fe5311a716026a1c6d0e5.pack` | 41.89 MB | 43,926,710 bytes |
| `rules/signature-base/.git/objects/pack/pack-8883483f1400b229c7632cdd046e65aba3968f0a.idx` | 0.39 MB | 411,356 bytes |
| `rules/signature-base/.git/objects/pack/pack-3e13d59f93f5ddc71a7fe5311a716026a1c6d0e5.idx` | 0.39 MB | 411,020 bytes |
| `rules/signature-base/.git/index` | 0.07 MB | 73,663 bytes |
| `rules/signature-base/.git/objects/pack/pack-8883483f1400b229c7632cdd046e65aba3968f0a.rev` | 0.06 MB | 58,664 bytes |
| `rules/signature-base/.git/objects/pack/pack-3e13d59f93f5ddc71a7fe5311a716026a1c6d0e5.rev` | 0.06 MB | 58,616 bytes |
| `rules/signature-base/.git/hooks/pre-rebase.sample` | 0.00 MB | 4,898 bytes |
| `rules/signature-base/.git/hooks/fsmonitor-watchman.sample` | 0.00 MB | 4,726 bytes |
| `rules/signature-base/.git/hooks/update.sample` | 0.00 MB | 3,650 bytes |
| `rules/signature-base/.git/hooks/push-to-checkout.sample` | 0.00 MB | 2,783 bytes |
| `rules/signature-base/.git/hooks/sendemail-validate.sample` | 0.00 MB | 2,308 bytes |
| `rules/signature-base/.git/FETCH_HEAD` | 0.00 MB | 2,235 bytes |
| `rules/signature-base/.git/hooks/pre-commit.sample` | 0.00 MB | 1,649 bytes |
| `rules/signature-base/.git/packed-refs` | 0.00 MB | 1,542 bytes |
| *... and 21 additional files* | *0.01 MB* | *10,066 bytes* |

### 7. Frontend Build Dependencies (app/web/node_modules/)
- **Safety Level**: `Safe to Remove in Production`
- **Total Items**: 13,924
- **Total Size**: **158.92 MB** (166,638,452 bytes)
- **Rationale**: Node modules used during Vite frontend compilation. The frontend is already precompiled into standalone app/web/dist/ (730 KB) which FastAPI serves directly.

*(Showing top 15 largest files out of 13,924 total files)*

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `app/web/node_modules/@rolldown/binding-win32-x64-msvc/rolldown-binding.win32-x64-msvc.node` | 20.20 MB | 21,176,832 bytes |
| `app/web/node_modules/@oxlint/binding-win32-x64-msvc/oxlint.win32-x64-msvc.node` | 12.67 MB | 13,284,352 bytes |
| `app/web/node_modules/lightningcss-win32-x64-msvc/lightningcss.win32-x64-msvc.node` | 9.05 MB | 9,484,800 bytes |
| `app/web/node_modules/typescript/lib/typescript.js` | 8.72 MB | 9,144,216 bytes |
| `app/web/node_modules/lucide-react/dist/cjs/lucide-react.js.map` | 6.98 MB | 7,317,903 bytes |
| `app/web/node_modules/typescript/lib/_tsc.js` | 5.95 MB | 6,239,091 bytes |
| `app/web/node_modules/tailwindcss/peers/index.js` | 4.30 MB | 4,504,586 bytes |
| `app/web/node_modules/recharts/umd/Recharts.js.map` | 2.80 MB | 2,940,220 bytes |
| `app/web/node_modules/lucide-react/dynamic.d.mts` | 2.48 MB | 2,605,620 bytes |
| `app/web/node_modules/lucide-react/dynamic.d.ts` | 2.48 MB | 2,605,620 bytes |
| `app/web/node_modules/lucide-react/dynamicIconImports.d.mts` | 2.48 MB | 2,604,402 bytes |
| `app/web/node_modules/lucide-react/dynamicIconImports.d.ts` | 2.48 MB | 2,604,402 bytes |
| `app/web/node_modules/typescript/lib/lib.dom.d.ts` | 2.24 MB | 2,349,483 bytes |
| `app/web/node_modules/lucide-react/dist/lucide-react.d.ts` | 2.15 MB | 2,253,506 bytes |
| `app/web/node_modules/lucide-react/dist/lucide-react.prefixed.d.ts` | 2.06 MB | 2,156,303 bytes |
| *... and 13,909 additional files* | *71.88 MB* | *75,367,116 bytes* |

### 8. Python & Test Execution Caches (__pycache__, .pytest_cache)
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 40
- **Total Size**: **0.16 MB** (163,779 bytes)
- **Rationale**: Precompiled Python bytecode (.pyc) and pytest execution caches. Automatically regenerated on-demand by Python.

*(Showing top 15 largest files out of 40 total files)*

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `app/engine/__pycache__/web_scanner.cpython-310.pyc` | 0.02 MB | 20,734 bytes |
| `app/api/__pycache__/main.cpython-310.pyc` | 0.02 MB | 18,949 bytes |
| `app/tests/__pycache__/test_web_scanner.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 10,589 bytes |
| `app/engine/__pycache__/db.cpython-310.pyc` | 0.01 MB | 9,254 bytes |
| `app/engine/checkers/__pycache__/vendor_hash.cpython-310.pyc` | 0.01 MB | 7,881 bytes |
| `app/tests/__pycache__/test_vendor_hash.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 7,190 bytes |
| `app/tests/__pycache__/test_api.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 6,516 bytes |
| `app/tests/__pycache__/test_signature.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 6,366 bytes |
| `app/tests/__pycache__/test_reputation.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 6,353 bytes |
| `app/engine/__pycache__/watcher.cpython-310.pyc` | 0.01 MB | 5,339 bytes |
| `app/tests/__pycache__/test_pe_static.cpython-310-pytest-9.1.1.pyc` | 0.01 MB | 5,244 bytes |
| `app/tests/__pycache__/test_scoring_pipeline.cpython-310-pytest-9.1.1.pyc` | 0.00 MB | 5,025 bytes |
| `app/engine/__pycache__/pipeline.cpython-310.pyc` | 0.00 MB | 4,717 bytes |
| `app/engine/checkers/__pycache__/signature.cpython-310.pyc` | 0.00 MB | 4,683 bytes |
| `app/engine/__pycache__/config.cpython-310.pyc` | 0.00 MB | 4,638 bytes |
| *... and 25 additional files* | *0.04 MB* | *40,301 bytes* |

### 9. Temporary Scratch Files & Ephemeral Caches
- **Safety Level**: `100% Safe to Delete`
- **Total Items**: 6
- **Total Size**: **0.04 MB** (41,232 bytes)
- **Rationale**: Temporary cleanup scripts (tools/clean_test_db.py), agent skill markdowns (.agent/), and temporary crawler feeds (app/data/feeds/).

| File Path | Size (MB) | Exact Bytes |
|:---|---:|---:|
| `.agent/skills/kpi-dashboard-design/SKILL.md` | 0.02 MB | 17,740 bytes |
| `.agent/skills/ui-ux-designer/SKILL.md` | 0.01 MB | 9,479 bytes |
| `AUTOMATED_ISOLATION_PROPOSAL.md` | 0.00 MB | 4,747 bytes |
| `app/data/feeds/libreoffice_page_78df225cf1583f56.txt` | 0.00 MB | 4,552 bytes |
| `app/data/feeds/wireshark_sigs_fd94d73c39e40a68.txt` | 0.00 MB | 3,963 bytes |
| `tools/clean_test_db.py` | 0.00 MB | 751 bytes |

---

## Retained Essential Runtime Files
After removing the unnecessary files above, the scanner directory will contain only the lean runtime components:

| Essential Component | Location | Estimated Size | Purpose |
|:---|:---|---:|:---|
| **ClamAV Antivirus Signatures** | `clamav/database/` (main.cvd, daily.cvd) | ~107.57 MB | Core offline virus signature definitions |
| **ClamAV Engine Binaries** | `clamav/` (clamd.exe, clamscan.exe, DLLs) | ~72.20 MB | Daemon & offline scanning engines |
| **Python Virtual Environment** | `.venv/` | ~71.38 MB | Runtime Python environment & installed wheels |
| **Neo23x0 YARA Signatures** | `rules/signature-base/yara/` | ~8.10 MB | Compiled & plaintext YARA rule definitions |
| **Scout Frontend Bundle** | `app/web/dist/` | ~0.73 MB | Prebuilt production React SPA served by FastAPI |
| **Scout Backend Application** | `app/api/`, `app/engine/` | ~0.40 MB | FastAPI endpoints, pipeline, analysis logic |
| **Configuration & Launcher** | `run.bat`, `.env`, `tools/sigcheck.exe` | ~0.45 MB | Startup script, environment config, PE checker |
| **Total Lean Package** | | **~261.56 MB** | **Minimal standalone footprint** |
