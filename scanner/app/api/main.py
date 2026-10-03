import asyncio
from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
import shutil
import threading
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.clamav_manager import get_clamav_status, start_clamav_daemon, stop_clamav_daemon
from engine.config import settings, save_trusted_signers
from engine.db import (
    SessionLocal,
    Scan,
    CheckResult,
    WebScan,
    WebFinding,
    get_scan,
    list_scans,
    stats,
)
from engine.pipeline import pipeline
from engine.vulns import get_vulns, refresh_vulns
from engine.watcher import watcher
import engine.web_scanner as web_scanner

logger = logging.getLogger("scanner.api")

# Active WebSocket clients
connected_clients: List[WebSocket] = []
main_loop: Optional[asyncio.AbstractEventLoop] = None


def broadcast_pipeline_event(event: Dict[str, Any]):
    if not connected_clients or not main_loop:
        return
    message = json.dumps(event)
    for client in list(connected_clients):
        asyncio.run_coroutine_threadsafe(client.send_text(message), main_loop)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()

    # Register broadcast callback with pipeline
    pipeline.register_callback(broadcast_pipeline_event)

    # Start ClamAV in background (silent, non-blocking)
    if settings.clamav.auto_start:
        asyncio.create_task(asyncio.to_thread(start_clamav_daemon, True, 60))

    # Start file system watcher
    watcher.start()
    logger.info("FastAPI engine watcher started.")

    yield

    # Teardown
    watcher.stop()
    stop_clamav_daemon()
    logger.info("FastAPI engine services stopped.")


app = FastAPI(title="Malware Scanner Demo API", version="1.0.0", lifespan=lifespan)

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "connect-src 'self' ws: wss: http: https:; "
        "img-src 'self' data: blob: https:;"
    )
    return response


# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/scans")
def get_scans(limit: int = Query(100, ge=1, le=500)):
    return list_scans(limit=limit)


@app.get("/api/scans/{scan_id}")
def get_scan_details(scan_id: int):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.post("/api/scans/{scan_id}/release")
def release_scan(scan_id: int):
    with SessionLocal() as session:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Find file in review directory
        filename = scan.filename
        source_candidates = [
            settings.review_dir / filename,
            Path(scan.path),
        ]
        target_dest = settings.clean_dir / filename

        moved = False
        for src in source_candidates:
            if src.is_file():
                settings.clean_dir.mkdir(parents=True, exist_ok=True)
                shutil.move(src, target_dest)
                scan.path = str(target_dest)
                moved = True
                break

        scan.verdict = "pass"
        scan.status = "released"
        session.commit()

        event = {
            "type": "scan_released",
            "scan_id": scan_id,
            "filename": filename,
            "verdict": "pass",
            "destination": str(target_dest) if moved else scan.path,
        }
        broadcast_pipeline_event(event)

        return {"message": "File released to clean directory", "scan_id": scan_id, "moved": moved}


@app.post("/api/scans/{scan_id}/delete")
def delete_scan(scan_id: int):
    with SessionLocal() as session:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        filename = scan.filename
        candidates = [
            settings.review_dir / filename,
            settings.quarantine_dir / filename,
            settings.clean_dir / filename,
            Path(scan.path),
        ]
        deleted_file = False
        for c in candidates:
            if c.is_file():
                try:
                    c.unlink()
                    deleted_file = True
                except Exception as e:
                    logger.warning(f"Error unlinking {c}: {e}")

        scan.status = "deleted"
        session.commit()

        event = {
            "type": "scan_deleted",
            "scan_id": scan_id,
            "filename": filename,
            "file_deleted": deleted_file,
        }
        broadcast_pipeline_event(event)

        return {"message": "File deleted", "scan_id": scan_id, "file_deleted": deleted_file}


@app.post("/api/scans/clear")
def clear_all_scans():
    with SessionLocal() as session:
        session.query(CheckResult).delete()
        session.query(Scan).delete()
        session.commit()
    broadcast_pipeline_event({"type": "history_cleared"})
    return {"message": "Scan history cleared", "success": True}


@app.get("/api/stats")
def get_stats():
    st = stats()
    st["clamav"] = get_clamav_status()
    st["queue_size"] = watcher.queue.qsize() if hasattr(watcher, "queue") else 0
    return st


@app.get("/api/system/clamav")
def get_system_clamav():
    return get_clamav_status()


@app.post("/api/system/clamav/start")
def trigger_start_clamav():
    success = start_clamav_daemon(wait_ready=True, timeout=20)
    return {"success": success, "status": get_clamav_status()}


@app.get("/api/tasks/signatures")
def get_task1_signatures():
    # Task 1 table: app, signer, digest_algorithm
    out = []
    with SessionLocal() as session:
        scans = session.query(Scan).order_by(Scan.id.desc()).all()
        seen = set()
        for s in scans:
            if s.filename in seen:
                continue
            seen.add(s.filename)

            sig_res = (
                session.query(CheckResult)
                .filter(CheckResult.scan_id == s.id, CheckResult.checker == "signature")
                .first()
            )
            details = sig_res.details if sig_res else {}
            signer = details.get("signer", "")
            alg = details.get("digest_algorithm", "")
            signed = details.get("signed", False)

            out.append(
                {
                    "scan_id": s.id,
                    "app": s.filename,
                    "signed": signed,
                    "signer": signer if signed else "",
                    "digest_algorithm": alg if signed else "",
                }
            )
    return out


@app.get("/api/tasks/hashes")
def get_task2_hashes():
    # Task 2 table: app, given_digest, calculated_digest, match
    out = []
    with SessionLocal() as session:
        scans = session.query(Scan).order_by(Scan.id.desc()).all()
        seen = set()
        for s in scans:
            if s.filename in seen:
                continue
            seen.add(s.filename)

            hash_res = (
                session.query(CheckResult)
                .filter(CheckResult.scan_id == s.id, CheckResult.checker == "vendor_hash")
                .first()
            )
            details = hash_res.details if hash_res else {}
            given = details.get("given_digest", "")
            calc = details.get("calculated_digest", s.sha256)
            match = details.get("match", None)

            out.append(
                {
                    "scan_id": s.id,
                    "app": s.filename,
                    "given_digest": given,
                    "calculated_digest": calc,
                    "match": match,
                    "source_url": details.get("source_url", ""),
                }
            )
    return out


@app.get("/api/tasks/malware")
def get_task3_malware():
    # Task 3 table: file, malicious yes/no, verdict, score, top reasons
    out = []
    with SessionLocal() as session:
        scans = session.query(Scan).order_by(Scan.id.desc()).all()
        for s in scans:
            is_malware = "Yes" if s.verdict == "block" else ("No" if s.verdict == "pass" else "Review")
            # Build top reasons from check results
            reasons = []
            for r in s.check_results:
                det = r.details
                if r.status == "fail":
                    if r.checker == "clamav":
                        reasons.append(f"ClamAV: {det.get('signature', 'malware')}")
                    elif r.checker == "yara":
                        reasons.append(f"YARA: {', '.join(det.get('rules', []))}")
                    elif r.checker == "malware_bazaar":
                        reasons.append(f"MalwareBazaar: {det.get('signature', 'hit')}")
                    elif r.checker == "signature":
                        reasons.append("Signature tampered")
                    elif r.checker == "vendor_hash":
                        reasons.append("Vendor hash mismatch")
                elif r.status == "warn" and r.checker == "pe_static":
                    for pr in det.get("reasons", []):
                        reasons.append(f"Static PE: {pr}")

            if not reasons:
                reasons = ["Passed standard authenticity and heuristic checks" if s.verdict == "pass" else "Under evaluation"]

            out.append(
                {
                    "scan_id": s.id,
                    "file": s.filename,
                    "malicious": is_malware,
                    "verdict": s.verdict or "scanning",
                    "score": s.score or 0,
                    "top_reasons": reasons[:3],
                }
            )
    return out


@app.get("/api/vulns")
def get_vulnerabilities():
    return get_vulns(force_refresh=False)


@app.post("/api/vulns/refresh")
def refresh_vulnerabilities():
    return refresh_vulns()


# ---------------------------------------------------------------------------
# Watcher Folder Configuration
# ---------------------------------------------------------------------------

class WatchFolderConfig(BaseModel):
    folder_path: Optional[str] = None
    reset_default: bool = False


@app.get("/api/watcher/folder")
def get_watch_folder():
    current_dir = str(watcher.inbox_dir)
    default_dir = str(settings.inbox_dir)
    return {
        "watch_dir": current_dir,
        "default_dir": default_dir,
        "is_default": current_dir.lower() == default_dir.lower(),
    }


@app.post("/api/watcher/folder")
def set_watch_folder(cfg: WatchFolderConfig):
    try:
        if cfg.reset_default or not cfg.folder_path or not cfg.folder_path.strip():
            updated = watcher.reset_to_default()
        else:
            updated = watcher.set_watch_dir(cfg.folder_path.strip())
        current_dir = str(updated)
        default_dir = str(settings.inbox_dir)
        broadcast_pipeline_event({
            "type": "watch_folder_updated",
            "watch_dir": current_dir,
            "is_default": current_dir.lower() == default_dir.lower(),
        })
        return {
            "status": "success",
            "watch_dir": current_dir,
            "default_dir": default_dir,
            "is_default": current_dir.lower() == default_dir.lower(),
        }
    except Exception as exc:
        logger.warning(f"Failed to update watch directory: {exc}")
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/watcher/browse-native")
async def browse_native_dialog(cfg: WatchFolderConfig):
    from engine.folder_browser import pick_folder_native_dialog
    chosen = await asyncio.to_thread(pick_folder_native_dialog, cfg.folder_path)
    return {"path": chosen}


# ---------------------------------------------------------------------------
# Trusted Signers Settings
# ---------------------------------------------------------------------------

PRESET_TRUSTED_SIGNERS = [
    "Microsoft Corporation",
    "Google LLC",
    "Apple Inc.",
    "Mozilla Corporation",
    "GitHub, Inc.",
    "Valve Corp.",
    "JetBrains s.r.o.",
    "Oracle America, Inc.",
    "Wireshark Foundation",
    "The Document Foundation",
    "Simon Bennetts",
    "Adobe Inc.",
    "Brave Software, Inc.",
    "Canonical Ltd.",
    "Cisco Systems, Inc.",
    "Docker Inc",
    "VideoLAN",
    "Notepad++",
    "Igor Pavlov",
]


class TrustedSignerRequest(BaseModel):
    signer: str


def _remove_signer_internal(signer_name: str):
    name = signer_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Signer name cannot be empty")

    original_len = len(settings.trusted_signers)
    settings.trusted_signers = [s for s in settings.trusted_signers if s.lower() != name.lower()]

    if len(settings.trusted_signers) == original_len:
        raise HTTPException(status_code=404, detail=f"Signer '{name}' not found in trusted signers")

    save_trusted_signers(settings.trusted_signers)
    broadcast_pipeline_event({
        "type": "trusted_signers_updated",
        "signers": settings.trusted_signers,
    })
    return {
        "status": "success",
        "message": f"Removed '{name}' from trusted signers.",
        "signers": settings.trusted_signers,
        "presets": PRESET_TRUSTED_SIGNERS,
    }


@app.get("/api/settings/trusted-signers")
def get_trusted_signers():
    return {
        "signers": settings.trusted_signers,
        "presets": PRESET_TRUSTED_SIGNERS,
    }


@app.post("/api/settings/trusted-signers")
def add_trusted_signer(body: TrustedSignerRequest):
    name = body.signer.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Signer name cannot be empty")

    for s in settings.trusted_signers:
        if s.lower() == name.lower():
            return {
                "status": "exists",
                "message": f"Signer '{name}' is already in trusted signers.",
                "signers": settings.trusted_signers,
                "presets": PRESET_TRUSTED_SIGNERS,
            }

    settings.trusted_signers.append(name)
    save_trusted_signers(settings.trusted_signers)
    broadcast_pipeline_event({
        "type": "trusted_signers_updated",
        "signers": settings.trusted_signers,
    })
    return {
        "status": "success",
        "message": f"Added '{name}' to trusted signers.",
        "signers": settings.trusted_signers,
        "presets": PRESET_TRUSTED_SIGNERS,
    }


@app.post("/api/settings/trusted-signers/delete")
def delete_trusted_signer_post(body: TrustedSignerRequest):
    return _remove_signer_internal(body.signer)


@app.delete("/api/settings/trusted-signers/{signer:path}")
def delete_trusted_signer_path(signer: str):
    return _remove_signer_internal(signer)


@app.post("/api/scans/clear")
def clear_scan_history():
    with SessionLocal() as session:
        session.query(CheckResult).delete()
        session.query(Scan).delete()
        session.commit()
    broadcast_pipeline_event({"type": "history_cleared"})
    return {"status": "cleared"}


# ---------------------------------------------------------------------------
# Unified Security Intelligence Report (Ranked High to Low)
# ---------------------------------------------------------------------------

@app.get("/api/reports/unified")
def get_unified_report():
    with SessionLocal() as session:
        scans = session.query(Scan).order_by(Scan.id.desc()).all()

        total = len(scans)
        blocked = sum(1 for s in scans if s.verdict == "block")
        review = sum(1 for s in scans if s.verdict == "review")
        passed = sum(1 for s in scans if s.verdict == "pass")

        entities = []
        for s in scans:
            findings = []
            sig_info = {}
            hash_info = {}

            for r in s.check_results:
                det = r.details or {}
                if r.checker == "signature":
                    sig_info = {
                        "signed": det.get("signed", False),
                        "verified": det.get("verified", False),
                        "signer": det.get("signer", ""),
                        "digest_algorithm": det.get("digest_algorithm", ""),
                        "trusted": det.get("trusted", False),
                    }
                    if r.status == "fail":
                        findings.append({
                            "severity": "critical",
                            "checker": "Authenticode",
                            "title": "Untrusted or Tampered Signature",
                            "description": f"Signer: {det.get('signer', 'Unknown')}. Failed cryptographic verification.",
                        })
                    elif r.status == "warn":
                        findings.append({
                            "severity": "medium",
                            "checker": "Authenticode",
                            "title": "Unsigned Executable",
                            "description": "Binary lacks a valid vendor digital certificate.",
                        })
                    elif r.status == "pass":
                        findings.append({
                            "severity": "info",
                            "checker": "Authenticode",
                            "title": f"Valid Signature: {det.get('signer', 'Verified')}",
                            "description": f"Verified using {det.get('digest_algorithm', 'SHA256')} digest.",
                        })

                elif r.checker == "vendor_hash":
                    hash_info = {
                        "given": det.get("given_digest", ""),
                        "calculated": det.get("calculated_digest", s.sha256),
                        "match": det.get("match", None),
                        "source": det.get("source_url", ""),
                    }
                    if r.status == "fail":
                        findings.append({
                            "severity": "high",
                            "checker": "Vendor Hash",
                            "title": "Checksum Mismatch against Official Feed",
                            "description": f"Mismatch against {det.get('source_url', 'vendor feed')}",
                        })
                    elif r.status == "pass":
                        findings.append({
                            "severity": "info",
                            "checker": "Vendor Hash",
                            "title": "Cryptographic Match with Official Vendor Hash",
                            "description": f"Matched official vendor feed: {det.get('source_url', 'trusted source')}",
                        })

                elif r.checker == "clamav":
                    if r.status == "fail":
                        findings.append({
                            "severity": "critical",
                            "checker": "ClamAV",
                            "title": f"Malware Signature: {det.get('signature', 'Malware.Detected')}",
                            "description": "Antivirus engine flagged file as malicious.",
                        })
                    elif r.status == "pass":
                        findings.append({
                            "severity": "info",
                            "checker": "ClamAV",
                            "title": "ClamAV Antivirus Clean",
                            "description": "No recognized malware signatures detected.",
                        })

                elif r.checker == "yara":
                    if r.status == "fail":
                        rules = det.get("rules", [])
                        findings.append({
                            "severity": "high",
                            "checker": "YARA",
                            "title": f"YARA Threat Rule Hit: {', '.join(rules) if rules else 'Malicious Pattern'}",
                            "description": f"Triggered {len(rules)} signature rule(s).",
                        })

                elif r.checker == "pe_static":
                    if r.status in ("warn", "fail"):
                        reasons = det.get("reasons", [])
                        for rea in reasons:
                            sev = "high" if "entropy" in rea.lower() or "suspicious" in rea.lower() else "medium"
                            findings.append({
                                "severity": sev,
                                "checker": "Static PE",
                                "title": f"Structural Anomaly: {rea}",
                                "description": f"Entropy: {det.get('entropy', 'N/A')}, Sections: {det.get('sections_count', 'N/A')}",
                            })

                elif r.checker == "malware_bazaar":
                    if r.status == "fail":
                        findings.append({
                            "severity": "critical",
                            "checker": "Threat Intelligence",
                            "title": f"MalwareBazaar Known Threat: {det.get('signature', 'Hit')}",
                            "description": f"Listed on abuse.ch database. Tags: {', '.join(det.get('tags', []))}",
                        })

            # Sort entity findings: critical -> high -> medium -> low -> info
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings.sort(key=lambda f: sev_rank.get(f.get("severity", "info"), 5))

            v_rank = 0 if s.verdict == "block" else (1 if s.verdict == "review" else 2)

            entities.append({
                "id": s.id,
                "filename": s.filename,
                "sha256": s.sha256,
                "size": s.size,
                "verdict": s.verdict or "pending",
                "score": s.score or 0,
                "path": s.path,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "signature": sig_info,
                "hash_verification": hash_info,
                "findings": findings,
                "_rank": (v_rank, -(s.score or 0)),
            })

        entities.sort(key=lambda e: e["_rank"])
        for e in entities:
            e.pop("_rank", None)

        return {
            "summary": {
                "total_scans": total,
                "blocked_count": blocked,
                "review_count": review,
                "clean_count": passed,
                "threat_ratio": round((blocked + review) / total * 100, 1) if total else 0.0,
            },
            "entities": entities,
        }


# ---------------------------------------------------------------------------
# Web audit endpoints
# ---------------------------------------------------------------------------

class WebScanRequest(BaseModel):
    url: str


@app.post("/api/web/scan")
def start_web_scan(body: WebScanRequest):
    """Validate target, create a DB row and kick off the scan in a background thread."""
    try:
        target = web_scanner.validate_target(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    with SessionLocal() as session:
        ws = WebScan(target_url=target, status="running", created_at=__import__("datetime").datetime.utcnow())
        session.add(ws)
        session.commit()
        session.refresh(ws)
        scan_id = ws.id

    def _run():
        try:
            findings, pages_count = web_scanner.run_scan(
                scan_id=scan_id,
                target_url=target,
                on_check_done=broadcast_pipeline_event,
            )
            score, grade = web_scanner.compute_grade(findings)
            with SessionLocal() as session:
                ws = session.get(WebScan, scan_id)
                if ws:
                    ws.status = "complete"
                    ws.score = score
                    ws.grade = grade
                    ws.pages_crawled = pages_count
                    ws.findings_count = len(findings)
                    ws.completed_at = __import__("datetime").datetime.utcnow()
                    for f in findings:
                        session.add(WebFinding(
                            web_scan_id=scan_id,
                            finding_id=f.id,
                            title=f.title,
                            severity=f.severity,
                            evidence=f.evidence,
                            remediation=f.remediation,
                            owasp_category=f.owasp_category,
                            url=f.url,
                            check_name=f.check_name,
                        ))
                    session.commit()
            broadcast_pipeline_event({
                "type": "web_scan_complete",
                "scan_id": scan_id,
                "score": score,
                "grade": grade,
                "findings_count": len(findings),
            })
        except Exception as exc:
            err_msg = str(exc)
            logger.error(f"Web scan {scan_id} error: {err_msg}", exc_info=True)
            with SessionLocal() as session:
                ws = session.get(WebScan, scan_id)
                if ws:
                    ws.status = "error"
                    ws.score = None
                    ws.grade = None
                    ws.pages_crawled = 0
                    ws.findings_count = 0
                    ws.error = err_msg
                    ws.completed_at = __import__("datetime").datetime.utcnow()
                    session.commit()
            broadcast_pipeline_event({
                "type": "web_scan_error",
                "scan_id": scan_id,
                "error": err_msg,
            })

    t = threading.Thread(target=_run, daemon=True, name=f"WebScan-{scan_id}")
    t.start()
    return {"scan_id": scan_id, "status": "running", "target": target}


@app.get("/api/web/scans")
def list_web_scans(limit: int = Query(50, ge=1, le=200)):
    with SessionLocal() as session:
        rows = (
            session.query(WebScan)
            .order_by(WebScan.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "target_url": r.target_url,
                "status": r.status,
                "score": r.score,
                "grade": r.grade,
                "pages_crawled": r.pages_crawled,
                "findings_count": r.findings_count,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in rows
        ]


@app.get("/api/web/scans/{scan_id}")
def get_web_scan(scan_id: int):
    with SessionLocal() as session:
        ws = session.get(WebScan, scan_id)
        if not ws:
            raise HTTPException(status_code=404, detail="Web scan not found")
        findings_out = [
            {
                "id": f.id,
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "owasp_category": f.owasp_category,
                "url": f.url,
                "check_name": f.check_name,
            }
            for f in ws.findings
        ]

        # Sort findings strictly by severity: critical -> high -> medium -> low -> info
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_out.sort(key=lambda f: sev_rank.get(f["severity"].lower(), 5))

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings_out:
            k = f["severity"].lower()
            if k in counts:
                counts[k] += 1

        return {
            "id": ws.id,
            "target_url": ws.target_url,
            "status": ws.status,
            "score": ws.score,
            "grade": ws.grade,
            "pages_crawled": ws.pages_crawled,
            "findings_count": ws.findings_count,
            "severity_counts": counts,
            "error": ws.error,
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
            "completed_at": ws.completed_at.isoformat() if ws.completed_at else None,
            "findings": findings_out,
        }


@app.post("/api/web/scans/clear")
def clear_all_web_scans():
    with SessionLocal() as session:
        session.query(WebFinding).delete()
        session.query(WebScan).delete()
        session.commit()
    broadcast_pipeline_event({"type": "web_history_cleared"})
    return {"message": "Web audit history cleared", "success": True}


@app.post("/api/web/scans/{scan_id}/delete")
def delete_web_scan(scan_id: int):
    with SessionLocal() as session:
        ws = session.get(WebScan, scan_id)
        if not ws:
            raise HTTPException(status_code=404, detail="Web scan not found")
        session.delete(ws)
        session.commit()
        broadcast_pipeline_event({"type": "web_scan_deleted", "scan_id": scan_id})
        return {"message": "Web scan deleted", "scan_id": scan_id}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({"type": "connected", "message": "Connected to Scout"}))
        while True:
            # Keep listening for client heartbeats or pings
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)
    except Exception as e:
        logger.debug(f"WebSocket client closed: {e}")
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# Mount built frontend if dist exists
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from engine.paths import get_web_dist_dir

dist_dir = get_web_dist_dir()
if dist_dir.is_dir():
    logger.info(f"Serving frontend from {dist_dir}")
    assets_dir = dist_dir / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("ws"):
            raise HTTPException(status_code=404, detail="Not found")
        file_path = dist_dir / full_path
        if file_path.is_file():
            return FileResponse(file_path)
        index_file = dist_dir / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Dashboard index.html not found")
else:
    logger.warning(f"Frontend dist directory not found at {dist_dir}. Static dashboard disabled.")

