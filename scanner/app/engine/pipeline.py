import logging
from pathlib import Path
import shutil
import time
from typing import Any, Callable, Dict, List, Optional

from engine.checkers.clamav import ClamAvChecker
from engine.checkers.pe_static import PeStaticChecker
from engine.checkers.reputation import CirclChecker, MalwareBazaarChecker
from engine.checkers.signature import SignatureChecker
from engine.checkers.vendor_hash import VendorHashChecker
from engine.checkers.yara_scan import YaraChecker
from engine.config import settings
from engine.db import add_result, create_scan, finish_scan
from engine.hashing import sha256_file
from engine.models import Checker, Result
from engine.scoring import score_results

logger = logging.getLogger("scanner.pipeline")


class ScanPipeline:
    def __init__(self, yara_auto_compile: bool = True):
        self.checkers: List[Checker] = [
            SignatureChecker(),
            VendorHashChecker(),
            CirclChecker(),
            MalwareBazaarChecker(),
            ClamAvChecker(),
            YaraChecker(auto_compile=yara_auto_compile),
            PeStaticChecker(),
        ]
        self.event_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def register_callback(self, cb: Callable[[Dict[str, Any]], None]):
        if cb not in self.event_callbacks:
            self.event_callbacks.append(cb)

    def unregister_callback(self, cb: Callable[[Dict[str, Any]], None]):
        if cb in self.event_callbacks:
            self.event_callbacks.remove(cb)

    def emit_event(self, event: Dict[str, Any]):
        for cb in self.event_callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}", exc_info=True)

    def process(self, original_path: Path) -> Dict[str, Any]:
        if not original_path.is_file():
            raise FileNotFoundError(f"Source file not found: {original_path}")

        filename = original_path.name
        timestamp = int(time.time() * 1000)

        # 1. Copy original file from inbox to processing directory
        proc_filename = f"{timestamp}_{filename}"
        proc_path = settings.processing_dir / proc_filename
        settings.processing_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original_path, proc_path)

        # 2. Compute file metadata
        size = proc_path.stat().st_size
        sha256 = sha256_file(proc_path)

        # 3. Create scan record in database
        scan_id = create_scan(filename, str(proc_path), sha256, size)

        # Emit scan_started
        self.emit_event(
            {
                "type": "scan_started",
                "scan_id": scan_id,
                "filename": filename,
                "sha256": sha256,
                "size": size,
            }
        )

        ctx = {
            "scan_id": scan_id,
            "filename": filename,
            "sha256": sha256,
            "size": size,
        }

        # 4. Execute checkers in strict order
        results: List[Result] = []
        for checker in self.checkers:
            try:
                res = checker.check(proc_path, ctx)
            except Exception as e:
                logger.error(f"Checker {checker.name} failed with unhandled exception: {e}")
                res = Result(
                    checker=checker.name,
                    status="skip",
                    score=0,
                    details={"error": str(e)},
                )

            results.append(res)

            # Persist checker result in DB
            add_result(scan_id, res.checker, res.status, res.score, res.details)

            # Emit check_done event
            self.emit_event(
                {
                    "type": "check_done",
                    "scan_id": scan_id,
                    "checker": res.checker,
                    "status": res.status,
                    "score": res.score,
                    "details": res.details,
                }
            )

        # 5. Calculate aggregate score and verdict
        score, verdict, reasons = score_results(results)

        is_custom_folder = original_path.parent.resolve() != settings.inbox_dir.resolve()

        if verdict == "block":
            # Quarantined malicious files are moved to quarantine folder
            dest_dir = settings.quarantine_dir
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest_path = dest_dir / filename
            if dest_path.exists():
                dest_path = dest_dir / f"{timestamp}_{filename}"

            import gc
            moved = False
            for attempt in range(10):
                try:
                    gc.collect()
                    shutil.move(proc_path, dest_path)
                    moved = True
                    break
                except PermissionError:
                    time.sleep(0.5)

            if moved and original_path.is_file():
                for attempt in range(5):
                    try:
                        gc.collect()
                        original_path.unlink()
                        break
                    except Exception:
                        time.sleep(0.3)
        else:
            # Clean (pass) or Review files:
            if is_custom_folder:
                # Custom monitored directory: Keep original file intact in place!
                # Do NOT delete or move the user's files from their directory.
                dest_path = original_path
                try:
                    if proc_path.is_file():
                        proc_path.unlink()
                except Exception:
                    pass
            else:
                # Default drop inbox: Move file to clean/ or review/ destination
                dest_dir = settings.clean_dir if verdict == "pass" else settings.review_dir
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_path = dest_dir / filename
                if dest_path.exists():
                    dest_path = dest_dir / f"{timestamp}_{filename}"

                import gc
                moved = False
                for attempt in range(10):
                    try:
                        gc.collect()
                        shutil.move(proc_path, dest_path)
                        moved = True
                        break
                    except PermissionError:
                        time.sleep(0.5)

                if moved and original_path.is_file():
                    for attempt in range(5):
                        try:
                            gc.collect()
                            original_path.unlink()
                            break
                        except Exception:
                            time.sleep(0.3)

        # 8. Update DB with final verdict and score
        finish_scan(scan_id, verdict, score, status="completed")

        final_event = {
            "type": "scan_finished",
            "scan_id": scan_id,
            "filename": filename,
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "destination": str(dest_path),
        }
        self.emit_event(final_event)

        return {
            "scan_id": scan_id,
            "filename": filename,
            "sha256": sha256,
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "results": results,
            "destination": str(dest_path),
        }


# Global default pipeline instance
pipeline = ScanPipeline(yara_auto_compile=True)
