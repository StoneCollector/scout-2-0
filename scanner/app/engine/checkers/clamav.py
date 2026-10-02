import logging
from pathlib import Path
import time
from typing import Any, Dict
import pyclamd

from engine.config import settings
from engine.models import Checker, Result

logger = logging.getLogger("scanner.clamav")


class ClamAvChecker(Checker):
    name = "clamav"

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path)
        except Exception as e:
            logger.warning(f"ClamAV scan skipped for {path}: {e}")
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _perform_check(self, path: Path) -> Result:
        host = settings.clamav.host
        port = settings.clamav.port

        cd = None
        last_err = None
        # Allow up to 3 quick retries (5 seconds) in case clamd is finishing CVD signature loading
        for attempt in range(4):
            try:
                candidate = pyclamd.ClamdNetworkSocket(host, port)
                if candidate.ping():
                    cd = candidate
                    break
            except Exception as e:
                last_err = e
            if attempt < 3:
                time.sleep(1.5)

        if cd is None:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"clamd connection failed: {last_err or f'Could not reach clamd on {host}:{port}'}"},
            )

        # Ensure file exists and clamd has absolute path
        abs_path = str(path.resolve())
        try:
            scan_result = cd.scan_file(abs_path)
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"scan_file exception: {e}"},
            )

        # pyclamd returns None if clean, or {filepath: ('FOUND', signature)}
        if not scan_result:
            return Result(
                checker=self.name,
                status="pass",
                score=0,
                details={"clean": True, "signature": None},
            )

        sig = "Unknown"
        for fpath, info in scan_result.items():
            if isinstance(info, (list, tuple)) and len(info) >= 2:
                sig = str(info[1])
            else:
                sig = str(info)
            break

        return Result(
            checker=self.name,
            status="fail",
            score=80,
            details={"clean": False, "signature": sig},
        )
