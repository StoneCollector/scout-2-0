import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional
import requests

from engine.config import settings
from engine.db import get_reputation_cache, set_reputation_cache
from engine.hashing import sha256_file
from engine.models import Checker, Result

logger = logging.getLogger("scanner.reputation")


class RateLimiter:
    def __init__(self, interval_seconds: float = 1.0):
        self.interval = interval_seconds
        self.last_call = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.last_call = time.time()


# Shared rate limiters (max 1 req/sec)
circl_limiter = RateLimiter(1.0)
mb_limiter = RateLimiter(1.0)


class CirclChecker(Checker):
    name = "circl"

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path, ctx)
        except Exception as e:
            logger.error(f"CIRCL checker error for {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _perform_check(self, path: Path, ctx: dict) -> Result:
        sha256 = ctx.get("sha256")
        if not sha256:
            sha256 = sha256_file(path)
        sha256 = sha256.lower()

        # Check reputation cache
        cached = get_reputation_cache(self.name, sha256)
        if cached:
            return Result(
                checker=self.name,
                status=cached["status"],
                score=cached["score"],
                details=cached["details"],
            )

        circl_limiter.wait()
        url = f"https://hashlookup.circl.lu/lookup/sha256/{sha256}"
        try:
            resp = requests.get(url, timeout=10)
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Network error connecting to CIRCL: {e}"},
            )

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                data = {}
            details = {
                "known": True,
                "source": data.get("source", "CIRCL Hashlookup"),
                "file_name": data.get("FileName"),
            }
            res = Result(checker=self.name, status="pass", score=-30, details=details)
            set_reputation_cache(self.name, sha256, res.status, res.score, res.details)
            return res
        elif resp.status_code == 404:
            details = {"known": False, "reason": "hash_not_found"}
            res = Result(checker=self.name, status="pass", score=0, details=details)
            set_reputation_cache(self.name, sha256, res.status, res.score, res.details)
            return res
        else:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Unexpected HTTP status {resp.status_code}"},
            )


class MalwareBazaarChecker(Checker):
    name = "malware_bazaar"

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path, ctx)
        except Exception as e:
            logger.error(f"MalwareBazaar checker error for {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _perform_check(self, path: Path, ctx: dict) -> Result:
        sha256 = ctx.get("sha256")
        if not sha256:
            sha256 = sha256_file(path)
        sha256 = sha256.lower()

        # Check reputation cache
        cached = get_reputation_cache(self.name, sha256)
        if cached:
            return Result(
                checker=self.name,
                status=cached["status"],
                score=cached["score"],
                details=cached["details"],
            )

        mb_limiter.wait()
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {}
        if settings.abusech_key:
            headers["Auth-Key"] = settings.abusech_key

        payload = {"query": "get_info", "hash": sha256}

        try:
            resp = requests.post(url, headers=headers, data=payload, timeout=10)
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Network error connecting to MalwareBazaar: {e}"},
            )

        if resp.status_code != 200:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Unexpected HTTP status {resp.status_code}"},
            )

        try:
            data = resp.json()
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"JSON decode error: {e}"},
            )

        query_status = data.get("query_status")
        if query_status == "ok":
            items = data.get("data", [])
            first = items[0] if items else {}
            details = {
                "signature": first.get("signature"),
                "tags": first.get("tags"),
                "first_seen": first.get("first_seen"),
                "reporter": first.get("reporter"),
            }
            res = Result(checker=self.name, status="fail", score=90, details=details)
            set_reputation_cache(self.name, sha256, res.status, res.score, res.details)
            return res
        elif query_status == "hash_not_found":
            details = {"found": False}
            res = Result(checker=self.name, status="pass", score=0, details=details)
            set_reputation_cache(self.name, sha256, res.status, res.score, res.details)
            return res
        else:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": query_status or "unknown_response"},
            )
