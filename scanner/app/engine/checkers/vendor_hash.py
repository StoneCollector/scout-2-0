import fnmatch
import hashlib
import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import requests

from engine.config import VendorHashSource, settings
from engine.hashing import sha256_file
from engine.models import Checker, Result

logger = logging.getLogger("scanner.vendor_hash")


class VendorHashChecker(Checker):
    name = "vendor_hash"

    def __init__(self):
        super().__init__()
        self._offline_hashes: Dict[str, dict] = {}
        self._offline_filenames: Dict[str, dict] = {}
        self._load_offline_database()

    def _load_offline_database(self) -> None:
        """Loads local known hashes from data/known_hashes.json if available."""
        from engine.paths import app_path, bundle_path

        candidate_paths = [
            settings.data_dir / "known_hashes.json",
            app_path("data", "known_hashes.json"),
            app_path("app", "data", "known_hashes.json"),
            bundle_path("data", "known_hashes.json"),
            Path(__file__).resolve().parents[2] / "data" / "known_hashes.json",
        ]
        for cp in candidate_paths:
            if cp.is_file():
                try:
                    data = json.loads(cp.read_text(encoding="utf-8"))
                    entries = data.get("entries", [])
                    for e in entries:
                        h = (e.get("sha256") or "").strip().lower()
                        fn = (e.get("filename") or "").strip().lower()
                        if h and len(h) == 64:
                            self._offline_hashes[h] = e
                        if fn and h:
                            self._offline_filenames[fn] = e
                    logger.debug(f"Loaded {len(entries)} verified entries from {cp}")
                    return
                except Exception as ex:
                    logger.warning(f"Error loading offline hashes from {cp}: {ex}")

    @staticmethod
    def extract_version(filename: str) -> Optional[str]:
        """Extracts normalized semantic version from filename (e.g. 4.6.8, 7.2.20, 2.17.0)."""
        m = re.search(r"(?:[-_vV]|^)(\d+(?:[._]\d+)+)", filename)
        if m:
            return m.group(1).replace("_", ".")
        return None

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path, ctx)
        except Exception as e:
            logger.error(f"Vendor hash check error for {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e), "reason": "checker_exception"},
            )

    def _perform_check(self, path: Path, ctx: dict) -> Result:
        filename = path.name
        calc_digest = ctx.get("sha256")
        if not calc_digest:
            calc_digest = sha256_file(path)
        calc_digest = calc_digest.strip().lower()
        fn_lower = filename.lower()

        # Tier 0: Direct Offline Hash Database Match (instant, 0ms, works fully offline)
        if calc_digest in self._offline_hashes:
            entry = self._offline_hashes[calc_digest]
            details = {
                "given_digest": calc_digest,
                "calculated_digest": calc_digest,
                "match": True,
                "source": "offline_database",
                "source_url": "offline_database",
                "product": entry.get("product"),
                "version": entry.get("version"),
                "vendor": entry.get("vendor"),
            }
            return Result(checker=self.name, status="pass", score=-30, details=details)

        # Tier 0b: Offline Filename check (if exact filename is in offline DB with expected hash)
        if fn_lower in self._offline_filenames:
            entry = self._offline_filenames[fn_lower]
            expected = entry["sha256"].strip().lower()
            is_match = (calc_digest == expected)
            details = {
                "given_digest": expected,
                "calculated_digest": calc_digest,
                "match": is_match,
                "source": "offline_database",
                "source_url": "offline_database",
                "product": entry.get("product"),
                "version": entry.get("version"),
                "vendor": entry.get("vendor"),
            }
            if is_match:
                return Result(checker=self.name, status="pass", score=-30, details=details)
            else:
                return Result(checker=self.name, status="fail", score=70, details=details)

        # Tier 1: Match against configured VendorHashSource
        matched_source: Optional[VendorHashSource] = None
        for vh in settings.vendor_hashes:
            if fnmatch.fnmatch(filename, vh.pattern) or fnmatch.fnmatch(fn_lower, vh.pattern.lower()):
                matched_source = vh
                break

        if not matched_source:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"reason": "no_registered_source"},
            )

        # Fetch and parse given digest from online feed (with dynamic version templating)
        given_digest, source_url = self._get_given_digest(filename, matched_source)

        if not given_digest:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={
                    "reason": "digest_not_found_in_feed",
                    "source_url": source_url,
                    "calculated_digest": calc_digest,
                },
            )

        given_digest = given_digest.strip().lower()
        is_match = (calc_digest == given_digest)

        details = {
            "given_digest": given_digest,
            "calculated_digest": calc_digest,
            "match": is_match,
            "source_url": source_url,
        }

        if is_match:
            return Result(checker=self.name, status="pass", score=-30, details=details)
        else:
            return Result(checker=self.name, status="fail", score=70, details=details)

    def _get_given_digest(self, filename: str, source: VendorHashSource) -> Tuple[Optional[str], str]:
        if source.source_type == "manual":
            return source.manual_sha256, "manual"

        content, resolved_url = self._fetch_feed_content(source, filename)
        if not content:
            return None, resolved_url or source.url or ""

        st = source.source_type
        given = None
        if st == "virtualbox_sums":
            given = self.parse_virtualbox_sums(content, filename)
        elif st == "wireshark_sigs":
            given = self.parse_wireshark_sigs(content, filename)
        elif st == "zap_xml":
            given = self.parse_zap_xml(content, filename)
        elif st == "libreoffice_page":
            given = self.parse_libreoffice_page(content, filename)
        elif st in ("html_scraper", "html_page", "web_page"):
            given = self.parse_generic_html(content, filename)

        # Fallback auto-detection if parser returned None or format changed
        if not given:
            given = self.auto_detect_and_parse(content, filename)

        return given, resolved_url or source.url or ""

    def _fetch_feed_content(self, source: VendorHashSource, filename: str = "") -> Tuple[Optional[str], str]:
        if not source.url:
            return None, ""

        ver = self.extract_version(filename)
        ver_underscore = ver.replace(".", "_") if ver else ""

        # Build candidate URLs replacing {version} and {version_underscore}
        raw_candidates = [source.url] + getattr(source, "fallback_urls", [])
        urls_to_try: List[str] = []
        for raw_u in raw_candidates:
            if "{version}" in raw_u or "{version_underscore}" in raw_u:
                if ver:
                    u = raw_u.replace("{version}", ver).replace("{version_underscore}", ver_underscore)
                    if u not in urls_to_try:
                        urls_to_try.append(u)
            else:
                if raw_u not in urls_to_try:
                    urls_to_try.append(raw_u)

        if not urls_to_try:
            return None, ""

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisSecurityScanner/1.0"
        }

        # Check local cache first for the resolved URLs
        for u in urls_to_try:
            url_hash = hashlib.sha256(u.encode("utf-8")).hexdigest()[:16]
            cache_file = settings.data_dir / "feeds" / f"{source.source_type}_{url_hash}.txt"
            if cache_file.is_file():
                age = time.time() - cache_file.stat().st_mtime
                if age < 86400:  # 24 hours
                    try:
                        text = cache_file.read_text(encoding="utf-8")
                        if text:
                            return text, u
                    except Exception as e:
                        logger.debug(f"Cache read error: {e}")

        # Fetch from network with fallback URLs
        last_url = urls_to_try[0]
        for u in urls_to_try:
            last_url = u
            try:
                resp = requests.get(u, headers=headers, timeout=10)
                if resp.status_code == 200 and resp.text:
                    url_hash = hashlib.sha256(u.encode("utf-8")).hexdigest()[:16]
                    cache_file = settings.data_dir / "feeds" / f"{source.source_type}_{url_hash}.txt"
                    cache_file.parent.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(resp.text, encoding="utf-8")
                    return resp.text, u
            except Exception as e:
                logger.warning(f"Failed to fetch hash feed from {u}: {e}")

        # If network failed, try stale cache for any candidate
        for u in urls_to_try:
            url_hash = hashlib.sha256(u.encode("utf-8")).hexdigest()[:16]
            cache_file = settings.data_dir / "feeds" / f"{source.source_type}_{url_hash}.txt"
            if cache_file.is_file():
                try:
                    return cache_file.read_text(encoding="utf-8"), u
                except Exception:
                    pass

        return None, last_url

    @staticmethod
    def parse_virtualbox_sums(content: str, filename: str) -> Optional[str]:
        # Format: "<sha256> *<filename>" or "<sha256>  <filename>"
        fn_lower = filename.lower()
        fn_norm = re.sub(r"[^a-z0-9]", "", fn_lower)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                h = parts[0].strip()
                name = parts[1].lstrip("* ").strip()
                name_lower = name.lower()
                name_norm = re.sub(r"[^a-z0-9]", "", name_lower)

                if (
                    name_lower == fn_lower
                    or name_norm == fn_norm
                    or (fn_lower in name_lower and ("extpack" in fn_lower or "win" in fn_lower))
                    or (name_lower in fn_lower and ("extpack" in fn_lower or "win" in fn_lower))
                ):
                    if len(h) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        return h.lower()
        return None

    @staticmethod
    def parse_wireshark_sigs(content: str, filename: str) -> Optional[str]:
        # Format: "SHA256(<filename>)=<hash>" or "SHA256 (<filename>) = <hash>"
        fn_lower = filename.lower()
        fn_norm = re.sub(r"[^a-z0-9]", "", fn_lower)
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("SHA256"):
                continue
            m = re.match(r"SHA256\s*\(([^)]+)\)\s*=\s*([0-9a-fA-F]{64})", line, re.IGNORECASE)
            if m:
                item_name = m.group(1).strip()
                item_lower = item_name.lower()
                item_norm = re.sub(r"[^a-z0-9]", "", item_lower)
                h = m.group(2).strip()
                if item_lower == fn_lower or item_norm == fn_norm or item_lower in fn_lower or fn_lower in item_lower:
                    return h.lower()
        return None

    @staticmethod
    def parse_zap_xml(content: str, filename: str) -> Optional[str]:
        # Parse XML, find entry whose url/file name matches, read its <hash> (strip "SHA-256:" prefix)
        fn_lower = filename.lower()
        fn_norm = re.sub(r"[^a-z0-9]", "", fn_lower)
        try:
            root = ET.fromstring(content)
        except Exception:
            return None

        # Search for elements containing hash
        for elem in root.iter():
            h_tag = elem.find("hash")
            if h_tag is not None and h_tag.text:
                file_tag = elem.find("file")
                url_tag = elem.find("url")
                file_val = (file_tag.text if file_tag is not None else "") or ""
                url_val = (url_tag.text if url_tag is not None else "") or ""

                file_lower = file_val.lower()
                url_lower = url_val.lower()
                file_norm = re.sub(r"[^a-z0-9]", "", file_lower)

                # Strict matching: exact normalized filename or URL tail
                matches = (
                    fn_lower == file_lower
                    or fn_norm == file_norm
                    or (file_lower and file_lower in fn_lower)
                    or (fn_lower and fn_lower in file_lower)
                    or url_lower.endswith("/" + fn_lower)
                )

                if matches:
                    raw_hash = h_tag.text.strip()
                    if raw_hash.upper().startswith("SHA-256:"):
                        raw_hash = raw_hash[8:].strip()
                    if re.fullmatch(r"[0-9a-fA-F]{64}", raw_hash):
                        return raw_hash.lower()
        return None

    @classmethod
    def parse_libreoffice_page(cls, content: str, filename: str) -> Optional[str]:
        return cls.parse_generic_html(content, filename)

    @staticmethod
    def parse_generic_html(content: str, filename: str) -> Optional[str]:
        """
        Intelligent HTML/Web scraper:
        1. Searches table rows (<tr>) containing filename/stem and a 64-hex SHA-256.
        2. Searches proximity window (+/- 500 characters) around filename occurrences.
        3. Matches labeled checksum patterns near filename.
        Never guesses random hashes when the filename is not matched.
        """
        fn_clean = filename.lower()
        fn_stem = Path(filename).stem.lower()

        # Strategy 1: Table row (<tr>) matching
        tr_matches = re.findall(r"<tr\b[^>]*>(.*?)</tr>", content, re.IGNORECASE | re.DOTALL)
        for tr in tr_matches:
            tr_lower = tr.lower()
            if fn_clean in tr_lower or fn_stem in tr_lower:
                h_match = re.search(r"\b([0-9a-fA-F]{64})\b", tr)
                if h_match:
                    return h_match.group(1).lower()

        # Strategy 2: Proximity window around filename or stem in raw content
        for target in (fn_clean, fn_stem):
            start = 0
            while True:
                idx = content.lower().find(target, start)
                if idx == -1:
                    break
                win_start = max(0, idx - 500)
                win_end = min(len(content), idx + len(target) + 500)
                window = content[win_start:win_end]

                # Look for labeled checksum in window first
                labeled = re.search(
                    r"(?:SHA-?256|sha256sum|Checksum|Digest|Hash)[\s:=<>\"/]*([0-9a-fA-F]{64})",
                    window,
                    re.IGNORECASE,
                )
                if labeled:
                    return labeled.group(1).lower()

                # Look for any 64-hex hash in window
                any_h = re.search(r"\b([0-9a-fA-F]{64})\b", window)
                if any_h:
                    return any_h.group(1).lower()

                start = idx + len(target)

        # Strategy 3: Global labeled checksum pattern ONLY if the document explicitly mentions the target filename
        if fn_clean in content.lower() or fn_stem in content.lower():
            labeled_global = re.search(
                r"(?:SHA-?256|sha256sum|Checksum|Digest)[\s:=<>\"/]*([0-9a-fA-F]{64})",
                content,
                re.IGNORECASE,
            )
            if labeled_global:
                return labeled_global.group(1).lower()

        # Strategy 4 (all_hashes[0] blind fallback) was intentionally removed
        # because grabbing the first arbitrary hash in an unmatching feed causes false positive +70 blocks.
        return None

    @classmethod
    def auto_detect_and_parse(cls, content: str, filename: str) -> Optional[str]:
        """Auto-detects format if the configured source_type did not match or changed."""
        content_stripped = content.strip()

        # Check for XML
        if content_stripped.startswith("<?xml") or (
            "<" in content_stripped and "</" in content_stripped and "xml" in content[:100].lower()
        ):
            res = cls.parse_zap_xml(content, filename)
            if res:
                return res

        # Check for BSD signatures (SHA256 (...) = ...)
        if "SHA256" in content and "=" in content:
            res = cls.parse_wireshark_sigs(content, filename)
            if res:
                return res

        # Check for GNU sha256sums
        res = cls.parse_virtualbox_sums(content, filename)
        if res:
            return res

        # Check for HTML
        if (
            "<html" in content.lower()
            or "<body" in content.lower()
            or "<table" in content.lower()
            or "<div" in content.lower()
        ):
            res = cls.parse_generic_html(content, filename)
            if res:
                return res

        return None
