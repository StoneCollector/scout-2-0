import fnmatch
import hashlib
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET
import requests

from engine.config import VendorHashSource, settings
from engine.hashing import sha256_file
from engine.models import Checker, Result

logger = logging.getLogger("scanner.vendor_hash")


class VendorHashChecker(Checker):
    name = "vendor_hash"

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

        # Find matching vendor hash source pattern
        matched_source: Optional[VendorHashSource] = None
        for vh in settings.vendor_hashes:
            if fnmatch.fnmatch(filename, vh.pattern) or fnmatch.fnmatch(filename.lower(), vh.pattern.lower()):
                matched_source = vh
                break

        if not matched_source:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"reason": "no_registered_source"},
            )

        # Calculate file digest
        calc_digest = ctx.get("sha256")
        if not calc_digest:
            calc_digest = sha256_file(path)

        # Fetch and parse given digest
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

        calc_digest = calc_digest.strip().lower()
        given_digest = given_digest.strip().lower()
        is_match = calc_digest == given_digest

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

    def _get_given_digest(self, filename: str, source: VendorHashSource) -> tuple[Optional[str], str]:
        if source.source_type == "manual":
            return source.manual_sha256, "manual"

        content = self._fetch_feed_content(source)
        if not content:
            return None, source.url or ""

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

        return given, source.url or ""

    def _fetch_feed_content(self, source: VendorHashSource) -> Optional[str]:
        if not source.url:
            return None

        # 24h cache in data/feeds/
        url_hash = hashlib.sha256(source.url.encode("utf-8")).hexdigest()[:16]
        cache_file = settings.data_dir / "feeds" / f"{source.source_type}_{url_hash}.txt"

        if cache_file.is_file():
            age = time.time() - cache_file.stat().st_mtime
            if age < 86400:  # 24 hours
                try:
                    return cache_file.read_text(encoding="utf-8")
                except Exception as e:
                    logger.debug(f"Cache read error: {e}")

        # Fetch from network with fallback URLs and browser User-Agent
        urls_to_try = [source.url] + getattr(source, "fallback_urls", [])
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisSecurityScanner/1.0"
        }
        for u in urls_to_try:
            try:
                resp = requests.get(u, headers=headers, timeout=12)
                if resp.status_code == 200 and resp.text:
                    cache_file.parent.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(resp.text, encoding="utf-8")
                    return resp.text
            except Exception as e:
                logger.warning(f"Failed to fetch hash feed from {u}: {e}")

        # If network failed, use stale cache if available
        if cache_file.is_file():
            return cache_file.read_text(encoding="utf-8")

        return None

    @staticmethod
    def parse_virtualbox_sums(content: str, filename: str) -> Optional[str]:
        # Format: "<sha256> *<filename>" or "<sha256>  <filename>"
        fn_lower = filename.lower()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                h = parts[0].strip()
                name = parts[1].lstrip("* ").strip()
                # Check exact or substring filename match
                if name.lower() == fn_lower or fn_lower in name.lower() or name.lower() in fn_lower:
                    if len(h) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", h):
                        return h.lower()
        return None

    @staticmethod
    def parse_wireshark_sigs(content: str, filename: str) -> Optional[str]:
        # Format: "SHA256(<filename>)=<hash>" or "SHA256 (<filename>) = <hash>"
        fn_lower = filename.lower()
        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("SHA256"):
                continue
            m = re.match(r"SHA256\s*\(([^)]+)\)\s*=\s*([0-9a-fA-F]{64})", line, re.IGNORECASE)
            if m:
                item_name = m.group(1).strip()
                h = m.group(2).strip()
                if item_name.lower() == fn_lower or fn_lower in item_name.lower() or item_name.lower() in fn_lower:
                    return h.lower()
        return None

    @staticmethod
    def parse_zap_xml(content: str, filename: str) -> Optional[str]:
        # Parse XML, find entry whose url/file name matches, read its <hash> (strip "SHA-256:" prefix)
        fn_lower = filename.lower()
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

                matches = (
                    fn_lower in file_val.lower()
                    or file_val.lower() in fn_lower
                    or fn_lower in url_val.lower()
                    or ("zap" in fn_lower and "zap" in file_val.lower())
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
        # Enhanced to use generic HTML scraping with filename proximity
        return cls.parse_generic_html(content, filename)

    @staticmethod
    def parse_generic_html(content: str, filename: str) -> Optional[str]:
        """
        Intelligent HTML/Web scraper:
        1. Searches table rows (<tr>) containing filename/stem and a 64-hex SHA-256.
        2. Searches proximity window (+/- 500 characters) around filename occurrences.
        3. Matches labeled checksum patterns (e.g. SHA-256: <hash>).
        4. Fallback to unique 64-hex string on dedicated single-file mirror pages.
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

        # Strategy 3: Global labeled checksum pattern
        labeled_global = re.search(
            r"(?:SHA-?256|sha256sum|Checksum|Digest)[\s:=<>\"/]*([0-9a-fA-F]{64})",
            content,
            re.IGNORECASE,
        )
        if labeled_global:
            return labeled_global.group(1).lower()

        # Strategy 4: Fallback for dedicated single-file mirror pages (e.g. LibreOffice mirrorlist)
        all_hashes = list(dict.fromkeys(re.findall(r"\b[0-9a-fA-F]{64}\b", content)))
        if all_hashes:
            return all_hashes[0].lower()

        return None

    @classmethod
    def auto_detect_and_parse(cls, content: str, filename: str) -> Optional[str]:
        """Auto-detects format if the configured source_type did not match or changed."""
        content_stripped = content.strip()

        # Check for XML
        if content_stripped.startswith("<?xml") or ("<" in content_stripped and "</" in content_stripped and "xml" in content[:100].lower()):
            res = cls.parse_zap_xml(content, filename)
            if res:
                return res

        # Check for HTML
        if "<html" in content.lower() or "<body" in content.lower() or "<table" in content.lower() or "<div" in content.lower():
            res = cls.parse_generic_html(content, filename)
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

        # Final fallback
        return cls.parse_generic_html(content, filename)
