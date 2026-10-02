import csv
import io
import logging
from pathlib import Path
import subprocess
from typing import Any, Dict, Tuple
import asn1crypto.cms
import olefile
import pefile

from engine.config import settings
from engine.models import Checker, Result

logger = logging.getLogger("scanner.signature")


class SignatureChecker(Checker):
    name = "signature"

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path)
        except Exception as e:
            logger.error(f"Signature check failed on {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _extract_digest_algorithm(self, path: Path) -> str:
        ext = path.suffix.lower()
        if ext in [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"]:
            pe = None
            try:
                pe = pefile.PE(str(path), fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                )
                sec_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                ]
                if sec_entry.VirtualAddress != 0 and sec_entry.Size > 8:
                    pe.__data__.seek(sec_entry.VirtualAddress)
                    raw = pe.__data__.read(sec_entry.Size)
                    # Skip 8-byte WIN_CERTIFICATE header: dwLength(4), wRevision(2), wCertificateType(2)
                    pkcs7 = raw[8:]
                    ci = asn1crypto.cms.ContentInfo.load(pkcs7)
                    content = ci["content"]
                    if "digest_algorithms" in content and len(content["digest_algorithms"]) > 0:
                        alg = content["digest_algorithms"][0]["algorithm"].native
                        return str(alg).lower()
            except Exception as e:
                logger.debug(f"PE security dir extract error: {e}")
            finally:
                if pe:
                    try:
                        pe.close()
                    except Exception:
                        pass

        elif ext == ".msi":
            ole = None
            try:
                if olefile.isOleFile(str(path)):
                    ole = olefile.OleFileIO(str(path))
                    stream_name = "\x05DigitalSignature"
                    if ole.exists(stream_name):
                        data = ole.openstream(stream_name).read()
                        try:
                            ci = asn1crypto.cms.ContentInfo.load(data)
                        except Exception:
                            # In some MSI packaging, an 8-byte WIN_CERTIFICATE header is present
                            ci = asn1crypto.cms.ContentInfo.load(data[8:])
                        content = ci["content"]
                        if "digest_algorithms" in content and len(content["digest_algorithms"]) > 0:
                            alg = content["digest_algorithms"][0]["algorithm"].native
                            return str(alg).lower()
            except Exception as e:
                logger.debug(f"MSI signature stream extract error: {e}")
            finally:
                if ole:
                    try:
                        ole.close()
                    except Exception:
                        pass

        return ""

    def _run_sigcheck(self, path: Path) -> Tuple[bool, bool, str]:
        sigcheck_exe = settings.sigcheck_path
        if not sigcheck_exe.is_file():
            raise FileNotFoundError(f"Sigcheck executable not found at {sigcheck_exe}")

        cmd = [str(sigcheck_exe), "-nobanner", "-a", "-c", "-accepteula", str(path)]
        res = subprocess.run(cmd, capture_output=True, timeout=60)

        # Sigcheck on Windows produces UTF-16LE CSV output
        raw_out = res.stdout
        out_text = ""
        for encoding in ["utf-16", "utf-16-le", "utf-8", "cp1252"]:
            try:
                out_text = raw_out.decode(encoding)
                if "Verified" in out_text or "Path" in out_text:
                    break
            except Exception:
                continue

        if not out_text:
            out_text = raw_out.decode("utf-8", errors="replace")

        reader = csv.DictReader(io.StringIO(out_text.strip()))
        rows = list(reader)
        if not rows:
            return False, False, ""

        row = rows[0]
        verified_raw = (row.get("Verified") or "").strip()
        publisher_raw = (row.get("Publisher") or row.get("Signers") or "").strip()

        verified_lower = verified_raw.lower()
        if "unsigned" in verified_lower:
            return False, False, ""
        elif "signed" in verified_lower:
            return True, True, publisher_raw
        elif verified_raw != "":
            # Indicates signed but invalid or tampered
            return True, False, publisher_raw

        return False, False, ""

    def _perform_check(self, path: Path) -> Result:
        signed, verified, signer = self._run_sigcheck(path)
        digest_alg = self._extract_digest_algorithm(path)

        # Unsigned rule: signed=False, signer="", digest_algorithm=""
        if not signed:
            signer = ""
            digest_alg = ""
            status = "warn"
            score = 10
            trusted = False
        elif not verified:
            # Invalid / tampered signature
            status = "fail"
            score = 60
            trusted = False
        else:
            # Valid signature: check if trusted
            trusted = any(t.lower() in signer.lower() for t in settings.trusted_signers)
            if trusted:
                status = "pass"
                score = 0
            else:
                status = "warn"
                score = 25

        details = {
            "signed": signed,
            "verified": verified,
            "signer": signer,
            "digest_algorithm": digest_alg,
            "trusted": trusted,
        }

        return Result(
            checker=self.name,
            status=status,
            score=score,
            details=details,
        )
