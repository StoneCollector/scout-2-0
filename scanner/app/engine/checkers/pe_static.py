import collections
import logging
import math
from pathlib import Path
from typing import Any, Dict, List
import pefile

from engine.models import Checker, Result

logger = logging.getLogger("scanner.pe_static")

PACKER_HINTS = [
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".themida",
    "vmp0",
    "vmp1",
    ".mpress",
    "pelock",
    ".enigma",
    ".petite",
]

SUSPICIOUS_API_GROUPS = {
    "hooking_keylogging": ["setwindowshookex", "getasynckeystate", "getkeystate"],
    "cryptography": ["cryptencrypt", "cryptgenkey"],
    "process_injection": ["virtualallocex", "writeprocessmemory", "createremotethread"],
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = collections.Counter(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class PeStaticChecker(Checker):
    name = "pe_static"

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path)
        except pefile.PEFormatError:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"reason": "not_a_pe_file"},
            )
        except Exception as e:
            logger.error(f"PE static analysis error for {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _perform_check(self, path: Path) -> Result:
        # Check quick magic bytes before opening with pefile
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                if magic != b"MZ":
                    return Result(
                        checker=self.name,
                        status="skip",
                        score=0,
                        details={"reason": "not_a_pe_file"},
                    )
                f.seek(0)
                file_bytes = f.read()
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Read error: {e}"},
            )

        pe = pefile.PE(data=file_bytes, fast_load=False)

        # 1. Overall Entropy
        overall_entropy = calculate_entropy(file_bytes)

        # 2. Per-section entropy & Packer names
        section_entropies: List[Dict[str, Any]] = []
        found_packer_sections: List[str] = []
        max_section_entropy = 0.0

        for sec in pe.sections:
            sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00").strip()
            ent = round(sec.get_entropy(), 4)
            if ent > max_section_entropy:
                max_section_entropy = ent
            section_entropies.append(
                {
                    "name": sec_name,
                    "entropy": ent,
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                }
            )
            # Check packer hints
            if any(hint in sec_name.lower() for hint in PACKER_HINTS):
                found_packer_sections.append(sec_name)

        # 3. Imports and Suspicious APIs
        found_suspicious_apis: List[str] = []
        triggered_groups: List[str] = []
        imports_map: Dict[str, List[str]] = {}

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                func_names = []
                for imp in entry.imports:
                    if imp.name:
                        fn = imp.name.decode("utf-8", errors="ignore")
                        func_names.append(fn)
                        fn_lower = fn.lower()
                        # Check suspicious APIs
                        for group, apis in SUSPICIOUS_API_GROUPS.items():
                            if any(api in fn_lower for api in apis):
                                if fn not in found_suspicious_apis:
                                    found_suspicious_apis.append(fn)
                                if group not in triggered_groups:
                                    triggered_groups.append(group)
                imports_map[dll_name] = func_names[:50]  # Cap per DLL

        # 4. Overlay presence
        has_overlay = False
        overlay_size = 0
        try:
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None and overlay_offset < len(file_bytes):
                has_overlay = True
                overlay_size = len(file_bytes) - overlay_offset
        except Exception:
            pass

        # 5. Score calculation
        # Rule: entropy > 7.2 adds 15, packer hint adds 10, 2+ suspicious import groups adds 15
        score = 0
        reasons = []

        if overall_entropy > 7.2 or max_section_entropy > 7.2:
            score += 15
            reasons.append(f"High entropy detected ({overall_entropy:.2f})")

        if found_packer_sections:
            score += 10
            reasons.append(f"Packer section detected: {', '.join(found_packer_sections)}")

        if len(triggered_groups) >= 2:
            score += 15
            reasons.append(
                f"{len(triggered_groups)} suspicious import groups: {', '.join(triggered_groups)}"
            )

        status = "pass"
        if score >= 30:
            status = "fail"
        elif score > 0:
            status = "warn"

        details = {
            "overall_entropy": overall_entropy,
            "max_section_entropy": max_section_entropy,
            "sections": section_entropies,
            "packer_detected": len(found_packer_sections) > 0,
            "packer_sections": found_packer_sections,
            "suspicious_apis": found_suspicious_apis,
            "suspicious_groups": triggered_groups,
            "has_overlay": has_overlay,
            "overlay_size": overlay_size,
            "reasons": reasons,
            "imports_dll_count": len(imports_map),
        }

        return Result(
            checker=self.name,
            status=status,
            score=score,
            details=details,
        )
