from typing import List, Tuple
from engine.models import Result, Verdict


def score_results(results: List[Result]) -> Tuple[int, Verdict, List[str]]:
    raw_score = sum(r.score for r in results)
    clamped_score = max(0, min(100, raw_score))

    reasons: List[str] = []
    force_block = False

    for r in results:
        chk = r.checker
        det = r.details or {}

        if chk == "signature":
            signed = det.get("signed", False)
            verified = det.get("verified", False)
            trusted = det.get("trusted", False)
            signer = det.get("signer", "")

            if signed and not verified:
                force_block = True
                reasons.append("Invalid or tampered digital signature.")
            elif not signed:
                if r.status != "skip":
                    reasons.append("Unsigned executable (+10 score).")
            elif signed and verified:
                if trusted:
                    reasons.append(f"Digitally signed and trusted ({signer}).")
                else:
                    reasons.append(f"Signed but untrusted publisher: {signer} (+25 score).")

        elif chk == "vendor_hash":
            if det.get("match") is True:
                reasons.append(f"Vendor hash matched official release from {det.get('source_url', 'vendor')} (-30 score).")
            elif det.get("match") is False:
                force_block = True
                reasons.append("Vendor hash mismatch against official release (+70 score).")

        elif chk == "circl":
            if det.get("known") is True:
                reasons.append(f"Known benign software in CIRCL database ({det.get('source', '')}) (-30 score).")

        elif chk == "malware_bazaar":
            if r.status == "fail":
                sig = det.get("signature") or "Malware"
                reasons.append(f"MalwareBazaar confirmed malware hit: {sig} (+90 score).")

        elif chk == "clamav":
            if r.status == "fail":
                sig = det.get("signature") or "Threat"
                reasons.append(f"ClamAV antivirus detected: {sig} (+80 score).")

        elif chk == "yara":
            if r.status == "fail":
                rules = det.get("rules", [])
                reasons.append(f"YARA rules matched: {', '.join(rules)} (+50 score).")

        elif chk == "pe_static":
            for pe_reason in det.get("reasons", []):
                reasons.append(f"PE static indicator: {pe_reason}")

    # Determine baseline verdict by score
    if clamped_score < 30:
        verdict: Verdict = "pass"
    elif clamped_score < 70:
        verdict = "review"
    else:
        verdict = "block"

    # Enforce override rules
    if force_block:
        verdict = "block"
        if clamped_score < 70:
            clamped_score = max(clamped_score, 70)

    if not reasons:
        reasons.append("No security anomalies detected.")

    return clamped_score, verdict, reasons
