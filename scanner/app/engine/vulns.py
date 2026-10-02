import json
import logging
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional
import requests

from engine.config import settings

logger = logging.getLogger("scanner.vulns")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = settings.data_dir / "vulns.json"


def _extract_cve_info(cve_item: Dict[str, Any]) -> Dict[str, Any]:
    cve = cve_item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # English description
    descriptions = cve.get("descriptions", [])
    desc_en = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc_en = d.get("value", "")
            break
    if not desc_en and descriptions:
        desc_en = descriptions[0].get("value", "")

    # CVSS Score and Severity (prefer V3.1 > V3.0 > V2)
    metrics = cve.get("metrics", {})
    cvss_score = 0.0
    severity = "NONE"

    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_score = float(cvss_data.get("baseScore", 0.0))
        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_score = float(cvss_data.get("baseScore", 0.0))
        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        v2_entry = metrics["cvssMetricV2"][0]
        cvss_data = v2_entry.get("cvssData", {})
        cvss_score = float(cvss_data.get("baseScore", 0.0))
        severity = v2_entry.get("baseSeverity", "UNKNOWN").upper()

    published = cve.get("published", "")

    # Remediation extraction
    # 1. First reference tagged "Patch" or "Vendor Advisory"
    remediation = ""
    references = cve.get("references", [])
    for ref in references:
        tags = [t.lower() for t in ref.get("tags", [])]
        if "patch" in tags or "vendor advisory" in tags:
            remediation = ref.get("url", "")
            break

    # 2. Extract fixed-version sentence if available
    if not remediation:
        m = re.search(r"(fixed in [^\.]+|resolved in [^\.]+|upgrade to [^\.]+)", desc_en, re.IGNORECASE)
        if m:
            remediation = m.group(0).capitalize()

    # 3. Default fallback
    if not remediation:
        remediation = "Upgrade GLPI to the latest 10.x release"

    return {
        "id": cve_id,
        "description": desc_en,
        "cvss_score": cvss_score,
        "severity": severity,
        "published": published,
        "remediation": remediation,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _query_nvd(params: Dict[str, Any]) -> List[Dict[str, Any]]:
    headers = {}
    if settings.nvd_key:
        headers["apiKey"] = settings.nvd_key

    try:
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulnerabilities", [])
        else:
            logger.warning(f"NVD query returned HTTP {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        logger.warning(f"NVD query error: {e}")
    return []


def refresh_vulns() -> List[Dict[str, Any]]:
    all_vulns: Dict[str, Dict[str, Any]] = {}

    # Query 1: GLPI 9.5.5 CPE
    glpi_items = _query_nvd(
        {"cpeName": "cpe:2.3:a:glpi-project:glpi:9.5.5:*:*:*:*:*:*:*", "resultsPerPage": 20}
    )
    # Fallback to keywordSearch="glpi 9.5.5" if CPE query returned nothing
    if not glpi_items:
        glpi_items = _query_nvd({"keywordSearch": "glpi 9.5.5", "resultsPerPage": 20})

    for item in glpi_items:
        info = _extract_cve_info(item)
        all_vulns[info["id"]] = info

    # Query 2: GLPI barcode plugin (rate limit pause if needed)
    time.sleep(0.6)
    barcode_items = _query_nvd({"keywordSearch": "glpi barcode", "resultsPerPage": 10})
    for item in barcode_items:
        info = _extract_cve_info(item)
        if "barcode" in info["description"].lower():
            all_vulns[info["id"]] = info

    cve_list = list(all_vulns.values())

    # Sort descending by CVSS score
    cve_list.sort(key=lambda x: x["cvss_score"], reverse=True)

    if cve_list:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            CACHE_FILE.write_text(json.dumps(cve_list, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to write vulns cache: {e}")
        return cve_list

    # If network returned nothing, fallback to cache
    return _read_cache()


def _read_cache() -> List[Dict[str, Any]]:
    if CACHE_FILE.is_file():
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except Exception as e:
            logger.error(f"Failed to read vulns cache: {e}")
    return []


def get_vulns(force_refresh: bool = False) -> List[Dict[str, Any]]:
    if not force_refresh:
        cached = _read_cache()
        if cached:
            return cached
    return refresh_vulns()
