from unittest.mock import patch
import pytest
from engine.vulns import _extract_cve_info, refresh_vulns, get_vulns


def test_extract_cve_info_v31():
    mock_item = {
        "cve": {
            "id": "CVE-2022-35914",
            "descriptions": [
                {"lang": "en", "value": "GLPI is an open source IT asset management software. Fixed in 10.0.3 and 9.5.9."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            },
            "published": "2022-09-19T21:15:09.917",
            "references": [
                {"url": "https://github.com/glpi-project/glpi/security/advisories/GHSA-4h86-98r3-2j2x", "tags": ["Patch", "Vendor Advisory"]}
            ],
        }
    }

    res = _extract_cve_info(mock_item)
    assert res["id"] == "CVE-2022-35914"
    assert res["cvss_score"] == 9.8
    assert res["severity"] == "CRITICAL"
    assert res["remediation"] == "https://github.com/glpi-project/glpi/security/advisories/GHSA-4h86-98r3-2j2x"


def test_refresh_vulns_with_mock():
    mock_nvd_response = [
        {
            "cve": {
                "id": "CVE-2021-39211",
                "descriptions": [{"lang": "en", "value": "A vulnerability in GLPI 9.5.5 allows remote code execution."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]
                },
                "published": "2021-09-01T00:00:00",
                "references": [],
            }
        },
        {
            "cve": {
                "id": "CVE-2021-21389",
                "descriptions": [{"lang": "en", "value": "GLPI Barcode plugin XSS issue."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}]
                },
                "published": "2021-04-01T00:00:00",
                "references": [],
            }
        },
    ]

    with patch("engine.vulns._query_nvd", return_value=mock_nvd_response):
        vulns = refresh_vulns()
        assert len(vulns) >= 2
        # Verify sorted descending by CVSS
        assert vulns[0]["cvss_score"] >= vulns[1]["cvss_score"]
        assert vulns[0]["id"] == "CVE-2021-39211"
