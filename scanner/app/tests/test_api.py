from fastapi.testclient import TestClient
import pytest
from api.main import app
from engine.db import create_scan, finish_scan, add_result

client = TestClient(app)


def test_api_scans():
    # Insert test scan
    scan_id = create_scan("sample_api_test.exe", "C:/scanner/clean/sample_api_test.exe", "1234567890abcdef" * 4, 2048)
    add_result(scan_id, "signature", "pass", 0, {"signed": True, "signer": "Oracle America, Inc.", "digest_algorithm": "sha256"})
    add_result(scan_id, "vendor_hash", "pass", -30, {"match": True, "given_digest": "1234567890abcdef" * 4})
    finish_scan(scan_id, "pass", 0)

    # 1. GET /api/scans
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    scans = resp.json()
    assert isinstance(scans, list)
    assert any(s["id"] == scan_id for s in scans)

    # 2. GET /api/scans/{id}
    resp_detail = client.get(f"/api/scans/{scan_id}")
    assert resp_detail.status_code == 200
    detail = resp_detail.json()
    assert detail["filename"] == "sample_api_test.exe"
    assert len(detail["check_results"]) >= 2

    # 3. GET /api/scans/999999 (404)
    resp_404 = client.get("/api/scans/999999")
    assert resp_404.status_code == 404


def test_api_stats():
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scans" in data
    assert "passed" in data
    assert "verdict_split" in data
    assert "scans_per_hour" in data
    assert "clamav" in data


def test_api_tasks_endpoints():
    # Task 1
    resp_sig = client.get("/api/tasks/signatures")
    assert resp_sig.status_code == 200
    assert isinstance(resp_sig.json(), list)

    # Task 2
    resp_hash = client.get("/api/tasks/hashes")
    assert resp_hash.status_code == 200
    assert isinstance(resp_hash.json(), list)

    # Task 3
    resp_mal = client.get("/api/tasks/malware")
    assert resp_mal.status_code == 200
    assert isinstance(resp_mal.json(), list)


def test_api_system_clamav():
    resp = client.get("/api/system/clamav")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "host" in data
    assert "port" in data
