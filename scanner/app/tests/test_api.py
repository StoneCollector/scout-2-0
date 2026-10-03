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


def test_api_trusted_signers():
    # 1. GET trusted signers
    resp = client.get("/api/settings/trusted-signers")
    assert resp.status_code == 200
    data = resp.json()
    assert "signers" in data
    assert "presets" in data
    assert isinstance(data["signers"], list)
    assert isinstance(data["presets"], list)

    test_signer = "Test Automation Signer Corp"

    # 2. Add signer
    resp_add = client.post("/api/settings/trusted-signers", json={"signer": test_signer})
    assert resp_add.status_code == 200
    data_add = resp_add.json()
    assert data_add["status"] == "success"
    assert test_signer in data_add["signers"]

    # 3. Add existing signer (idempotent / status: exists)
    resp_dup = client.post("/api/settings/trusted-signers", json={"signer": test_signer})
    assert resp_dup.status_code == 200
    assert resp_dup.json()["status"] == "exists"

    # 4. Delete signer via path
    resp_del = client.delete(f"/api/settings/trusted-signers/{test_signer}")
    assert resp_del.status_code == 200
    data_del = resp_del.json()
    assert data_del["status"] == "success"
    assert test_signer not in data_del["signers"]
