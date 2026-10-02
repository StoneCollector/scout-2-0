import os
import pytest
from pathlib import Path
from engine.db import (
    create_scan,
    add_result,
    finish_scan,
    get_scan,
    list_scans,
    cached_verdict_by_sha256,
    stats,
)


def test_scan_lifecycle():
    # 1. Create a scan
    scan_id = create_scan("test_sample.exe", "C:/scanner/inbox/test_sample.exe", "a" * 64, 1024)
    assert scan_id > 0

    # 2. Add results
    res1_id = add_result(scan_id, "signature", "pass", 0, {"signed": True, "verified": True})
    assert res1_id > 0

    res2_id = add_result(scan_id, "vendor_hash", "warn", 25, {"match": False})
    assert res2_id > 0

    # 3. Finish scan
    finished = finish_scan(scan_id, "review", 25)
    assert finished is not None
    assert finished["verdict"] == "review"
    assert finished["score"] == 25
    assert finished["status"] == "completed"
    assert len(finished["check_results"]) == 2

    # 4. Get scan
    fetched = get_scan(scan_id)
    assert fetched["id"] == scan_id
    assert fetched["filename"] == "test_sample.exe"
    assert fetched["sha256"] == "a" * 64

    # 5. List scans
    all_scans = list_scans(limit=10)
    assert len(all_scans) >= 1
    assert any(s["id"] == scan_id for s in all_scans)

    # 6. Cached verdict
    cached = cached_verdict_by_sha256("a" * 64)
    assert cached is not None
    assert cached["verdict"] == "review"
    assert cached["score"] == 25

    # 7. Stats
    current_stats = stats()
    assert current_stats["total_scans"] >= 1
    assert current_stats["review"] >= 1
