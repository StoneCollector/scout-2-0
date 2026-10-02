from pathlib import Path
import pytest
from engine.db import get_scan, list_scans
from engine.models import Result
from engine.pipeline import ScanPipeline
from engine.scoring import score_results


def test_scoring_logic_and_overrides():
    # 1. Clean file: score 0 -> pass
    res_clean = [
        Result(checker="signature", status="pass", score=0, details={"signed": True, "verified": True, "trusted": True}),
        Result(checker="vendor_hash", status="pass", score=-30, details={"match": True}),
    ]
    score, verdict, reasons = score_results(res_clean)
    assert score == 0
    assert verdict == "pass"

    # 2. Hash mismatch override -> block
    res_mismatch = [
        Result(checker="signature", status="pass", score=0, details={"signed": True, "verified": True, "trusted": True}),
        Result(checker="vendor_hash", status="fail", score=70, details={"match": False}),
    ]
    score, verdict, reasons = score_results(res_mismatch)
    assert score >= 70
    assert verdict == "block"
    assert any("mismatch" in r.lower() for r in reasons)

    # 3. Tampered signature override -> block
    res_tampered = [
        Result(checker="signature", status="fail", score=60, details={"signed": True, "verified": False}),
    ]
    score, verdict, reasons = score_results(res_tampered)
    assert verdict == "block"
    assert any("tampered" in r.lower() or "invalid" in r.lower() for r in reasons)


def test_end_to_end_pipeline(tmp_path, monkeypatch):
    # Set up temp folders
    temp_inbox = tmp_path / "inbox"
    temp_proc = tmp_path / "proc"
    temp_clean = tmp_path / "clean"
    temp_review = tmp_path / "review"
    temp_quar = tmp_path / "quar"
    for d in [temp_inbox, temp_proc, temp_clean, temp_review, temp_quar]:
        d.mkdir(parents=True, exist_ok=True)

    from engine.config import settings
    monkeypatch.setattr(settings, "inbox_dir", temp_inbox)
    monkeypatch.setattr(settings, "processing_dir", temp_proc)
    monkeypatch.setattr(settings, "clean_dir", temp_clean)
    monkeypatch.setattr(settings, "review_dir", temp_review)
    monkeypatch.setattr(settings, "quarantine_dir", temp_quar)

    test_file = temp_inbox / "sample_doc.txt"
    test_file.write_text("Safe university demo test content.", encoding="utf-8")

    pipe = ScanPipeline(yara_auto_compile=False)
    result = pipe.process(test_file)

    assert result["scan_id"] > 0
    assert result["verdict"] in ["pass", "review", "block"]

    # Verify original file removed from inbox
    assert not test_file.exists()

    # Verify destination file exists in clean/ (or review/quar)
    dest_path = Path(result["destination"])
    assert dest_path.is_file()

    # Verify database scan row
    db_scan = get_scan(result["scan_id"])
    assert db_scan is not None
    assert db_scan["filename"] == "sample_doc.txt"
    assert db_scan["status"] == "completed"
    assert len(db_scan["check_results"]) == 7
