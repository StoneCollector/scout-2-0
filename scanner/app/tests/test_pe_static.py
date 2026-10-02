from pathlib import Path
import pytest
from engine.checkers.pe_static import PeStaticChecker, calculate_entropy


def test_calculate_entropy():
    # Uniform bytes have near maximum entropy (8.0 for all 256 byte values)
    all_bytes = bytes(range(256))
    ent = calculate_entropy(all_bytes)
    assert 7.9 <= ent <= 8.0

    # Constant bytes have 0 entropy
    zero_bytes = b"\x00" * 1000
    ent_zero = calculate_entropy(zero_bytes)
    assert ent_zero == 0.0


def test_pe_static_on_notepad():
    checker = PeStaticChecker()
    notepad_path = Path("C:/Windows/System32/notepad.exe")
    if notepad_path.is_file():
        res = checker.check(notepad_path, {})
        assert res.checker == "pe_static"
        assert res.status in ["pass", "warn"]
        assert "overall_entropy" in res.details
        assert "sections" in res.details
        assert len(res.details["sections"]) > 0


def test_pe_static_on_non_pe(tmp_path):
    checker = PeStaticChecker()
    text_file = tmp_path / "dummy.txt"
    text_file.write_text("Hello, this is a plain text file, not a PE.", encoding="utf-8")

    res = checker.check(text_file, {})
    assert res.checker == "pe_static"
    assert res.status == "skip"
    assert res.score == 0
    assert res.details.get("reason") == "not_a_pe_file"
