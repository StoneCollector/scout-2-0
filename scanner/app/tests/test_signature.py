from pathlib import Path
from unittest.mock import patch
import pytest
from engine.checkers.signature import SignatureChecker


def test_signature_mocked_trusted():
    checker = SignatureChecker()
    mock_csv = (
        '"Path","Verified","Date","Publisher","Company","Description"\n'
        '"C:\\sample.exe","Signed","2026-01-01","Oracle America, Inc.","Oracle","VirtualBox"\n'
    ).encode("utf-16")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_csv
        with patch.object(checker, "_extract_digest_algorithm", return_value="sha256"):
            res = checker.check(Path("C:/sample.exe"), {})
            assert res.status == "pass"
            assert res.score == 0
            assert res.details["signed"] is True
            assert res.details["verified"] is True
            assert res.details["trusted"] is True
            assert res.details["signer"] == "Oracle America, Inc."
            assert res.details["digest_algorithm"] == "sha256"


def test_signature_mocked_untrusted():
    checker = SignatureChecker()
    mock_csv = (
        '"Path","Verified","Date","Publisher","Company","Description"\n'
        '"C:\\unknown.exe","Signed","2026-01-01","Random Hacker Corp","Hacker","Tool"\n'
    ).encode("utf-16")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_csv
        with patch.object(checker, "_extract_digest_algorithm", return_value="sha256"):
            res = checker.check(Path("C:/unknown.exe"), {})
            assert res.status == "warn"
            assert res.score == 25
            assert res.details["trusted"] is False


def test_signature_mocked_unsigned():
    checker = SignatureChecker()
    mock_csv = (
        '"Path","Verified","Date","Publisher","Company","Description"\n'
        '"C:\\unsigned.exe","Unsigned","","","",""\n'
    ).encode("utf-16")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_csv
        with patch.object(checker, "_extract_digest_algorithm", return_value="sha1"):
            res = checker.check(Path("C:/unsigned.exe"), {})
            assert res.status == "warn"
            assert res.score == 10
            assert res.details["signed"] is False
            assert res.details["signer"] == ""
            assert res.details["digest_algorithm"] == ""


def test_signature_mocked_invalid():
    checker = SignatureChecker()
    mock_csv = (
        '"Path","Verified","Date","Publisher","Company","Description"\n'
        '"C:\\tampered.exe","Invalid","","Some Publisher","",""\n'
    ).encode("utf-16")

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = mock_csv
        with patch.object(checker, "_extract_digest_algorithm", return_value="sha256"):
            res = checker.check(Path("C:/tampered.exe"), {})
            assert res.status == "fail"
            assert res.score == 60


def test_signature_live_notepad():
    checker = SignatureChecker()
    notepad_path = Path("C:/Windows/System32/notepad.exe")
    if notepad_path.is_file():
        res = checker.check(notepad_path, {})
        assert res.status in ["pass", "warn"]
        assert "signed" in res.details
        assert "verified" in res.details
