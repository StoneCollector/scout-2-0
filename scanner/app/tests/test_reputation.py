from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from engine.checkers.reputation import CirclChecker, MalwareBazaarChecker


def test_circl_checker_known_good():
    checker = CirclChecker()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "source": "NSRL",
        "FileName": "calc.exe",
    }

    with patch("requests.get", return_value=mock_resp):
        res = checker.check(Path("C:/calc.exe"), {"sha256": "1" * 64})
        assert res.status == "pass"
        assert res.score == -30
        assert res.details["known"] is True
        assert res.details["source"] == "NSRL"


def test_circl_checker_unknown():
    checker = CirclChecker()
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("requests.get", return_value=mock_resp):
        res = checker.check(Path("C:/unknown.exe"), {"sha256": "2" * 64})
        assert res.status == "pass"
        assert res.score == 0
        assert res.details["known"] is False


def test_circl_checker_network_error():
    checker = CirclChecker()
    with patch("requests.get", side_effect=Exception("Connection timed out")):
        res = checker.check(Path("C:/error.exe"), {"sha256": "3" * 64})
        assert res.status == "skip"
        assert res.score == 0
        assert "error" in res.details


def test_malware_bazaar_hit():
    checker = MalwareBazaarChecker()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "data": [
            {
                "signature": "WannaCry",
                "tags": ["ransomware", "trojan"],
                "first_seen": "2021-05-01 10:00:00",
            }
        ],
    }

    with patch("requests.post", return_value=mock_resp):
        res = checker.check(Path("C:/wannacry.exe"), {"sha256": "4" * 64})
        assert res.status == "fail"
        assert res.score == 90
        assert res.details["signature"] == "WannaCry"
        assert "ransomware" in res.details["tags"]


def test_malware_bazaar_not_found():
    checker = MalwareBazaarChecker()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"query_status": "hash_not_found"}

    with patch("requests.post", return_value=mock_resp):
        res = checker.check(Path("C:/clean.exe"), {"sha256": "5" * 64})
        assert res.status == "pass"
        assert res.score == 0
        assert res.details["found"] is False


def test_malware_bazaar_network_error():
    checker = MalwareBazaarChecker()
    with patch("requests.post", side_effect=Exception("DNS resolution failed")):
        res = checker.check(Path("C:/clean.exe"), {"sha256": "6" * 64})
        assert res.status == "skip"
        assert res.score == 0
        assert "error" in res.details
