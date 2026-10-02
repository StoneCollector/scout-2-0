import pytest
from pathlib import Path
from engine.checkers.vendor_hash import VendorHashChecker
from engine.config import VendorHashSource


def test_parse_virtualbox_sums():
    sample_text = (
        "a5ee3e693a0470a77735556a77a09aa83bfc48181998b9b21b1af82ef1d11c2a *Oracle_VM_VirtualBox_Extension_Pack-6.1.30.vbox-extpack\n"
        "8bad003d65e9f385c4bf1f413f1ea1242a4f16fd9f352848685c78732147c97b *VirtualBox-6.1.30-148432-Win.exe\n"
    )
    h = VendorHashChecker.parse_virtualbox_sums(sample_text, "VirtualBox-6.1.30-148432-Win.exe")
    assert h == "8bad003d65e9f385c4bf1f413f1ea1242a4f16fd9f352848685c78732147c97b"

    h2 = VendorHashChecker.parse_virtualbox_sums(sample_text, "Oracle_VM_VirtualBox_Extension_Pack-6.1.30.vbox-extpack")
    assert h2 == "a5ee3e693a0470a77735556a77a09aa83bfc48181998b9b21b1af82ef1d11c2a"


def test_parse_wireshark_sigs():
    sample_text = (
        "Wireshark-win64-3.6.0.exe: 77270896 bytes\n"
        "SHA256(Wireshark-win64-3.6.0.exe)=8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255\n"
        "SHA1(Wireshark-win64-3.6.0.exe)=a847cd6fcc0764429601e7ab7967936d83f1a9f8\n"
    )
    h = VendorHashChecker.parse_wireshark_sigs(sample_text, "Wireshark-win64-3.6.0.exe")
    assert h == "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255"


def test_parse_zap_xml():
    sample_xml = """<ZAP>
      <core>
        <windows>
          <url>https://github.com/zaproxy/zaproxy/releases/download/v2.11.1/ZAP_2_11_1_windows.exe</url>
          <file>ZAP_2_11_1_windows.exe</file>
          <hash>SHA-256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff</hash>
        </windows>
      </core>
    </ZAP>"""
    h = VendorHashChecker.parse_zap_xml(sample_xml, "ZAP_2_11_1_windows.exe")
    assert h == "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"


def test_parse_libreoffice_page():
    sample_html = """
    <html>
      <body>
        <p>Details for LibreOffice_7.2.3_Win_x64.msi</p>
        <p>SHA-256 Hash: 8f6b3fa8bdf81f70b43689d45178b4790b0140d6962deac1b9381245d6568461</p>
      </body>
    </html>
    """
    h = VendorHashChecker.parse_libreoffice_page(sample_html, "LibreOffice_7.2.3_Win_x64.msi")
    assert h == "8f6b3fa8bdf81f70b43689d45178b4790b0140d6962deac1b9381245d6568461"


def test_vendor_hash_checker_match_and_mismatch(monkeypatch):
    checker = VendorHashChecker()

    # Match test
    def mock_get_digest_match(filename, source):
        return "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255", "http://test"

    monkeypatch.setattr(checker, "_get_given_digest", mock_get_digest_match)
    res_match = checker.check(
        Path("C:/Wireshark-win64-3.6.0.exe"),
        {"sha256": "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255"},
    )
    assert res_match.status == "pass"
    assert res_match.score == -30
    assert res_match.details["match"] is True

    # Mismatch test
    res_mismatch = checker.check(
        Path("C:/Wireshark-win64-3.6.0.exe"),
        {"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
    )
    assert res_mismatch.status == "fail"
    assert res_mismatch.score == 70
    assert res_mismatch.details["match"] is False


def test_parse_generic_html_table():
    sample_html = """
    <table>
      <thead><tr><th>File</th><th>Size</th><th>SHA256</th></tr></thead>
      <tbody>
        <tr>
          <td>VLC-3.0.18-win64.exe</td>
          <td>42MB</td>
          <td>1111111111111111111111111111111111111111111111111111111111111111</td>
        </tr>
        <tr>
          <td>VLC-3.0.18-win32.exe</td>
          <td>40MB</td>
          <td>2222222222222222222222222222222222222222222222222222222222222222</td>
        </tr>
      </tbody>
    </table>
    """
    h64 = VendorHashChecker.parse_generic_html(sample_html, "VLC-3.0.18-win64.exe")
    assert h64 == "1111111111111111111111111111111111111111111111111111111111111111"

    h32 = VendorHashChecker.parse_generic_html(sample_html, "VLC-3.0.18-win32.exe")
    assert h32 == "2222222222222222222222222222222222222222222222222222222222222222"


def test_parse_generic_html_proximity():
    sample_html = """
    <div class="download-card">
      <h3>Release Wireshark 3.6.0</h3>
      <p>Download link: <a href="/Wireshark-win64-3.6.0.exe">Wireshark-win64-3.6.0.exe</a></p>
      <code>SHA256 Checksum: 8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255</code>
    </div>
    """
    h = VendorHashChecker.parse_generic_html(sample_html, "Wireshark-win64-3.6.0.exe")
    assert h == "8ffa9f2c7943d1e8ed8020d7d08c8015ec649c3e3af901808a9ec858564cd255"


def test_auto_detect_and_parse():
    # Detects plain sums without knowing format
    sums_text = "3333333333333333333333333333333333333333333333333333333333333333 *MyTool-1.0.exe\n"
    h = VendorHashChecker.auto_detect_and_parse(sums_text, "MyTool-1.0.exe")
    assert h == "3333333333333333333333333333333333333333333333333333333333333333"

