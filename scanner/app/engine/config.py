from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import yaml

# Locate root directory
CURRENT_FILE = Path(__file__).resolve()
ENGINE_DIR = CURRENT_FILE.parent
APP_DIR = ENGINE_DIR.parent
SCANNER_DIR = APP_DIR.parent

# Load .env (check scanner root, app root, current dir)
env_candidates = [
    SCANNER_DIR / ".env",
    APP_DIR / ".env",
    Path(".env"),
]
for env_path in env_candidates:
    if env_path.is_file():
        load_dotenv(env_path)
        break


@dataclass
class VendorHashSource:
    pattern: str
    source_type: str
    url: Optional[str] = None
    manual_sha256: Optional[str] = None
    fallback_urls: List[str] = field(default_factory=list)


@dataclass
class ClamAvSettings:
    host: str = "127.0.0.1"
    port: int = 3310
    auto_start: bool = True


@dataclass
class Settings:
    # Folders
    inbox_dir: Path
    processing_dir: Path
    clean_dir: Path
    review_dir: Path
    quarantine_dir: Path
    data_dir: Path
    tools_dir: Path
    rules_dir: Path
    clamav_dir: Path

    # Keys
    abusech_key: str = ""
    nvd_key: str = ""

    # Signers & Hashes
    trusted_signers: List[str] = field(default_factory=list)
    vendor_hashes: List[VendorHashSource] = field(default_factory=list)

    # ClamAV
    clamav: ClamAvSettings = field(default_factory=ClamAvSettings)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scanner.db"

    @property
    def sigcheck_path(self) -> Path:
        candidates = [
            self.tools_dir / "sigcheck64.exe",
            self.tools_dir / "sigcheck.exe",
            SCANNER_DIR / "sigcheck.exe",
            SCANNER_DIR / "tools" / "sigcheck.exe",
            SCANNER_DIR / "tools" / "sigcheck64.exe",
        ]
        for c in candidates:
            if c.is_file():
                return c
        return self.tools_dir / "sigcheck.exe"

    @property
    def clamd_exe(self) -> Path:
        candidates = [
            self.clamav_dir / "clamd.exe",
            SCANNER_DIR / "clamav" / "clamd.exe",
        ]
        for c in candidates:
            if c.is_file():
                return c
        return self.clamav_dir / "clamd.exe"

    @property
    def yara_rules_dir(self) -> Path:
        candidates = [
            self.rules_dir / "signature-base" / "yara",
            self.rules_dir / "yara",
            SCANNER_DIR / "rules" / "signature-base" / "yara",
        ]
        for c in candidates:
            if c.is_dir():
                return c
        return self.rules_dir / "signature-base" / "yara"


def load_settings(config_file: Optional[Path] = None) -> Settings:
    if config_file is None:
        candidates = [
            APP_DIR / "config.yaml",
            SCANNER_DIR / "config.yaml",
            Path("config.yaml"),
        ]
        for c in candidates:
            if c.is_file():
                config_file = c
                break

    raw_config: Dict[str, Any] = {}
    if config_file and config_file.is_file():
        with open(config_file, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f) or {}

    paths = raw_config.get("paths", {})

    def resolve_path(val: Optional[str], default: Path) -> Path:
        if not val:
            return default
        p = Path(val)
        if not p.is_absolute():
            p = (config_file.parent if config_file else APP_DIR) / p
        return p

    inbox = resolve_path(paths.get("inbox"), SCANNER_DIR / "inbox")
    processing = resolve_path(paths.get("processing"), SCANNER_DIR / "processing")
    clean = resolve_path(paths.get("clean"), SCANNER_DIR / "clean")
    review = resolve_path(paths.get("review"), SCANNER_DIR / "review")
    quarantine = resolve_path(paths.get("quarantine"), SCANNER_DIR / "quarantine")
    data = resolve_path(paths.get("data"), APP_DIR / "data")
    tools = resolve_path(paths.get("tools"), SCANNER_DIR / "tools")
    rules = resolve_path(paths.get("rules"), SCANNER_DIR / "rules")
    clamav_p = resolve_path(paths.get("clamav"), SCANNER_DIR / "clamav")

    for d in [inbox, processing, clean, review, quarantine, data, data / "feeds", data / "logs"]:
        d.mkdir(parents=True, exist_ok=True)

    trusted = raw_config.get(
        "trusted_signers",
        [
            "Oracle America, Inc.",
            "The Document Foundation",
            "Wireshark Foundation",
            "Simon Bennetts",
            "ZAP",
        ],
    )

    vendor_sources: List[VendorHashSource] = []
    for entry in raw_config.get("vendor_hashes", []):
        vendor_sources.append(
            VendorHashSource(
                pattern=entry.get("pattern", "*"),
                source_type=entry.get("source_type", "manual"),
                url=entry.get("url"),
                manual_sha256=entry.get("manual_sha256"),
                fallback_urls=entry.get("fallback_urls", []),
            )
        )

    clamav_cfg = raw_config.get("clamav", {})
    clamav_settings = ClamAvSettings(
        host=clamav_cfg.get("host", "127.0.0.1"),
        port=clamav_cfg.get("port", 3310),
        auto_start=clamav_cfg.get("auto_start", True),
    )

    return Settings(
        inbox_dir=inbox,
        processing_dir=processing,
        clean_dir=clean,
        review_dir=review,
        quarantine_dir=quarantine,
        data_dir=data,
        tools_dir=tools,
        rules_dir=rules,
        clamav_dir=clamav_p,
        abusech_key=os.getenv("ABUSECH_KEY", ""),
        nvd_key=os.getenv("NVD_KEY", ""),
        trusted_signers=trusted,
        vendor_hashes=vendor_sources,
        clamav=clamav_settings,
    )


# Default singleton instance
settings = load_settings()
