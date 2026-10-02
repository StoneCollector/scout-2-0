from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import yaml

from engine.paths import APP_DIR, BUNDLE_DIR, app_path, bundle_path

# Backwards compatibility alias
SCANNER_DIR = APP_DIR

# Load .env (check APP_DIR, APP_DIR / app, current dir)
env_candidates = [
    app_path(".env"),
    APP_DIR / "app" / ".env",
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
            app_path("tools", "sigcheck64.exe"),
            app_path("tools", "sigcheck.exe"),
            app_path("sigcheck64.exe"),
            app_path("sigcheck.exe"),
        ]
        for c in candidates:
            if c.is_file():
                return c
        return self.tools_dir / "sigcheck.exe"

    @property
    def clamd_exe(self) -> Path:
        candidates = [
            self.clamav_dir / "clamd.exe",
            self.tools_dir / "clamav" / "clamd.exe",
            app_path("tools", "clamav", "clamd.exe"),
            app_path("clamav", "clamd.exe"),
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
            app_path("rules", "signature-base", "yara"),
            app_path("rules", "yara"),
        ]
        for c in candidates:
            if c.is_dir():
                return c
        return self.rules_dir / "signature-base" / "yara"


def load_settings(config_file: Optional[Path] = None) -> Settings:
    if config_file is None:
        candidates = [
            app_path("config.yaml"),
            APP_DIR / "app" / "config.yaml",
            bundle_path("config.yaml"),
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
        if p.is_absolute():
            return p
        # Check relative to APP_DIR first, then config_file parent
        cand = (APP_DIR / p).resolve()
        if cand.exists():
            return cand
        cand_app = (APP_DIR / "app" / p).resolve()
        if cand_app.exists():
            return cand_app
        if config_file:
            cand_cfg = (config_file.parent / p).resolve()
            if cand_cfg.exists():
                return cand_cfg
        return cand

    inbox = resolve_path(paths.get("inbox"), app_path("inbox"))
    processing = resolve_path(paths.get("processing"), app_path("processing"))
    clean = resolve_path(paths.get("clean"), app_path("clean"))
    review = resolve_path(paths.get("review"), app_path("review"))
    quarantine = resolve_path(paths.get("quarantine"), app_path("quarantine"))

    default_data = app_path("data")
    if not default_data.exists() and (APP_DIR / "app" / "data").exists():
        default_data = APP_DIR / "app" / "data"
    data = resolve_path(paths.get("data"), default_data)

    tools = resolve_path(paths.get("tools"), app_path("tools"))
    rules = resolve_path(paths.get("rules"), app_path("rules"))

    default_clamav = app_path("tools", "clamav")
    if not default_clamav.exists() and app_path("clamav").exists():
        default_clamav = app_path("clamav")
    clamav_p = resolve_path(paths.get("clamav"), default_clamav)

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
