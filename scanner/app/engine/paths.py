import sys
from pathlib import Path


def is_frozen() -> bool:
    """Return True if running inside a PyInstaller frozen bundle."""
    return getattr(sys, "frozen", False)


if is_frozen():
    # PyInstaller unpacks bundled read-only assets to sys._MEIPASS
    BUNDLE_DIR = Path(sys._MEIPASS).resolve()
    # Executable directory (writable persistent storage)
    APP_DIR = Path(sys.executable).resolve().parent
else:
    # Unfrozen dev mode: paths.py is in scanner/app/engine/paths.py
    _CURRENT_FILE = Path(__file__).resolve()
    _SCANNER_DIR = _CURRENT_FILE.parent.parent.parent
    BUNDLE_DIR = _SCANNER_DIR
    APP_DIR = _SCANNER_DIR


def app_path(*parts: str) -> Path:
    """Return a Path resolved under the writable APP_DIR."""
    return APP_DIR.joinpath(*parts)


def bundle_path(*parts: str) -> Path:
    """Return a Path resolved under the read-only BUNDLE_DIR."""
    return BUNDLE_DIR.joinpath(*parts)


def get_web_dist_dir() -> Path:
    """Find the built frontend static directory in frozen bundle or source."""
    candidates = [
        BUNDLE_DIR / "web" / "dist",
        APP_DIR / "app" / "web" / "dist",
        APP_DIR / "web" / "dist",
        Path(__file__).resolve().parent.parent / "web" / "dist",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return BUNDLE_DIR / "web" / "dist"
