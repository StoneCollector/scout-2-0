import atexit
import logging
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from typing import Any, Dict, Optional
from engine.config import settings

logger = logging.getLogger("scanner.clamav")

_process: Optional[subprocess.Popen] = None
_status_lock = threading.Lock()
_clamav_state = {
    "status": "offline",  # offline, starting, ready, failed
    "running": False,
    "host": "127.0.0.1",
    "port": 3310,
    "pid": None,
    "message": "ClamAV is stopped.",
    "error": None,
}


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_clamav_status() -> Dict[str, Any]:
    with _status_lock:
        # Verify if port is currently open
        if is_port_open(_clamav_state["host"], _clamav_state["port"], timeout=0.5):
            _clamav_state["running"] = True
            _clamav_state["status"] = "ready"
            _clamav_state["message"] = f"ClamAV daemon active on port {_clamav_state['port']}."
        elif _clamav_state["status"] == "ready":
            _clamav_state["running"] = False
            _clamav_state["status"] = "offline"
            _clamav_state["message"] = "ClamAV connection lost."
        return dict(_clamav_state)


def ensure_clamav_configured() -> Optional[Path]:
    clamd_exe = settings.clamd_exe
    if not clamd_exe.is_file():
        return None
    clamav_dir = clamd_exe.parent
    db_candidates = [
        clamav_dir / "database",
        clamav_dir / "db",
    ]
    db_dir = None
    for d in db_candidates:
        if d.is_dir():
            db_dir = d
            break
    if db_dir is None:
        db_dir = clamav_dir / "database"
        db_dir.mkdir(parents=True, exist_ok=True)

    log_dir = settings.data_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    clamd_log = log_dir / "clamd.log"
    freshclam_log = log_dir / "freshclam.log"

    conf_file = clamav_dir / "clamd.conf"
    try:
        conf_content = (
            f"TCPSocket {settings.clamav.port}\n"
            f"TCPAddr {settings.clamav.host}\n"
            f"DatabaseDirectory {db_dir.resolve()}\n"
            f"LogFile {clamd_log.resolve()}\n"
            "LogTime yes\n"
            "MaxQueue 200\n"
            "MaxThreads 10\n"
        )
        conf_file.write_text(conf_content, encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not write clamd.conf: {e}")

    fresh_conf_file = clamav_dir / "freshclam.conf"
    try:
        fresh_content = (
            f"DatabaseDirectory {db_dir.resolve()}\n"
            f"UpdateLogFile {freshclam_log.resolve()}\n"
            "DatabaseMirror database.clamav.net\n"
        )
        fresh_conf_file.write_text(fresh_content, encoding="utf-8")
    except Exception as e:
        logger.warning(f"Could not write freshclam.conf: {e}")

    # Check for db files; if missing, run freshclam
    has_db = any(db_dir.glob("*.cvd")) or any(db_dir.glob("*.cld"))
    freshclam_exe = clamav_dir / "freshclam.exe"
    if not has_db and freshclam_exe.is_file():
        print("\n" + "=" * 60)
        print("  [Launcher] Antivirus threat definitions not found.")
        print("  [Launcher] Downloading latest database from database.clamav.net...")
        print("  [Launcher] (One-time initial setup, please wait a moment)")
        print("=" * 60 + "\n")
        logger.info("ClamAV signature database missing. Running freshclam to download definitions...")
        try:
            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NO_WINDOW
            p = subprocess.Popen(
                [str(freshclam_exe), f"--config-file={fresh_conf_file}"],
                cwd=str(clamav_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
            if p.stdout:
                for line in p.stdout:
                    line_str = line.strip()
                    if line_str:
                        print(f"  [freshclam] {line_str}")
            p.wait(timeout=300)
            if p.returncode == 0:
                print("\n  [Launcher] Threat definitions downloaded successfully! ClamAV ready.\n")
            else:
                print(f"\n  [Launcher] Notice: freshclam completed with status {p.returncode}.\n")
        except Exception as e:
            print(f"\n  [Launcher] Warning: freshclam download issue: {e}\n")
            logger.warning(f"freshclam signature download failed or timed out: {e}")

    return clamd_exe



def start_clamav_daemon(wait_ready: bool = True, timeout: int = 60) -> bool:
    global _process

    host = settings.clamav.host
    port = settings.clamav.port

    with _status_lock:
        if is_port_open(host, port, timeout=0.5):
            _clamav_state.update(
                {
                    "status": "ready",
                    "running": True,
                    "host": host,
                    "port": port,
                    "message": f"ClamAV is already running on {host}:{port}.",
                }
            )
            return True

        clamd_exe = ensure_clamav_configured()
        if not clamd_exe or not clamd_exe.is_file():
            _clamav_state.update(
                {
                    "status": "failed",
                    "running": False,
                    "message": f"clamd.exe not found at {settings.clamd_exe}.",
                    "error": "executable_missing",
                }
            )
            return False

        clamav_dir = clamd_exe.parent
        conf_file = clamav_dir / "clamd.conf"
        if not conf_file.is_file():
            _clamav_state.update(
                {
                    "status": "failed",
                    "running": False,
                    "message": f"clamd.conf not found at {conf_file}.",
                    "error": "conf_missing",
                }
            )
            return False

        # Prepare subprocess with hidden window (NO terminal visible to user)
        creationflags = 0
        if os.name == "nt":

            creationflags = subprocess.CREATE_NO_WINDOW

        cmd = [str(clamd_exe), f"--config-file={conf_file}"]
        log_file_path = settings.data_dir / "logs" / "clamd.log"
        log_file_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            log_handle = open(log_file_path, "a", encoding="utf-8")
            _process = subprocess.Popen(
                cmd,
                cwd=str(clamav_dir),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
            _clamav_state.update(
                {
                    "status": "starting",
                    "running": False,
                    "pid": _process.pid,
                    "message": "Starting ClamAV service in background...",
                    "error": None,
                }
            )
        except Exception as e:
            _clamav_state.update(
                {
                    "status": "failed",
                    "running": False,
                    "message": f"Failed to launch clamd: {e}",
                    "error": str(e),
                }
            )
            return False

    if not wait_ready:
        return True

    # Poll port until ready or timeout
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_port_open(host, port, timeout=0.8):
            with _status_lock:
                _clamav_state.update(
                    {
                        "status": "ready",
                        "running": True,
                        "host": host,
                        "port": port,
                        "message": f"ClamAV daemon active and listening on {host}:{port}.",
                    }
                )
            return True
        # Check if process died
        if _process and _process.poll() is not None:
            with _status_lock:
                _clamav_state.update(
                    {
                        "status": "failed",
                        "running": False,
                        "message": f"clamd process terminated unexpectedly with code {_process.returncode}.",
                        "error": "process_died",
                    }
                )
            return False
        time.sleep(1.0)

    with _status_lock:
        _clamav_state.update(
            {
                "status": "failed",
                "running": False,
                "message": f"ClamAV startup timed out after {timeout}s.",
                "error": "startup_timeout",
            }
        )
    return False


def stop_clamav_daemon():
    global _process
    with _status_lock:
        if _process is not None:
            try:
                _process.terminate()
                _process.wait(timeout=5)
            except Exception:
                try:
                    _process.kill()
                except Exception:
                    pass
            _process = None
        _clamav_state.update(
            {
                "status": "offline",
                "running": False,
                "pid": None,
                "message": "ClamAV service stopped.",
            }
        )


# Clean up automatically when Python process exits
atexit.register(stop_clamav_daemon)
