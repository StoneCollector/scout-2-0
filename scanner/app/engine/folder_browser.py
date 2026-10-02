import base64
import os
from pathlib import Path
import subprocess
from typing import Optional

from engine.config import APP_DIR, SCANNER_DIR, settings


def pick_folder_native_dialog(initial_dir: Optional[str] = None) -> Optional[str]:
    """
    Spawns a native Windows folder browser dialog.
    Uses PowerShell STA FolderBrowserDialog for safe execution from background server threads,
    falling back to Tkinter if necessary.
    """
    start_p = ""
    if initial_dir and os.path.isdir(initial_dir):
        start_p = str(Path(initial_dir).resolve())
    elif settings.inbox_dir.is_dir():
        start_p = str(settings.inbox_dir.resolve())
    elif APP_DIR.is_dir():
        start_p = str(APP_DIR.resolve())
    else:
        start_p = str(SCANNER_DIR.resolve())

    # 1. Preferred on Windows: STA PowerShell FolderBrowserDialog (immune to thread apartment issues)
    if os.name == "nt":
        try:
            escaped_p = start_p.replace("'", "''")
            ps_script = f"""
            [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = 'Scout - Select Watch Folder'
            $dialog.ShowNewFolderButton = $true
            if (Test-Path '{escaped_p}') {{
                $dialog.SelectedPath = '{escaped_p}'
            }}
            $owner = New-Object System.Windows.Forms.Form
            $owner.TopMost = $true
            $owner.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
            $owner.Size = New-Object System.Drawing.Size(1, 1)
            $owner.Opacity = 0
            $owner.Show()
            $result = $dialog.ShowDialog($owner)
            $owner.Close()
            $owner.Dispose()
            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
                [Console]::Out.WriteLine($dialog.SelectedPath)
            }}
            """
            encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            res = subprocess.run(
                ["powershell", "-NoProfile", "-STA", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                timeout=120,
            )
            out = res.stdout.strip()
            if out and os.path.isdir(out):
                return str(Path(out).resolve())
            if res.returncode == 0 and not out:
                return None
        except Exception:
            pass

    # 2. Secondary fallback: Tkinter
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.wm_attributes("-topmost", 1)

        chosen = filedialog.askdirectory(
            initialdir=start_p,
            title="Scout - Select Watch Folder",
        )
        root.destroy()
        if chosen:
            return str(Path(chosen).resolve())
    except Exception:
        pass

    return None
