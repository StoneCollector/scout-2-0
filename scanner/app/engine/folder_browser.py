import os
from pathlib import Path
import subprocess
from typing import Optional

from engine.config import APP_DIR, SCANNER_DIR, settings


def pick_folder_native_dialog(initial_dir: Optional[str] = None) -> Optional[str]:
    """
    Spawns a native Windows folder browser dialog.
    Tries Tkinter first; falls back to PowerShell WinForms if Tkinter fails.
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

    # 1. Try Tkinter
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        # Bring to front on Windows
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

    # 2. Fallback to PowerShell folder dialog
    if os.name == "nt":
        try:
            ps_script = f"""
            Add-Type -AssemblyName System.Windows.Forms
            $f = New-Object System.Windows.Forms.FolderBrowserDialog
            $f.Description = 'Scout - Select Watch Folder'
            $f.SelectedPath = '{start_p}'
            $f.ShowNewFolderButton = $true
            if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{
                Write-Output $f.SelectedPath
            }}
            """
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                timeout=60,
            )
            out = res.stdout.strip()
            if out and os.path.isdir(out):
                return str(Path(out).resolve())
        except Exception:
            pass

    return None
