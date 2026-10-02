import os
from pathlib import Path
from typing import Optional

from engine.config import SCANNER_DIR, settings


def pick_folder_native_dialog(initial_dir: Optional[str] = None) -> Optional[str]:
    """
    Spawns a native Windows folder browser dialog using Tkinter.
    Runs locally on the desktop.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        # Bring to front on Windows
        root.wm_attributes("-topmost", 1)

        start_p = ""
        if initial_dir and os.path.isdir(initial_dir):
            start_p = str(Path(initial_dir).resolve())
        elif settings.inbox_dir.is_dir():
            start_p = str(settings.inbox_dir.resolve())
        else:
            start_p = str(SCANNER_DIR.resolve())

        chosen = filedialog.askdirectory(
            initialdir=start_p,
            title="Scout - Select Watch Folder",
        )
        root.destroy()
        if chosen:
            return str(Path(chosen).resolve())
        return None
    except Exception:
        return None
