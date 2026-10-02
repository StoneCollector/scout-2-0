import atexit
import ctypes
import os
from pathlib import Path
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import font as tkfont
import webbrowser

# Enable DPI awareness on Windows for sharp fonts
if os.name == "nt":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

# Ensure paths are set up whether running from source or frozen
if getattr(sys, "frozen", False):
    BUNDLE_DIR = Path(sys._MEIPASS).resolve()
    APP_DIR = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    APP_DIR = BUNDLE_DIR

for cand in [BUNDLE_DIR / "app", APP_DIR / "app", BUNDLE_DIR, APP_DIR]:
    if cand.is_dir() and str(cand) not in sys.path:
        sys.path.insert(0, str(cand))

from engine.paths import app_path

LOCK_PORT = 8765
_lock_socket = None


def acquire_instance_lock():
    """Ensure only one instance runs. If running, open dashboard and exit."""
    global _lock_socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
        _lock_socket = s
        return True
    except OSError:
        webbrowser.open("http://localhost:8000")
        sys.exit(0)


def init_environment():
    """Ensure working directories and default .env exist."""
    for folder in [
        "inbox",
        "processing",
        "clean",
        "review",
        "quarantine",
        "data",
        "data/logs",
        "data/feeds",
    ]:
        p = app_path(*folder.split("/"))
        p.mkdir(parents=True, exist_ok=True)

    env_path = app_path(".env")
    if not env_path.is_file():
        try:
            env_path.write_text("ABUSECH_KEY=\nNVD_KEY=\n", encoding="utf-8")
        except Exception:
            pass


# Thread-safe log queue
log_queue = queue.Queue(maxsize=5000)


class LogStream:
    def __init__(self, original_stream, log_file_handle=None):
        self.original_stream = original_stream
        self.log_file_handle = log_file_handle
        self.encoding = getattr(original_stream, "encoding", "utf-8") or "utf-8"
        self.errors = getattr(original_stream, "errors", "replace") or "replace"
        self.closed = False

    def isatty(self):
        return False

    def readable(self):
        return False

    def writable(self):
        return True

    def seekable(self):
        return False

    def write(self, text):
        if not text:
            return 0
        try:
            log_queue.put_nowait(text)
        except queue.Full:
            pass

        if self.log_file_handle:
            try:
                self.log_file_handle.write(text)
                self.log_file_handle.flush()
            except Exception:
                pass

        if self.original_stream:
            try:
                self.original_stream.write(text)
                self.original_stream.flush()
            except Exception:
                pass
        return len(text)

    def flush(self):
        if self.original_stream:
            try:
                self.original_stream.flush()
            except Exception:
                pass
        if self.log_file_handle:
            try:
                self.log_file_handle.flush()
            except Exception:
                pass



# Background server references
_uvicorn_server = None
_backend_thread = None
_is_shutting_down = False


def run_uvicorn():
    global _uvicorn_server
    import uvicorn
    from api.main import app as fastapi_app

    class ThreadSafeServer(uvicorn.Server):
        def install_signal_handlers(self):
            pass

    config = uvicorn.Config(
        fastapi_app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
        access_log=False,
    )
    _uvicorn_server = ThreadSafeServer(config=config)
    _uvicorn_server.run()


class LauncherApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Scout")
        self.root.geometry("860x560")
        self.root.minsize(680, 420)
        self.root.configure(bg="#080c14")

        # Center window on screen
        self.center_window(860, 560)

        # Build UI layout
        self.build_ui()

        # Handle window close (X button)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start drain queue loop for logs
        self.root.after(40, self.drain_log_queue)

    def center_window(self, width: int, height: int):
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def build_ui(self):
        # 1. Top Header Frame (Packed at TOP)
        header = tk.Frame(self.root, bg="#0f172a", padx=20, pady=12)
        header.pack(fill=tk.X, side=tk.TOP)

        # Title & Subtitle container
        title_box = tk.Frame(header, bg="#0f172a")
        title_box.pack(side=tk.LEFT)

        title_lbl = tk.Label(
            title_box,
            text="SCOUT",
            font=("Segoe UI", 13, "bold"),
            fg="#38bdf8",
            bg="#0f172a",
        )
        title_lbl.pack(anchor="w")

        sub_lbl = tk.Label(
            title_box,
            text="Malware Scanner & Security Platform",
            font=("Segoe UI", 9),
            fg="#94a3b8",
            bg="#0f172a",
        )
        sub_lbl.pack(anchor="w", pady=(2, 0))

        # Status badge container
        badge_box = tk.Frame(header, bg="#0f172a")
        badge_box.pack(side=tk.RIGHT)

        self.status_lbl = tk.Label(
            badge_box,
            text="● INITIALIZING",
            font=("Segoe UI", 9, "bold"),
            fg="#f59e0b",
            bg="#0f172a",
        )
        self.status_lbl.pack(side=tk.RIGHT, pady=6)

        # 2. Bottom Action Bar (Packed at BOTTOM so it is NEVER clipped)
        footer = tk.Frame(self.root, bg="#0f172a", padx=20, pady=12)
        footer.pack(fill=tk.X, side=tk.BOTTOM)

        # Host link info on left
        link_box = tk.Frame(footer, bg="#0f172a")
        link_box.pack(side=tk.LEFT)

        self.url_label = tk.Label(
            link_box,
            text="http://localhost:8000",
            font=("Segoe UI", 9, "underline"),
            fg="#38bdf8",
            bg="#0f172a",
            cursor="hand2",
        )
        self.url_label.pack(side=tk.LEFT)
        self.url_label.bind("<Button-1>", lambda e: self.open_dashboard())

        # Buttons on right: "Open" and "Exit"
        btn_box = tk.Frame(footer, bg="#0f172a")
        btn_box.pack(side=tk.RIGHT)

        self.open_btn = tk.Button(
            btn_box,
            text="Open",
            font=("Segoe UI", 9, "bold"),
            bg="#2563eb",
            fg="#ffffff",
            activebackground="#1d4ed8",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=20,
            pady=5,
            cursor="hand2",
            command=self.open_dashboard,
        )
        self.open_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.exit_btn = tk.Button(
            btn_box,
            text="Exit",
            font=("Segoe UI", 9, "bold"),
            bg="#1e293b",
            fg="#f1f5f9",
            activebackground="#dc2626",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=20,
            pady=5,
            cursor="hand2",
            command=self.on_close,
        )
        self.exit_btn.pack(side=tk.LEFT)

        # 3. Main Content (Terminal output view - fills remaining space)
        content_frame = tk.Frame(self.root, bg="#080c14", padx=16, pady=12)
        content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Label above terminal
        console_hdr = tk.Frame(content_frame, bg="#080c14")
        console_hdr.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            console_hdr,
            text="TERMINAL OUTPUT",
            font=("Segoe UI", 8, "bold"),
            fg="#64748b",
            bg="#080c14",
        ).pack(side=tk.LEFT)

        # Terminal text area with scrollbar
        term_box = tk.Frame(
            content_frame,
            bg="#030712",
            highlightthickness=1,
            highlightbackground="#1e293b",
        )
        term_box.pack(fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(
            term_box,
            bg="#0f172a",
            troughcolor="#030712",
            activebackground="#334155",
            width=12,
            relief="flat",
        )
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.text_area = tk.Text(
            term_box,
            bg="#030712",
            fg="#e2e8f0",
            insertbackground="#38bdf8",
            selectbackground="#1e293b",
            selectforeground="#ffffff",
            font=("Consolas", 9),
            wrap=tk.WORD,
            relief="flat",
            padx=12,
            pady=10,
            yscrollcommand=self.scrollbar.set,
        )
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.text_area.yview)

        # Configure color tags for log levels
        self.text_area.tag_config("info", foreground="#94a3b8")
        self.text_area.tag_config("success", foreground="#10b981")
        self.text_area.tag_config("warn", foreground="#f59e0b")
        self.text_area.tag_config("error", foreground="#ef4444")
        self.text_area.tag_config("highlight", foreground="#38bdf8")

    def open_dashboard(self):
        webbrowser.open("http://localhost:8000")

    def drain_log_queue(self):
        chunk = []
        try:
            while True:
                chunk.append(log_queue.get_nowait())
        except queue.Empty:
            pass

        if chunk:
            text = "".join(chunk)
            self.text_area.insert(tk.END, text)
            # Cap maximum lines to prevent infinite memory growth
            line_count = int(self.text_area.index("end-1c").split(".")[0])
            if line_count > 3000:
                self.text_area.delete("1.0", f"{line_count - 2500}.0")
            self.text_area.see(tk.END)

        if not _is_shutting_down:
            self.root.after(40, self.drain_log_queue)

    def set_ready_status(self):
        self.status_lbl.config(text="● READY", fg="#10b981")

    def set_shutdown_status(self):
        self.status_lbl.config(text="● STOPPING", fg="#ef4444")
        self.open_btn.config(state="disabled")
        self.exit_btn.config(state="disabled")

    def on_close(self):
        global _is_shutting_down
        if _is_shutting_down:
            return
        _is_shutting_down = True
        self.set_shutdown_status()
        print("\n[Launcher] Stopping Scout services...")

        def do_shutdown():
            try:
                from engine.watcher import watcher
                watcher.stop()
            except Exception:
                pass

            try:
                from engine.clamav_manager import stop_clamav_daemon
                stop_clamav_daemon()
            except Exception:
                pass

            global _uvicorn_server
            if _uvicorn_server is not None:
                _uvicorn_server.should_exit = True
                _uvicorn_server.force_exit = True

            global _lock_socket
            if _lock_socket is not None:
                try:
                    _lock_socket.close()
                except Exception:
                    pass

            time.sleep(0.3)
            self.root.after(100, self.root.destroy)
            sys.exit(0)

        threading.Thread(target=do_shutdown, daemon=True).start()


def startup_background_tasks(app_instance: LauncherApp):
    """Wait for backend server to respond, then auto-open browser and set status."""
    import urllib.request

    print("=" * 60)
    print("  Scout Security Platform")
    print("  Local URL: http://localhost:8000")
    print(f"  App Directory: {APP_DIR}")
    print("=" * 60)

    # Poll /api/stats
    url = "http://127.0.0.1:8000/api/stats"
    ready = False
    for _ in range(60):
        if _is_shutting_down:
            return
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Scout-Launcher"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.5)

    if ready and not _is_shutting_down:
        print("\n[Launcher] Backend server is ready at http://localhost:8000")
        app_instance.root.after(0, app_instance.set_ready_status)
        webbrowser.open("http://localhost:8000")
    elif not _is_shutting_down:
        print("\n[Launcher] Notice: Backend took longer than expected to report status.")


def main():
    # 1. Enforce single instance lock
    acquire_instance_lock()

    # 2. Initialize working folders & .env
    init_environment()

    # 3. Setup file log stream
    log_file_path = app_path("data", "logs", "app.log")
    log_file_handle = None
    try:
        log_file_handle = open(log_file_path, "a", encoding="utf-8")
    except Exception:
        pass

    # Redirect stdout and stderr into GUI log stream
    sys.stdout = LogStream(sys.stdout, log_file_handle)
    sys.stderr = LogStream(sys.stderr, log_file_handle)

    # 4. Start Uvicorn in background thread
    global _backend_thread
    _backend_thread = threading.Thread(target=run_uvicorn, daemon=True)
    _backend_thread.start()

    # 5. Create and run Tkinter desktop app window
    root = tk.Tk()
    app = LauncherApp(root)

    # 6. Start health-check & auto-open thread
    checker_thread = threading.Thread(
        target=startup_background_tasks, args=(app,), daemon=True
    )
    checker_thread.start()

    # Run main GUI loop
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        import traceback
        crash_log = app_path("data", "logs", "crash.log")
        try:
            crash_log.parent.mkdir(parents=True, exist_ok=True)
            with open(crash_log, "w", encoding="utf-8") as f:
                traceback.print_exc(file=f)
        except Exception:
            pass
        try:
            from tkinter import messagebox
            import tkinter as tk
            r = tk.Tk()
            r.withdraw()
            messagebox.showerror(
                "Scout Startup Error",
                f"Scout encountered an error during startup:\n\n{exc}\n\nLog saved to:\n{crash_log}",
            )
        except Exception:
            pass
        sys.exit(1)

