import logging
from pathlib import Path
import queue
import threading
import time
from typing import Optional
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from engine.config import settings
from engine.pipeline import pipeline

logger = logging.getLogger("scanner.watcher")

IGNORE_EXTENSIONS = {".crdownload", ".part", ".tmp", ".swp"}


class InboxEventHandler(FileSystemEventHandler):
    def __init__(self, work_queue: queue.Queue):
        super().__init__()
        self.work_queue = work_queue

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._handle_event(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory and hasattr(event, "dest_path"):
            self._handle_event(Path(event.dest_path))

    def _handle_event(self, path: Path):
        name = path.name
        if name.startswith(".") or name.startswith("~"):
            return
        if path.suffix.lower() in IGNORE_EXTENSIONS:
            return
        logger.info(f"New file discovered in inbox: {path.name}")
        self.work_queue.put(path)


class InboxWatcher:
    def __init__(self, inbox_dir: Optional[Path] = None):
        self.inbox_dir = inbox_dir or self._get_initial_watch_dir()
        self.queue: queue.Queue = queue.Queue()
        self.observer: Optional[Observer] = None
        self.worker_thread: Optional[threading.Thread] = None
        self.running = False

    def _get_initial_watch_dir(self) -> Path:
        custom_file = settings.data_dir / "watch_folder.txt"
        if custom_file.is_file():
            try:
                saved = custom_file.read_text(encoding="utf-8").strip()
                if saved and Path(saved).is_dir():
                    logger.info(f"Loaded persistent watch folder: {saved}")
                    return Path(saved).resolve()
            except Exception:
                pass
        return settings.inbox_dir

    def _is_file_ready(self, path: Path) -> bool:
        if not path.is_file():
            return False

        # Wait until file size is stable for 2 seconds and can be opened for reading
        last_size = -1
        stable_checks = 0

        for _ in range(20):  # max 10 seconds wait
            if not path.is_file():
                return False
            try:
                current_size = path.stat().st_size
                if current_size == last_size and current_size > 0:
                    stable_checks += 1
                else:
                    stable_checks = 0
                    last_size = current_size

                if stable_checks >= 4:  # 4 * 0.5s = 2.0s stable
                    # Test opening for reading
                    with open(path, "rb") as f:
                        f.read(1024)
                    return True
            except (PermissionError, OSError):
                stable_checks = 0

            time.sleep(0.5)

        return False

    def _worker_loop(self):
        logger.info("Inbox watcher worker loop started.")
        while self.running:
            try:
                path: Path = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                if self._is_file_ready(path):
                    logger.info(f"Processing inbox item: {path.name}")
                    pipeline.process(path)
                else:
                    logger.warning(f"File {path.name} was not ready or disappeared before scan.")
            except Exception as e:
                logger.error(f"Error processing {path}: {e}", exc_info=True)
            finally:
                self.queue.task_done()

    def start(self):
        if self.running:
            return

        self.inbox_dir.mkdir(parents=True, exist_ok=True)
        self.running = True

        # Process any existing files in inbox first
        for item in self.inbox_dir.iterdir():
            if item.is_file() and item.suffix.lower() not in IGNORE_EXTENSIONS:
                if not item.name.startswith(".") and not item.name.startswith("~"):
                    self.queue.put(item)

        # Start single worker thread
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="WatcherWorker")
        self.worker_thread.start()

        # Start watchdog observer
        event_handler = InboxEventHandler(self.queue)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.inbox_dir), recursive=False)
        self.observer.start()
        logger.info(f"Watching inbox directory: {self.inbox_dir}")

    def stop(self):
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass
            self.observer = None

        if self.worker_thread:
            self.worker_thread.join(timeout=3)
            self.worker_thread = None
        logger.info("Inbox watcher stopped.")

    def set_watch_dir(self, new_dir: Path | str) -> Path:
        target = Path(new_dir).resolve()
        target.mkdir(parents=True, exist_ok=True)
        if not target.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {target}")

        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.observer = None

        self.inbox_dir = target

        # Persist custom watch directory to data/watch_folder.txt
        custom_file = settings.data_dir / "watch_folder.txt"
        try:
            if target.resolve() == settings.inbox_dir.resolve():
                if custom_file.exists():
                    custom_file.unlink()
            else:
                custom_file.parent.mkdir(parents=True, exist_ok=True)
                custom_file.write_text(str(target), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not persist watch_folder.txt: {e}")

        if self.running:
            # Enqueue any existing ready files in newly configured folder
            try:
                for item in self.inbox_dir.iterdir():
                    try:
                        if item.is_file() and item.suffix.lower() not in IGNORE_EXTENSIONS:
                            if not item.name.startswith(".") and not item.name.startswith("~"):
                                self.queue.put(item)
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError) as e:
                logger.warning(f"Could not enumerate existing files in {self.inbox_dir}: {e}")

            event_handler = InboxEventHandler(self.queue)
            self.observer = Observer()
            self.observer.schedule(event_handler, str(self.inbox_dir), recursive=False)
            self.observer.start()
            logger.info(f"Watch directory dynamically updated to: {self.inbox_dir}")
        return self.inbox_dir

    def reset_to_default(self) -> Path:
        custom_file = settings.data_dir / "watch_folder.txt"
        try:
            if custom_file.exists():
                custom_file.unlink()
        except Exception:
            pass
        return self.set_watch_dir(settings.inbox_dir)


# Global watcher instance
watcher = InboxWatcher()
