import logging
import signal
import sys
import time
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel

from engine.clamav_manager import get_clamav_status, start_clamav_daemon, stop_clamav_daemon
from engine.config import settings
from engine.pipeline import pipeline
from engine.watcher import watcher

# Configure Rich logger
logging.basicConfig(
    level=logging.INFO,
    format="%(message)",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
)
logger = logging.getLogger("scanner")
console = Console()


def log_pipeline_event(event: dict):
    etype = event.get("type")
    if etype == "scan_started":
        console.print(
            f"[bold cyan]Scan Started[/bold cyan]: {event.get('filename')} (ID: {event.get('scan_id')}, SHA256: {event.get('sha256')[:12]}...)"
        )
    elif etype == "check_done":
        status = event.get("status")
        color = "green" if status == "pass" else ("yellow" if status == "warn" else ("red" if status == "fail" else "blue"))
        console.print(
            f"  [dim]->[/dim] [bold]{event.get('checker')}[/bold]: [{color}]{status.upper()}[/{color}] (score: {event.get('score')})"
        )
    elif etype == "scan_finished":
        verdict = event.get("verdict")
        color = "green" if verdict == "pass" else ("yellow" if verdict == "review" else "red")
        console.print(
            f"[bold {color}]Verdict: {verdict.upper()}[/bold {color}] | Final Score: {event.get('score')} | Destination: {event.get('destination')}\n"
        )


def main():
    banner = f"""
[bold green]Malware Scanner Engine[/bold green]
Inbox:        {settings.inbox_dir}
Clean:        {settings.clean_dir}
Review:       {settings.review_dir}
Quarantine:   {settings.quarantine_dir}
Sigcheck:     {settings.sigcheck_path}
    """
    console.print(Panel(banner.strip(), title="System Initialized", border_style="cyan"))

    # Register rich event listener
    pipeline.register_callback(log_pipeline_event)

    # Automated ClamAV daemon start (no visible window)
    if settings.clamav.auto_start:
        console.print("[dim]Checking / starting ClamAV daemon...[/dim]")
        start_clamav_daemon(wait_ready=True, timeout=20)
        c_status = get_clamav_status()
        console.print(f"ClamAV: [bold]{c_status['status']}[/bold] - {c_status['message']}")

    # Start inbox watcher
    watcher.start()
    console.print("[bold green]Scanner watcher active.[/bold green] Drop files into inbox to begin scanning. Press Ctrl+C to stop.")

    def signal_handler(sig, frame):
        console.print("\n[yellow]Shutting down scanner engine...[/yellow]")
        watcher.stop()
        stop_clamav_daemon()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
