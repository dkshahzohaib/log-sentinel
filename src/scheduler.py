"""
Schedule recurring scans via Windows Task Scheduler.

Idea: register a scheduled task that runs `LogSentinel.exe --scan` (or
`python app.py --scan`) at the chosen interval. Headless mode collects,
analyses, saves to scan history, exits — and writes a small alert file
if any Critical/High finding shows up.

The actual app, when next opened, can read the alert file and surface it.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR


TASK_NAME = "LogSentinelScheduledScan"
ALERT_FILE = PREFS_DIR / "scheduled_alert.json"


@dataclass
class ScheduledTaskInfo:
    registered: bool = False
    interval_hours: int = 0
    next_run: str = ""
    last_run: str = ""
    last_result: str = ""


def _run(cmd: list[str], timeout: int = 15) -> tuple[bool, str]:
    flags = 0x08000000 if platform.system() == "Windows" else 0
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        ok = result.returncode == 0
        msg = (result.stdout if ok else (result.stderr or result.stdout)).strip()
        return ok, msg
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def get_executable_path() -> str:
    """
    Returns the command Task Scheduler should run.

    - When running from a frozen .exe (PyInstaller): use sys.executable
    - When running from `python app.py`: use 'python "<absolute app.py>"'
    """
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --scan'
    # Find the project root by walking up from this file
    repo_root = Path(__file__).resolve().parent.parent
    py = sys.executable
    return f'"{py}" "{repo_root / "app.py"}" --scan'


def register(interval_hours: int = 24) -> tuple[bool, str]:
    """Create / replace a scheduled task."""
    if interval_hours < 1 or interval_hours > 24 * 7:
        return False, "interval_hours must be between 1 and 168 (7 days)"

    cmd_line = get_executable_path()

    # /SC DAILY with /RI for sub-day intervals; for >=24h we use DAILY /MO
    if interval_hours < 24:
        cmd = [
            "schtasks", "/Create", "/F",
            "/TN", TASK_NAME,
            "/TR", cmd_line,
            "/SC", "HOURLY",
            "/MO", str(interval_hours),
            "/RL", "LIMITED",
        ]
    else:
        cmd = [
            "schtasks", "/Create", "/F",
            "/TN", TASK_NAME,
            "/TR", cmd_line,
            "/SC", "DAILY",
            "/MO", str(interval_hours // 24),
            "/RL", "LIMITED",
        ]

    ok, msg = _run(cmd)
    if not ok:
        return False, f"Couldn't create task: {msg}"
    return True, f"Scheduled scan registered to run every {interval_hours} hours."


def unregister() -> tuple[bool, str]:
    ok, msg = _run(["schtasks", "/Delete", "/F", "/TN", TASK_NAME])
    if not ok and "cannot find" in msg.lower():
        return True, "No task to remove."
    return ok, msg or "Removed."


def is_registered() -> bool:
    ok, _ = _run(["schtasks", "/Query", "/TN", TASK_NAME])
    return ok


def info() -> ScheduledTaskInfo:
    if not is_registered():
        return ScheduledTaskInfo(registered=False)
    ok, out = _run(["schtasks", "/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST"])
    info = ScheduledTaskInfo(registered=True)
    if not ok:
        return info
    for raw in out.splitlines():
        line = raw.strip()
        if line.startswith("Next Run Time:"):
            info.next_run = line.split(":", 1)[1].strip()
        elif line.startswith("Last Run Time:"):
            info.last_run = line.split(":", 1)[1].strip()
        elif line.startswith("Last Result:"):
            info.last_result = line.split(":", 1)[1].strip()
    return info


def run_now() -> tuple[bool, str]:
    return _run(["schtasks", "/Run", "/TN", TASK_NAME])


# ──────────────────────────────────────────────
# Alert file (written by headless scan, read by GUI)
# ──────────────────────────────────────────────

def write_alert(critical: int, high: int, total: int, score: int) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    ALERT_FILE.write_text(
        json.dumps({
            "timestamp": datetime.now().isoformat(),
            "critical": critical,
            "high": high,
            "total_findings": total,
            "score": score,
        }, indent=2),
        encoding="utf-8",
    )


def read_alert() -> dict | None:
    if not ALERT_FILE.exists():
        return None
    try:
        return json.loads(ALERT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def clear_alert() -> None:
    if ALERT_FILE.exists():
        try:
            ALERT_FILE.unlink()
        except OSError:
            pass
