"""
🚨 PANIC BUTTON — Device Isolation Mode

One click → cuts ALL network traffic on this PC. The killer feature for
ransomware response: when something nasty is happening, isolation
immediately stops data exfiltration, lateral movement, and command-and-control.

How it works:
  1. Lists every enabled network adapter via netsh
  2. Saves their names to a state file (so we can restore exactly the same set)
  3. Disables each one (netsh interface set interface ... admin=disable)

Restore is the inverse: read the state file, re-enable each saved adapter.
Requires Administrator.
"""

from __future__ import annotations

import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR


PANIC_STATE_FILE = PREFS_DIR / "panic_state.json"


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


def list_adapters() -> list[dict]:
    """Returns list of {name, admin_state, type, connect_state}."""
    if platform.system() != "Windows":
        return []
    ok, out = _run(["netsh", "interface", "show", "interface"])
    if not ok:
        return []
    adapters: list[dict] = []
    for raw in out.splitlines():
        line = raw.rstrip()
        if not line or line.startswith(("Admin", "----")):
            continue
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        admin, conn, ifc_type, name = parts
        adapters.append({
            "name": name,
            "admin_state": admin,
            "type": ifc_type,
            "connect_state": conn,
        })
    return adapters


def is_isolated() -> bool:
    """Quick check: state file exists AND there are saved adapters."""
    if not PANIC_STATE_FILE.exists():
        return False
    try:
        data = json.loads(PANIC_STATE_FILE.read_text(encoding="utf-8"))
        return bool(data.get("disabled_adapters"))
    except (OSError, json.JSONDecodeError):
        return False


def isolate(reason: str = "") -> tuple[bool, str]:
    """Disable every currently-enabled adapter. Returns (ok, message)."""
    if platform.system() != "Windows":
        return False, "Panic mode only works on Windows."
    if is_isolated():
        return False, "Already isolated. Use Restore to reconnect."

    adapters = list_adapters()
    enabled = [a for a in adapters if a["admin_state"].lower() == "enabled"]
    if not enabled:
        return False, "No enabled network adapters found."

    succeeded: list[str] = []
    failed: list[tuple[str, str]] = []

    for a in enabled:
        ok, msg = _run([
            "netsh", "interface", "set", "interface",
            f"name={a['name']}",
            "admin=disable",
        ])
        if ok:
            succeeded.append(a["name"])
        else:
            failed.append((a["name"], msg))

    if not succeeded:
        return False, ("Could not disable any adapter. "
                       "Run as Administrator. "
                       + (f"First error: {failed[0][1]}" if failed else ""))

    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    PANIC_STATE_FILE.write_text(
        json.dumps({
            "disabled_adapters": succeeded,
            "isolated_at": datetime.now().isoformat(),
            "reason": reason,
        }, indent=2),
        encoding="utf-8",
    )

    msg = f"Disabled {len(succeeded)} network adapter(s): {', '.join(succeeded)}."
    if failed:
        msg += f"\nFailed: {len(failed)} ({', '.join(n for n,_ in failed)})."
    return True, msg


def restore() -> tuple[bool, str]:
    """Re-enable adapters that were disabled by isolate()."""
    if not PANIC_STATE_FILE.exists():
        return False, "No isolation state to restore."

    try:
        data = json.loads(PANIC_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return False, f"Cannot read state: {e}"

    saved = data.get("disabled_adapters", [])
    if not saved:
        PANIC_STATE_FILE.unlink()
        return False, "No adapters were saved."

    succeeded = []
    failed: list[tuple[str, str]] = []
    for name in saved:
        ok, msg = _run([
            "netsh", "interface", "set", "interface",
            f"name={name}",
            "admin=enable",
        ])
        if ok:
            succeeded.append(name)
        else:
            failed.append((name, msg))

    if succeeded and not failed:
        try:
            PANIC_STATE_FILE.unlink()
        except OSError:
            pass

    msg = f"Re-enabled {len(succeeded)} adapter(s)."
    if failed:
        msg += f"\nFailed: {len(failed)} ({', '.join(n for n,_ in failed)})."
    return bool(succeeded), msg


def isolation_info() -> dict | None:
    """Return state dict if isolated, else None."""
    if not is_isolated():
        return None
    try:
        return json.loads(PANIC_STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
