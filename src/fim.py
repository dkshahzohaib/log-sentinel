"""
File Integrity Monitoring (FIM).

Watch a list of important files. On every scan, compute SHA-256 + size +
mtime and compare to the recorded baseline. Anything that has changed
becomes a Finding so the user sees it.

Default watchlist focuses on high-value Windows targets — hosts file,
boot config, drivers folder summary, etc. Users can add their own paths
through the Settings UI.

Storage: ~/.log_sentinel/fim_baseline.json
        ~/.log_sentinel/fim_watchlist.json
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR
from .analyzer import Finding


WATCHLIST_FILE = PREFS_DIR / "fim_watchlist.json"
BASELINE_FILE  = PREFS_DIR / "fim_baseline.json"


@dataclass
class WatchedFile:
    path: str
    note: str = ""


@dataclass
class FileSnapshot:
    sha256: str
    size: int
    mtime: float
    captured_at: str


# ──────────────────────────────────────────────
# Defaults
# ──────────────────────────────────────────────

def _default_watchlist() -> list[WatchedFile]:
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return [
        WatchedFile(
            path=str(sysroot / "System32" / "drivers" / "etc" / "hosts"),
            note="Windows hosts file (DNS overrides — common malware target)",
        ),
        WatchedFile(
            path=str(sysroot / "System32" / "drivers" / "etc" / "services"),
            note="Windows services-port mapping",
        ),
    ]


# ──────────────────────────────────────────────
# Watchlist storage
# ──────────────────────────────────────────────

def load_watchlist() -> list[WatchedFile]:
    if not WATCHLIST_FILE.exists():
        save_watchlist(_default_watchlist())
        return _default_watchlist()
    try:
        data = json.loads(WATCHLIST_FILE.read_text(encoding="utf-8"))
        return [WatchedFile(**d) for d in data]
    except (OSError, json.JSONDecodeError, TypeError):
        return _default_watchlist()


def save_watchlist(items: list[WatchedFile]) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    WATCHLIST_FILE.write_text(
        json.dumps([asdict(i) for i in items], indent=2),
        encoding="utf-8",
    )


def add_path(path: str, note: str = "") -> tuple[bool, str]:
    p = Path(path).expanduser()
    if not p.exists():
        return False, f"Path does not exist: {p}"
    items = load_watchlist()
    if any(Path(i.path) == p for i in items):
        return False, "Already in watchlist."
    items.append(WatchedFile(path=str(p), note=note))
    save_watchlist(items)
    return True, f"Added {p} to FIM watchlist."


def remove_path(path: str) -> tuple[bool, str]:
    items = load_watchlist()
    new_items = [i for i in items if Path(i.path) != Path(path)]
    if len(new_items) == len(items):
        return False, "Path not in watchlist."
    save_watchlist(new_items)
    return True, "Removed."


# ──────────────────────────────────────────────
# Baseline / hashing
# ──────────────────────────────────────────────

def _hash_file(path: Path) -> str | None:
    """SHA-256 of the file content. Returns None on permission errors."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _snapshot(path: Path) -> FileSnapshot | None:
    try:
        if not path.exists():
            return None
        st = path.stat()
    except (OSError, PermissionError):
        return None
    sha = _hash_file(path) or ""
    return FileSnapshot(
        sha256=sha,
        size=st.st_size,
        mtime=st.st_mtime,
        captured_at=datetime.now().isoformat(),
    )


def _load_baseline() -> dict[str, dict]:
    if not BASELINE_FILE.exists():
        return {}
    try:
        return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_baseline(data: dict[str, dict]) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def reset_baseline() -> tuple[int, int]:
    """Re-snapshot every watched file, replacing the existing baseline.
    Returns (snapshotted, missing)."""
    items = load_watchlist()
    baseline: dict[str, dict] = {}
    miss = 0
    for item in items:
        snap = _snapshot(Path(item.path))
        if snap is None:
            miss += 1
            continue
        baseline[item.path] = asdict(snap)
    _save_baseline(baseline)
    return len(baseline), miss


def baseline_size() -> int:
    return len(_load_baseline())


# ──────────────────────────────────────────────
# Scan against baseline
# ──────────────────────────────────────────────

def scan() -> list[Finding]:
    """Hash every watched file, compare to baseline. If no baseline, snapshot."""
    items = load_watchlist()
    baseline = _load_baseline()
    findings: list[Finding] = []
    now = datetime.now()
    new_baseline = dict(baseline)
    changed_baseline = False

    for item in items:
        try:
            path = Path(item.path)
            snap = _snapshot(path)
        except (OSError, PermissionError):
            continue

        if snap is None:
            if item.path in baseline:
                findings.append(Finding(
                    rule="fim_missing",
                    severity="High",
                    title=f"Watched file is missing: {path.name}",
                    description=(
                        f"FIM watch path no longer exists or can't be read.\n"
                        f"Path: {item.path}\n"
                        f"Note: {item.note or '—'}"
                    ),
                    events=[],
                    timestamp=now,
                ))
            continue

        if item.path not in baseline:
            # First time we see it — capture baseline silently
            new_baseline[item.path] = asdict(snap)
            changed_baseline = True
            continue

        old = baseline[item.path]
        old_hash = old.get("sha256", "")
        old_size = old.get("size", 0)
        old_mtime = old.get("mtime", 0)

        diffs: list[str] = []
        if snap.sha256 and old_hash and snap.sha256 != old_hash:
            diffs.append(f"hash changed (was {old_hash[:12]}..., now {snap.sha256[:12]}...)")
        if snap.size != old_size:
            diffs.append(f"size {old_size} → {snap.size} bytes")
        if abs(snap.mtime - old_mtime) > 1:
            old_dt = datetime.fromtimestamp(old_mtime).strftime("%Y-%m-%d %H:%M")
            new_dt = datetime.fromtimestamp(snap.mtime).strftime("%Y-%m-%d %H:%M")
            diffs.append(f"modified {old_dt} → {new_dt}")

        if diffs:
            findings.append(Finding(
                rule="fim_modified",
                severity="High",
                title=f"Watched file changed: {path.name}",
                description=(
                    f"File integrity monitor detected changes:\n  • "
                    + "\n  • ".join(diffs)
                    + f"\n\nPath: {item.path}\n"
                    f"Note: {item.note or '—'}\n\n"
                    "If you didn't update Windows or install software around "
                    "this time, investigate. Use 'Reset baseline' if you "
                    "expected the change."
                ),
                events=[],
                timestamp=now,
            ))

    if changed_baseline:
        _save_baseline(new_baseline)
    return findings


def register_explanations() -> None:
    """Make the FIM rules show nice cards via plain_english."""
    from . import plain_english
    plain_english.EXPLANATIONS["fim_modified"] = plain_english.PlainEnglish(
        problem="A monitored file changed when you didn't expect.",
        why_matters=(
            "The hosts file, boot config, and similar are common targets "
            "for malware. If they change without you doing it, something "
            "else did."
        ),
        what_to_do=(
            "1. Check if you ran Windows Update around this time.\n"
            "2. Inspect the file — see what changed.\n"
            "3. If unexpected: run a full antivirus scan.\n"
            "4. If you DID make the change, click 'Reset baseline' in Settings."
        ),
        user_category="Security",
    )
    plain_english.EXPLANATIONS["fim_missing"] = plain_english.PlainEnglish(
        problem="A monitored file disappeared.",
        why_matters="A file we expected to be there is gone — could be malicious deletion or a normal uninstall.",
        what_to_do="Check whether you uninstalled something. If not, restore from backup.",
        user_category="Security",
    )
