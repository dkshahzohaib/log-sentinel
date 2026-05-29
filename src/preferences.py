"""
Persistent user preferences. Stored as JSON in the user's home directory so
they survive across runs.

Keys:
  theme              "dark" | "light"
  snoozed_findings   {fingerprint: snooze_until_iso}
  ignored_findings   set of fingerprints (never re-show)
  resolved_findings  set of fingerprints (user marked as fixed)
  scan_schedule      {"enabled": bool, "interval_hours": int}
  threat_intel_url   optional override for threat-intel feed
  last_scan_path     path to last saved scan
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PREFS_DIR = Path.home() / ".log_sentinel"
PREFS_FILE = PREFS_DIR / "preferences.json"
SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@dataclass
class Preferences:
    theme: str = "dark"
    snoozed_findings: dict[str, str] = field(default_factory=dict)   # fp -> ISO
    ignored_findings: list[str] = field(default_factory=list)
    resolved_findings: list[str] = field(default_factory=list)
    pinned_findings: list[str] = field(default_factory=list)
    scan_schedule_enabled: bool = False
    scan_schedule_hours: int = 24
    minimize_to_tray: bool = False
    auto_open_report: bool = True
    low_priority_mode: str = "show"  # show | hide | later
    min_severity: str = "Info"       # Info | Low | Medium | High | Critical
    # Window state
    window_geometry: str = ""         # e.g. "1500x950+100+50"
    window_zoomed: bool = True
    last_tab_index: int = 0
    # Notification center
    seen_notifications: list[str] = field(default_factory=list)


_cache: Preferences | None = None


def _load() -> Preferences:
    global _cache
    if _cache is not None:
        return _cache
    if not PREFS_FILE.exists():
        _cache = Preferences()
        return _cache
    try:
        data = json.loads(PREFS_FILE.read_text(encoding="utf-8"))
        _cache = Preferences(
            theme=data.get("theme", "dark"),
            snoozed_findings=data.get("snoozed_findings", {}),
            ignored_findings=data.get("ignored_findings", []),
            resolved_findings=data.get("resolved_findings", []),
            pinned_findings=data.get("pinned_findings", []),
            scan_schedule_enabled=data.get("scan_schedule_enabled", False),
            scan_schedule_hours=data.get("scan_schedule_hours", 24),
            minimize_to_tray=data.get("minimize_to_tray", False),
            auto_open_report=data.get("auto_open_report", True),
            low_priority_mode=data.get("low_priority_mode", "show"),
            min_severity=data.get("min_severity", "Info"),
            window_geometry=data.get("window_geometry", ""),
            window_zoomed=data.get("window_zoomed", True),
            last_tab_index=data.get("last_tab_index", 0),
            seen_notifications=data.get("seen_notifications", []),
        )
    except (OSError, json.JSONDecodeError):
        _cache = Preferences()
    return _cache


def get() -> Preferences:
    return _load()


def save() -> None:
    p = _load()
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    PREFS_FILE.write_text(
        json.dumps(asdict(p), indent=2),
        encoding="utf-8",
    )


# ──────────────────────────────────────────────
# Finding fingerprinting (for snooze/ignore/resolve)
# ──────────────────────────────────────────────

def fingerprint(finding) -> str:
    """Stable hash so the same problem on the next scan is recognised."""
    key = f"{finding.rule}|{finding.title}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def is_snoozed(finding) -> bool:
    p = _load()
    fp = fingerprint(finding)
    until = p.snoozed_findings.get(fp)
    if not until:
        return False
    try:
        until_dt = datetime.fromisoformat(until)
    except ValueError:
        return False
    return datetime.now(timezone.utc) < until_dt


def is_ignored(finding) -> bool:
    p = _load()
    return fingerprint(finding) in p.ignored_findings


def is_resolved(finding) -> bool:
    p = _load()
    return fingerprint(finding) in p.resolved_findings


def snooze(finding, days: int = 7) -> None:
    p = _load()
    fp = fingerprint(finding)
    until = datetime.now(timezone.utc) + timedelta(days=days)
    p.snoozed_findings[fp] = until.isoformat()
    save()


def ignore(finding) -> None:
    p = _load()
    fp = fingerprint(finding)
    if fp not in p.ignored_findings:
        p.ignored_findings.append(fp)
    save()


def resolve(finding) -> None:
    p = _load()
    fp = fingerprint(finding)
    if fp not in p.resolved_findings:
        p.resolved_findings.append(fp)
    save()


def clear_state(finding) -> None:
    """Remove finding from all snooze / ignore / resolve lists."""
    p = _load()
    fp = fingerprint(finding)
    p.snoozed_findings.pop(fp, None)
    if fp in p.ignored_findings:
        p.ignored_findings.remove(fp)
    if fp in p.resolved_findings:
        p.resolved_findings.remove(fp)
    save()


def state_for(finding) -> str:
    """Returns 'active' | 'snoozed' | 'ignored' | 'resolved'."""
    if is_resolved(finding):
        return "resolved"
    if is_ignored(finding):
        return "ignored"
    if is_snoozed(finding):
        return "snoozed"
    return "active"


def is_pinned(finding) -> bool:
    return fingerprint(finding) in _load().pinned_findings


def pin(finding) -> None:
    p = _load()
    fp = fingerprint(finding)
    if fp not in p.pinned_findings:
        p.pinned_findings.append(fp)
        save()


def unpin(finding) -> None:
    p = _load()
    fp = fingerprint(finding)
    if fp in p.pinned_findings:
        p.pinned_findings.remove(fp)
        save()


def toggle_pin(finding) -> bool:
    if is_pinned(finding):
        unpin(finding)
        return False
    pin(finding)
    return True


def filter_active(findings: list) -> list:
    """Return findings that aren't snoozed, ignored, or resolved."""
    prefs = _load()
    mode = prefs.low_priority_mode
    min_rank = SEVERITY_ORDER.get(prefs.min_severity, 0)
    out = []
    for f in findings:
        if state_for(f) != "active":
            continue
        if SEVERITY_ORDER.get(getattr(f, "severity", ""), 0) < min_rank:
            continue
        if mode in ("hide", "later") and getattr(f, "severity", "") in ("Low", "Info"):
            continue
        out.append(f)
    return out


def low_priority_hidden_count(findings: list) -> int:
    """How many active findings are hidden by low-noise/sensitivity settings."""
    prefs = _load()
    mode = prefs.low_priority_mode
    min_rank = SEVERITY_ORDER.get(prefs.min_severity, 0)
    return sum(
        1 for f in findings
        if state_for(f) == "active"
        and (
            SEVERITY_ORDER.get(getattr(f, "severity", ""), 0) < min_rank
            or (mode in ("hide", "later") and getattr(f, "severity", "") in ("Low", "Info"))
        )
    )


def meets_min_severity(finding) -> bool:
    """True when a finding passes the global sensitivity threshold."""
    min_rank = SEVERITY_ORDER.get(_load().min_severity, 0)
    return SEVERITY_ORDER.get(getattr(finding, "severity", ""), 0) >= min_rank


def stats() -> dict:
    p = _load()
    # Drop expired snoozes
    now = datetime.now(timezone.utc)
    active_snoozed = sum(
        1 for v in p.snoozed_findings.values()
        if datetime.fromisoformat(v) > now
    )
    return {
        "snoozed":  active_snoozed,
        "ignored":  len(p.ignored_findings),
        "resolved": len(p.resolved_findings),
    }


def reset() -> None:
    """Clear all snooze / ignore / resolve state. (Settings panel button.)"""
    global _cache
    if _cache is None:
        return
    _cache.snoozed_findings = {}
    _cache.ignored_findings = []
    _cache.resolved_findings = []
    save()
