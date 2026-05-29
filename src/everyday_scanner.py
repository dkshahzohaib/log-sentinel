"""
Scans aimed at everyday-user concerns:

  - Slow startup programs
  - Memory hogs
  - Apps with webcam/mic access
  - Recently modified Windows system files
  - Browser extensions (best-effort detection)

These are what a non-technical user actually wants to see.
"""

from __future__ import annotations

import os
import winreg
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .analyzer import Finding


# ──────────────────────────────────────────────
# Startup / boot-impact analysis
# ──────────────────────────────────────────────

STARTUP_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM-32"),
]


def scan_startup_impact() -> list[Finding]:
    """Flag autoruns that aren't well-known — they may be slowing boot."""
    KNOWN_GOOD = {
        "onedrive", "microsoft", "windows security", "defender",
        "intel", "nvidia", "amd", "realtek",
        "sectray", "rtkaudu", "igfxtray", "synaptics", "elan",
    }
    findings: list[Finding] = []
    now = datetime.utcnow()

    for hive, subkey, label in STARTUP_KEYS:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    name_l = name.lower()
                    if any(k in name_l for k in KNOWN_GOOD):
                        continue
                    findings.append(Finding(
                        rule="slow_startup_program",
                        severity="Low",
                        title=f"Auto-starts at boot: {name}",
                        description=(
                            f"'{name}' runs every time you start your computer.\n"
                            f"Source: {label}\\Run\n"
                            f"Command: {value}\n"
                            "Disable in Task Manager → Startup if you don't need it."
                        ),
                        events=[],
                        timestamp=now,
                    ))
        except OSError:
            continue
    return findings


# ──────────────────────────────────────────────
# Memory hogs
# ──────────────────────────────────────────────

MB = 1024  # tasklist returns KB

def scan_memory_hogs(processes: list, threshold_mb: int = 500) -> list[Finding]:
    """Flag processes using more than threshold_mb of RAM."""
    findings: list[Finding] = []
    now = datetime.utcnow()

    KNOWN_HEAVY = {
        "chrome.exe", "firefox.exe", "msedge.exe", "code.exe",
        "studio64.exe", "idea64.exe", "pycharm64.exe",
        "outlook.exe", "winword.exe", "excel.exe",
        "photoshop.exe", "illustrator.exe", "premiere pro.exe",
        "obs64.exe", "spotify.exe", "discord.exe",
        "slack.exe", "teams.exe", "msmpeng.exe",
    }

    for p in processes:
        if p.memory_kb < threshold_mb * MB:
            continue
        if p.name.lower() in KNOWN_HEAVY:
            continue
        if p.name.lower() in {"system", "memory compression"}:
            continue

        mb_used = p.memory_kb / MB
        findings.append(Finding(
            rule="high_memory_process",
            severity="Low",
            title=f"Using a lot of RAM: {p.name} ({mb_used:.0f} MB)",
            description=(
                f"PID {p.pid} ({p.name}) is using {mb_used:.0f} MB of RAM.\n"
                f"Path: {p.path or '—'}\n"
                "If you don't recognise this program, end it in Task Manager."
            ),
            events=[],
            timestamp=now,
        ))
    return findings


# ──────────────────────────────────────────────
# Webcam / microphone access
# ──────────────────────────────────────────────

PRIVACY_BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"


def scan_camera_mic_users() -> list[Finding]:
    """
    Find apps that have used the camera/mic recently.
    Windows logs LastUsedTimeStart for each app under the privacy registry.
    """
    findings: list[Finding] = []
    now = datetime.utcnow()

    for device, label in [("webcam", "camera"), ("microphone", "microphone")]:
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, f"{PRIVACY_BASE}\\{device}\\NonPackaged") as root:
                    i = 0
                    while True:
                        try:
                            sk = winreg.EnumKey(root, i)
                        except OSError:
                            break
                        i += 1
                        try:
                            with winreg.OpenKey(root, sk) as k:
                                try:
                                    last_used, _ = winreg.QueryValueEx(k, "LastUsedTimeStop")
                                except OSError:
                                    last_used = 0
                                # last_used is FILETIME (100ns since 1601). Convert.
                                if last_used:
                                    secs = (last_used - 116444736000000000) // 10000000
                                    used_at = datetime.utcfromtimestamp(secs)
                                else:
                                    used_at = None

                                # Path is the registry key name, with # as path separator
                                app_path = sk.replace("#", "\\")
                                app_name = app_path.split("\\")[-1]

                                # Only flag if used in the last 30 days
                                if used_at and (now - used_at) > timedelta(days=30):
                                    continue
                                if app_name.lower() in {"zoom.exe", "teams.exe", "skype.exe",
                                                        "discord.exe", "obs64.exe",
                                                        "msteams.exe", "chrome.exe",
                                                        "firefox.exe", "msedge.exe"}:
                                    continue
                                findings.append(Finding(
                                    rule="webcam_or_mic_access",
                                    severity="Low",
                                    title=f"App has {label} access: {app_name}",
                                    description=(
                                        f"App '{app_name}' has used the {label} "
                                        f"({'last seen ' + used_at.strftime('%Y-%m-%d') if used_at else 'recently'}).\n"
                                        f"Path: {app_path}\n"
                                        f"Review in Settings → Privacy & security → "
                                        f"{label.capitalize()}."
                                    ),
                                    events=[],
                                    timestamp=now,
                                ))
                        except OSError:
                            continue
            except OSError:
                continue
    return findings


# ──────────────────────────────────────────────
# Recently modified system files
# ──────────────────────────────────────────────

CRITICAL_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]


def scan_recently_modified_system(hours: int = 48, max_results: int = 8) -> list[Finding]:
    """
    Look for system files modified in the last N hours.
    Some are normal (Windows Update); we cap at max_results to keep noise down.
    """
    findings: list[Finding] = []
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=hours)

    found_files: list[tuple[Path, datetime]] = []
    for d in CRITICAL_DIRS:
        p = Path(d)
        if not p.exists():
            continue
        try:
            for f in p.iterdir():
                try:
                    if not f.is_file():
                        continue
                    mtime = datetime.utcfromtimestamp(f.stat().st_mtime)
                    if mtime > cutoff:
                        found_files.append((f, mtime))
                except OSError:
                    continue
        except (PermissionError, OSError):
            continue

    found_files.sort(key=lambda x: x[1], reverse=True)
    for f, mtime in found_files[:max_results]:
        findings.append(Finding(
            rule="recently_modified_critical",
            severity="Low",
            title=f"Recently modified system file: {f.name}",
            description=(
                f"File: {f}\n"
                f"Modified: {mtime.strftime('%Y-%m-%d %H:%M UTC')}\n"
                "If you didn't run Windows Update around then, this is unusual."
            ),
            events=[],
            timestamp=mtime,
        ))
    return findings


# ──────────────────────────────────────────────
# Browser extensions (best-effort)
# ──────────────────────────────────────────────

def scan_browser_extensions() -> list[Finding]:
    """
    List browser extensions for Chrome / Edge / Brave.
    Each extension is a finding so the user can review them.
    We don't flag good vs bad — we just expose them.
    """
    findings: list[Finding] = []
    now = datetime.utcnow()

    appdata = os.environ.get("LOCALAPPDATA", "")
    if not appdata:
        return findings

    browsers = {
        "Chrome":  Path(appdata) / "Google" / "Chrome" / "User Data",
        "Edge":    Path(appdata) / "Microsoft" / "Edge" / "User Data",
        "Brave":   Path(appdata) / "BraveSoftware" / "Brave-Browser" / "User Data",
    }

    for browser, base in browsers.items():
        if not base.exists():
            continue
        # Default + Profile * folders
        for profile_dir in base.glob("*"):
            ext_dir = profile_dir / "Extensions"
            if not ext_dir.exists():
                continue
            try:
                for ext in ext_dir.iterdir():
                    if not ext.is_dir():
                        continue
                    # Read manifest
                    versions = list(ext.iterdir())
                    if not versions:
                        continue
                    latest = max(versions, key=lambda p: p.stat().st_mtime)
                    manifest = latest / "manifest.json"
                    name = ext.name
                    if manifest.exists():
                        try:
                            import json
                            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                            name = data.get("name", ext.name)
                            # Resolve __MSG_xxx__ names by reading _locales/<locale>/messages.json
                            if name.startswith("__MSG_"):
                                msg_key = name[6:-2]
                                for loc in ("en", "en_US"):
                                    msgs = latest / "_locales" / loc / "messages.json"
                                    if msgs.exists():
                                        try:
                                            mdata = json.loads(msgs.read_text(encoding="utf-8", errors="ignore"))
                                            name = mdata.get(msg_key, {}).get("message", ext.name)
                                            break
                                        except Exception:
                                            pass
                        except Exception:
                            pass
                    findings.append(Finding(
                        rule="browser_extension_suspicious",
                        severity="Info",
                        title=f"{browser} extension: {name}",
                        description=(
                            f"Browser: {browser}\n"
                            f"ID: {ext.name}\n"
                            f"Profile: {profile_dir.name}\n"
                            "Extensions can read everything you do online. "
                            "Open your browser's Extensions page and remove any you don't recognise."
                        ),
                        events=[],
                        timestamp=now,
                    ))
            except (OSError, PermissionError):
                continue
    return findings


# ──────────────────────────────────────────────
# Combined entry point
# ──────────────────────────────────────────────

def scan_everyday(processes: list) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_startup_impact())
    findings.extend(scan_memory_hogs(processes))
    findings.extend(scan_camera_mic_users())
    findings.extend(scan_recently_modified_system())
    findings.extend(scan_browser_extensions())
    return findings
