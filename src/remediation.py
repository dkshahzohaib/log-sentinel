"""
One-click "Fix it" actions for findings.

Each action is reversible-ish and clearly described. We never:
  - Delete files automatically
  - Modify Windows settings without confirmation
  - Touch user data

What we DO:
  - End a process (Task Manager-style)
  - Disable a registry autorun (we only RENAME the value, easy to undo)
  - Disable a scheduled task (not delete)
  - Open Windows-built-in tools focused at the right place
  - Copy useful info (commands, IPs) to clipboard
  - Open the relevant Microsoft / VirusTotal page in browser
"""

from __future__ import annotations

import platform
import subprocess
import webbrowser
import winreg
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class Action:
    label: str                       # button text e.g. "End this process"
    description: str                 # tooltip / confirmation text
    danger: str                      # "safe" | "moderate" | "destructive"
    requires_admin: bool = False
    run: Optional[Callable[[], tuple[bool, str]]] = None


def _run(cmd: list[str], timeout: int = 15) -> tuple[bool, str]:
    """Run a command, return (success, stdout-or-stderr)."""
    try:
        flags = 0x08000000 if platform.system() == "Windows" else 0
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        ok = result.returncode == 0
        msg = result.stdout if ok else (result.stderr or result.stdout)
        return ok, msg.strip()
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except OSError as e:
        return False, str(e)


# ──────────────────────────────────────────────
# Actions
# ──────────────────────────────────────────────

def end_process(pid: int) -> tuple[bool, str]:
    if pid <= 4:
        return False, "Refusing to kill PID <= 4 (system process)."
    return _run(["taskkill", "/F", "/PID", str(pid)])


def end_process_by_name(name: str) -> tuple[bool, str]:
    return _run(["taskkill", "/F", "/IM", name])


def disable_autorun(hive_name: str, subkey: str, value_name: str) -> tuple[bool, str]:
    """
    'Disable' an autorun by renaming its registry value to '<name>.disabled'.
    Reversible — user can rename it back manually if needed.
    """
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }
    hive = hive_map.get(hive_name)
    if hive is None:
        return False, f"Unknown registry hive: {hive_name}"

    # subkey may include hive prefix; strip it
    if subkey.upper().startswith(("HKLM\\", "HKCU\\")):
        subkey = subkey.split("\\", 1)[1]

    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            try:
                value, vtype = winreg.QueryValueEx(key, value_name)
            except FileNotFoundError:
                return False, f"Autorun '{value_name}' not found (may already be removed)."
            new_name = f"{value_name}.disabled"
            winreg.SetValueEx(key, new_name, 0, vtype, value)
            winreg.DeleteValue(key, value_name)
        from . import change_log
        change_log.record(
            "registry.disable_autorun",
            f"{hive_name}\\{subkey}\\{value_name}",
            True,
            f"Renamed value to {new_name}.",
            undo_hint=f"Rename '{new_name}' back to '{value_name}' in {hive_name}\\{subkey}.",
        )
        return True, (
            f"Disabled '{value_name}' in {hive_name}\\{subkey}.\n"
            f"To re-enable, rename '{new_name}' back to '{value_name}'."
        )
    except PermissionError:
        return False, "Access denied — run Log Sentinel as Administrator to fix this."
    except OSError as e:
        return False, str(e)


def disable_scheduled_task(task_name: str) -> tuple[bool, str]:
    ok, msg = _run(["schtasks", "/Change", "/TN", task_name, "/Disable"])
    from . import change_log
    change_log.record(
        "scheduled_task.disable",
        task_name,
        ok,
        msg,
        undo_hint=f"Run: schtasks /Change /TN \"{task_name}\" /Enable",
    )
    return ok, msg


def stop_service(service_name: str) -> tuple[bool, str]:
    ok, msg = _run(["sc", "stop", service_name])
    from . import change_log
    change_log.record(
        "service.stop",
        service_name,
        ok,
        msg,
        undo_hint=f"Run: sc start \"{service_name}\"",
    )
    return ok, msg


def block_ip_in_firewall(ip: str, rule_name: str = "") -> tuple[bool, str]:
    rule_name = rule_name or f"LogSentinel_Block_{ip}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=out", "action=block",
        f"remoteip={ip}",
    ]
    ok, msg = _run(cmd)
    if ok:
        from . import change_log
        change_log.record(
            "firewall.block_ip",
            ip,
            True,
            f"Created firewall rule {rule_name}.",
            undo_hint=f"Delete firewall rule '{rule_name}'.",
        )
        return True, f"Outbound traffic to {ip} now blocked (rule: {rule_name})."
    from . import change_log
    change_log.record("firewall.block_ip", ip, False, msg)
    return False, msg


def open_task_manager() -> tuple[bool, str]:
    try:
        subprocess.Popen(["taskmgr"])
        return True, "Task Manager opened."
    except OSError as e:
        return False, str(e)


def open_services() -> tuple[bool, str]:
    try:
        subprocess.Popen(["services.msc"], shell=True)
        return True, "Services opened."
    except OSError as e:
        return False, str(e)


def open_settings_panel(panel: str) -> tuple[bool, str]:
    """Opens a Windows Settings deep-link, e.g. 'ms-settings:privacy-camera'."""
    try:
        subprocess.Popen(["start", panel], shell=True)
        return True, f"Opened {panel}."
    except OSError as e:
        return False, str(e)


def open_url(url: str) -> tuple[bool, str]:
    try:
        webbrowser.open(url)
        return True, f"Opened {url}."
    except Exception as e:
        return False, str(e)


def lookup_on_virustotal(indicator: str) -> tuple[bool, str]:
    return open_url(f"https://www.virustotal.com/gui/search/{indicator}")


def lookup_on_abuseipdb(ip: str) -> tuple[bool, str]:
    return open_url(f"https://www.abuseipdb.com/check/{ip}")


def run_defender_full_scan() -> tuple[bool, str]:
    return _run([
        "powershell", "-NoProfile", "-Command",
        "Start-MpScan -ScanType FullScan",
    ], timeout=10)


def run_defender_quick_scan() -> tuple[bool, str]:
    return _run([
        "powershell", "-NoProfile", "-Command",
        "Start-MpScan -ScanType QuickScan",
    ], timeout=10)


def run_sfc_scannow() -> tuple[bool, str]:
    """Repair Windows system files. Long-running."""
    try:
        subprocess.Popen(["cmd", "/k", "sfc /scannow"], shell=True)
        return True, "Started 'sfc /scannow' in a new console window."
    except OSError as e:
        return False, str(e)


# ──────────────────────────────────────────────
# Action builder — build a list of actions for a finding
# ──────────────────────────────────────────────

def actions_for_finding(finding) -> list[Action]:
    """Return a list of suggested actions for a Finding."""
    rule = finding.rule
    actions: list[Action] = []

    # Process-related
    if rule in ("suspicious_process", "suspicious_process_critical",
                "process_in_temp", "process_name_spoof", "ioc_match_process",
                "remote_access_tool"):
        actions.append(Action(
            label="🛑  Open Task Manager",
            description="See running processes and end them manually.",
            danger="safe",
            run=open_task_manager,
        ))
        actions.append(Action(
            label="🩺  Run Defender Quick Scan",
            description="Start a Microsoft Defender quick scan.",
            danger="safe",
            run=run_defender_quick_scan,
        ))

    # Network/IP related
    if rule in ("ioc_match_ip", "external_connection",
                "suspicious_listening_port", "uncommon_listening_port",
                "brute_force_from_ip"):
        # Try to extract IP from description
        import re
        ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", finding.description)
        if ips:
            ip = ips[0]
            # Use the new firewall manager (pre-validates, dangerous-block check, etc.)
            from .firewall_manager import (
                quick_block_ip, add_rule, is_admin, is_dangerous_block,
            )
            def _block(i=ip):
                if not is_admin():
                    return False, ("Adding firewall rules needs Admin. "
                                   "Re-launch via LAUNCH-as-admin.bat.")
                rule = quick_block_ip(i, port="any", direction="out")
                warn = is_dangerous_block(rule)
                if warn:
                    return False, warn
                return add_rule(rule)
            actions.append(Action(
                label=f"🚫  Block {ip} (outbound)",
                description=(
                    f"Add a Windows Firewall outbound BLOCK rule for {ip}. "
                    "Reversible — you can delete it from the Firewall tab."
                ),
                danger="moderate",
                requires_admin=True,
                run=_block,
            ))
            actions.append(Action(
                label=f"🔍  Look up {ip} on AbuseIPDB",
                description="Open the abuseipdb.com page in your browser.",
                danger="safe",
                run=lambda i=ip: lookup_on_abuseipdb(i),
            ))

    # Service-related
    if rule == "new_service_installed":
        actions.append(Action(
            label="🛠  Open Services",
            description="Stop or disable the service in services.msc.",
            danger="safe",
            run=open_services,
        ))

    # Autorun-related
    if rule == "suspicious_autorun":
        actions.append(Action(
            label="📋  Open Startup Apps",
            description="Disable startup items (Task Manager → Startup).",
            danger="safe",
            run=open_task_manager,
        ))

    # Privacy
    if rule == "webcam_or_mic_access":
        actions.append(Action(
            label="📷  Camera privacy settings",
            description="Open Windows camera permission settings.",
            danger="safe",
            run=lambda: open_settings_panel("ms-settings:privacy-webcam"),
        ))
        actions.append(Action(
            label="🎙  Microphone privacy settings",
            description="Open Windows microphone permission settings.",
            danger="safe",
            run=lambda: open_settings_panel("ms-settings:privacy-microphone"),
        ))

    # Performance
    if rule in ("slow_startup_program", "high_memory_process"):
        actions.append(Action(
            label="📋  Open Task Manager",
            description="Disable startup items or end heavy processes.",
            danger="safe",
            run=open_task_manager,
        ))

    # Crash / stability
    if rule in ("system_crash", "recently_modified_critical"):
        actions.append(Action(
            label="🩹  Run sfc /scannow",
            description=(
                "Run Windows' built-in system-file repair. "
                "Opens a new admin console."
            ),
            danger="safe",
            requires_admin=True,
            run=run_sfc_scannow,
        ))

    # ── Always-available default actions ──────
    actions.append(Action(
        label="🛡  Run Defender Full Scan",
        description="Comprehensive antivirus scan. Takes 30–60 minutes.",
        danger="safe",
        run=run_defender_full_scan,
    ))

    return actions
