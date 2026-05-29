"""
Rules that operate on system_collector snapshots (processes, connections,
autoruns, etc.) rather than Event Log events.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .analyzer import Finding
from .system_collector import (
    AutorunEntry, NetConnection, Process,
    ScheduledTask, Service, UsbDevice,
)


# ──────────────────────────────────────────────
# Knowledge base
# ──────────────────────────────────────────────

# Ports commonly used by malware / RATs / backdoors
SUSPICIOUS_PORTS = {
    1337: "Common backdoor",
    4444: "Metasploit default",
    4445: "Metasploit alt",
    5555: "Common backdoor",
    6666: "IRC botnet",
    6667: "IRC botnet",
    7777: "Common backdoor",
    8888: "Common backdoor",
    9999: "Common backdoor",
    12345: "NetBus",
    31337: "Back Orifice",
    65535: "Suspicious",
}

# Legitimate listening ports (don't flag these)
COMMON_LEGIT_PORTS = {
    80, 443, 22, 21, 25, 53, 110, 143, 465, 587, 993, 995,
    135, 139, 445, 3389, 5040, 5985, 5986, 49664, 49665, 49666,
    49667, 49668, 49669, 49670,
    137, 138, 1900, 5353, 5355, 5357, 5358,
    8080, 8443, 3000, 3001, 5000, 8000, 8888,
}

# Process name → expected legitimate path fragment(s) (lowercase).
# Anything outside these paths is suspicious (impersonation).
SYSTEM_PROCESSES: dict[str, tuple[str, ...]] = {
    "svchost.exe":     ("\\windows\\system32\\", "\\windows\\syswow64\\"),
    "lsass.exe":       ("\\windows\\system32\\",),
    "winlogon.exe":    ("\\windows\\system32\\",),
    "csrss.exe":       ("\\windows\\system32\\",),
    "services.exe":    ("\\windows\\system32\\",),
    "smss.exe":        ("\\windows\\system32\\",),
    "wininit.exe":     ("\\windows\\system32\\",),
    "spoolsv.exe":     ("\\windows\\system32\\",),
    "explorer.exe":    ("\\windows\\",),  # lives directly in C:\Windows
    "taskhostw.exe":   ("\\windows\\system32\\",),
    "dwm.exe":         ("\\windows\\system32\\",),
}

# Known remote access / RAT-style processes
REMOTE_ACCESS_TOOLS = {
    "teamviewer.exe", "anydesk.exe", "vncviewer.exe", "vnc.exe",
    "logmein.exe", "ammyy.exe", "rustdesk.exe", "supremo.exe",
    "screenconnect.exe", "splashtop.exe",
}

# Suspicious autorun command keywords
SUSPICIOUS_AUTORUN_KEYWORDS = [
    "powershell", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "certutil", "bitsadmin", "-enc",
    r"\temp\\", r"\appdata\\", r"\public\\",
]

# Locations that legitimate processes shouldn't run from
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\appdata\\local\\temp\\", "\\users\\public\\",
    "\\windows\\temp\\", "\\downloads\\",
    "\\$recycle.bin\\",
]


# ──────────────────────────────────────────────
# Process rules
# ──────────────────────────────────────────────

def analyze_processes(processes: list[Process]) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for p in processes:
        path_l = p.path.lower()
        name_l = p.name.lower()

        # Process running from suspicious location
        if path_l and any(s in path_l for s in SUSPICIOUS_PATHS):
            findings.append(Finding(
                rule="process_in_temp",
                severity="High",
                title=f"Process running from suspicious location: {p.name}",
                description=(
                    f"PID {p.pid} ({p.name}) is running from {p.path}. "
                    "Legitimate software is rarely installed in Temp/AppData/Public."
                ),
                events=[],
                timestamp=now,
            ))

        # System process running from non-system location (impersonation)
        if name_l in SYSTEM_PROCESSES and path_l:
            allowed = SYSTEM_PROCESSES[name_l]
            if not any(a in path_l for a in allowed):
                findings.append(Finding(
                    rule="process_name_spoof",
                    severity="Critical",
                    title=f"Possible process impersonation: {p.name}",
                    description=(
                        f"'{p.name}' should run from "
                        f"{' or '.join(allowed)}, but PID "
                        f"{p.pid} is running from {p.path}. "
                        "This is a classic malware impersonation technique."
                    ),
                    events=[],
                    timestamp=now,
                ))

        # Remote access tool detected
        if name_l in REMOTE_ACCESS_TOOLS:
            findings.append(Finding(
                rule="remote_access_tool",
                severity="Medium",
                title=f"Remote access tool detected: {p.name}",
                description=(
                    f"PID {p.pid} ({p.name}) — remote access tools are "
                    "legitimate but commonly used by attackers for persistence. "
                    "Verify it was installed by your IT team."
                ),
                events=[],
                timestamp=now,
            ))

    return findings


# ──────────────────────────────────────────────
# Network rules
# ──────────────────────────────────────────────

def analyze_network(connections: list[NetConnection]) -> list[Finding]:
    from . import threat_intel
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    # Threat-intel hits on remote IPs
    for c in connections:
        if c.state != "ESTABLISHED" or not c.is_external:
            continue
        ioc = threat_intel.check_ip(c.remote_addr)
        if ioc:
            findings.append(Finding(
                rule="ioc_match_ip",
                severity=ioc.severity,
                title=f"Threat-intel hit: {c.remote_addr} ({ioc.description})",
                description=(
                    f"Active connection to {c.remote_addr}:{c.remote_port} "
                    f"from {c.process or 'PID '+str(c.pid)}.\n"
                    f"Indicator: {ioc.indicator}\n"
                    f"Reason: {ioc.description}"
                ),
                events=[],
                timestamp=now,
            ))

    # Listening on suspicious port?
    for c in connections:
        if c.state != "LISTENING":
            continue
        if c.local_port in SUSPICIOUS_PORTS:
            findings.append(Finding(
                rule="suspicious_listening_port",
                severity="High",
                title=f"Suspicious listening port {c.local_port}",
                description=(
                    f"{c.proto}/{c.local_port} is listening "
                    f"({c.process or f'PID {c.pid}'}). "
                    f"Reason: {SUSPICIOUS_PORTS[c.local_port]}."
                ),
                events=[],
                timestamp=now,
            ))
        elif c.local_port not in COMMON_LEGIT_PORTS and c.local_port > 49152:
            # High-numbered ephemeral listeners are common, skip
            continue
        elif (c.local_port not in COMMON_LEGIT_PORTS
              and c.local_port < 49152
              and c.local_port > 1024):
            findings.append(Finding(
                rule="uncommon_listening_port",
                severity="Low",
                title=f"Uncommon listening port {c.local_port}",
                description=(
                    f"{c.proto}/{c.local_port} listening "
                    f"({c.process or f'PID {c.pid}'}). "
                    "Verify this is expected."
                ),
                events=[],
                timestamp=now,
            ))

    # Established external connections
    external = [c for c in connections if c.state == "ESTABLISHED" and c.is_external]
    if len(external) >= 30:
        sample = external[:5]
        sample_str = ", ".join(f"{c.remote_addr}:{c.remote_port}" for c in sample)
        findings.append(Finding(
            rule="external_connection",
            severity="Low",
            title=f"{len(external)} active external connections",
            description=(
                f"This machine has {len(external)} active outbound connections. "
                f"Sample: {sample_str}. Review if abnormal for this host."
            ),
            events=[],
            timestamp=now,
        ))

    return findings


# ──────────────────────────────────────────────
# Autorun rules
# ──────────────────────────────────────────────

def analyze_autoruns(entries: list[AutorunEntry]) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for e in entries:
        cmd_l = e.command.lower()
        hits = [k for k in SUSPICIOUS_AUTORUN_KEYWORDS if k.lower() in cmd_l]
        if hits:
            findings.append(Finding(
                rule="suspicious_autorun",
                severity="High",
                title=f"Suspicious autorun: {e.name}",
                description=(
                    f"Registry autorun '{e.name}' at {e.location} runs:\n"
                    f"  {e.command}\n"
                    f"Suspicious indicators: {', '.join(hits)}"
                ),
                events=[],
                timestamp=now,
            ))

    return findings


# ──────────────────────────────────────────────
# Combined entry
# ──────────────────────────────────────────────

def analyze_system(
    processes: list[Process],
    connections: list[NetConnection],
    autoruns: list[AutorunEntry],
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(analyze_processes(processes))
    findings.extend(analyze_network(connections))
    findings.extend(analyze_autoruns(autoruns))
    return findings
