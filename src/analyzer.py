"""
Analyzes collected log events and flags suspicious activity.
Each rule produces one or more Finding objects.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from .collector import LogEvent

# ──────────────────────────────────────────────
# Finding data model
# ──────────────────────────────────────────────

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass
class Finding:
    rule: str
    severity: str          # Critical / High / Medium / Low / Info
    title: str
    description: str
    events: list[LogEvent] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def __lt__(self, other: Finding) -> bool:
        return SEVERITY_ORDER.get(self.severity, 0) < SEVERITY_ORDER.get(
            other.severity, 0
        )


# ──────────────────────────────────────────────
# Rule engine
# ──────────────────────────────────────────────

Rule = Callable[[list[LogEvent]], list[Finding]]
_RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    _RULES.append(fn)
    return fn


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _by_id(events: list[LogEvent], *ids: int) -> list[LogEvent]:
    return [e for e in events if e.event_id in ids]


def _window(events: list[LogEvent], minutes: int) -> list[list[LogEvent]]:
    """Group events into sliding windows of `minutes` minutes."""
    if not events:
        return []
    events = sorted(events, key=lambda e: e.timestamp)
    windows: list[list[LogEvent]] = []
    start = events[0].timestamp
    current: list[LogEvent] = []
    for e in events:
        if e.timestamp - start <= timedelta(minutes=minutes):
            current.append(e)
        else:
            if current:
                windows.append(current)
            current = [e]
            start = e.timestamp
    if current:
        windows.append(current)
    return windows


# ──────────────────────────────────────────────
# Rules
# ──────────────────────────────────────────────

@rule
def brute_force_login(events: list[LogEvent]) -> list[Finding]:
    """Multiple 4625 (failed logon) from same IP or targeting same account."""
    THRESHOLD = 5
    WINDOW_MIN = 5

    failed = _by_id(events, 4625)
    findings: list[Finding] = []

    # Group by target account
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    for e in failed:
        user = e.extra.get("TargetUserName") or e.user or "unknown"
        if user not in ("-", "", "UNKNOWN"):
            by_user[user].append(e)

    for user, user_events in by_user.items():
        for window in _window(user_events, WINDOW_MIN):
            if len(window) >= THRESHOLD:
                findings.append(
                    Finding(
                        rule="brute_force_login",
                        severity="High",
                        title=f"Brute-force login attempt on account '{user}'",
                        description=(
                            f"{len(window)} failed logins for '{user}' "
                            f"within {WINDOW_MIN} minutes "
                            f"(first: {window[0].timestamp.strftime('%H:%M:%S')})."
                        ),
                        events=window,
                        timestamp=window[0].timestamp,
                    )
                )
                break  # one finding per user per analysis

    # Group by source IP
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for e in failed:
        ip = e.extra.get("IpAddress") or ""
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            by_ip[ip].append(e)

    for ip, ip_events in by_ip.items():
        for window in _window(ip_events, WINDOW_MIN):
            if len(window) >= THRESHOLD:
                findings.append(
                    Finding(
                        rule="brute_force_from_ip",
                        severity="High",
                        title=f"Brute-force from IP {ip}",
                        description=(
                            f"{len(window)} failed logins from {ip} "
                            f"in {WINDOW_MIN} min."
                        ),
                        events=window,
                        timestamp=window[0].timestamp,
                    )
                )
                break

    return findings


@rule
def audit_log_cleared(events: list[LogEvent]) -> list[Finding]:
    """Event 1102: Security audit log was cleared — common in ransomware / cover-up."""
    cleared = _by_id(events, 1102, 104)  # 104 = System log cleared
    if not cleared:
        return []
    findings = []
    for e in cleared:
        user = e.user or e.extra.get("SubjectUserName", "unknown")
        findings.append(
            Finding(
                rule="audit_log_cleared",
                severity="Critical",
                title="Security audit log cleared",
                description=(
                    f"The audit log was cleared by '{user}' at "
                    f"{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}. "
                    "This is a strong indicator of an attacker covering tracks."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def privilege_escalation(events: list[LogEvent]) -> list[Finding]:
    """4672: Special privileges assigned to new logon (admin-level session)."""
    privs = _by_id(events, 4672)
    findings: list[Finding] = []
    sensitive = {
        "SeDebugPrivilege", "SeAssignPrimaryTokenPrivilege",
        "SeTcbPrivilege", "SeLoadDriverPrivilege",
        "SeImpersonatePrivilege", "SeTakeOwnershipPrivilege",
    }
    for e in privs:
        priv_str = e.extra.get("PrivilegeList", "")
        granted = {p.strip() for p in priv_str.split() if p.strip()}
        hits = granted & sensitive
        if hits:
            user = e.user or e.extra.get("SubjectUserName", "unknown")
            findings.append(
                Finding(
                    rule="privilege_escalation",
                    severity="High",
                    title=f"Sensitive privileges granted to '{user}'",
                    description=(
                        f"User '{user}' was granted: {', '.join(sorted(hits))} "
                        f"at {e.timestamp.strftime('%H:%M:%S')}."
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )
    return findings


@rule
def new_user_created(events: list[LogEvent]) -> list[Finding]:
    """4720: A user account was created."""
    created = _by_id(events, 4720)
    findings = []
    for e in created:
        new_user = e.extra.get("TargetUserName") or "unknown"
        actor = e.extra.get("SubjectUserName") or e.user or "unknown"
        findings.append(
            Finding(
                rule="new_user_created",
                severity="Medium",
                title=f"New local user account created: '{new_user}'",
                description=(
                    f"Account '{new_user}' was created by '{actor}' "
                    f"at {e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def user_added_to_admin_group(events: list[LogEvent]) -> list[Finding]:
    """4732: Member added to local Administrators group."""
    added = _by_id(events, 4732, 4756)
    findings = []
    for e in added:
        group = e.extra.get("TargetUserName") or e.extra.get("GroupName") or ""
        member = e.extra.get("MemberName") or "unknown"
        if "admin" in group.lower() or "administrators" in group.lower() or not group:
            actor = e.extra.get("SubjectUserName") or "unknown"
            findings.append(
                Finding(
                    rule="user_added_to_admin_group",
                    severity="High",
                    title=f"User added to privileged group '{group}'",
                    description=(
                        f"'{member}' was added to group '{group}' by '{actor}'."
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )
    return findings


@rule
def new_service_installed(events: list[LogEvent]) -> list[Finding]:
    """4697 / 7045: A new service was installed on the system."""
    installed = _by_id(events, 4697, 7045)
    findings = []
    suspicious_paths = {
        "temp", "appdata", "public", "downloads", "recycle",
        "programdata", "%temp%", "\\windows\\temp",
    }
    for e in installed:
        svc_name = (
            e.extra.get("ServiceName")
            or e.extra.get("param1")
            or "unknown"
        )
        svc_path = (
            e.extra.get("ServiceFileName")
            or e.extra.get("param3")
            or ""
        ).lower()
        suspicious = any(p in svc_path for p in suspicious_paths)
        severity = "Critical" if suspicious else "Medium"
        findings.append(
            Finding(
                rule="new_service_installed",
                severity=severity,
                title=f"New service installed: '{svc_name}'",
                description=(
                    f"Service '{svc_name}' installed"
                    + (f" from suspicious path: {svc_path}" if suspicious else f" at: {svc_path}")
                    + f" at {e.timestamp.strftime('%H:%M:%S')}."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def suspicious_process(events: list[LogEvent]) -> list[Finding]:
    """4688: Process creation — flag known attacker tools."""
    SUSPICIOUS = {
        "mimikatz", "procdump", "psexec", "wce.exe",
        "pwdump", "gsecdump", "fgdump", "wscript",
        "cscript", "regsvr32", "mshta", "certutil",
        "bitsadmin", "wmic", "rundll32", "cmd.exe",
        "powershell", "net.exe", "net1.exe", "nltest",
        "whoami", "tasklist", "ipconfig", "nmap",
        "netstat", "arp",
    }
    # Only flag if combined with suspicious command line args
    SUSPICIOUS_ARGS = {
        "-enc", "-encodedcommand", "bypass", "hidden",
        "downloadstring", "iex", "invoke-expression",
        "downloadfile", "webclient", "net use",
        "/add", "sekurlsa", "lsadump",
    }

    proc_events = _by_id(events, 4688)
    findings: list[Finding] = []

    for e in proc_events:
        proc = (
            e.extra.get("NewProcessName")
            or e.extra.get("ProcessName")
            or ""
        ).lower()
        cmdline = (e.extra.get("CommandLine") or "").lower()
        proc_name = proc.split("\\")[-1].replace(".exe", "") if proc else ""

        is_suspicious_proc = proc_name in SUSPICIOUS
        has_suspicious_args = any(a in cmdline for a in SUSPICIOUS_ARGS)

        if is_suspicious_proc and has_suspicious_args:
            user = e.extra.get("SubjectUserName") or e.user or "unknown"
            findings.append(
                Finding(
                    rule="suspicious_process",
                    severity="High",
                    title=f"Suspicious process: {proc_name}",
                    description=(
                        f"Process '{proc}' launched by '{user}' "
                        f"with args: {cmdline[:200]}"
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )
        elif proc_name in {"mimikatz", "procdump", "wce.exe", "pwdump"}:
            # Always flag these regardless of args
            user = e.extra.get("SubjectUserName") or e.user or "unknown"
            findings.append(
                Finding(
                    rule="suspicious_process_critical",
                    severity="Critical",
                    title=f"Known attacker tool detected: {proc_name}",
                    description=(
                        f"'{proc}' executed by '{user}'. "
                        "This tool is commonly used for credential dumping / lateral movement."
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )

    return findings


@rule
def powershell_encoded_command(events: list[LogEvent]) -> list[Finding]:
    """4103/4104: PowerShell script block with encoded command or download cradle."""
    ps_events = _by_id(events, 4103, 4104)
    DANGER_PATTERNS = [
        "-enc", "-encodedcommand", "downloadstring",
        "iex(", "invoke-expression", "webclient",
        "bypass", "hidden", "frombase64string",
        "reflection.assembly", "system.net.sockets",
    ]
    findings: list[Finding] = []
    for e in ps_events:
        script = (e.extra.get("ScriptBlockText") or e.message or "").lower()
        hits = [p for p in DANGER_PATTERNS if p in script]
        if hits:
            findings.append(
                Finding(
                    rule="powershell_encoded",
                    severity="High",
                    title="Suspicious PowerShell script block detected",
                    description=(
                        f"PowerShell script contains: {', '.join(hits)}. "
                        f"Snippet: {script[:300]}"
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )
    return findings


@rule
def scheduled_task_created(events: list[LogEvent]) -> list[Finding]:
    """4698: Scheduled task created — persistence mechanism."""
    tasks = _by_id(events, 4698)
    findings = []
    for e in tasks:
        task_name = e.extra.get("TaskName") or "unknown"
        user = e.extra.get("SubjectUserName") or e.user or "unknown"
        findings.append(
            Finding(
                rule="scheduled_task_created",
                severity="Medium",
                title=f"Scheduled task created: '{task_name}'",
                description=(
                    f"Task '{task_name}' was created by '{user}' "
                    f"at {e.timestamp.strftime('%H:%M:%S')}. "
                    "Scheduled tasks are a common persistence technique."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def account_locked_out(events: list[LogEvent]) -> list[Finding]:
    """4740: User account locked out."""
    lockouts = _by_id(events, 4740)
    findings = []
    for e in lockouts:
        user = e.extra.get("TargetUserName") or e.user or "unknown"
        src = e.extra.get("CallerComputerName") or "unknown source"
        findings.append(
            Finding(
                rule="account_locked_out",
                severity="Medium",
                title=f"Account locked out: '{user}'",
                description=(
                    f"Account '{user}' was locked out (triggered from {src}). "
                    "May indicate a brute-force attempt."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def firewall_rule_changed(events: list[LogEvent]) -> list[Finding]:
    """4946/4947/4948: Windows Firewall rule added/modified/deleted."""
    fw = _by_id(events, 4946, 4947, 4948)
    findings = []
    for e in fw:
        rule_name = e.extra.get("RuleName") or "unknown"
        action = {4946: "added", 4947: "modified", 4948: "deleted"}.get(
            e.event_id, "changed"
        )
        findings.append(
            Finding(
                rule="firewall_rule_changed",
                severity="Medium",
                title=f"Firewall rule {action}: '{rule_name}'",
                description=(
                    f"Firewall rule '{rule_name}' was {action} "
                    f"at {e.timestamp.strftime('%H:%M:%S')}. "
                    "Unexpected changes may indicate an attacker disabling defenses."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


@rule
def off_hours_logon(events: list[LogEvent]) -> list[Finding]:
    """Successful logons (4624) outside business hours (6am–10pm local)."""
    logons = _by_id(events, 4624)
    findings = []
    for e in logons:
        logon_type = e.extra.get("LogonType", "")
        # Only flag interactive / remote interactive / network logons
        if logon_type not in ("2", "10", "3"):
            continue
        user = e.extra.get("TargetUserName") or e.user or "unknown"
        if user in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            continue
        # Convert to local-ish hour (UTC is fine for flagging)
        hour = e.timestamp.hour
        if hour < 6 or hour >= 22:
            findings.append(
                Finding(
                    rule="off_hours_logon",
                    severity="Low",
                    title=f"Off-hours logon: '{user}'",
                    description=(
                        f"User '{user}' logged in at "
                        f"{e.timestamp.strftime('%H:%M UTC')} "
                        "(outside 06:00–22:00 UTC)."
                    ),
                    events=[e],
                    timestamp=e.timestamp,
                )
            )
    return findings


@rule
def threat_intel_process(events: list[LogEvent]) -> list[Finding]:
    """4688: cross-check new process names + cmdlines against IOC database."""
    from . import threat_intel
    procs = _by_id(events, 4688)
    findings: list[Finding] = []
    for e in procs:
        proc = e.extra.get("NewProcessName") or ""
        name = proc.split("\\")[-1] if proc else ""
        cmd = e.extra.get("CommandLine", "")
        ioc = threat_intel.check_process(name, cmd)
        if ioc:
            findings.append(Finding(
                rule="ioc_match_process",
                severity=ioc.severity,
                title=f"IOC match: {ioc.indicator} ({ioc.description})",
                description=(
                    f"Process '{name}' matched threat-intel database.\n"
                    f"Type: {ioc.ioc_type}\n"
                    f"Description: {ioc.description}"
                ),
                events=[e],
                timestamp=e.timestamp,
            ))
    return findings


@rule
def system_crash(events: list[LogEvent]) -> list[Finding]:
    """6008: Unexpected system shutdown."""
    crashes = _by_id(events, 6008)
    findings = []
    for e in crashes:
        findings.append(
            Finding(
                rule="system_crash",
                severity="Medium",
                title="Unexpected system shutdown detected",
                description=(
                    f"System experienced an unexpected shutdown at "
                    f"{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')}. "
                    "Could be hardware failure, crash, or forced power-off."
                ),
                events=[e],
                timestamp=e.timestamp,
            )
        )
    return findings


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def analyze(events: list[LogEvent]) -> list[Finding]:
    """Run all rules and return sorted findings (highest severity first)."""
    findings: list[Finding] = []
    for rule_fn in _RULES:
        try:
            findings.extend(rule_fn(events))
        except Exception as e:
            print(f"[!] Rule {rule_fn.__name__} failed: {e}")

    # Deduplicate exact-same (rule, title) pairs
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule, f.title)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.timestamp),
        reverse=True,
    )
    return unique
