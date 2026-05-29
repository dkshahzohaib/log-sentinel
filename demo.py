"""
Demo mode: generates synthetic events to test the analyser and produce a
sample HTML report without requiring Administrator access or real Windows logs.

Usage:
    python demo.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.collector import LogEvent
from src.analyzer import analyze
from src.reporter import print_summary, generate_html, generate_json, generate_pdf

NOW = datetime.now(timezone.utc)


def _e(event_id: int, channel: str, source: str, user: str,
        delta_minutes: int = 0, **extra) -> LogEvent:
    return LogEvent(
        event_id=event_id,
        timestamp=NOW - timedelta(minutes=delta_minutes),
        channel=channel,
        level="Info",
        source=source,
        computer="DEMO-PC",
        message=f"Demo EventID {event_id}",
        user=user,
        extra=extra,
    )


def generate_demo_events() -> list[LogEvent]:
    events: list[LogEvent] = []

    # ── Brute-force on Administrator ─────────────────────────────────────────
    for i in range(8):
        events.append(_e(
            4625, "Security", "Microsoft-Windows-Security-Auditing",
            "Administrator", delta_minutes=120 - i,
            TargetUserName="Administrator",
            IpAddress="185.220.101.45",
            LogonType="3",
        ))

    # ── Successful logon after brute-force ───────────────────────────────────
    events.append(_e(
        4624, "Security", "Microsoft-Windows-Security-Auditing",
        "Administrator", delta_minutes=110,
        TargetUserName="Administrator",
        IpAddress="185.220.101.45",
        LogonType="3",
    ))

    # ── Audit log cleared ────────────────────────────────────────────────────
    events.append(_e(
        1102, "Security", "Microsoft-Windows-Eventlog",
        "hacker", delta_minutes=100,
        SubjectUserName="hacker",
    ))

    # ── New user created ─────────────────────────────────────────────────────
    events.append(_e(
        4720, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=95,
        TargetUserName="backdoor_user",
        SubjectUserName="hacker",
    ))

    # ── User added to Administrators ─────────────────────────────────────────
    events.append(_e(
        4732, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=94,
        MemberName="backdoor_user",
        TargetUserName="Administrators",
        SubjectUserName="hacker",
    ))

    # ── Suspicious service installed ─────────────────────────────────────────
    events.append(_e(
        7045, "System", "Service Control Manager",
        "SYSTEM", delta_minutes=90,
        ServiceName="WindowsUpdateHelper",
        ServiceFileName="C:\\Users\\Public\\svc.exe",
    ))

    # ── PowerShell encoded command ────────────────────────────────────────────
    events.append(_e(
        4104, "Windows PowerShell", "PowerShell",
        "hacker", delta_minutes=85,
        ScriptBlockText=(
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAu"
            "AFcAZQBiAEMAbABpAGUAbgB0ACAALQBDAG8AbgBuAGUAYwB0AFQAaQBtAGUAbwB1AHQA"
            "IAAxADAAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA="
        ),
    ))

    # ── Known attacker tool ───────────────────────────────────────────────────
    events.append(_e(
        4688, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=80,
        NewProcessName="C:\\Temp\\mimikatz.exe",
        CommandLine="mimikatz.exe sekurlsa::logonpasswords",
        SubjectUserName="hacker",
    ))

    # ── Scheduled task for persistence ───────────────────────────────────────
    events.append(_e(
        4698, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=75,
        TaskName="\\Microsoft\\Windows\\SystemUpdateCheck",
        SubjectUserName="hacker",
    ))

    # ── Firewall rule changed ─────────────────────────────────────────────────
    events.append(_e(
        4946, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=70,
        RuleName="Allow_Backdoor_4444",
    ))

    # ── Special privileges (privilege escalation) ─────────────────────────────
    events.append(_e(
        4672, "Security", "Microsoft-Windows-Security-Auditing",
        "hacker", delta_minutes=65,
        SubjectUserName="hacker",
        PrivilegeList="SeDebugPrivilege\nSeTcbPrivilege\nSeImpersonatePrivilege",
    ))

    # ── Off-hours logon (3am) ─────────────────────────────────────────────────
    from datetime import datetime, timedelta, timezone
    off_hours = NOW.replace(hour=3, minute=15, second=0)
    events.append(LogEvent(
        event_id=4624,
        timestamp=off_hours,
        channel="Security",
        level="Info",
        source="Microsoft-Windows-Security-Auditing",
        computer="DEMO-PC",
        message="Off-hours logon demo",
        user="contractor_bob",
        extra={
            "TargetUserName": "contractor_bob",
            "LogonType": "10",
            "IpAddress": "203.0.113.42",
        },
    ))

    # ── Account lockout ───────────────────────────────────────────────────────
    events.append(_e(
        4740, "Security", "Microsoft-Windows-Security-Auditing",
        "bob_smith", delta_minutes=50,
        TargetUserName="bob_smith",
        CallerComputerName="WORKSTATION-07",
    ))

    # ── System crash ──────────────────────────────────────────────────────────
    events.append(_e(
        6008, "System", "EventLog",
        "SYSTEM", delta_minutes=200,
    ))

    return events


def main() -> None:
    print("[*] Running in DEMO mode (synthetic events, no real logs needed)")
    print()

    events = generate_demo_events()
    print(f"[*] Generated {len(events)} synthetic events")

    findings = analyze(events)
    print_summary(findings, events)

    out_dir = Path("reports")
    out_dir.mkdir(exist_ok=True)
    html_path = str(out_dir / "demo_report.html")
    pdf_path = str(out_dir / "demo_report.pdf")
    json_path = str(out_dir / "demo_findings.json")

    generate_html(findings, events, html_path, hours_back=24)
    generate_pdf(findings, events, pdf_path, hours_back=24)
    generate_json(findings, json_path)

    try:
        import os
        os.startfile(str(Path(html_path).resolve()))
    except Exception:
        print(f"[*] Open manually: {Path(html_path).resolve()}")


if __name__ == "__main__":
    main()
