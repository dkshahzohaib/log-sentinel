"""
Demo mode — synthetic data so the app can be shown without real telemetry.

Produces a realistic mix of findings, processes, connections, autoruns,
and events so the dashboard is populated and screenshots look good.

Used for: landing page videos, cold-email recipients, customer demos,
training new users.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .analyzer import Finding
from .system_collector import (
    AutorunEntry, NetConnection, Process,
    ScheduledTask, Service, Software, SystemInfo, UsbDevice,
    RecentFile, DnsEntry,
)
from .collector import LogEvent


NOW = datetime.now()


def synthetic_processes() -> list[Process]:
    """A plausible mix of 30 processes."""
    return [
        Process(pid=4,    name="System",        user="Services",  memory_kb=128,    path="",                                                           parent_pid=0),
        Process(pid=672,  name="csrss.exe",      user="Services",  memory_kb=2_100,  path="C:\\Windows\\System32\\csrss.exe",                            parent_pid=4),
        Process(pid=708,  name="winlogon.exe",   user="Services",  memory_kb=4_500,  path="C:\\Windows\\System32\\winlogon.exe",                         parent_pid=4),
        Process(pid=812,  name="services.exe",   user="Services",  memory_kb=8_900,  path="C:\\Windows\\System32\\services.exe",                         parent_pid=672),
        Process(pid=860,  name="lsass.exe",      user="Services",  memory_kb=12_300, path="C:\\Windows\\System32\\lsass.exe",                            parent_pid=672),
        Process(pid=1024, name="svchost.exe",    user="Services",  memory_kb=24_500, path="C:\\Windows\\System32\\svchost.exe",                          parent_pid=812),
        Process(pid=1200, name="explorer.exe",   user="Console",   memory_kb=72_300, path="C:\\Windows\\explorer.exe",                                   parent_pid=812),
        Process(pid=2104, name="chrome.exe",     user="Console",   memory_kb=412_800,path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",  parent_pid=1200),
        Process(pid=2208, name="chrome.exe",     user="Console",   memory_kb=189_500,path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",  parent_pid=2104),
        Process(pid=2310, name="Code.exe",       user="Console",   memory_kb=325_600,path="C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", parent_pid=1200),
        Process(pid=2412, name="Discord.exe",    user="Console",   memory_kb=212_300,path="C:\\Users\\demo\\AppData\\Local\\Discord\\Discord.exe",       parent_pid=1200),
        Process(pid=3024, name="Spotify.exe",    user="Console",   memory_kb=158_400,path="C:\\Users\\demo\\AppData\\Roaming\\Spotify\\Spotify.exe",     parent_pid=1200),
        Process(pid=3308, name="OneDrive.exe",   user="Console",   memory_kb=98_200, path="C:\\Users\\demo\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", parent_pid=1200),
        # Suspicious ones
        Process(pid=6612, name="svchost.exe",    user="Console",   memory_kb=8_400,  path="C:\\Users\\demo\\AppData\\Local\\Temp\\svchost.exe",          parent_pid=1200),  # impersonation
        Process(pid=7104, name="mimikatz.exe",   user="Console",   memory_kb=18_900, path="C:\\Temp\\mimikatz.exe",                                      parent_pid=1200,
                cmdline="mimikatz.exe sekurlsa::logonpasswords"),
        Process(pid=7820, name="powershell.exe", user="Console",   memory_kb=42_100, path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                parent_pid=1200, cmdline="powershell -nop -w hidden -enc V3JpdGUtSG9zdCBoaQ=="),
        Process(pid=8420, name="xmrig.exe",      user="Console",   memory_kb=624_800,path="C:\\Users\\demo\\Downloads\\xmrig.exe",                       parent_pid=1200,
                cmdline="xmrig --url=pool.minexmr.com:4444"),
    ]


def synthetic_connections() -> list[NetConnection]:
    return [
        NetConnection(proto="TCP", local_addr="0.0.0.0",    local_port=445,   remote_addr="0.0.0.0", remote_port=0,    state="LISTENING",   pid=4,    process="System"),
        NetConnection(proto="TCP", local_addr="0.0.0.0",    local_port=3389,  remote_addr="0.0.0.0", remote_port=0,    state="LISTENING",   pid=812,  process="services.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49234, remote_addr="142.250.74.46",  remote_port=443,  state="ESTABLISHED", pid=2104, process="chrome.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49251, remote_addr="13.107.42.14",   remote_port=443,  state="ESTABLISHED", pid=2310, process="Code.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49267, remote_addr="162.159.135.234",remote_port=443,  state="ESTABLISHED", pid=2412, process="Discord.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49301, remote_addr="35.186.224.25",  remote_port=443,  state="ESTABLISHED", pid=3024, process="Spotify.exe"),
        # Suspicious
        NetConnection(proto="TCP", local_addr="0.0.0.0",    local_port=4444,  remote_addr="0.0.0.0", remote_port=0,    state="LISTENING",   pid=6612, process="svchost.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49555, remote_addr="185.220.101.45", remote_port=9001, state="ESTABLISHED", pid=7820, process="powershell.exe"),
        NetConnection(proto="TCP", local_addr="192.168.1.4",local_port=49606, remote_addr="116.202.5.5",    remote_port=4444, state="ESTABLISHED", pid=8420, process="xmrig.exe"),
    ]


def synthetic_autoruns() -> list[AutorunEntry]:
    return [
        AutorunEntry(location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     name="OneDrive",
                     command='"C:\\Users\\demo\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background'),
        AutorunEntry(location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     name="Spotify",
                     command='"C:\\Users\\demo\\AppData\\Roaming\\Spotify\\Spotify.exe" --autostart'),
        # Suspicious autorun
        AutorunEntry(location="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     name="WindowsUpdateCheck",
                     command='powershell -nop -w hidden -enc SQBFAFgAIAA='),
    ]


def synthetic_findings() -> list[Finding]:
    """Spread of findings across all severities + categories."""
    return [
        Finding(
            rule="suspicious_process_critical",
            severity="Critical",
            title="Known attacker tool detected: mimikatz",
            description=(
                "'C:\\Temp\\mimikatz.exe' executed by demo. "
                "This tool is commonly used for credential dumping."
            ),
            events=[], timestamp=NOW - timedelta(minutes=12),
        ),
        Finding(
            rule="process_name_spoof",
            severity="Critical",
            title="Possible process impersonation: svchost.exe",
            description=(
                "'svchost.exe' should run from System32, but PID 6612 is running "
                "from C:\\Users\\demo\\AppData\\Local\\Temp\\svchost.exe. "
                "Classic malware impersonation."
            ),
            events=[], timestamp=NOW - timedelta(minutes=18),
        ),
        Finding(
            rule="ioc_match_ip",
            severity="High",
            title="Threat-intel hit: 185.220.101.45 (TOR exit)",
            description=(
                "Active connection to 185.220.101.45:9001 from powershell.exe. "
                "This IP is a known TOR exit node."
            ),
            events=[], timestamp=NOW - timedelta(minutes=8),
        ),
        Finding(
            rule="suspicious_listening_port",
            severity="High",
            title="Suspicious listening port 4444",
            description=(
                "TCP/4444 is listening (svchost.exe). Default Metasploit port — "
                "extremely rare on a normal user PC."
            ),
            events=[], timestamp=NOW - timedelta(minutes=20),
        ),
        Finding(
            rule="powershell_encoded",
            severity="High",
            title="Suspicious PowerShell script block detected",
            description=(
                "PowerShell script contains: -enc, downloadstring. "
                "Snippet: powershell -nop -w hidden -enc V3JpdGUtSG9zdCBoaQ=="
            ),
            events=[], timestamp=NOW - timedelta(minutes=15),
        ),
        Finding(
            rule="suspicious_autorun",
            severity="High",
            title="Suspicious autorun: WindowsUpdateCheck",
            description=(
                "Registry autorun 'WindowsUpdateCheck' at HKCU\\...Run runs:\n"
                "  powershell -nop -w hidden -enc SQBFAFgAIAA=\n"
                "Suspicious indicators: powershell, -enc, hidden"
            ),
            events=[], timestamp=NOW - timedelta(minutes=45),
        ),
        Finding(
            rule="custom_crypto-miner-process",
            severity="High",
            title="Cryptocurrency miner detected",
            description=(
                "xmrig.exe is running with stratum+tcp pool URL. "
                "Crypto miners use 100% of your CPU/GPU when you're away."
            ),
            events=[], timestamp=NOW - timedelta(minutes=5),
        ),
        Finding(
            rule="new_user_created",
            severity="Medium",
            title="New local user account created: 'backdoor_user'",
            description=(
                "Account 'backdoor_user' was created by 'hacker' at "
                f"{(NOW - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')}."
            ),
            events=[], timestamp=NOW - timedelta(hours=2),
        ),
        Finding(
            rule="scheduled_task_created",
            severity="Medium",
            title="Scheduled task created: 'SystemUpdateCheck'",
            description=(
                "Task '\\Microsoft\\Windows\\SystemUpdateCheck' was created by "
                "'hacker' at 14:25. Scheduled tasks are a common persistence technique."
            ),
            events=[], timestamp=NOW - timedelta(hours=1, minutes=30),
        ),
        Finding(
            rule="remote_access_tool",
            severity="Medium",
            title="Remote access tool detected: AnyDesk.exe",
            description=(
                "PID 4128 (AnyDesk.exe). Remote access tools are legitimate "
                "but commonly used by attackers for persistence."
            ),
            events=[], timestamp=NOW - timedelta(hours=3),
        ),
        Finding(
            rule="off_hours_logon",
            severity="Low",
            title="Off-hours logon: 'demo'",
            description=(
                "User 'demo' logged in at 03:15 UTC (outside 06:00–22:00 UTC)."
            ),
            events=[], timestamp=NOW - timedelta(hours=5),
        ),
        Finding(
            rule="slow_startup_program",
            severity="Low",
            title="Auto-starts at boot: BackupTool",
            description=(
                "'BackupTool' runs every time you start your computer.\n"
                "Disable in Task Manager → Startup if you don't need it."
            ),
            events=[], timestamp=NOW - timedelta(hours=6),
        ),
        Finding(
            rule="high_memory_process",
            severity="Low",
            title="Using a lot of RAM: chrome.exe (402 MB)",
            description=(
                "PID 2104 (chrome.exe) is using 402 MB of RAM. "
                "If you don't recognise this program, end it in Task Manager."
            ),
            events=[], timestamp=NOW - timedelta(hours=4),
        ),
        Finding(
            rule="external_connection",
            severity="Low",
            title="35 active external connections",
            description=(
                "This machine has 35 active outbound connections. "
                "Review if abnormal for this host."
            ),
            events=[], timestamp=NOW - timedelta(minutes=2),
        ),
        Finding(
            rule="webcam_or_mic_access",
            severity="Low",
            title="App has microphone access: Discord.exe",
            description=(
                "App 'Discord.exe' has used the microphone (last seen yesterday). "
                "Review in Settings → Privacy & security → Microphone."
            ),
            events=[], timestamp=NOW - timedelta(hours=18),
        ),
    ]


def synthetic_system_info():
    import socket
    return SystemInfo(
        hostname="DEMO-PC",
        os="Windows 11 Pro 24H2 (Build 26200)",
        user="demo",
        boot_time="11/05/2026  09:14:23",
        domain="WORKGROUP",
        ip_addresses=["192.168.1.4", "fe80::1234:5678:9abc:def0"],
    )


def synthetic_services() -> list[Service]:
    out = []
    for name, display, state in [
        ("Spooler",     "Print Spooler",          "RUNNING"),
        ("Dhcp",        "DHCP Client",            "RUNNING"),
        ("EventLog",    "Windows Event Log",      "RUNNING"),
        ("LanmanWorkstation", "Workstation",      "RUNNING"),
        ("WSearch",     "Windows Search",         "RUNNING"),
        ("WinDefend",   "Microsoft Defender Antivirus", "RUNNING"),
        ("CryptSvc",    "Cryptographic Services", "RUNNING"),
        ("BITS",        "Background Intelligent Transfer", "RUNNING"),
        ("wuauserv",    "Windows Update",         "STOPPED"),
        ("WindowsUpdateHelper", "Windows Update Helper", "RUNNING"),  # suspicious
    ]:
        out.append(Service(name=name, display_name=display, state=state))
    return out


def synthetic_tasks() -> list[ScheduledTask]:
    return [
        ScheduledTask(name="\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
                      next_run="12/05/2026 03:00:00", status="Ready"),
        ScheduledTask(name="\\Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                      next_run="13/05/2026 01:00:00", status="Ready"),
        ScheduledTask(name="\\Microsoft\\Windows\\SystemUpdateCheck",   # suspicious
                      next_run="11/05/2026 23:00:00", status="Ready"),
    ]


def synthetic_software() -> list[Software]:
    return [
        Software(name="Google Chrome", version="138.0.6422.114", publisher="Google LLC", install_date="20241201"),
        Software(name="Microsoft Visual Studio Code", version="1.96.4", publisher="Microsoft Corporation", install_date="20250108"),
        Software(name="Spotify", version="1.2.45.327", publisher="Spotify AB", install_date="20240518"),
        Software(name="Discord", version="1.0.9192", publisher="Discord Inc.", install_date="20240612"),
        Software(name="OneDrive", version="25.018.0125", publisher="Microsoft", install_date="20240101"),
        Software(name="AnyDesk", version="9.0.5", publisher="AnyDesk Software GmbH", install_date="20250320"),  # suspicious to find here
        Software(name="7-Zip 24.09", version="24.09", publisher="Igor Pavlov", install_date="20240910"),
    ]


def synthetic_usb() -> list[UsbDevice]:
    return [
        UsbDevice(device_id="Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\AABB12345&0",
                  friendly_name="SanDisk Ultra USB 3.0"),
        UsbDevice(device_id="Disk&Ven_Kingston&Prod_DataTraveler&Rev_PMAP\\XYZ9876&0",
                  friendly_name="Kingston DataTraveler"),
    ]


def synthetic_dns() -> list[DnsEntry]:
    return [
        DnsEntry(name="www.google.com",   type="A",     data="142.250.74.46"),
        DnsEntry(name="github.com",       type="A",     data="140.82.112.3"),
        DnsEntry(name="discord.com",      type="A",     data="162.159.135.234"),
        DnsEntry(name="spotify.com",      type="A",     data="35.186.224.25"),
        DnsEntry(name="pool.minexmr.com", type="A",     data="116.202.5.5"),  # suspicious
    ]


def synthetic_recent_files() -> list[RecentFile]:
    return [
        RecentFile(name="Q4 budget", modified="2026-05-11 14:32:00"),
        RecentFile(name="resume", modified="2026-05-11 11:08:00"),
        RecentFile(name="vacation_pics", modified="2026-05-10 19:14:00"),
        RecentFile(name="passwords.txt", modified="2026-05-09 22:45:00"),  # honeypot bait
    ]


def synthetic_events() -> list[LogEvent]:
    """A handful of plausible Windows events."""
    out = []
    base = NOW - timedelta(hours=2)
    for i, (eid, channel, source, msg) in enumerate([
        (4624, "Security",     "Microsoft-Windows-Security-Auditing", "Successful logon by demo"),
        (4625, "Security",     "Microsoft-Windows-Security-Auditing", "Failed logon attempt"),
        (4720, "Security",     "Microsoft-Windows-Security-Auditing", "New user created: backdoor_user"),
        (7045, "System",       "Service Control Manager",             "Service installed: WindowsUpdateHelper"),
        (4698, "Security",     "Microsoft-Windows-Security-Auditing", "Scheduled task created: SystemUpdateCheck"),
        (4104, "Windows PowerShell", "PowerShell",                    "Encoded script block executed"),
        (4688, "Security",     "Microsoft-Windows-Security-Auditing", "Process created: mimikatz.exe"),
        (1102, "Security",     "Microsoft-Windows-Eventlog",          "Audit log cleared"),
    ]):
        out.append(LogEvent(
            event_id=eid,
            timestamp=base + timedelta(minutes=i * 10),
            channel=channel, level="Info",
            source=source, computer="DEMO-PC",
            message=msg, user="demo",
            extra={},
        ))
    return out
