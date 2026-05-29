"""
Collects Windows Event Logs from Security, System, and Application channels.
"""

import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
import json
import sys


@dataclass
class LogEvent:
    event_id: int
    timestamp: datetime
    channel: str
    level: str
    source: str
    computer: str
    message: str
    user: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Windows Event Log channels to collect
CHANNELS = ["Security", "System", "Application"]

# Event IDs we care about (reduces noise)
INTERESTING_EVENT_IDS = {
    # Auth
    4624, 4625, 4634, 4647, 4648, 4649, 4672, 4673, 4674,
    4771, 4776, 4800, 4801,
    # Account management
    4720, 4722, 4723, 4724, 4725, 4726, 4727, 4728, 4732,
    4735, 4737, 4738, 4740, 4756, 4767,
    # Process
    4688, 4689,
    # Services / tasks
    4697, 7045, 4698, 4699, 4700, 4701, 4702,
    # Audit / log tampering
    1102, 4719,
    # Firewall / network
    4946, 4947, 4948, 5156, 5157,
    # PowerShell
    4103, 4104,
    # Object access
    4663, 4670,
    # System
    6005, 6006, 6008, 6009,
}

LEVEL_MAP = {"0": "Info", "1": "Critical", "2": "Error", "3": "Warning",
             "4": "Info", "5": "Verbose"}


def _query_channel(channel: str, hours_back: int = 24) -> list[LogEvent]:
    """Use wevtutil to pull events from a channel as XML."""
    events: list[LogEvent] = []

    # Build XPath query — filter to interesting IDs to keep it fast
    ids_xpath = " or ".join(f"EventID={eid}" for eid in INTERESTING_EVENT_IDS)
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    xpath = (
        f"*[System[({ids_xpath}) and "
        f"TimeCreated[@SystemTime>='{since}']]]"
    )

    cmd = [
        "wevtutil", "qe", channel,
        "/q:" + xpath,
        "/f:XML",
        "/rd:true",   # newest first
        "/c:5000",    # cap at 5000 events per channel
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        print(f"[!] wevtutil not found — are you on Windows?", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout reading {channel}", file=sys.stderr)
        return []

    if result.returncode != 0:
        # Access denied on Security log without admin rights
        if "Access is denied" in result.stderr:
            print(
                f"[!] Access denied on {channel} — run as Administrator.",
                file=sys.stderr,
            )
        return []

    # wevtutil outputs events without a root element; wrap them
    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        root = ET.fromstring(f"<Events>{raw}</Events>")
    except ET.ParseError as e:
        print(f"[!] XML parse error on {channel}: {e}", file=sys.stderr)
        return []

    ns = "http://schemas.microsoft.com/win/2004/08/events/event"

    for event_el in root.findall(f"{{{ns}}}Event"):
        sys_el = event_el.find(f"{{{ns}}}System")
        if sys_el is None:
            continue

        def get(tag: str) -> str:
            el = sys_el.find(f"{{{ns}}}{tag}")
            return el.text or "" if el is not None else ""

        try:
            event_id = int(get("EventID"))
        except ValueError:
            continue

        time_str = ""
        tc = sys_el.find(f"{{{ns}}}TimeCreated")
        if tc is not None:
            time_str = tc.get("SystemTime", "")

        try:
            ts = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()

        level_code = get("Level")
        level = LEVEL_MAP.get(level_code, "Info")
        source = ""
        prov = sys_el.find(f"{{{ns}}}Provider")
        if prov is not None:
            source = prov.get("Name", "")
        computer = get("Computer")

        # Extract user from EventData / UserData
        user = None
        extra: dict = {}
        ed = event_el.find(f"{{{ns}}}EventData")
        if ed is not None:
            for data in ed.findall(f"{{{ns}}}Data"):
                name = data.get("Name", "")
                val = data.text or ""
                if name in ("SubjectUserName", "TargetUserName", "AccountName"):
                    user = val or user
                extra[name] = val

        # Build human-readable message snippet
        message = f"EventID {event_id} from {source}"
        if extra:
            kv = ", ".join(f"{k}={v}" for k, v in list(extra.items())[:4])
            message = f"{message} [{kv}]"

        events.append(
            LogEvent(
                event_id=event_id,
                timestamp=ts,
                channel=channel,
                level=level,
                source=source,
                computer=computer,
                message=message,
                user=user,
                extra=extra,
            )
        )

    return events


def collect(hours_back: int = 24) -> list[LogEvent]:
    """Collect events from all channels for the last N hours."""
    all_events: list[LogEvent] = []
    for channel in CHANNELS:
        print(f"[*] Collecting {channel} logs (last {hours_back}h)...")
        events = _query_channel(channel, hours_back)
        print(f"    Found {len(events)} interesting events.")
        all_events.extend(events)

    all_events.sort(key=lambda e: e.timestamp)
    return all_events


def save_raw(events: list[LogEvent], path: str) -> None:
    """Dump raw events to JSON for offline analysis."""
    data = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp.isoformat(),
            "channel": e.channel,
            "level": e.level,
            "source": e.source,
            "computer": e.computer,
            "user": e.user,
            "message": e.message,
            "extra": e.extra,
        }
        for e in events
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
