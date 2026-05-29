"""
Custom detection rule engine.

Users define rules in `~/.log_sentinel/custom_rules.json`. Each rule is a
small JSON object with a `match` block that's matched against the data
streams already collected (processes, network, autoruns, events).

Rule schema:

  {
    "id":        "unique-id",
    "enabled":   true,
    "name":      "Block crypto miners",
    "severity":  "High",
    "category":  "Process Activity",
    "user_category": "Performance",
    "problem":     "A program with a known miner name is running.",
    "why_matters": "Crypto miners eat CPU and inflate power bills.",
    "what_to_do":  "End the process; investigate where it came from.",
    "match": {
      "type": "process",        # process | connection | autorun | event
      "name_in":         ["xmrig.exe", "minerd.exe"],
      "name_contains":   ["miner"],
      "cmdline_contains": ["pool.minexmr"],
      "path_contains":   ["\\Temp\\"],
      "remote_ip":       ["1.2.3.4"],
      "remote_port":     [4444, 5555],
      "registry_path":   ["HKCU\\..."],
      "event_id":        [4625]
    }
  }

Most fields are optional. A rule fires if ANY of the populated match
conditions match the data point.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .preferences import PREFS_DIR
from .analyzer import Finding


RULES_FILE = PREFS_DIR / "custom_rules.json"


# ──────────────────────────────────────────────
# Built-in starter rules (shipped to every user)
# ──────────────────────────────────────────────

DEFAULT_RULES: list[dict[str, Any]] = [
    {
        "id": "crypto-miner-process",
        "enabled": True,
        "name": "Cryptocurrency miner detected",
        "severity": "High",
        "category": "Process Activity",
        "user_category": "Performance",
        "problem": "A program associated with crypto-mining is running.",
        "why_matters": (
            "Crypto miners use 100% of your CPU/GPU when you're away. They "
            "drive up your power bill and shorten your hardware's life. "
            "Legitimate users almost never install them deliberately."
        ),
        "what_to_do": (
            "1. End the process in Task Manager.\n"
            "2. Check what installed it (Settings → Apps).\n"
            "3. Run a full antivirus scan."
        ),
        "match": {
            "type": "process",
            "name_in": [
                "xmrig.exe", "minerd.exe", "ccminer.exe", "phoenixminer.exe",
                "lolminer.exe", "nbminer.exe", "trex.exe", "ethminer.exe",
            ],
            "name_contains": ["miner"],
            "cmdline_contains": [
                "stratum+tcp://", "pool.minexmr", "moneropools",
                "--coin=", "--algo=", "--rig-id=",
            ],
        },
    },
    {
        "id": "remote-shell-port",
        "enabled": True,
        "name": "Remote shell on common attacker port",
        "severity": "Critical",
        "category": "Network",
        "user_category": "Security",
        "problem": "A program is listening on a port commonly used for remote shells.",
        "why_matters": (
            "Ports like 4444 (Metasploit default) are almost never used by "
            "legitimate software. If something is listening there, it's "
            "almost certainly a backdoor."
        ),
        "what_to_do": (
            "Disconnect from the internet, end the listening process, "
            "run a full antivirus scan, change all important passwords."
        ),
        "match": {
            "type": "connection",
            "remote_port": [],
            "local_port_in": [4444, 5555, 6666, 1337, 31337],
        },
    },
    {
        "id": "scheduled-task-from-temp",
        "enabled": True,
        "name": "Suspicious scheduled task from a Temp folder",
        "severity": "High",
        "category": "Persistence",
        "user_category": "Security",
        "problem": "A scheduled task points at a program in a temp folder.",
        "why_matters": (
            "Scheduled tasks survive reboots. Combined with a Temp/AppData "
            "path, this is a classic malware persistence pattern."
        ),
        "what_to_do": (
            "Open Task Scheduler, find the task, disable it. "
            "Note the path and delete the file at that location."
        ),
        "match": {
            "type": "autorun",
            "command_contains": ["\\temp\\", "\\appdata\\local\\temp\\", "\\public\\"],
        },
    },
]


# ──────────────────────────────────────────────
# Storage
# ──────────────────────────────────────────────

def _ensure_rules_file() -> None:
    if RULES_FILE.exists():
        return
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(
        json.dumps(DEFAULT_RULES, indent=2),
        encoding="utf-8",
    )


def load_rules() -> list[dict[str, Any]]:
    _ensure_rules_file()
    try:
        raw = json.loads(RULES_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            return []
        return raw
    except (OSError, json.JSONDecodeError):
        return []


def save_rules(rules: list[dict[str, Any]]) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(
        json.dumps(rules, indent=2),
        encoding="utf-8",
    )


def restore_defaults() -> None:
    save_rules(list(DEFAULT_RULES))


# ──────────────────────────────────────────────
# Matching
# ──────────────────────────────────────────────

def _str_contains_any(haystack: str, needles: list[str]) -> bool:
    if not haystack or not needles:
        return False
    s = haystack.lower()
    return any(n.lower() in s for n in needles)


def _str_in(value: str, needles: list[str]) -> bool:
    if not value or not needles:
        return False
    s = value.lower()
    return any(s == n.lower() for n in needles)


def _match_process(rule_match: dict, p) -> bool:
    name = (p.name or "").lower()
    path = (p.path or "").lower()
    cmd = (p.cmdline or "").lower()

    # Helper: a rule matches if ANY of its conditions match
    if rule_match.get("name_in") and _str_in(name, rule_match["name_in"]):
        return True
    if rule_match.get("name_contains") and _str_contains_any(name, rule_match["name_contains"]):
        return True
    if rule_match.get("path_contains") and _str_contains_any(path, rule_match["path_contains"]):
        return True
    if rule_match.get("cmdline_contains") and _str_contains_any(cmd, rule_match["cmdline_contains"]):
        return True
    return False


def _match_connection(rule_match: dict, c) -> bool:
    remote_ip = (c.remote_addr or "")
    if rule_match.get("remote_ip") and remote_ip in rule_match["remote_ip"]:
        return True
    if rule_match.get("remote_port") and c.remote_port in rule_match["remote_port"]:
        return True
    if rule_match.get("local_port_in") and c.local_port in rule_match["local_port_in"]:
        return True
    if (rule_match.get("listening_port_in")
            and c.state == "LISTENING"
            and c.local_port in rule_match["listening_port_in"]):
        return True
    return False


def _match_autorun(rule_match: dict, a) -> bool:
    command = (a.command or "").lower()
    if (rule_match.get("command_contains")
            and _str_contains_any(command, rule_match["command_contains"])):
        return True
    if (rule_match.get("location_contains")
            and _str_contains_any((a.location or "").lower(),
                                   rule_match["location_contains"])):
        return True
    return False


def _match_event(rule_match: dict, e) -> bool:
    if rule_match.get("event_id") and e.event_id in rule_match["event_id"]:
        return True
    if (rule_match.get("message_contains")
            and _str_contains_any(e.message or "",
                                   rule_match["message_contains"])):
        return True
    return False


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def evaluate(processes, connections, autoruns, events) -> list[Finding]:
    """Run every enabled rule against the data streams. Return Findings."""
    findings: list[Finding] = []
    rules = load_rules()
    now = datetime.now()

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        rule_id = rule.get("id", "custom")
        match = rule.get("match", {})
        kind = match.get("type", "process")

        items = []
        if kind == "process":
            items = [p for p in processes if _match_process(match, p)]
        elif kind == "connection":
            items = [c for c in connections if _match_connection(match, c)]
        elif kind == "autorun":
            items = [a for a in autoruns if _match_autorun(match, a)]
        elif kind == "event":
            items = [e for e in events if _match_event(match, e)]

        if not items:
            continue

        # Build a single Finding per rule (with a count) — keeps the
        # findings list short and tidy
        title = rule.get("name", rule_id)
        if len(items) > 1:
            title = f"{title} ({len(items)} matches)"

        findings.append(Finding(
            rule=f"custom_{rule_id}",
            severity=rule.get("severity", "Medium"),
            title=title,
            description=(
                f"Custom rule '{rule.get('name', rule_id)}' fired.\n"
                f"Type: {kind}    Matches: {len(items)}\n\n"
                f"{rule.get('problem', '')}\n\n"
                f"Why it matters: {rule.get('why_matters', '')}\n\n"
                f"What to do: {rule.get('what_to_do', '')}"
            ),
            events=[],
            timestamp=now,
        ))

    return findings


def register_explanations() -> None:
    """
    Make sure every rule's `custom_<id>` is in the plain_english.EXPLANATIONS
    table so the GUI shows nice cards instead of generic text.
    """
    from . import plain_english
    rules = load_rules()
    for rule in rules:
        rid = f"custom_{rule.get('id', 'custom')}"
        plain_english.EXPLANATIONS[rid] = plain_english.PlainEnglish(
            problem=rule.get("problem", "Custom rule fired."),
            why_matters=rule.get("why_matters", "Investigate the details."),
            what_to_do=rule.get("what_to_do", "Open the rule for guidance."),
            user_category=rule.get("user_category", "Security"),
        )
