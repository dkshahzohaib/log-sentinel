"""
Honeypot tripwires.

Drop fake "interesting" files in user-chosen folders (Documents, Desktop,
…) named things like `passwords.txt`, `wallet.dat.txt`, `tax_return_2024.xlsx`.
Record their initial mtime + access time + hash. On every scan, check
whether they have been opened, modified, or deleted.

Real attackers / ransomware / malicious insiders will read or encrypt them.
Normal users will leave them alone.

Storage: ~/.log_sentinel/honeypots.json
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR
from .analyzer import Finding


HONEYPOTS_FILE = PREFS_DIR / "honeypots.json"


# Plausible-but-fake file names that attract attention
HONEYPOT_TEMPLATES: dict[str, dict] = {
    "passwords.txt": {
        "content": (
            "# Password backup\n"
            "# Last updated: 2024-11\n\n"
            "Gmail            : <REDACTED>\n"
            "Online banking   : <REDACTED>\n"
            "Crypto wallet    : <REDACTED>\n"
            "VPN              : <REDACTED>\n"
            "Work account     : <REDACTED>\n"
        ),
        "rationale": "Looks like a stored password file — irresistible to attackers.",
    },
    "tax_return_2024.txt": {
        "content": "TAX RETURN — DO NOT SHARE\n\n[redacted document — private financial info]\n",
        "rationale": "Identity-theft bait.",
    },
    "wallet_backup.txt": {
        "content": "Cryptocurrency wallet seed phrase backup.\n\n[redacted — restore-only]\n",
        "rationale": "Crypto-stealer malware looks for these files.",
    },
    "vpn_credentials.txt": {
        "content": "Corporate VPN credentials.\n\nServer: vpn.example.com\nUsername: [redacted]\nPassword: [redacted]\n",
        "rationale": "Lateral-movement target.",
    },
    "Desktop_Backup_DO_NOT_DELETE.txt": {
        "content": "This file is part of an automated backup. Do not delete.\n",
        "rationale": "Vague and slightly authoritative — most users don't touch it.",
    },
}


@dataclass
class Honeypot:
    path: str
    placed_at: str
    placed_mtime: float
    placed_atime: float
    placed_size: int
    rationale: str = ""
    note: str = ""


# ──────────────────────────────────────────────
# Storage
# ──────────────────────────────────────────────

def load() -> list[Honeypot]:
    if not HONEYPOTS_FILE.exists():
        return []
    try:
        data = json.loads(HONEYPOTS_FILE.read_text(encoding="utf-8"))
        return [Honeypot(**d) for d in data]
    except (OSError, json.JSONDecodeError, TypeError):
        return []


def save(items: list[Honeypot]) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    HONEYPOTS_FILE.write_text(
        json.dumps([asdict(i) for i in items], indent=2),
        encoding="utf-8",
    )


# ──────────────────────────────────────────────
# Common "drop" locations
# ──────────────────────────────────────────────

def common_locations() -> list[tuple[str, str]]:
    """Returns list of (label, path) suggestions."""
    home = Path.home()
    return [
        ("Documents", str(home / "Documents")),
        ("Desktop",   str(home / "Desktop")),
        ("Downloads", str(home / "Downloads")),
        ("OneDrive",  str(home / "OneDrive")),
    ]


# ──────────────────────────────────────────────
# Place / remove
# ──────────────────────────────────────────────

def place(folder: str, template_name: str = "passwords.txt") -> tuple[bool, str]:
    """Drop a tripwire in `folder`. Records its initial state."""
    if template_name not in HONEYPOT_TEMPLATES:
        return False, f"Unknown template: {template_name}"
    folder_p = Path(folder).expanduser()
    if not folder_p.exists() or not folder_p.is_dir():
        return False, f"Folder doesn't exist: {folder_p}"

    target = folder_p / template_name
    if target.exists():
        return False, f"A file named {template_name} already exists at that location."

    template = HONEYPOT_TEMPLATES[template_name]
    try:
        target.write_text(template["content"], encoding="utf-8")
    except (OSError, PermissionError) as e:
        return False, f"Couldn't create the file: {e}"

    try:
        st = target.stat()
    except OSError as e:
        return False, str(e)

    items = load()
    items.append(Honeypot(
        path=str(target),
        placed_at=datetime.now().isoformat(),
        placed_mtime=st.st_mtime,
        placed_atime=st.st_atime,
        placed_size=st.st_size,
        rationale=template["rationale"],
    ))
    save(items)
    return True, f"Placed honeypot at {target}.\n\nReason: {template['rationale']}"


def remove(path: str) -> tuple[bool, str]:
    items = load()
    target = Path(path)
    new_items = [i for i in items if Path(i.path) != target]
    if len(new_items) == len(items):
        return False, "Honeypot not in list."
    save(new_items)
    if target.exists():
        try:
            target.unlink()
        except OSError as e:
            return True, f"Removed from list, but couldn't delete the file: {e}"
    return True, f"Removed honeypot {target.name}."


def remove_all() -> tuple[int, int]:
    items = load()
    deleted = errors = 0
    for h in items:
        try:
            p = Path(h.path)
            if p.exists():
                p.unlink()
            deleted += 1
        except OSError:
            errors += 1
    save([])
    return deleted, errors


# ──────────────────────────────────────────────
# Scan
# ──────────────────────────────────────────────

def scan() -> list[Finding]:
    """Check every honeypot for tampering. Updates baseline mtime if benign."""
    items = load()
    if not items:
        return []
    findings: list[Finding] = []
    now = datetime.now()
    changed = False

    for h in items:
        p = Path(h.path)
        if not p.exists():
            findings.append(Finding(
                rule="honeypot_deleted",
                severity="Critical",
                title=f"Honeypot file deleted: {p.name}",
                description=(
                    f"A tripwire file you placed at {h.path} has been DELETED. "
                    "Normal users have no reason to delete this — it's a strong "
                    "signal that ransomware or a wiper is active.\n\n"
                    "Action: disconnect from the network NOW (Panic button), "
                    "run a full antivirus scan, restore from backup."
                ),
                events=[],
                timestamp=now,
            ))
            continue

        try:
            st = p.stat()
        except OSError:
            continue

        # Modification or significant access
        if abs(st.st_mtime - h.placed_mtime) > 2:
            findings.append(Finding(
                rule="honeypot_modified",
                severity="Critical",
                title=f"Honeypot file modified: {p.name}",
                description=(
                    f"A tripwire file at {h.path} has been MODIFIED. "
                    "Normal users have no reason to edit this — typical signs "
                    "of ransomware (encrypting it) or active intrusion.\n\n"
                    f"Original mtime: {datetime.fromtimestamp(h.placed_mtime)}\n"
                    f"Current mtime : {datetime.fromtimestamp(st.st_mtime)}\n\n"
                    "Action: disconnect from the network, run a full scan."
                ),
                events=[],
                timestamp=now,
            ))
        elif st.st_size != h.placed_size:
            findings.append(Finding(
                rule="honeypot_modified",
                severity="High",
                title=f"Honeypot file size changed: {p.name}",
                description=(
                    f"Size of tripwire {h.path} changed from "
                    f"{h.placed_size} to {st.st_size} bytes."
                ),
                events=[],
                timestamp=now,
            ))
        # Access time changed by more than 5 minutes — someone read it
        elif st.st_atime - h.placed_atime > 300:
            findings.append(Finding(
                rule="honeypot_accessed",
                severity="High",
                title=f"Honeypot file READ: {p.name}",
                description=(
                    f"The tripwire at {h.path} has been opened or read since "
                    f"you placed it. Normal users don't open random files like "
                    f"this. Common attacker pattern: search Documents folder "
                    f"for 'password' / 'wallet' / 'tax' files.\n\n"
                    f"First seen at: {datetime.fromtimestamp(h.placed_atime)}\n"
                    f"Latest access: {datetime.fromtimestamp(st.st_atime)}"
                ),
                events=[],
                timestamp=now,
            ))
            # Update the recorded atime so we don't keep re-firing
            h.placed_atime = st.st_atime
            changed = True

    if changed:
        save(items)
    return findings


def register_explanations() -> None:
    from . import plain_english
    plain_english.EXPLANATIONS["honeypot_deleted"] = plain_english.PlainEnglish(
        problem="A decoy file you planted has been DELETED.",
        why_matters="Ransomware and wipers delete or overwrite files in bulk. Real users don't delete files they didn't make.",
        what_to_do="Disconnect from the network immediately (Panic button). Run a full antivirus scan. Check your backups.",
        user_category="Security",
    )
    plain_english.EXPLANATIONS["honeypot_modified"] = plain_english.PlainEnglish(
        problem="A decoy file you planted has been MODIFIED.",
        why_matters="Modification of a tripwire is a near-perfect ransomware indicator — they're encrypting your files.",
        what_to_do="Panic button → disconnect now. Run a full scan. Check other files for damage.",
        user_category="Security",
    )
    plain_english.EXPLANATIONS["honeypot_accessed"] = plain_english.PlainEnglish(
        problem="A decoy file you planted has been READ.",
        why_matters="An attacker (or insider) is browsing your files looking for credentials and financial info.",
        what_to_do="Audit recent activity (Live Feed tab). If you didn't open this file, run a full antivirus scan.",
        user_category="Security",
    )
