"""
Block / unblock websites by editing the Windows hosts file.

Hosts file path: C:\\Windows\\System32\\drivers\\etc\\hosts

When we block a domain we add four lines (IPv4 + IPv6, with and without www.):

    0.0.0.0 example.com    # LogSentinel|2026-05-08|user note
    0.0.0.0 www.example.com  # LogSentinel|2026-05-08|user note
    ::      example.com    # LogSentinel|2026-05-08|user note
    ::      www.example.com  # LogSentinel|2026-05-08|user note

Every line we add carries the marker `# LogSentinel|<date>|<note>` so we can
find / list / remove only our entries without disturbing the file.

Requires Administrator (the hosts file is system-protected).
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
MARKER = "# LogSentinel|"


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────

@dataclass
class HostsBlock:
    domain: str                 # canonical, lowercase, no scheme
    added: str = ""             # ISO date string
    note: str = ""
    variants: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)  # ['ipv4','ipv6']


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def is_admin() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+(?<!-)$"
)


def canonicalize(raw: str) -> tuple[bool, str]:
    """
    Normalise a user-typed domain. Returns (ok, canonical_or_error).
    Strips http(s)://, paths, ports, and a leading 'www.'.
    """
    if not raw:
        return False, "Domain is empty."
    s = raw.strip()
    # Strip scheme
    if "://" in s:
        s = s.split("://", 1)[1]
    # Strip path
    s = s.split("/", 1)[0]
    # Strip port
    s = s.split(":", 1)[0]
    # Strip 'www.' prefix — we'll add it back as a variant
    s = s.lower()
    if s.startswith("www."):
        s = s[4:]

    if not _DOMAIN_RE.match(s):
        return False, f"Doesn't look like a valid domain: '{raw}'"

    # Refuse to block locally-significant names
    danger = {"localhost", "broadcasthost", "ip6-localhost", "ip6-loopback"}
    parts = s.split(".")
    if parts[0] in danger or s in danger:
        return False, f"Refusing to block reserved name '{s}'."
    # Refuse very-short single-label or accidental TLDs
    if len(parts) < 2:
        return False, f"Need at least domain.tld — got '{s}'"
    return True, s


def _ensure_admin() -> tuple[bool, str]:
    if not is_admin():
        return False, ("Editing the hosts file requires Administrator. "
                       "Re-launch via LAUNCH-as-admin.bat.")
    if not HOSTS_PATH.exists():
        return False, f"Hosts file not found at {HOSTS_PATH}."
    return True, ""


def _read_hosts() -> str:
    try:
        return HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        raise RuntimeError(f"Cannot read hosts file: {e}")


def _write_hosts(text: str) -> None:
    # Atomic-ish: write to temp, replace
    tmp = HOSTS_PATH.with_suffix(".sentinel.tmp")
    try:
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, HOSTS_PATH)
    except OSError as e:
        raise RuntimeError(f"Cannot write hosts file: {e}")
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _flush_dns() -> None:
    flags = 0x08000000 if platform.system() == "Windows" else 0
    try:
        subprocess.run(["ipconfig", "/flushdns"],
                       capture_output=True, timeout=10,
                       creationflags=flags)
    except (OSError, subprocess.TimeoutExpired):
        pass


# ──────────────────────────────────────────────
# Add / remove
# ──────────────────────────────────────────────

def add_block(domain: str, note: str = "",
              include_www: bool = True,
              ipv4: bool = True, ipv6: bool = True) -> tuple[bool, str]:
    ok, err = _ensure_admin()
    if not ok:
        return False, err

    ok, canonical = canonicalize(domain)
    if not ok:
        return False, canonical

    text = _read_hosts()
    existing = {h.domain for h in list_blocks_from_text(text)}
    if canonical in existing:
        return False, f"'{canonical}' is already blocked."

    today = datetime.now().strftime("%Y-%m-%d")
    safe_note = note.replace("|", " ").replace("\n", " ")[:120]
    tag = f"  {MARKER}{today}|{safe_note}"

    domains_to_block = [canonical]
    if include_www:
        domains_to_block.append("www." + canonical)

    new_lines: list[str] = []
    if ipv4:
        for d in domains_to_block:
            new_lines.append(f"0.0.0.0 {d}{tag}")
    if ipv6:
        for d in domains_to_block:
            new_lines.append(f":: {d}{tag}")

    if not new_lines:
        return False, "Need at least IPv4 or IPv6 enabled."

    block = "\n".join(new_lines)
    if not text.endswith("\n"):
        text += "\n"
    text += block + "\n"

    try:
        _write_hosts(text)
    except RuntimeError as e:
        from . import change_log
        change_log.record("hosts.add_block", canonical, False, str(e))
        return False, str(e)
    _flush_dns()
    from . import change_log
    change_log.record(
        "hosts.add_block", canonical, True,
        f"Added {len(new_lines)} hosts entries.",
        undo_hint=f"Remove '{canonical}' from the Firewall > Websites tab.",
        metadata={"include_www": include_www, "ipv4": ipv4, "ipv6": ipv6},
    )
    return True, (
        f"Blocked {canonical}"
        + (f" (+ www.{canonical})" if include_www else "")
        + f". Added {len(new_lines)} hosts entr{'ies' if len(new_lines)!=1 else 'y'}. "
        "DNS cache flushed."
    )


def remove_block(domain: str) -> tuple[bool, str]:
    ok, err = _ensure_admin()
    if not ok:
        return False, err
    ok, canonical = canonicalize(domain)
    if not ok:
        return False, canonical

    text = _read_hosts()
    targets = {canonical, "www." + canonical}
    kept: list[str] = []
    removed = 0
    for line in text.splitlines():
        if MARKER in line:
            # Format: <ip> <domain>  # LogSentinel|date|note
            parts = line.split()
            if len(parts) >= 2 and parts[1].lower() in targets:
                removed += 1
                continue
        kept.append(line)
    if removed == 0:
        return False, f"No Log Sentinel block found for '{canonical}'."
    new_text = "\n".join(kept)
    if not new_text.endswith("\n"):
        new_text += "\n"
    try:
        _write_hosts(new_text)
    except RuntimeError as e:
        from . import change_log
        change_log.record("hosts.remove_block", canonical, False, str(e))
        return False, str(e)
    _flush_dns()
    from . import change_log
    change_log.record(
        "hosts.remove_block", canonical, True,
        f"Removed {removed} hosts lines.",
        undo_hint=f"Block '{canonical}' again from the Firewall > Websites tab if needed.",
    )
    return True, f"Unblocked {canonical} ({removed} line{'s' if removed != 1 else ''} removed)."


def remove_all_blocks() -> tuple[int, int]:
    """Strip every Log Sentinel hosts entry. Returns (removed, kept)."""
    ok, _ = _ensure_admin()
    if not ok:
        return 0, 0
    text = _read_hosts()
    kept: list[str] = []
    removed = 0
    for line in text.splitlines():
        if MARKER in line:
            removed += 1
            continue
        kept.append(line)
    new_text = "\n".join(kept)
    if not new_text.endswith("\n"):
        new_text += "\n"
    try:
        _write_hosts(new_text)
    except RuntimeError:
        return 0, len(kept)
    _flush_dns()
    from . import change_log
    change_log.record(
        "hosts.remove_all_blocks", "all LogSentinel hosts blocks", True,
        f"Removed {removed} hosts entries.",
    )
    return removed, len(kept)


# ──────────────────────────────────────────────
# List
# ──────────────────────────────────────────────

def list_blocks() -> list[HostsBlock]:
    if not HOSTS_PATH.exists():
        return []
    return list_blocks_from_text(_read_hosts())


def list_blocks_from_text(text: str) -> list[HostsBlock]:
    """Parse a hosts file text and return one HostsBlock per blocked domain."""
    grouped: dict[str, HostsBlock] = {}
    for raw in text.splitlines():
        if MARKER not in raw:
            continue
        # Split off comment
        line, _, comment = raw.partition("#")
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        d = parts[1].lower()
        family = "ipv4" if ip in ("0.0.0.0", "127.0.0.1") else "ipv6"
        # Canonicalise www.foo.com → foo.com for grouping
        key = d[4:] if d.startswith("www.") else d
        # Parse marker comment: LogSentinel|date|note
        m = comment.strip()
        added = ""
        note = ""
        if m.startswith("LogSentinel|"):
            bits = m.split("|", 2)
            if len(bits) >= 2:
                added = bits[1]
            if len(bits) >= 3:
                note = bits[2]

        block = grouped.setdefault(
            key, HostsBlock(domain=key, added=added, note=note),
        )
        if d not in block.variants:
            block.variants.append(d)
        if family not in block.families:
            block.families.append(family)
        # Prefer earliest "added" date; preserve note if not set yet
        if not block.added and added:
            block.added = added
        if not block.note and note:
            block.note = note
    return sorted(grouped.values(), key=lambda b: b.domain)
