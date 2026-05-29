"""
Local threat intelligence module.

Maintains hardcoded indicators of compromise (IOCs) and a fast lookup API.
Real products subscribe to commercial feeds (CrowdStrike, AlienVault OTX, etc.)
or pull from MISP. Here we ship a curated baseline so the tool is useful
offline — and any user can extend it by editing this file or dropping a
JSON file at iocs.json next to it.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class IocMatch:
    ioc_type: str          # "ip", "domain", "process", "port", "ip_range"
    indicator: str
    description: str
    severity: str          # Critical / High / Medium / Low


# ──────────────────────────────────────────────
# Built-in IOC database
# ──────────────────────────────────────────────

# Known TOR exit node ranges (small sample — real product would auto-update)
TOR_RANGES = [
    "185.220.100.0/22",
    "185.220.101.0/24",
    "185.220.102.0/24",
    "199.249.230.0/24",
    "204.85.191.0/24",
    "171.25.193.0/24",
    "23.129.64.0/24",
]

# Known bulletproof / abuse-prone hosting ranges
SUSPICIOUS_RANGES = [
    "5.188.86.0/24",
    "45.227.255.0/24",
    "194.5.249.0/24",
    "91.219.236.0/22",
]

# Specific IPs flagged as known C2 / scanners
MALICIOUS_IPS = {
    # (placeholder — would normally come from a feed)
}

# Suspicious TLDs commonly used by malware
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free TLDs abused by phishing
    ".top", ".xyz", ".click", ".loan",
    ".onion",                            # TOR hidden services
}

# Domain patterns indicating DGA (domain-generation algorithms)
DGA_PATTERN = re.compile(r"^[a-z0-9]{16,}\.(com|net|org|info|biz)$")

# Process names that should never appear on a normal user system
MALICIOUS_PROCESS_NAMES = {
    "mimikatz.exe":        ("Critical", "Credential dumper"),
    "mimikatz":            ("Critical", "Credential dumper"),
    "procdump.exe":        ("High",     "Memory dumping (LSASS abuse)"),
    "wce.exe":             ("Critical", "Windows Credential Editor"),
    "pwdump.exe":          ("Critical", "Password hash dumper"),
    "fgdump.exe":          ("Critical", "Password hash dumper"),
    "gsecdump.exe":        ("Critical", "Credential dumper"),
    "ncat.exe":            ("High",     "Reverse-shell tool"),
    "nc.exe":              ("High",     "Netcat — pen-test / reverse shell"),
    "psexec.exe":          ("Medium",   "Lateral movement (legitimate but abused)"),
    "lazagne.exe":         ("Critical", "Credential harvester"),
    "rubeus.exe":          ("Critical", "Kerberos abuse / Golden Ticket"),
    "bloodhound.exe":      ("High",     "AD reconnaissance"),
    "sharphound.exe":      ("High",     "AD reconnaissance ingestor"),
    "covenant.exe":        ("Critical", "C2 framework"),
    "cobaltstrike.exe":    ("Critical", "C2 framework"),
    "empire.exe":          ("Critical", "Post-exploitation framework"),
    "metasploit.exe":      ("Critical", "Exploitation framework"),
    "havoc.exe":           ("Critical", "C2 framework"),
}

# Suspicious command-line patterns (substrings, lower-case)
MALICIOUS_CMD_PATTERNS = [
    ("invoke-mimikatz",     "Critical", "Mimikatz invoked via PowerShell"),
    ("invoke-bloodhound",   "High",     "BloodHound recon"),
    ("downloadstring",      "High",     "PowerShell download cradle"),
    ("downloadfile",        "Medium",   "PowerShell download"),
    ("frombase64string",    "Medium",   "Encoded PowerShell payload"),
    ("net user /add",       "High",     "Account creation via cmd"),
    ("vssadmin delete",     "Critical", "Shadow-copy deletion (ransomware)"),
    ("wbadmin delete",      "Critical", "Backup deletion (ransomware)"),
    ("bcdedit /set",        "High",     "Boot config tampering"),
    ("schtasks /create",    "Medium",   "Scheduled task creation"),
    ("certutil -urlcache",  "High",     "LOLBAS download via certutil"),
    ("bitsadmin /transfer", "High",     "LOLBAS download via BITS"),
    ("rundll32 javascript", "High",     "JavaScript via rundll32"),
    ("regsvr32 /s /n /u",   "High",     "Squiblydoo bypass"),
    ("wmic process call",   "Medium",   "WMIC for execution"),
    ("powershell -enc",     "High",     "Encoded PowerShell command"),
    ("powershell -nop",     "Medium",   "PowerShell with NoProfile"),
    ("powershell -w hidden", "Medium",  "Hidden PowerShell window"),
]


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def _load_external_iocs() -> dict:
    """Load custom IOCs from iocs.json beside this file (if present)."""
    p = Path(__file__).parent / "iocs.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


_external = _load_external_iocs()
_ext_ips = set(_external.get("ips", []))
_ext_domains = set(_external.get("domains", []))


def check_ip(ip: str) -> IocMatch | None:
    """Return an IocMatch if ip is in any known-bad list, else None."""
    if not ip:
        return None
    if ip in MALICIOUS_IPS or ip in _ext_ips:
        return IocMatch("ip", ip, "Known malicious IP", "Critical")
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return None

    for net in TOR_RANGES:
        try:
            if addr in ipaddress.ip_network(net):
                return IocMatch("ip_range", ip, f"TOR exit node ({net})", "High")
        except ValueError:
            continue

    for net in SUSPICIOUS_RANGES:
        try:
            if addr in ipaddress.ip_network(net):
                return IocMatch("ip_range", ip,
                                f"Bulletproof hosting range ({net})", "Medium")
        except ValueError:
            continue
    return None


def check_domain(domain: str) -> IocMatch | None:
    if not domain:
        return None
    domain = domain.lower().strip(".")
    if domain in _ext_domains:
        return IocMatch("domain", domain, "Known malicious domain", "Critical")
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return IocMatch("domain", domain,
                            f"Suspicious TLD ({tld})", "Medium")
    if DGA_PATTERN.match(domain):
        return IocMatch("domain", domain,
                        "Possible DGA (domain-generation algorithm)", "High")
    return None


def check_process(name: str, cmdline: str = "") -> IocMatch | None:
    """Check a process name + cmdline against known-bad indicators."""
    if not name:
        return None
    n = name.lower()
    if n in MALICIOUS_PROCESS_NAMES:
        sev, desc = MALICIOUS_PROCESS_NAMES[n]
        return IocMatch("process", name, desc, sev)

    if cmdline:
        cl = cmdline.lower()
        for pattern, sev, desc in MALICIOUS_CMD_PATTERNS:
            if pattern in cl:
                return IocMatch("command", pattern, desc, sev)
    return None


def stats() -> dict:
    """Quick summary of the loaded IOC corpus."""
    return {
        "tor_ranges":             len(TOR_RANGES),
        "suspicious_ranges":      len(SUSPICIOUS_RANGES),
        "malicious_ips":          len(MALICIOUS_IPS) + len(_ext_ips),
        "suspicious_tlds":        len(SUSPICIOUS_TLDS),
        "malicious_processes":    len(MALICIOUS_PROCESS_NAMES),
        "command_patterns":       len(MALICIOUS_CMD_PATTERNS),
        "external_domains":       len(_ext_domains),
    }
