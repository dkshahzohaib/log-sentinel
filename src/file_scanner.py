"""
Lightweight local file scanner for suspicious test artifacts and common red flags.

This is not antivirus. It gives Log Sentinel a safe way to spot obvious risky
files in user-selected folders and to validate detections against harmless lab
samples such as the EICAR test marker.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .analyzer import Finding


EICAR_MARKER = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
SUSPICIOUS_NAMES = {
    "mimikatz", "rubeus", "cobaltstrike", "meterpreter", "bloodhound",
    "procdump", "psexec", "pwdump", "gsecdump", "fgdump",
}
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"}
SUSPICIOUS_TEXT_PATTERNS = {
    "-enc": "PowerShell encoded command flag",
    "frombase64string": "Base64 decode behavior",
    "downloadstring": "PowerShell download cradle",
    "invoke-expression": "PowerShell dynamic execution",
    "iex(": "PowerShell dynamic execution",
    "sekurlsa": "Credential dumping keyword",
}


def _read_small_text(path: Path, max_bytes: int = 512_000) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def scan_paths(paths: list[str | Path], recursive: bool = True) -> list[Finding]:
    """Scan selected paths and return suspicious-file findings."""
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    for raw in paths:
        base = Path(raw)
        if not base.exists():
            continue
        files = base.rglob("*") if base.is_dir() and recursive else [base]
        for path in files:
            if not path.is_file():
                continue

            name_l = path.name.lower()
            suffix_l = path.suffix.lower()
            text = _read_small_text(path)
            text_l = text.lower()

            if EICAR_MARKER.lower() in text_l:
                findings.append(Finding(
                    rule="test_malware_marker",
                    severity="Critical",
                    title=f"Antivirus test marker detected: {path.name}",
                    description=(
                        f"{path} contains the harmless EICAR-style antivirus "
                        "test marker. This is not real malware, but it proves "
                        "file scanning can raise a high-confidence alert."
                    ),
                    events=[],
                    timestamp=now,
                ))
                continue

            matched_name = next((word for word in SUSPICIOUS_NAMES if word in name_l), "")
            if matched_name:
                findings.append(Finding(
                    rule="suspicious_file_name",
                    severity="High",
                    title=f"Suspicious tool name found: {path.name}",
                    description=(
                        f"{path} contains '{matched_name}' in the filename. "
                        "This may be a benign lab file, but the name matches a "
                        "tool commonly seen in offensive security or intrusions."
                    ),
                    events=[],
                    timestamp=now,
                ))

            if suffix_l in SCRIPT_EXTENSIONS:
                hits = [reason for pattern, reason in SUSPICIOUS_TEXT_PATTERNS.items()
                        if pattern in text_l]
                if hits:
                    findings.append(Finding(
                        rule="suspicious_script_file",
                        severity="High",
                        title=f"Suspicious script content: {path.name}",
                        description=f"{path} matched: {', '.join(sorted(set(hits)))}.",
                        events=[],
                        timestamp=now,
                    ))

    return sorted(findings, key=lambda f: f.severity, reverse=True)
