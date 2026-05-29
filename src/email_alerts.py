"""
SMTP email alerts.

Stores config in ~/.log_sentinel/email_config.json. After every scan, if
any Critical or High finding is present and email is enabled, sends a
short summary to the configured recipients.

App passwords are recommended over real passwords (Gmail, Outlook all
require this for SMTP). We store the password in plaintext on disk —
that's an acceptable trade-off for a single-machine tool, but documented
clearly in the UI.
"""

from __future__ import annotations

import json
import smtplib
import socket
from dataclasses import asdict, dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR


CONFIG_FILE = PREFS_DIR / "email_config.json"


@dataclass
class EmailConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password: str = ""           # plaintext (app password recommended)
    from_address: str = ""
    to_addresses: list[str] = field(default_factory=list)
    only_critical_high: bool = True


# ──────────────────────────────────────────────
# Config storage
# ──────────────────────────────────────────────

def load_config() -> EmailConfig:
    if not CONFIG_FILE.exists():
        return EmailConfig()
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return EmailConfig(
            enabled=data.get("enabled", False),
            smtp_host=data.get("smtp_host", ""),
            smtp_port=int(data.get("smtp_port", 587)),
            use_tls=data.get("use_tls", True),
            username=data.get("username", ""),
            password=data.get("password", ""),
            from_address=data.get("from_address", ""),
            to_addresses=data.get("to_addresses", []) or [],
            only_critical_high=data.get("only_critical_high", True),
        )
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return EmailConfig()


def save_config(cfg: EmailConfig) -> None:
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(asdict(cfg), indent=2), encoding="utf-8")


# ──────────────────────────────────────────────
# Send
# ──────────────────────────────────────────────

def _build_message(cfg: EmailConfig, subject: str, body: str) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg.from_address or cfg.username
    msg["To"] = ", ".join(cfg.to_addresses)
    msg.attach(MIMEText(body, "plain", "utf-8"))
    return msg


def _send(cfg: EmailConfig, subject: str, body: str) -> tuple[bool, str]:
    if not cfg.smtp_host:
        return False, "SMTP host not set."
    if not cfg.to_addresses:
        return False, "No recipients configured."
    msg = _build_message(cfg, subject, body)

    try:
        if cfg.use_tls:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as s:
                s.ehlo()
                s.starttls()
                s.ehlo()
                if cfg.username:
                    s.login(cfg.username, cfg.password)
                s.send_message(msg)
        else:
            with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=15) as s:
                if cfg.username:
                    s.login(cfg.username, cfg.password)
                s.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        return False, f"SMTP error: {e}"
    return True, f"Sent to {', '.join(cfg.to_addresses)}."


def send_test() -> tuple[bool, str]:
    cfg = load_config()
    if not cfg.smtp_host:
        return False, "Configure SMTP first."
    return _send(cfg,
                 "Log Sentinel — test email",
                 (f"This is a test from Log Sentinel running on "
                  f"{socket.gethostname()}.\n\n"
                  f"If you got this, your SMTP configuration is working.\n"
                  f"Sent at: {datetime.now().isoformat()}\n"))


def send_findings_alert(findings: list, score: int, grade: str) -> tuple[bool, str]:
    cfg = load_config()
    if not cfg.enabled:
        return False, "Email alerts disabled."
    if not cfg.smtp_host or not cfg.to_addresses:
        return False, "Email not configured."

    if cfg.only_critical_high:
        crits = [f for f in findings if f.severity in ("Critical", "High")]
    else:
        crits = list(findings)

    if not crits:
        return False, "No findings to send."

    host = socket.gethostname()
    subject = f"[Log Sentinel] {len(crits)} alert(s) on {host}"

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    lines: list[str] = [
        f"Log Sentinel scan summary — {datetime.now().isoformat()}",
        f"Host: {host}",
        f"Health: {score}/100 (Grade {grade})",
        "",
        "Findings by severity:",
    ]
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        if by_sev.get(sev):
            lines.append(f"  {sev:<10} {by_sev[sev]}")

    lines.append("")
    lines.append(f"Top {min(10, len(crits))} active alerts:")
    for f in crits[:10]:
        ts = f.timestamp.strftime("%Y-%m-%d %H:%M")
        lines.append(f"  • [{f.severity}] {f.title}  ({ts})")

    if len(crits) > 10:
        lines.append(f"  …and {len(crits) - 10} more.")

    lines += [
        "",
        "Open Log Sentinel on this machine for details and remediation.",
        "",
        "— Log Sentinel",
    ]

    return _send(cfg, subject, "\n".join(lines))


# ──────────────────────────────────────────────
# Common SMTP presets
# ──────────────────────────────────────────────

PRESETS = {
    "Gmail":         {"smtp_host": "smtp.gmail.com",      "smtp_port": 587, "use_tls": True},
    "Outlook":       {"smtp_host": "smtp.office365.com",  "smtp_port": 587, "use_tls": True},
    "Yahoo":         {"smtp_host": "smtp.mail.yahoo.com", "smtp_port": 587, "use_tls": True},
    "iCloud":        {"smtp_host": "smtp.mail.me.com",    "smtp_port": 587, "use_tls": True},
    "Custom":        {"smtp_host": "",                    "smtp_port": 587, "use_tls": True},
}
