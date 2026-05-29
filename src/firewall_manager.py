"""
Wraps Windows Firewall (netsh advfirewall) so users can:

  - Block or allow a remote IP (single, range, CIDR, or comma-list)
  - Optionally restrict by port + protocol
  - Pick direction (inbound, outbound, or both)
  - List rules they've added through this app
  - Delete rules

Every rule we create is prefixed "LogSentinel_" so we can find / clean up
our own rules without touching system ones. Adding rules requires Admin.
"""

from __future__ import annotations

import ctypes
import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass, field


RULE_PREFIX = "LogSentinel_"


@dataclass
class FirewallRule:
    name: str
    direction: str = "out"        # "in" | "out"
    action: str = "block"         # "block" | "allow"
    protocol: str = "any"         # "TCP" | "UDP" | "any"
    remote_ip: str = "any"        # IP / CIDR / "any"
    remote_port: str = "any"      # number / range / "any"
    local_port: str = "any"
    enabled: bool = True
    description: str = ""


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


def _run(cmd: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        flags = 0x08000000 if platform.system() == "Windows" else 0
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=flags,
        )
        ok = result.returncode == 0
        msg = (result.stdout if ok else (result.stderr or result.stdout)).strip()
        return ok, msg
    except FileNotFoundError as e:
        return False, f"Command not found: {e}"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except OSError as e:
        return False, str(e)


def validate_ip(value: str) -> tuple[bool, str]:
    """Validate IP / CIDR / 'any'. Returns (ok, normalised_or_error)."""
    if not value or value.strip().lower() == "any":
        return True, "any"
    value = value.strip()
    parts = [p.strip() for p in value.split(",") if p.strip()]
    out_parts: list[str] = []
    for p in parts:
        # CIDR
        try:
            net = ipaddress.ip_network(p, strict=False)
            out_parts.append(str(net))
            continue
        except ValueError:
            pass
        # Range like 192.168.1.10-192.168.1.20
        if "-" in p:
            lo, _, hi = p.partition("-")
            try:
                ipaddress.ip_address(lo.strip())
                ipaddress.ip_address(hi.strip())
                out_parts.append(f"{lo.strip()}-{hi.strip()}")
                continue
            except ValueError:
                pass
        # Single IP
        try:
            ipaddress.ip_address(p)
            out_parts.append(p)
            continue
        except ValueError:
            return False, f"Not a valid IP / range / CIDR: '{p}'"
    return True, ",".join(out_parts)


def validate_port(value: str) -> tuple[bool, str]:
    """Validate port / range / 'any'. Returns (ok, normalised_or_error)."""
    if not value or value.strip().lower() == "any":
        return True, "any"
    value = value.strip()
    parts = [p.strip() for p in value.split(",") if p.strip()]
    out: list[str] = []
    for p in parts:
        if "-" in p:
            a, _, b = p.partition("-")
            try:
                ai, bi = int(a), int(b)
                if not (1 <= ai <= 65535 and 1 <= bi <= 65535 and ai <= bi):
                    raise ValueError
                out.append(f"{ai}-{bi}")
                continue
            except ValueError:
                return False, f"Invalid port range: '{p}'"
        try:
            n = int(p)
            if not 1 <= n <= 65535:
                return False, f"Port must be 1–65535: '{p}'"
            out.append(str(n))
        except ValueError:
            return False, f"Not a port number: '{p}'"
    return True, ",".join(out)


def is_dangerous_block(rule: FirewallRule) -> str | None:
    """Warn if a rule could lock the user out. Returns message or None."""
    if rule.action != "block":
        return None
    ip = rule.remote_ip.lower()
    port = rule.remote_port

    if ip in ("any", ""):
        if rule.direction == "in" and port in ("any", "*"):
            return ("This rule blocks ALL inbound traffic from the internet. "
                    "It may break Windows Update, file sharing, and remote access.")
        if rule.direction == "out" and port in ("any", "*"):
            return ("This rule blocks ALL outbound traffic. "
                    "Browsers, email, Windows Update — everything will fail. "
                    "Are you sure?")
    return None


# ──────────────────────────────────────────────
# Add / delete
# ──────────────────────────────────────────────

def add_rule(rule: FirewallRule) -> tuple[bool, str]:
    if not is_admin():
        return False, ("Adding firewall rules requires Administrator. "
                       "Right-click LAUNCH-as-admin.bat and run as administrator.")

    name = rule.name if rule.name.startswith(RULE_PREFIX) else RULE_PREFIX + rule.name
    name = re.sub(r'[\\/:"*?<>|]', "_", name)[:120]

    # Validate
    ok, ip_norm = validate_ip(rule.remote_ip)
    if not ok:
        return False, ip_norm
    ok, port_norm = validate_port(rule.remote_port)
    if not ok:
        return False, port_norm

    directions = []
    if rule.direction in ("in", "out"):
        directions = [rule.direction]
    elif rule.direction == "both":
        directions = ["in", "out"]
    else:
        return False, f"direction must be in/out/both, got '{rule.direction}'"

    protocol = rule.protocol.upper()
    if protocol not in ("TCP", "UDP", "ANY"):
        return False, f"protocol must be TCP/UDP/any, got '{rule.protocol}'"

    messages: list[str] = []
    for d in directions:
        rule_name = name + ("_in" if d == "in" else "_out") if rule.direction == "both" else name
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={d}",
            f"action={rule.action}",
            "enable=" + ("yes" if rule.enabled else "no"),
        ]
        if protocol != "ANY":
            cmd.append(f"protocol={protocol}")
        if ip_norm != "any":
            cmd.append(f"remoteip={ip_norm}")
        if port_norm != "any" and protocol != "ANY":
            cmd.append(f"remoteport={port_norm}")
        if rule.description:
            cmd.append(f"description={rule.description[:255]}")

        ok, msg = _run(cmd)
        if not ok:
            from . import change_log
            change_log.record(
                "firewall.add_rule", rule_name, False, msg,
                metadata={"direction": d, "remote_ip": ip_norm, "remote_port": port_norm},
            )
            return False, f"Failed creating {rule_name}: {msg}"
        from . import change_log
        change_log.record(
            "firewall.add_rule", rule_name, True, "Rule created.",
            undo_hint=f"Delete firewall rule '{rule_name}' from the Firewall tab.",
            metadata={"direction": d, "remote_ip": ip_norm, "remote_port": port_norm},
        )
        messages.append(f"Added {rule_name}")

    return True, "\n".join(messages)


def delete_rule(name: str) -> tuple[bool, str]:
    if not is_admin():
        return False, "Need Administrator to delete firewall rules."
    ok, msg = _run([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ])
    detail = msg or (f"Deleted {name}" if ok else "Delete failed")
    from . import change_log
    change_log.record(
        "firewall.delete_rule", name, ok, detail,
        undo_hint="Recreate the rule from the Firewall tab if needed.",
    )
    return ok, detail


def delete_all_sentinel_rules() -> tuple[int, int]:
    """Delete every rule whose name starts with LogSentinel_. Returns (deleted, failed)."""
    rules = list_sentinel_rules()
    succ = fail = 0
    for r in rules:
        ok, _ = delete_rule(r.name)
        if ok:
            succ += 1
        else:
            fail += 1
    return succ, fail


# ──────────────────────────────────────────────
# List / parse
# ──────────────────────────────────────────────

def list_sentinel_rules() -> list[FirewallRule]:
    """Pull rules whose names start with LogSentinel_."""
    return _list_rules(name_filter=RULE_PREFIX + "*")


def list_all_rules() -> list[FirewallRule]:
    return _list_rules()


def _list_rules(name_filter: str = "all") -> list[FirewallRule]:
    cmd = ["netsh", "advfirewall", "firewall", "show", "rule",
           f"name={name_filter}", "verbose"]
    ok, out = _run(cmd, timeout=30)
    if not ok or not out.strip():
        return []

    rules: list[FirewallRule] = []
    current: dict[str, str] = {}

    def flush():
        if not current.get("name"):
            return
        # Only keep our rules unless asked for all
        if name_filter != "all" and not current["name"].startswith(RULE_PREFIX):
            return
        rules.append(FirewallRule(
            name=current.get("name", ""),
            direction="in" if current.get("direction", "").lower().startswith("in") else "out",
            action=current.get("action", "").lower() or "block",
            protocol=current.get("protocol", "any").upper(),
            remote_ip=current.get("remoteip", "any") or "any",
            remote_port=current.get("remoteport", "any") or "any",
            local_port=current.get("localport", "any") or "any",
            enabled=current.get("enabled", "yes").lower().startswith("y"),
            description=current.get("description", ""),
        ))

    for raw in out.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if line.startswith("Rule Name:"):
            flush()
            current = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "")
            val = val.strip()
            if key in ("enabled", "direction", "action", "protocol",
                      "remoteip", "remoteport", "localport", "description"):
                current[key] = val
    flush()
    return rules


# ──────────────────────────────────────────────
# Convenience builders
# ──────────────────────────────────────────────

def quick_block_ip(ip: str, port: str = "any", direction: str = "out",
                   protocol: str = "any") -> FirewallRule:
    name = f"Block_{ip}".replace("/", "_").replace(":", "_")
    if port not in ("any", "", "*"):
        name += f"_p{port}"
    return FirewallRule(
        name=name,
        direction=direction,
        action="block",
        protocol=protocol,
        remote_ip=ip,
        remote_port=port,
        description=f"Blocked by Log Sentinel: {ip} ({port})",
    )


def quick_allow_ip(ip: str, port: str = "any", direction: str = "out",
                   protocol: str = "any") -> FirewallRule:
    name = f"Allow_{ip}".replace("/", "_").replace(":", "_")
    if port not in ("any", "", "*"):
        name += f"_p{port}"
    return FirewallRule(
        name=name,
        direction=direction,
        action="allow",
        protocol=protocol,
        remote_ip=ip,
        remote_port=port,
        description=f"Allowed by Log Sentinel: {ip} ({port})",
    )
