"""
Baseline and diff support.

This catches the SOC question users care about most: "what changed since the
last scan?" We focus on relatively stable, security-relevant surfaces instead
of noisy process churn: autoruns, services, scheduled tasks, and listening
ports.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .analyzer import Finding
from .preferences import PREFS_DIR


BASELINE_FILE = PREFS_DIR / "baseline.json"


@dataclass(frozen=True)
class BaselineItem:
    kind: str
    key: str
    label: str
    severity: str
    description: str


def _stable_key(*parts: object) -> str:
    raw = "|".join(str(p or "").strip().lower() for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]


def _as_items(
    autoruns: Iterable = (),
    services: Iterable = (),
    tasks: Iterable = (),
    connections: Iterable = (),
) -> list[BaselineItem]:
    items: list[BaselineItem] = []

    for a in autoruns or []:
        key = _stable_key("autorun", getattr(a, "location", ""), getattr(a, "name", ""), getattr(a, "command", ""))
        label = f"Autorun: {getattr(a, 'name', 'unknown')}"
        items.append(BaselineItem(
            kind="autorun",
            key=key,
            label=label,
            severity="High",
            description=(
                f"New startup entry observed at {getattr(a, 'location', 'unknown')}: "
                f"{getattr(a, 'command', '')}"
            ),
        ))

    for s in services or []:
        service_path = getattr(s, "binary_path", "") or getattr(s, "path", "")
        key = _stable_key("service", getattr(s, "name", ""), service_path, getattr(s, "start_type", ""))
        label = f"Service: {getattr(s, 'name', 'unknown')}"
        items.append(BaselineItem(
            kind="service",
            key=key,
            label=label,
            severity="Medium",
            description=(
                f"New or changed service observed: {getattr(s, 'name', 'unknown')} "
                f"({getattr(s, 'display_name', '')}). Path: {service_path}"
            ),
        ))

    for t in tasks or []:
        task_action = getattr(t, "task_to_run", "") or getattr(t, "status", "")
        key = _stable_key("task", getattr(t, "name", ""), task_action)
        label = f"Scheduled task: {getattr(t, 'name', 'unknown')}"
        items.append(BaselineItem(
            kind="task",
            key=key,
            label=label,
            severity="Medium",
            description=(
                f"New or changed scheduled task observed: {getattr(t, 'name', 'unknown')}. "
                f"Status/action: {task_action}"
            ),
        ))

    for c in connections or []:
        if getattr(c, "state", "") != "LISTENING":
            continue
        local_port = getattr(c, "local_port", 0)
        if not local_port:
            continue
        key = _stable_key("listener", getattr(c, "proto", ""), local_port, getattr(c, "pid", 0), getattr(c, "process", ""))
        proc = getattr(c, "process", "") or f"PID {getattr(c, 'pid', 0)}"
        items.append(BaselineItem(
            kind="listener",
            key=key,
            label=f"Listener: {getattr(c, 'proto', '')}/{local_port}",
            severity="Low",
            description=f"New listening port observed: {getattr(c, 'proto', '')}/{local_port} ({proc}).",
        ))

    return items


def load_snapshot() -> dict[str, dict]:
    if not BASELINE_FILE.exists():
        return {}
    try:
        data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    items = data.get("items", {})
    return items if isinstance(items, dict) else {}


def save_snapshot(
    autoruns: Iterable = (),
    services: Iterable = (),
    tasks: Iterable = (),
    connections: Iterable = (),
) -> int:
    """Persist the current baseline. Returns number of tracked items."""
    items = _as_items(
        autoruns=autoruns,
        services=services,
        tasks=tasks,
        connections=connections,
    )
    data = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "items": {item.key: asdict(item) for item in items},
    }
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return len(items)


def diff_snapshot(
    autoruns: Iterable = (),
    services: Iterable = (),
    tasks: Iterable = (),
    connections: Iterable = (),
    persist: bool = True,
) -> list[Finding]:
    """
    Compare current snapshot to the saved baseline. On first run, saves a
    baseline and returns no findings.
    """
    previous = load_snapshot()
    current_items = _as_items(
        autoruns=autoruns,
        services=services,
        tasks=tasks,
        connections=connections,
    )
    current = {item.key: item for item in current_items}

    if not BASELINE_FILE.exists():
        if persist:
            save_snapshot(autoruns=autoruns, services=services, tasks=tasks, connections=connections)
        return []

    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    for key, item in current.items():
        if key in previous:
            continue
        findings.append(Finding(
            rule=f"baseline_new_{item.kind}",
            severity=item.severity,
            title=f"New since last baseline: {item.label}",
            description=item.description,
            events=[],
            timestamp=now,
        ))

    if persist:
        save_snapshot(autoruns=autoruns, services=services, tasks=tasks, connections=connections)
    return findings


def reset() -> None:
    try:
        BASELINE_FILE.unlink()
    except FileNotFoundError:
        pass
