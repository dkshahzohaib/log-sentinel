"""
Append-only audit trail for actions Log Sentinel takes on the user's machine.

Security tools earn trust by making changes traceable. This module records
firewall, hosts, scheduled-task, service, registry, and scan-baseline actions
under ~/.log_sentinel/change_log.jsonl.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .preferences import PREFS_DIR


CHANGE_LOG_FILE = PREFS_DIR / "change_log.jsonl"


@dataclass
class ChangeRecord:
    timestamp: str
    action: str
    target: str
    success: bool
    detail: str = ""
    undo_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def record(
    action: str,
    target: str,
    success: bool,
    detail: str = "",
    undo_hint: str = "",
    metadata: dict[str, Any] | None = None,
) -> ChangeRecord:
    """Append one action to the local audit log and return the record."""
    rec = ChangeRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action=action,
        target=target,
        success=success,
        detail=detail,
        undo_hint=undo_hint,
        metadata=metadata or {},
    )
    PREFS_DIR.mkdir(parents=True, exist_ok=True)
    with CHANGE_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
    return rec


def load(limit: int = 200) -> list[ChangeRecord]:
    """Load recent change records, newest last."""
    if not CHANGE_LOG_FILE.exists():
        return []
    records: list[ChangeRecord] = []
    try:
        lines = CHANGE_LOG_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        try:
            records.append(ChangeRecord(**json.loads(line)))
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def clear() -> None:
    """Clear the audit log. Intended for tests and explicit user reset only."""
    try:
        CHANGE_LOG_FILE.unlink()
    except FileNotFoundError:
        pass
