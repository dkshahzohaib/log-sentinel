"""
Persists each scan to disk so we can show trends and "what's new since last scan."
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .preferences import PREFS_DIR


HISTORY_DIR = PREFS_DIR / "history"
HISTORY_INDEX = HISTORY_DIR / "index.json"


@dataclass
class ScanSummary:
    timestamp: str        # ISO-8601 UTC
    score: int
    grade: str
    severity_counts: dict[str, int]   # {Critical: 1, High: 2, ...}
    user_categories: dict[str, int]   # {Security: 4, Privacy: 3, ...}
    total_findings: int
    total_events: int
    total_processes: int
    total_connections: int
    file: str             # relative filename of the saved finding fingerprints


def _load_index() -> list[ScanSummary]:
    if not HISTORY_INDEX.exists():
        return []
    try:
        data = json.loads(HISTORY_INDEX.read_text(encoding="utf-8"))
        return [ScanSummary(**d) for d in data]
    except (OSError, json.JSONDecodeError, TypeError):
        return []


def _save_index(items: list[ScanSummary]) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_INDEX.write_text(
        json.dumps([asdict(s) for s in items], indent=2),
        encoding="utf-8",
    )


def save_scan(
    health_score,
    findings: list,
    total_events: int,
    total_processes: int,
    total_connections: int,
) -> ScanSummary:
    """Append a scan to history. Saves a list of finding fingerprints to a file."""
    from .preferences import fingerprint
    from .plain_english import explain

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    sev_counts: dict[str, int] = {}
    cat_counts: dict[str, int] = {}
    fingerprints: list[dict] = []
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        ucat = explain(f.rule).user_category
        cat_counts[ucat] = cat_counts.get(ucat, 0) + 1
        fingerprints.append({
            "fp": fingerprint(f),
            "severity": f.severity,
            "rule": f.rule,
            "title": f.title,
        })

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    fname = f"scan_{ts}.json"
    (HISTORY_DIR / fname).write_text(
        json.dumps(fingerprints, indent=2),
        encoding="utf-8",
    )

    summary = ScanSummary(
        timestamp=datetime.utcnow().isoformat(),
        score=health_score.score,
        grade=health_score.grade,
        severity_counts=sev_counts,
        user_categories=cat_counts,
        total_findings=len(findings),
        total_events=total_events,
        total_processes=total_processes,
        total_connections=total_connections,
        file=fname,
    )

    items = _load_index()
    items.append(summary)
    # Keep only last 100 scans
    items = items[-100:]
    _save_index(items)
    return summary


def load_history() -> list[ScanSummary]:
    return _load_index()


def diff_against_last(current_findings: list) -> dict:
    """
    Compare the current scan to the previous saved scan.
    Returns: { "new": [titles], "resolved": [titles], "unchanged": int }
    """
    from .preferences import fingerprint

    items = _load_index()
    if len(items) < 1:
        return {"new": [], "resolved": [], "unchanged": 0, "is_first_scan": True}

    # The MOST recent saved scan is what we compare against.
    last = items[-1]
    last_file = HISTORY_DIR / last.file
    if not last_file.exists():
        return {"new": [], "resolved": [], "unchanged": 0, "is_first_scan": True}

    try:
        last_findings = json.loads(last_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"new": [], "resolved": [], "unchanged": 0, "is_first_scan": True}

    last_fps = {f["fp"]: f["title"] for f in last_findings}
    current_fps = {fingerprint(f): f.title for f in current_findings}

    new = [current_fps[fp] for fp in current_fps if fp not in last_fps]
    resolved = [last_fps[fp] for fp in last_fps if fp not in current_fps]
    unchanged = len(set(current_fps.keys()) & set(last_fps.keys()))

    return {
        "new":       new,
        "resolved":  resolved,
        "unchanged": unchanged,
        "is_first_scan": False,
        "last_score": last.score,
        "last_timestamp": last.timestamp,
    }


def trend_data(n: int = 30) -> list[tuple[str, int]]:
    """Last N (timestamp, score) pairs for the trend chart."""
    items = _load_index()[-n:]
    return [(s.timestamp, s.score) for s in items]


def clear_history() -> None:
    if HISTORY_INDEX.exists():
        HISTORY_INDEX.unlink()
    if HISTORY_DIR.exists():
        for f in HISTORY_DIR.glob("scan_*.json"):
            try:
                f.unlink()
            except OSError:
                pass
