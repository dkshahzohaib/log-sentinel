"""
Shared detection orchestration for GUI, scheduled scans, and future CLI flows.

Keeping this in one place prevents the desktop scan and headless scan from
quietly running different rule sets.
"""

from __future__ import annotations

from .analyzer import SEVERITY_ORDER, analyze
from .system_analyzer import analyze_system
from .everyday_scanner import scan_everyday


def _sort_timestamp(finding):
    ts = getattr(finding, "timestamp", None)
    if ts is None:
        return ""
    return ts.isoformat()


def _safe(label: str, fn) -> list:
    try:
        return list(fn())
    except Exception as e:
        print(f"[!] {label} failed: {e}")
        return []


def _deduplicate(findings: list) -> list:
    seen: set[tuple[str, str]] = set()
    unique = []
    for finding in findings:
        key = (getattr(finding, "rule", ""), getattr(finding, "title", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def run_detection(
    *,
    events: list,
    processes: list,
    connections: list,
    autoruns: list,
    services: list | None = None,
    tasks: list | None = None,
    file_scan_paths: list | None = None,
    include_baseline: bool = True,
) -> list:
    """Run all detection layers and return severity-sorted findings."""
    from . import baseline, custom_rules, fim, honeypots

    findings = []
    findings.extend(_safe("Event analysis", lambda: analyze(events)))
    findings.extend(_safe("System analysis", lambda: analyze_system(processes, connections, autoruns)))
    findings.extend(_safe("Everyday scan", lambda: scan_everyday(processes)))
    findings.extend(_safe("Custom rules", lambda: custom_rules.evaluate(processes, connections, autoruns, events)))
    findings.extend(_safe("FIM scan", fim.scan))
    findings.extend(_safe("Honeypot scan", honeypots.scan))
    if file_scan_paths:
        from . import file_scanner
        findings.extend(_safe("File scan", lambda: file_scanner.scan_paths(file_scan_paths)))

    if include_baseline:
        findings.extend(_safe("Baseline diff", lambda: baseline.diff_snapshot(
            autoruns=autoruns,
            services=services or [],
            tasks=tasks or [],
            connections=connections,
        )))

    return sorted(
        _deduplicate(findings),
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), _sort_timestamp(f)),
        reverse=True,
    )
