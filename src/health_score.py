"""
Calculates an overall PC health score (0–100) and a verdict line for the user.

The score subtracts points based on findings — Critical hits hurt the most.
We deliberately keep this simple and transparent — users can see WHY their
score is low.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass
class HealthScore:
    score: int               # 0–100
    grade: str               # A / B / C / D / F
    verdict: str             # one-line summary
    color: str               # hex for the gauge
    detail: str              # short paragraph explaining the score


# Severity → points lost
PENALTY = {
    "Critical": 25,
    "High":     12,
    "Medium":    5,
    "Low":       1,
    "Info":      0,
}


def calculate(findings: Iterable) -> HealthScore:
    """findings is an iterable of objects with a .severity attribute."""
    findings = list(findings)
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    score = 100
    for sev, n in counts.items():
        score -= PENALTY.get(sev, 0) * n

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A"
        verdict = "Your computer looks healthy."
        color = "#4ecdc4"
        detail = (
            "We didn't find anything serious. Keep Windows updated, run "
            "antivirus regularly, and you're in good shape."
        )
    elif score >= 80:
        grade = "B"
        verdict = "A few minor things to look at."
        color = "#6dd5ed"
        detail = (
            "Nothing scary, but there are some small issues worth cleaning up. "
            "Check the Recommended Actions list."
        )
    elif score >= 60:
        grade = "C"
        verdict = "Some real concerns — please review."
        color = "#ffd93d"
        detail = (
            "We found things that need your attention. Most are easy fixes. "
            "Don't ignore them — small problems become big ones."
        )
    elif score >= 30:
        grade = "D"
        verdict = "Multiple problems found. Take action soon."
        color = "#ff7f50"
        detail = (
            "Your computer has several security or stability issues. "
            "Work through the Recommended Actions list before doing anything sensitive (banking, etc.)."
        )
    else:
        grade = "F"
        verdict = "⚠ Serious threats detected. Act now."
        color = "#ff4757"
        detail = (
            "We found indicators of compromise. Do NOT enter passwords or use "
            "online banking until you fix these. If you're unsure, disconnect "
            "from the internet and follow the steps in each finding."
        )

    return HealthScore(
        score=score, grade=grade, verdict=verdict,
        color=color, detail=detail,
    )


def top_actions(findings: list, n: int = 5) -> list:
    """Return the top N most-impactful findings (Critical/High first)."""
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    return sorted(findings, key=lambda f: order.get(f.severity, 0), reverse=True)[:n]
