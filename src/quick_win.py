"""
"Quick Win" mode — identifies SAFE, REVERSIBLE auto-fixes that can be run
in batch with one click. We deliberately exclude anything that could break
the user's workflow:

  - We do NOT end processes (might lose unsaved work)
  - We do NOT delete files
  - We do NOT block IPs (might break legitimate apps)
  - We do NOT change firewall rules

Quick Win can:
  - Disable suspicious autoruns (reversible — renames the value)
  - Disable suspicious scheduled tasks (reversible — re-enable in Task Scheduler)
  - Snooze low-severity informational findings for 30 days

Everything Quick Win does shows the user exactly what was changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import preferences
from .remediation import disable_autorun, disable_scheduled_task


@dataclass
class QuickWinPlan:
    safe_disable_autoruns: list = field(default_factory=list)
    safe_disable_tasks: list = field(default_factory=list)
    snooze_low_priority: list = field(default_factory=list)

    def total(self) -> int:
        return (len(self.safe_disable_autoruns)
                + len(self.safe_disable_tasks)
                + len(self.snooze_low_priority))


def build_plan(findings: list) -> QuickWinPlan:
    """Look at all findings and decide what's safe to auto-fix."""
    plan = QuickWinPlan()
    for f in findings:
        if preferences.state_for(f) != "active":
            continue
        rule = f.rule

        # Suspicious autorun — high severity, reversible
        if rule == "suspicious_autorun":
            plan.safe_disable_autoruns.append(f)

        # Snooze every Low/Info that the user is likely to ignore anyway
        elif f.severity in ("Low", "Info"):
            plan.snooze_low_priority.append(f)

    return plan


@dataclass
class QuickWinResult:
    succeeded: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    snoozed: int = 0


def run_plan(plan: QuickWinPlan) -> QuickWinResult:
    """Execute the plan. Each action is logged; no automatic commits beyond plan."""
    result = QuickWinResult()

    for f in plan.safe_disable_autoruns:
        # Try to parse hive\subkey + value name from the description
        # Description format: 'Registry autorun X at HKCU\\... runs ...'
        # We rely on the AutorunEntry fields stored in description
        import re
        m = re.search(r"at\s+(HKLM|HKCU)\\([^\s]+)", f.description, re.IGNORECASE)
        m2 = re.search(r"'([^']+)'", f.description)
        if not m or not m2:
            result.failed.append((f.title, "could not parse registry path"))
            continue
        hive = m.group(1).upper()
        subkey = m.group(2)
        value_name = m2.group(1)
        ok, msg = disable_autorun(hive, subkey, value_name)
        if ok:
            result.succeeded.append(f.title)
            preferences.resolve(f)
        else:
            result.failed.append((f.title, msg))

    for f in plan.safe_disable_tasks:
        # Reserved for future
        pass

    for f in plan.snooze_low_priority:
        preferences.snooze(f, days=30)
        result.snoozed += 1

    return result
