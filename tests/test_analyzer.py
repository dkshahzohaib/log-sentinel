import unittest
from datetime import datetime, timedelta, timezone

from src.analyzer import analyze
from src.collector import LogEvent


def event(event_id, minutes=0, user="user", **extra):
    return LogEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc) + timedelta(minutes=minutes),
        channel="Security",
        level="Info",
        source="test",
        computer="TEST-PC",
        message=f"Event {event_id}",
        user=user,
        extra=extra,
    )


class AnalyzerTests(unittest.TestCase):
    def test_brute_force_by_user_and_ip(self):
        events = [
            event(4625, i, TargetUserName="Administrator", IpAddress="203.0.113.10")
            for i in range(5)
        ]

        findings = analyze(events)
        rules = {f.rule for f in findings}

        self.assertIn("brute_force_login", rules)
        self.assertIn("brute_force_from_ip", rules)

    def test_audit_log_clear_is_critical(self):
        findings = analyze([
            event(1102, SubjectUserName="intruder"),
        ])

        self.assertEqual(findings[0].rule, "audit_log_cleared")
        self.assertEqual(findings[0].severity, "Critical")

    def test_suspicious_powershell_scriptblock(self):
        findings = analyze([
            event(4104, ScriptBlockText="powershell -enc SQBFAFgA downloadstring iex("),
        ])

        self.assertTrue(any(f.rule == "powershell_encoded" for f in findings))


if __name__ == "__main__":
    unittest.main()
