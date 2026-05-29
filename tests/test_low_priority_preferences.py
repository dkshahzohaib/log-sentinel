import unittest
from types import SimpleNamespace

from src import preferences


class LowPriorityPreferencesTests(unittest.TestCase):
    def tearDown(self):
        preferences._cache = None

    def test_hide_mode_filters_low_and_info_from_active(self):
        preferences._cache = preferences.Preferences(low_priority_mode="hide")
        findings = [
            SimpleNamespace(rule="critical", title="Critical", severity="Critical"),
            SimpleNamespace(rule="low", title="Low", severity="Low"),
            SimpleNamespace(rule="info", title="Info", severity="Info"),
        ]

        active = preferences.filter_active(findings)

        self.assertEqual([f.severity for f in active], ["Critical"])
        self.assertEqual(preferences.low_priority_hidden_count(findings), 2)

    def test_show_mode_keeps_low_and_info(self):
        preferences._cache = preferences.Preferences(low_priority_mode="show")
        findings = [
            SimpleNamespace(rule="low", title="Low", severity="Low"),
            SimpleNamespace(rule="info", title="Info", severity="Info"),
        ]

        active = preferences.filter_active(findings)

        self.assertEqual(len(active), 2)
        self.assertEqual(preferences.low_priority_hidden_count(findings), 0)

    def test_min_severity_filters_below_sensitivity(self):
        preferences._cache = preferences.Preferences(
            low_priority_mode="show",
            min_severity="Medium",
        )
        findings = [
            SimpleNamespace(rule="info", title="Info", severity="Info"),
            SimpleNamespace(rule="low", title="Low", severity="Low"),
            SimpleNamespace(rule="medium", title="Medium", severity="Medium"),
            SimpleNamespace(rule="high", title="High", severity="High"),
        ]

        active = preferences.filter_active(findings)

        self.assertEqual([f.severity for f in active], ["Medium", "High"])
        self.assertEqual(preferences.low_priority_hidden_count(findings), 2)


if __name__ == "__main__":
    unittest.main()
