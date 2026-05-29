import unittest
from types import SimpleNamespace

from src.health_score import calculate


class HealthScoreTests(unittest.TestCase):
    def test_critical_findings_reduce_score_heavily(self):
        health = calculate([
            SimpleNamespace(severity="Critical"),
            SimpleNamespace(severity="High"),
            SimpleNamespace(severity="Low"),
        ])

        self.assertEqual(health.score, 62)
        self.assertEqual(health.grade, "C")

    def test_empty_findings_is_healthy(self):
        health = calculate([])

        self.assertEqual(health.score, 100)
        self.assertEqual(health.grade, "A")


if __name__ == "__main__":
    unittest.main()
