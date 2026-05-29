import unittest
from unittest.mock import patch

from src.collector import LogEvent
from src.detection_pipeline import run_detection


class DetectionPipelineTests(unittest.TestCase):
    def test_pipeline_sorts_findings_from_multiple_layers(self):
        with patch("src.detection_pipeline.scan_everyday", return_value=[]), \
             patch("src.custom_rules.evaluate", return_value=[]), \
             patch("src.fim.scan", return_value=[]), \
             patch("src.honeypots.scan", return_value=[]):
            findings = run_detection(
                events=[],
                processes=[],
                connections=[],
                autoruns=[],
                include_baseline=False,
            )

        self.assertEqual(findings, [])

    def test_pipeline_can_include_file_scan_paths(self):
        with patch("src.detection_pipeline.scan_everyday", return_value=[]), \
             patch("src.custom_rules.evaluate", return_value=[]), \
             patch("src.fim.scan", return_value=[]), \
             patch("src.honeypots.scan", return_value=[]), \
             patch("src.file_scanner.scan_paths") as scan_paths:
            scan_paths.return_value = []
            run_detection(
                events=[],
                processes=[],
                connections=[],
                autoruns=[],
                file_scan_paths=["fake_malware_lab"],
                include_baseline=False,
            )

        scan_paths.assert_called_once_with(["fake_malware_lab"])


if __name__ == "__main__":
    unittest.main()
