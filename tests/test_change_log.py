import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import change_log


class ChangeLogTests(unittest.TestCase):
    def test_record_and_load(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "change_log.jsonl"
            with patch.object(change_log, "CHANGE_LOG_FILE", path):
                rec = change_log.record(
                    "firewall.add_rule",
                    "LogSentinel_Test",
                    True,
                    "created",
                    undo_hint="delete rule",
                )
                loaded = change_log.load()

                self.assertEqual(rec.action, "firewall.add_rule")
                self.assertEqual(len(loaded), 1)
                self.assertEqual(loaded[0].target, "LogSentinel_Test")
                self.assertEqual(loaded[0].undo_hint, "delete rule")


if __name__ == "__main__":
    unittest.main()
