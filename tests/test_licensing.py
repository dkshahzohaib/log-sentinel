import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

from src import licensing


class LicensingTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.old_dir = licensing.PREFS_DIR
        self.old_file = licensing.LICENSE_FILE
        licensing.PREFS_DIR = Path(self.td.name)
        licensing.LICENSE_FILE = Path(self.td.name) / "license.json"

    def tearDown(self):
        licensing.PREFS_DIR = self.old_dir
        licensing.LICENSE_FILE = self.old_file

    def test_new_install_gets_30_day_trial(self):
        with patch.object(licensing, "_today", return_value=date(2026, 5, 14)):
            status = licensing.status()
        self.assertTrue(status.can_run)
        self.assertEqual(status.mode, "trial")
        self.assertEqual(status.trial_expires, "2026-06-13")

    def test_expired_trial_requires_key(self):
        with patch.object(licensing, "_today", return_value=date(2026, 5, 14)):
            licensing.status()
        with patch.object(licensing, "_today", return_value=date(2026, 6, 14)):
            status = licensing.status()
        self.assertFalse(status.can_run)
        self.assertEqual(status.mode, "expired")

    def test_monthly_key_activates_and_expires(self):
        email = "customer@example.com"
        key = licensing.create_license_key(
            email,
            expires=date(2026, 6, 13),
        )
        with patch.object(licensing, "_today", return_value=date(2026, 5, 14)):
            status = licensing.activate(email, key)
        self.assertTrue(status.can_run)
        self.assertEqual(status.mode, "licensed")
        self.assertEqual(status.license_expires, "2026-06-13")

        with patch.object(licensing, "_today", return_value=date(2026, 6, 14)):
            status = licensing.status()
        self.assertFalse(status.can_run)
        self.assertEqual(status.mode, "expired")

    def test_key_email_must_match(self):
        key = licensing.create_license_key(
            "buyer@example.com",
            expires=date.today() + timedelta(days=30),
        )
        with self.assertRaises(ValueError):
            licensing.activate("other@example.com", key)

    def test_device_locked_key_only_activates_on_matching_pc(self):
        email = "device@example.com"
        with patch.object(licensing, "device_fingerprint", return_value="abc123"):
            key = licensing.create_license_key(
                email,
                expires=date.today() + timedelta(days=30),
                device="abc123",
            )
            status = licensing.activate(email, key)
        self.assertTrue(status.can_run)
        self.assertEqual(status.mode, "licensed")

        with patch.object(licensing, "device_fingerprint", return_value="different"):
            status = licensing.status()
        self.assertEqual(status.mode, "trial")

        with patch.object(licensing, "device_fingerprint", return_value="different"):
            with self.assertRaises(ValueError):
                licensing.activate(email, key)


if __name__ == "__main__":
    unittest.main()
