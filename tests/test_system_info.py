import unittest

from src.system_collector import SystemInfo


class SystemInfoModelTests(unittest.TestCase):
    def test_extended_system_info_defaults_are_safe(self):
        info = SystemInfo(
            hostname="PC",
            os="Windows",
            user="user",
            boot_time="now",
        )

        self.assertEqual(info.gpus, [])
        self.assertEqual(info.disks, [])
        self.assertEqual(info.battery, {})
        self.assertEqual(info.ram_total_gb, 0.0)


if __name__ == "__main__":
    unittest.main()
