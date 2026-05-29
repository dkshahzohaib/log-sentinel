import unittest

from src.firewall_manager import FirewallRule, is_dangerous_block, validate_ip, validate_port
from src.hosts_manager import canonicalize


class ValidatorTests(unittest.TestCase):
    def test_firewall_ip_validation_accepts_cidr(self):
        ok, value = validate_ip("192.168.1.1/24")

        self.assertTrue(ok)
        self.assertEqual(value, "192.168.1.0/24")

    def test_firewall_port_validation_rejects_out_of_range(self):
        ok, value = validate_port("70000")

        self.assertFalse(ok)
        self.assertIn("Port must be", value)

    def test_dangerous_outbound_block_warns(self):
        warning = is_dangerous_block(FirewallRule(name="bad", direction="out", remote_ip="any", remote_port="any"))

        self.assertIsNotNone(warning)

    def test_hosts_canonicalize_strips_scheme_and_www(self):
        ok, domain = canonicalize("https://www.Example.com/path")

        self.assertTrue(ok)
        self.assertEqual(domain, "example.com")


if __name__ == "__main__":
    unittest.main()
