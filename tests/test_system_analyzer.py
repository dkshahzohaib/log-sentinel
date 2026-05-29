import unittest

from src.system_analyzer import analyze_network, analyze_processes
from src.system_collector import NetConnection, Process


class SystemAnalyzerTests(unittest.TestCase):
    def test_process_impersonation_is_critical(self):
        findings = analyze_processes([
            Process(
                pid=1234,
                name="svchost.exe",
                path=r"C:\Users\Public\svchost.exe",
            )
        ])

        self.assertTrue(any(f.rule == "process_name_spoof" and f.severity == "Critical" for f in findings))

    def test_suspicious_listener_is_high(self):
        findings = analyze_network([
            NetConnection(
                proto="TCP",
                local_addr="0.0.0.0",
                local_port=4444,
                remote_addr="0.0.0.0",
                remote_port=0,
                state="LISTENING",
                pid=99,
                process="listener.exe",
            )
        ])

        self.assertTrue(any(f.rule == "suspicious_listening_port" and f.severity == "High" for f in findings))


if __name__ == "__main__":
    unittest.main()
