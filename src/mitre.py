"""
Maps detection rules to MITRE ATT&CK techniques.
This is what real SOC tools do — gives findings a vendor-grade lineage.

Reference: https://attack.mitre.org/
"""

from dataclasses import dataclass


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    url: str = ""

    def __post_init__(self):
        if not self.url:
            self.url = f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}"


# Tactics (kill-chain phases)
TACTICS = {
    "Initial Access":          "TA0001",
    "Execution":               "TA0002",
    "Persistence":             "TA0003",
    "Privilege Escalation":    "TA0004",
    "Defense Evasion":         "TA0005",
    "Credential Access":       "TA0006",
    "Discovery":               "TA0007",
    "Lateral Movement":        "TA0008",
    "Collection":              "TA0009",
    "Command and Control":     "TA0011",
    "Exfiltration":            "TA0010",
    "Impact":                  "TA0040",
}


# Rule name → ATT&CK technique
RULE_TO_TECHNIQUE: dict[str, AttackTechnique] = {
    "brute_force_login": AttackTechnique(
        "T1110", "Brute Force", "Credential Access"),
    "brute_force_from_ip": AttackTechnique(
        "T1110.001", "Password Guessing", "Credential Access"),
    "audit_log_cleared": AttackTechnique(
        "T1070.001", "Clear Windows Event Logs", "Defense Evasion"),
    "privilege_escalation": AttackTechnique(
        "T1134", "Access Token Manipulation", "Privilege Escalation"),
    "new_user_created": AttackTechnique(
        "T1136.001", "Create Local Account", "Persistence"),
    "user_added_to_admin_group": AttackTechnique(
        "T1098", "Account Manipulation", "Persistence"),
    "new_service_installed": AttackTechnique(
        "T1543.003", "Windows Service", "Persistence"),
    "suspicious_process": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution"),
    "suspicious_process_critical": AttackTechnique(
        "T1003", "OS Credential Dumping", "Credential Access"),
    "powershell_encoded": AttackTechnique(
        "T1059.001", "PowerShell", "Execution"),
    "scheduled_task_created": AttackTechnique(
        "T1053.005", "Scheduled Task", "Persistence"),
    "account_locked_out": AttackTechnique(
        "T1110", "Brute Force", "Credential Access"),
    "firewall_rule_changed": AttackTechnique(
        "T1562.004", "Disable or Modify System Firewall", "Defense Evasion"),
    "off_hours_logon": AttackTechnique(
        "T1078", "Valid Accounts", "Initial Access"),
    "system_crash": AttackTechnique(
        "T1499", "Endpoint Denial of Service", "Impact"),
    "suspicious_listening_port": AttackTechnique(
        "T1571", "Non-Standard Port", "Command and Control"),
    "uncommon_listening_port": AttackTechnique(
        "T1571", "Non-Standard Port", "Command and Control"),
    "external_connection": AttackTechnique(
        "T1071", "Application Layer Protocol", "Command and Control"),
    "suspicious_autorun": AttackTechnique(
        "T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    "process_in_temp": AttackTechnique(
        "T1036.005", "Match Legitimate Name or Location", "Defense Evasion"),
    "process_name_spoof": AttackTechnique(
        "T1036.005", "Masquerading", "Defense Evasion"),
    "remote_access_tool": AttackTechnique(
        "T1219", "Remote Access Software", "Command and Control"),
    "new_process_observed": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution"),
    "new_external_connection": AttackTechnique(
        "T1071", "Application Layer Protocol", "Command and Control"),
    "ioc_match_ip": AttackTechnique(
        "T1071", "Application Layer Protocol", "Command and Control"),
    "ioc_match_process": AttackTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution"),
}


def technique_for_rule(rule: str) -> AttackTechnique | None:
    return RULE_TO_TECHNIQUE.get(rule)


def technique_short(rule: str) -> str:
    """Returns short ID like 'T1110' for display in tables."""
    t = RULE_TO_TECHNIQUE.get(rule)
    return t.technique_id if t else "—"
