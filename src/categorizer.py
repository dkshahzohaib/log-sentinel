"""
Maps Windows Event IDs and rule names to human-readable categories.
Used by the GUI to group events and findings.
"""

CATEGORIES = [
    "Authentication",
    "Account Management",
    "Process Activity",
    "Network",
    "Services",
    "Persistence",
    "Audit / Tampering",
    "Privilege",
    "Firewall",
    "PowerShell",
    "Object Access",
    "System",
    "Application",
    "Other",
]

CATEGORY_COLORS = {
    "Authentication":     "#3498db",
    "Account Management": "#9b59b6",
    "Process Activity":   "#e67e22",
    "Network":            "#1abc9c",
    "Services":           "#16a085",
    "Persistence":        "#e74c3c",
    "Audit / Tampering":  "#c0392b",
    "Privilege":          "#d35400",
    "Firewall":           "#2c3e50",
    "PowerShell":         "#8e44ad",
    "Object Access":      "#34495e",
    "System":             "#7f8c8d",
    "Application":        "#95a5a6",
    "Other":              "#bdc3c7",
}

# Event ID → Category
EVENT_CATEGORIES = {
    # Auth
    4624: "Authentication", 4625: "Authentication", 4634: "Authentication",
    4647: "Authentication", 4648: "Authentication", 4649: "Authentication",
    4740: "Authentication", 4767: "Authentication",

    # Privilege
    4672: "Privilege", 4673: "Privilege", 4674: "Privilege",

    # Account management
    4720: "Account Management", 4722: "Account Management",
    4723: "Account Management", 4724: "Account Management",
    4725: "Account Management", 4726: "Account Management",
    4727: "Account Management", 4728: "Account Management",
    4732: "Account Management", 4735: "Account Management",
    4737: "Account Management", 4738: "Account Management",
    4756: "Account Management",

    # Process
    4688: "Process Activity", 4689: "Process Activity",

    # Services / persistence
    4697: "Services", 7045: "Services",
    4698: "Persistence", 4699: "Persistence", 4700: "Persistence",
    4701: "Persistence", 4702: "Persistence",

    # Audit / tampering
    1102: "Audit / Tampering", 104: "Audit / Tampering", 4719: "Audit / Tampering",

    # Firewall / network
    4946: "Firewall", 4947: "Firewall", 4948: "Firewall",
    5156: "Network", 5157: "Network",

    # PowerShell
    4103: "PowerShell", 4104: "PowerShell",

    # Object access
    4663: "Object Access", 4670: "Object Access",

    # System
    6005: "System", 6006: "System", 6008: "System", 6009: "System",
}

# Rule name → category (for findings)
RULE_CATEGORIES = {
    "brute_force_login": "Authentication",
    "brute_force_from_ip": "Authentication",
    "audit_log_cleared": "Audit / Tampering",
    "privilege_escalation": "Privilege",
    "new_user_created": "Account Management",
    "user_added_to_admin_group": "Account Management",
    "new_service_installed": "Services",
    "suspicious_process": "Process Activity",
    "suspicious_process_critical": "Process Activity",
    "powershell_encoded": "PowerShell",
    "scheduled_task_created": "Persistence",
    "account_locked_out": "Authentication",
    "firewall_rule_changed": "Firewall",
    "off_hours_logon": "Authentication",
    "system_crash": "System",
    "suspicious_listening_port": "Network",
    "external_connection": "Network",
    "suspicious_autorun": "Persistence",
    "process_in_temp": "Process Activity",
    "process_name_spoof": "Process Activity",
    "uncommon_listening_port": "Network",
    "remote_access_tool": "Network",
}


def category_for_event_id(eid: int) -> str:
    return EVENT_CATEGORIES.get(eid, "Other")


def category_for_rule(rule: str) -> str:
    return RULE_CATEGORIES.get(rule, "Other")
