"""
intelligence/event_intelligence.py — Windows Event ID knowledge base.
Maps Event IDs to name, category, severity, MITRE ATT&CK technique, and analyst notes.
Adapted from winlog-soc-analyzer/event_intelligence.py.

Used by normalize.py (Stage 2) to enrich Winlog events with classification data.
"""
from __future__ import annotations

EVENT_KNOWLEDGE: dict[int, dict] = {

    # ---------------------------------------------------------------------------
    # Authentication
    # ---------------------------------------------------------------------------
    4624: {
        "name": "Successful Logon",
        "category": "authentication",
        "severity": "info",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "An account was successfully logged on.",
        "analyst_note": "Logon Type 3 (network) from unexpected source IPs warrants investigation.",
    },
    4625: {
        "name": "Failed Logon",
        "category": "authentication",
        "severity": "low",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "description": "An account failed to log on.",
        "analyst_note": "Repeated failures from the same source IP indicate brute force activity.",
    },
    4648: {
        "name": "Explicit Credential Logon",
        "category": "authentication",
        "severity": "medium",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "A logon was attempted using explicit credentials.",
        "analyst_note": "Common in lateral movement and credential reuse scenarios.",
    },
    4672: {
        "name": "Special Privileges Assigned",
        "category": "privilege_escalation",
        "severity": "medium",
        "mitre_technique": "T1078.002",
        "mitre_name": "Valid Accounts: Domain Accounts",
        "description": "Special privileges were assigned to a new logon.",
        "analyst_note": "Correlate with 4624 — admin logon immediately after user logon is suspicious.",
    },
    4740: {
        "name": "Account Locked Out",
        "category": "authentication",
        "severity": "medium",
        "mitre_technique": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "description": "A user account was locked out.",
        "analyst_note": "Multiple lockouts across different accounts may indicate a password spray attack.",
    },
    4771: {
        "name": "Kerberos Pre-Authentication Failed",
        "category": "credential_access",
        "severity": "low",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "description": "Kerberos pre-authentication failed for a user account.",
        "analyst_note": "Repeated failures across many accounts is a password spray indicator.",
    },
    4776: {
        "name": "NTLM Authentication Attempt",
        "category": "credential_access",
        "severity": "low",
        "mitre_technique": "T1550.002",
        "mitre_name": "Use Alternate Authentication Material: Pass the Hash",
        "description": "The domain controller attempted to validate NTLM credentials.",
        "analyst_note": "Repeated failures suggest pass-the-hash or credential stuffing.",
    },

    # ---------------------------------------------------------------------------
    # Kerberos
    # ---------------------------------------------------------------------------
    4768: {
        "name": "Kerberos TGT Requested",
        "category": "authentication",
        "severity": "info",
        "mitre_technique": "T1558",
        "mitre_name": "Steal or Forge Kerberos Tickets",
        "description": "A Kerberos authentication ticket (TGT) was requested.",
        "analyst_note": "Anomalous volume or off-hours requests warrant review.",
    },
    4769: {
        "name": "Kerberos Service Ticket Requested",
        "category": "credential_access",
        "severity": "medium",
        "mitre_technique": "T1558.003",
        "mitre_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "description": "A Kerberos service ticket was requested.",
        "analyst_note": "RC4 encryption (0x17) requests for service accounts are a Kerberoasting indicator.",
    },

    # ---------------------------------------------------------------------------
    # Remote Access
    # ---------------------------------------------------------------------------
    4778: {
        "name": "RDP Session Reconnected",
        "category": "lateral_movement",
        "severity": "low",
        "mitre_technique": "T1021.001",
        "mitre_name": "Remote Services: Remote Desktop Protocol",
        "description": "A session was reconnected to a Windows host using RDP.",
        "analyst_note": "Unexpected source IPs or off-hours reconnections may indicate unauthorized remote access.",
    },
    4779: {
        "name": "RDP Session Disconnected",
        "category": "lateral_movement",
        "severity": "info",
        "mitre_technique": "T1021.001",
        "mitre_name": "Remote Services: Remote Desktop Protocol",
        "description": "A session was disconnected from a Windows host using RDP.",
        "analyst_note": "Correlate with 4778 for full RDP session timeline.",
    },

    # ---------------------------------------------------------------------------
    # Execution
    # ---------------------------------------------------------------------------
    4688: {
        "name": "Process Created",
        "category": "execution",
        "severity": "info",
        "mitre_technique": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "description": "A new process has been created.",
        "analyst_note": "Flag cmd.exe, powershell.exe, wscript.exe launched by unusual parent processes.",
    },
    4104: {
        "name": "PowerShell Script Block Logged",
        "category": "execution",
        "severity": "high",
        "mitre_technique": "T1059.001",
        "mitre_name": "Command and Scripting Interpreter: PowerShell",
        "description": "A PowerShell script block was logged by script block logging.",
        "analyst_note": "Encoded commands, download cradles (IEX, WebClient), and AMSI bypass attempts are red flags.",
    },

    # ---------------------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------------------
    4697: {
        "name": "Service Installed (Security Log)",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1543.003",
        "mitre_name": "Create or Modify System Process: Windows Service",
        "description": "A service was installed in the system (Security channel).",
        "analyst_note": "Correlate with 7045 (System channel). Service installs by non-admin accounts are critical.",
    },
    4698: {
        "name": "Scheduled Task Created",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task",
        "description": "A scheduled task was created.",
        "analyst_note": "Attackers use scheduled tasks for persistence. Always review task content and author.",
    },
    4702: {
        "name": "Scheduled Task Updated",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task",
        "description": "A scheduled task was updated.",
        "analyst_note": "Modification of existing tasks can indicate an attacker hijacking persistence.",
    },
    7045: {
        "name": "New Service Installed (System Log)",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1543.003",
        "mitre_name": "Create or Modify System Process: Windows Service",
        "description": "A new service was installed in the system (System channel).",
        "analyst_note": "Malware frequently installs as a service for persistence and privilege.",
    },

    # ---------------------------------------------------------------------------
    # WMI Persistence
    # ---------------------------------------------------------------------------
    19: {
        "name": "WMI Filter Activity Detected",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1546.003",
        "mitre_name": "Event Triggered Execution: WMI Event Subscription",
        "description": "A WMI event filter was registered.",
        "analyst_note": "WMI event filters are the trigger component of a WMI subscription persistence mechanism.",
    },
    20: {
        "name": "WMI Consumer Activity Detected",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1546.003",
        "mitre_name": "Event Triggered Execution: WMI Event Subscription",
        "description": "A WMI event consumer was registered.",
        "analyst_note": "WMI consumers execute the attacker payload when the filter condition fires.",
    },
    21: {
        "name": "WMI Subscription Binding Detected",
        "category": "persistence",
        "severity": "critical",
        "mitre_technique": "T1546.003",
        "mitre_name": "Event Triggered Execution: WMI Event Subscription",
        "description": "A WMI filter was bound to a consumer, completing a WMI subscription.",
        "analyst_note": "Filter-to-consumer binding completes a persistent WMI backdoor. Treat as active incident.",
    },

    # ---------------------------------------------------------------------------
    # Account Management
    # ---------------------------------------------------------------------------
    4720: {
        "name": "User Account Created",
        "category": "persistence",
        "severity": "high",
        "mitre_technique": "T1136.001",
        "mitre_name": "Create Account: Local Account",
        "description": "A user account was created.",
        "analyst_note": "Unauthorized account creation is a strong persistence indicator.",
    },
    4722: {
        "name": "User Account Enabled",
        "category": "persistence",
        "severity": "medium",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "A user account was enabled.",
        "analyst_note": "Enabling a previously disabled account may indicate backdoor account activation.",
    },
    4725: {
        "name": "User Account Disabled",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1531",
        "mitre_name": "Account Access Removal",
        "description": "A user account was disabled.",
        "analyst_note": "Disabling accounts (especially admin accounts) can lock out defenders.",
    },
    4726: {
        "name": "User Account Deleted",
        "category": "defense_evasion",
        "severity": "high",
        "mitre_technique": "T1531",
        "mitre_name": "Account Access Removal",
        "description": "A user account was deleted.",
        "analyst_note": "Deleting accounts after use is a cleanup technique to hide attacker activity.",
    },
    4738: {
        "name": "User Account Changed",
        "category": "persistence",
        "severity": "medium",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "A user account was changed.",
        "analyst_note": "Password resets or privilege changes on service accounts are high-risk indicators.",
    },

    # ---------------------------------------------------------------------------
    # Privilege Escalation — Group Membership
    # ---------------------------------------------------------------------------
    4728: {
        "name": "Member Added to Global Security Group",
        "category": "privilege_escalation",
        "severity": "high",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "A member was added to a security-enabled global group.",
        "analyst_note": "Adding accounts to Domain Admins or other global privileged groups is a critical escalation.",
    },
    4732: {
        "name": "Member Added to Local Security Group",
        "category": "privilege_escalation",
        "severity": "high",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "A member was added to a security-enabled local group.",
        "analyst_note": "Adding accounts to Administrators group is a primary local escalation path.",
    },
    4756: {
        "name": "Member Added to Universal Security Group",
        "category": "privilege_escalation",
        "severity": "high",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "A member was added to a security-enabled universal group.",
        "analyst_note": "Universal groups often have broad domain-wide access. Review the group being modified.",
    },

    # ---------------------------------------------------------------------------
    # Defense Evasion
    # ---------------------------------------------------------------------------
    1100: {
        "name": "Event Log Service Shutdown",
        "category": "defense_evasion",
        "severity": "high",
        "mitre_technique": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs",
        "description": "The Windows Event Log service was shut down.",
        "analyst_note": "Intentional shutdown of event logging is a strong defense evasion indicator.",
    },
    1102: {
        "name": "Audit Log Cleared",
        "category": "defense_evasion",
        "severity": "critical",
        "mitre_technique": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs",
        "description": "The audit log was cleared.",
        "analyst_note": "Almost always malicious. Treat as active incident until proven otherwise.",
    },
    4616: {
        "name": "System Time Changed",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1070.006",
        "mitre_name": "Indicator Removal: Timestomp",
        "description": "The system time was changed.",
        "analyst_note": "Attackers modify system time to corrupt log timestamps and disrupt forensic timelines.",
    },
    4657: {
        "name": "Registry Value Modified",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1112",
        "mitre_name": "Modify Registry",
        "description": "A registry value was modified.",
        "analyst_note": "Run keys (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) are common persistence locations.",
    },
    4670: {
        "name": "Permissions on Object Changed",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1222",
        "mitre_name": "File and Directory Permissions Modification",
        "description": "Permissions on an object were changed.",
        "analyst_note": "ACL modifications on sensitive files or registry keys can enable persistence or privilege escalation.",
    },
    4719: {
        "name": "Audit Policy Changed",
        "category": "defense_evasion",
        "severity": "high",
        "mitre_technique": "T1562.002",
        "mitre_name": "Impair Defenses: Disable Windows Event Logging",
        "description": "System audit policy was changed.",
        "analyst_note": "Attackers disable auditing to blind defenders before executing actions.",
    },
    4946: {
        "name": "Firewall Rule Added",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1562.004",
        "mitre_name": "Impair Defenses: Disable or Modify System Firewall",
        "description": "A rule was added to the Windows Firewall exception list.",
        "analyst_note": "New inbound allow rules on uncommon ports can expose attack surface.",
    },
    4947: {
        "name": "Firewall Rule Modified",
        "category": "defense_evasion",
        "severity": "medium",
        "mitre_technique": "T1562.004",
        "mitre_name": "Impair Defenses: Disable or Modify System Firewall",
        "description": "A rule was modified in the Windows Firewall exception list.",
        "analyst_note": "Modification of existing rules is a subtler way to open firewall gaps.",
    },

    # ---------------------------------------------------------------------------
    # Collection
    # ---------------------------------------------------------------------------
    4663: {
        "name": "Object Access Attempt",
        "category": "collection",
        "severity": "low",
        "mitre_technique": "T1039",
        "mitre_name": "Data from Network Shared Drive",
        "description": "An attempt was made to access an object.",
        "analyst_note": "Bulk file access in short timeframes indicates staging or exfiltration prep.",
    },
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}

CATEGORIES: set[str] = {
    "authentication",
    "privilege_escalation",
    "execution",
    "persistence",
    "credential_access",
    "defense_evasion",
    "collection",
    "lateral_movement",
}

_UNKNOWN: dict = {
    "name":             "Unknown Event",
    "category":         "unknown",
    "severity":         "info",
    "mitre_technique":  "N/A",
    "mitre_name":       "N/A",
    "description":      "No intelligence available for this Event ID.",
    "analyst_note":     "",
}


def get_event(event_id: int) -> dict:
    """Return the intelligence record for event_id, or a neutral unknown record."""
    return EVENT_KNOWLEDGE.get(event_id, {**_UNKNOWN, "name": f"Event {event_id}"})


def is_known(event_id: int) -> bool:
    return event_id in EVENT_KNOWLEDGE
