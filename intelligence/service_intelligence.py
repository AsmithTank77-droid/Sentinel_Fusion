"""
intelligence/service_intelligence.py — Network service threat knowledge base.
Provides service risk scores, threat descriptions, CVEs, and MITRE attack phases
for use in enrichment (Stage 3) and scoring (Stage 7).

Adapted from nmap-recon-analyzer/service_intelligence.py and threat_context.py.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Service risk scores (0-10 scale, used by scoring/host_risk.py)
# ---------------------------------------------------------------------------
SERVICE_RISK: dict[str, int] = {
    "rdp":           9,
    "vnc":           8,
    "telnet":        9,
    "ssh":           5,
    "ftp":           7,
    "tftp":          7,
    "smb":           8,
    "netbios-ssn":   7,
    "http":          4,
    "https":         3,
    "http-proxy":    5,
    "mysql":         8,
    "postgresql":    8,
    "mssql":         8,
    "oracle":        8,
    "redis":         7,
    "mongodb":       7,
    "elasticsearch": 7,
    "smtp":          5,
    "pop3":          5,
    "imap":          5,
    "domain":        4,
    "snmp":          6,
    "ntp":           2,
    "ldap":          6,
    "ldaps":         5,
    "msrpc":         6,
    "nfs":           7,
    "unknown":       4,
}

# ---------------------------------------------------------------------------
# High-risk port numbers (port → common service name for display)
# ---------------------------------------------------------------------------
HIGH_RISK_PORTS: dict[int, str] = {
    23:    "Telnet",
    111:   "RPCBind",
    135:   "MS-RPC",
    139:   "NetBIOS",
    445:   "SMB",
    512:   "rexec",
    513:   "rlogin",
    514:   "rsh",
    1433:  "MSSQL",
    2049:  "NFS",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# ---------------------------------------------------------------------------
# Dangerous service combinations — each match raises attack surface score
# ---------------------------------------------------------------------------
DANGEROUS_COMBOS: list[tuple[frozenset, str]] = [
    (frozenset({"smb",  "rdp"}),   "SMB + RDP — classic ransomware staging environment"),
    (frozenset({"rdp",  "mssql"}), "RDP + MSSQL — Windows server with exposed DB and remote desktop"),
    (frozenset({"rdp",  "vnc"}),   "RDP + VNC — dual remote-desktop paths, high takeover risk"),
    (frozenset({"smb",  "telnet"}), "SMB + Telnet — cleartext credentials combined with file sharing"),
    (frozenset({"ssh",  "ftp"}),   "SSH + FTP — dual remote-access paths increase attack surface"),
    (frozenset({"ssh",  "mysql"}), "SSH + MySQL — Linux database server exposed, lateral-movement risk"),
    (frozenset({"http", "mysql"}), "HTTP + MySQL — web app with exposed database layer"),
    (frozenset({"ftp",  "http"}),  "FTP + HTTP — file upload via FTP may expose the web root"),
    (frozenset({"http", "smb"}),   "HTTP + SMB — pivot from web compromise to internal shares"),
]

# Services whose simultaneous presence raises concentration risk
DANGEROUS_SERVICES: set[str] = {
    "rdp", "smb", "telnet", "vnc", "ftp",
    "mssql", "mysql", "redis", "mongodb",
}

# ---------------------------------------------------------------------------
# Threat descriptions per service (for enrichment metadata)
# ---------------------------------------------------------------------------
THREAT_MAP: dict[str, str] = {
    "ssh":           "Brute-force attacks target SSH to gain shell access; compromised keys enable silent persistence.",
    "telnet":        "Cleartext credential interception — telnet transmits credentials in plaintext.",
    "rdp":           "Top ransomware entry point; credential stuffing and BlueKeep (CVE-2019-0708) enable unauthenticated RCE.",
    "vnc":           "VNC frequently ships with no password or a weak single password. Cleartext transmission exposes sessions.",
    "ftp":           "Commonly allows anonymous login; credentials travel in cleartext. vsftpd 2.3.4 backdoor (CVE-2011-1137).",
    "tftp":          "No authentication. Attackers can retrieve network device configs or stage payloads.",
    "smb":           "EternalBlue (CVE-2017-0144) and SMBGhost (CVE-2020-0796) enable unauthenticated RCE. Primary WannaCry/NotPetya vector.",
    "netbios-ssn":   "Exposes host and workgroup names, facilitates NTLM relay attacks.",
    "nfs":           "Misconfigured exports allow any host to mount and read/write sensitive data without credentials.",
    "http":          "SQL injection, XSS, directory traversal, and CMS exploitation. Credentials submitted over HTTP are trivially intercepted.",
    "https":         "Same risks as HTTP plus TLS misconfigurations: Heartbleed (CVE-2014-0160), POODLE, weak cipher suites.",
    "http-proxy":    "Unauthenticated proxy allows attackers to pivot to internal networks or use as a C2 relay.",
    "mysql":         "Often ships with an anonymous user or empty root password. UDF injection enables OS-level RCE.",
    "postgresql":    "COPY TO/FROM PROGRAM enables OS command execution (CVE-2019-9193).",
    "mssql":         "xp_cmdshell enables direct OS command execution from SQL.",
    "redis":         "No auth by default. CONFIG SET allows writing arbitrary files, enabling SSH key injection and cron persistence.",
    "mongodb":       "No auth by default until 3.x. Ransomware bots actively scan port 27017.",
    "elasticsearch": "No auth by default. Dynamic scripting in older versions enables RCE (CVE-2015-1427).",
    "smtp":          "Open relay enables spam/phishing origination. VRFY/EXPN commands leak valid usernames.",
    "pop3":          "Transmits passwords in plaintext on port 110.",
    "imap":          "Sends credentials in plaintext on port 143.",
    "domain":        "Misconfigured DNS allows full zone transfers. SIGRed (CVE-2020-1350) enables unauthenticated RCE.",
    "snmp":          "Default community strings (public/private) expose full device configuration.",
    "ldap":          "Anonymous LDAP binds expose all users, groups, computers, and OUs — feeds BloodHound and Kerberoasting.",
    "ldaps":         "Encrypted LDAP still exposes directory to queries if bind controls are not enforced.",
    "msrpc":         "RPC endpoint enumeration. DCOM RPC buffer overflow (Blaster CVE-2003-0352). Anonymous sessions leak domain info.",
    "ntp":           "NTP monlist (CVE-2013-5211) enables DDoS amplification attacks.",
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK attack phases per service
# ---------------------------------------------------------------------------
ATTACK_PHASES: dict[str, list[str]] = {
    "ssh":     ["Initial Access", "Lateral Movement", "Persistence"],
    "rdp":     ["Initial Access", "Lateral Movement"],
    "smb":     ["Lateral Movement", "Execution", "Collection"],
    "ftp":     ["Initial Access", "Collection"],
    "telnet":  ["Initial Access"],
    "vnc":     ["Initial Access", "Lateral Movement"],
    "mysql":   ["Collection", "Execution"],
    "mssql":   ["Collection", "Execution"],
    "redis":   ["Persistence", "Execution"],
    "http":    ["Initial Access"],
    "https":   ["Initial Access"],
    "ldap":    ["Discovery"],
    "snmp":    ["Discovery"],
    "domain":  ["Discovery", "Collection"],
}

# ---------------------------------------------------------------------------
# Cleartext and anonymous-access risk flags
# ---------------------------------------------------------------------------
_CLEARTEXT_SERVICES: frozenset[str] = frozenset({
    "telnet", "ftp", "tftp", "http", "http-proxy",
    "smtp", "pop3", "imap", "snmp", "ldap", "netbios-ssn",
})

_ANONYMOUS_RISK_SERVICES: frozenset[str] = frozenset({
    "ftp", "tftp", "redis", "mongodb", "elasticsearch", "nfs", "snmp",
})

# ---------------------------------------------------------------------------
# Service categories  (service → (category, subcategory))
# ---------------------------------------------------------------------------
_SERVICE_CATEGORIES: dict[str, tuple[str, str]] = {
    "ssh":           ("Remote Access",      "Encrypted Shell"),
    "telnet":        ("Remote Access",      "Cleartext Shell"),
    "rdp":           ("Remote Access",      "Remote Desktop"),
    "vnc":           ("Remote Access",      "Remote Desktop"),
    "ftp":           ("File Transfer",      "Cleartext FTP"),
    "tftp":          ("File Transfer",      "Unauthenticated TFTP"),
    "smb":           ("File Sharing",       "Windows SMB"),
    "netbios-ssn":   ("File Sharing",       "NetBIOS"),
    "nfs":           ("File Sharing",       "Network File System"),
    "http":          ("Web Service",        "Unencrypted HTTP"),
    "https":         ("Web Service",        "Encrypted HTTPS"),
    "http-proxy":    ("Web Service",        "HTTP Proxy"),
    "mysql":         ("Database",           "MySQL"),
    "postgresql":    ("Database",           "PostgreSQL"),
    "mssql":         ("Database",           "MSSQL"),
    "oracle":        ("Database",           "Oracle DB"),
    "redis":         ("Database",           "In-Memory Store"),
    "mongodb":       ("Database",           "NoSQL"),
    "elasticsearch": ("Database",           "Search Engine"),
    "smtp":          ("Mail",               "Mail Transfer"),
    "pop3":          ("Mail",               "Mail Retrieval"),
    "imap":          ("Mail",               "Mail Access"),
    "domain":        ("Infrastructure",     "DNS"),
    "snmp":          ("Infrastructure",     "Network Management"),
    "ntp":           ("Infrastructure",     "Time Protocol"),
    "ldap":          ("Directory Services", "LDAP"),
    "ldaps":         ("Directory Services", "LDAPS"),
    "msrpc":         ("Windows Services",   "MS RPC"),
    "unknown":       ("Unknown",            ""),
}

# ---------------------------------------------------------------------------
# Notable CVEs per service
# ---------------------------------------------------------------------------
_NOTABLE_CVES: dict[str, list[str]] = {
    "ssh":           ["CVE-2023-38408", "CVE-2018-10933"],
    "rdp":           ["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"],
    "ftp":           ["CVE-2011-1137"],
    "smb":           ["CVE-2017-0144", "CVE-2020-0796"],
    "netbios-ssn":   ["CVE-2017-0144"],
    "https":         ["CVE-2014-0160"],
    "mysql":         ["CVE-2012-2122"],
    "postgresql":    ["CVE-2019-9193"],
    "elasticsearch": ["CVE-2015-1427", "CVE-2014-3120"],
    "domain":        ["CVE-2020-1350"],
    "snmp":          ["CVE-2013-5211"],
    "msrpc":         ["CVE-2003-0352"],
}

# ---------------------------------------------------------------------------
# Scanner name aliases → canonical service names
# ---------------------------------------------------------------------------
_SI_ALIASES: dict[str, str] = {
    "microsoft-ds":   "smb",
    "ms-wbt-server":  "rdp",
    "ms-sql-s":       "mssql",
    "netbios-ns":     "netbios-ssn",
    "http-alt":       "http",
    "http-rpc-epmap": "msrpc",
    "epmap":          "msrpc",
    "imaps":          "imap",
    "pop3s":          "pop3",
    "smtps":          "smtp",
    "submission":     "smtp",
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_service_risk(service: str) -> int:
    """Return base risk score (0-10) for a service name."""
    return SERVICE_RISK.get(service.lower(), SERVICE_RISK["unknown"])


def get_threat(service: str) -> str | None:
    """Return threat description for a service, or None if unknown."""
    return THREAT_MAP.get(service.lower())


def get_attack_phases(service: str) -> list[str]:
    """Return MITRE ATT&CK attack phases for a service."""
    return ATTACK_PHASES.get(service.lower(), [])


def is_high_risk_port(port: int) -> bool:
    return port in HIGH_RISK_PORTS


def check_dangerous_combos(services: set[str]) -> list[str]:
    """
    Return descriptions of all dangerous service combinations present.
    services: set of lowercase service name strings.
    """
    found = []
    for required, label in DANGEROUS_COMBOS:
        if required.issubset(services):
            found.append(label)
    return found


def analyze(service: str, port: int, risk_label: str = "") -> dict:
    """
    Return a structured intelligence dict for a service/port pair.
    Resolves scanner aliases to canonical names and surfaces cleartext,
    anonymous-access, CVE, and MITRE phase metadata.
    Consumed by reporting/recommended_actions.py.
    """
    raw = service.lower()
    svc = _SI_ALIASES.get(raw, raw)
    category, subcategory = _SERVICE_CATEGORIES.get(svc, ("Unknown", ""))
    cves = _NOTABLE_CVES.get(svc, [])
    return {
        "service":            svc,
        "category":           category,
        "subcategory":        subcategory,
        "protocol_cleartext": svc in _CLEARTEXT_SERVICES,
        "anonymous_risk":     svc in _ANONYMOUS_RISK_SERVICES,
        "attack_phases":      get_attack_phases(svc),
        "cve_prone":          bool(cves),
        "notable_cves":       cves,
        "enum_commands":      [],
        "hardening_checks":   [],
    }


def enrich_service(service: str, port: int) -> dict:
    """
    Return a combined enrichment dict for a service/port pair.
    Used by enrich.py to populate metadata["enrichment"]["services"].
    """
    svc = service.lower()
    return {
        "service":       svc,
        "port":          port,
        "risk_score":    get_service_risk(svc),
        "is_high_risk_port": is_high_risk_port(port),
        "threat":        get_threat(svc),
        "attack_phases": get_attack_phases(svc),
    }
