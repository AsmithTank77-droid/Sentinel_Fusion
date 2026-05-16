"""
reporting/recommended_actions.py — SOC Recommended Actions engine.

Adapted from nmap-recon-analyzer/recommended_actions_engine.py for
Sentinel_Fusion's reporting layer.

Consumes structured scan data produced by report_generator._build_nra_scan_data()
and produces a per-host SOC triage report with service context, risk rationale,
immediate action steps, and CVE references.

Public API
----------
generate_recommendations(scan_data) → list[dict]

Output schema per host:
  {
    "ip":                   str,
    "overall_risk_level":   str,
    "overall_host_summary": str,
    "recommendations": [
      {
        "port":              int,
        "protocol":          str,
        "service":           str,
        "category":          str,
        "subcategory":       str,
        "risk_level":        str,
        "priority":          int,   # 1 (Critical) → 5 (Informational)
        "service_context":   str,
        "risk_rationale":    str,
        "action_taken":      str,
        "enumeration_steps": list,
        "hardening_checks":  list,
        "notable_cves":      list,
        "flags":             list,
      }
    ]
  }
"""
from __future__ import annotations

from intelligence.service_intelligence import analyze as _si_analyze

# ---------------------------------------------------------------------------
# Priority: 1 = immediate (Critical) → 5 = routine (Informational)
# ---------------------------------------------------------------------------
_PRIORITY_MAP: dict[str, int] = {
    "Critical":      1,
    "High":          2,
    "Medium":        3,
    "Low":           4,
    "Informational": 5,
}

# ---------------------------------------------------------------------------
# SOC context per service
# ---------------------------------------------------------------------------
_SOC_CONTEXT: dict[str, dict] = {

    "ssh": {
        "service_context": (
            "Encrypted remote shell access. Primary system administration method on Linux/Unix "
            "systems. Targeted for credential brute-force, key theft, and as a pivot point "
            "for lateral movement."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Record SSH version. Confirm key-based authentication is enforced. "
                "Verify access is restricted to authorised source IPs."
            ),
            "Medium": (
                "Enumerate supported authentication methods and cipher algorithms. Review "
                "sshd_config for PasswordAuthentication=no and PermitRootLogin=no. "
                "Validate host key fingerprint against a known-good baseline."
            ),
            "High": (
                "Audit auth logs for brute-force activity (auth.log / syslog). Review all "
                "authorized_keys files across every user account on the host. Confirm "
                "MaxAuthTries <= 3. Restrict access via AllowUsers or network-level firewall rule."
            ),
            "Critical": (
                "Treat as active compromise risk. Immediately review SSH session logs and "
                "running process list. Verify OpenSSH version against CVE-2023-38408 and "
                "CVE-2018-10933. Engage incident response if any unauthorised sessions are found."
            ),
        },
    },

    "telnet": {
        "service_context": (
            "Unencrypted remote shell transmitting all data — including credentials — in "
            "cleartext over the network. No legitimate use case exists in modern infrastructure. "
            "Presence indicates a legacy device or a critical misconfiguration."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm telnet is intentionally enabled and document the justification. "
                "Verify SSH is available as an immediate replacement."
            ),
            "Medium": (
                "Capture telnet banner and identify the device owner. Begin a migration "
                "timeline to SSH. Verify no production systems rely on this service."
            ),
            "High": (
                "Flag as a critical misconfiguration requiring immediate remediation. Disable "
                "telnet or restrict to an isolated management VLAN. Treat all credentials "
                "used over this service as compromised and initiate rotation."
            ),
            "Critical": (
                "Treat all credentials used over this connection as compromised. Disable "
                "telnet immediately. Initiate credential rotation for all accounts that may "
                "have authenticated over this service. Notify the security team and log all "
                "connected sessions in the incident record."
            ),
        },
    },

    "rdp": {
        "service_context": (
            "Windows Remote Desktop Protocol providing full graphical access. Primary delivery "
            "vector for ransomware, targeted intrusion, and lateral movement in Windows "
            "environments. Internet-exposed RDP without Network Level Authentication is one "
            "of the highest-risk exposures in enterprise networks."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm Network Level Authentication (NLA) is enforced. Verify RDP is not "
                "directly internet-accessible — access must require VPN or a jump host."
            ),
            "Medium": (
                "Check RDP encryption level and NLA enforcement via rdp-enum-encryption. "
                "Verify account lockout policy is active. Review RDP event logs (Event ID 4625) "
                "for failed authentication attempts."
            ),
            "High": (
                "Audit all successful and failed RDP logins. Confirm BlueKeep (CVE-2019-0708) "
                "and DejaBlue (CVE-2019-1181/1182) patches are applied. Verify RDP is behind "
                "a VPN with IP whitelisting enforced. Alert on off-hours or geographically "
                "anomalous sessions."
            ),
            "Critical": (
                "If RDP is internet-accessible without NLA, isolate the host immediately. "
                "Test for BlueKeep (CVE-2019-0708) — unauthenticated RCE on Windows 7/2008. "
                "Review all RDP session logs for evidence of lateral movement. Engage "
                "incident response and consider emergency patching."
            ),
        },
    },

    "vnc": {
        "service_context": (
            "Lightweight remote desktop protocol. Frequently deployed without passwords or "
            "with weak credentials. Transmits screen contents in cleartext in many "
            "configurations. Often exposed unintentionally on developer or lab systems."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm VNC requires password authentication. Document the justification "
                "for remote desktop access over VNC rather than SSH or RDP."
            ),
            "Medium": (
                "Test for null authentication (empty password). Check VNC security type "
                "in use. Verify VNC is not accessible from untrusted networks."
            ),
            "High": (
                "Check for null authentication immediately. Restrict VNC to localhost and "
                "require an SSH tunnel for all external access. Review VNC access logs for "
                "unauthorised sessions."
            ),
            "Critical": (
                "If null authentication is confirmed, treat as an active exposure. Immediately "
                "disable VNC or firewall port 5900. Review the system for signs of unauthorised "
                "access. Require SSH-tunnelled access only going forward."
            ),
        },
    },

    "ftp": {
        "service_context": (
            "Cleartext file transfer protocol transmitting all data — including credentials — "
            "unencrypted over the network. High risk for anonymous access and credential "
            "interception. Should be replaced by SFTP or FTPS in all modern environments."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Test for anonymous FTP access. Document whether FTP serves a current "
                "business function and whether SFTP is available as a replacement."
            ),
            "Medium": (
                "Enumerate FTP server type, version, and accessible directories. Check for "
                "anonymous login and review file permissions on all accessible paths."
            ),
            "High": (
                "Audit FTP access logs for unauthorised sessions. Restrict accessible "
                "directories to least-privilege. Treat all FTP credentials as potentially "
                "compromised and initiate rotation."
            ),
            "Critical": (
                "Disable FTP immediately if anonymous access is confirmed or sensitive data "
                "is accessible without credentials. Rotate all FTP credentials. Initiate "
                "migration to SFTP. Audit all files accessible via FTP for data exposure."
            ),
        },
    },

    "tftp": {
        "service_context": (
            "Unauthenticated file transfer over UDP. No credentials are required — any client "
            "can read or write files in the TFTP root directory. Legitimate use is limited to "
            "network device bootstrapping (PXE, router configs). Exposure outside a management "
            "network is always a misconfiguration."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm TFTP is only used for network device bootstrapping (PXE/router config). "
                "Verify the TFTP root directory contains no sensitive files."
            ),
            "Medium": (
                "Enumerate accessible files via TFTP. Check the root directory for network "
                "device configuration files, cryptographic keys, or other sensitive content."
            ),
            "High": (
                "Attempt retrieval of sensitive files (e.g. /etc/passwd, running-config) to "
                "confirm exposure scope. Immediately restrict TFTP to the management VLAN."
            ),
            "Critical": (
                "Disable TFTP immediately if accessible from non-management networks. Audit "
                "all files in the TFTP root for data exposure. Review any network device "
                "configurations that may have been accessible without authentication."
            ),
        },
    },

    "smb": {
        "service_context": (
            "Windows file and printer sharing. A high-value target for network-wide propagation "
            "(WannaCry, NotPetya), credential relay attacks, lateral movement, and data "
            "exfiltration. SMBv1 is critically dangerous due to EternalBlue (CVE-2017-0144)."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm SMBv1 is disabled. Verify SMB signing is enforced on this host. "
                "Confirm SMB is not accessible from untrusted network segments."
            ),
            "Medium": (
                "Enumerate accessible shares and test for null session (unauthenticated guest) "
                "access. Confirm SMBv1 is disabled and SMB signing is active. Review all "
                "share permissions."
            ),
            "High": (
                "Test for EternalBlue (CVE-2017-0144) and SMBGhost (CVE-2020-0796). Audit "
                "all share permissions and disable null session access. Verify MS17-010 "
                "(KB4012212) and SMBGhost (KB4551762) patches are applied. Review SMB event "
                "logs (Event ID 4624/4625) for lateral movement indicators."
            ),
            "Critical": (
                "If SMBv1 is confirmed active, treat this as a ransomware precursor. Isolate "
                "the host immediately. Disable SMBv1 network-wide. Check SMB event logs for "
                "EternalBlue exploitation indicators. Engage incident response and assess "
                "the scope of any lateral propagation."
            ),
        },
    },

    "netbios-ssn": {
        "service_context": (
            "NetBIOS Session Service used by legacy Windows file sharing on port 139. Enables "
            "host and workgroup name enumeration, exposing network topology. Commonly present "
            "alongside SMB on Windows systems. Has shared CVE history with EternalBlue."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm NetBIOS is required for network operations on this host. Verify it "
                "is not exposed to untrusted network segments."
            ),
            "Medium": (
                "Enumerate NetBIOS names and workgroup membership. Confirm DNS is configured "
                "as the primary name resolution method where possible."
            ),
            "High": (
                "Enumerate all NetBIOS names and workgroup memberships. Review SMB-related "
                "activity on the same host (ports 139 and 445). Consider disabling NetBIOS "
                "over TCP/IP if not operationally required."
            ),
            "Critical": (
                "Block NetBIOS ports 137-139 at the network perimeter immediately. Disable "
                "NetBIOS over TCP/IP on this host. Treat as part of a broader Windows "
                "infrastructure exposure review alongside any co-located SMB service."
            ),
        },
    },

    "nfs": {
        "service_context": (
            "Network File System — mounts remote directories over the network. Misconfigured "
            "exports (wildcard access, no_root_squash) can allow full filesystem access or "
            "client-to-server privilege escalation. NFSv2/v3 uses no cryptographic "
            "authentication; NFSv4 supports Kerberos (AUTH_GSS)."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Enumerate NFS exports via showmount. Verify no wildcard (*) entries exist "
                "and all exports are restricted to specific authorised host IPs."
            ),
            "Medium": (
                "List NFS exports and their mount options. Check for no_root_squash on any "
                "export — this allows a root user on a client to act as root on the server."
            ),
            "High": (
                "Attempt to mount exports and enumerate accessible file content. Verify "
                "AUTH_SYS is not the sole authentication method. Block NFS ports (2049, 111) "
                "at the network perimeter."
            ),
            "Critical": (
                "If exports are accessible without restrictions, treat as a full data exposure. "
                "Immediately restrict all exports to authorised hosts or disable NFS. Audit "
                "all currently-mounted clients and review for data exfiltration indicators."
            ),
        },
    },

    "http": {
        "service_context": (
            "Unencrypted web service. All data — including session tokens and submitted "
            "credentials — is transmitted in cleartext. Commonly hosts login portals, admin "
            "interfaces, and application endpoints. Vulnerable to content injection, session "
            "hijacking, and a broad range of web application attacks."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Retrieve HTTP response headers to identify server software and technology "
                "stack. Confirm the service is intentionally public-facing and expected."
            ),
            "Medium": (
                "Enumerate accessible paths and directories. Review security response headers "
                "(CSP, X-Frame-Options, HSTS redirect). Check for exposed admin interfaces, "
                "sensitive files, backup files, or default application pages."
            ),
            "High": (
                "Run a web vulnerability scan (nikto) to surface misconfigurations, outdated "
                "software, and dangerous files. Verify no sensitive data is served over plain "
                "HTTP. Test visible parameter inputs for injection. Check for default "
                "credentials on any login interfaces."
            ),
            "Critical": (
                "Escalate to the application security team. Perform a full web application "
                "assessment covering SQL injection, authentication bypass, IDOR, and file "
                "inclusion. Review WAF policy and network access controls. Force HTTPS "
                "redirect and remediate all open findings."
            ),
        },
    },

    "https": {
        "service_context": (
            "TLS-encrypted web service. Risk lies in application-layer vulnerabilities, weak "
            "TLS cipher configurations, and expired or misconfigured certificates rather than "
            "transport-layer interception. CVE exposure depends on the application framework "
            "version and the underlying OpenSSL build."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Validate TLS certificate validity, expiry date, and issuing authority. "
                "Confirm TLS 1.2 or higher is enforced."
            ),
            "Medium": (
                "Enumerate supported TLS cipher suites and protocol versions. Review security "
                "response headers (HSTS, CSP, X-Frame-Options). Fingerprint the web technology "
                "stack and note all identified component versions."
            ),
            "High": (
                "Run a full TLS configuration audit using sslscan or testssl.sh. Check for "
                "Heartbleed (CVE-2014-0160). Run a web vulnerability scan (nikto -ssl) for "
                "misconfigurations and outdated components. Verify HSTS is enforced with "
                "includeSubDomains."
            ),
            "Critical": (
                "Verify OpenSSL version against CVE-2014-0160 (Heartbleed), POODLE, and "
                "DROWN. Perform a full web application security assessment. Engage the "
                "application security team. Remediate all weak cipher configurations and "
                "ensure TLS 1.0/1.1 are disabled."
            ),
        },
    },

    "http-proxy": {
        "service_context": (
            "Open or reverse HTTP proxy service. An unauthenticated open proxy allows external "
            "actors to relay requests through this host, bypassing network controls and "
            "obscuring the true origin of traffic. Can be used to reach internal network "
            "resources that would otherwise be inaccessible."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm whether proxy authentication is required. Verify the proxy is not "
                "accessible from untrusted external networks."
            ),
            "Medium": (
                "Test for open proxy by sending a request to an external destination. "
                "Verify outbound CONNECT method is restricted where HTTPS tunnelling "
                "is not a business requirement."
            ),
            "High": (
                "If open proxy is confirmed, immediately disable or require authentication. "
                "Review proxy access logs for signs of external abuse or internal pivoting. "
                "Block the service from untrusted network segments."
            ),
            "Critical": (
                "Treat as active network bypass risk. Disable unauthenticated proxy access "
                "immediately. Review all proxy logs for evidence of internal network pivoting. "
                "Restrict outbound CONNECT and implement proxy authentication with logging."
            ),
        },
    },

    "mysql": {
        "service_context": (
            "MySQL relational database service exposed over the network. Represents a direct "
            "data exfiltration risk. Default installation misconfigurations — including empty "
            "root passwords, anonymous users, and the test database — are frequently exploited "
            "on internet-facing and improperly segmented hosts."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm MySQL is intentionally network-accessible. Verify it is not bound "
                "to all interfaces (0.0.0.0) and document the authorised client hosts."
            ),
            "Medium": (
                "Check for empty root password and anonymous user accounts. Verify MySQL "
                "is not accessible from untrusted network segments. Review GRANT privileges "
                "for all user accounts."
            ),
            "High": (
                "Audit all MySQL user accounts and their source IP restrictions. Remove "
                "anonymous accounts and the test database. Rotate all database credentials. "
                "Test for the CVE-2012-2122 authentication bypass."
            ),
            "Critical": (
                "Treat as a data breach risk. Immediately restrict MySQL to localhost or "
                "authorised application server IPs. Rotate all database credentials. Audit "
                "the MySQL general query log or binary log for evidence of data exfiltration. "
                "Engage the DBA and incident response team."
            ),
        },
    },

    "postgresql": {
        "service_context": (
            "PostgreSQL relational database service exposed over the network. Trust "
            "authentication entries in pg_hba.conf can permit connections without any "
            "credentials. CVE-2019-9193 enables OS-level command execution via COPY FROM "
            "PROGRAM if an authenticated connection can be established."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm PostgreSQL is intentionally network-accessible. Verify it is not "
                "listening on all interfaces unless explicitly required."
            ),
            "Medium": (
                "Review pg_hba.conf for trust authentication entries. Verify all roles use "
                "md5 or scram-sha-256 — not trust or ident."
            ),
            "High": (
                "Audit all database roles and their authentication methods. Remove any trust "
                "authentication entries. Rotate all database credentials. If an authenticated "
                "connection is possible, test for CVE-2019-9193."
            ),
            "Critical": (
                "Restrict PostgreSQL to localhost or specific application server IPs. Rotate "
                "all credentials. Audit PostgreSQL logs for evidence of COPY FROM PROGRAM "
                "execution (CVE-2019-9193). Engage the DBA and incident response team."
            ),
        },
    },

    "mssql": {
        "service_context": (
            "Microsoft SQL Server exposed over the network. Provides access to application "
            "databases and, if the SA account is accessible or xp_cmdshell is enabled, "
            "direct OS-level command execution. A weak SA password is one of the most "
            "commonly exploited misconfigurations in Windows environments."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm MSSQL is only accessible from authorised application servers. "
                "Verify the SA account is disabled or renamed."
            ),
            "Medium": (
                "Check for empty SA password. Enumerate instance configuration. Verify "
                "xp_cmdshell is disabled. Review linked server configurations for privilege "
                "escalation paths."
            ),
            "High": (
                "Test for empty SA password and confirm xp_cmdshell status. Audit all SQL "
                "login accounts and their source IP restrictions. Apply all SQL Server "
                "Cumulative Updates. Verify port 1433 is firewalled from untrusted networks."
            ),
            "Critical": (
                "If xp_cmdshell is enabled and the SA account is accessible, treat as a full "
                "system compromise risk. Disable xp_cmdshell immediately (sp_configure). "
                "Rotate the SA password and all SQL credentials. Block port 1433 from all "
                "untrusted networks. Engage the DBA and incident response team."
            ),
        },
    },

    "redis": {
        "service_context": (
            "In-memory data store often deployed without authentication by default. An "
            "unauthenticated Redis instance allows full data read/write access and, via "
            "CONFIG SET, arbitrary file writes to the server filesystem — enabling SSH "
            "authorized_keys injection and cron-based persistence without any credentials."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Test whether Redis responds to PING without credentials. Verify the "
                "requirepass directive is configured in redis.conf."
            ),
            "Medium": (
                "Retrieve Redis server INFO and CONFIG to confirm authentication is enforced. "
                "Verify Redis is not accessible from untrusted network segments. Confirm port "
                "6379 is firewalled."
            ),
            "High": (
                "If unauthenticated access is confirmed, enumerate stored keys for sensitive "
                "application data. Review CONFIG dir setting to confirm arbitrary file write "
                "paths are restricted. Enable requirepass and bind to localhost immediately."
            ),
            "Critical": (
                "Treat unauthenticated Redis as a full host compromise risk. CONFIG SET can "
                "write SSH keys or cron jobs without credentials. Immediately firewall port "
                "6379, enable requirepass, and audit the filesystem for unauthorised changes "
                "to crontabs, SSH authorized_keys, and web root directories."
            ),
        },
    },

    "mongodb": {
        "service_context": (
            "NoSQL document store frequently deployed without authentication in default "
            "configurations. An exposed MongoDB instance allows unauthenticated listing and "
            "retrieval of all databases and collections. Commonly involved in large-scale "
            "data breach incidents due to misconfigured cloud deployments."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm MongoDB requires authentication. Verify the --auth flag is active "
                "and MongoDB is not bound to all interfaces (0.0.0.0)."
            ),
            "Medium": (
                "Test for unauthenticated database listing. Review the bind IP configuration "
                "and confirm firewall rules restrict port 27017 to authorised hosts."
            ),
            "High": (
                "Enumerate accessible databases and collections. Assess the sensitivity of "
                "any accessible data. Restrict MongoDB to localhost or authorised application "
                "hosts and enable authentication immediately."
            ),
            "Critical": (
                "Treat as an active data breach. Enumerate all accessible data and assess the "
                "full exposure scope. Enable authentication, restrict network access, and "
                "rotate any credentials stored within the database. Engage incident response."
            ),
        },
    },

    "elasticsearch": {
        "service_context": (
            "Search and analytics engine frequently deployed without authentication in default "
            "configurations. Exposes all indexed data — which may include application logs, "
            "user records, or business-critical documents — via an unauthenticated HTTP REST "
            "API. Historically involved in numerous significant data breach incidents."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm whether Elasticsearch responds without authentication. Verify "
                "X-Pack Security or an equivalent authentication plugin is enabled."
            ),
            "Medium": (
                "List all indices and their document counts. Review cluster settings for "
                "authentication enforcement. Verify port 9200 is firewalled from untrusted "
                "networks."
            ),
            "High": (
                "Enumerate all indices and assess data sensitivity. Check cluster node versions "
                "against CVE-2015-1427 and CVE-2014-3120. Restrict access and enable "
                "authentication immediately."
            ),
            "Critical": (
                "Treat as an active data breach. Enumerate all accessible indices and assess "
                "the full exposure scope. Enable X-Pack Security, restrict network access, "
                "and engage incident response. Review access logs for prior exfiltration activity."
            ),
        },
    },

    "smtp": {
        "service_context": (
            "Mail Transfer Agent. An open relay configuration can be exploited to send spam "
            "and phishing campaigns originating from this host. VRFY and EXPN commands may "
            "enable valid user enumeration, providing a target list for credential attacks."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm the SMTP banner does not disclose sensitive version information. "
                "Verify the server is not configured as an open relay."
            ),
            "Medium": (
                "Test for open relay via the smtp-open-relay NSE script. Enumerate valid users "
                "via VRFY and EXPN. Verify STARTTLS is available and enforced for all "
                "authenticated connections."
            ),
            "High": (
                "Confirm VRFY and EXPN are disabled. Verify SPF, DKIM, and DMARC DNS records "
                "are properly configured. Review outbound mail queue and logs for anomalous "
                "sending patterns or relay abuse indicators."
            ),
            "Critical": (
                "If open relay is confirmed, treat as active abuse risk. Immediately restrict "
                "the relay policy to authorised senders only. Review the mail queue for "
                "unauthorised outbound messages. Notify the abuse team and update SPF/DMARC "
                "to prevent domain spoofing."
            ),
        },
    },

    "pop3": {
        "service_context": (
            "Mail retrieval protocol transmitting authentication credentials and message "
            "content in cleartext on port 110. All data is exposed to network interception. "
            "Should be migrated to POP3S (port 995) in all modern deployments."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm POP3S (port 995) is available as a replacement. Document whether "
                "plain POP3 on port 110 is required for any active client."
            ),
            "Medium": (
                "Enumerate POP3 capabilities to confirm STLS (opportunistic TLS) support. "
                "Verify account lockout is in place to limit brute-force attempts."
            ),
            "High": (
                "Disable plain POP3 on port 110. Migrate all active users to POP3S or IMAPS. "
                "Review authentication logs for credential compromise indicators."
            ),
            "Critical": (
                "Treat all credentials used over plain POP3 as potentially compromised. "
                "Disable port 110 immediately. Enforce encrypted mail access exclusively. "
                "Initiate credential rotation for all affected mail accounts."
            ),
        },
    },

    "imap": {
        "service_context": (
            "Mail access protocol transmitting authentication credentials and message content "
            "in cleartext on port 143. All data is exposed to network interception. Should "
            "be migrated to IMAPS (port 993) in all modern deployments."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm IMAPS (port 993) is available as a replacement. Document whether "
                "plain IMAP on port 143 is required for any active client."
            ),
            "Medium": (
                "Enumerate IMAP capabilities to confirm STARTTLS support. Verify account "
                "lockout policy is enforced."
            ),
            "High": (
                "Disable plain IMAP on port 143. Migrate all active users to IMAPS. Review "
                "authentication logs for credential compromise indicators."
            ),
            "Critical": (
                "Treat all credentials used over plain IMAP as potentially compromised. "
                "Disable port 143 immediately. Enforce IMAPS exclusively. Initiate credential "
                "rotation for all affected mail accounts."
            ),
        },
    },

    "domain": {
        "service_context": (
            "DNS server. Zone transfer misconfigurations can expose every internal DNS record, "
            "revealing the complete network topology to an attacker. CHAOS class queries may "
            "disclose the DNS software version string, enabling targeted vulnerability research."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm DNS server version and whether it is authoritative or recursive. "
                "Verify the CHAOS class version.bind response is disabled."
            ),
            "Medium": (
                "Attempt a DNS zone transfer (AXFR) to test for misconfiguration. Verify "
                "zone transfers are restricted to authorised secondary DNS servers only."
            ),
            "High": (
                "If zone transfer succeeds, document all exposed records and restrict AXFR "
                "immediately to authorised secondaries. Verify the SIGRed patch (KB4569509) "
                "is applied on Windows DNS servers. Disable recursion on authoritative servers."
            ),
            "Critical": (
                "If a full zone transfer is confirmed, treat as a complete network topology "
                "disclosure. Restrict all zone transfers immediately. Apply KB4569509 "
                "(CVE-2020-1350). Enable DNSSEC. Audit all DNS records for inadvertent "
                "exposure of sensitive internal hosts."
            ),
        },
    },

    "snmp": {
        "service_context": (
            "Network management protocol. Default community strings ('public', 'private') "
            "allow full network device information disclosure without authentication. "
            "SNMPv1 and v2c transmit community strings in cleartext. Successful SNMP access "
            "can expose running processes, routing tables, interface configurations, and "
            "software versions across network devices."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm SNMP community strings are not set to defaults ('public', 'private'). "
                "Flag SNMPv1 or v2c usage — authentication and privacy require SNMPv3."
            ),
            "Medium": (
                "Test default and common community strings. Retrieve system description to "
                "confirm access level. Verify SNMP access is restricted to authorised "
                "management hosts via ACL."
            ),
            "High": (
                "Brute-force common community strings. Perform a full SNMP walk if any "
                "community string is identified. Immediately restrict SNMP access via ACL. "
                "Begin migration planning to SNMPv3 with authPriv security level."
            ),
            "Critical": (
                "If default community strings are confirmed, treat as full device configuration "
                "disclosure. Immediately rotate community strings and restrict SNMP access via "
                "ACL. Upgrade to SNMPv3. Audit all data accessible in the MIB tree for "
                "sensitive credential or configuration exposure."
            ),
        },
    },

    "ldap": {
        "service_context": (
            "Lightweight Directory Access Protocol, typically fronting Active Directory. "
            "Anonymous bind misconfigurations allow full user, group, and computer enumeration "
            "without credentials. A critical reconnaissance target in enterprise environments — "
            "enables targeted credential attacks and BloodHound-style AD attack path analysis."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm anonymous LDAP bind is disabled. Verify LDAP is not accessible from "
                "untrusted network segments."
            ),
            "Medium": (
                "Attempt an anonymous LDAP bind and base DN enumeration. Retrieve the root DSE "
                "to identify domain information and supported LDAP features."
            ),
            "High": (
                "If anonymous bind succeeds, enumerate all LDAP objects (users, groups, "
                "computers, GPOs). Disable anonymous bind immediately. Plan migration to LDAPS "
                "and enforce LDAP signing (KB4520412)."
            ),
            "Critical": (
                "If unauthenticated LDAP enumeration is confirmed, treat as a complete Active "
                "Directory reconnaissance exposure. Disable anonymous bind immediately. Enforce "
                "LDAP signing and channel binding (KB4520412). Restrict LDAP to authorised "
                "management hosts. Engage the Active Directory team."
            ),
        },
    },

    "ldaps": {
        "service_context": (
            "LDAP over SSL/TLS — encrypted directory access. Lower risk than plain LDAP due "
            "to transport encryption, but still targeted for anonymous bind enumeration and "
            "Active Directory reconnaissance. Requires valid TLS certificate configuration "
            "and LDAP channel binding enforcement."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Verify the TLS certificate is valid, not self-signed, and not expired. "
                "Confirm anonymous bind is disabled."
            ),
            "Medium": (
                "Test for anonymous LDAPS bind. Verify LDAP channel binding is enforced. "
                "Confirm the certificate uses a strong cipher suite."
            ),
            "High": (
                "Enumerate LDAP objects if anonymous bind succeeds. Enforce LDAP channel "
                "binding and LDAP signing (KB4520412). Review TLS configuration for weak "
                "cipher suites or deprecated protocol versions."
            ),
            "Critical": (
                "If unauthenticated enumeration is confirmed over LDAPS, disable anonymous "
                "bind immediately. Enforce LDAP channel binding. Restrict access to authorised "
                "management hosts only. Engage the Active Directory and security teams."
            ),
        },
    },

    "msrpc": {
        "service_context": (
            "Microsoft RPC Endpoint Mapper — dynamically assigns ports for Windows services "
            "including DCOM, WMI, and AD replication. Enables enumeration of registered "
            "Windows services via anonymous RPC sessions. Has a significant historical CVE "
            "record including the Blaster worm (MS03-026, CVE-2003-0352)."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Confirm port 135 is not accessible from untrusted network segments. Document "
                "the services registered with the RPC endpoint mapper."
            ),
            "Medium": (
                "Enumerate RPC endpoints to identify all exposed services. Test for anonymous "
                "RPC session access via rpcclient."
            ),
            "High": (
                "Perform a full RPC endpoint dump using Impacket rpcdump.py. Restrict port 135 "
                "at the network perimeter. Apply all outstanding Windows security updates "
                "related to RPC."
            ),
            "Critical": (
                "Block port 135 at all network perimeters immediately. Apply MS03-026 and all "
                "subsequent RPC-related security patches. Investigate any anonymous RPC session "
                "access that was confirmed as accessible."
            ),
        },
    },

    "unknown": {
        "service_context": (
            "Unclassified service. The application or protocol running on this port could not "
            "be identified from the scan data alone. Manual identification via banner grabbing "
            "and aggressive version detection is required before a complete risk assessment "
            "can be performed."
        ),
        "action_taken_by_risk": {
            "Low": (
                "Perform version detection and raw banner grabbing to identify the service. "
                "Determine whether this port should be exposed and identify the service owner."
            ),
            "Medium": (
                "Run aggressive version detection (nmap -sV --version-intensity 9) and a raw "
                "banner grab (netcat). Identify the service and re-assess its risk level once "
                "the protocol is confirmed."
            ),
            "High": (
                "Prioritise identification. Run nmap default NSE scripts alongside version "
                "detection. Cross-reference the port number against known service registries. "
                "Escalate if the service cannot be attributed within the triage window."
            ),
            "Critical": (
                "Treat any unidentified port at Critical risk as an immediate investigation "
                "target. Isolate the host if the operational context supports it. Perform "
                "full protocol analysis and escalate to the incident response team if the "
                "service cannot be accounted for."
            ),
        },
    },
}

# ---------------------------------------------------------------------------
# Scanner alias → canonical service name (for SOC context lookup fallback)
# ---------------------------------------------------------------------------
_SERVICE_ALIASES: dict[str, str] = {
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
# Internal helpers
# ---------------------------------------------------------------------------

def _normalise_host(host: dict) -> tuple[str, str, list[dict]]:
    """
    Normalise a host dict from report_generator or the risk_engine shim.

    Supported shapes:
      report_generator : {"ip": str, "risk_level": str, "ports": [...]}
      risk_engine shim : {"ip": str, "ports": [{"port","protocol","service","risk"}]}

    Returns (ip, overall_risk_level, ports_list).
    """
    ip         = str(host.get("ip") or host.get("host") or "unknown")
    risk_level = str(host.get("risk_level", ""))

    ports = host.get("ports", [])

    if not risk_level and ports:
        _order = ["Critical", "High", "Medium", "Low", "Informational"]
        found  = {str(p.get("risk", "Informational")) for p in ports}
        for level in _order:
            if level in found:
                risk_level = level
                break

    risk_level = risk_level or "Unknown"
    return ip, risk_level, ports


def _risk_rationale(service: str, risk_level: str, intel: dict) -> str:
    """Build a deterministic risk rationale string from structured intel properties."""
    parts: list[str] = []

    _level_framing: dict[str, str] = {
        "Critical": (
            f"{service.upper()} is assessed at Critical risk. "
            "Immediate triage and potential host isolation are warranted."
        ),
        "High": (
            f"{service.upper()} is assessed at High risk. "
            "Prompt investigation is required before the next business day."
        ),
        "Medium": (
            f"{service.upper()} is assessed at Medium risk. "
            "Schedule investigation within the standard SLA window."
        ),
        "Low": (
            f"{service.upper()} is assessed at Low risk. "
            "Review during the next routine maintenance cycle."
        ),
        "Informational": (
            f"{service.upper()} is assessed as Informational. "
            "No immediate action required; document and monitor."
        ),
    }
    parts.append(
        _level_framing.get(
            risk_level,
            f"{service.upper()} is assessed at {risk_level} risk.",
        )
    )

    if intel.get("protocol_cleartext"):
        parts.append(
            "This protocol transmits data in cleartext — credentials and content "
            "are exposed to interception on the network path."
        )

    if intel.get("anonymous_risk"):
        parts.append(
            "Unauthenticated or anonymous access is common with this service — "
            "authentication enforcement must be verified before treating the "
            "service as secured."
        )

    if intel.get("cve_prone") and intel.get("notable_cves"):
        n = len(intel["notable_cves"])
        parts.append(
            f"This service has a documented CVE history ({n} notable CVE(s) on record) — "
            "patch status must be confirmed as part of triage."
        )

    phases = intel.get("attack_phases", [])
    if phases:
        parts.append(f"MITRE ATT&CK relevance: {', '.join(phases)}.")

    return " ".join(parts)


def _build_host_summary(ip: str, ports: list[dict], overall_risk: str) -> str:
    """Build a plain-text overall host summary for SOC triage intake."""
    open_ports = [p for p in ports if str(p.get("state", "open")).lower() == "open"]
    n_open     = len(open_ports) if open_ports else len(ports)

    _prio = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sorted_ports = sorted(
        ports,
        key=lambda p: _prio.get(str(p.get("risk", "Informational")), 5),
    )
    top          = sorted_ports[0] if sorted_ports else {}
    top_service  = str(top.get("service", "unknown")).upper()
    top_port_num = top.get("port", "?")
    top_risk     = str(top.get("risk", "Unknown"))

    cleartext_svcs: list[str] = []
    anonymous_svcs: list[str] = []
    for p in ports:
        svc   = str(p.get("service", "unknown"))
        port  = int(p.get("port", 0))
        intel = _si_analyze(svc, port)
        if intel.get("protocol_cleartext"):
            cleartext_svcs.append(svc.upper())
        if intel.get("anonymous_risk"):
            anonymous_svcs.append(svc.upper())

    flags: list[str] = []
    if cleartext_svcs:
        unique = sorted(set(cleartext_svcs))
        flags.append(f"cleartext protocol(s) detected: {', '.join(unique)}")
    if anonymous_svcs:
        unique = sorted(set(anonymous_svcs))
        flags.append(f"anonymous/unauthenticated access risk on: {', '.join(unique)}")

    flag_str = f" Notable flags: {'; '.join(flags)}." if flags else ""

    return (
        f"Host {ip} has {n_open} open port(s) assessed at overall {overall_risk} risk. "
        f"Highest-priority service: {top_service} on port {top_port_num} ({top_risk} risk)."
        f"{flag_str} "
        f"Review all recommendations below in priority order."
    )


def _build_recommendation(port: dict, ip: str) -> dict:
    """Build a single-port SOC recommendation record."""
    port_num   = int(port.get("port", 0))
    protocol   = str(port.get("protocol", "tcp"))
    service    = str(port.get("service", "unknown")).lower()
    risk_level = str(port.get("risk", "Informational"))
    flags      = list(port.get("risk_flags", port.get("flags", [])))

    intel    = _si_analyze(service, port_num, risk_level)
    resolved = intel.get("service", service)

    soc = _SOC_CONTEXT.get(resolved) or _SOC_CONTEXT.get(
        _SERVICE_ALIASES.get(service, ""), _SOC_CONTEXT["unknown"]
    )

    action_taken = soc["action_taken_by_risk"].get(
        risk_level,
        soc["action_taken_by_risk"].get("Low", "Review this service and determine exposure scope."),
    )

    enum_steps = [
        {
            "step":    idx + 1,
            "tool":    cmd.get("tool", ""),
            "command": (
                cmd.get("command", "")
                   .replace("{target}", ip)
                   .replace("{port}", str(port_num))
            ),
            "purpose": cmd.get("purpose", ""),
        }
        for idx, cmd in enumerate(intel.get("enum_commands", []))
    ]

    return {
        "port":              port_num,
        "protocol":          protocol,
        "service":           resolved,
        "category":          intel.get("category", "Unknown"),
        "subcategory":       intel.get("subcategory", ""),
        "risk_level":        risk_level,
        "priority":          _PRIORITY_MAP.get(risk_level, 5),
        "service_context":   soc["service_context"],
        "risk_rationale":    _risk_rationale(resolved, risk_level, intel),
        "action_taken":      action_taken,
        "enumeration_steps": enum_steps,
        "hardening_checks":  intel.get("hardening_checks", []),
        "notable_cves":      intel.get("notable_cves", []),
        "flags":             flags,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_recommendations(scan_data: list[dict]) -> list[dict]:
    """
    Generate a SOC Recommended Actions Report for each host in scan_data.

    Parameters
    ----------
    scan_data : list[dict]
        Each dict must contain either an 'ip' or 'host' key and a 'ports' list
        where each port provides at minimum:
          - port      : int or str
          - protocol  : str
          - service   : str
          - risk      : str  (e.g. "Critical", "High", "Medium", "Low")

    Returns
    -------
    list[dict]
        One report dict per host, sorted in the order hosts appear in scan_data.
    """
    if not scan_data:
        return []

    report: list[dict] = []

    for host in scan_data:
        ip, overall_risk, all_ports = _normalise_host(host)

        ports = [
            p for p in all_ports
            if str(p.get("state", "open")).lower() == "open"
        ]
        if not ports:
            ports = all_ports

        if not ports:
            report.append({
                "ip":                   ip,
                "overall_risk_level":   overall_risk,
                "overall_host_summary": (
                    f"Host {ip}: no port data available. "
                    "Run a targeted nmap scan to populate the service inventory."
                ),
                "recommendations": [],
            })
            continue

        recommendations = [_build_recommendation(p, ip) for p in ports]
        recommendations.sort(key=lambda r: (r["priority"], r["port"]))

        report.append({
            "ip":                   ip,
            "overall_risk_level":   overall_risk,
            "overall_host_summary": _build_host_summary(ip, ports, overall_risk),
            "recommendations":      recommendations,
        })

    return report
