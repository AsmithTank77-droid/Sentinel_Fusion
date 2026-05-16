
# Sentinel_Fusion SOC Report
**Generated:** 2026-05-11T20:21:06Z  
**Total Events:** 18  
**Total Alerts:** 13

## Executive Summary
**Generated:** 2026-05-11T20:21:06Z  
**Overall Verdict:** Critical

### Risk Surface

| Metric | Value |
|--------|-------|
| Critical Hosts | 1 |
| High Hosts | 0 |
| Medium Hosts | 2 |
| Low Hosts | 0 |
| Total Alerts | 13 |
| Attack Surface | **Significant** |
| Lateral Movement | Yes |
| WINLOG Rules Fired | WINLOG-005, WINLOG-006, WINLOG-009 |
| MITRE Tactics | TA0001 - Initial Access, TA0003 - Persistence, TA0004 - Privilege Escalation, TA0005 - Defense Evasion, TA0006 - Credential Access, TA0008 - Lateral Movement, TA0043 - Reconnaissance |

### Key Findings

- Highest-risk host: 10.0.0.10 — Critical (score 9.8/10).
- 3 host(s) assessed; 1 Critical risk host(s) require immediate attention.
- Lateral movement detected across 1 hop(s) — attacker has likely pivoted beyond the initial entry point.
- Attack surface expansion rated 'Significant' (score 7.5/10) — multiple techniques and targets observed in this session.
- 3 Windows behavioural rule(s) fired: WINLOG-005, WINLOG-006, WINLOG-009.
- Critical/High NRA service exposure: NETBIOS-SSN on 10.0.0.10:139, MYSQL on 10.0.0.11:3306, REDIS on 10.0.0.11:6379 (+3 more).
- MITRE ATT&CK tactics observed: TA0001 - Initial Access, TA0003 - Persistence, TA0004 - Privilege Escalation, TA0005 - Defense Evasion, TA0006 - Credential Access, TA0008 - Lateral Movement, TA0043 - Reconnaissance.

### Immediate Actions Required

1. Isolate Critical host(s) pending investigation: 10.0.0.10.
2. Engage incident response — lateral movement confirmed. Scope the blast radius before any remediation.
3. [WINLOG-006] Audit log cleared — treat as active evidence tampering. Engage incident response and preserve all available artefacts.
4. [WINLOG-009] Scheduled task persistence detected — enumerate and remove unauthorised scheduled tasks; review the process that created them.
5. Apply emergency controls for Critical-risk network service(s): TELNET (10.0.0.20:23).

---
## Attack Surface Overview

| Metric | Value |
|--------|-------|
| Expansion Score | 7.5 / 10 |
| Expansion Label | **significant** |
| External Sources | 1 |
| Internal Targets | 3 |
| Lateral Movement Hops | 1 |
| Distinct Event Types | 8 |

**MITRE ATT&CK Tactics Observed:**
- TA0001 - Initial Access
- TA0003 - Persistence
- TA0004 - Privilege Escalation
- TA0005 - Defense Evasion
- TA0006 - Credential Access
- TA0008 - Lateral Movement
- TA0043 - Reconnaissance

---
## Host Risk Scores

| Host | Risk Score | Label | Alerts | Max Severity |
|------|-----------|-------|--------|--------------|
| `10.0.0.10` | 9.8 | **critical** | 8 | 8 |
| `10.0.0.20` | 5.2 | **medium** | 0 | 5 |
| `10.0.0.11` | 4.0 | **medium** | 1 | 5 |

---
## Asset Exposure

| Asset | Exposure Score | Label | Lateral Target |
|-------|---------------|-------|----------------|
| `10.0.0.10` | 10.0 | **critical** | No |
| `10.0.0.11` | 7.8 | **high** | Yes |
| `10.0.0.20` | 1.0 | **low** | No |

---
## Detection Alerts

### Correlated Attack Chain
- **Confidence:** 99%
- **Source:** `185.220.101.45`

### Correlated Attack Chain
- **Confidence:** 90%
- **Source:** `10.0.0.10`

### Brute Force Detected
- **Confidence:** 85%
- **MITRE:** TA0006 - Credential Access
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`

### Lateral Movement Detected
- **Confidence:** 75%
- **MITRE:** TA0008 - Lateral Movement
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.11`

### Malicious Ip Activity
- **Confidence:** 89%
- **MITRE:** TA0043 - Reconnaissance
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`
- **Detail:** Source IP '185.220.101.45' is flagged malicious (score=0.97, categories=['tor_exit', 'ssh_brute_force', 'scanner'])

### Tor Exit Node Activity
- **Confidence:** 85%
- **MITRE:** TA0005 - Defense Evasion
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`
- **Detail:** Source IP '185.220.101.45' is a TOR exit node

### High Risk Country Access
- **Confidence:** 65%
- **MITRE:** TA0043 - Reconnaissance
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`
- **Detail:** Traffic from high-risk country: Russia

### Off Hours Access
- **Confidence:** 55%
- **MITRE:** TA0003 - Persistence
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`
- **Detail:** Activity at off-hours UTC hour 03:xx

### Threat Feed Match
- **Confidence:** 99%
- **MITRE:** TA0043 - Reconnaissance
- **Source:** `185.220.101.45`
- **Target:** `10.0.0.10`
- **Detail:** Matches threat feeds: ['tor-exit-nodes', 'ssh-brute-force-ips', 'shodan-scanner']

### Off Hours Access
- **Confidence:** 55%
- **MITRE:** TA0003 - Persistence
- **Source:** `10.0.0.10`
- **Target:** `10.0.0.10`
- **Detail:** Activity at off-hours UTC hour 03:xx

### Winlog-005
- **Confidence:** 85%
- **MITRE:** TA0004 - Privilege Escalation

### Winlog-006
- **Confidence:** 99%
- **MITRE:** TA0005 - Defense Evasion

### Winlog-009
- **Confidence:** 85%
- **MITRE:** TA0003 - Persistence

---
## Attack Timeline

| Timestamp | Event Type | Src IP | Dst IP | Severity |
|-----------|------------|--------|--------|----------|
| `2025-05-11T12:00:00Z` | port_scan | `` | `10.0.0.10` | 5 |
| `2025-05-11T12:00:00Z` | port_scan | `` | `10.0.0.11` | 8 |
| `2025-05-11T12:00:00Z` | port_scan | `` | `10.0.0.20` | 8 |
| `2026-05-11T03:01:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:02:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:03:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:04:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:05:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:06:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:07:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:08:00Z` | authentication_failure | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:09:00Z` | authentication_success | `185.220.101.45` | `10.0.0.10` | 2 |
| `2026-05-11T03:09:30Z` | privileged_logon | `185.220.101.45` | `10.0.0.10` | 5 |
| `2026-05-11T03:12:00Z` | domain_group_member_added | `10.0.0.10` | `10.0.0.10` | 5 |
| `2026-05-11T03:14:00Z` | scheduled_task_created | `10.0.0.10` | `10.0.0.10` | 8 |
| `2026-05-11T03:17:00Z` | explicit_credential_logon | `10.0.0.10` | `10.0.0.11` | 5 |
| `2026-05-11T03:17:15Z` | authentication_success | `10.0.0.10` | `10.0.0.11` | 2 |
| `2026-05-11T03:21:00Z` | winlog_event_1102 | `10.0.0.10` | `10.0.0.10` | 2 |

---

## Attack Campaign Summary

Between **2025-05-11T12:00:00Z** and **2026-05-11T03:21:00Z**, Sentinel_Fusion detected a coordinated multi-stage intrusion campaign. The attack originated from `185.220.101.45`, and `10.0.0.10`. Targeted assets include: `10.0.0.10`, `10.0.0.11`, and `10.0.0.20`.

## Attack Phases


### Phase 1: Reconnaissance
_2025-05-11T12:00:00Z_

The attacker performed network reconnaissance against 3 target(s). 3 scan event(s) observed.

### Phase 2: Credential Attack
_2026-05-11T03:01:00Z_

8 authentication failure(s) recorded from 1 source(s) targeting 1 host(s). This pattern is consistent with automated credential brute-forcing.

### Phase 3: Initial Access
_2026-05-11T03:09:00Z_

Authentication succeeded after credential attacks. The attacker gained access to 10.0.0.10, 10.0.0.11.

## Detection Alerts

The following alert types were triggered during this campaign:

- **correlated_attack_chain**: 2 instance(s)
- **brute_force_detected**: 1 instance(s)
- **lateral_movement_detected**: 1 instance(s)
- **malicious_ip_activity**: 1 instance(s)
- **tor_exit_node_activity**: 1 instance(s)
- **high_risk_country_access**: 1 instance(s)
- **off_hours_access**: 2 instance(s)
- **threat_feed_match**: 1 instance(s)
- **WINLOG-005**: 1 instance(s)
- **WINLOG-006**: 1 instance(s)
- **WINLOG-009**: 1 instance(s)

## MITRE ATT&CK Coverage

Observed tactics mapped to ATT&CK framework:

- TA0006 - Credential Access
- TA0001 - Initial Access
- TA0008 - Lateral Movement
- TA0043 - Reconnaissance
- TA0005 - Defense Evasion
- TA0003 - Persistence
- TA0004 - Privilege Escalation

## Analyst Recommendations

- Block source IPs involved in brute force activity at the perimeter firewall.
- Enforce account lockout policy: lock after 5 failed attempts within 10 minutes.
- Enable multi-factor authentication on all externally-accessible SSH/RDP endpoints.
- Isolate compromised hosts from the network pending forensic investigation.
- Audit internal SMB and RDP session logs for unauthorized lateral connections.
- Block all TOR exit node ranges at the network perimeter.
- Update threat intelligence blocklists and enforce geo-blocking for high-risk regions.
- Initiate full incident response procedure — multi-stage attack chain confirmed.
- Preserve memory dumps and disk images from all affected hosts before remediation.

---
## NRA Recommended Actions

### Host: `10.0.0.10` — Critical Risk

Host 10.0.0.10 has 5 open port(s) assessed at overall Critical risk. Highest-priority service: NETBIOS-SSN on port 139 (High risk). Notable flags: cleartext protocol(s) detected: NETBIOS-SSN. Review all recommendations below in priority order.

#### Port 139/tcp — NETBIOS-SSN (High, Priority 2)
**Category:** File Sharing / NetBIOS  
**Context:** NetBIOS Session Service used by legacy Windows file sharing on port 139. Enables host and workgroup name enumeration, exposing network topology. Commonly present alongside SMB on Windows systems. Has shared CVE history with EternalBlue.  
**Rationale:** NETBIOS-SSN is assessed at High risk. Prompt investigation is required before the next business day. This protocol transmits data in cleartext — credentials and content are exposed to interception on the network path. This service has a documented CVE history (1 notable CVE(s) on record) — patch status must be confirmed as part of triage.  
**Action:** Enumerate all NetBIOS names and workgroup memberships. Review SMB-related activity on the same host (ports 139 and 445). Consider disabling NetBIOS over TCP/IP if not operationally required.  
**CVEs:** CVE-2017-0144  

#### Port 135/tcp — MSRPC (Medium, Priority 3)
**Category:** Windows Services / MS RPC  
**Context:** Microsoft RPC Endpoint Mapper — dynamically assigns ports for Windows services including DCOM, WMI, and AD replication. Enables enumeration of registered Windows services via anonymous RPC sessions. Has a significant historical CVE record including the Blaster worm (MS03-026, CVE-2003-0352).  
**Rationale:** MSRPC is assessed at Medium risk. Schedule investigation within the standard SLA window. This service has a documented CVE history (1 notable CVE(s) on record) — patch status must be confirmed as part of triage.  
**Action:** Enumerate RPC endpoints to identify all exposed services. Test for anonymous RPC session access via rpcclient.  
**CVEs:** CVE-2003-0352  

#### Port 445/tcp — SMB (Medium, Priority 3)
**Category:** File Sharing / Windows SMB  
**Context:** Windows file and printer sharing. A high-value target for network-wide propagation (WannaCry, NotPetya), credential relay attacks, lateral movement, and data exfiltration. SMBv1 is critically dangerous due to EternalBlue (CVE-2017-0144).  
**Rationale:** SMB is assessed at Medium risk. Schedule investigation within the standard SLA window. This service has a documented CVE history (2 notable CVE(s) on record) — patch status must be confirmed as part of triage. MITRE ATT&CK relevance: Lateral Movement, Execution, Collection.  
**Action:** Enumerate accessible shares and test for null session (unauthenticated guest) access. Confirm SMBv1 is disabled and SMB signing is active. Review all share permissions.  
**CVEs:** CVE-2017-0144, CVE-2020-0796  

#### Port 1433/tcp — MSSQL (Medium, Priority 3)
**Category:** Database / MSSQL  
**Context:** Microsoft SQL Server exposed over the network. Provides access to application databases and, if the SA account is accessible or xp_cmdshell is enabled, direct OS-level command execution. A weak SA password is one of the most commonly exploited misconfigurations in Windows environments.  
**Rationale:** MSSQL is assessed at Medium risk. Schedule investigation within the standard SLA window. MITRE ATT&CK relevance: Collection, Execution.  
**Action:** Check for empty SA password. Enumerate instance configuration. Verify xp_cmdshell is disabled. Review linked server configurations for privilege escalation paths.  

#### Port 3389/tcp — RDP (Medium, Priority 3)
**Category:** Remote Access / Remote Desktop  
**Context:** Windows Remote Desktop Protocol providing full graphical access. Primary delivery vector for ransomware, targeted intrusion, and lateral movement in Windows environments. Internet-exposed RDP without Network Level Authentication is one of the highest-risk exposures in enterprise networks.  
**Rationale:** RDP is assessed at Medium risk. Schedule investigation within the standard SLA window. This service has a documented CVE history (3 notable CVE(s) on record) — patch status must be confirmed as part of triage. MITRE ATT&CK relevance: Initial Access, Lateral Movement.  
**Action:** Check RDP encryption level and NLA enforcement via rdp-enum-encryption. Verify account lockout policy is active. Review RDP event logs (Event ID 4625) for failed authentication attempts.  
**CVEs:** CVE-2019-0708, CVE-2019-1181, CVE-2019-1182  

### Host: `10.0.0.11` — Medium Risk

Host 10.0.0.11 has 4 open port(s) assessed at overall Medium risk. Highest-priority service: MYSQL on port 3306 (High risk). Notable flags: cleartext protocol(s) detected: HTTP; anonymous/unauthenticated access risk on: REDIS. Review all recommendations below in priority order.

#### Port 3306/tcp — MYSQL (High, Priority 2)
**Category:** Database / MySQL  
**Context:** MySQL relational database service exposed over the network. Represents a direct data exfiltration risk. Default installation misconfigurations — including empty root passwords, anonymous users, and the test database — are frequently exploited on internet-facing and improperly segmented hosts.  
**Rationale:** MYSQL is assessed at High risk. Prompt investigation is required before the next business day. This service has a documented CVE history (1 notable CVE(s) on record) — patch status must be confirmed as part of triage. MITRE ATT&CK relevance: Collection, Execution.  
**Action:** Audit all MySQL user accounts and their source IP restrictions. Remove anonymous accounts and the test database. Rotate all database credentials. Test for the CVE-2012-2122 authentication bypass.  
**CVEs:** CVE-2012-2122  

#### Port 6379/tcp — REDIS (High, Priority 2)
**Category:** Database / In-Memory Store  
**Context:** In-memory data store often deployed without authentication by default. An unauthenticated Redis instance allows full data read/write access and, via CONFIG SET, arbitrary file writes to the server filesystem — enabling SSH authorized_keys injection and cron-based persistence without any credentials.  
**Rationale:** REDIS is assessed at High risk. Prompt investigation is required before the next business day. Unauthenticated or anonymous access is common with this service — authentication enforcement must be verified before treating the service as secured. MITRE ATT&CK relevance: Persistence, Execution.  
**Action:** If unauthenticated access is confirmed, enumerate stored keys for sensitive application data. Review CONFIG dir setting to confirm arbitrary file write paths are restricted. Enable requirepass and bind to localhost immediately.  

#### Port 22/tcp — SSH (Medium, Priority 3)
**Category:** Remote Access / Encrypted Shell  
**Context:** Encrypted remote shell access. Primary system administration method on Linux/Unix systems. Targeted for credential brute-force, key theft, and as a pivot point for lateral movement.  
**Rationale:** SSH is assessed at Medium risk. Schedule investigation within the standard SLA window. This service has a documented CVE history (2 notable CVE(s) on record) — patch status must be confirmed as part of triage. MITRE ATT&CK relevance: Initial Access, Lateral Movement, Persistence.  
**Action:** Enumerate supported authentication methods and cipher algorithms. Review sshd_config for PasswordAuthentication=no and PermitRootLogin=no. Validate host key fingerprint against a known-good baseline.  
**CVEs:** CVE-2023-38408, CVE-2018-10933  

#### Port 80/tcp — HTTP (Medium, Priority 3)
**Category:** Web Service / Unencrypted HTTP  
**Context:** Unencrypted web service. All data — including session tokens and submitted credentials — is transmitted in cleartext. Commonly hosts login portals, admin interfaces, and application endpoints. Vulnerable to content injection, session hijacking, and a broad range of web application attacks.  
**Rationale:** HTTP is assessed at Medium risk. Schedule investigation within the standard SLA window. This protocol transmits data in cleartext — credentials and content are exposed to interception on the network path. MITRE ATT&CK relevance: Initial Access.  
**Action:** Enumerate accessible paths and directories. Review security response headers (CSP, X-Frame-Options, HSTS redirect). Check for exposed admin interfaces, sensitive files, backup files, or default application pages.  

### Host: `10.0.0.20` — Medium Risk

Host 10.0.0.20 has 3 open port(s) assessed at overall Medium risk. Highest-priority service: TELNET on port 23 (Critical risk). Notable flags: cleartext protocol(s) detected: FTP, TELNET; anonymous/unauthenticated access risk on: FTP. Review all recommendations below in priority order.

#### Port 23/tcp — TELNET (Critical, Priority 1)
**Category:** Remote Access / Cleartext Shell  
**Context:** Unencrypted remote shell transmitting all data — including credentials — in cleartext over the network. No legitimate use case exists in modern infrastructure. Presence indicates a legacy device or a critical misconfiguration.  
**Rationale:** TELNET is assessed at Critical risk. Immediate triage and potential host isolation are warranted. This protocol transmits data in cleartext — credentials and content are exposed to interception on the network path. MITRE ATT&CK relevance: Initial Access.  
**Action:** Treat all credentials used over this connection as compromised. Disable telnet immediately. Initiate credential rotation for all accounts that may have authenticated over this service. Notify the security team and log all connected sessions in the incident record.  

#### Port 21/tcp — FTP (High, Priority 2)
**Category:** File Transfer / Cleartext FTP  
**Context:** Cleartext file transfer protocol transmitting all data — including credentials — unencrypted over the network. High risk for anonymous access and credential interception. Should be replaced by SFTP or FTPS in all modern environments.  
**Rationale:** FTP is assessed at High risk. Prompt investigation is required before the next business day. This protocol transmits data in cleartext — credentials and content are exposed to interception on the network path. Unauthenticated or anonymous access is common with this service — authentication enforcement must be verified before treating the service as secured. This service has a documented CVE history (1 notable CVE(s) on record) — patch status must be confirmed as part of triage. MITRE ATT&CK relevance: Initial Access, Collection.  
**Action:** Audit FTP access logs for unauthorised sessions. Restrict accessible directories to least-privilege. Treat all FTP credentials as potentially compromised and initiate rotation.  
**CVEs:** CVE-2011-1137  

#### Port 5900/tcp — VNC (High, Priority 2)
**Category:** Remote Access / Remote Desktop  
**Context:** Lightweight remote desktop protocol. Frequently deployed without passwords or with weak credentials. Transmits screen contents in cleartext in many configurations. Often exposed unintentionally on developer or lab systems.  
**Rationale:** VNC is assessed at High risk. Prompt investigation is required before the next business day. MITRE ATT&CK relevance: Initial Access, Lateral Movement.  
**Action:** Check for null authentication immediately. Restrict VNC to localhost and require an SSH tunnel for all external access. Review VNC access logs for unauthorised sessions.  

---
_Report generated by Sentinel_Fusion SOC Pipeline_
