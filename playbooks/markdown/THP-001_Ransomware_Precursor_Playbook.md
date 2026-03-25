**THREAT HUNTING PLAYBOOK**

Ransomware Precursor Activity Detection

|                  |                                                                        |
|------------------|------------------------------------------------------------------------|
| **Field**        | **Value**                                                              |
| Playbook ID      | THP-001                                                                |
| Severity         | CRITICAL                                                               |
| Author           | Muhammed Can                                                           |
| Version          | 2.0                                                                    |
| Last Updated     | 2026-03-24                                                             |
| Technology Stack | Splunk (SIEM) + CrowdStrike Falcon (EDR)                               |
| Status           | Active                                                                 |
| Next Review      | 2026-06-24                                                             |
| Tags             | ransomware, lateral-movement, discovery, pre-ransomware, cobalt-strike |

**1. HUNT HYPOTHESIS & DESCRIPTION**

**Hypothesis**

Ransomware operatives do not deploy encryption payloads instantly upon gaining initial access. Analysis of intrusions attributed to BlackCat (ALPHV), LockBit 3.0, Black Basta, Akira, and Scattered Spider reveals a constant operational pattern: threat actors stage their attack over a period of 48–72 hours (in some cases longer than this) before executing the final ransomware payload. Throughout this dwell time, operatives utilize Active Directory enumeration, credential harvesting, lateral movement, data exfiltration, and security tool tampering.

> *"If a threat actor has gained initial access and is preparing to deploy ransomware, we should observe a cluster of behavioral indicators — including AD enumeration, credential dumping, C2 beaconing, backup interference, and security tool tampering — within a compressed timeframe of 48–72 hours."*

**Threat Intelligence Context**

The following ransomware groups and their documented TTPs further confirms this playbook´s departure point. Dwell time data is derived from The DFIR Report, Mandiant M-Trends, and CISA advisories.

|                  |                                                           |                    |
|------------------|-----------------------------------------------------------|--------------------|
| **Threat Group** | **Known TTPs**                                            | **Avg Dwell Time** |
| BlackCat (ALPHV) | Cobalt Strike, ExMatter exfiltration, ESXi targeting      | 4–9 days           |
| LockBit 3.0      | RMM abuse, Mimikatz, wevtutil log clearing                | 1–5 days           |
| Black Basta      | QakBot delivery, SystemBC proxy, AD enumeration           | 2–7 days           |
| Akira            | AnyDesk/RMM abuse, LSASS dumping, domain admin escalation | 2–5 days           |
| Scattered Spider | Social engineering, MFA bypass, cloud-identity pivot      | Variable           |

**Attack Timeline Overview**

The following generalized timeline represents the typical progression from initial access to ransomware deployment, based on observed incidents:

> T-72h  Initial Access (Phishing, VPN exploit, RMM abuse)
>
> T-60h  C2 Establishment (Cobalt Strike beacon, SystemBC, Sliver)
>
> T-48h  Internal Discovery (ADFind, BloodHound, net commands, nltest)
>
> T-36h  Credential Access (Mimikatz, LSASS dump, Kerberoasting)
>
> T-24h  Lateral Movement (PsExec, WMI, RDP, Pass-the-Hash)
>
> T-12h  Pre-Deployment (Backup deletion, AV tampering, exfiltration)
>
> T-0h  RANSOMWARE DEPLOYMENT

**2. MITRE ATT&CK MAPPING**

All technique IDs below are sourced from the MITRE ATT&CK Enterprise framework (https://attack.mitre.org). Each ID links to the canonical MITRE page for verification.

|                      |                  |                                 |
|----------------------|------------------|---------------------------------|
| **Kill Chain Phase** | **Technique ID** | **Technique Name**              |
| Initial Access       | T1566            | Phishing                        |
| Initial Access       | T1133            | External Remote Services        |
| Execution            | T1059.001        | PowerShell                      |
| Execution            | T1059.003        | Windows Command Shell           |
| Persistence          | T1543.003        | Windows Service                 |
| Persistence          | T1219            | Remote Access Software          |
| Discovery            | T1069            | Permission Groups Discovery     |
| Discovery            | T1087            | Account Discovery               |
| Discovery            | T1482            | Domain Trust Discovery          |
| Discovery            | T1083            | File and Directory Discovery    |
| Credential Access    | T1003.001        | LSASS Memory                    |
| Credential Access    | T1558.003        | Kerberoasting                   |
| Lateral Movement     | T1570            | Lateral Tool Transfer           |
| Lateral Movement     | T1021.001        | Remote Desktop Protocol         |
| Lateral Movement     | T1550.002        | Pass the Hash                   |
| Command & Control    | T1071.001        | Application Layer Protocol: Web |
| Command & Control    | T1090            | Proxy                           |
| Exfiltration         | T1567            | Exfiltration Over Web Service   |
| Impact               | T1490            | Inhibit System Recovery         |
| Impact               | T1562.001        | Disable or Modify Tools         |
| Impact               | T1486            | Data Encrypted for Impact       |

**3. REQUIRED DATA SOURCES**

**Log Sources**

|                                        |                                                                      |              |
|----------------------------------------|----------------------------------------------------------------------|--------------|
| **Log Source**                         | **Purpose**                                                          | **Priority** |
| Windows Security Event Logs            | Logon events (4624/4625), account activity, service installs (7045)  | Critical     |
| Sysmon (EventID 1,3,7,8,10,11,13)      | Process creation, network connections, file creation, process access | Critical     |
| PowerShell Script Block Logging (4104) | Detects encoded/obfuscated PowerShell execution                      | Critical     |
| Active Directory Logs                  | Account enumeration, group membership changes, GPO modifications     | Critical     |
| CrowdStrike Falcon EDR Telemetry       | Process trees, memory access, DNS queries, file operations           | Critical     |
| Network / Firewall Logs                | C2 beaconing, unusual outbound connections, lateral movement         | High         |
| VPN / Remote Access Logs               | Initial access detection, unusual geographic logons                  | High         |
| Backup Solution Logs (Veeam, etc.)     | Backup deletion or tampering detection                               | High         |
| AV/EDR Alert Logs                      | Security tool tampering, detection suppression                       | Medium       |

**Required Tooling**

- SIEM: Splunk Enterprise / Splunk Cloud (all SIEM queries in this playbook use SPL)

- EDR: CrowdStrike Falcon (all EDR queries use Falcon / LogScale syntax)

- Network Monitoring: Zeek, Suricata, or dedicated NDR solution (e.g., Vectra AI)

- Threat Intelligence Platform: MISP, OpenCTI, Recorded Future, or SOCRadar

**Recommended Supplemental Tools**

- **Velociraptor** — Endpoint hunting and artifact collection at scale (https://docs.velociraptor.app)

- **KAPE** — Kroll Artifact Parser and Extractor for triage collection

- **Chainsaw** — Rapid Windows event log analysis (https://github.com/WithSecureLabs/chainsaw)

- **BloodHound** — Active Directory attack path visualization for defensive use

**4. SPLUNK SPL QUERIES**

All queries below are written in valid Splunk Processing Language (SPL). Adjust index names, sourcetypes, and field names to match your Splunk deployment. Inline comments (prefixed with \`\| \`) explain the logic.

**Phase 1: Initial Access & Foothold Detection**

Goal: Identify first-time-seen RMM tools, suspicious logon patterns, and phishing-driven process chains.

**SPL 1.1 — Unauthorized RMM Tool Installation**

> \`\`\` Detects first-time execution of common RMM tools abused by ransomware operators.
>
> Maps to: T1219 (Remote Access Software)
>
> Source: Sysmon EventCode 1 (Process Creation) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (Image="\*\\anydesk.exe" OR Image="\*\\atera_agent.exe"
>
> OR Image="\*\\ScreenConnect.ClientService.exe"
>
> OR Image="\*\\teamviewer.exe" OR Image="\*\\splashtop\*.exe"
>
> OR Image="\*\\netsupport\*.exe" OR Image="\*\\rustdesk.exe")
>
> \| stats earliest(\_time) AS first_seen, count BY dest, Image, User, ParentImage
>
> \| where first_seen \> relative_time(now(), "-72h")
>
> \`\`\` Filter: Only RMM tools seen for the first time in the last 72 hours \`\`\`
>
> \| sort - first_seen
>
> \| table first_seen, dest, User, Image, ParentImage, count

**SPL 1.2 — VPN Logon from New or Unusual Source IP**

> \`\`\` Identifies VPN logons from IP addresses not seen in the prior 30 days.
>
> Maps to: T1133 (External Remote Services) \`\`\`
>
> index=vpn sourcetype=vpn_logs action=success
>
> \| stats earliest(\_time) AS first_logon, latest(\_time) AS last_logon, count BY src_ip, user
>
> \| where first_logon \> relative_time(now(), "-72h")
>
> \| lookup known_vpn_ips.csv src_ip OUTPUT known
>
> \`\`\` Lookup: Cross-reference against a baseline of known VPN source IPs \`\`\`
>
> \| where isnull(known)
>
> \| table first_logon, user, src_ip, count

**SPL 1.3 — Suspicious Parent-Child Process Chains**

> \`\`\` Detects Office applications or email clients spawning scripting interpreters.
>
> Maps to: T1566 (Phishing), T1059.001 (PowerShell) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (ParentImage="\*\\outlook.exe" OR ParentImage="\*\\winword.exe"
>
> OR ParentImage="\*\\excel.exe" OR ParentImage="\*\\mshta.exe")
>
> (Image="\*\\powershell.exe" OR Image="\*\\cmd.exe"
>
> OR Image="\*\\wscript.exe" OR Image="\*\\cscript.exe"
>
> OR Image="\*\\mshta.exe" OR Image="\*\\rundll32.exe")
>
> \| table \_time, dest, User, ParentImage, Image, CommandLine

**SPL 1.4 — New Windows Service Installed**

> \`\`\` Detects new services being registered, a common persistence mechanism.
>
> Maps to: T1543.003 (Windows Service)
>
> Source: Windows Security EventCode 7045 \`\`\`
>
> index=windows EventCode=7045
>
> \| table \_time, dest, Service_Name, Service_File_Name, Service_Start_Type, Service_Account
>
> \| search NOT \[\| inputlookup approved_services.csv \| fields Service_Name\]
>
> \`\`\` Filter: Exclude services from your known-good baseline \`\`\`

**Phase 2: Discovery & Enumeration**

Goal: Detect Active Directory enumeration, reconnaissance commands, and LDAP query abuse.

**SPL 2.1 — Rapid Discovery Command Burst**

> \`\`\` Detects multiple built-in reconnaissance commands executed in a short window.
>
> Maps to: T1087 (Account Discovery), T1069 (Permission Groups Discovery) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (Image="\*\\net.exe" OR Image="\*\\net1.exe" OR Image="\*\\nltest.exe"
>
> OR Image="\*\\whoami.exe" OR Image="\*\\ipconfig.exe"
>
> OR Image="\*\\systeminfo.exe" OR Image="\*\\tasklist.exe"
>
> OR Image="\*\\qprocess.exe")
>
> \| bin \_time span=5m
>
> \`\`\` Bucket events into 5-minute windows to detect bursts \`\`\`
>
> \| stats dc(Image) AS unique_tools, values(Image) AS tools_used, count BY \_time, dest, User
>
> \| where unique_tools \>= 3
>
> \`\`\` Threshold: 3+ distinct recon tools within 5 minutes is anomalous \`\`\`
>
> \| sort - unique_tools

**SPL 2.2 — AD Enumeration Tool Execution**

> \`\`\` Detects execution of known AD enumeration tools.
>
> Maps to: T1482 (Domain Trust Discovery), T1069 (Permission Groups) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (Image="\*\\adfind.exe" OR Image="\*\\sharphound.exe"
>
> OR Image="\*\\bloodhound.exe" OR Image="\*\\ldifde.exe"
>
> OR CommandLine="\*Get-DomainTrust\*" OR CommandLine="\*Get-NetDomain\*"
>
> OR CommandLine="\*Invoke-BloodHound\*")
>
> \| table \_time, dest, User, Image, CommandLine, ParentImage

**SPL 2.3 — LDAP Query Spike from Non-DC Host**

> \`\`\` Detects workstations or member servers generating unusual LDAP traffic to DCs.
>
> Maps to: T1087 (Account Discovery) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
>
> DestinationPort=389 OR DestinationPort=636
>
> NOT src_ip IN (10.0.0.1, 10.0.0.2)
>
> \`\`\` Exclude your Domain Controller IPs above \`\`\`
>
> \| bin \_time span=1h
>
> \| stats count BY \_time, SourceIp, dest, User
>
> \| where count \> 500
>
> \`\`\` Threshold: Adjust 500 based on your environment baseline \`\`\`

**Phase 3: Credential Access**

Goal: Detect LSASS memory access, Kerberoasting, and credential dumping activity.

**SPL 3.1 — Suspicious LSASS Memory Access (Sysmon Event 10)**

> \`\`\` Detects non-standard processes accessing LSASS memory, indicative of credential dumping.
>
> Maps to: T1003.001 (OS Credential Dumping: LSASS Memory)
>
> GrantedAccess values 0x1010, 0x1410, 0x147a, 0x1fffff are commonly used by
>
> Mimikatz and similar tools. \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
>
> TargetImage="\*\\lsass.exe"
>
> NOT SourceImage IN ("\*\\MsMpEng.exe", "\*\\csrss.exe",
>
> "\*\\wininit.exe", "\*\\svchost.exe", "\*\\lsass.exe",
>
> "\*\\wmiprvse.exe", "\*\\taskmgr.exe")
>
> \`\`\` Allowlist: Add your EDR agent and known security tool paths here \`\`\`
>
> \| table \_time, dest, SourceImage, TargetImage, GrantedAccess, SourceProcessGUID
>
> \| sort - \_time

**SPL 3.2 — Kerberoasting Detection (Event 4769)**

> \`\`\` Detects Kerberos TGS requests using RC4 encryption (0x17), which is anomalous in
>
> modern AD environments that should prefer AES. Filters out machine accounts and krbtgt.
>
> Maps to: T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) \`\`\`
>
> index=windows EventCode=4769 Ticket_Encryption_Type=0x17
>
> ServiceName!="krbtgt" ServiceName!="\*\$"
>
> \`\`\` Exclude machine accounts (\*\$) and the krbtgt account \`\`\`
>
> \| bin \_time span=1h
>
> \| stats count, dc(ServiceName) AS unique_spns BY \_time, Account_Name, Client_Address
>
> \| where count \> 5 OR unique_spns \> 3
>
> \`\`\` Alert: 5+ RC4 TGS requests or 3+ unique SPNs from a single account is suspicious \`\`\`
>
> \| sort - count

**SPL 3.3 — Credential Dump Tool Execution**

> \`\`\` Detects execution of common credential dumping utilities.
>
> Maps to: T1003.001 (LSASS Memory) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (CommandLine="\*sekurlsa\*" OR CommandLine="\*lsadump\*"
>
> OR CommandLine="\*procdump\*lsass\*"
>
> OR CommandLine="\*comsvcs.dll\*MiniDump\*"
>
> OR CommandLine="\*Out-Minidump\*"
>
> OR Image="\*\\mimikatz.exe" OR Image="\*\\procdump\*.exe")
>
> \| table \_time, dest, User, Image, CommandLine, ParentImage

**Phase 4: Lateral Movement**

Goal: Detect PsExec, WMI remote execution, RDP anomalies, and Pass-the-Hash indicators.

**SPL 4.1 — PsExec Service Installation on Remote Hosts**

> \`\`\` Detects the PsExec service (PSEXESVC) being installed on endpoints.
>
> Maps to: T1570 (Lateral Tool Transfer), T1543.003 (Windows Service) \`\`\`
>
> index=windows (EventCode=7045 Service_Name="PSEXESVC")
>
> OR (EventCode=1 Image="\*\\psexesvc.exe")
>
> \| stats count BY \_time, dest, Service_File_Name, User
>
> \| sort - \_time

**SPL 4.2 — NTLM Lateral Movement Spray (Pass-the-Hash Indicator)**

> \`\`\` Detects a single source making NTLM network logons to many hosts in a short window.
>
> Maps to: T1550.002 (Use Alternate Authentication Material: Pass the Hash) \`\`\`
>
> index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
>
> \| bin \_time span=1h
>
> \| stats dc(dest) AS unique_hosts, values(dest) AS targets BY \_time, Source_Network_Address, Account_Name
>
> \| where unique_hosts \>= 10
>
> \`\`\` Threshold: Single source NTLM-authenticating to 10+ hosts in 1 hour \`\`\`
>
> \| sort - unique_hosts

**SPL 4.3 — Anomalous RDP Connections (Workstation to Workstation)**

> \`\`\` Flags RDP sessions between workstations, which is abnormal in most environments.
>
> Maps to: T1021.001 (Remote Desktop Protocol) \`\`\`
>
> index=windows EventCode=4624 Logon_Type=10
>
> \`\`\` Type 10 = RemoteInteractive (RDP) \`\`\`
>
> \| search NOT dest IN ("DC01", "DC02", "JUMP01")
>
> \`\`\` Exclude Domain Controllers and authorized jump hosts \`\`\`
>
> \| stats count BY \_time, Source_Network_Address, dest, Account_Name
>
> \| lookup workstation_inventory.csv dest OUTPUT asset_type
>
> \| where asset_type="workstation"
>
> \`\`\` Flag: Workstations receiving RDP from other workstations \`\`\`

**SPL 4.4 — WMI Remote Process Creation**

> \`\`\` Detects WMI being used for remote command execution.
>
> Maps to: T1047 (Windows Management Instrumentation) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> ParentImage="\*\\wmiprvse.exe"
>
> NOT Image IN ("\*\\svchost.exe", "\*\\werfault.exe")
>
> \| table \_time, dest, User, ParentImage, Image, CommandLine

**Phase 5: Pre-Deployment Indicators**

> **⚠** CRITICAL: These indicators suggest ransomware deployment is imminent. Treat any match as a P1 incident.

**SPL 5.1 — Shadow Copy / Backup Deletion**

> \`\`\` Detects deletion of Volume Shadow Copies or Windows Recovery disabling.
>
> Maps to: T1490 (Inhibit System Recovery) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
>
> (CommandLine="\*vssadmin\*delete\*shadows\*"
>
> OR CommandLine="\*wmic\*shadowcopy\*delete\*"
>
> OR CommandLine="\*wbadmin\*delete\*catalog\*"
>
> OR CommandLine="\*bcdedit\*/set\*recoveryenabled\*no\*"
>
> OR CommandLine="\*bcdedit\*/set\*bootstatuspolicy\*ignoreallfailures\*")
>
> \| table \_time, dest, User, Image, CommandLine, ParentImage, ParentCommandLine

**SPL 5.2 — Windows Event Log Clearing**

> \`\`\` Detects clearing of Windows event logs, a common anti-forensics technique.
>
> Maps to: T1070.001 (Indicator Removal: Clear Windows Event Logs)
>
> EventCode 104 = System log cleared, 1102 = Security audit log cleared \`\`\`
>
> index=windows (EventCode=104 OR EventCode=1102)
>
> \| table \_time, dest, user, EventCode, Message
>
> \| sort - \_time

**SPL 5.3 — Security Service Stopped or Disabled**

> \`\`\` Detects security-related services being stopped or their start type changed.
>
> Maps to: T1562.001 (Impair Defenses: Disable or Modify Tools) \`\`\`
>
> index=windows (EventCode=7036 OR EventCode=7040)
>
> (Message="\*Windows Defender\*" OR Message="\*CrowdStrike\*"
>
> OR Message="\*Carbon Black\*" OR Message="\*SentinelOne\*"
>
> OR Message="\*Symantec\*" OR Message="\*McAfee\*"
>
> OR Message="\*Sophos\*" OR Message="\*Cylance\*")
>
> \`\`\` Adjust the service name list to match your deployed security stack \`\`\`
>
> \| table \_time, dest, EventCode, Message

**SPL 5.4 — Exfiltration to Cloud Storage (rclone / Mega)**

> \`\`\` Detects use of rclone or connections to known exfiltration cloud services.
>
> Maps to: T1567 (Exfiltration Over Web Service) \`\`\`
>
> index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
>
> (EventCode=1 (Image="\*\\rclone.exe" OR CommandLine="\*rclone\*"))
>
> OR (EventCode=3 (DestinationHostname="\*mega.nz" OR DestinationHostname="\*mega.co.nz"
>
> OR DestinationHostname="\*transfer.sh" OR DestinationHostname="\*anonfiles.com"
>
> OR DestinationHostname="\*send.exploit.in"))
>
> \| table \_time, dest, User, Image, CommandLine, DestinationIp, DestinationHostname

**SPL 5.5 — GPO Modification by Non-Admin Account**

> \`\`\` Detects Group Policy Object changes that could be used to push ransomware payloads.
>
> Maps to: T1484.001 (Domain Policy Modification: Group Policy Modification) \`\`\`
>
> index=windows EventCode=5136 ObjectClass="groupPolicyContainer"
>
> \| table \_time, dest, SubjectUserName, ObjectDN, AttributeLDAPDisplayName, AttributeValue
>
> \| search NOT SubjectUserName IN ("svc_gpo_admin", "domain_admin_account")
>
> \`\`\` Exclude known GPO administrator accounts \`\`\`

**5. CROWDSTRIKE FALCON EDR QUERIES**

The following queries are written for CrowdStrike Falcon Long Term Repository (LTR) / LogScale query syntax. Adjust field names if using a different CrowdStrike data pipeline. Inline comments explain each query’s logic.

**CS 1 — Unauthorized RMM Tool Execution**

> // Detects execution of RMM tools commonly abused by ransomware operators.
>
> // Maps to: T1219 (Remote Access Software)
>
> \#event_simpleName=ProcessRollup2
>
> \| ImageFileName=/\\(anydesk\|atera_agent\|ScreenConnect\|teamviewer\|
>
> splashtop\|netsupport\|rustdesk)\\exe\$/i
>
> \| groupBy(\[aid, ComputerName, ImageFileName, ParentBaseFileName, UserName\],
>
> function=count())
>
> \| sort(count, order=desc)

**CS 2 — LSASS Memory Access (Credential Dumping)**

> // Detects non-standard processes accessing LSASS memory.
>
> // Maps to: T1003.001 (LSASS Memory)
>
> \#event_simpleName=ProcessRollup2 OR \#event_simpleName=SyntheticProcessRollup2
>
> \| TargetFileName=/lsass\\exe/i
>
> \| ImageFileName!=/\\(MsMpEng\|csrss\|wininit\|svchost\|lsass)\\exe\$/i
>
> \| select(\[timestamp, aid, ComputerName, ImageFileName,
>
> ParentBaseFileName, UserName\])

*Note: For deeper LSASS access telemetry, also review CrowdStrike’s built-in detection “Credential Dumping via LSASS Access” in the Falcon console under Detections \> Custom IOAs.*

**CS 3 — Rapid Discovery Command Burst**

> // Detects multiple reconnaissance commands in a short window.
>
> // Maps to: T1087 (Account Discovery), T1069 (Permission Groups)
>
> \#event_simpleName=ProcessRollup2
>
> \| ImageFileName=/\\(net\|net1\|nltest\|whoami\|ipconfig\|
>
> systeminfo\|tasklist\|qprocess)\\exe\$/i
>
> \| bucket(timestamp, span=5m)
>
> \| groupBy(\[aid, ComputerName, UserName, \_bucket\],
>
> function=\[count(), collectDistinct(ImageFileName)\])
>
> \| count \> 3

**CS 4 — PsExec Lateral Movement**

> // Detects PSEXESVC service binary or PsExec execution on endpoints.
>
> // Maps to: T1570 (Lateral Tool Transfer)
>
> \#event_simpleName=ProcessRollup2
>
> \| ImageFileName=/\\psexe(c\|svc)\\exe\$/i
>
> \| select(\[timestamp, aid, ComputerName, ImageFileName,
>
> CommandLine, ParentBaseFileName, UserName\])
>
> \| sort(timestamp, order=desc)

**CS 5 — Shadow Copy / Backup Deletion**

> // Detects shadow copy deletion or recovery disabling commands.
>
> // Maps to: T1490 (Inhibit System Recovery)
>
> \#event_simpleName=ProcessRollup2
>
> \| CommandLine=/(?i)(vssadmin.\*delete.\*shadows\|wmic.\*shadowcopy.\*delete
>
> \|wbadmin.\*delete.\*catalog\|bcdedit.\*recoveryenabled.\*no)/
>
> \| select(\[timestamp, aid, ComputerName, UserName,
>
> ImageFileName, CommandLine, ParentBaseFileName\])

**CS 6 — Security Tool Tampering**

> // Detects attempts to stop or uninstall security tools.
>
> // Maps to: T1562.001 (Disable or Modify Tools)
>
> \#event_simpleName=ProcessRollup2
>
> \| CommandLine=/(?i)(net\s+stop\|sc\s+stop\|sc\s+delete\|sc\s+config.\*disabled)
>
> .\*(defender\|crowdstrike\|sentinel\|symantec\|carbon\|sophos\|mcafee\|cylance)/
>
> \| select(\[timestamp, aid, ComputerName, UserName,
>
> ImageFileName, CommandLine\])

**CS 7 — Kerberoasting Indicators**

> // Logic description: CrowdStrike Falcon does not natively expose raw Windows
>
> // Event 4769 fields in LogScale. Kerberoasting is best detected through:
>
> // 1. Falcon’s built-in detection: "Credential Access via Kerberoasting"
>
> // in Detections \> Custom IOAs
>
> // 2. Forwarding Windows Security 4769 events to Splunk (see SPL 3.2)
>
> // 3. Using CrowdStrike Identity Protection if licensed
>
> // Supplemental: Detect known Kerberoasting tool execution
>
> \#event_simpleName=ProcessRollup2
>
> \| CommandLine=/(?i)(rubeus.\*kerberoast\|Invoke-Kerberoast\|
>
> GetUserSPNs\\py)/
>
> \| select(\[timestamp, aid, ComputerName, UserName,
>
> ImageFileName, CommandLine\])

**CS 8 — Exfiltration Tool Execution**

> // Detects use of rclone or known exfiltration tools.
>
> // Maps to: T1567 (Exfiltration Over Web Service)
>
> \#event_simpleName=ProcessRollup2
>
> \| ImageFileName=/\\rclone\\exe\$/i OR CommandLine=/(?i)rclone/
>
> \| select(\[timestamp, aid, ComputerName, UserName,
>
> ImageFileName, CommandLine, ParentBaseFileName\])

**6. KNOWN FALSE POSITIVES & TUNING GUIDANCE**

Each detection in this playbook will generate false positives if not properly tuned to your environment. The table below provides guidance for each hunt category.

|                         |                                                                                  |                                                                               |
|-------------------------|----------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Hunt Category**       | **Common False Positives**                                                       | **Tuning Recommendation**                                                     |
| Shadow Copy Deletion    | Backup software (Veeam, Backup Exec, Commvault) performing scheduled maintenance | Allowlist known backup service accounts and scheduled maintenance windows     |
| LSASS Memory Access     | EDR/AV engines, SCCM client, security scanning tools                             | Allowlist by SourceImage path for known and verified security tools           |
| Kerberoasting (RC4 TGS) | Legitimate service accounts with legacy applications requiring RC4               | Baseline normal TGS request volume per account; flag deviations from baseline |
| Discovery Command Burst | IT admin scripts, helpdesk automation, SCCM client inventory                     | Allowlist known admin workstations and automation service accounts            |
| RMM Tool Detection      | Approved IT support tools (e.g., corporate TeamViewer deployment)                | Maintain an approved RMM software inventory; alert only on unapproved tools   |
| Event Log Clearing      | SIEM agent log rotation, GPO-driven log management                               | Allowlist known SIEM and log management service accounts                      |
| PsExec Lateral Movement | Legitimate sysadmin use of PsExec for remote management                          | Restrict PsExec usage to designated jump hosts; alert on all other endpoints  |
| Security Tool Tampering | Planned maintenance, endpoint agent upgrades                                     | Correlate with change management tickets; alert on unscheduled stops          |

**7. RESPONSE ACTIONS**

**Immediate (0–15 minutes)**

- [ ] Isolate affected host(s) from the network via CrowdStrike Falcon network containment

- [ ] Preserve memory dump of suspicious processes before isolation (use Falcon RTR or Velociraptor)

- [ ] Notify IR lead and escalate to P1 incident

- [ ] Revoke and reset credentials of any confirmed-compromised accounts

- [ ] Block identified C2 IP addresses and domains at firewall and proxy

**Short-Term (15 minutes – 2 hours)**

- [ ] Identify patient zero — trace the initial access vector

- [ ] Scope lateral movement: identify all systems the threat actor accessed

- [ ] Hunt for persistence mechanisms (scheduled tasks, services, registry Run keys)

- [ ] Review all privileged account activity over the prior 72 hours

- [ ] Engage backup team to verify backup integrity before any restoration attempt

**Containment**

- [ ] Reset all privileged account passwords (Domain Admins, service accounts)

- [ ] Reset the krbtgt account password twice (10+ hours apart) if Golden/Silver Ticket is suspected

- [ ] Block all identified attacker infrastructure across all perimeter controls

- [ ] Force re-authentication across the environment (revoke all active sessions)

- [ ] Harden the initial access vector (patch VPN, enforce MFA, audit RMM access)

**Recovery**

- [ ] Restore systems from verified-clean backups only after full scoping is complete

- [ ] Rebuild compromised systems from clean base images

- [ ] Deploy enhanced monitoring on all recovered systems for 30 days minimum

- [ ] Conduct post-incident review within 72 hours; update this playbook with lessons learned

**8. LAB VALIDATION**

>  All testing described below was performed in an isolated lab environment. Never execute offensive tools in production.

**Lab Environment**

- Windows Server 2019 Domain Controller

- Windows 10 Workstation (victim endpoint)

- Kali Linux (attacker endpoint)

- Sysmon deployed with SwiftOnSecurity configuration (https://github.com/SwiftOnSecurity/sysmon-config)

- Splunk Enterprise (SIEM) for log collection and query validation

**Validated Detections**

|                         |                                   |            |                                                   |
|-------------------------|-----------------------------------|------------|---------------------------------------------------|
| **Detection**           | **Tool Used**                     | **Result** | **Notes**                                         |
| LSASS Memory Dump       | Mimikatz sekurlsa::logonpasswords | Detected   | Sysmon EventID 10 triggered; SPL 3.1 matched      |
| Shadow Copy Deletion    | vssadmin delete shadows /all      | Detected   | SPL 5.1 matched; CrowdStrike CS 5 matched         |
| Kerberoasting           | Rubeus.exe kerberoast             | Detected   | EventID 4769 with RC4 (0x17); SPL 3.2 matched     |
| PsExec Lateral Movement | PsExec.exe \\victim cmd           | Detected   | PSEXESVC service creation logged; SPL 4.1 matched |
| BloodHound Enumeration  | SharpHound.exe -c All             | Detected   | LDAP query spike detected; SPL 2.2 matched        |
| Discovery Burst         | net user/group/nltest in sequence | Detected   | SPL 2.1 flagged 5 tools in \<2 minutes            |

**9. CREDIBLE SOURCES & REFERENCES**

**Threat Intelligence**

- **CISA StopRansomware Advisories —** https://www.cisa.gov/stopransomware

- **CISA StopRansomware Guide —** https://www.cisa.gov/stopransomware/ransomware-guide

- **The DFIR Report (Real Intrusion Case Studies) —** https://thedfirreport.com/

- **Microsoft DART: Human-Operated Ransomware —** https://www.microsoft.com/en-us/security/blog/2020/03/05/human-operated-ransomware-attacks-a-preventable-disaster/

- **Mandiant M-Trends Report —** https://www.mandiant.com/resources/m-trends

- **Mandiant/Google Threat Intelligence Blog —** https://www.mandiant.com/resources/blog

- **Microsoft Security Blog (Ransomware Tag) —** https://www.microsoft.com/en-us/security/blog/tag/ransomware/

**MITRE ATT&CK Technique References**

- **T1490 — Inhibit System Recovery:** https://attack.mitre.org/techniques/T1490/

- **T1003.001 — LSASS Memory:** https://attack.mitre.org/techniques/T1003/001/

- **T1558.003 — Kerberoasting:** https://attack.mitre.org/techniques/T1558/003/

- **T1570 — Lateral Tool Transfer:** https://attack.mitre.org/techniques/T1570/

- **T1562.001 — Disable or Modify Tools:** https://attack.mitre.org/techniques/T1562/001/

- **T1219 — Remote Access Software:** https://attack.mitre.org/techniques/T1219/

- **T1566 — Phishing:** https://attack.mitre.org/techniques/T1566/

- **T1059.001 — PowerShell:** https://attack.mitre.org/techniques/T1059/001/

- **T1550.002 — Pass the Hash:** https://attack.mitre.org/techniques/T1550/002/

- **T1021.001 — Remote Desktop Protocol:** https://attack.mitre.org/techniques/T1021/001/

- **T1567 — Exfiltration Over Web Service:** https://attack.mitre.org/techniques/T1567/

- **T1486 — Data Encrypted for Impact:** https://attack.mitre.org/techniques/T1486/

**Tools & Frameworks**

- **Sigma Rules Repository —** https://github.com/SigmaHQ/sigma

- **Velociraptor Documentation —** https://docs.velociraptor.app/

- **Sysmon Config (SwiftOnSecurity) —** https://github.com/SwiftOnSecurity/sysmon-config

- **MITRE ATT&CK Navigator —** https://mitre-attack.github.io/attack-navigator/

- **CrowdStrike Falcon LogScale Documentation —** https://library.humio.com/

- **Splunk SPL Documentation —** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

Playbook Status: **Active** \| Next Review: 2026-06-24 \| Validated Against: LockBit 3.0, Black Basta, Akira TTPs

GitHub: https://github.com/survivedwannacry
