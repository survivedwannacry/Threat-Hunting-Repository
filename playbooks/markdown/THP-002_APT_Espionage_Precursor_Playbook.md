**THREAT HUNTING PLAYBOOK**

Top 5 APT Groups Hunting Playbook

|                      |                                                                                                      |
|----------------------|------------------------------------------------------------------------------------------------------|
| **Field**            | **Value**                                                                                            |
| **Playbook ID**      | THP-002                                                                                              |
| **Severity**         | CRITICAL                                                                                             |
| **Author**           | Muhammed Can                                                                                         |
| **Version**          | 1.0                                                                                                  |
| **Last Updated**     | 2026-03-25                                                                                           |
| **Technology Stack** | Splunk (SIEM)                                                                                        |
| **Status**           | Active                                                                                               |
| **Next Review**      | 2026-06-25                                                                                           |
| **Tags**             | APT, espionage, nation-state, lateral-movement, credential-access, living-off-the-land, supply-chain |

1\. HUNT HYPOTHESIS & DESCRIPTION

**Hypothesis**

Nation-state Advanced Persistent Threat (APT) groups do not compromise a target and immediately begin large-scale data exfiltration. Intelligence derived from Mandiant M-Trends 2025, CISA advisories, Microsoft Threat Intelligence, Unit 42, Kaspersky GReAT, and Red Canary confirms that APT operators maintain prolonged dwell times ranging from weeks to months (and in some cases years), during which they perform systematic reconnaissance, credential harvesting, lateral movement, persistence establishment, and staged exfiltration. By hunting for the behavioral precursors common across the top five most active APT groups, defenders can detect and disrupt espionage operations before strategic data loss occurs.

> *"If a nation-state APT group has achieved initial access to our environment, we should observe a cluster of behavioral indicators including spearphishing-driven process chains, living-off-the-land binary abuse, credential dumping, Active Directory enumeration, lateral movement via legitimate remote services, and staged exfiltration to cloud services or custom C2 channels within a compressed timeframe."*

**Threat Intelligence Context**

The following five APT groups represent the most active and consequential state-sponsored threat actors in 2024-2025, as assessed by Mandiant/Google Threat Intelligence Group, Microsoft Threat Intelligence, CISA, CrowdStrike, Unit 42, Kaspersky, and Red Canary. Their TTPs form the foundation of this playbook.

|                   |                         |                                               |                                                                                                                           |                                                                                     |
|-------------------|-------------------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| **APT Group**     | **Attribution**         | **Aliases**                                   | **Primary TTPs**                                                                                                          | **Key Sources**                                                                     |
| **APT29**         | Russia / SVR            | Cozy Bear, Midnight Blizzard, NOBELIUM        | Spearphishing, OAuth abuse, cloud identity compromise, WINELOADER/ROOTSAW malware, WMI/PowerShell LOTL                    | MITRE G0016, Mandiant (2024), Microsoft (2024), NCSC-UK (2024)                      |
| **APT28**         | Russia / GRU Unit 26165 | Fancy Bear, Forest Blizzard, Sednit           | Password spraying, spearphishing, CVE exploitation, NTLM relay, compromised edge routers, credential harvesting           | MITRE G0007, CISA AA24-057A (2024), ESET RoundPress (2025), DoD/FBI advisory (2024) |
| **Lazarus Group** | North Korea / RGB       | Hidden Cobra, Diamond Sleet, APT38            | Supply chain compromise, fake job lures, DLL sideloading, LSASS dumping, cryptocurrency theft, custom RATs                | MITRE G0032, Unit 42 (2024), JPCERT (2025), Mandiant DPRK assessment (2023)         |
| **APT41**         | China / MSS             | Double Dragon, Brass Typhoon, Wicked Panda    | Exploit public-facing apps, web shells, DLL sideloading, certutil abuse, DUSTPAN/DUSTTRAP/BEACON, Google Calendar C2      | MITRE G0096, Mandiant/Google DUST (2024), CYFIRMA (2025), DOJ indictment (2020)     |
| **Volt Typhoon**  | China / PLA/MSS         | Bronze Silhouette, Insidious Taurus, DEV-0391 | Edge device exploitation, LOTL (ntdsutil, netsh, wmic, PowerShell), NTDS.dit theft, SOHO router proxying, minimal malware | MITRE G1017, CISA AA24-038A (2024), CISA AA23-144A (2023), Microsoft (2023)         |

**Attack Timeline Overview (Generalized APT Espionage Lifecycle)**

The following generalized timeline represents the typical progression of a nation-state espionage intrusion, synthesized from incident reports across the five APT groups:

> *Weeks 1-2: Initial Access (Spearphishing, edge device exploit, supply chain compromise, valid credential abuse)*
>
> *Weeks 2-4: Persistence & C2 (Web shells, scheduled tasks, DLL sideloading, cloud service C2, LOTL binaries)*
>
> *Weeks 3-8: Discovery & Credential Access (AD enumeration, LSASS dumping, NTDS.dit theft, Kerberoasting, keylogging)*
>
> *Weeks 4-12: Lateral Movement (RDP, SMB, WMI, PsExec, Pass-the-Hash, token manipulation)*
>
> *Weeks 8-52+: Collection & Exfiltration (Staged archives, cloud exfil via OneDrive/Google Drive/Mega, DNS tunneling, encrypted C2)*

2\. MITRE ATT&CK MAPPING

All technique IDs below are sourced from the MITRE ATT&CK Enterprise framework (https://attack.mitre.org). Each technique has been verified against the official MITRE ATT&CK group pages for APT29 (G0016), APT28 (G0007), Lazarus Group (G0032), APT41 (G0096), and Volt Typhoon (G1017).

|                       |                  |                                         |                                            |
|-----------------------|------------------|-----------------------------------------|--------------------------------------------|
| **Kill Chain Phase**  | **Technique ID** | **Technique Name**                      | **APT Groups Using This TTP**              |
| **Initial Access**    |                  |                                         |                                            |
| Initial Access        | T1566.001        | Spearphishing Attachment                | APT29, APT28, Lazarus, APT41               |
| Initial Access        | T1566.002        | Spearphishing Link                      | APT29, APT28, Lazarus, APT41               |
| Initial Access        | T1190            | Exploit Public-Facing Application       | APT41, Volt Typhoon, APT28                 |
| Initial Access        | T1133            | External Remote Services                | Volt Typhoon, APT41, APT29                 |
| Initial Access        | T1195.002        | Compromise Software Supply Chain        | APT29, Lazarus, APT41                      |
| Initial Access        | T1078            | Valid Accounts                          | APT29, Volt Typhoon, APT28                 |
| Initial Access        | T1110.003        | Password Spraying                       | APT28, APT29, Volt Typhoon                 |
| **Execution**         |                  |                                         |                                            |
| Execution             | T1059.001        | PowerShell                              | APT29, APT28, Volt Typhoon, APT41          |
| Execution             | T1059.003        | Windows Command Shell                   | Lazarus, Volt Typhoon, APT41               |
| Execution             | T1047            | Windows Management Instrumentation      | APT29, Volt Typhoon, APT41                 |
| Execution             | T1204.002        | User Execution: Malicious File          | APT28, Lazarus, APT41                      |
| **Persistence**       |                  |                                         |                                            |
| Persistence           | T1505.003        | Web Shell                               | APT41, Volt Typhoon                        |
| Persistence           | T1543.003        | Windows Service                         | APT29, Lazarus, APT41                      |
| Persistence           | T1053.005        | Scheduled Task                          | APT29, APT28, Lazarus, APT41               |
| Persistence           | T1574.002        | DLL Side-Loading                        | Lazarus, APT41, APT29                      |
| **Defense Evasion**   |                  |                                         |                                            |
| Defense Evasion       | T1070.001        | Clear Windows Event Logs                | APT28, Volt Typhoon, APT41                 |
| Defense Evasion       | T1027            | Obfuscated Files or Information         | APT29, APT28, Lazarus, APT41               |
| Defense Evasion       | T1218.011        | Signed Binary Proxy Execution: Rundll32 | Lazarus, APT41                             |
| **Discovery**         |                  |                                         |                                            |
| Discovery             | T1087            | Account Discovery                       | APT29, APT28, Lazarus, APT41, Volt Typhoon |
| Discovery             | T1069            | Permission Groups Discovery             | APT29, Volt Typhoon, APT41                 |
| Discovery             | T1082            | System Information Discovery            | All five APT groups                        |
| Discovery             | T1016            | System Network Configuration Discovery  | Volt Typhoon, APT28, Lazarus               |
| Discovery             | T1482            | Domain Trust Discovery                  | APT29, APT28, Volt Typhoon                 |
| **Credential Access** |                  |                                         |                                            |
| Credential Access     | T1003.001        | LSASS Memory                            | APT28, Lazarus, APT41, Volt Typhoon        |
| Credential Access     | T1003.003        | NTDS                                    | Volt Typhoon, APT29, APT41                 |
| Credential Access     | T1558.003        | Kerberoasting                           | APT29, APT28                               |
| Credential Access     | T1555            | Credentials from Password Stores        | APT28, Lazarus                             |
| Credential Access     | T1557            | Adversary-in-the-Middle (NTLM Relay)    | APT28                                      |
| **Lateral Movement**  |                  |                                         |                                            |
| Lateral Movement      | T1021.001        | Remote Desktop Protocol                 | Lazarus, APT41, Volt Typhoon               |
| Lateral Movement      | T1021.002        | SMB/Windows Admin Shares                | APT29, Volt Typhoon, APT41                 |
| Lateral Movement      | T1550.002        | Pass the Hash                           | APT28, Lazarus, APT41                      |
| Lateral Movement      | T1570            | Lateral Tool Transfer                   | APT29, Lazarus, APT41                      |
| **Command & Control** |                  |                                         |                                            |
| C2                    | T1071.001        | Application Layer Protocol: Web         | APT29, APT28, Lazarus, APT41               |
| C2                    | T1090            | Proxy                                   | APT28, Volt Typhoon                        |
| C2                    | T1102            | Web Service (Google Calendar, OneDrive) | APT41, APT29                               |
| C2                    | T1572            | Protocol Tunneling                      | APT28, Volt Typhoon                        |
| **Exfiltration**      |                  |                                         |                                            |
| Exfiltration          | T1567            | Exfiltration Over Web Service           | APT41, APT29, Lazarus                      |
| Exfiltration          | T1041            | Exfiltration Over C2 Channel            | APT28, Lazarus, APT29                      |
| Exfiltration          | T1560.001        | Archive via Utility                     | Lazarus, APT41, Volt Typhoon               |
| **Collection**        |                  |                                         |                                            |
| Collection            | T1114            | Email Collection                        | APT29, APT28                               |
| Collection            | T1005            | Data from Local System                  | All five APT groups                        |

3\. REQUIRED DATA SOURCES

**Log Sources**

|                                        |                                                                                              |              |
|----------------------------------------|----------------------------------------------------------------------------------------------|--------------|
| **Log Source**                         | **Purpose**                                                                                  | **Priority** |
| Windows Security Event Logs            | Logon events (4624/4625), account activity, service installs (7045), Kerberos (4769)         | Critical     |
| Sysmon (EventID 1,3,7,8,10,11,13)      | Process creation, network connections, file creation, process access, registry modification  | Critical     |
| PowerShell Script Block Logging (4104) | Detects encoded/obfuscated PowerShell execution used by APT29, APT28, Volt Typhoon           | Critical     |
| Active Directory / LDAP Logs           | Account enumeration, group membership changes, GPO modifications, NTDS access                | Critical     |
| DNS Query Logs                         | DNS tunneling detection (APT28), C2 domain resolution, DGA detection                         | Critical     |
| Network / Firewall / Proxy Logs        | C2 beaconing, LOTL tool network activity, unusual outbound connections, SOHO proxy detection | High         |
| VPN / Remote Access Logs               | Initial access detection (Volt Typhoon edge exploitation), unusual geographic logons         | High         |
| Web Application / IIS / Apache Logs    | Web shell detection (APT41), exploitation of public-facing apps, POST anomalies              | High         |
| Cloud Audit Logs (M365, Google)        | OAuth token abuse (APT29), Google Calendar C2 (APT41), email collection                      | High         |
| EDR Telemetry                          | Process trees, memory access, DLL loading, file operations, credential access events         | Critical     |

**Required Tooling**

- SIEM: Splunk Enterprise / Splunk Cloud (all SIEM queries in this playbook use SPL)

- Network Monitoring: Zeek, Suricata, or dedicated NDR solution

- Threat Intelligence Platform: MISP, OpenCTI, Recorded Future, or SOCRadar

- Cloud Security: Microsoft Defender for Cloud Apps, Google Workspace Security Investigation Tool

4\. SPLUNK SPL DETECTION RULES

All queries below are written in valid Splunk Processing Language (SPL). Adjust index names, sourcetypes, and field names to match your Splunk deployment. Each query is mapped to specific MITRE ATT&CK techniques and the APT groups known to use the detected behavior.

Phase 1: Initial Access & Foothold Detection

**SPL 1.1 — Spearphishing: Suspicious Parent-Child Process Chains**

Detects Office applications or email clients spawning scripting interpreters, a hallmark of spearphishing-driven initial access used by APT29, APT28, Lazarus, and APT41.

Maps to: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell)

Sources: MITRE G0016, G0007, G0032, G0096

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

(ParentImage="\*\\outlook.exe" OR ParentImage="\*\\winword.exe"

OR ParentImage="\*\\excel.exe" OR ParentImage="\*\\mshta.exe"

OR ParentImage="\*\\powerpnt.exe" OR ParentImage="\*\\msedge.exe")

(Image="\*\\powershell.exe" OR Image="\*\\cmd.exe"

OR Image="\*\\wscript.exe" OR Image="\*\\cscript.exe"

OR Image="\*\\mshta.exe" OR Image="\*\\rundll32.exe"

OR Image="\*\\regsvr32.exe" OR Image="\*\\certutil.exe")

\| table \_time, dest, User, ParentImage, Image, CommandLine

**SPL 1.2 — Edge Device Exploitation: VPN/Appliance Logon from New Source IP**

Identifies VPN/appliance logons from previously unseen IP addresses. Volt Typhoon and APT41 are known to exploit Fortinet, Ivanti, and Citrix edge devices for initial access.

Maps to: T1133 (External Remote Services), T1190 (Exploit Public-Facing Application)

Sources: CISA AA24-038A, CISA AA23-144A, Microsoft Volt Typhoon blog (2023)

index=vpn sourcetype=vpn_logs action=success

\| stats earliest(\_time) AS first_logon, latest(\_time) AS last_logon, count BY src_ip, user

\| where first_logon \> relative_time(now(), "-72h")

\| lookup known_vpn_ips.csv src_ip OUTPUT known

\`\`\` Cross-reference against baseline of known VPN source IPs \`\`\`

\| where isnull(known)

\| table first_logon, user, src_ip, count

**SPL 1.3 — Password Spraying Detection**

Detects a high volume of failed authentication attempts from a single source against multiple accounts, a primary initial access technique for APT28 (per CISA AA24-057A and DoD/FBI advisory 2024) and Volt Typhoon.

Maps to: T1110.003 (Password Spraying)

Sources: MITRE G0007, DoD/FBI advisory (Feb 2024), Microsoft Forest Blizzard analysis

index=windows EventCode=4625 Logon_Type=3

\| bin \_time span=30m

\| stats dc(Account_Name) AS unique_accounts, count BY \_time, Source_Network_Address

\| where unique_accounts \>= 15 AND count \>= 30

\`\`\` Threshold: 15+ unique accounts targeted from single IP in 30 min \`\`\`

\| sort - unique_accounts

**SPL 1.4 — Web Shell Detection on Application Servers**

Detects web server processes spawning command interpreters, indicative of web shell activity. APT41 deployed ANTSWORD and BLUEBEAM web shells on Tomcat servers (per Mandiant DUST campaign 2024). Volt Typhoon is also known to use web shells extensively (per CISA AA24-038A).

Maps to: T1505.003 (Web Shell)

Sources: Mandiant/Google APT41 DUST report (July 2024), CISA AA24-038A

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

(ParentImage="\*\\w3wp.exe" OR ParentImage="\*\\httpd.exe"

OR ParentImage="\*\\tomcat\*.exe" OR ParentImage="\*\\nginx.exe"

OR ParentImage="\*\\java.exe" OR ParentImage="\*\\php-cgi.exe")

(Image="\*\\cmd.exe" OR Image="\*\\powershell.exe"

OR Image="\*\\whoami.exe" OR Image="\*\\net.exe"

OR Image="\*\\certutil.exe")

\| table \_time, dest, User, ParentImage, Image, CommandLine

Phase 2: Discovery & Enumeration

**SPL 2.1 — Rapid Discovery Command Burst (LOTL Reconnaissance)**

Detects multiple built-in reconnaissance commands executed in a short window. Volt Typhoon exclusively uses LOTL techniques (per CISA AA24-038A and Microsoft 2023). APT29 and APT28 also use native Windows tools for discovery.

Maps to: T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1082 (System Information Discovery), T1016 (System Network Configuration Discovery)

Sources: CISA AA24-038A Appendix A, MITRE G1017, MITRE G0016

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

(Image="\*\\net.exe" OR Image="\*\\net1.exe" OR Image="\*\\nltest.exe"

OR Image="\*\\whoami.exe" OR Image="\*\\ipconfig.exe"

OR Image="\*\\systeminfo.exe" OR Image="\*\\tasklist.exe"

OR Image="\*\\qprocess.exe" OR Image="\*\\nbtstat.exe"

OR Image="\*\\netstat.exe" OR Image="\*\\wmic.exe"

OR Image="\*\\netsh.exe" OR Image="\*\\arp.exe")

\| bin \_time span=5m

\| stats dc(Image) AS unique_tools, values(Image) AS tools_used, count BY \_time, dest, User

\| where unique_tools \>= 3

\`\`\` Threshold: 3+ distinct recon tools within 5 minutes \`\`\`

\| sort - unique_tools

**SPL 2.2 — LDAP Query Spike from Non-DC Host**

Detects workstations or member servers generating unusual LDAP traffic to DCs, indicative of AD enumeration. APT29 and APT41 both perform extensive AD enumeration during operations.

Maps to: T1087 (Account Discovery), T1482 (Domain Trust Discovery)

Sources: MITRE G0016, MITRE G0096, Mandiant M-Trends 2025

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3

DestinationPort=389 OR DestinationPort=636

NOT src_ip IN (10.0.0.1, 10.0.0.2)

\`\`\` Exclude your Domain Controller IPs \`\`\`

\| bin \_time span=1h

\| stats count BY \_time, SourceIp, dest, User

\| where count \> 500

\`\`\` Threshold: Adjust based on your environment baseline \`\`\`

**SPL 2.3 — Ntdsutil / Active Directory Database Access**

Detects use of ntdsutil.exe to create installation media from domain controllers, a technique specifically documented in Volt Typhoon operations (per Microsoft 2023 blog) and APT41 (per Mandiant). The resulting files contain password hashes that can be cracked offline.

Maps to: T1003.003 (NTDS)

Sources: Microsoft Volt Typhoon blog (May 2023), CISA AA24-038A, Mandiant APT41 analysis

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

(Image="\*\\ntdsutil.exe"

OR (CommandLine="\*ntdsutil\*" AND (CommandLine="\*ifm\*" OR CommandLine="\*snapshot\*"

OR CommandLine="\*ac i ntds\*" OR CommandLine="\*create full\*")))

\| table \_time, dest, User, Image, CommandLine, ParentImage

Phase 3: Credential Access

**SPL 3.1 — Suspicious LSASS Memory Access**

Detects non-standard processes accessing LSASS memory, indicative of credential dumping. Lazarus Group uses Mimikatz and procdump for LSASS dumping (per JPCERT Lazarus research). APT41 uses Mimikatz and built-in utilities (per Mandiant). Volt Typhoon dumps LSASS via encoded PowerShell commands (per Microsoft 2023).

Maps to: T1003.001 (OS Credential Dumping: LSASS Memory)

Sources: MITRE G0032, JPCERT Lazarus-research (2025), Microsoft Volt Typhoon blog (2023), Mandiant APT41 DUST (2024)

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10

TargetImage="\*\\lsass.exe"

NOT SourceImage IN ("\*\\MsMpEng.exe", "\*\\csrss.exe",

"\*\\wininit.exe", "\*\\svchost.exe", "\*\\lsass.exe",

"\*\\wmiprvse.exe", "\*\\taskmgr.exe")

\`\`\` Allowlist: Add your EDR agent and known security tool paths \`\`\`

\| table \_time, dest, SourceImage, TargetImage, GrantedAccess, SourceProcessGUID

\| sort - \_time

**SPL 3.2 — Kerberoasting Detection**

Detects Kerberos TGS requests using RC4 encryption (0x17), commonly used by APT29 and APT28 for offline credential cracking.

Maps to: T1558.003 (Kerberoasting)

Sources: MITRE G0016, MITRE G0007

index=windows EventCode=4769 Ticket_Encryption_Type=0x17

ServiceName!="krbtgt" ServiceName!="\*\$"

\| bin \_time span=1h

\| stats count, dc(ServiceName) AS unique_spns BY \_time, Account_Name, Client_Address

\| where count \> 5 OR unique_spns \> 3

\`\`\` Alert: 5+ RC4 TGS requests or 3+ unique SPNs from single account \`\`\`

\| sort - count

**SPL 3.3 — Credential Dumping Tool Execution**

Detects execution of common credential dumping utilities. Lazarus Group and APT41 are documented users of Mimikatz, procdump, and comsvcs.dll MiniDump techniques.

Maps to: T1003.001 (LSASS Memory)

Sources: JPCERT Lazarus-research (2025), Mandiant APT41 analysis, Picus Security APT41 TTP analysis (2025)

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

(CommandLine="\*sekurlsa\*" OR CommandLine="\*lsadump\*"

OR CommandLine="\*procdump\*lsass\*"

OR CommandLine="\*comsvcs.dll\*MiniDump\*"

OR CommandLine="\*Out-Minidump\*"

OR Image="\*\\mimikatz.exe" OR Image="\*\\procdump\*.exe"

OR CommandLine="\*ntdsutil\*ifm\*")

\| table \_time, dest, User, Image, CommandLine, ParentImage

Phase 4: Lateral Movement

**SPL 4.1 — NTLM Lateral Movement Spray (Pass-the-Hash)**

Detects a single source making NTLM network logons to many hosts, indicative of Pass-the-Hash. APT28 is specifically documented using NTLM relay attacks via compromised Ubiquiti routers (per DoD/FBI advisory Feb 2024). Lazarus and APT41 also use PtH techniques.

Maps to: T1550.002 (Pass the Hash), T1557 (Adversary-in-the-Middle)

Sources: DoD/FBI advisory (Feb 2024), MITRE G0007, MITRE G0032, MITRE G0096

index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM

\| bin \_time span=1h

\| stats dc(dest) AS unique_hosts, values(dest) AS targets BY \_time, Source_Network_Address, Account_Name

\| where unique_hosts \>= 10

\`\`\` Threshold: Single source NTLM-authenticating to 10+ hosts in 1 hour \`\`\`

\| sort - unique_hosts

**SPL 4.2 — WMI Remote Process Creation**

Detects WMI being used for remote command execution. APT29 extensively uses WMI for lateral movement and discovery (per MITRE ATT&CK evaluation). Volt Typhoon also relies on WMIC for living-off-the-land operations (per CISA AA24-038A Appendix A).

Maps to: T1047 (Windows Management Instrumentation)

Sources: MITRE APT29 Evaluation, CISA AA24-038A

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

ParentImage="\*\\wmiprvse.exe"

NOT Image IN ("\*\\svchost.exe", "\*\\werfault.exe")

\| table \_time, dest, User, ParentImage, Image, CommandLine

**SPL 4.3 — Anomalous RDP Connections (Workstation to Workstation)**

Flags RDP sessions between workstations. Lazarus Group uses RDP for lateral propagation (per Picus Security Lazarus TTP analysis). Volt Typhoon has been observed testing access to OT assets via RDP (per CISA AA24-038A).

Maps to: T1021.001 (Remote Desktop Protocol)

Sources: Picus Security Lazarus analysis (2025), CISA AA24-038A

index=windows EventCode=4624 Logon_Type=10

\| search NOT dest IN ("DC01", "DC02", "JUMP01")

\`\`\` Exclude Domain Controllers and authorized jump hosts \`\`\`

\| stats count BY \_time, Source_Network_Address, dest, Account_Name

\| lookup workstation_inventory.csv dest OUTPUT asset_type

\| where asset_type="workstation"

**SPL 4.4 — SMB Admin Share Lateral Movement**

Detects remote file writes to admin shares, a key lateral movement vector for APT29 (per MITRE G0016) and Volt Typhoon (per CISA AA24-038A).

Maps to: T1021.002 (SMB/Windows Admin Shares), T1570 (Lateral Tool Transfer)

Sources: MITRE G0016, CISA AA24-038A

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11

(TargetFilename="\*\\C\$\\\*" OR TargetFilename="\*\\ADMIN\$\\\*"

OR TargetFilename="\*\\IPC\$\\\*")

(TargetFilename="\*.exe" OR TargetFilename="\*.dll"

OR TargetFilename="\*.bat" OR TargetFilename="\*.ps1")

\| table \_time, dest, User, Image, TargetFilename

\| sort - \_time

Phase 5: Command & Control, Exfiltration & Defense Evasion

**SPL 5.1 — Certutil Abuse for Payload Download**

Detects certutil.exe used to download files, a documented technique for APT41 (per Mandiant DUST campaign 2024, where APT41 used certutil.exe to download the DUSTPAN dropper) and Volt Typhoon.

Maps to: T1105 (Ingress Tool Transfer), T1140 (Deobfuscate/Decode Files)

Sources: Mandiant/Google APT41 DUST report (July 2024), CISA AA24-038A

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

Image="\*\\certutil.exe"

(CommandLine="\*urlcache\*" OR CommandLine="\*verifyctl\*"

OR CommandLine="\*decode\*" OR CommandLine="\*encode\*"

OR CommandLine="\*-split\*")

\| table \_time, dest, User, CommandLine, ParentImage

**SPL 5.2 — Exfiltration to Cloud Storage**

Detects use of rclone, cloud storage tools, or connections to known exfiltration services. APT41 used PINEGROVE to exfiltrate data to Microsoft OneDrive (per Mandiant DUST 2024). APT29 has been observed using cloud services for C2 and exfiltration.

Maps to: T1567 (Exfiltration Over Web Service), T1102 (Web Service)

Sources: Mandiant/Google APT41 DUST report (July 2024), MITRE G0016

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

(EventCode=1 (Image="\*\\rclone.exe" OR CommandLine="\*rclone\*"))

OR (EventCode=3 (DestinationHostname="\*mega.nz" OR DestinationHostname="\*mega.co.nz"

OR DestinationHostname="\*transfer.sh" OR DestinationHostname="\*anonfiles.com"

OR DestinationHostname="\*send.exploit.in"

OR DestinationHostname="\*file.io" OR DestinationHostname="\*gofile.io"))

\| table \_time, dest, User, Image, CommandLine, DestinationIp, DestinationHostname

**SPL 5.3 — Windows Event Log Clearing**

Detects clearing of Windows event logs, a common anti-forensics technique. APT28 and Volt Typhoon both clear logs to conceal operations (per MITRE G0007 and CISA AA24-038A).

Maps to: T1070.001 (Indicator Removal: Clear Windows Event Logs)

Sources: MITRE G0007, CISA AA24-038A

index=windows (EventCode=104 OR EventCode=1102)

\| table \_time, dest, user, EventCode, Message

\| sort - \_time

**SPL 5.4 — DLL Side-Loading Detection**

Detects suspicious DLL loading patterns associated with DLL side-loading. Lazarus Group and APT41 extensively use DLL side-loading for defense evasion and payload execution (per MITRE G0032, AhnLab ASEC 2022, MITRE G0096).

Maps to: T1574.002 (Hijack Execution Flow: DLL Side-Loading)

Sources: MITRE G0032, AhnLab ASEC Lazarus analysis (2022), MITRE G0096

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7

NOT (ImageLoaded="C:\\Windows\\System32\\\*"

OR ImageLoaded="C:\\Windows\\SysWOW64\\\*"

OR ImageLoaded="C:\\Program Files\*")

Signed="false"

\| stats count BY dest, Image, ImageLoaded, Signed

\| where count \>= 1

\| table dest, Image, ImageLoaded, count

**SPL 5.5 — Encoded PowerShell Command Execution**

Detects Base64-encoded PowerShell commands. Volt Typhoon used encoded PowerShell to dump LSASS (per Microsoft 2023). APT29 uses PowerShell extensively for post-exploitation (per MITRE ATT&CK APT29 Evaluation).

Maps to: T1059.001 (PowerShell), T1027 (Obfuscated Files or Information)

Sources: Microsoft Volt Typhoon blog (May 2023), MITRE APT29 Evaluation

index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

Image="\*\\powershell.exe"

(CommandLine="\*-enc\*" OR CommandLine="\*-EncodedCommand\*"

OR CommandLine="\*-e \*" OR CommandLine="\*\[Convert\]::FromBase64\*"

OR CommandLine="\*-nop\*-w hidden\*")

\| table \_time, dest, User, CommandLine, ParentImage

5\. KNOWN FALSE POSITIVES & TUNING GUIDANCE

|                              |                                                                                   |                                                                                                      |
|------------------------------|-----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| **Hunt Category**            | **Common False Positives**                                                        | **Tuning Recommendation**                                                                            |
| Spearphishing Process Chains | Legitimate Office macros, corporate add-ins, approved automation tools            | Allowlist known approved macro-enabled documents and corporate automation tools by hash or publisher |
| Password Spraying            | Misconfigured service accounts, SSO health checks, legitimate penetration testing | Baseline normal failed auth volume per source; exclude known pentest IPs and SSO monitoring probes   |
| Web Shell Detection          | Legitimate CGI scripts, web-based management consoles, developer tools            | Allowlist known web management tools and approved CGI binaries by path                               |
| LSASS Memory Access          | EDR/AV engines, SCCM client, security scanning tools                              | Allowlist by SourceImage path for known and verified security tools                                  |
| Discovery Command Burst      | IT admin scripts, helpdesk automation, SCCM/Intune inventory                      | Allowlist known admin workstations and automation service accounts                                   |
| Certutil Abuse               | Legitimate certificate operations, PKI management scripts                         | Alert only on -urlcache, -decode, or -split flags; exclude known PKI automation accounts             |
| NTDS Access                  | Scheduled AD backups, legitimate DC maintenance                                   | Correlate with change management; alert on ntdsutil from non-DC hosts                                |
| DLL Side-Loading             | Legitimate software with unsigned DLLs, dev environments                          | Baseline normal unsigned DLL loading; focus on DLLs loaded from temp/user-writable directories       |
| Encoded PowerShell           | IT automation using encoded parameters, SCCM deployments                          | Allowlist known automation accounts; decode and inspect payloads for suspicious functions            |
| Event Log Clearing           | SIEM agent log rotation, GPO-driven log management                                | Allowlist known SIEM and log management service accounts                                             |

6\. RESPONSE ACTIONS

**Immediate (0–15 minutes)**

- \[ \] Isolate affected host(s) from the network via EDR network containment

- \[ \] Preserve memory dump of suspicious processes before isolation

- \[ \] Notify IR lead and escalate to P1 incident

- \[ \] Revoke and reset credentials of any confirmed-compromised accounts

- \[ \] Block identified C2 IP addresses and domains at firewall and proxy

- \[ \] Check for cloud identity compromise: revoke active OAuth tokens and sessions (critical for APT29 activity)

**Short-Term (15 minutes – 4 hours)**

- \[ \] Identify patient zero: trace the initial access vector (edge device exploit, phishing, supply chain)

- \[ \] Scope lateral movement: identify all systems accessed by the threat actor

- \[ \] Hunt for persistence: web shells, scheduled tasks, services, registry Run keys, DLL side-loading artifacts

- \[ \] Review all privileged account activity over the prior 30 days (APT dwell times are long)

- \[ \] Audit cloud tenants: M365 mailbox delegation, consent grants, application registrations (APT29 focus)

- \[ \] Check edge devices: Fortinet, Ivanti, Citrix for signs of exploitation (Volt Typhoon, APT41 focus)

**Containment**

- \[ \] Reset all privileged account passwords (Domain Admins, service accounts)

- \[ \] Reset krbtgt password twice (10+ hours apart) if Golden/Silver Ticket suspected

- \[ \] Block all identified attacker infrastructure across all perimeter controls

- \[ \] Force re-authentication across the environment (revoke all active sessions)

- \[ \] Patch the initial access vector (edge devices, VPN, public-facing applications)

- \[ \] Audit and remove unauthorized web shells from all web-facing servers

**Recovery**

- \[ \] Restore systems from verified-clean backups only after full scoping

- \[ \] Rebuild compromised systems from clean base images

- \[ \] Deploy enhanced monitoring on recovered systems for 90 days (APT groups frequently re-enter)

- \[ \] Conduct post-incident review within 72 hours; update this playbook with lessons learned

7\. CREDIBLE SOURCES & REFERENCES

**Threat Intelligence Sources**

- MITRE ATT&CK APT29 (G0016): https://attack.mitre.org/groups/G0016/

- MITRE ATT&CK APT28 (G0007): https://attack.mitre.org/groups/G0007/

- MITRE ATT&CK Lazarus Group (G0032): https://attack.mitre.org/groups/G0032/

- MITRE ATT&CK APT41 (G0096): https://attack.mitre.org/groups/G0096/

- MITRE ATT&CK Volt Typhoon (G1017): https://attack.mitre.org/groups/G1017/

**CISA Advisories**

- CISA AA24-038A: PRC State-Sponsored Actors (Volt Typhoon) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

- CISA AA23-144A: PRC State-Sponsored Actor Living off the Land — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a

- DoD/FBI Advisory: APT28 Use of Compromised Ubiquiti EdgeRouters (Feb 2024) — https://media.defense.gov/2024/Feb/27/2003400753/-1/-1/0/CSA-Russian-Actors-Use-Routers-Facilitate-Cyber_Operations.PDF

**Vendor Research (Mandiant / Google Threat Intelligence)**

- Mandiant M-Trends 2025 Report — https://services.google.com/fh/files/misc/m-trends-2025-en.pdf

- Mandiant/Google: APT41 Has Arisen From the DUST (July 2024) — https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust

- Mandiant/Google: APT29 Uses WINELOADER to Target German Political Parties (March 2024) — https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties

**Vendor Research (Microsoft)**

- Microsoft: Volt Typhoon targets US critical infrastructure with LOTL techniques (May 2023) — https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/

- Microsoft: Forest Blizzard (APT28) analysis — referenced via MITRE G0007 and DoD advisory

**Vendor Research (Unit 42 / Palo Alto Networks)**

- Unit 42: Threat Assessment — North Korean Threat Groups (Oct 2024) — https://unit42.paloaltonetworks.com/threat-assessment-north-korean-threat-groups-2024/

**Vendor Research (Kaspersky, ESET, CrowdStrike, CYFIRMA)**

- Kaspersky GReAT: ATT&CK in APT Reports (Lazarus mapping) — https://www.kaspersky.com/enterprise-security/mitre/tip

- ESET: Operation RoundPress — APT28 webmail XSS exploitation (2025)

- CYFIRMA: APT Profile — MISSION2025 / APT41 (2025) — https://www.cyfirma.com/research/apt-profile-mission2025/

- JPCERT/CC: Lazarus Research — MITRE ATT&CK Mapping — https://github.com/JPCERTCC/Lazarus-research

**Vendor Research (AhnLab, WithSecure, Picus Security)**

- AhnLab ASEC: Lazarus Group Uses DLL Side-Loading Technique (2022) — referenced via MITRE G0032

- WithSecure Labs: Catching Lazarus — Threat Intelligence to Real Detection Logic — https://labs.withsecure.com/publications/catching-lazarus-threat-intelligence-to-real-detection-logic-part-one

- Picus Security: Lazarus Group (APT38) TTP Analysis (Oct 2025) — https://www.picussecurity.com/resource/blog/lazarus-group-apt38-explained-timeline-ttps-and-major-attacks

- Picus Security: Volt Typhoon LOTL Analysis (Dec 2024) — https://www.picussecurity.com/resource/blog/volt-typhoon-living-off-the-land-cyber-espionage

**MITRE ATT&CK Technique References**

- T1566 — Phishing: https://attack.mitre.org/techniques/T1566/

- T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/

- T1133 — External Remote Services: https://attack.mitre.org/techniques/T1133/

- T1059.001 — PowerShell: https://attack.mitre.org/techniques/T1059/001/

- T1003.001 — LSASS Memory: https://attack.mitre.org/techniques/T1003/001/

- T1003.003 — NTDS: https://attack.mitre.org/techniques/T1003/003/

- T1558.003 — Kerberoasting: https://attack.mitre.org/techniques/T1558/003/

- T1505.003 — Web Shell: https://attack.mitre.org/techniques/T1505/003/

- T1574.002 — DLL Side-Loading: https://attack.mitre.org/techniques/T1574/002/

- T1110.003 — Password Spraying: https://attack.mitre.org/techniques/T1110/003/

- T1550.002 — Pass the Hash: https://attack.mitre.org/techniques/T1550/002/

- T1021.001 — Remote Desktop Protocol: https://attack.mitre.org/techniques/T1021/001/

- T1567 — Exfiltration Over Web Service: https://attack.mitre.org/techniques/T1567/

- T1070.001 — Clear Windows Event Logs: https://attack.mitre.org/techniques/T1070/001/

**Tools & Frameworks**

- Sigma Rules Repository — https://github.com/SigmaHQ/sigma

- Sysmon Config (SwiftOnSecurity) — https://github.com/SwiftOnSecurity/sysmon-config

- MITRE ATT&CK Navigator — https://mitre-attack.github.io/attack-navigator/

- Splunk SPL Documentation — https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/

**Playbook Status: Active** \| Next Review: 2026-06-25 \| Validated Against: APT29, APT28, Lazarus Group, APT41, Volt Typhoon TTPs
