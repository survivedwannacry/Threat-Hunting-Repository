**THREAT HUNTING PLAYBOOK**

Identity Compromise & Credential Abuse Detection

|                      |                                                                                                                                      |
|----------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Field**            | **Value**                                                                                                                            |
| **Playbook ID**      | THP-004                                                                                                                              |
| **Severity**         | CRITICAL                                                                                                                             |
| **Author**           | Muhammed Can                                                                                                                         |
| **Version**          | 1.0                                                                                                                                  |
| **Last Updated**     | 2026-03-25                                                                                                                           |
| **Technology Stack** | Splunk (SIEM) — Windows Security Logs + Entra ID / Okta / M365 Audit Logs                                                            |
| **Status**           | Active                                                                                                                               |
| **Next Review**      | 2026-06-25                                                                                                                           |
| **Tags**             | identity, credential-abuse, MFA-bypass, password-spray, OAuth, token-theft, Scattered-Spider, BEC, impossible-travel, cloud-identity |

1\. HUNT HYPOTHESIS & DESCRIPTION

**Hypothesis**

Identity has become the primary attack vector in modern intrusions. Unit 42’s 2026 Global Incident Response Report, based on 750+ engagements across 50 countries, found that identity weaknesses played a material role in nearly 90% of all investigations and that 65% of initial access was identity-driven including credential theft, MFA bypass, and IAM misconfigurations. Mandiant M-Trends 2025 confirmed stolen credentials surged to the second most common initial access vector at 16%, driven by widespread infostealer malware campaigns, while cloud compromises were led by phishing (39%) and stolen credentials (35%). This playbook hunts for the behavioral precursors and indicators of identity compromise across on-premises Active Directory, cloud identity providers (Entra ID, Okta), and SaaS applications.

> *"If an adversary is leveraging compromised identities to access our environment, we should observe a cluster of behavioral indicators including password spraying against authentication endpoints, MFA fatigue push bombing, impossible travel anomalies, OAuth consent grant manipulation, suspicious mailbox delegation, anomalous service principal activity, and credential-based lateral movement — detectable through Windows Security Event Logs, Entra ID sign-in logs, Okta system logs, and M365 Unified Audit Logs."*

**Threat Intelligence Context**

|                                       |                                                                                                                                                                                                                               |          |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| **Source**                            | **Key Finding**                                                                                                                                                                                                               | **Date** |
| Unit 42 GIR 2026                      | Identity weaknesses factored into ~90% of 750+ IR engagements; 65% of initial access was identity-driven (credential theft, MFA bypass, IAM misconfiguration); fastest exfiltration in 72 minutes (4x faster than prior year) | Feb 2026 |
| Mandiant M-Trends 2025                | Stolen credentials rose to \#2 initial access vector at 16% (first time); cloud compromises led by phishing (39%) and stolen credentials (35%); UNC3944 used social engineering to compromise SSO and deploy ransomware       | Apr 2025 |
| Mandiant M-Trends 2026                | Voice phishing climbed to \#2 initial access vector (11%); initial access handoff shrank to 22 seconds; attackers exploited misconfigured AD CS templates to create admin accounts bypassing MFA                              | Mar 2026 |
| CISA AA23-320A (Updated Jul 2025)     | Scattered Spider uses push bombing, SIM swapping, and helpdesk social engineering to bypass MFA; targets Okta, AWS, and Office 365 via identity workflows                                                                     | Jul 2025 |
| CrowdStrike 2025 Global Threat Report | Scattered Spider targets IT help desks via phone, posing as employees to solicit password resets and MFA credential resets for privileged accounts                                                                            | 2025     |
| Microsoft (Octo Tempest Analysis)     | Scattered Spider/Octo Tempest crosses boundaries to facilitate extortion via identity-focused intrusions; uses AiTM phishing, SIM swaps, and OAuth token theft                                                                | Oct 2023 |
| Obsidian Security                     | Scattered Spider SaaS breach analysis: attackers used SSPR abuse, OAuth token replay, Temporary Access Pass registration, and conditional access policy deletion in Entra ID                                                  | Nov 2025 |
| Darktrace                             | Over 70% of US incidents in 2025 involved SaaS/M365 account compromise and phishing or email-based social engineering                                                                                                         | Jul 2025 |

**Threat Scenarios**

|                                                  |                                       |                                                                                                                       |                      |
|--------------------------------------------------|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------|----------------------|
| **Threat Scenario**                              | **Threat Actors**                     | **Why It’s Dangerous**                                                                                                | **MITRE ATT&CK**     |
| Password spraying against cloud IdP              | APT28, Scattered Spider, Volt Typhoon | Automated credential testing at scale; bypasses account lockout thresholds                                            | T1110.003            |
| MFA fatigue / push bombing                       | Scattered Spider, APT29               | Repeated push notifications until user accepts; bypasses MFA without technical exploit                                | T1621                |
| OAuth token theft and consent phishing           | Scattered Spider, APT29               | Stolen tokens provide persistent access without passwords; survive credential resets                                  | T1528, T1550.001     |
| Impossible travel / anomalous sign-in            | All credential-based actors           | Stolen credentials used from geographically impossible locations indicate account takeover                            | T1078                |
| Mailbox delegation abuse / BEC                   | APT29, Scattered Spider               | Hidden mailbox rules forward emails to attacker; enables BEC and intelligence collection                              | T1114.003, T1098.002 |
| Service principal / non-human identity abuse     | APT29, APT41                          | API keys and OAuth apps with excessive permissions; 99% of cloud identities are over-permissioned (Unit 42)           | T1078.004, T1098.001 |
| Helpdesk social engineering for credential reset | Scattered Spider                      | Attackers impersonate employees via phone to reset passwords and MFA for privileged accounts                          | T1656, T1598         |
| Infostealer credential harvesting                | Initial Access Brokers, UNC5537       | Credentials stolen from endpoints via VIDAR, RACCOON, etc. and sold to ransomware operators; drove Snowflake campaign | T1555, T1539         |

2\. MITRE ATT&CK MAPPING

All technique IDs are verified against the MITRE ATT&CK Enterprise framework (https://attack.mitre.org). Technique associations to threat actors are sourced from MITRE group pages, CISA advisories, and vendor reports cited in Section 1.

|                               |                  |                                                             |                                                                                       |
|-------------------------------|------------------|-------------------------------------------------------------|---------------------------------------------------------------------------------------|
| **Kill Chain Phase**          | **Technique ID** | **Technique Name**                                          | **Source / Threat Actor**                                                             |
| **Initial Access**            |                  |                                                             |                                                                                       |
| Initial Access                | T1110.003        | Brute Force: Password Spraying                              | APT28 (MITRE G0007), Scattered Spider (CISA AA23-320A), Volt Typhoon (CISA AA24-038A) |
| Initial Access                | T1621            | MFA Request Generation (Push Bombing)                       | Scattered Spider (CISA AA23-320A, MITRE T1621), APT29 (NCSC-UK 2024)                  |
| Initial Access                | T1078            | Valid Accounts                                              | Unit 42 GIR 2026 (65% of initial access), Mandiant M-Trends 2025 (16% stolen creds)   |
| Initial Access                | T1078.004        | Valid Accounts: Cloud Accounts                              | Scattered Spider (MITRE G1015), APT29 (MITRE G0016)                                   |
| Initial Access                | T1566.001        | Phishing: Spearphishing Attachment                          | Mandiant M-Trends 2025 (39% cloud initial access via phishing)                        |
| Initial Access                | T1656            | Impersonation                                               | Scattered Spider (CISA AA23-320A) — helpdesk impersonation                            |
| **Credential Access**         |                  |                                                             |                                                                                       |
| Credential Access             | T1528            | Steal Application Access Token                              | Scattered Spider (Obsidian Security Nov 2025, MITRE G1015)                            |
| Credential Access             | T1539            | Steal Web Session Cookie                                    | Scattered Spider (Picus Security Jul 2025), APT29 (MITRE G0016)                       |
| Credential Access             | T1555            | Credentials from Password Stores                            | Infostealer campaigns (Mandiant M-Trends 2025 — UNC5537 Snowflake)                    |
| Credential Access             | T1557            | Adversary-in-the-Middle                                     | Scattered Spider AiTM phishing (Microsoft Octo Tempest, Oct 2023)                     |
| Credential Access             | T1556.009        | Modify Authentication Process: Conditional Access           | Scattered Spider deleted conditional access policies (Obsidian Security Nov 2025)     |
| **Persistence**               |                  |                                                             |                                                                                       |
| Persistence                   | T1098.001        | Account Manipulation: Additional Cloud Credentials          | APT29 (MITRE G0016), Scattered Spider (MITRE G1015)                                   |
| Persistence                   | T1098.002        | Account Manipulation: Additional Email Delegate Permissions | APT29 (MITRE G0016) — mailbox delegation abuse                                        |
| Persistence                   | T1136.003        | Create Account: Cloud Account                               | Scattered Spider (Obsidian Security Nov 2025 — “Malicious Admin” service account)     |
| Persistence                   | T1550.001        | Use Alternate Auth Material: Application Access Token       | Scattered Spider (Picus Security Jul 2025) — OAuth token replay                       |
| **Lateral Movement**          |                  |                                                             |                                                                                       |
| Lateral Movement              | T1550.002        | Pass the Hash                                               | APT28, Lazarus (MITRE G0007, G0032)                                                   |
| Lateral Movement              | T1021.001        | Remote Desktop Protocol                                     | Scattered Spider, Lazarus (CISA AA23-320A, MITRE G0032)                               |
| **Collection & Exfiltration** |                  |                                                             |                                                                                       |
| Collection                    | T1114.003        | Email Collection: Email Forwarding Rule                     | APT29 (MITRE G0016), Scattered Spider (CISA AA23-320A)                                |
| Exfiltration                  | T1567            | Exfiltration Over Web Service                               | Unit 42 GIR 2026 (23% SaaS data involved)                                             |

3\. REQUIRED DATA SOURCES

|                                                   |                                                                                                                                       |                    |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| **Log Source**                                    | **Purpose**                                                                                                                           | **Priority**       |
| Windows Security Event Logs (4624/4625/4648/4769) | Logon events, failed authentications, explicit credential use, Kerberos TGS requests                                                  | Critical           |
| Entra ID (Azure AD) Sign-In Logs                  | Cloud authentication events, conditional access evaluation, MFA challenge/response, risk detections, impossible travel                | Critical           |
| Entra ID Audit Logs                               | Application consent grants, service principal creation, role assignments, conditional access policy changes, user/group modifications | Critical           |
| Okta System Log                                   | Authentication events, MFA push notifications, SSPR activity, admin actions, application assignments                                  | Critical (if Okta) |
| M365 Unified Audit Log                            | Mailbox delegation, inbox rule creation, email forwarding, eDiscovery abuse, SharePoint/OneDrive access                               | Critical           |
| Active Directory Logs (LDAP/Replication)          | DCSync detection, LDAP enumeration, group membership changes, privileged account modifications                                        | High               |
| VPN / CASB / Proxy Logs                           | Geographic anomaly detection, impossible travel correlation, user-agent analysis                                                      | High               |
| EDR Telemetry                                     | Infostealer detection, credential dumping tools, browser credential harvesting                                                        | High               |

4\. SPLUNK SPL DETECTION RULES

All queries are written in valid Splunk Processing Language (SPL). Adjust index names, sourcetypes, and field names to match your deployment. Each query is mapped to specific MITRE ATT&CK techniques and threat actors documented to use the detected behavior.

SPL 4.1 — Password Spraying Detection (On-Premises AD)

Detects a high volume of failed logon attempts from a single source against multiple accounts, the primary initial access technique for APT28 (per CISA/DoD advisory Feb 2024) and Scattered Spider (per CISA AA23-320A).

Maps to: T1110.003 (Password Spraying)

Sources: CISA AA23-320A (Jul 2025), DoD/FBI APT28 advisory (Feb 2024), MITRE T1110.003

index=windows EventCode=4625 Logon_Type=3

\| bin \_time span=30m

\| stats dc(Account_Name) AS unique_accounts, count BY \_time, Source_Network_Address

\| where unique_accounts \>= 15 AND count \>= 30

\`\`\` Threshold: 15+ unique accounts from single source in 30 min \`\`\`

\| sort - unique_accounts

SPL 4.2 — MFA Fatigue / Push Bombing Detection (Entra ID)

Detects multiple failed MFA challenges followed by a successful authentication, indicating MFA fatigue attack. Scattered Spider uses this technique extensively (per CISA AA23-320A, CrowdStrike 2025 Threat Report). MITRE documents this as T1621.

Maps to: T1621 (MFA Request Generation)

Sources: CISA AA23-320A (Jul 2025), CrowdStrike MFA fatigue detection (Sep 2025), MITRE T1621

index=azure sourcetype="azure:aad:signin"

\| eval mfa_result=case(

match(Status.errorCode, "50074\|50076\|500121"), "MFA_challenged",

Status.errorCode=0, "success",

1=1, "other_failure")

\| bin \_time span=15m

\| stats count(eval(mfa_result="MFA_challenged")) AS mfa_failures,

count(eval(mfa_result="success")) AS mfa_successes

BY \_time, UserPrincipalName, IPAddress, Location.city

\| where mfa_failures \>= 5 AND mfa_successes \>= 1

\`\`\` Alert: 5+ MFA failures followed by success within 15 min \`\`\`

\| sort - mfa_failures

SPL 4.3 — Impossible Travel Detection (Entra ID)

Detects a single user authenticating from geographically distant locations within an impossibly short timeframe, a strong indicator of credential compromise. Unit 42 GIR 2026 confirmed identity-driven attacks are the primary vector in 65% of initial access cases.

Maps to: T1078 (Valid Accounts), T1078.004 (Cloud Accounts)

Sources: Unit 42 GIR 2026 (Feb 2026), Mandiant M-Trends 2025

index=azure sourcetype="azure:aad:signin" Status.errorCode=0

\| sort 0 UserPrincipalName, \_time

\| streamstats current=f last(\_time) AS prev_time, last(Location.city) AS prev_city,

last(Location.countryOrRegion) AS prev_country, last(IPAddress) AS prev_ip

BY UserPrincipalName

\| eval time_diff_minutes=round((\_time - prev_time) / 60, 0)

\| where isnotnull(prev_city) AND prev_country != Location.countryOrRegion

AND time_diff_minutes \< 120 AND time_diff_minutes \> 0

\`\`\` Flag: Different country within 2 hours = impossible travel \`\`\`

\| table \_time, UserPrincipalName, prev_city, prev_country, Location.city,

Location.countryOrRegion, time_diff_minutes, IPAddress, prev_ip

SPL 4.4 — Suspicious OAuth Application Consent Grant

Detects OAuth application consent grants, which attackers use to establish persistent access. Unit 42 GIR 2026 found SaaS supply chain attacks surged 3.8x since 2022, with attackers abusing OAuth tokens for lateral movement (23% of all attacks). Scattered Spider exploited Salesloft-Drift OAuth tokens to access hundreds of downstream environments (per Obsidian Security Nov 2025).

Maps to: T1528 (Steal Application Access Token), T1098.001 (Additional Cloud Credentials)

Sources: Unit 42 GIR 2026 (Feb 2026), Obsidian Security Scattered Spider analysis (Nov 2025)

index=azure sourcetype="azure:aad:audit"

OperationName="Consent to application"

\| spath "TargetResources{}.displayName" output=app_name

\| spath "TargetResources{}.modifiedProperties{}.newValue" output=permissions

\| eval risk=if(match(permissions, "(?i)(Mail\\Read\|Files\\Read\|User\\Read\\All\|Directory\\Read)"),

"HIGH — Sensitive permissions granted", "Medium")

\| table \_time, InitiatedBy.user.userPrincipalName, app_name, permissions, risk

\| sort - \_time

SPL 4.5 — Suspicious Mailbox Forwarding Rule Creation

Detects creation of inbox rules that forward or redirect email to external addresses. APT29 and Scattered Spider both use email collection via forwarding rules (per MITRE G0016, CISA AA23-320A). Mandiant M-Trends 2026 highlighted that attackers search victim Slack, Teams, and Exchange for security response communications.

Maps to: T1114.003 (Email Forwarding Rule), T1098.002 (Additional Email Delegate Permissions)

Sources: MITRE G0016, CISA AA23-320A (Jul 2025), Mandiant M-Trends 2026 (Mar 2026)

index=o365 sourcetype="o365:management:activity"

(Operation="New-InboxRule" OR Operation="Set-InboxRule"

OR Operation="UpdateInboxRules" OR Operation="Set-Mailbox")

(Parameters.ForwardTo="\*" OR Parameters.ForwardAsAttachmentTo="\*"

OR Parameters.RedirectTo="\*" OR Parameters.DeliverToMailboxAndForward="True")

\| eval external=if(NOT match(Parameters.ForwardTo, "@yourdomain\\com"), "EXTERNAL", "Internal")

\| table \_time, UserId, Operation, Parameters.ForwardTo, Parameters.RedirectTo, external, ClientIP

\| where external="EXTERNAL"

SPL 4.6 — Conditional Access Policy Modification or Deletion

Detects modification or deletion of conditional access policies. Obsidian Security (Nov 2025) documented Scattered Spider deleting conditional access policies (including those blocking specific IPs and requiring MFA) to enable persistence and bypass security controls. MITRE maps this to T1556.009.

Maps to: T1556.009 (Modify Authentication Process: Conditional Access Policies)

Sources: Obsidian Security Scattered Spider analysis (Nov 2025), MITRE T1556.009

index=azure sourcetype="azure:aad:audit"

(OperationName="Delete conditional access policy"

OR OperationName="Update conditional access policy")

\| spath "TargetResources{}.displayName" output=policy_name

\| spath "InitiatedBy.user.userPrincipalName" output=actor

\| table \_time, actor, OperationName, policy_name

\| sort - \_time

SPL 4.7 — New Service Principal or Application Registration

Detects creation of new service principals or app registrations, which attackers use for persistent API access. Unit 42 found attackers exploit inherited permissions of OAuth tokens and API keys to blend into legitimate automation traffic (GIR 2026). APT29 uses application impersonation for persistent access (per MITRE G0016).

Maps to: T1098.001 (Additional Cloud Credentials), T1136.003 (Create Cloud Account)

Sources: Unit 42 GIR 2026 (Feb 2026), MITRE G0016

index=azure sourcetype="azure:aad:audit"

(OperationName="Add service principal" OR OperationName="Add application"

OR OperationName="Add service principal credentials"

OR OperationName="Update application – Certificates and secrets management")

\| spath "InitiatedBy.user.userPrincipalName" output=actor

\| spath "TargetResources{}.displayName" output=app_name

\| table \_time, actor, OperationName, app_name

\| sort - \_time

SPL 4.8 — NTLM Relay / Pass-the-Hash Lateral Movement (On-Premises)

Detects a single source making NTLM network logons to multiple hosts, indicative of Pass-the-Hash or NTLM relay attacks. APT28 conducted NTLM relay attacks via compromised Ubiquiti routers (per DoD/FBI advisory Feb 2024).

Maps to: T1550.002 (Pass the Hash), T1557 (Adversary-in-the-Middle)

Sources: DoD/FBI advisory (Feb 2024), MITRE G0007

index=windows EventCode=4624 Logon_Type=3 Authentication_Package=NTLM

\| bin \_time span=1h

\| stats dc(dest) AS unique_hosts, values(dest) AS targets

BY \_time, Source_Network_Address, Account_Name

\| where unique_hosts \>= 10

\`\`\` Single source NTLM-authenticating to 10+ hosts in 1 hour \`\`\`

\| sort - unique_hosts

SPL 4.9 — Privileged Role Assignment to Non-Admin Account

Detects assignment of privileged directory roles (Global Admin, Exchange Admin, etc.) to accounts that were not previously in privileged groups. Scattered Spider assigned compromised accounts to all SSO-linked applications and created disguised service accounts with admin roles (per Obsidian Security Nov 2025, Mandiant M-Trends 2025 UNC3944 analysis).

Maps to: T1098.001 (Additional Cloud Credentials), T1136.003 (Create Cloud Account)

Sources: Obsidian Security (Nov 2025), Mandiant M-Trends 2025 UNC3944 analysis

index=azure sourcetype="azure:aad:audit"

OperationName="Add member to role"

\| spath "TargetResources{}.modifiedProperties{}.newValue" output=role_name

\| where match(role_name, "(?i)(Global Admin\|Exchange Admin\|SharePoint Admin\|

Privileged Role Admin\|Application Admin\|Cloud Application Admin)")

\| spath "TargetResources{}.userPrincipalName" output=target_user

\| spath "InitiatedBy.user.userPrincipalName" output=actor

\| table \_time, actor, target_user, role_name

\| sort - \_time

5\. KNOWN FALSE POSITIVES & TUNING GUIDANCE

|                            |                                                                                  |                                                                                             |
|----------------------------|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **Detection**              | **Common False Positives**                                                       | **Tuning Recommendation**                                                                   |
| Password Spraying          | Misconfigured service accounts, SSO health probes, legitimate pentest activity   | Baseline normal failed auth volume per source; exclude known pentest IPs and SSO monitoring |
| MFA Fatigue                | Users accidentally triggering multiple MFA prompts; legitimate re-authentication | Tune threshold to 5+ failures followed by success; correlate with helpdesk tickets          |
| Impossible Travel          | VPN use, corporate proxies, mobile roaming, users on flights                     | Allowlist known corporate VPN egress IPs and travel-heavy roles; focus on new IPs           |
| OAuth Consent              | Legitimate SaaS onboarding, IT-approved application integrations                 | Maintain approved OAuth app registry; alert only on unregistered app consent grants         |
| Mail Forwarding            | Legitimate forwarding to personal email during leave; shared mailbox management  | Alert only on external forwarding; cross-reference with HR leave data                       |
| CA Policy Changes          | IT security team policy updates; planned policy migration                        | Correlate with change management tickets; alert on deletions by non-security admins         |
| Service Principal          | DevOps CI/CD pipeline creation; legitimate app registrations                     | Maintain app registration approval workflow; alert on credential additions to existing apps |
| NTLM Lateral Movement      | Legitimate admin tools, SCCM scanning, vulnerability scanners                    | Allowlist known admin workstations and service accounts; restrict NTLM where possible       |
| Privileged Role Assignment | Planned role assignments by identity governance team                             | Correlate with ITSM tickets; alert on any Global Admin assignment as P1                     |

6\. RESPONSE ACTIONS

**Immediate (0–15 minutes)**

- \[ \] Confirm the identity compromise: correlate sign-in logs with user to determine if activity is legitimate

- \[ \] If confirmed: force sign-out of all active sessions and revoke refresh tokens

- \[ \] Reset the compromised account password immediately

- \[ \] Re-register MFA methods (attacker may have registered their own MFA device)

- \[ \] Block the attacker IP addresses at conditional access policy / firewall

- \[ \] Notify the affected user directly (not via potentially compromised email)

**Investigation (15 minutes – 4 hours)**

- \[ \] Trace the initial compromise: check for infostealer artifacts, phishing email delivery, helpdesk social engineering calls

- \[ \] Audit all OAuth application consent grants made by the compromised account

- \[ \] Check for inbox rules forwarding email to external addresses

- \[ \] Review conditional access policy modifications and role assignments

- \[ \] Scan for new service principals or app registrations created by the compromised account

- \[ \] Check for Temporary Access Pass (TAP) registrations on any accounts (per Obsidian Security Scattered Spider analysis)

- \[ \] Scope lateral movement: identify all systems and SaaS apps accessed by the compromised identity

- \[ \] Check for eDiscovery searches or SharePoint mass downloads

**Containment**

- \[ \] Revoke all OAuth tokens and application consent grants created during the compromise window

- \[ \] Remove any unauthorized inbox forwarding rules

- \[ \] Restore any deleted or modified conditional access policies

- \[ \] Disable any attacker-created accounts (especially those disguised as service accounts)

- \[ \] Reset credentials for all accounts accessed by the compromised identity

- \[ \] If domain compromise suspected: reset krbtgt password twice (10+ hours apart)

**Recovery & Governance**

- \[ \] Deploy phishing-resistant MFA (FIDO2 hardware keys) for all privileged accounts

- \[ \] Implement number matching for push MFA to prevent MFA fatigue attacks

- \[ \] Conduct an OAuth application audit: revoke unnecessary consent grants across the tenant

- \[ \] Review and harden helpdesk identity verification procedures to prevent social engineering

- \[ \] Enable risk-based conditional access policies requiring step-up authentication for anomalous sign-ins

- \[ \] Deploy continuous access evaluation (CAE) to enforce near-real-time token revocation

- \[ \] Conduct post-incident review within 72 hours; update this playbook with lessons learned

7\. CREDIBLE SOURCES & REFERENCES

**Primary Intelligence Sources**

- Unit 42 Global Incident Response Report 2026 (Feb 2026, 750+ engagements) — https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report

- Unit 42 GIR 2026 Press Release: identity weaknesses in 89% of investigations, 65% identity-driven initial access — https://www.prnewswire.com/news-releases/unit-42-report-ai-and-attack-surface-complexity-fuel-majority-of-breaches-302689259.html

- Mandiant M-Trends 2025: stolen credentials \#2 initial vector at 16%; cloud phishing 39%, stolen creds 35% — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

- Mandiant M-Trends 2026: voice phishing \#2 vector (11%); initial access handoff in 22 seconds; AD CS exploitation for MFA bypass — https://www.securityweek.com/m-trends-2026-initial-access-handoff-shrinks-from-hours-to-22-seconds/

**CISA Advisories**

- CISA AA23-320A: Scattered Spider Advisory (updated Jul 2025) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a

- CISA/IC3 Scattered Spider PDF (Jul 2025) — https://www.ic3.gov/CSA/2025/250729.pdf

**Vendor Research**

- CrowdStrike: Defending Against Scattered Spider with Falcon Next-Gen SIEM (Sep 2025) — https://www.crowdstrike.com/en-us/blog/defending-against-scattered-spider-with-falcon-next-gen-siem/

- Microsoft: Octo Tempest crosses boundaries (Oct 2023) — referenced via MITRE G1015

- Obsidian Security: Scattered Spider SaaS Attack Analysis & ATT&CK Mapping (Nov 2025) — https://www.obsidiansecurity.com/blog/scattered-spider-saas-attack-analysis

- Picus Security: Tracking Scattered Spider Through Identity Attacks and Token Theft (Jul 2025) — https://www.picussecurity.com/resource/blog/tracking-scattered-spider-through-identity-attacks-and-token-theft

- Darktrace: Scattered Spider Evolving TTPs (Jul 2025) — https://www.darktrace.com/blog/untangling-the-web-darktraces-investigation-of-scattered-spiders-evolving-tactics

**MITRE ATT&CK References**

- MITRE ATT&CK Scattered Spider (G1015) — https://attack.mitre.org/groups/G1015/

- T1110.003 — Password Spraying: https://attack.mitre.org/techniques/T1110/003/

- T1621 — MFA Request Generation: https://attack.mitre.org/techniques/T1621/

- T1078 — Valid Accounts: https://attack.mitre.org/techniques/T1078/

- T1528 — Steal Application Access Token: https://attack.mitre.org/techniques/T1528/

- T1556.009 — Modify Auth: Conditional Access Policies: https://attack.mitre.org/techniques/T1556/009/

- T1098.001 — Additional Cloud Credentials: https://attack.mitre.org/techniques/T1098/001/

- T1098.002 — Additional Email Delegate Permissions: https://attack.mitre.org/techniques/T1098/002/

- T1114.003 — Email Forwarding Rule: https://attack.mitre.org/techniques/T1114/003/

- T1136.003 — Create Cloud Account: https://attack.mitre.org/techniques/T1136/003/

- T1550.001 — Application Access Token: https://attack.mitre.org/techniques/T1550/001/

- T1550.002 — Pass the Hash: https://attack.mitre.org/techniques/T1550/002/

- T1656 — Impersonation: https://attack.mitre.org/techniques/T1656/

**Playbook Status: Active** \| Next Review: 2026-06-25 \| Key Threat Actor: Scattered Spider (MITRE G1015) \| Key Statistic: Identity implicated in ~90% of incidents (Unit 42 GIR 2026)
