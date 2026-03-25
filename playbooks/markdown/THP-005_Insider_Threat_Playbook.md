**THREAT HUNTING PLAYBOOK**

Insider Threat & Data Exfiltration Detection

|                      |                                                                                                                          |
|----------------------|--------------------------------------------------------------------------------------------------------------------------|
| **Field**            | **Value**                                                                                                                |
| **Playbook ID**      | THP-005                                                                                                                  |
| **Severity**         | CRITICAL                                                                                                                 |
| **Author**           | Muhammed Can                                                                                                             |
| **Version**          | 1.0                                                                                                                      |
| **Last Updated**     | 2026-03-25                                                                                                               |
| **Technology Stack** | Splunk (SIEM) — Windows Security + M365 UAL + CASB + DLP Logs                                                            |
| **Status**           | Active                                                                                                                   |
| **Next Review**      | 2026-06-25                                                                                                               |
| **Tags**             | insider-threat, data-exfiltration, behavioral-profiling, departing-employee, USB, cloud-exfil, BEC, DPRK-IT-worker, UEBA |

1\. HUNT HYPOTHESIS & DESCRIPTION

**Hypothesis**

Insider threats represent one of the most difficult challenges in cybersecurity because the adversary already possesses legitimate access. Unlike external threat actors who must breach perimeter defenses, insiders operate within the trust boundary. This playbook combines technical detection engineering with behavioral risk profiling to hunt for insider-driven data exfiltration, sabotage, fraud, and policy violations. It addresses both malicious insiders (intentional) and negligent insiders (unintentional), as well as the emerging threat of fraudulent insiders such as DPRK IT workers using fabricated identities.

> *"If an insider is preparing to exfiltrate sensitive data, we should observe a convergence of behavioral risk indicators (financial stress, disgruntlement, departure signals) with technical indicators (mass file downloads, USB device usage, cloud upload anomalies, email forwarding to personal accounts, abnormal database queries, and after-hours access patterns) — detectable through a combination of UEBA behavioral baselines, Windows Security Event Logs, M365 Unified Audit Logs, DLP alerts, and HR data correlation."*

**Threat Intelligence Context**

|                                                   |                                                                                                                                                                                                                                 |           |
|---------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| **Source**                                        | **Key Finding**                                                                                                                                                                                                                 | **Date**  |
| Unit 42 GIR 2026                                  | Encryption-based extortion declined 15%; attackers increasingly skip encryption and move straight to data theft and disruption; SaaS data involved in 23% of incidents                                                          | Feb 2026  |
| Mandiant M-Trends 2025                            | Data theft was the primary objective in 66% of cloud compromises; UNC5537 used infostealer-harvested credentials to exfiltrate data from Snowflake customer instances at scale                                                  | Apr 2025  |
| Mandiant M-Trends 2026                            | DPRK IT workers using false identities had median dwell time of 122 days as insiders, with some cases undetected for over a year; ransomware operators now target identity services and backup infrastructure for data theft    | Mar 2026  |
| Verizon DBIR 2024                                 | Human element involved in 68% of breaches; privilege misuse by insiders remains a top breach pattern; ransomware appeared in 44% of data breaches                                                                               | 2024      |
| CISA Insider Threat Mitigation Guide              | Comprehensive guide covering insider motivations (financial, revenge, ideology, recognition), behavioral progression, stressors, and observable warning signs; notes that malicious insider acts are rarely spontaneous         | Nov 2020  |
| Carnegie Mellon CERT/SEI                          | Published Insider Threat Indicator Ontology providing structured taxonomy of behavioral, technical, and organizational indicators; referenced by CISA as authoritative source                                                   | Ongoing   |
| 2025 Insider Risk Report (Cybersecurity Insiders) | 635 CISOs surveyed: only 21% integrate behavioral indicators (HR signals, financial stress); only 12% have predictive models; 93% say insider threats harder to detect than external; 60% concerned about AI misuse by insiders | Dec 2025  |
| SIFMA Insider Threat Best Practices Guide, 3rd Ed | Identifies insider categories: opportunists, calculated attackers, emotional attackers; correlates employee categories (recent hires, contractors, temps) with higher insider risk                                              | Jul 2024  |
| Proofpoint (via industry reports)                 | Financial pressure is the primary motivation for 89% of malicious insider incidents                                                                                                                                             | 2024–2025 |

2\. INSIDER THREAT BEHAVIORAL RISK PROFILING

This section provides a structured framework for identifying potential insider threats through behavioral, psychological, and situational indicators. It is designed to complement technical detection (Section 5) by providing early-warning context that pure log analysis cannot capture. All indicators and frameworks are sourced from CISA, Carnegie Mellon CERT/SEI, SIFMA, and peer-reviewed insider threat research.

* IMPORTANT: Behavioral indicators are risk signals, not proof of malicious intent. No single indicator should trigger an investigation. The convergence of multiple behavioral indicators with technical anomalies warrants further assessment by a cross-functional team including HR, Legal, and Security. Per CISA guidance, the goal of threat assessment is prevention, not punishment.**

2.1 Insider Motivation Categories

The CISA Insider Threat Mitigation Guide (Nov 2020) and SIFMA Best Practices Guide (Jul 2024) identify the following primary motivation categories for malicious insiders:

|                           |                                                                                                                                                                                       |                                                                                                                                                                                  |                                                                                 |
|---------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| **Motivation**            | **Description**                                                                                                                                                                       | **Behavioral Indicators**                                                                                                                                                        | **Source**                                                                      |
| Financial Gain            | Primary motivation for 89% of malicious insider incidents. Insiders steal data, commit fraud, or sell access for money                                                                | Unexplained lifestyle changes, living beyond means, gambling activity, debt collection, sudden interest in data they don’t normally access                                       | Proofpoint (via industry reports), CISA Insider Threat Mitigation Guide p.13–14 |
| Revenge / Disgruntlement  | Perceived grievance against employer: denied promotion, termination, workplace conflict. CISA notes unmet expectations have motivated many insiders to “get even”                     | Vocal complaints about organization, conflicts with management, declining performance, tardiness, discussing grievances with coworkers                                           | CISA Insider Threat Mitigation Guide p.11–12, SIFMA Guide Section V             |
| Ideology / Activism       | Insiders motivated by political, ethical, or social beliefs who leak data or sabotage systems to advance a cause                                                                      | Consumption of extremist content, expressed grievances about organizational ethics, desire to “expose wrongdoing”, whistleblower-adjacent behavior without using proper channels | CISA Insider Threat Mitigation Guide p.12, Carnegie Mellon CERT/SEI             |
| Recognition / Ego         | Desire for attention or importance; may leak sensitive information to appear knowledgeable or important to external parties                                                           | Boasting about access to sensitive information, sharing non-public details in social settings, excessive self-promotion regarding security clearance or access level             | CISA Insider Threat Mitigation Guide p.11                                       |
| Coercion / Recruitment    | External actor (foreign intelligence, competitor, criminal) recruits or coerces an insider. The “professional insider” may be coached and may not understand the full scope           | Unexplained foreign contacts, unusual travel patterns, reluctance to discuss personal life changes, signs of being coached on what to access                                     | SIFMA Guide Section V (“professional insider”), CISA Guide p.15                 |
| Unintentional / Negligent | No malicious intent but creates risk through carelessness. Most common category overall. Clicking phishing links, emailing sensitive files to personal accounts, using weak passwords | Repeated security policy violations, resistance to security training, use of personal devices/accounts for work, circumventing security controls for convenience                 | Verizon DBIR 2024 (68% human element), CISA Guide Chapter 2                     |

2.2 Observable Behavioral Indicators

CISA’s “Detecting and Identifying Insider Threats” guidance states that for insiders who turn to malicious activity, “the acts are rarely spontaneous; instead, they are usually the result of a deliberate decision to act.” The following indicator categories represent the observable precursors identified across CISA, Carnegie Mellon CERT/SEI, and the 2025 Insider Risk Report:

|                                                    |                                                                                                                                                          |                |                                                                              |
|----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|------------------------------------------------------------------------------|
| **Indicator Category**                             | **Observable Behaviors**                                                                                                                                 | **Risk Level** | **Source**                                                                   |
| **Personal & Financial Stressors**                 |                                                                                                                                                          |                |                                                                              |
| Financial Distress                                 | Unexplained wealth or debt indicators, gambling, bankruptcy, sudden lifestyle changes, living beyond means                                               | High           | CISA Guide p.13–14, Proofpoint (89% stat)                                    |
| Personal Crisis                                    | Divorce, custody disputes, substance abuse, mental health changes, major life disruption                                                                 | Medium         | CISA Guide p.14–15, Carnegie Mellon CERT/SEI                                 |
| **Workplace Behavioral Changes**                   |                                                                                                                                                          |                |                                                                              |
| Disgruntlement                                     | Vocal complaints, conflicts with management, declining performance, tardiness, expressions of wanting revenge                                            | High           | CISA Guide p.11–12, SIFMA Guide Section V                                    |
| Policy Violations                                  | Repeatedly bypassing security controls, refusing security training, pushing back against access restrictions, patterns of non-compliance                 | Medium–High    | CISA Guide Chapter 3, 2025 Insider Risk Report                               |
| Reluctance to Take Vacation                        | Employee avoids time off, doesn’t want anyone else accessing their systems or work; may indicate concealment of unauthorized activity                    | Medium         | SIFMA Guide Section V                                                        |
| Unusual Work Patterns                              | Working at odd hours without clear justification, accessing systems outside normal duties, increased after-hours access                                  | Medium         | CISA “Detecting and Identifying” page, Securonix                             |
| **Departure & Flight Risk Signals**                |                                                                                                                                                          |                |                                                                              |
| Resignation / Departure                            | Notice of resignation, contract end, performance improvement plan (PIP), imminent layoff — departing employees pose heightened exfiltration risk         | Critical       | SIFMA Guide Section V, CISA Guide p.17                                       |
| Job Search Activity                                | LinkedIn profile updates, resume uploads, recruiter communications, competitor research during work hours                                                | Medium         | 2025 Insider Risk Report, Insider Threat Matrix 2025                         |
| **Access & Information Seeking**                   |                                                                                                                                                          |                |                                                                              |
| Unauthorized Access Requests                       | Requesting access to data or systems outside their role without clear business justification                                                             | High           | CISA Guide Chapter 3                                                         |
| Excessive Data Access                              | Downloading, copying, or printing unusually large volumes of data; accessing files or databases they have never accessed before                          | Critical       | Carnegie Mellon CERT/SEI, Mandiant M-Trends 2025 (UNC5537 Snowflake pattern) |
| **DPRK IT Worker / Fraudulent Insider (Emerging)** |                                                                                                                                                          |                |                                                                              |
| Fabricated Identity                                | Remote employee using stolen/fabricated identity, falsified employment history, laptop farms; median 122-day dwell time; some undetected for over a year | Critical       | Mandiant M-Trends 2025 (UNC5267), M-Trends 2026 (DPRK IT workers)            |

2.3 The Convergence Model: When Behavioral Meets Technical

The 2025 Insider Risk Report found that only 21% of organizations integrate behavioral indicators (HR signals, financial stress, psychosocial context) into their detection programs. This leaves 79% relying exclusively on technical anomalies, causing teams to miss critical early-warning signs. The most effective approach is convergence: correlating behavioral risk signals from HR and management with technical indicators from SIEM and DLP.

**High-confidence insider threat detection occurs when indicators converge across at least two of the following three domains:**

- BEHAVIORAL: Observable changes in the person (disgruntlement, financial stress, departure signals, policy violations) — sourced from HR, management observation, and employee assistance programs

- TECHNICAL: Anomalous digital activity (mass downloads, USB usage, cloud uploads, after-hours access, abnormal database queries) — sourced from SIEM, DLP, UEBA, and audit logs

- CONTEXTUAL: Situational factors that increase risk (imminent departure, access to crown jewels, recent disciplinary action, contractor status) — sourced from HR systems and asset inventories

**When indicators from at least two domains converge for the same individual, the case should be escalated to a cross-functional Insider Threat Working Group (per CISA Insider Threat Mitigation Guide recommendation) comprising representatives from Security, HR, Legal, and relevant business leadership.**

3\. MITRE ATT&CK MAPPING

All technique IDs verified against MITRE ATT&CK Enterprise framework (https://attack.mitre.org).

|                 |                  |                                             |                                                                 |
|-----------------|------------------|---------------------------------------------|-----------------------------------------------------------------|
| **Phase**       | **Technique ID** | **Technique Name**                          | **Insider Threat Scenario**                                     |
| Collection      | T1005            | Data from Local System                      | Mass file download to local storage before departure            |
| Collection      | T1039            | Data from Network Shared Drive              | Bulk download from corporate file shares                        |
| Collection      | T1114.003        | Email Collection: Email Forwarding Rule     | Auto-forwarding corporate email to personal account             |
| Collection      | T1113            | Screen Capture                              | Screenshotting sensitive data to bypass DLP                     |
| Collection      | T1560.001        | Archive Collected Data: Archive via Utility | Zipping large data collections before exfil                     |
| Exfiltration    | T1567            | Exfiltration Over Web Service               | Upload to personal OneDrive/Google Drive/Dropbox                |
| Exfiltration    | T1052.001        | Exfiltration Over Physical Medium: USB      | Copy to USB drive                                               |
| Exfiltration    | T1048            | Exfiltration Over Alternative Protocol      | Data sent via non-standard channels (personal email, messaging) |
| Defense Evasion | T1070.004        | Indicator Removal: File Deletion            | Deleting access logs or evidence of data staging                |
| Persistence     | T1098.002        | Account Manipulation: Email Delegate        | Adding hidden delegates to mailboxes                            |
| Initial Access  | T1078            | Valid Accounts                              | Legitimate credentials used for unauthorized purposes           |
| Impact          | T1485            | Data Destruction                            | Sabotage: deleting critical data before departure               |

4\. REQUIRED DATA SOURCES

|                                     |                                                                                                           |              |
|-------------------------------------|-----------------------------------------------------------------------------------------------------------|--------------|
| **Log Source**                      | **Purpose**                                                                                               | **Priority** |
| Windows Security Event Logs         | Process creation (4688), file access (4663), USB device (6416), logon events (4624/4625)                  | Critical     |
| M365 Unified Audit Log              | SharePoint/OneDrive downloads, email forwarding rules, eDiscovery, Teams file sharing, mailbox delegation | Critical     |
| DLP Alerts (M365 / Endpoint)        | Sensitive data classification matches, policy violations, blocked/overridden transfers                    | Critical     |
| CASB Logs (Defender for Cloud Apps) | Shadow IT cloud uploads, personal cloud storage access, anomalous SaaS activity                           | High         |
| Entra ID Sign-In / Audit Logs       | After-hours authentication, anomalous access patterns, conditional access evaluation                      | High         |
| HR Data Feed (HRIS Integration)     | Departure dates, PIP status, disciplinary actions, contractor end dates — for behavioral correlation      | High         |
| Database Audit Logs                 | Abnormal query volumes, bulk SELECT statements, access to tables outside normal role                      | High         |
| Print/MFP Audit Logs                | Unusual print volumes of sensitive documents                                                              | Medium       |

5\. SPLUNK SPL DETECTION RULES

All queries are written in valid SPL. Each is mapped to MITRE ATT&CK techniques and specific insider threat scenarios.

SPL 5.1 — Mass File Download from SharePoint/OneDrive

Detects users downloading an unusually high number of files from SharePoint or OneDrive in a single session. Mandiant M-Trends 2025 confirmed data theft was the primary objective in 66% of cloud compromises. Unit 42 GIR 2026 found 23% of incidents involved SaaS application data.

Maps to: T1005 (Data from Local System), T1039 (Data from Network Shared Drive), T1567 (Exfiltration Over Web Service)

Sources: Mandiant M-Trends 2025, Unit 42 GIR 2026

index=o365 sourcetype="o365:management:activity"

(Operation="FileDownloaded" OR Operation="FileSyncDownloadedFull")

\| bin \_time span=1h

\| stats count AS downloads, dc(SourceFileName) AS unique_files,

values(SourceFileName) AS files BY \_time, UserId, ClientIP

\| where downloads \>= 50 OR unique_files \>= 30

\`\`\` Threshold: 50+ downloads or 30+ unique files in 1 hour \`\`\`

\| sort - downloads

SPL 5.2 — USB Removable Device Insertion

Detects USB removable storage device insertion on corporate endpoints. USB exfiltration remains a core insider threat vector per CISA Insider Threat Mitigation Guide and Carnegie Mellon CERT/SEI research.

Maps to: T1052.001 (Exfiltration Over Physical Medium: USB)

Sources: CISA Insider Threat Mitigation Guide, MITRE T1052.001

index=windows (EventCode=6416 OR EventCode=6419 OR EventCode=6420)

ClassName="DiskDrive" OR ClassName="USB"

\| table \_time, Computer, SubjectUserName, DeviceId, DeviceDescription, ClassName

\| sort - \_time

SPL 5.3 — Email Forwarding to External / Personal Address

Detects creation of inbox rules forwarding email to external addresses. Both APT29 and insider threats use email forwarding for persistent data collection (per MITRE G0016 and CISA AA23-320A).

Maps to: T1114.003 (Email Forwarding Rule)

Sources: MITRE G0016, CISA Insider Threat Mitigation Guide

index=o365 sourcetype="o365:management:activity"

(Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="Set-Mailbox")

(Parameters.ForwardTo="\*" OR Parameters.ForwardAsAttachmentTo="\*"

OR Parameters.RedirectTo="\*")

\| eval external=if(NOT match(Parameters.ForwardTo,"@yourdomain\\com"),"EXTERNAL","Internal")

\| where external="EXTERNAL"

\| table \_time, UserId, Operation, Parameters.ForwardTo, Parameters.RedirectTo, ClientIP

SPL 5.4 — Upload to Personal Cloud Storage

Detects uploads to personal cloud storage services (personal OneDrive, Google Drive, Dropbox, iCloud, WeTransfer) that bypass corporate DLP. CASB or proxy logs provide visibility into this activity.

Maps to: T1567 (Exfiltration Over Web Service)

Sources: CISA Insider Threat Mitigation Guide, Mandiant M-Trends 2025

index=proxy OR index=casb

(url="\*drive.google.com/upload\*" OR url="\*dropbox.com/upload\*"

OR url="\*onedrive.live.com\*" OR url="\*icloud.com\*upload\*"

OR url="\*wetransfer.com\*" OR url="\*mega.nz\*"

OR url="\*send.firefox.com\*" OR url="\*file.io\*")

action="allowed"

\| stats count, sum(bytes_out) AS total_bytes BY \_time, src_user, url, dest

\| eval MB_uploaded=round(total_bytes/1048576,2)

\| where MB_uploaded \> 50

\`\`\` Flag: 50+ MB uploaded to personal cloud in a session \`\`\`

\| sort - MB_uploaded

SPL 5.5 — After-Hours Access to Sensitive Resources

Detects user access to sensitive resources outside normal business hours, a key behavioral indicator per CISA and Carnegie Mellon CERT/SEI. Context from HR data (departure date, PIP status) increases confidence.

Maps to: T1078 (Valid Accounts)

Sources: CISA "Detecting and Identifying Insider Threats" page, Carnegie Mellon CERT/SEI

index=o365 sourcetype="o365:management:activity"

(Operation="FileAccessed" OR Operation="FileDownloaded")

(SiteUrl="\*confidential\*" OR SiteUrl="\*restricted\*" OR SiteUrl="\*executive\*"

OR SourceFileName="\*board\*" OR SourceFileName="\*M&A\*"

OR SourceFileName="\*salary\*" OR SourceFileName="\*strategy\*")

\| eval hour=strftime(\_time, "%H")

\| where hour \< 6 OR hour \> 21

\`\`\` Flag: Access between 9pm and 6am \`\`\`

\| lookup departing_employees.csv UserId OUTPUT departure_date, on_pip

\`\`\` Enrich with HR data for context \`\`\`

\| table \_time, UserId, Operation, SourceFileName, SiteUrl, hour, departure_date, on_pip

SPL 5.6 — Abnormal Database Query Volume

Detects users executing an unusually high volume of database queries or bulk SELECT statements. Mandiant M-Trends 2025 documented UNC5537 using stolen credentials to bulk-exfiltrate data from Snowflake database instances, representing the large-scale insider-like data theft pattern.

Maps to: T1005 (Data from Local System)

Sources: Mandiant M-Trends 2025 (UNC5537 Snowflake campaign)

index=database sourcetype=db_audit

(query_type="SELECT" OR query_type="COPY INTO" OR query_type="EXPORT")

\| bin \_time span=1h

\| stats count AS queries, dc(table_name) AS unique_tables,

sum(rows_returned) AS total_rows BY \_time, db_user, src_ip

\| where queries \> 100 OR unique_tables \> 20 OR total_rows \> 100000

\`\`\` Threshold: Adjust based on normal DBA activity baseline \`\`\`

\| sort - total_rows

SPL 5.7 — Large Archive Creation Before Exfiltration

Detects creation of large archive files (ZIP, RAR, 7z) on endpoints, a common staging technique before data exfiltration.

Maps to: T1560.001 (Archive Collected Data: Archive via Utility)

Sources: MITRE T1560.001, CISA Insider Threat Mitigation Guide

index=windows sourcetype=XmlWinEventLog EventCode=4663

(ObjectName="\*.zip" OR ObjectName="\*.rar" OR ObjectName="\*.7z"

OR ObjectName="\*.tar.gz")

ObjectName="\*\\Users\\\*"

\| eval file_size_mb=round(ObjectSize/1048576,2)

\| where file_size_mb \> 100

\`\`\` Flag: Archive \> 100 MB in user directory \`\`\`

\| table \_time, Computer, SubjectUserName, ObjectName, file_size_mb

SPL 5.8 — Departing Employee Correlation Hunt

Combines HR departure data with technical activity indicators to identify departing employees exhibiting elevated data access patterns. The SIFMA Best Practices Guide (Jul 2024) specifically identifies departing employees as a heightened risk category. The 2025 Insider Risk Report found only 21% of organizations integrate HR signals into detection.

Maps to: T1005, T1567, T1052.001 (data collection and exfiltration techniques)

Sources: SIFMA Guide Section V (Jul 2024), 2025 Insider Risk Report (Dec 2025)

\`\`\` Prerequisite: departing_employees.csv lookup with UserId, departure_date, department \`\`\`

index=o365 sourcetype="o365:management:activity"

(Operation="FileDownloaded" OR Operation="FileSyncDownloadedFull")

\| lookup departing_employees.csv UserId OUTPUT departure_date, department

\| where isnotnull(departure_date)

\| eval days_until_departure=round((strptime(departure_date,"%Y-%m-%d")-\_time)/86400,0)

\| where days_until_departure \>= 0 AND days_until_departure \<= 30

\`\`\` Focus: Users within 30 days of departure \`\`\`

\| stats count AS downloads, dc(SourceFileName) AS unique_files

BY UserId, departure_date, department, days_until_departure

\| where downloads \>= 20

\`\`\` Flag: 20+ downloads by departing employee \`\`\`

\| sort days_until_departure

6\. KNOWN FALSE POSITIVES & TUNING GUIDANCE

|                    |                                                                                      |                                                                                                         |
|--------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Detection**      | **Common False Positives**                                                           | **Tuning Recommendation**                                                                               |
| Mass File Download | Migration projects, content audits, legitimate bulk exports, data science workflows  | Baseline normal download volumes per user role; exclude known migration service accounts                |
| USB Device         | Authorized USB peripherals (keyboards, mice), IT-approved encrypted drives           | Allowlist approved USB device IDs; alert only on mass storage class devices                             |
| Email Forwarding   | Legitimate forwarding during leave, shared mailbox management, approved integrations | Alert on external forwarding only; cross-reference with HR leave data and approved forwarding list      |
| Cloud Upload       | Marketing teams using approved cloud sharing, developer file transfers               | Exclude approved cloud domains; focus on personal accounts and new/unsanctioned services                |
| After-Hours Access | Global team members in different time zones, on-call rotation, deadline-driven work  | Adjust hours for user’s local timezone; combine with HR context (departure, PIP) to increase confidence |
| Database Queries   | DBA maintenance, scheduled reports, legitimate analytics workloads                   | Baseline normal query volume per database role; exclude automated/scheduled query accounts              |
| Archive Creation   | Developers archiving project deliverables, IT backup operations                      | Scope to user directories only; correlate with departure date for high confidence                       |
| Departing Employee | Normal handover activity, knowledge transfer downloads                               | Distinguish handover (shared team folders) from hoarding (personal copies of sensitive data)            |

7\. RESPONSE ACTIONS

**IMPORTANT: Insider threat investigations involve sensitive legal, HR, and privacy considerations. All response actions must be coordinated with Legal and HR before taking action against an individual. Per CISA guidance, the goal is prevention and harm reduction, not punitive action.**

**Immediate (0–30 minutes)**

- \[ \] Validate the alert: confirm technical indicator is not a false positive (check business context)

- \[ \] Check for behavioral convergence: cross-reference with HR data (departure date, PIP, recent disciplinary action)

- \[ \] If high-risk convergence confirmed: escalate to Insider Threat Working Group (Security + HR + Legal)

- \[ \] Preserve evidence: capture current file access logs, email rules, cloud activity, USB history

- \[ \] Do NOT alert the subject until Legal and HR have assessed the situation

**Investigation (30 minutes – 48 hours)**

- \[ \] Establish full timeline: when did anomalous activity begin relative to departure date or other stressor?

- \[ \] Identify what data was accessed: classify sensitivity level of accessed/downloaded files

- \[ \] Determine if data left the organization: check USB usage, cloud uploads, email attachments, print jobs

- \[ \] Interview the individual (coordinated with HR and Legal) to determine intent

- \[ \] Assess scope: are other insiders engaged in similar activity? Run fleet-wide hunts.

**Containment**

- \[ \] Restrict access: reduce permissions to least-privilege immediately if exfiltration confirmed

- \[ \] Disable email forwarding rules and external sharing permissions

- \[ \] Block USB devices via endpoint policy if USB exfiltration detected

- \[ \] Revoke VPN/remote access if the individual is no longer authorized

- \[ \] Engage eDiscovery to identify full scope of data exposed

**Governance & Prevention**

- \[ \] Implement automated departure workflow: HR departure trigger activates enhanced monitoring for 30 days pre-departure

- \[ \] Deploy UEBA baseline per user to detect deviations from normal data access patterns

- \[ \] Establish cross-functional Insider Threat Working Group (per CISA recommendation)

- \[ \] Conduct regular insider threat awareness training emphasizing reporting pathways (not surveillance)

- \[ \] Integrate behavioral indicators (HR signals) with technical detection per the convergence model (Section 2.3)

- \[ \] Conduct post-incident review; update this playbook with lessons learned

8\.  REFERENCES

**Primary Intelligence Sources**

- Unit 42 Global Incident Response Report 2026 (Feb 2026) — https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report

- Mandiant M-Trends 2025 (Apr 2025) — https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

- Mandiant M-Trends 2026 (Mar 2026) — https://www.securityweek.com/m-trends-2026-initial-access-handoff-shrinks-from-hours-to-22-seconds/

- Verizon 2024 Data Breach Investigations Report — https://www.verizon.com/business/resources/reports/dbir/

**Insider Threat Behavioral Profiling Sources**

- CISA Insider Threat Mitigation Guide (Nov 2020) — https://www.cisa.gov/sites/default/files/2022-11/Insider%20Threat%20Mitigation%20Guide_Final_508.pdf

- CISA Detecting and Identifying Insider Threats — https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/detecting-and-identifying-insider-threats

- CISA Insider Threat Mitigation (Main Page) — https://www.cisa.gov/topics/physical-security/insider-threat-mitigation

- Carnegie Mellon CERT/SEI Insider Threat Center — referenced by CISA; published Insider Threat Indicator Ontology

- SIFMA Cybersecurity Insider Threat Best Practices Guide, 3rd Edition (Jul 2024) — https://www.sifma.org/wp-content/uploads/2025/03/2024-SIFMA-Insider-Threat-Best-Practices-Guide-FINAL.pdf

- 2025 Insider Risk Report (Cybersecurity Insiders, 635 CISOs surveyed, Dec 2025) — https://www.cybersecurity-insiders.com/2025-insider-risk-report-the-shift-to-predictive-whole-person-insider-risk-management/

- Proofpoint: financial pressure primary motivation for 89% of malicious insider incidents — cited across industry reports

**MITRE ATT&CK Technique References**

- T1005 — Data from Local System: https://attack.mitre.org/techniques/T1005/

- T1039 — Data from Network Shared Drive: https://attack.mitre.org/techniques/T1039/

- T1052.001 — Exfiltration Over Physical Medium: USB: https://attack.mitre.org/techniques/T1052/001/

- T1114.003 — Email Forwarding Rule: https://attack.mitre.org/techniques/T1114/003/

- T1560.001 — Archive via Utility: https://attack.mitre.org/techniques/T1560/001/

- T1567 — Exfiltration Over Web Service: https://attack.mitre.org/techniques/T1567/

- T1078 — Valid Accounts: https://attack.mitre.org/techniques/T1078/

- T1485 — Data Destruction: https://attack.mitre.org/techniques/T1485/

**Playbook Status: Active** \| Next Review: 2026-06-25 \| Frameworks: MITRE ATT&CK + CISA Insider Threat Guide + Carnegie Mellon CERT/SEI \| Key Stat: 89% of malicious insider incidents financially motivated (Proofpoint)
