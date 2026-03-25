# Threat Hunting Playbook Series

**Author:** Dr. Muhammed Can  
**Version:** 1.0  
**Last Updated:** March 2026  
---

## Overview

This repository contains a series of threat hunting playbooks designed to help security teams proactively detect, investigate, and respond to a range of cyber threats. Each playbook provides a structured hunting hypothesis, MITRE ATT&CK mapping, Splunk SPL detection rules, false positive tuning guidance, and incident response checklists.

The playbooks are built on intelligence from publicly available and credible sources including CISA advisories, Mandiant/Google Threat Intelligence, Unit 42 (Palo Alto Networks), Microsoft Threat Intelligence, CrowdStrike, Kaspersky GReAT, ESET, Carnegie Mellon CERT/SEI, and the MITRE ATT&CK and MITRE ATLAS frameworks. Every claim, statistic, and technique mapping in these playbooks is cited to its original source.

---

## Playbooks

| ID | Title | Threat Domain | Severity | SIEM | Key Frameworks |
|----|-------|---------------|----------|------|----------------|
| [THP-001](playbooks/markdown/THP-001_Ransomware_Precursor_Playbook.md) | Ransomware Precursor Activity Detection | Ransomware / Financial | CRITICAL | Splunk + CrowdStrike Falcon | MITRE ATT&CK |
| [THP-002](playbooks/markdown/THP-002_APT_Espionage_Precursor_Playbook.md) | Top 5 APT Groups Hunting Playbook | Nation-State Espionage | CRITICAL | Splunk | MITRE ATT&CK |
| [THP-003](playbooks/markdown/THP-003_Shadow_AI_Local_LLM_Playbook.md) | Shadow AI — Local LLM Inference Tool Detection | Emerging Technology / Shadow IT | HIGH | Splunk | MITRE ATT&CK + MITRE ATLAS |
| [THP-004](playbooks/markdown/THP-004_Identity_Compromise_Playbook.md) | Identity Compromise & Credential Abuse Detection | Identity / Cloud | CRITICAL | Splunk | MITRE ATT&CK |
| [THP-005](playbooks/markdown/THP-005_Insider_Threat_Playbook.md) | Insider Threat & Data Exfiltration Detection | Insider Threat / Data Loss | CRITICAL | Splunk | MITRE ATT&CK + CISA Insider Threat Guide |

---

## Playbook Summaries

### THP-001 — Ransomware Precursor Activity Detection

Hunts for the behavioral precursors that ransomware operators exhibit during the 48–72 hour dwell time before payload deployment. Covers BlackCat (ALPHV), LockBit 3.0, Black Basta, Akira, and Scattered Spider. Detection rules span initial access, discovery, credential access, lateral movement, and pre-deployment indicators. Includes both Splunk SPL and CrowdStrike Falcon LogScale queries.

### THP-002 — Top 5 APT Groups Hunting Playbook

Focuses on the five most active nation-state APT groups in 2024–2025: APT29 (Russia/SVR), APT28 (Russia/GRU), Lazarus Group (North Korea/RGB), APT41 (China/MSS), and Volt Typhoon (China/PLA). TTPs are verified against official MITRE ATT&CK group pages (G0016, G0007, G0032, G0096, G1017) and sourced from Mandiant, CISA, Microsoft, Unit 42, and Kaspersky research.

### THP-003 — Shadow AI — Local LLM Inference Tool Detection

Detects unauthorized local AI inference tools (Ollama, LM Studio, llama.cpp, GPT4All, koboldcpp, Jan, LocalAI, whisper.cpp, Coqui TTS) running on corporate endpoints. Based on the Local AI Detection Pack v2.0. Addresses shadow IT risks including data leakage through local LLM processing, meeting transcription without cloud telemetry, deepfake voice cloning, and exposed inference APIs. Maps to both MITRE ATT&CK and MITRE ATLAS frameworks. Uses only native Windows Event Logs (no Sysmon required).

### THP-004 — Identity Compromise & Credential Abuse Detection

Addresses the dominant attack vector of 2025–2026. Unit 42's 2026 Global Incident Response Report found identity weaknesses in ~90% of 750+ engagements, with 65% of initial access being identity-driven. Covers password spraying, MFA fatigue/push bombing, impossible travel, OAuth consent abuse, mailbox forwarding rule manipulation, conditional access policy tampering, service principal abuse, and NTLM lateral movement. Includes detections for Entra ID, Okta, and M365 environments.

### THP-005 — Insider Threat & Data Exfiltration Detection

The most comprehensive playbook in the series, combining technical detection engineering with behavioral risk profiling. Includes a dedicated Insider Threat Behavioral Risk Profiling section (Section 2) covering motivation categories, observable behavioral indicators, and a convergence model for correlating behavioral signals with technical anomalies. Behavioral profiling is sourced from the CISA Insider Threat Mitigation Guide (Nov 2020), Carnegie Mellon CERT/SEI, SIFMA Best Practices Guide (Jul 2024), and the 2025 Insider Risk Report. Detection rules cover mass file downloads, USB exfiltration, email forwarding, personal cloud uploads, after-hours access, abnormal database queries, archive staging, and departing employee correlation.

---

## Repository Structure

```
threat-hunting-playbooks/
├── README.md
├── playbooks/
│   ├── markdown/                              # GitHub-readable markdown versions
│   │   ├── THP-001_Ransomware_Precursor_Playbook.md
│   │   ├── THP-002_APT_Espionage_Precursor_Playbook.md
│   │   ├── THP-003_Shadow_AI_Local_LLM_Playbook.md
│   │   ├── THP-004_Identity_Compromise_Playbook.md
│   │   └── THP-005_Insider_Threat_Playbook.md
│   └── docx/                                  # Formatted Word document versions
│       ├── THP-001_Ransomware_Precursor_Playbook.docx
│       ├── THP-002_APT_Espionage_Precursor_Playbook.docx
│       ├── THP-003_Shadow_AI_Local_LLM_Playbook.docx
│       ├── THP-004_Identity_Compromise_Playbook.docx
│       └── THP-005_Insider_Threat_Playbook.docx
```

---

## Important Disclaimer

> **This project is provided for educational and research purposes only.**
>
> The threat hunting playbooks, detection rules, Splunk SPL queries, and all associated content in this repository are shared as a community resource to support security professionals in improving their detection and response capabilities.
>
> **Please be aware of the following:**
>
> - **Results will vary.** Detection effectiveness depends entirely on your specific environment, infrastructure, log sources, audit policy configurations, SIEM deployment, and the security tools in use. What works in one environment may not work in another without significant tuning and adaptation.
>
> - **No guarantees are made.** The author does not guarantee that these playbooks will detect any specific threat, prevent any breach, or produce accurate results in your environment. Detection thresholds, index names, sourcetypes, and field names used in the SPL queries are examples and must be adjusted to match your deployment.
>
> - **This is an experimental project.** The author assumes no responsibility or liability for any outcomes, damages, or consequences resulting from the use or misuse of the content in this repository. Users are solely responsible for validating, testing, and adapting these materials to their own environments before any operational deployment.
>
> - **Not a substitute for professional services.** These playbooks are not a replacement for professional threat hunting, incident response, or managed security services. Organizations should engage qualified security professionals for their specific needs.
>
> - **Audit policy dependencies.** Many detection rules require specific Windows Group Policy audit settings, cloud log source configurations, or SIEM data onboarding to function. Deploying the SPL queries without the required data sources will produce no results.
>
> - **False positives are expected.** Every detection rule in this series will generate false positives if not properly tuned to your environment. The false positive tuning guidance in each playbook provides a starting point, but environment-specific tuning is essential.
>
> By using the content in this repository, you acknowledge and accept these limitations.

---

## Frameworks & Methodologies

The playbooks in this series are aligned with the following publicly available frameworks:

- [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org) — Adversary tactics, techniques, and procedures for enterprise environments
- [MITRE ATLAS](https://atlas.mitre.org) — Adversarial Threat Landscape for Artificial Intelligence Systems
- [CISA Insider Threat Mitigation](https://www.cisa.gov/topics/physical-security/insider-threat-mitigation) — U.S. government guidance on insider threat detection and response
- [Carnegie Mellon CERT/SEI](https://www.sei.cmu.edu/our-work/insider-threat/) — Insider threat research and indicator ontology
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — Top risks for LLM applications
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma) — Open signature format for SIEM systems

---

## Key Intelligence Sources

The following sources are cited across the playbook series. All are publicly available:

| Source | Playbooks | URL |
|--------|-----------|-----|
| Unit 42 Global Incident Response Report 2026 | THP-004, THP-005 | [paloaltonetworks.com](https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report) |
| Mandiant M-Trends 2025 | THP-002, THP-004, THP-005 | [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025) |
| Mandiant M-Trends 2026 | THP-004, THP-005 | [securityweek.com](https://www.securityweek.com/m-trends-2026-initial-access-handoff-shrinks-from-hours-to-22-seconds/) |
| CISA StopRansomware Advisories | THP-001 | [cisa.gov/stopransomware](https://www.cisa.gov/stopransomware) |
| CISA Scattered Spider Advisory (AA23-320A) | THP-004 | [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a) |
| CISA Volt Typhoon Advisory (AA24-038A) | THP-002 | [cisa.gov](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a) |
| CISA Insider Threat Mitigation Guide | THP-005 | [cisa.gov (PDF)](https://www.cisa.gov/sites/default/files/2022-11/Insider%20Threat%20Mitigation%20Guide_Final_508.pdf) |
| Cisco Talos — Exposed Ollama Servers | THP-003 | [blogs.cisco.com](https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama) |
| SentinelLABS & Censys — 175K Exposed Ollama | THP-003 | [cybernews.com](https://cybernews.com/security/hadow-ai-ollama-exposed-infrastructure/) |
| Splunk Security Content — Suspicious Local LLM Frameworks | THP-003 | [research.splunk.com](https://research.splunk.com/stories/suspicious_local_llm_frameworks/) |
| Obsidian Security — Scattered Spider SaaS Analysis | THP-004 | [obsidiansecurity.com](https://www.obsidiansecurity.com/blog/scattered-spider-saas-attack-analysis) |
| 2025 Insider Risk Report (Cybersecurity Insiders) | THP-005 | [cybersecurity-insiders.com](https://www.cybersecurity-insiders.com/2025-insider-risk-report-the-shift-to-predictive-whole-person-insider-risk-management/) |
| SIFMA Insider Threat Best Practices Guide, 3rd Ed | THP-005 | [sifma.org (PDF)](https://www.sifma.org/wp-content/uploads/2025/03/2024-SIFMA-Insider-Threat-Best-Practices-Guide-FINAL.pdf) |
| The DFIR Report | THP-001 | [thedfirreport.com](https://thedfirreport.com/) |

---

## How to Use

1. **Read the playbook** relevant to your hunting objective
2. **Verify prerequisites** — ensure the required audit policies, log sources, and SIEM data onboarding are in place
3. **Adapt the SPL queries** — adjust index names, sourcetypes, field names, and thresholds to match your environment
4. **Test in a non-production environment first** — validate detection logic before operational deployment
5. **Tune for false positives** — use the tuning guidance in each playbook as a starting point
6. **Integrate with your workflow** — deploy as saved searches, correlation rules, or scheduled alerts in Splunk

---

## Contributing

Contributions, suggestions, and feedback are welcome. If you identify an error, have a tuning recommendation, or want to suggest a new playbook topic, please open an issue or submit a pull request.

---

## Author

**Dr. Muhammed Can**  
GitHub: [survivedwannacry](https://github.com/survivedwannacry)


