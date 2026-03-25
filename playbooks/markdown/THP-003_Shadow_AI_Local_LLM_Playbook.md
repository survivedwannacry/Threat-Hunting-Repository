**THREAT HUNTING PLAYBOOK**

Shadow AI — Local LLM Inference Tool Detection

|                      |                                                                                                           |
|----------------------|-----------------------------------------------------------------------------------------------------------|
| **Field**            | **Value**                                                                                                 |
| **Playbook ID**      | THP-003                                                                                                   |
| **Severity**         | HIGH                                                                                                      |
| **Author**           | Muhammed Can                                                                                              |
| **Version**          | 1.0                                                                                                       |
| **Last Updated**     | 2026-03-25                                                                                                |
| **Technology Stack** | Splunk (SIEM) — Windows Native Event Logs (No Sysmon Required)                                            |
| **Status**           | Active                                                                                                    |
| **Next Review**      | 2026-06-25                                                                                                |
| **Tags**             | shadow-AI, local-LLM, data-leak, Ollama, LM-Studio, llama.cpp, GPT4All, whisper, voice-clone, MITRE-ATLAS |
| **Detection Pack**   | Local AI Detection Pack v2.0 (github.com/survivedwannacry)                                                |

1\. HUNT HYPOTHESIS & DESCRIPTION

**Hypothesis**

Local AI inference tools (Ollama, LM Studio, llama.cpp, GPT4All, koboldcpp, Jan, LocalAI, whisper.cpp, and others) allow employees to run large language models, audio transcription engines, and image generation models entirely on endpoint hardware with zero cloud telemetry. These tools create a shadow AI ecosystem that bypasses traditional DLP, proxy-based controls, and cloud audit logging. This playbook hunts for the installation, execution, persistence, and abuse of these tools as indicators of shadow IT activity that may lead to data leakage, data exposure, intellectual property theft, or malicious activity such as deepfake audio creation.

> *"If employees are running local AI inference tools on corporate endpoints, we should observe a combination of known AI binary executions, AI model file artifacts (.gguf/.ggml/safetensors) written to disk, local inference server port bindings on non-standard ports, Python-based AI framework launches, scheduled task persistence for AI servers, and audio transcription or voice cloning tool executions — all detectable through native Windows Event Logs without Sysmon or EDR dependencies."*

**Threat Intelligence Context**

The proliferation of local AI tools has been identified as a significant and growing enterprise security risk by multiple credible sources:

|                                |                                                                                                                                                                              |          |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| **Source**                     | **Key Finding**                                                                                                                                                              | **Date** |
| SentinelLABS & Censys          | Discovered 175,000+ publicly exposed Ollama instances across 130 countries; ~48% had tool-calling capabilities enabling code execution and API access                        | Jan 2026 |
| Cisco Talos                    | Identified 1,100+ exposed Ollama servers via Shodan; ~20% were actively hosting models susceptible to unauthorized access                                                    | Sep 2025 |
| Oligo Security                 | Discovered 6 vulnerabilities in Ollama (CVE-2024-39719 through CVE-2024-39722) enabling DoS, model poisoning, model theft, and path traversal                                | 2024     |
| Fuzzinglabs / Black Hat Europe | Disclosed 4 additional Ollama vulnerabilities including auth bypass (CVE-2025-51471) and arbitrary file copy (CVE-2025-48889); presented at Pwn2Own Berlin 2025              | Dec 2025 |
| UpGuard                        | Warned that misconfigured Ollama instances leave systems subject to unauthorized access, data exfiltration, model theft, and adversarial manipulation                        | Mar 2025 |
| Akamai Hunt (SentinelOne)      | Discovered new malware strain hiding C2 traffic inside LLM API calls (/v1/chat/completions), blending malicious traffic with legitimate AI traffic patterns                  | 2025     |
| Splunk Security Research       | Published "Suspicious Local LLM Frameworks" analytic story with detection rules for Ollama, LM Studio, GPT4All, Jan, llama.cpp, KoboldCPP, and model file artifacts          | Nov 2025 |
| MITRE ATLAS                    | Framework expanded with 14 new agentic AI techniques (Oct 2025); catalogs Inference API Access, model theft, prompt injection, and exfiltration via AI agent tool invocation | Oct 2025 |
| OWASP LLM Top 10 (2025)        | Lists sensitive information disclosure, prompt injection, and model theft as top risks for LLM deployments                                                                   | 2025     |

**Threat Scenarios**

|                                                |                                                        |                                                                                                       |                         |
|------------------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------------------------------------------|-------------------------|
| **Threat Scenario**                            | **Tools Involved**                                     | **Why It’s Dangerous**                                                                                | **MITRE Mapping**       |
| Sensitive document summarisation via local LLM | llama.cpp, Ollama, LM Studio, GPT4All                  | No API logs, no data leaving the network — invisible to DLP                                           | T1005, AML.T0024        |
| Meeting transcription via local Whisper        | whisper.cpp, faster-whisper, LocalAI                   | Recorded audio processed locally — invisible to cloud-based DLP                                       | T1123, T1056.002        |
| Deepfake voice cloning                         | Coqui TTS, Kokoro, Chatterbox via LocalAI              | Deepfake audio created with no external service — social engineering risk                             | T1123, AML.T0043        |
| Persistent shadow AI API endpoint              | LocalAI as Windows service, Ollama service             | Full OpenAI-compatible endpoint running on a corporate endpoint — accessible to other users/malware   | T1543.003, T1569.002    |
| Model staging / exfil preparation              | Any GGUF-based tool                                    | Multi-GB model files written to disk — could contain fine-tuned data or serve as exfiltration staging | T1074.001, T1105        |
| Exposed inference server accessible on network | Ollama (11434), llama.cpp (8080), LocalAI (8080/50051) | Misconfigured binding to 0.0.0.0 exposes AI inference API to entire network or internet               | T1571, T1046, AML.T0040 |
| Malware abusing LLM API patterns for C2        | Any local inference server                             | Attackers hide C2 in /v1/chat/completions traffic (per Akamai)                                        | T1071.001, AML.T0051    |

2\. MITRE ATT&CK & ATLAS MAPPING

This playbook maps detections to both the MITRE ATT&CK Enterprise framework (https://attack.mitre.org) for endpoint/infrastructure TTPs and MITRE ATLAS (https://atlas.mitre.org) for AI-specific adversarial techniques. All technique IDs have been verified against the canonical MITRE pages.

|                               |                  |                                                  |                       |                                  |
|-------------------------------|------------------|--------------------------------------------------|-----------------------|----------------------------------|
| **Framework**                 | **Technique ID** | **Technique Name**                               | **Detection Rule(s)** | **Threat Scenario**              |
| **MITRE ATT&CK Enterprise**   |                  |                                                  |                       |                                  |
| ATT&CK                        | T1204.002        | User Execution: Malicious File                   | R01, R04, R06, R07    | Shadow AI tool launch            |
| ATT&CK                        | T1059.006        | Command and Scripting Interpreter: Python        | R04                   | Python AI framework              |
| ATT&CK                        | T1105            | Ingress Tool Transfer                            | R02, R06              | Model file download              |
| ATT&CK                        | T1074.001        | Data Staged: Local Data Staging                  | R02                   | Model staging / exfil            |
| ATT&CK                        | T1571            | Non-Standard Port                                | R03                   | Inference server port            |
| ATT&CK                        | T1046            | Network Service Discovery                        | R03                   | Exposed AI API                   |
| ATT&CK                        | T1053.005        | Scheduled Task/Job                               | R05                   | AI server persistence            |
| ATT&CK                        | T1543.003        | Create or Modify System Process: Windows Service | R08                   | LocalAI as service               |
| ATT&CK                        | T1569.002        | System Services: Service Execution               | R08                   | AI service execution             |
| ATT&CK                        | T1123            | Audio Capture                                    | R07                   | Whisper transcription            |
| ATT&CK                        | T1056.002        | Input Capture: GUI Input Capture                 | R07                   | Voice cloning input              |
| ATT&CK                        | T1071.001        | Application Layer Protocol: Web Protocols        | R03                   | C2 via LLM API                   |
| **MITRE ATLAS (AI-Specific)** |                  |                                                  |                       |                                  |
| ATLAS                         | AML.T0024        | Exfiltration via ML Inference API                | R01, R03              | Data leak via local LLM          |
| ATLAS                         | AML.T0040        | ML Model Inference API Access                    | R03                   | Exposed inference API            |
| ATLAS                         | AML.T0043        | Craft Adversarial Data                           | R07                   | Deepfake audio creation          |
| ATLAS                         | AML.T0051        | LLM Prompt Injection                             | R03, R04              | Model manipulation               |
| ATLAS                         | AML.T0020        | Poison Training Data                             | R02                   | Model poisoning via staged files |

3\. REQUIRED DATA SOURCES & PREREQUISITES

This playbook operates exclusively on native Windows Event Logs. No Sysmon, EDR, or cloud telemetry is required. The following GPO audit policies must be enabled before any detection rules will produce results.

|                                                 |                |                     |              |
|-------------------------------------------------|----------------|---------------------|--------------|
| **GPO Audit Setting**                           | **Event IDs**  | **Detection Rules** | **Priority** |
| Audit Process Creation (Success)                | 4688           | R01, R04, R06, R07  | Critical     |
| Include command line in process creation events | 4688 (cmdline) | R04, R07            | Critical     |
| Audit Object Access: File System (Success)      | 4663           | R02, R06            | Critical     |
| Audit Filtering Platform Connection (Success)   | 5156, 5158     | R03                 | High         |
| Audit Other Object Access Events (Success)      | 4698, 4702     | R05                 | High         |
| Audit Security System Extension (Success)       | 4697           | R08                 | High         |
| System Log (default, no GPO needed)             | 7045           | R08 (fallback)      | Medium       |

**Tools Covered**

|                       |                           |                  |                      |                                 |
|-----------------------|---------------------------|------------------|----------------------|---------------------------------|
| **Tool**              | **Type**                  | **Default Port** | **Primary Binary**   | **Source**                      |
| llama.cpp             | LLM inference             | 8080             | llama-server.exe     | github.com/ggml-org/llama.cpp   |
| Ollama                | LLM inference + model mgr | 11434            | ollama.exe           | ollama.com                      |
| LM Studio             | LLM inference GUI         | 1234             | LM Studio.exe        | lmstudio.ai                     |
| GPT4All               | LLM inference GUI         | —                | gpt4all.exe          | gpt4all.io                      |
| koboldcpp             | LLM inference             | 5001             | koboldcpp.exe        | GitHub/LostRuins                |
| Jan                   | LLM inference GUI         | —                | jan.exe              | jan.ai                          |
| LocalAI               | Multi-modal server        | 8080/50051/9090  | local-ai.exe         | github.com/mudler/LocalAI       |
| whisper.cpp           | Audio transcription       | —                | whisper.exe          | github.com/ggml-org/whisper.cpp |
| Coqui TTS / Kokoro    | Voice cloning / TTS       | —                | Python (via LocalAI) | GitHub/idiap/coqui-ai-TTS       |
| text-generation-webui | LLM inference UI          | 7860             | Python / .exe        | GitHub/oobabooga                |

4\. SPLUNK SPL DETECTION RULES

All queries are written in valid Splunk Processing Language (SPL) and use only native Windows Event Logs (no Sysmon required). Each rule is mapped to MITRE ATT&CK / ATLAS techniques. Rules are derived from the Local AI Detection Pack v2.0 and augmented with intelligence from Splunk Security Research ("Suspicious Local LLM Frameworks" analytic story, Nov 2025).

R01 — Known AI Inference Binary Execution

Detects execution of known local AI inference tool binaries on Windows endpoints. This covers the full tool landscape documented by Splunk Security Research in the "Suspicious Local LLM Frameworks" analytic story (Nov 2025) and the Local AI Detection Pack.

Maps to: T1204.002 (User Execution: Malicious File), AML.T0024 (Exfiltration via ML Inference API)

Sources: Splunk Security Content ID a3f8e2c9 (Nov 2025), Local AI Detection Pack R01, MITRE ATT&CK T1204.002

index=windows sourcetype=XmlWinEventLog EventCode=4688

(NewProcessName="\*\\ollama.exe"

OR NewProcessName="\*\\llama-server.exe" OR NewProcessName="\*\\llama-cli.exe"

OR NewProcessName="\*\\llama-run.exe"

OR NewProcessName="\*\\LM Studio.exe" OR NewProcessName="\*\\lmstudio.exe"

OR NewProcessName="\*\\gpt4all.exe"

OR NewProcessName="\*\\koboldcpp.exe"

OR NewProcessName="\*\\jan.exe"

OR NewProcessName="\*\\local-ai.exe" OR NewProcessName="\*\\localai.exe"

OR NewProcessName="\*\\text-generation-webui.exe"

OR NewProcessName="\*\\whisper.exe"

OR NewProcessName="\*\\stable-diffusion.exe")

\| eval tool=case(

match(NewProcessName, "(?i)ollama"), "Ollama",

match(NewProcessName, "(?i)llama-(server\|cli\|run)"), "llama.cpp",

match(NewProcessName, "(?i)(lm.studio\|lmstudio)"), "LM Studio",

match(NewProcessName, "(?i)gpt4all"), "GPT4All",

match(NewProcessName, "(?i)koboldcpp"), "koboldcpp",

match(NewProcessName, "(?i)jan\\exe"), "Jan",

match(NewProcessName, "(?i)local.?ai"), "LocalAI",

match(NewProcessName, "(?i)whisper"), "whisper.cpp",

match(NewProcessName, "(?i)stable.diffusion"), "Stable Diffusion",

1=1, "Unknown AI Tool")

\| stats earliest(\_time) AS first_seen, latest(\_time) AS last_seen, count

BY Computer, SubjectUserName, NewProcessName, tool

\| sort - count

R02 — AI Model File Written to Disk

Detects creation of AI model files (.gguf, .ggml, safetensors, Modelfile) on Windows endpoints using file system audit events. These file types are characteristic of local inference frameworks (per Splunk Security Content ID 23e5b797, Nov 2025). Multi-GB GGUF files written to disk may indicate model staging for shadow AI use or exfiltration preparation.

Maps to: T1105 (Ingress Tool Transfer), T1074.001 (Data Staged: Local Data Staging), AML.T0020 (Poison Training Data)

Sources: Splunk Security Content ID 23e5b797 (Nov 2025), Local AI Detection Pack R02

index=windows sourcetype=XmlWinEventLog EventCode=4663

(ObjectName="\*.gguf" OR ObjectName="\*.ggml"

OR ObjectName="\*.safetensors" OR ObjectName="\*Modelfile\*"

OR ObjectName="\*Q4_K_M\*" OR ObjectName="\*Q5_K_M\*"

OR ObjectName="\*Q8_0\*" OR ObjectName="\*IQ4_XS\*" OR ObjectName="\*F16\*")

\| stats dc(ObjectName) AS unique_models, values(ObjectName) AS model_files,

earliest(\_time) AS first_write, count BY Computer, SubjectUserName

\| eval risk=case(unique_models\>=3, "critical", unique_models\>=2, "high", 1=1, "medium")

\`\`\` 3+ unique model files = critical: possible model hoarding or staging \`\`\`

\| sort - unique_models

R03 — Local AI Inference Server Port Binding

Detects local processes binding to known AI inference server ports. Ollama defaults to port 11434, llama.cpp/LocalAI to 8080, LM Studio to 1234, koboldcpp to 5001, text-generation-webui to 7860, LocalAI gRPC to 50051, and Prometheus metrics to 9090. SentinelLABS/Censys (Jan 2026) found 175,000+ exposed Ollama instances globally, many due to binding to 0.0.0.0 instead of localhost.

Maps to: T1571 (Non-Standard Port), T1046 (Network Service Discovery), AML.T0040 (Inference API Access)

Sources: SentinelLABS/Censys (Jan 2026), Cisco Talos (Sep 2025), Local AI Detection Pack R03

index=windows sourcetype=XmlWinEventLog (EventCode=5156 OR EventCode=5158)

(DestPort=11434 OR DestPort=8080 OR DestPort=1234

OR DestPort=5001 OR DestPort=7860 OR DestPort=50051 OR DestPort=9090)

\| eval tool_hint=case(

DestPort=11434, "Ollama",

DestPort=8080, "llama.cpp / LocalAI",

DestPort=1234, "LM Studio",

DestPort=5001, "koboldcpp",

DestPort=7860, "text-generation-webui",

DestPort=50051, "LocalAI gRPC",

DestPort=9090, "LocalAI Prometheus")

\| eval exposed=if(match(Destination_Address, "0\\0\\0\\0"), "WARNING: BOUND TO ALL INTERFACES", "localhost only")

\| stats count, values(Application_Name) AS process, values(exposed) AS binding

BY Computer, DestPort, tool_hint

\| sort - count

R04 — Python-Based AI Inference Framework Launch

Detects Python processes launching with command-line arguments referencing AI/ML frameworks (transformers, langchain, huggingface, vllm, text-generation-webui, faster-whisper, coqui). Requires command-line logging to be enabled via GPO.

Maps to: T1059.006 (Python), T1204.002 (User Execution)

Sources: Splunk Security Content (Nov 2025), Local AI Detection Pack R04

index=windows sourcetype=XmlWinEventLog EventCode=4688

NewProcessName="\*\\python\*"

(CommandLine="\*transformers\*" OR CommandLine="\*langchain\*"

OR CommandLine="\*huggingface\*" OR CommandLine="\*text-generation\*"

OR CommandLine="\*llama_cpp\*" OR CommandLine="\*llama-run\*"

OR CommandLine="\*vllm\*serve\*" OR CommandLine="\*vllm.entrypoints\*"

OR CommandLine="\*langchain\*huggingface\*"

OR CommandLine="\*localai\*"

OR CommandLine="\*faster_whisper\*" OR CommandLine="\*faster-whisper\*"

OR CommandLine="\*coqui\*" OR CommandLine="\*TTS\*synthesize\*")

\| table \_time, Computer, SubjectUserName, NewProcessName, CommandLine, ParentProcessName

R05 — Scheduled Task Created to Persist AI Server

Detects creation of scheduled tasks referencing AI tool binaries, indicating persistence mechanisms for shadow AI servers. A scheduled Ollama or LocalAI task transforms a workstation into a persistent, unmonitored AI endpoint.

Maps to: T1053.005 (Scheduled Task/Job)

Sources: Local AI Detection Pack R05, MITRE ATT&CK T1053.005

index=windows sourcetype=XmlWinEventLog (EventCode=4698 OR EventCode=4702)

(TaskContent="\*ollama\*" OR TaskContent="\*llama-server\*"

OR TaskContent="\*llama-cli\*" OR TaskContent="\*lmstudio\*"

OR TaskContent="\*gpt4all\*" OR TaskContent="\*koboldcpp\*"

OR TaskContent="\*local-ai\*" OR TaskContent="\*localai\*"

OR TaskContent="\*jan.exe\*" OR TaskContent="\*whisper\*"

OR TaskContent="\*stable-diffusion\*" OR TaskContent="\*text-generation\*")

\| table \_time, Computer, SubjectUserName, TaskName, TaskContent

R06 — Behavioral: Model Download Then Execution Chain

Correlates model file artifacts appearing on disk (EID 4663) followed by AI tool execution (EID 4688) within a 60-minute window, indicating a download-then-execute attack chain or deliberate shadow AI setup.

Maps to: T1105 (Ingress Tool Transfer), T1204.002 (User Execution)

Sources: Local AI Detection Pack R06

\`\`\` Stage 1: Model file written to disk \`\`\`

index=windows sourcetype=XmlWinEventLog EventCode=4663

(ObjectName="\*.gguf" OR ObjectName="\*.ggml" OR ObjectName="\*.safetensors")

\| rename \_time AS file_time, Computer AS file_host, SubjectUserName AS file_user

\| table file_time, file_host, file_user, ObjectName

\`\`\` Stage 2: Join with AI tool execution within 60 minutes \`\`\`

\| join file_host file_user type=inner

\[search index=windows sourcetype=XmlWinEventLog EventCode=4688

(NewProcessName="\*\\ollama\*" OR NewProcessName="\*\\llama-\*"

OR NewProcessName="\*\\lmstudio\*" OR NewProcessName="\*\\gpt4all\*"

OR NewProcessName="\*\\koboldcpp\*" OR NewProcessName="\*\\local-ai\*")

\| rename \_time AS exec_time, Computer AS file_host, SubjectUserName AS file_user

\| table exec_time, file_host, file_user, NewProcessName\]

\| where exec_time \> file_time AND exec_time \< (file_time + 3600)

\| table file_time, exec_time, file_host, file_user, ObjectName, NewProcessName

R07 — Local Audio Transcription or Voice Cloning Execution

Detects execution of local audio transcription (whisper.cpp, faster-whisper) and voice cloning tools (Coqui TTS, Kokoro, Chatterbox). This addresses MITRE ATT&CK T1123 (Audio Capture) — a technique rarely covered in standard endpoint detection packs. Local meeting transcription with zero cloud telemetry represents a significant data leakage vector.

Maps to: T1123 (Audio Capture), T1056.002 (GUI Input Capture), AML.T0043 (Craft Adversarial Data)

Sources: Local AI Detection Pack R07, MITRE ATT&CK T1123

index=windows sourcetype=XmlWinEventLog EventCode=4688

(NewProcessName="\*\\whisper\*"

OR (NewProcessName="\*\\python\*"

AND (CommandLine="\*faster_whisper\*" OR CommandLine="\*faster-whisper\*"

OR CommandLine="\*whisper\*transcribe\*"

OR CommandLine="\*coqui\*" OR CommandLine="\*TTS\*synthesize\*"

OR CommandLine="\*kokoro\*" OR CommandLine="\*chatterbox\*")))

\| eval category=case(

match(NewProcessName,"(?i)whisper") OR match(CommandLine,"(?i)whisper"), "Audio Transcription",

match(CommandLine,"(?i)(coqui\|kokoro\|chatterbox\|TTS.\*synth)"), "Voice Cloning",

1=1, "Unknown Audio AI")

\| table \_time, Computer, SubjectUserName, NewProcessName, CommandLine, category

R08 — LocalAI or AI Tool Installed as Windows Service

Detects AI tools being installed as Windows services, indicating persistent shadow AI infrastructure. Uses dual-source approach: EID 4697 (Security log, requires Audit Security System Extension) and EID 7045 (System log, fires without advanced audit policy as fallback).

Maps to: T1543.003 (Windows Service), T1569.002 (Service Execution)

Sources: Local AI Detection Pack R08, MITRE ATT&CK T1543.003

index=windows (sourcetype=XmlWinEventLog EventCode=4697)

OR (sourcetype=WinEventLog:System EventCode=7045)

(ServiceFileName="\*ollama\*" OR ServiceFileName="\*llama\*"

OR ServiceFileName="\*local-ai\*" OR ServiceFileName="\*localai\*"

OR ServiceFileName="\*lmstudio\*" OR ServiceFileName="\*gpt4all\*"

OR ServiceFileName="\*koboldcpp\*" OR ServiceFileName="\*whisper\*"

OR Service_File_Name="\*ollama\*" OR Service_File_Name="\*local-ai\*"

OR Service_File_Name="\*llama\*")

\| table \_time, Computer, SubjectUserName, ServiceName, ServiceFileName,

Service_File_Name, Service_Start_Type

5\. KNOWN FALSE POSITIVES & TUNING GUIDANCE

|                       |                                                                                            |                                                                                                         |
|-----------------------|--------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Rule**              | **Common False Positives**                                                                 | **Tuning Recommendation**                                                                               |
| R01: Binary Execution | Approved AI/ML development environments; sanctioned data science workstations              | Maintain an approved AI tool inventory per department; exclude sanctioned dev/lab systems via allowlist |
| R02: Model Files      | Legitimate ML research downloading models for approved projects                            | Scope file auditing to user-writable directories; baseline normal model activity by user role           |
| R03: Port Binding     | Port 8080 used by web proxies, local dev servers, Java apps; port 9090 used by Prometheus  | Tune using Application_Name field; alert only on AI-specific binaries binding to these ports            |
| R04: Python AI        | Approved data science Python environments using transformers/langchain for sanctioned work | Baseline approved Python environments; correlate with approved user/machine lists                       |
| R05: Scheduled Tasks  | IT automation creating scheduled tasks with matching keywords                              | Correlate with change management; alert on tasks created by non-admin accounts                          |
| R06: Download+Execute | Approved model deployment workflows in ML operations pipelines                             | Exclude sanctioned MLOps pipelines; focus on user-initiated chains outside business hours               |
| R07: Audio/Voice      | Accessibility tools, legitimate transcription for authorized meeting recording             | Allowlist approved transcription solutions; alert on Coqui/voice cloning tools as high-risk             |
| R08: Service Install  | IT-deployed AI services; approved MLOps infrastructure                                     | Correlate with ITSM tickets; any non-IT service installation should be treated as high severity         |

6\. RESPONSE ACTIONS

**Immediate (0–15 minutes)**

- \[ \] Identify the user and endpoint running the shadow AI tool

- \[ \] Determine if the tool is accessing sensitive data (check recent file access logs for the same user)

- \[ \] Check if the inference server is bound to 0.0.0.0 (exposed to network) vs 127.0.0.1 (localhost only)

- \[ \] If exposed to network: isolate the endpoint immediately to prevent unauthorized inference API access

- \[ \] Preserve evidence: capture running process list, open network connections, and model files on disk

**Investigation (15 minutes – 2 hours)**

- \[ \] Interview the user to determine intent (innocent productivity tool vs. deliberate policy circumvention)

- \[ \] Audit all files processed through the local AI tool (check recent file access patterns for sensitive documents)

- \[ \] Examine model files: are they standard open-source models or custom fine-tuned models containing proprietary data?

- \[ \] Check for scheduled tasks or services indicating persistent shadow AI infrastructure

- \[ \] Scan for additional endpoints running similar tools (use R01 across full fleet)

- \[ \] Determine if any audio files were processed locally (meeting recordings, calls) via R07 detections

**Containment & Remediation**

- \[ \] Remove unauthorized AI tools and model files from the endpoint

- \[ \] Revoke any API keys or tokens associated with the local AI server

- \[ \] Block AI tool binaries via application control policy (AppLocker / WDAC)

- \[ \] Add known AI inference ports (11434, 8080, 1234, 5001, 7860, 50051) to network monitoring

- \[ \] Update DLP policies to monitor for GGUF/GGML/safetensors file creation

- \[ \] Deploy GPO to enforce audit policies required by this playbook across all endpoints

**Governance & Prevention**

- \[ \] Establish an AI Acceptable Use Policy defining approved AI tools and prohibited shadow AI use

- \[ \] Create an AI tool registry (per MITRE ATLAS governance guidance) with owner, approved use, and audit date

- \[ \] Implement regular shadow AI sweeps using R01-R08 detections as scheduled saved searches in Splunk

- \[ \] Conduct user awareness training on risks of processing sensitive data through local AI tools

- \[ \] Conduct post-incident review within 72 hours; update this playbook with lessons learned

7\. CREDIBLE SOURCES & REFERENCES

**Primary Detection Source**

- Local AI Detection Pack v2.0 (Muhammed Can) — github.com/survivedwannacry/local-ai-detection

**Splunk Security Research**

- Splunk Blog: "From Discovery to Defense: Detecting Local LLMs to Address Shadow AI" — https://www.splunk.com/en_us/blog/artificial-intelligence/detecting-local-llms-shadow-ai-splunk.html

- Splunk Security Content: "Suspicious Local LLM Frameworks" Analytic Story (ID 0b4396a1, Nov 2025) — https://research.splunk.com/stories/suspicious_local_llm_frameworks/

- Splunk Security Content: "Windows Local LLM Framework Execution" (ID a3f8e2c9, Nov 2025) — https://research.splunk.com/endpoint/a3f8e2c9-7d4b-4e1f-9c6a-2b5d8f3e1a7c/

- Splunk Security Content: "LLM Model File Creation" (ID 23e5b797, Nov 2025) — https://research.splunk.com/endpoint/23e5b797-378d-45d6-ab3e-d034ca12a99b/

**Vulnerability & Exposure Research**

- Cisco Talos: "Detecting Exposed LLM Servers: A Shodan Case Study on Ollama" (Sep 2025) — https://blogs.cisco.com/security/detecting-exposed-llm-servers-shodan-case-study-on-ollama

- SentinelLABS & Censys: 175,000+ exposed Ollama instances (Jan 2026) — reported via Cybernews: https://cybernews.com/security/hadow-ai-ollama-exposed-infrastructure/

- Oligo Security: "More Models, More Probllms" — 6 Ollama CVEs (CVE-2024-39719 through CVE-2024-39722) — https://www.oligo.security/blog/more-models-more-probllms

- Fuzzinglabs / Black Hat Europe 2025: Ollama CVE-2025-51471 (auth bypass), CVE-2025-48889 (file copy) — reported via Dark Reading: https://www.darkreading.com/vulnerabilities-threats/ollama-nvidia-flaws-ai-infrastructure-risk

- UpGuard: "Understanding and Securing Exposed Ollama Instances" (Mar 2025) — https://www.upguard.com/blog/understanding-and-securing-exposed-ollama-instances

- Ridge Security: "Securing Your AI: Critical Vulnerabilities Found in Popular Ollama Framework" (Mar 2025) — https://ridgesecurity.ai/blog/securing-your-ai-critical-vulnerabilities-found-in-popular-ollama-framework/

**Malware & Threat Intelligence**

- Akamai Hunt: "What We Do In The Shadow (AI): New Malware Strain" — C2 traffic hidden in LLM API calls — https://www.akamai.com/blog/security-research/new-malware-chat-completions-llm-shadow-ai

**Frameworks**

- MITRE ATT&CK Enterprise Framework — https://attack.mitre.org

- MITRE ATLAS (Adversarial Threat Landscape for AI Systems) — https://atlas.mitre.org

- MITRE ATLAS: 15 tactics, 66 techniques (Oct 2025 update with 14 agentic AI techniques) — https://www.vectra.ai/topics/mitre-atlas

- OWASP LLM Top 10 (2025 Edition) — https://owasp.org/www-project-top-10-for-large-language-model-applications/

- NIST AI RMF — https://www.nist.gov/artificial-intelligence/ai-rmf

- MITRE SAFE-AI Framework (ATLAS + NIST SP 800-53 mapping) — https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf

**MITRE ATT&CK Technique References**

- T1204.002 — User Execution: Malicious File: https://attack.mitre.org/techniques/T1204/002/

- T1059.006 — Python: https://attack.mitre.org/techniques/T1059/006/

- T1105 — Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/

- T1074.001 — Local Data Staging: https://attack.mitre.org/techniques/T1074/001/

- T1571 — Non-Standard Port: https://attack.mitre.org/techniques/T1571/

- T1053.005 — Scheduled Task: https://attack.mitre.org/techniques/T1053/005/

- T1543.003 — Windows Service: https://attack.mitre.org/techniques/T1543/003/

- T1123 — Audio Capture: https://attack.mitre.org/techniques/T1123/

- T1056.002 — GUI Input Capture: https://attack.mitre.org/techniques/T1056/002/

- T1071.001 — Web Protocols: https://attack.mitre.org/techniques/T1071/001/

**Tool References**

- Sigma Rules Repository — https://github.com/SigmaHQ/sigma

- Ollama — https://ollama.com / https://github.com/ollama/ollama

- llama.cpp — https://github.com/ggml-org/llama.cpp

- LocalAI — https://github.com/mudler/LocalAI

- LM Studio — https://lmstudio.ai

- GPT4All — https://gpt4all.io

- whisper.cpp — https://github.com/ggml-org/whisper.cpp

**Playbook Status: Active** \| Next Review: 2026-06-25 \| Based on: Local AI Detection Pack v2.0 \| Frameworks: MITRE ATT&CK + MITRE ATLAS + OWASP LLM Top 10
