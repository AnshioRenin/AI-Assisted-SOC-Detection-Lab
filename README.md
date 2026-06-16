# AI-Assisted SOC Detection Lab

A home Security Operations Center that detects, investigates, and responds to simulated attacks — with an **LLM-powered triage assistant** layered on top, and that assistant **hardened against prompt-injection**. The project combines hands-on **detection engineering** with applied **AI security**.

> Status: building in public. See [my write-up/videos](https://anshio-renin.vercel.app/).

---

## Why this project

It mirrors real threat-detection operations work: developing detection **signals**, **risk hunting**, **alert investigation**, mapping activity to **MITRE ATT&CK**, **automation via code**, **log/data analysis with SQL**, and **reducing operational toil** — plus a modern twist most labs skip: using AI to assist triage *and* securing that AI.

## Architecture

```
[ Windows VM + Sysmon ] --logs--> [ Wazuh Agent ] --> [ Wazuh Manager + Dashboard ]
        ^                                                       |
        |                                                 [ ai_triage.py ]
[ Atomic Red Team ]  simulates                            local LLM (Ollama):
techniques mapped to MITRE ATT&CK                         summary, ATT&CK map,
                                                          severity, next steps
                                                                |
                                                       [ hunt_queries.sql ]
                                                       SQL hunting over the logs
```

## Stack (all free)

| Layer | Tool |
|-------|------|
| Endpoint telemetry | Sysmon (SwiftOnSecurity config) |
| SIEM / XDR | Wazuh (single-node) |
| Attack simulation | Atomic Red Team (MITRE ATT&CK) |
| AI triage | Python + Ollama (local LLM, e.g., Llama 3.1) |
| Log analysis | SQLite + SQL |

## Repo layout

```
detection-rules/   custom Wazuh rules (local_rules.xml)
automation/        ai_triage.py, prompt_injection_test.py, sample_alert.json
analysis/          hunt_queries.sql
docs/              screenshots, ATT&CK Navigator export, write-up
```

## Quick start

```bash
# 1. Local LLM (free, runs offline - good for data privacy)
ollama pull llama3.1
ollama serve

# 2. Python deps
pip install -r automation/requirements.txt

# 3. Triage a sample alert
python automation/ai_triage.py automation/sample_alert.json

# 4. See the AI-security demo (prompt injection + defense)
python automation/prompt_injection_test.py
```

## Detections (fill in as you build)

| MITRE ID | Technique | Data source | Custom rule | Result |
|----------|-----------|-------------|-------------|--------|
| T1059.001 | Encoded PowerShell | Sysmon EID 1 | rule 100210 | detected |
| T1547.001 | Registry Run key persistence | Sysmon EID 13 | rule 100211 | detected |
| T1003 | LSASS access (cred dumping) | Sysmon EID 10 | rule 100212 | detected |
| ... | ... | ... | ... | ... |

## AI triage assistant

`ai_triage.py` sends a Wazuh alert to a locally-hosted LLM and returns a structured triage: plain-English summary, likely MITRE ATT&CK technique, severity, indicators, and suggested next steps — turning raw alerts into analyst-ready notes and cutting manual effort.

## AI security: prompt-injection hardening

Alert fields are attacker-influenced data. `prompt_injection_test.py` shows what happens when an attacker plants instructions in a log field, and how the assistant defends: alert content is wrapped as untrusted **data** (never instructions), suspicious instruction-like text is sanitised, and the system prompt forbids following embedded commands. *(Document your before/after finding here.)*

## Disclaimer

For education and defensive research in an isolated lab only. Run attack simulations only against systems you own.
