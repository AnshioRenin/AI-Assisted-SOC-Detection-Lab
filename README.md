# AI-Assisted SOC Detection Lab

A home Security Operations Center that detects, investigates, and responds to simulated attacks — with an **LLM-powered triage assistant** layered on top, and that assistant **hardened against prompt-injection**. The project combines hands-on **detection engineering** with applied **AI security**.

> **Status (building in public):** Phase 1 complete — the AI triage assistant runs locally and triages alerts. Detection lab (Wazuh + Sysmon + Atomic Red Team) in progress. Follow the build at [my portfolio](https://anshio-renin.vercel.app/).

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
| AI triage | Python + Ollama (local LLM: `llama3.2:3b`) |
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
ollama pull llama3.2:3b
# Ollama runs in the background automatically (system tray on Windows)

# 2. Python deps
pip install -r automation/requirements.txt

# 3. Triage a sample alert
python automation/ai_triage.py automation/sample_alert.json

# 4. See the AI-security demo (prompt injection + defense)
python automation/prompt_injection_test.py
```

## Detections (template — fill in with your own results in Phase 3)

| MITRE ID | Technique | Data source | Custom rule | Result |
|----------|-----------|-------------|-------------|--------|
| T1059.001 | Command & Scripting Interpreter: PowerShell | Sysmon EID 1 | rule 100210 | _to test_ |
| T1547.001 | Registry Run Key persistence | Sysmon EID 13 | rule 100211 | _to test_ |
| T1003 | LSASS access (credential dumping) | Sysmon EID 10 | rule 100212 | _to test_ |

## AI triage assistant

`ai_triage.py` sends a Wazuh alert to a locally-hosted LLM and returns a structured triage: plain-English summary, likely MITRE ATT&CK technique, severity, indicators, and suggested next steps — turning raw alerts into analyst-ready notes and cutting manual effort.

**Example output** (sample alert — encoded PowerShell):

```json
{
  "summary": "Encoded PowerShell execution detected on endpoint WIN-ENDPOINT-01",
  "mitre_attack": { "id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell" },
  "severity": "High",
  "indicators": ["powershell.exe -enc ...", "powershell.exe", "winword.exe"],
  "next_steps": ["Investigate the encoded payload", "Verify why winword.exe spawned PowerShell", "Check for follow-on network activity"]
}
```

## Findings & Limitations (AI reliability)

A key, deliberate finding from building this:

- **Small local models can hallucinate.** On the `llama3.2:3b` model, the assistant correctly identified the technique **ID** (`T1059.001`) but returned an **incorrect technique name** ("Exfiltration to Network via Other Protocol" instead of "Command and Scripting Interpreter: PowerShell"). The ID was right; the model invented a plausible-but-wrong label.
- **Takeaway:** an LLM triage assistant should *accelerate* an analyst, never *replace* one. Outputs must be validated — this is why AI-assisted SOC tooling keeps a human in the loop.
- **Mitigation applied:** the technique name is resolved from an authoritative MITRE ATT&CK ID→name lookup rather than trusted from the model, and the prompt constrains the model to output the ID plus rationale only. (Using a larger model, e.g. `llama3.1` 8B, also reduces hallucination at the cost of speed/VRAM.)

## AI security: prompt-injection hardening

Alert fields are attacker-influenced data. `prompt_injection_test.py` shows what happens when an attacker plants instructions in a log field, and how the assistant defends: alert content is wrapped as untrusted **data** (never instructions), suspicious instruction-like text is sanitised, and the system prompt forbids following embedded commands. Document your before/after result here.

## Disclaimer

For education and defensive research in an isolated lab only. Run attack simulations only against systems you own.
