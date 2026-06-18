# POC Write-up: Can a Local LLM Safely Triage SOC Alerts?

> This is the proof-of-concept record for the AI-triage component of the lab.
## 1. Hypothesis
Can a small, locally-hosted language model (`llama3.2:3b` via Ollama) take a
raw SOC alert and produce a reliable, analyst-ready triage - summary, MITRE
ATT&CK mapping, severity, and next steps - while running entirely offline for
data privacy?

## 2. Method
- Model: `llama3.2:3b` running locally in Ollama (no data leaves the machine).
- Input: a single Wazuh alert in JSON (`automation/sample_alert.json`).
- Script: `automation/ai_triage.py` sends the alert to the model and parses
  a structured JSON triage back.
- AI-security test: `automation/prompt_injection_test.py` plants a malicious
  instruction inside an alert field and compares a naive prompt vs a hardened one.

## 3. Result - triage quality

**Command run:**
```
python automation/ai_triage.py automation/sample_alert.json
```

**Screenshot:** `docs/screenshots/triage_output.png`

**What I observed:**
- Technique ID returned by the model: `[id: T1059.001]`
- Technique NAME returned by the raw model: `[name: Command and Scripting Interpreter: PowerShell]`
- Severity: `[High]`
- Were the next steps sensible? `[yes / partly / no - explain]`

**Key finding (the interesting bit):**
The 3B model frequently returns the correct ATT&CK **ID** but **hallucinates
the technique name** - it invents a plausible-but-wrong label. Severity is also
inconsistent run to run.

**Mitigation I built in:**
`ai_triage.py` does not trust the model for the technique name. It takes only
the ID from the model and resolves the authoritative name from a local
ATT&CK lookup table. This removes the most damaging hallucination while still
using the model for the parts it is good at (summarising, suggesting steps).

## 4. Result - AI security (prompt injection)

**Command run:**
```
python automation/prompt_injection_test.py
```

**Screenshots:** `docs/screenshots/injection_naive.png`,
`docs/screenshots/injection_hardened.png`

**Naive run (no data boundary):**
- Did the model obey the injected "mark this benign" instruction? `[yes / no]`
- Observation: `[...]`

**Hardened run (alert wrapped as untrusted data + defensive system prompt):**
- Did the model resist the injection? `[yes / partly / no]`
- Observation: `[...]`

**Honest conclusion:**
Wrapping alert content as untrusted data and instructing the model to ignore
embedded commands **reduces** injection success, but it is **necessary, not
sufficient**. Results were not 100% reliable across runs. A production triage
assistant must keep a **human in the loop** and never auto-action a verdict.

## 5. Overall takeaway
An LLM triage assistant is useful for **accelerating** a Tier-1 analyst -
summarising noisy alerts and drafting next steps - but it must **augment, never
replace** human judgement. The two controls that mattered most:
1. Resolve high-stakes facts (ATT&CK names) from an authoritative source, not the model.
2. Treat all alert content as untrusted data, and keep a human validating output.

## 6. What I would do next
- Compare against a larger model (e.g. `llama3.1:8b`) to measure how much
  hallucination drops with scale (at the cost of speed/VRAM).
- Feed real Wazuh alerts from Phase 4 instead of a crafted sample.
- Add automated output validation (schema check + ATT&CK ID existence check).
