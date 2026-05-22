# TalonResponse

**Local-First Incident Response Orchestration & Cryptographic Forensic Triage Engine**

The grand finale - the tool that closes the loop. When the sensors scream and the chains escalate, TalonResponse executes the containment, signs the isolation payload, and seals the evidence.

Built by Rayyan Umair - *Technology evolves quickly. Responsibility does not.*

---

# What it does

TalonResponse sits at the terminal end of the NetRaptor pipeline. It subscribes to critical alerts from SIEMulate and AD-Audit over ZeroMQ, matches them against a YAML playbook library, executes automated containment actions, and generates cryptographically verified forensic case files.

Every incident becomes a **sealed, immutable case file**:

### Instead of an unacted alert:
CRITICAL: AD-002 - jsmith added to Domain Admins at 10:22 UTC

### You get:

* playbook matched and executed within seconds
* account disabled via AD-Audit API callback
* Kerberos tickets revoked domain-wide
* HMAC-signed isolation payload dispatched to endpoint agent
* SHA-256 hashed evidence chain locked
* immutable Markdown case file written to disk
* full timeline from alert to containment with delta timing

No manual triage. No alert fatigue. No uncontained incidents.

---

# System Overview

TalonResponse is a single-process orchestration engine with four internal layers:

## Orchestrator

The pipeline state loop.

Handles:

* ZeroMQ subscriber (receives critical alerts from SIEMulate and AD-Audit)
* inbound alert parsing and validation
* playbook matching via detection code
* action dispatch coordination
* case file lifecycle management
* WebSocket broadcast of case state changes

## Playbook Engine

The automation routing layer.

Handles:

* YAML playbook file loading and hot-reload
* detection code to action mapping
* action parameter resolution
* playbook versioning and metadata

## Forensic Triage Engine

The evidence compilation layer.

Handles:

* volatile state snapshot simulation (process list, network connections)
* SHA-256 hash computation for all captured artifacts
* evidence integrity chain construction
* immutable Markdown case file serialisation
* DuckDB case index for queryable history

## Integrations

The defensive callback layer.

Handles:

* AD-Audit API callbacks (account disable, ticket revocation)
* Go agent client (HMAC-signed isolation payload dispatch)
* SIEMulate status updates

---

# Core Concept

TalonResponse does NOT treat alerts as notifications.

It treats them as:

> **executable triggers that demand a verified, timed, and signed response**

---

# Playbook Schema

Every playbook entry maps a detection code to a sequence of actions:

```yaml
playbooks:
  - id: "PLAY-001"
    name: "Critical AD Domain Protection"
    trigger_source: "AD-Audit"
    match_detections:
      - "AD-002"
      - "AD-004"
    actions:
      - type: "identity_lockdown"
        target: "actor_username"
        parameters:
          disable_account: true
          revoke_active_kerberos_tickets: true
      - type: "generate_forensic_case"
        severity: "Critical"
```

---

# Case File Format

Every contained incident produces an immutable Markdown case file:

data/cases/CASE-2026-A1B2.md

Containing:

* attack fingerprint verification
* automated containment timeline with per-step timestamps
* evidence integrity chain with SHA-256 hashes
* containment delta timing (seconds from alert to containment)

---

# Quick Start

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Configure

```bash
cp .env.example .env
# Set ISOLATION_SIGNING_KEY to a secure random string
```

## 3. Start TalonResponse

```bash
python main.py
```

Runs:

* FastAPI server (default: http://0.0.0.0:8005)
* ZeroMQ subscriber on tcp://127.0.0.1:5556
* Orchestrator pipeline
* WebSocket stream at ws://localhost:8005/ws/cases

---

# The Five Action Types

## identity_lockdown

Calls back to AD-Audit to disable the actor account and revoke all active Kerberos tickets. The fastest path from detection to containment.

## host_isolation

Dispatches an HMAC-signed isolation payload to the Go endpoint agent. The agent applies firewall rules isolating the host from all subnets except the management IP.

## generate_forensic_case

Triggers the forensic triage engine to capture volatile state, hash all artifacts, and write the immutable case file to disk.

## notify_siemulate

Posts a case status update to SIEMulate so the attack chain record reflects the containment outcome.

## log_evidence

Records a specific evidence artifact to the active case file with timestamp and hash.

---

# Forensic Case File

Every case file is written once and never modified. The file name includes the case ID and is treated as an immutable forensic artifact.

Evidence integrity is verified via SHA-256 hashes of all captured artifacts. The hash chain is included in the case file so any tampering is immediately detectable.

---

# ZeroMQ Integration

TalonResponse subscribes to the same ZMQ channel used by the NetRaptor pipeline:

tcp://127.0.0.1:5556

This matches the SIEMulate and AD-Audit publisher addresses. TalonResponse listens for critical alert frames and processes them through the orchestrator in real time.

---

# AI Layer (Optional)

AI is NOT required.

When enabled it acts as:

> an incident response analyst assistant - not a decision maker

It can:

* summarise the incident in plain English
* suggest remediation steps beyond the playbook
* generate executive incident reports
* explain the attack chain context

Supported providers:

* Local LLMs (Ollama / llama.cpp)
* OpenAI, Gemini, Groq
* Disabled mode (fully offline)

---

# NetRaptor Ecosystem

TalonResponse is the **terminal operational layer** of the NetRaptor platform.

It receives from:

* **SIEMulate** - detection intelligence and attack chains (port 8002)
* **AD-Audit** - identity compromise alerts (port 8004)

It calls back to:

* **AD-Audit** - account lockdown directives (port 8004)
* **SIEMulate** - case status updates (port 8002)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

# Hard Constraints

* Orchestrator processes alerts only - no detection logic
* Playbook engine routes only - no action execution
* Forensic triage writes only - no reads after case creation
* Case files are immutable - never modified after creation
* All isolation payloads are HMAC-signed before dispatch
* UTC is mandatory everywhere
* DuckDB is the case index - Markdown files are the forensic artifacts

---

# Legal Notice

TalonResponse is a defensive cybersecurity tool.

Only use it on systems and networks you own or are explicitly authorized to monitor and respond to.

Automated account disabling and host isolation are destructive operations. Misconfiguration can cause service outages. The author accepts no liability for misuse or misconfiguration.