# RUBIN Private Phase Incident Response v1.1 (Operator-run)

Status: OPERATIONAL RUNBOOK (non-consensus)  
Date: 2026-02-16  
Audience: controller + invited operators  
Scope: private mainnet phase only

Goal: prevent rumor-driven splits and reduce time-to-recovery during incidents.

## 1) Single incident channel (required)

Requirement:
- There MUST be exactly one primary incident channel for the private phase.
- Ownership MUST be explicit (primary + backup).
- Escalation rules MUST be defined and testable.

Minimum format:
- Primary: `ops@<domain>` (mailing list) **and** one real-time channel (e.g., `Slack: #rubin-private-incident`).
- Owner: Controller (primary) + one named backup (operator lead).
- SLA:
  - Acknowledge within 15 minutes.
  - Status update at least every 30 minutes until resolved.

Publication locus:
- The channel identifier(s) and owner roster are distributed out-of-band to invited participants and referenced in the private phase checklist.

## 2) Rollback policy for node binaries (required)

Purpose: fast revert when a release causes instability without changing consensus.

Definitions:
- `APPROVED_RELEASES`: a pinned list of GitHub Release tags allowed in the private phase.
- `CURRENT_RELEASE`: the tag currently in use.
- `ROLLBACK_RELEASE`: the last-known-good tag.

Trigger criteria (any one):
- Node crash loop rate > 5% across participants.
- Consensus safety concern reported by ≥2 independent operators.
- Detected network partition attributable to release behavior.

Authority:
- Controller authorizes rollback.
- Operators execute rollback locally and confirm completion in incident channel.

Operator procedure (minimal):
1. Stop node service.
2. Install binaries for `ROLLBACK_RELEASE` (from GitHub Release artifacts).
3. Restart node service.
4. Confirm:
   - `chain_id_hex` pinned value unchanged,
   - node reaches tip,
   - no new error spikes in logs/metrics.

## 3) “Halt communications” template (required)

Purpose: stop uncontrolled announcements while incident triage runs.

Authorized approvers:
- Controller only.

Recipients:
- All invited operators.

Template (copy/paste):

> SUBJECT: RUBIN private phase — communication hold  
> Time (UTC): <YYYY-MM-DDTHH:MM:SSZ>  
> Trigger: <what happened, 1 sentence>  
> Action required: Do not publish updates externally. Do not change configs/releases unless explicitly instructed by Controller.  
> Status cadence: Next update in <N> minutes in the incident channel.  
> Clear condition: Controller will explicitly announce “communication hold lifted”.  

