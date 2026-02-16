# RUBIN Private Mainnet Phase v1.1 (Pre-Public Launch)

Status: OPERATIONAL RUNBOOK (non-consensus)  
Date: 2026-02-16  
Audience: controller + invited operators (exchanges, infra providers, large participants)  
Scope: run mainnet privately before public announcement, without changing consensus.

This document defines operational controls for a **private participation phase** on a permissionless protocol.
It does not modify consensus validity rules in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

## 0. Design intent (why this phase exists)

Goals:
1. Validate stability of node releases and operational playbooks under real conditions.
2. Run conformance parity checks across independent implementations.
3. Onboard large operators (DEX/CEX/market makers/infra providers) before public launch.

Non-goals:
- This is not an attempt to “make the protocol permissioned”. PoW/UTXO rules remain permissionless.
- This phase relies on **bootstrap and network access controls**, not on-chain gating.

## 1. Core invariant: chain identity must be pinned

RUBIN network identity is anchored by genesis bytes → `chain_id` (CANONICAL v1.1 §1.1).

Private phase rule:
- Every participant MUST pin the expected `chain_id_hex` and refuse to connect to a chain with a different `chain_id_hex`.
- The controller distributes the canonical chain-instance profile out-of-band to invited participants only.

Consequences:
- A third party can fork the repo and run a different network, but it will have a different `chain_id_hex`.
- If the private mainnet genesis bytes leak, anyone can join (permissionless). Mitigations are in §2.

## 2. Network access controls (how “private” is enforced)

Privacy is achieved via **limited peer discovery** and **edge controls**:

### 2.1 Bootstrap controls (required)

Controller maintains a private list of bootstrap endpoints:
- static IP allowlist (preferred),
- or private DNS with access control.

Participants:
- MUST configure outbound peers to the provided bootstrap list.
- MUST disable public peer discovery features unless explicitly approved.

### 2.2 Inbound access controls (required)

Operators SHOULD implement:
- firewall allowlists on P2P port (only known peers),
- per-peer connection caps + bandwidth caps,
- aggressive stale/unknown peer eviction.

### 2.3 “Don’t leak the network” rules (required)

During the private phase:
- Do not publish: bootstrap IPs, DNS seeds, node configs, or the mainnet profile file.
- Do not expose P2P ports broadly on the public Internet.
- Do not post logs that include peer lists or network identifiers.

## 3. Genesis secrecy vs. auditability

Tradeoff:
- Keeping genesis/profile private reduces unsolicited joins, but reduces public verifiability.

Rule:
- Treat the private phase as **pre-public**: no “public mainnet” claims until the signed launch manifest is published.

## 4. Operational minimums for invited participants

Each invited operator MUST:
1. Run at least one full node and one observer instance.
2. Keep clocks synchronized (NTP).
3. Implement basic DoS hygiene (bandwidth limits, connection caps, log rotation).
4. Verify the pinned `chain_id_hex` on startup and on re-connect.

Recommended:
- Run both clients (Rust + Go) if feasible to increase diversity.

## 5. Conformance and release gates

Private phase is used to enforce deterministic behavior before public launch:

Required gates:
- `python3 conformance/runner/run_cv_sighash.py` must PASS on release artifacts.
- Any new protocol-affecting change requires an explicit controller announcement and a new release build.

## 6. Incident handling during private phase

Controller MUST define:
- a single incident channel,
- a rollback policy for node binaries,
- a “halt communications” template to avoid rumor-driven chain splits.

## 7. Transition to public launch (controller checklist)

NUЖНО ОДОБРЕНИЕ КОНТРОЛЕРА:
You authorize the transition only when all are true:

1. Genesis is final and reproducible (two independent derivations match).
2. Signed launch manifest is ready (`operational/RUBIN_MAINNET_GENESIS_CEREMONY_v1.1.md`).
3. At least N independent operators confirm pinned `chain_id_hex` and stable operation over T days.
4. Public bootstrap plan is ready (DNS seeds, docs, monitoring).

Public launch action:
- Publish a GitHub Release containing the signed launch manifest + mainnet profile + exact `chain_id_hex`.

## 8. What to call things (communication hygiene)

During private phase, use:
- “private mainnet phase” / “pre-public mainnet”

Avoid:
- “mainnet is live” (public claim) until the signed manifest is published.

