# IMPLEMENTATION_ROADMAP (local, non-repo)

This file is deliberately ignored by git (`.gitignore`) and is a **local controller/operator planning artifact**.
It MUST NOT be published before genesis.

Date: 2026-02-16

## Phase model (0 → 3)

### Phase 0 — Determinism foundation (spec → executable checks)

Goal: turn the spec into **deterministic, cross-client executable gates** before we build “a node”.

Scope (minimum):
- Parsing/serialization: CompactSize, Tx, Witness, BlockHeader, Block.
- Deterministic txid/wtxid, sighash v1, error codes.
- UTXO rules (value conservation, coinbase rules as applicable to vectors).
- VERSION_BITS state machine (CV-DEP) semantics.
- Conformance runners: a runner exists for each CV family and produces a single PASS/FAIL with a stable summary.

Definition of Done (DoD):
1. Runners exist and run locally:
   - `CV-PARSE`, `CV-BIND`, `CV-UTXO`, `CV-DEP`, `CV-BLOCK`, `CV-REORG`, `CV-SIGHASH`.
2. Rust and Go both PASS the same fixtures with identical:
   - txid/sighash outputs,
   - accept/reject outcomes,
   - error codes.
3. Spec refs are stable (no missing files referenced from `README.md` / `SPEC.md` / CANONICAL).
4. “Policy vs consensus” boundaries are explicit in docs (node policy defaults are non-consensus).

Non-goals:
- P2P networking beyond minimal skeleton.
- Mempool economics tuning beyond documented defaults.
- Mainnet genesis ceremony (Phase 3).

### Phase 1 — Node core (headers + blocks + UTXO)

Goal: a validating node core that can follow the best chain and apply blocks deterministically.

DoD:
- Header-chain validation (PoW, target, retarget, timestamps).
- Block validation + ApplyBlock updates UTXO set.
- Reorg handling passes `CV-REORG`.
- Subsidy/coinbase constraints implemented per canonical notes and vectors.

### Phase 2 — Networking + sync (P2P baseline)

Goal: minimal but robust P2P for header sync and block/tx relay. Key lifecycle for sequencer/validator nodes.

DoD:
- Handshake + envelope implemented per `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md`.
- Header sync works against a reference peer in a private testnet environment.
- Basic DoS controls (caps/rate limits) are wired to operator policy config.
- Key lifecycle: `GenerateMLDSA87Key()`, `GenerateSLHDSAKey()`, `SignMLDSA87()`, `SignSLHDSA()` implemented in wolfcrypt provider.
- Encrypted keystore: load/save key from file or HSM slot (KeyWrap/KeyUnwrap already present).
- Key rotation and revocation runbook documented in `operational/`.

### Phase 3 — Private mainnet + genesis ceremony

Goal: controller-signed genesis and restricted initial rollout among verified participants.

DoD (high level):
- Genesis ceremony dry-run completed (signed manifest verification is reproducible).
- Private mainnet phase runbook executed with allowlisted peers.
- Public release artifacts are published only via GitHub Releases (genesis bytes + signed manifest).

## TODO — RETL bond policy workstream (non-consensus)

Context: In `spec/RUBIN_L1_CANONICAL_v1.1.md` the RETL bond is an application/policy construct. L1 consensus does not validate bond amount or enforce slashing.

Tasks:
1. Define `MIN_RETL_BOND` defaults by network profile (public vs corporate) and how it is configured/overridden.
2. Define "active bond" lifecycle:
   - creation, renewal/rotation, withdrawal/unbonding,
   - timeouts/grace periods,
   - how "no active bond => domain inactive" is detected operationally.
3. Define enforcement points (L2/gateway/indexers):
   - who checks bond existence/size,
   - which actions are blocked without an active bond (publish batch, withdrawals finalization, bridge settlement, etc.).
4. Define slashing model (if required):
   - slashable offenses (equivocation, invalid withdrawals_root, fraud proof failure, etc.),
   - proof format and publication channel (e.g. via `CORE_ANCHOR` commitments),
   - who can submit proofs and who receives slashed funds.
5. Add non-consensus test plan:
   - policy-profile fixtures (accept/reject reasons),
   - bridge/gateway runbook scenarios.

## TODO — L2 capabilities workstream (design + implementation, mostly non-consensus)

Goal: define and build the L2 surface area (DEX/bridges/channels) that the market expects, while keeping L1 consensus minimal and stable.

Tasks (high level):
1. RETL domains as the canonical L2 container:
   - define domain lifecycle (create/activate/deactivate/rotate sequencer key),
   - specify batch production rules and reorg tolerance expectations,
   - define data availability strategy (what is anchored vs what is off-chain distributed).
2. Sequencer / proposer implementation:
   - reference sequencer for devnet (batch builder + signer),
   - deterministic serialization and signing (CNSA 2.0 aligned suites where applicable),
   - operational controls (rate limits, backpressure, reorg handling).
3. Deposits and withdrawals (bridge-like semantics):
   - canonical deposit parsing rules from L1 (UTXO patterns and covenant types),
   - withdrawals model (`withdrawals_root` semantics, inclusion proofs, challenge windows if any),
   - finality parameters aligned with `K_CONFIRM_BRIDGE`.
4. Bridge taxonomy (decide per product requirement):
   - HTLC-based atomic swaps (minimal trust, limited UX),
   - committee/relayer bridges (operational trust, better UX),
   - light-client/proof bridges (highest assurance, highest complexity).
5. DEX layer decision:
   - choose execution environment (EVM-like, custom VM, or app-specific rollup),
   - define transaction format, fees, and state model for the chosen L2,
   - define how L2 state commitments map into RETL batch fields.
6. Payment/channel network (Lightning-like) feasibility:
   - channel protocol selection (revocation-style vs alternative),
   - watchtower / monitoring requirements,
   - HTLC usage patterns (V1 vs V2) and routing/invoice format.
7. Indexing and interoperability:
   - canonical event indexing spec for anchors/RETL commitments,
   - reference indexer + API for wallets/bridges/DEX frontends,
   - schema/versioning and replay protection.
8. Security + economics:
   - threat model for L2 sequencer/relayers/bridges,
   - DoS constraints (policy profiles) and fee market tuning for L2-related tx patterns,
   - incident runbooks (halt/rollback, key compromise, forced exit).
9. Conformance and test harnesses (non-consensus + integration):
   - integration test plan (L1 <-> L2 deposits/withdrawals),
   - fuzzing targets for batch parsers/commitment verifiers,
   - cross-client compatibility checks for any L2-critical serialization.

## TODO — Data Availability (DA) layer options via RETL (design work)

Context: v1.1 treats `CORE_ANCHOR` as a commitment channel, not a DA layer. L2 calldata availability must be provided
externally or by a separate mechanism.

Options to evaluate:
1. External DA + on-chain commitments (baseline):
   - RETL publishes `tx_data_root` (and related roots) on L1; calldata lives in an external DA network.
   - Define retrieval protocol, retention windows, and availability attestations.
2. RETL-integrated DA committee (semi-trusted DA):
   - A designated committee attests to data availability; L1 anchors commitments plus committee signatures.
   - Define committee membership, rotation, slashing model (policy or future consensus), and auditability.
3. On-chain DA expansion (consensus upgrade):
   - Increase `MAX_ANCHOR_BYTES_PER_BLOCK` and/or introduce a new covenant/channel intended for DA.
   - Requires VERSION_BITS deployment, re-baselined conformance, and explicit node resource requirements.
4. Hybrid: small on-chain blobs for forced-exit / withdrawals only:
   - Keep full calldata off-chain, but allow critical paths (forced exits, proofs) to be published on-chain within bounded bytes.

Deliverables:
1. Threat model + trust assumptions per option (censorship, withholding, equivocation).
2. Concrete RETL batch format changes (if any) and client requirements.
3. Ops requirements: storage, bandwidth, pruning, light-client impact.
4. Go/no-go recommendation for public mainnet vs corporate networks.
