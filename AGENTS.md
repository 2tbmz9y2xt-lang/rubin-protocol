# AGENTS.md

This repository contains the RUBIN protocol implementation and related verification tooling.

Scope: this `AGENTS.md` is repository-visible guidance for the Codex GitHub/cloud PR review bot and Codex review tasks. It is not a general implementation runbook. Non-review implementation agents must not treat the review-only rules, four-pass review protocol, or clean-review output format as instructions to refuse edits, spawn reviewers, or change their implementation workflow. For explicit implementation, fix, CI, merge, release, or documentation-authoring tasks, follow the direct user request, issue/PR contract, repository scripts, and applicable implementation profiles.

Treat review requests as merge-safety reviews, not summaries.

## Review guidelines

These guidelines apply to review requests such as `@codex review`, Codex GitHub review, Codex cloud PR review, and explicit local "review this PR/diff" tasks. They do not apply to explicit implementation requests such as "fix", "address feedback", "edit", "commit", "push", or "open a PR".

### Review-only mode

When performing a review, do not create, edit, delete, stage, commit, push, or open pull requests. Review output only.

This rule applies to review requests. It does not apply to explicit implementation tasks.

### PR-head discipline

When asked to review a GitHub pull request, do not review `main` alone. Fetch or otherwise inspect the PR head and compare it against the base branch. If the PR number, PR head, or base ref is unavailable, return `INSUFFICIENT_EVIDENCE` for the PR review instead of reviewing an unrelated checkout.

Codex review must prioritize P0/P1 merge blockers. Do not report style, wording, or speculative issues unless this file explicitly makes them safety-relevant. Report safety-relevant P2 observations separately when they involve lock contention, avoidable large allocations, validation-after-copy, aliasing/ownership, missing negative tests, or missing review evidence.

Before saying there are no major issues:

- Treat the PR body, commit messages, author comments, and prior bot comments as claims, not evidence.
- Inspect the changed files, direct callers/callees, touched tests, relevant fixtures, and relevant spec/policy artifacts.
- Inspect unresolved GitHub review threads when available.
- Run the repository checks relevant to the changed files. If safety-relevant checks cannot run in the Codex cloud environment, report `INSUFFICIENT_EVIDENCE` instead of a clean review.
- A clean review must include the evidence used: files inspected and commands run.

For non-trivial PRs, perform four independent review passes before final verdict. Use separate subagents or versions when the environment supports them; otherwise perform the passes sequentially and keep their evidence separate:

1. Correctness and invariants: changed behavior, caller/callee contracts, error paths, state mutation order, persistent state effects.
2. Security, DoS, and runtime safety: untrusted input, validation-before-copy/mutation, resource bounds, aliasing/ownership, locks, races, shutdown behavior.
3. Consensus, parity, and specs: Go/Rust parity, conformance fixtures, generated artifacts, canonical/spec/policy boundaries, formal-claim scope.
4. Tests and CI evidence: changed tests, missing negative cases, commands run, CI/check status, mismatch between PR claims and evidence.

The final review must merge findings from all four passes and state which pass produced each finding or evidence gap.

Severity policy:

- P0: concrete path to invalid block/transaction acceptance, valid block/transaction rejection that can split clients, fund loss, private key exposure, or bypass of required signature/authorization checks.
- P1: concrete path to merge-unsafe behavior in consensus, crypto, P2P relay, storage, runtime lifecycle, policy guardrails, governance gates, or test/fixture coverage. Missing required evidence in safety-sensitive code is P1.
- P2: non-blocking but safety-adjacent risk, including lock contention on large data, avoidable large allocation/copy on error paths, unclear ownership contracts, missing negative tests for non-consensus behavior, or maintainability that can reasonably hide a future P0/P1. Report these in a separate "Non-blocking observations" section, not as merge blockers.
- Do not raise style-only findings as Codex review findings.

Every finding must include:

1. the exact changed code or artifact that causes the issue;
2. the failure path from input/state to bad outcome;
3. the affected invariant;
4. the required fix or missing evidence.

Do not accept broad claims like "tests pass", "covered by CI", "formal verification complete", or "policy-only" without checking the actual files and commands.

## Source-of-truth precedence

Use this precedence when reviewing conflicts:

1. `spec/RUBIN_L1_CANONICAL.md` - consensus validity.
2. `spec/RUBIN_COMPACT_BLOCKS.md` - normative P2P relay behavior.
3. `spec/RUBIN_NETWORK_PARAMS.md` - derived reference summary; CANONICAL wins on conflict.
4. AUX, policy, operational, audit, roadmap, and governance documents.
5. PR narrative and comments.

## Spec repository discovery

Canonical spec files may be absent from this public protocol checkout. Before requiring private specs, read `SPEC_LOCATION.md` when present.

The canonical specification repository is `2tbmz9y2xt-lang/rubin-spec`, default branch `main`. Local developer checkouts may be named `rubin-spec` or `rubin-spec-private`; verify the remote origin before treating them as authoritative.

When a review depends on normative specs, search in this order:

1. `SPEC_LOCATION.md` in this repository, which defines the current cross-repo convention.
2. `RUBIN_SPEC_ROOT`, when set. Treat it as the spec root only after verifying it contains the required spec files.
3. An explicit tool `--spec-root` value, when the task or script provides one.
4. This repository, if a current `spec/` directory exists in the PR/base checkout.
5. A sibling checkout whose remote is `github.com/2tbmz9y2xt-lang/rubin-spec`, commonly `../rubin-spec` or `../rubin-spec-private`.
6. The GitHub repository `2tbmz9y2xt-lang/rubin-spec` at `origin/main`, if the Codex environment has access.

Required normative files by surface:

- Consensus validity: `spec/RUBIN_L1_CANONICAL.md`
- Compact-block / P2P relay behavior: `spec/RUBIN_COMPACT_BLOCKS.md`
- Derived network parameters: `spec/RUBIN_NETWORK_PARAMS.md`
- Pinned section hashes: `spec/SECTION_HASHES.json`
- Controller/governance evidence: `spec/CONTROLLER_GOVERNANCE.md`, `spec/CONTROLLER_REGISTRY.json`, `spec/DEPLOYMENT_DESCRIPTOR.json`

Do not use archived snapshots, copied artifacts, stale security-scan snapshots, or local notes as normative spec evidence unless the user explicitly identifies them as the target artifact under review.

For every spec-dependent finding or clean verdict, record the spec source used: repository, branch/ref, commit SHA, and file path. If a required spec file is not available in the Codex environment, report `INSUFFICIENT_EVIDENCE` only for the safety surface whose correctness depends on that unavailable spec. Continue reviewing code-level invariants that can be verified from the public repository.

## Required checks

Select the narrowest required check set based on changed files and safety surface. Do not require full baseline checks for every PR. If a narrower check passes but a broader required check cannot run, report the exact residual evidence gap instead of replacing the whole review with a generic `INSUFFICIENT_EVIDENCE`.

Run commands through `scripts/dev-env.sh` when available. If `scripts/dev-env.sh` is absent or broken, run the closest direct command and report the deviation.

Full baseline checks for consensus, conformance, spec, generated artifact, formal, cross-client, or release-gate changes:

```bash
# Set RUBIN_SPEC_ROOT per SPEC_LOCATION.md before running spec-dependent checks.
RUBIN_SPEC_ROOT=/path/to/private/spec scripts/dev-env.sh -- python3 tools/check_conformance_ids.py
RUBIN_SPEC_ROOT=/path/to/private/spec scripts/dev-env.sh -- node scripts/check-spec-invariants.mjs
RUBIN_SPEC_ROOT=/path/to/private/spec scripts/dev-env.sh -- node scripts/check-section-hashes.mjs
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
```

For spec-dependent checks, first resolve the spec root through `SPEC_LOCATION.md`, `RUBIN_SPEC_ROOT`, or `--spec-root`. Do not list or run Python spec-repo-only checks such as `tools/check_readme_index.py` or `tools/check_section_hashes.py` as protocol-repo baseline commands unless executing from a current spec repository root with `spec/README.md` and `spec/SECTION_HASHES.json`.

Formal/refinement changes or any PR making formal claims:

```bash
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
scripts/dev-env.sh -- python3 tools/check_formal_coverage.py
scripts/dev-env.sh -- python3 tools/check_formal_risk_gate.py --profile phase0
scripts/dev-env.sh -- python3 tools/check_formal_refinement_bridge.py
scripts/dev-env.sh -- python3 tools/check_formal_claims_lint.py
```

Conformance fixture or runner changes:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- python3 tools/gen_conformance_matrix.py --check
scripts/dev-env.sh -- python3 tools/check_conformance_edge_pack.py
scripts/dev-env.sh -- python3 tools/check_conformance_fixtures_policy.py
```

Go-only changes under `clients/go/`:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
```

For narrowly scoped Go PRs, also run the most specific package/test command first and report both targeted and full-package evidence when feasible.

Rust-only changes under `clients/rust/`:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
```

Crypto/backend changes:

```bash
scripts/dev-env.sh -- python3 tools/check_crypto_backend_policy.py
scripts/dev-env.sh -- scripts/crypto/openssl/fips-preflight.sh
RUBIN_OPENSSL_FIPS_MODE=only scripts/dev-env.sh -- scripts/crypto/openssl/fips-preflight.sh
```

If a check is not discoverable, unavailable, or cannot run because the Codex cloud environment lacks Go, Rust, Lean, OpenSSL, Node, Python, `fd`, or repository dependencies, report `INSUFFICIENT_EVIDENCE` for the affected safety surface.

If GitHub review threads, PR body, changed-file list, or CI/check logs are unavailable, state that explicitly. Do not use unavailable GitHub metadata as a reason to ignore concrete code findings that are visible in the diff.

## Consensus-critical review rules

A PR is consensus-impacting if it changes, directly or indirectly:

- valid/invalid status for transactions or blocks;
- transaction/block wire format, parse rules, TXID/WTXID, sighash, Merkle roots, witness commitment, DA fields, or genesis identity;
- validation order, error-code priority, covenant semantics, UTXO state transitions, replay checks, value conservation, subsidy, timestamps, difficulty, fork choice, or suite authorization;
- consensus constants, limits, activation boundaries, deployment descriptors, or `SECTION_HASHES.json`.

For such PRs, verify the release train:

1. spec update and `SECTION_HASHES` update when pinned sections changed;
2. conformance fixture update that machine-encodes the behavior;
3. Go reference implementation update;
4. Rust parity update;
5. full conformance bundle pass;
6. controller approval evidence when required.

Flag P1 if a consensus-impacting PR skips any required stage or lacks controller approval evidence.

## RUBIN-specific invariants to check

### Transaction wire, parsing, and identifiers

- CompactSize minimality must be enforced everywhere.
- Parsers must reject premature EOF and trailing bytes.
- Unknown witness suites may be parse-canonical but must fail at semantic authorization. There is no `CORE_EXT` activation path: covenant_type `0x0102` is unassigned (CANONICAL §14) and rejected as `TX_ERR_COVENANT_TYPE_INVALID` (RUB-585).
- Implementations must not compute/cache TXID or WTXID for non-canonically parsed transactions.
- Validation-before-mutation must hold: no UTXO or chain state mutation before all prior required checks pass.

### Sighash and cryptography

- `verify_sig` receives exactly `digest32` as the protocol message. No extra hashing, truncation, domain prefix, context string, or wrapper is allowed.
- `crypto_sig` excludes the trailing `sighash_type` byte.
- Native consensus suite is ML-DSA-87 (`suite_id=0x01`) only.
- Non-native signature suites have no consensus activation path: the `CORE_EXT` covenant (`0x0102`) is unassigned and rejected (RUB-585), so only the native ML-DSA-87 suite is consensus-valid.
- OpenSSL/FIPS paths must not overclaim regulatory compliance. Runtime preflight success is not production FIPS certification.
- Consensus verification must not depend on ambient `OPENSSL_CONF`, `OPENSSL_MODULES`, or mutable process-global OpenSSL provider state unless an explicit isolation test proves identical behavior.

### Covenants and `CORE_EXT`

- `CORE_EXT` (`covenant_type=0x0102`) is unassigned per CANONICAL §14 and is rejected by consensus as `TX_ERR_COVENANT_TYPE_INVALID` at both creation and spend (RUB-585; spec RUB-517). There is no `CORE_EXT` activation path and 0x0102 is not spendable; the legacy pre-activation anyone-can-spend semantics have been retired.
- The Go node retains a non-consensus mempool/miner guardrail that excludes 0x0102 (now redundant with consensus rejection, kept as defense in depth). Do not reintroduce `CORE_EXT` covenant semantics or treat 0x0102 as spendable; covenant-type validity follows CANONICAL §14 + `RUBIN_CONSENSUS_STATE_MACHINE`.
- For `CORE_HTLC`, structural selector checks must run before cryptographic verification. Enforce `MIN_HTLC_PREIMAGE_BYTES`, selector coupling, locktime, suite gating, and error priority.
- For `CORE_VAULT`, enforce one-vault-input, owner authorization, no non-owner fee sponsorship, whitelist rules, and `sum_out >= sum_in_vault` in the canonical order.

### Conformance and formal claims

- Go is the reference implementation; Rust must match Go behavior for every executable conformance gate.
- Fixture changes must preserve gate/vector ID governance. Renames or semantic changes require changelog evidence.
- Manual fixture generators must not be silently wired into CI.
- Do not allow public wording such as "formal verification of RUBIN consensus/CANONICAL", "bit-exact wire proven", or "universal mechanized equivalence" unless `rubin-formal/proof_coverage.json` explicitly permits that claim.
- Treat `proof_level=refinement` as bounded executable replay/refinement coverage, not universal proof of all inputs and sections.

### P2P, compact blocks, and DA relay

- P2P relay checks must be bounded before allocation: payload length, CompactSize counts, in-flight caps, deadlines, orphan pools, DA set sizes, and per-peer/global quotas.
- The 4-byte envelope checksum is corruption detection only. It must not be treated as authentication, sender identity, anti-replay, or trust-score evidence.
- Compact block short-ID handling must preserve deterministic collision fallback. Do not ban peers for short-ID collisions.
- Do not apply inventory/request batch caps to total compact-block transaction positions unless a block-derived cap justifies it.
- DA relay state must be atomic by `da_id`: orphan chunks are not pinned, incomplete sets are not mineable, duplicate commits are first-seen, and complete-set eviction uses total fee/total bytes.

### Runtime, storage, and operations

- Node shutdown must be bounded and must close owned RPC/P2P services instead of sleeping forever.
- Persistent state, WAL, replay, chainstate, and storage changes must not mutate durable state before validation has succeeded.
- Genesis bytes, chain ID, genesis hash, POW limit, and deployment descriptor changes are chain-identity changes. Require explicit artifact updates and governance evidence.
- Logs and telemetry must not print private key material, raw secrets, or misleading crypto/FIPS claims.

## Documentation review rules

Documentation changes are P1 when they can mislead implementers or operators about:

- consensus vs relay/policy boundaries;
- activation state or controller approval;
- formal verification scope;
- native vs non-native signature suites;
- `CORE_EXT` pre-activation safety;
- genesis identity or chain parameters;
- whether checks are authoritative or only operational guidance.

Typos are not findings unless they change a safety-critical identifier, command, path, constant, error code, vector ID, or governance instruction.

## Expected clean-review format

A clean review should include a short evidence section:

```text
Evidence inspected:
- Files/specs: <list>
- Callers/callees: <list>
- Fixtures/tests: <list>
- Commands run: <list with PASS/FAIL/NOT RUN>

Result:
- No P0/P1 findings, or INSUFFICIENT_EVIDENCE for <surface> because <reason>.
```

Never claim "no major issues" for consensus, crypto, P2P, conformance, formal, genesis, or governance changes without either passing the relevant commands or explicitly reporting why evidence is insufficient.
