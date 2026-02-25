<!--
RUBIN SPEC FREEZE HEADER (informational)

This repository contains consensus-critical and normative specifications.
Consensus source-of-truth: RUBIN_L1_CANONICAL.md.

Precedence (normative):
  1) RUBIN_L1_CANONICAL.md     (consensus validity)
  2) RUBIN_COMPACT_BLOCKS.md   (normative P2P behavior)
  3) RUBIN_NETWORK_PARAMS.md   (reference summary; derived; CANONICAL prevails)
  4) AUX / operational docs

Integrity:
  - SECTION_HASHES.json pins consensus-critical section hashes of RUBIN_L1_CANONICAL.md.
  - Any change to a pinned section MUST update SECTION_HASHES.json deterministically
    (per canonicalization rules in SECTION_HASHES.json).
-->

# Spec Index

## Consensus-Critical

- `./RUBIN_L1_CANONICAL.md` — **authoritative source of truth**
  - L1 canonical transaction wire (single genesis format)
  - TXID/WTXID, weight, block header, PoW, difficulty retarget
  - Covenant registry and error code registry (genesis profile)
  - Emission schedule (smooth decay + tail, `EMISSION_SPEED_FACTOR=20`)
  - At conflict with any other document, CANONICAL takes precedence.

- `./SECTION_HASHES.json` — consensus-critical integrity pins
  - SHA3-256 hashes of selected consensus-critical sections from `RUBIN_L1_CANONICAL.md`
  - Canonicalization rule is documented inside the JSON.

- `./RUBIN_CORE_HTLC_SPEC.md` — consensus-critical covenant spec
  - `CORE_HTLC` (0x0100), active from genesis block 0
  - Spend rules, witness format, conformance vectors CV-HTLC-01..14
  - Lean4 proof-pack baseline is vendored in `../rubin-formal/` (`proof_level=toy-model`; `status=proved` = proved in the toy/model baseline; refinement to byte-accurate/executable semantics is pending)

## Normative (Non-Consensus)

- `./RUBIN_COMPACT_BLOCKS.md` — normative P2P relay spec
  - Compact block protocol, short_id (wtxid-based), DA mempool state machine
  - Conformance vectors CV-COMPACT (machine-executable)
  - Depends on CANONICAL for DA tx types and block validity rules.

- `./RUBIN_NETWORK_PARAMS.md` — reference parameters summary
  - Derived from CANONICAL and COMPACT_BLOCKS; no independent authority.
  - At conflict with CANONICAL: CANONICAL wins.
  - Human-readable throughput/storage/TPS estimates.

- `./RUBIN_CRYPTO_BACKEND_PROFILE.md` — normative implementation profile
  - OpenSSL-only crypto backend profile for clients and CI
  - Explicit ban on alternative PQ backend bindings in this repo
  - Non-consensus: does not change wire format or block validity rules

## Non-Consensus / AUX

- `./RUBIN_L1_P2P_AUX.md` — non-consensus P2P notes
  - Envelope format, peer scoring; defers to COMPACT_BLOCKS for relay policy.

- `./RUBIN_SPEC_GOVERNANCE.md` — non-consensus governance rules
  - Registry lifecycle, SECTION_HASHES discipline, conformance ID rules (CI lint).

- `./RUBIN_SLH_FALLBACK_PLAYBOOK.md` — operational runbook
  - Activation/rollback procedure for SLH-DSA fallback mode
  - Non-normative; consensus gate is `SLH_DSA_ACTIVATION_HEIGHT` in CANONICAL.

- `./RUBIN_PROTOCOL_MIGRATION_PLAYBOOK.md` — non-consensus migration playbook
  - Rollout/rollback sequence (spec → fixtures → Go → Rust → CI → audit pack).

- `./RUBIN_CRYPTO_BACKEND_OPS.md` — non-consensus crypto ops
  - KPI/perf + parity acceptance policy for OpenSSL/PQC stack.

## Audit

- `./AUDIT_CONTEXT.md` — прикладывать к каждому аудит-сеансу
  - Known-closed findings (KC-01..KC-12)
  - Open findings (Q-C013..Q-C019, HTLC BUG-1/2)
  - Инструкция для аудитора

### Audit Tooling Repro (operational)

Для воспроизводимых локальных запусков в macOS/Homebrew окружении используем единый env-wrapper
(устраняет проблемы с урезанным `PATH` в Codex-сессиях):

```bash
scripts/dev-env.sh
```

Для запуска команд:

```bash
scripts/dev-env.sh -- python3 tools/check_readme_index.py
scripts/dev-env.sh -- node scripts/check-section-hashes.mjs
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
```

Версия Node.js для spec tooling pinned в корне репо:
- `.node-version` (source-of-truth для CI)
- `.nvmrc` (удобство для `nvm`)
- `package.json#engines.node` (guardrail)

Минимальный набор проверок:

```bash
python3 tools/check_readme_index.py
python3 tools/check_section_hashes.py
node scripts/check-spec-invariants.mjs
node scripts/check-section-hashes.mjs
python3 conformance/runner/run_cv_bundle.py
```

Сборка **audit pack** (для внешнего аудита, только tracked файлы; детерминированный архив):

```bash
scripts/dev-env.sh -- python3 tools/make_audit_pack.py --print-sha256
```

Проверка детерминизма (sha256 должен совпасть при неизменном git tree):

```bash
scripts/dev-env.sh -- python3 tools/make_audit_pack.py --out artifacts/audit-pack/a1.tar.gz --print-sha256
scripts/dev-env.sh -- python3 tools/make_audit_pack.py --out artifacts/audit-pack/a2.tar.gz --print-sha256
```

Это operational note (не консенсус).

### Go→Rust parity (operational)

- Go (`clients/go`) — **reference client** для parity.
- Rust (`clients/rust`) — **MUST** совпадать с Go на всех executable conformance gates.
- `conformance/runner/run_cv_bundle.py` проверяет:
  1) Go vs Rust parity (ok/err + ответы),
  2) соответствие ожиданиям в fixtures (спека → fixtures → ожидаемые значения).

## Document Precedence

```
CANONICAL > COMPACT_BLOCKS > NETWORK_PARAMS
CANONICAL > HTLC_SPEC (for wire format)
COMPACT_BLOCKS > P2P_AUX
```
