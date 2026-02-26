# Rubin Protocol — Architecture Map

## 1) Source of Truth and Governance Flow

```text
rubin-spec (private repo)
        │
        ├──> RUBIN_L1_CANONICAL.md (consensus authority)
        ├──> SECTION_HASHES.json (pinned integrity hashes)
        ├──> RUBIN_COMPACT_BLOCKS.md (normative P2P behavior)
        └──> RUBIN_NETWORK_PARAMS.md (derived summary)
```

- `RUBIN_L1_CANONICAL.md` is the consensus authority.
- `SECTION_HASHES.json` protects consensus-critical sections from accidental drift.
- `RUBIN_COMPACT_BLOCKS.md` and `RUBIN_NETWORK_PARAMS.md` are normative/derived layers and must not contradict CANONICAL.

Normative precedence (from private spec repo):

```text
CANONICAL > COMPACT_BLOCKS > NETWORK_PARAMS
CANONICAL > HTLC_SPEC (for wire format)
COMPACT_BLOCKS > P2P_AUX
```

## 2) Implementation Flow (Spec -> Clients)

```text
rubin-spec (private) /*
  │
  ├──> clients/go/consensus/*              (reference implementation)
  └──> clients/rust/crates/rubin-consensus/* (parity implementation)
```

- Go is treated as reference behavior for executable conformance parity.
- Rust must match Go at the behavior level on all executable gates.

## 3) Conformance Flow (Spec -> Fixtures -> Runners -> Gates)

```text
rubin-spec (private) /*
  │
  └──> conformance/fixtures/CV-*.json
            │
            └──> conformance/runner/run_cv_bundle.py
                     │
                     ├── builds/runs Go CLI
                     ├── builds/runs Rust CLI
                     └── checks:
                          1) Go vs fixture expectations
                          2) Rust vs Go parity
```

- Fixtures encode expected outcomes for protocol operations.
- The runner prevents "both implementations drift together" by validating Go against fixtures first.

## 4) CI Control Plane

```text
.github/workflows/ci.yml
  ├── formal job
  │     ├── rubin-formal/ (Lean build)
  │     └── tools/check_formal_*.py
  └── test job
        ├── Go fmt/test/vet/vulncheck
        ├── Rust fmt/test/clippy/audit
        ├── spec checks (node scripts/*)
        ├── audit checks (tools/*snapshot*)
        └── conformance bundle run
```

- CI enforces both correctness (tests/parity) and process integrity (spec invariants, audit snapshot freshness, policy checks).

## 5) Operational Tooling

- `scripts/` contains spec integrity tooling and reproducible env helpers.
- `tools/` contains policy and integrity checks used by CI and local validation.
- `rubin-formal/` maintains a toy/model formal baseline and risk-gate metadata.

## 6) Practical Change Path (Recommended)

1. Update spec document(s) in private `rubin-spec`.
2. If semantics changed, update/extend `conformance/fixtures/CV-*.json`.
3. Implement behavior in Go + Rust clients.
4. Run conformance runner and local checks.
5. Refresh audit/formal metadata if needed.
6. Ensure CI-equivalent checks pass before merge.

## 7) Minimal Local Validation Bundle

Run these in `rubin-protocol` after protocol-affecting changes:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- python3 tools/gen_audit_snapshot.py --check
scripts/dev-env.sh -- python3 tools/check_audit_snapshot.py
```

Spec integrity checks (`check_readme_index.py`, `check_section_hashes.py`, `check-spec-invariants.mjs`, `check-section-hashes.mjs`) must be run in the private `rubin-spec` repository.

---

## Quick Onboarding Entry Points

- Protocol authority (private): `rubin-spec`
- Spec location pointer: `SPEC_LOCATION.md`
- Parity harness: `conformance/README.md`
- Go CLI entrypoint: `clients/go/cmd/rubin-consensus-cli/main.go`
- Rust CLI entrypoint: `clients/rust/crates/rubin-consensus-cli/src/main.rs`
- CI pipeline: `.github/workflows/ci.yml`
