# rubin-protocol

Public implementation and evidence repository for the Rubin protocol.

It contains the Go and Rust implementations, cross-client conformance fixtures
and runners, reproducible evidence tooling, and protocol-owned formal artifacts.
Consensus rules are not defined by this README or by repository documentation.
The canonical specification source is identified in [SPEC_LOCATION.md](SPEC_LOCATION.md).

## Repository layout

- [`clients/go/`](clients/go/) — Go implementation and command-line tools.
- [`clients/rust/`](clients/rust/) — Rust implementation and command-line tools.
- [`conformance/`](conformance/) — shared fixtures and Go/Rust parity runners.
- [`evidence/`](evidence/) — checked-in evidence and provenance artifacts.
- [`rubin-formal/`](rubin-formal/) — protocol-owned formal and refinement artifacts.
- [`scripts/`](scripts/) and [`tools/`](tools/) — reproducible checks used locally and in CI.

## Minimal local verification

Run the primary implementation and security checks through the repository
environment wrapper:

```bash
scripts/dev-env.sh -- bash -lc 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -lc 'cd clients/rust && cargo test --workspace'
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- scripts/security/precheck.sh --local
```

Additional targeted, nightly, and release checks are defined by the scripts and
GitHub workflows in this repository. Required pull-request checks are enforced
by repository governance. Automatic approval and automatic merge are disabled.

## Authority and architecture

- Rubin network rules belong only to the canonical specification source named
  in [SPEC_LOCATION.md](SPEC_LOCATION.md).
- Detailed product architecture, machine-readable architecture, and agent
  routing are maintained in the private Rubin control plane, not in this public
  repository.
- [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) is retained only as a compatibility
  pointer to that private architecture entrypoint.
- Conformance, tests, evidence, and formal artifacts support scoped claims; they
  do not replace the authority that owns the behavior being checked.

Repository documentation must not be used to infer consensus activation,
governance approval, task status, or complete formal coverage.
