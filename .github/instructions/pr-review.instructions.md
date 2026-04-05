---
applyTo: '**'
---

# PR Review Instructions for rubin-protocol

## Project Context

This is a blockchain protocol repository containing:
- Go and Rust reference consensus implementations (`clients/go/`, `clients/rust/`)
- Lean4 formal verification proofs (`rubin-formal/`)
- Cross-client conformance runner with parity gates (`conformance/`)
- Post-quantum cryptography (ML-DSA-87)
- Canonical transaction wire format (TXID/WTXID, DA fields, tx_kind)

## Review Priorities (ordered by severity)

### P0 — Block merge
- **Consensus-breaking changes**: any modification to serialization, TXID/WTXID computation, signature verification, or block validation MUST have a corresponding conformance test update
- **Cryptographic correctness**: ML-DSA-87 parameter changes, key derivation, signature scheme modifications require formal proof or explicit justification
- **Go↔Rust parity**: changes to one client without equivalent change in the other client MUST be flagged
- **Unsafe code**: new `unsafe` blocks in Rust require safety comments and justification
- **Formal proof breakage**: changes that invalidate existing Lean4 proofs in `rubin-formal/`
- **Wire format changes**: any change to transaction/block serialization, hash computation, or encoding MUST update conformance vectors in `conformance/fixtures/`

### P1 — Request changes
- Missing or inadequate error handling in consensus-critical paths
- Public API changes without backward compatibility analysis
- New dependencies without security review justification
- Test coverage gaps for modified consensus logic
- UTXO state transitions without validation proof coverage
- Cross-language parity drift: logic change in Go or Rust without matching change in the other client

### P2 — Comment (non-blocking)
- Code style, naming, documentation improvements
- Performance suggestions
- Refactoring opportunities
- CI/tooling improvements

## Review Checklist

1. Does the PR maintain Go↔Rust conformance parity?
2. Are all serialization changes covered by conformance fixtures?
3. Do Lean4 proofs still compile and pass?
4. Is ML-DSA-87 usage correct (parameter sets, context strings)?
5. Are POLICY_* documents updated if policy semantics change?
6. Does the change update ARCHITECTURE_MAP.md if structural changes are made?
7. Are new error types properly propagated and tested?

## Language-Specific Rules

### Rust
- No bare `unwrap()` in consensus paths — use proper error propagation. Guard-checked `unwrap()` (e.g., after length validation) is acceptable with a `// SAFETY:` comment explaining the invariant
- Prefer `#[must_use]` on functions whose return value (especially `Result<T, E>`) must not be silently discarded by the caller
- Public types in consensus crates should implement `Debug` where feasible. Types with lifetime parameters or external constraints may omit it with a justification comment

### Go
- Return explicit errors; no `panic()` in library code except for hard invariant violations that indicate a programming bug (not runtime conditions). Document such panics with a comment
- Use structured logging
- Context propagation for cancellable operations

### Lean4
- Proofs must be `sorry`-free before merge
- New theorems need docstrings explaining what property they verify
- Verify that proof dependencies match the implementation they formalize

## False Positive Guidance

To reduce noise, do NOT flag the following patterns:
- `unwrap()` inside `#[cfg(test)]` modules or test files (`_test.go`, `*_test.rs`)
- `panic!()` / `panic()` in `init()`, `main()`, CLI entry points, or test helpers
- Missing `Debug` on types that contain `dyn Trait`, external FFI types, or raw pointers
- Style-only issues (formatting, import order) — these are enforced by `gofmt`/`rustfmt`
- Single-use variables in test fixtures

## Severity Calibration

- P0 is reserved for changes that could cause consensus failure, data loss, or security vulnerabilities. Do not use P0 for style, naming, or documentation issues
- When in doubt between P1 and P2, prefer P2. Over-escalation creates review fatigue
- A finding without a concrete failure scenario or code path is P2 at most

## Review Output Format

- Leave findings as **line-level comments** on the specific code lines, not as summary-only reviews
- Each comment should state: severity (P0/P1/P2), what the issue is, and a suggested fix or action
- Group related findings into a single thread rather than scattering across lines
