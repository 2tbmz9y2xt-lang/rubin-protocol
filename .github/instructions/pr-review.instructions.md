---
applyTo: '**'
---

# PR Review Instructions for rubin-protocol

## Project Context

This is a blockchain protocol repository containing:
- Go reference consensus implementation (`clients/go/`) and Rust parity implementation (`clients/rust/`), frozen on the current line
- Lean4 formal verification proofs (`rubin-formal/`)
- Cross-client conformance runner with parity gates (`conformance/`)
- Post-quantum cryptography (ML-DSA-87)
- Canonical transaction wire format (TXID/WTXID, DA fields, tx_kind)

## Review Priorities (ordered by severity)

### P0 — Block merge
- **Consensus-breaking changes**: any modification to serialization, TXID/WTXID computation, signature verification, or block validation MUST have a corresponding conformance test update
- **Cryptographic correctness**: ML-DSA-87 parameter changes, key derivation, signature scheme modifications require formal proof or explicit justification
- **Go↔Rust parity**: P0 only for an unpaired change (consensus implementation paths of one client without a change to the other client's consensus implementation paths, or consensus CLI paths of one client without a change to the other client's consensus CLI paths, each category paired separately as the gate does; `clients/go/consensus/`, `clients/go/cmd/rubin-consensus-cli/`, `clients/rust/crates/rubin-consensus/` and `clients/rust/crates/rubin-consensus-cli/`, excluding test-only files: names ending in `_test.go`, `_test.rs` or `_tests.rs` and any path with a `benches`, `testdata` or `tests` directory) that lacks the `parity-exempt` label or the "### Parity exemption justification" body block required by `.github/workflows/parity-gate.yml` (for either pair), or for an unpaired change of those consensus paths that contradicts a PR contract requiring both clients. A missing counterpart outside those consensus paths that the contract requires is a P1 contract finding
- **Unsafe code**: new `unsafe` blocks in Rust require safety comments and justification
- **Formal proof breakage**: changes that invalidate existing Lean4 proofs in `rubin-formal/`
- **Wire format changes**: any change to transaction/block serialization, hash computation, or encoding MUST update conformance vectors in `conformance/fixtures/`

### P1 — Request changes
- Missing or inadequate error handling in consensus-critical paths
- Public API changes without backward compatibility analysis
- New dependencies without security review justification
- Test coverage gaps for modified consensus logic
- UTXO state transitions without validation proof coverage
- Cross-language parity drift: a change under `clients/rust/` that the PR's Linear contract does not authorize

### P2 — Comment (non-blocking)
- Code style, naming, documentation improvements
- Performance suggestions
- Refactoring opportunities
- CI/tooling improvements

## Review Checklist

1. Does the PR match its Linear contract (RUB-NNN), and keep Go↔Rust parity where that contract or the parity gate requires it?
2. Are all serialization changes covered by conformance fixtures?
3. Do Lean4 proofs still compile and pass?
4. Is ML-DSA-87 usage correct (parameter sets, context strings)?
5. Are POLICY_* documents updated if policy semantics change?
6. Does the change update ARCHITECTURE_MAP.md if structural changes are made?
7. Are new error types properly propagated and tested?

## Consensus Hazard Checklist (extended)

This checklist is a Rubin-specific review aid. It is not executable proof; Go
reference behavior, Rust behavior, and fixture expectations remain the
responsibility of the conformance runner.

### Determinism (P0 if violated in consensus path)
- [ ] Consensus serialization and hashing do not rely on Go `map` or Rust
      `HashMap` iteration order; sort keys or use deterministic containers.
- [ ] Validation and parsing do not depend on wall-clock time, ambient RNG,
      goroutine scheduling, async task ordering, or filesystem traversal order.
- [ ] Consensus-visible iteration order is specified by canonical data order,
      not by process-local collection behavior.

### Canonical encoding (P0)
- [ ] CompactSize uses Rubin canonical 1/3/5/9-byte minimal encoding.
- [ ] Non-minimal CompactSize rejects as `TX_ERR_PARSE`.
- [ ] `parse_tx` consumes exactly one canonical `TxBytes` payload and rejects
      trailing bytes.
- [ ] Transaction and block round trips check both object equality and canonical
      byte equality when byte-equivalence is claimed.

### Arithmetic safety (P0/P1)
- [ ] `amount`, `fee`, `height`, `weight`, and size accounting are exact and
      checked before use in consensus-validity decisions.
- [ ] Saturating arithmetic is forbidden in consensus-validity decisions unless
      CANONICAL explicitly defines clamping for that field.
- [ ] Rust narrowing casts and Go `int`/fixed-width conversions have explicit
      bounds checks at consensus boundaries.

### DoS surface (P1)
- [ ] Deserialization has explicit max-size / max-depth limits
- [ ] No unbounded `Vec::with_capacity(n)` or `make([]T, n)` from untrusted `n`
- [ ] Loops over network input have iteration caps

### Crypto correctness (P0)
- [ ] ML-DSA-87 verification uses exactly `(pubkey, crypto_sig, digest32)`.
- [ ] ML-DSA verification adds no extra context, prehash, truncation, or domain
      prefix unless CANONICAL explicitly requires it.
- [ ] `crypto_sig` excludes the trailing `sighash_type` byte.
- [ ] Secret/private key material uses redaction and constant-time handling
      where secrecy matters; public consensus IDs (`txid`, `wtxid`, `key_id`,
      hashes, pubkeys) may use ordinary deterministic byte comparison.
- [ ] Key generation uses an OS-backed CSPRNG path (for example OpenSSL RNG or
      getrandom-backed RNG), never `math/rand`, `thread_rng`, or another
      non-cryptographic PRNG.

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
