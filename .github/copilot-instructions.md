# Copilot Instructions for rubin-protocol

## Task contract (required)

Every pull-request title carries a Linear issue key of the form RUB-NNN.

1. Before reviewing, read that issue's complete description with the linear MCP tool `get_issue`. When the description has an `annex_ref` field, also read exactly the Linear documents that field names, with `get_document` (`list_documents` only locates those named documents among the issue's documents; other attached documents are not part of the contract).
2. That description plus its annex documents is the task contract and the sole authority for the task's scope and behavior. The GitHub issue mirror and the pull-request body are not the contract.
3. Review the diff against the contract and flag as P1: a changed file outside `allowed_files_or_surfaces` or inside `forbidden_files_or_surfaces`, a behavior the contract does not authorize, and an `accepted_cases`, `rejected_cases`, `hostile_cases` or `done_when` row that the diff does not implement or test. A finding that also meets a P0 class keeps P0. The Severity Calibration section of `.github/instructions/pr-review.instructions.md` does not lower these contract findings.
4. Every such comment cites the contract field or case ID it relies on.
5. When the issue or a named annex document cannot be read, say so once in the review and do not reconstruct the contract from the GitHub issue mirror, the pull-request body or memory.
6. When the title carries no RUB-NNN key, say so once and review against the remaining instructions.

## PR Review Behavior

When reviewing pull requests:

1. **Always leave line-level comments** on the specific lines where you find issues. Do NOT write summary-only reviews — line-level threads are required for the merge gate to work.

2. **Use the severity system** defined in `.github/instructions/pr-review.instructions.md`:
   - P0 = block merge (consensus, crypto, parity, safety)
   - P1 = request changes (error handling, coverage, API)
   - P2 = comment only (style, docs, refactoring)

3. **Each comment must include**: severity tag, description of the issue, and a concrete suggestion or fix.

4. **Do not flag false positives** listed in the review instructions (test-only unwrap, init panics, formatter-enforced style).

## Repository Context

- This is a consensus-critical blockchain protocol with dual Go+Rust implementations
- The Go client is the reference implementation and the Rust client is frozen on the current line, so a Go-only change is expected. Flag a missing counterpart in the other client only when the PR's Linear contract requires both clients, or when an unpaired change is made, paired by category as the gate pairs them (consensus implementation paths of one client change while the other client's consensus implementation paths do not, or consensus CLI paths of one client change while the other client's consensus CLI paths do not; `clients/go/consensus/`, `clients/go/cmd/rubin-consensus-cli/`, `clients/rust/crates/rubin-consensus/` and `clients/rust/crates/rubin-consensus-cli/`, counted only after the gate drops test-only files: names ending in `_test.go`, `_test.rs` or `_tests.rs` and any path with a `benches`, `testdata` or `tests` directory), while the pull request lacks the `parity-exempt` label or the "### Parity exemption justification" body block that `.github/workflows/parity-gate.yml` requires (for either pair). Flag any change under `clients/rust/` that the contract does not explicitly authorize
- Post-quantum cryptography (ML-DSA-87) — be precise about parameter correctness
- Wire format and serialization changes are P0 by definition
