# Copilot Instructions for rubin-protocol

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
- Go↔Rust parity is mandatory — flag any logic change in one language without a matching change in the other
- Post-quantum cryptography (ML-DSA-87) — be precise about parameter correctness
- Wire format and serialization changes are P0 by definition
