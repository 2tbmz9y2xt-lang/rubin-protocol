# Q-CONF-ROTATION-REGRESS-01: Regression Gate Evidence

**Date:** 2026-03-18
**Baseline:** origin/main@7e00b641 (post-rotation: PR#728 Go + PR#736 Rust)
**Runner:** `conformance/runner/run_cv_bundle.py`

**Historical coverage note (2026-10-22, RUB-1710):** The result and suite list
below describe the original 2026-03-18 baseline. `CV-STEALTH` and the three
`NATIVE-ROT-SPEND-STEALTH-01/02/03` vectors are retired under the separately
invoked canonical governance permission. Their identities remain permanently
nonreusable; this historical result is not evidence of current coverage.

## Result

```
PASS: 401 vectors
```

All existing CV-* fixture suites pass without modification after native
crypto rotation implementation (Go PR#728, Rust PR#736).

## Suites Verified

- CV-BLOCK-BASIC
- CV-CANONICAL-INVARIANT
- CV-COMPACT
- CV-COVENANT-GENESIS
- CV-DA-INTEGRITY
- CV-DETERMINISM
- CV-DEVNET-CHAIN / CV-DEVNET-GENESIS / CV-DEVNET-MATURITY / CV-DEVNET-SIGHASH-CHAINID / CV-DEVNET-SUBSIDY
- CV-FEATUREBITS
- CV-FLAGDAY
- CV-FORK-CHOICE
- CV-HTLC / CV-HTLC-ORDERING
- CV-MERKLE
- CV-MULTISIG
- CV-OUTPUT-DESCRIPTOR
- CV-PARSE
- CV-POW
- CV-REPLAY
- CV-SIG
- CV-SIGHASH
- CV-STEALTH
- CV-SUBSIDY
- CV-TIMESTAMP
- CV-UTXO-BASIC
- CV-VALIDATION-ORDER
- CV-VAULT / CV-VAULT-POLICY
- CV-WEIGHT

## Go vs Rust Parity

Both Go and Rust CLI clients produce identical results on all 401 vectors.
No regressions detected.
