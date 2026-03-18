# Q-CONF-ROTATION-REGRESS-01: Regression Gate Evidence

**Date:** 2026-03-18
**Baseline:** origin/main@7e00b641 (post-rotation: PR#728 Go + PR#736 Rust)
**Runner:** `conformance/runner/run_cv_bundle.py`

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
