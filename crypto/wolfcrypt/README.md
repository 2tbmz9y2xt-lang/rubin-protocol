# wolfCrypt Backend (Implementation Notes)

Status: DEVELOPMENT

This directory will contain build notes and adapters for using wolfCrypt as the primary crypto backend:

1. `SHA3-256`
2. `ML-DSA-87` verify
3. `SLH-DSA-SHAKE-256f` verify

Provider API contracts are defined in:

- `clients/rust/crates/rubin-crypto/src/lib.rs`
- `clients/go/crypto/provider.go`

Build profiles and compliance claims are defined in:
- this repository README and operational documents under `operational/` (non-consensus)
