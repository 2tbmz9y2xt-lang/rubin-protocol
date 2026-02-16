# RETL Interop Fixtures (v1.1)

Status: DEVELOPMENT  
Scope: application-layer interoperability

These fixtures validate that independent RETL implementations and indexers:

1. compute identical `descriptor_bytes` and `retl_domain_id`,
2. parse the canonical `anchor_data` envelope,
3. compute identical sequencer signing preimage hashes.

Source of truth:

- `spec/RUBIN_L1_CANONICAL_v1.1.md §7`
- `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md`

Notes:

- L1 consensus treats anchor payload bytes as opaque. These fixtures are RETL-only.

## Fixture status declaration

The table below declares fixture intent and acceptance status for this release:

| Fixture ID | Scope | Expected behavior | Status |
|---|---|---|---|
| `RETL-01-minimal-batch-devnet` | devnet | Positive path, signed by local shim fixture flow | **DEVELOPMENT (DEV)** |
| `RETL-01-minimal-batch-testnet` | testnet profile | Positive path, signature check not required at L1 consensus level | **PRODUCTION READY (consensus-optional)** |
| `RETL-01-minimal-batch-mainnet` | mainnet profile | Positive path, signature check not required at L1 consensus level | **PRODUCTION READY (consensus-optional)** |
| `RETL-02-invalid-magic` | both | Parsing rejection (`RETL_ERR_MAGIC`) | **NEGATIVE (MUST FAIL)** |
| `RETL-03-truncated-payload` | both | Parsing rejection (`RETL_ERR_TRUNCATED`) | **NEGATIVE (MUST FAIL)** |
| `RETL-04-nonminimal-compactsize-in-witness` | both | Parsing rejection (`RETL_ERR_COMPACTSIZE_NONMINIMAL`) | **NEGATIVE (MUST FAIL)** |
| `RETL-05-batch-number-discontinuity` | indexer/integration | Parse success, indexer-level discontinuity warning only | **INDEXER LEVEL (NON-CONSENSUS)** |

Definition:

- **DEVELOPMENT (DEV)**: requires local dev fixture tooling/shim.
- **PRODUCTION READY (consensus-optional)**: accepted by interoperability checks, does not gate L1 consensus.
- **NEGATIVE (MUST FAIL)**: parse layer must reject fixture.
- **INDEXER LEVEL (NON-CONSENSUS)**: valid parsing, but policy handling is not consensus rule.
