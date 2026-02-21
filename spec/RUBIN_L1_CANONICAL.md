# RUBIN L1 CANONICAL (DRAFT)

Consensus-critical specification.

## Genesis rule

- The chain is defined with **transaction wire v2 at genesis**.
- There is no activation height / VERSION_BITS gate for wire versions.

## TODO (must become normative)

- Transaction Wire v2: bytes, parsing, error mapping
- TXID/WTXID: what hashes include witness and/or payload
- Block and header wire
- Weight model and witness discount
- Covenant registry and evaluation
- P2P protocol + compact blocks (WTXID-based shortids)
- Deployments (VERSION_BITS) for future feature gates (not wire)
