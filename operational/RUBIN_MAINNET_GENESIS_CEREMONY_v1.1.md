# RUBIN Mainnet Genesis Ceremony v1.1 (Controller-run)

Status: OPERATIONAL RUNBOOK (non-consensus)  
Date: 2026-02-16  
Audience: controller (single-signer) + operators verifying independently  
Publication channel: GitHub Releases only

Goal: produce an unambiguous, signed, reproducible mainnet chain identity (`chain_id`) by fixing concrete genesis bytes.

This runbook does not change consensus rules. It operationalizes the chain-instance publication requirements referenced by:
- `spec/RUBIN_L1_CANONICAL_v1.1.md §1.1`
- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md`
- `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md`

Threat model (why this matters):
- Anyone can fork the repo and claim “official mainnet”. The defense is a unique `chain_id` derived from concrete genesis bytes and a controller signature over a launch manifest.
- If genesis bytes differ, the resulting `chain_id` differs and it is a different network.

## 0. Outputs (what we must publish)

The ceremony produces and publishes:

1. `genesis_header_bytes` (hex)
2. `genesis_tx_bytes` (hex)
3. `chain_id` (hex; derived)
4. `genesis_block_hash` (hex; derived)
5. `operational/RUBIN_MAINNET_LAUNCH_MANIFEST_v1.1.json` (signed by controller key)

## 1. Preconditions (controller)

1. Decide the exact mainnet genesis parameters (timestamp, target, nonce, coinbase output policy, etc.).
2. Freeze the repo revision used as the “spec publication point”:
   - identify commit `SPEC_COMMIT` (Git SHA) that contains CANONICAL v1.1 and the **final** mainnet profile values (including concrete genesis bytes).
3. Select a signing key and a signing algorithm for the *manifest signature*.
   - Recommended: a widely supported, offline-friendly signature scheme (e.g., minisign or OpenPGP).
   - The signature is **not** a consensus primitive; it is a publication authenticity mechanism.

### Tooling (recommended, non-consensus)

Use the deterministic genesis builder to avoid hand-editing or inconsistent derivations:

- Verify the current profile is self-consistent (derivations match the published bytes):

```bash
python3 scripts/genesis/build_genesis_v1_1.py \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md \
  --verify-profile
```

- Update the mainnet profile in-place during the ceremony (controller/operator workflow):

```bash
python3 scripts/genesis/build_genesis_v1_1.py \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md \
  --update-profile \
  --schedule-csv <path-to-dev-fund-schedule.csv> \
  --recovery-key-id-unspendable-hex <bytes32hex> \
  --timestamp <u64> \
  --target-hex <hex32> \
  --nonce <u64>
```

Notes:
- If you use a premine/dev-fund schedule, it is an *input artifact* only; do not publish private keys. See:
  - `operational/RUBIN_GENESIS_DEV_FUND_SCHEDULE_TEMPLATE_v1.1.md`
  - `scripts/genesis/README.md`
- After updating the profile, commit the changes. The resulting commit hash is the `SPEC_COMMIT` you must tag/release.

## 2. Deterministic derivations (must match spec)

Given the chosen concrete bytes:

```text
serialized_genesis_without_chain_id_field =
  ASCII("RUBIN-GENESIS-v1") ||
  genesis_header_bytes ||
  CompactSize(1) ||
  genesis_tx_bytes

chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
genesis_block_hash = SHA3-256(genesis_header_bytes)
```

## 3. Ceremony procedure (step-by-step)

### Step 1 — Prepare the final mainnet profile values

1. Insert the final `genesis_header_bytes` and `genesis_tx_bytes` into:
   - `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md`
2. Recompute and update the derived:
   - `chain_id`
   - `genesis_block_hash`
3. Commit the changes and record the commit hash as `SPEC_COMMIT`.

### Step 2 — Independent verification (required)

At least two independent runs MUST reproduce the same values (controller + one operator, or two operators).

Verifiers MUST compute `chain_id` and `genesis_block_hash` from the published bytes and check equality.

### Step 3 — Produce the launch manifest

Create `operational/RUBIN_MAINNET_LAUNCH_MANIFEST_v1.1.json` using the schema below (Section 4).

### Step 4 — Controller signature

Controller signs the manifest using **byte-exact signing**:

- The controller MUST sign the **exact UTF-8 bytes** of the manifest file that will be published in the GitHub Release asset.
- Verifiers MUST validate the detached signature against the **exact published bytes** (i.e., the downloaded file bytes).
- If any canonicalization is used, it MUST be a named canonical scheme (recommended: RFC 8785 JSON Canonicalization Scheme) and the chosen scheme MUST be stated alongside the signature; otherwise, tools MUST NOT re-serialize or reformat JSON between signing and verification.

Controller publishes:

- the manifest JSON,
- the detached signature file,
- the controller public key (or key fingerprint + retrieval instructions).

### Step 5 — Release publication (GitHub)

1. Create the release tag **pointing exactly at `SPEC_COMMIT`**:
   - Create tag `mainnet-genesis-v1.1` on `SPEC_COMMIT` (not on a branch tip by accident).
   - Verify the tag target equals `SPEC_COMMIT` before publishing.
2. Create a GitHub Release containing:
   - the exact mainnet profile Markdown,
   - the JSON manifest,
   - the signature,
   - the controller public key / fingerprint file.
3. Final pre-publish verification (controller + at least one operator):
   - `manifest.spec_commit` MUST equal `SPEC_COMMIT`.
   - The detached signature MUST verify against the **downloaded** manifest bytes from the release draft.

## 4. Launch manifest schema (JSON)

Create a JSON object with the following fields:

```json
{
  "protocol": "RUBIN",
  "canonical_revision": "v1.1",
  "network": "mainnet",
  "spec_commit": "<git sha1 or sha256>",
  "published_at_utc": "YYYY-MM-DDTHH:MM:SSZ",
  "genesis_header_bytes_hex": "<hex>",
  "genesis_tx_bytes_hex": "<hex>",
  "chain_id_hex": "<hex32>",
  "genesis_block_hash_hex": "<hex32>",
  "signing": {
    "scheme": "<minisign|openpgp|...>",
    "public_key": "<key material or fingerprint>",
    "signature_file": "<filename>"
  }
}
```

Rules:
- All `*_hex` fields MUST be lowercase hex with no `0x` prefix.
- `chain_id_hex` and `genesis_block_hash_hex` MUST be exactly 64 hex chars.
- `spec_commit` MUST equal `SPEC_COMMIT` used for the `mainnet-genesis-v1.1` tag.

## 5. Post-publication operator checklist

Operators MUST:

1. Verify the controller signature over the manifest.
2. Re-derive `chain_id_hex` from the published genesis bytes and confirm it matches the manifest.
3. Pin `chain_id_hex` in configs/monitoring dashboards as the network identifier.

## 6. Communication rule (anti-spoof)

All official communication MUST reference `chain_id_hex` and the GitHub Release tag `mainnet-genesis-v1.1`.
Any “RUBIN mainnet” claim without the exact `chain_id_hex` is non-authoritative.
