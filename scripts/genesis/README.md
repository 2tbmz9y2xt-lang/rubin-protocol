# Genesis Builder (v1.1)

This folder contains **non-consensus** tooling to deterministically derive RUBIN chain identity from concrete genesis bytes.

Spec reference:
- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md`
- `spec/RUBIN_L1_CANONICAL_v1.1.md` (genesis + hashing rules)

## Verify An Existing Profile

Derive and print:
- `chain_id_hex`
- `genesis_block_hash_hex`

from the profile's published genesis bytes:

```bash
python3 scripts/genesis/build_genesis_v1_1.py \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md \
  --verify-profile
```

## Build A Genesis With Premine VAULT Outputs

Provide a schedule CSV with exactly 100 rows:

- `owner_key_id_hex` (bytes32 hex)
- `value_base_units` (u64)
- `spend_delay_blocks` (u64)

and one constant `recovery_key_id_unspendable_hex` (bytes32 hex) shared by all outputs.

Generate a skeleton schedule (no secrets; owner_key_id left empty):

```bash
python3 scripts/genesis/gen_dev_fund_schedule_v1_1.py --out /tmp/dev_fund_schedule.csv
```

```bash
python3 scripts/genesis/build_genesis_v1_1.py \
  --schedule-csv operational/dev_fund_schedule.csv \
  --recovery-key-id-unspendable-hex <bytes32hex> \
  --timestamp 0 \
  --target-hex $(python3 - <<'PY'\nprint('ff'*32)\nPY) \
  --nonce 0
```

The script prints:
- `genesis_header_bytes_hex`
- `genesis_tx_bytes_hex`
- `chain_id_hex`
- `genesis_block_hash_hex`

Optional: rewrite a chain-instance profile in-place (controller/operator workflow):

```bash
python3 scripts/genesis/build_genesis_v1_1.py \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_TESTNET_v1.1.md \
  --update-profile \
  --schedule-csv operational/dev_fund_schedule.csv \
  --recovery-key-id-unspendable-hex <bytes32hex>
```
