# RUBIN Genesis Developer Fund Schedule: TEMPLATE v1.1

Status: TEMPLATE (NON-CONSENSUS, PRIVATE)  
Date: 2026-02-17  
Audience: controller + operators (private bring-up)

Purpose: define the per-output schedule inputs used to construct the v1.1 genesis developer fund allocations described in:
- `spec/RUBIN_L1_CANONICAL_v1.1.md` (§1.1.1, genesis allocation rules; constants `GENESIS_DEV_FUND_SAT`, `GENESIS_DEV_FUND_OUTPUTS`)
- `operational/RUBIN_MAINNET_GENESIS_CEREMONY_v1.1.md` (Step 1.1)

This file is not consensus by itself. Consensus binds the exact genesis bytes; this file is an input artifact for producing those bytes.

## 1. Global parameters (fill in)

These values MUST be reflected in the constructed `genesis_tx_bytes`:

- `recovery_key_id_unspendable_hex`: `<bytes32 hex>` (same for all dev-fund VAULT outputs; disables recovery path)

Rules:
- Each `owner_key_id_hex` below MUST be a valid key_id (bytes32) for the recipient.
- `recovery_key_id_unspendable_hex` MUST be provably unspendable for your threat model (do not use a key you might later recover).
- `lock_mode` is fixed to `0x00` (height lock) for all outputs in this schedule.
- `lock_value` is fixed to `2^64-1` (never) for all outputs in this schedule.
- Vesting is implemented by `spend_delay` (relative height) in the VAULT extended encoding, not by `lock_value`.

## 2. Developer fund outputs (exactly 100 rows)

Each row corresponds to one `CORE_VAULT_V1` output in genesis coinbase tx:
- `covenant_type = CORE_VAULT_V1`
- `covenant_data = owner_key_id || spend_delay(u64le blocks) || lock_mode(0x00) || lock_value(u64le 2^64-1) || recovery_key_id_unspendable`

Invariants for this schedule:
- row count MUST equal `GENESIS_DEV_FUND_OUTPUTS` (100).
- `Σ value_sat` MUST equal `GENESIS_DEV_FUND_SAT` (1,000,000 RBN in satoshi).
- `spend_delay_blocks` MUST be a non-negative integer (relative delay in blocks).

CSV schema (recommended):
`output_index,value_sat,owner_key_id_hex,spend_delay_blocks`

Vesting schedule intent (deterministic):
- `TARGET_BLOCK_INTERVAL = 600s`
- `days_per_year = 365` (fixed)
- `blocks_per_year = 52_560`
- `blocks_per_month = 4_380`
- `spend_delay_blocks = m * 4_380` for `m in [1..48]` (4 years)
- Distribution across months: months 1..4 => 3 outputs/month; months 5..48 => 2 outputs/month (100 outputs total)

Template (fill all 100 rows):

```csv
output_index,value_sat,owner_key_id_hex,spend_delay_blocks
0,<value_sat>,<bytes32hex>,<blocks>
1,<value_sat>,<bytes32hex>,<blocks>
2,<value_sat>,<bytes32hex>,<blocks>
3,<value_sat>,<bytes32hex>,<blocks>
4,<value_sat>,<bytes32hex>,<blocks>
5,<value_sat>,<bytes32hex>,<blocks>
6,<value_sat>,<bytes32hex>,<blocks>
7,<value_sat>,<bytes32hex>,<blocks>
8,<value_sat>,<bytes32hex>,<blocks>
9,<value_sat>,<bytes32hex>,<blocks>
10,<value_sat>,<bytes32hex>,<blocks>
11,<value_sat>,<bytes32hex>,<blocks>
12,<value_sat>,<bytes32hex>,<blocks>
13,<value_sat>,<bytes32hex>,<blocks>
14,<value_sat>,<bytes32hex>,<blocks>
15,<value_sat>,<bytes32hex>,<blocks>
16,<value_sat>,<bytes32hex>,<blocks>
17,<value_sat>,<bytes32hex>,<blocks>
18,<value_sat>,<bytes32hex>,<blocks>
19,<value_sat>,<bytes32hex>,<blocks>
20,<value_sat>,<bytes32hex>,<blocks>
21,<value_sat>,<bytes32hex>,<blocks>
22,<value_sat>,<bytes32hex>,<blocks>
23,<value_sat>,<bytes32hex>,<blocks>
24,<value_sat>,<bytes32hex>,<blocks>
25,<value_sat>,<bytes32hex>,<blocks>
26,<value_sat>,<bytes32hex>,<blocks>
27,<value_sat>,<bytes32hex>,<blocks>
28,<value_sat>,<bytes32hex>,<blocks>
29,<value_sat>,<bytes32hex>,<blocks>
30,<value_sat>,<bytes32hex>,<blocks>
31,<value_sat>,<bytes32hex>,<blocks>
32,<value_sat>,<bytes32hex>,<blocks>
33,<value_sat>,<bytes32hex>,<blocks>
34,<value_sat>,<bytes32hex>,<blocks>
35,<value_sat>,<bytes32hex>,<blocks>
36,<value_sat>,<bytes32hex>,<blocks>
37,<value_sat>,<bytes32hex>,<blocks>
38,<value_sat>,<bytes32hex>,<blocks>
39,<value_sat>,<bytes32hex>,<blocks>
40,<value_sat>,<bytes32hex>,<blocks>
41,<value_sat>,<bytes32hex>,<blocks>
42,<value_sat>,<bytes32hex>,<blocks>
43,<value_sat>,<bytes32hex>,<blocks>
44,<value_sat>,<bytes32hex>,<blocks>
45,<value_sat>,<bytes32hex>,<blocks>
46,<value_sat>,<bytes32hex>,<blocks>
47,<value_sat>,<bytes32hex>,<blocks>
48,<value_sat>,<bytes32hex>,<blocks>
49,<value_sat>,<bytes32hex>,<blocks>
50,<value_sat>,<bytes32hex>,<blocks>
51,<value_sat>,<bytes32hex>,<blocks>
52,<value_sat>,<bytes32hex>,<blocks>
53,<value_sat>,<bytes32hex>,<blocks>
54,<value_sat>,<bytes32hex>,<blocks>
55,<value_sat>,<bytes32hex>,<blocks>
56,<value_sat>,<bytes32hex>,<blocks>
57,<value_sat>,<bytes32hex>,<blocks>
58,<value_sat>,<bytes32hex>,<blocks>
59,<value_sat>,<bytes32hex>,<blocks>
60,<value_sat>,<bytes32hex>,<blocks>
61,<value_sat>,<bytes32hex>,<blocks>
62,<value_sat>,<bytes32hex>,<blocks>
63,<value_sat>,<bytes32hex>,<blocks>
64,<value_sat>,<bytes32hex>,<blocks>
65,<value_sat>,<bytes32hex>,<blocks>
66,<value_sat>,<bytes32hex>,<blocks>
67,<value_sat>,<bytes32hex>,<blocks>
68,<value_sat>,<bytes32hex>,<blocks>
69,<value_sat>,<bytes32hex>,<blocks>
70,<value_sat>,<bytes32hex>,<blocks>
71,<value_sat>,<bytes32hex>,<blocks>
72,<value_sat>,<bytes32hex>,<blocks>
73,<value_sat>,<bytes32hex>,<blocks>
74,<value_sat>,<bytes32hex>,<blocks>
75,<value_sat>,<bytes32hex>,<blocks>
76,<value_sat>,<bytes32hex>,<blocks>
77,<value_sat>,<bytes32hex>,<blocks>
78,<value_sat>,<bytes32hex>,<blocks>
79,<value_sat>,<bytes32hex>,<blocks>
80,<value_sat>,<bytes32hex>,<blocks>
81,<value_sat>,<bytes32hex>,<blocks>
82,<value_sat>,<bytes32hex>,<blocks>
83,<value_sat>,<bytes32hex>,<blocks>
84,<value_sat>,<bytes32hex>,<blocks>
85,<value_sat>,<bytes32hex>,<blocks>
86,<value_sat>,<bytes32hex>,<blocks>
87,<value_sat>,<bytes32hex>,<blocks>
88,<value_sat>,<bytes32hex>,<blocks>
89,<value_sat>,<bytes32hex>,<blocks>
90,<value_sat>,<bytes32hex>,<blocks>
91,<value_sat>,<bytes32hex>,<blocks>
92,<value_sat>,<bytes32hex>,<blocks>
93,<value_sat>,<bytes32hex>,<blocks>
94,<value_sat>,<bytes32hex>,<blocks>
95,<value_sat>,<bytes32hex>,<blocks>
96,<value_sat>,<bytes32hex>,<blocks>
97,<value_sat>,<bytes32hex>,<blocks>
98,<value_sat>,<bytes32hex>,<blocks>
99,<value_sat>,<bytes32hex>,<blocks>
```
