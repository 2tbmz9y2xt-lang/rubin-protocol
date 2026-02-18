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

- `owner_key_id_unspendable_hex`: `<bytes32 hex>` (same for all dev-fund VAULT outputs; makes owner path unspendable)
- `burn_key_id_unspendable_hex`: `<bytes32 hex>` (used for the burn `CORE_P2PK` output of value `GENESIS_BURN_SAT`)

Rules:
- `owner_key_id_unspendable_hex` MUST be provably unspendable for your threat model (do not use a key you might later recover).
- Each `recovery_key_id_hex` below MUST be a valid key_id (bytes32) for the recipient.
- `lock_mode` is fixed to `0x00` (height lock) for all outputs in this schedule.

## 2. Developer fund outputs (exactly 100 rows)

Each row corresponds to one `CORE_VAULT_V1` output in genesis coinbase tx:
- `covenant_type = CORE_VAULT_V1`
- `covenant_data = owner_key_id || lock_mode(0x00) || lock_value(u64le height) || recovery_key_id`

Invariants for this schedule:
- row count MUST equal `GENESIS_DEV_FUND_OUTPUTS` (100).
- `Σ value_sat` MUST equal `GENESIS_DEV_FUND_SAT` (1,000,000 RBN in satoshi).
- `lock_height` MUST be a non-negative integer height.

CSV schema (recommended):
`output_index,value_sat,recovery_key_id_hex,lock_height`

Template (fill all 100 rows):

```csv
output_index,value_sat,recovery_key_id_hex,lock_height
0,<value_sat>,<bytes32hex>,<height>
1,<value_sat>,<bytes32hex>,<height>
2,<value_sat>,<bytes32hex>,<height>
3,<value_sat>,<bytes32hex>,<height>
4,<value_sat>,<bytes32hex>,<height>
5,<value_sat>,<bytes32hex>,<height>
6,<value_sat>,<bytes32hex>,<height>
7,<value_sat>,<bytes32hex>,<height>
8,<value_sat>,<bytes32hex>,<height>
9,<value_sat>,<bytes32hex>,<height>
10,<value_sat>,<bytes32hex>,<height>
11,<value_sat>,<bytes32hex>,<height>
12,<value_sat>,<bytes32hex>,<height>
13,<value_sat>,<bytes32hex>,<height>
14,<value_sat>,<bytes32hex>,<height>
15,<value_sat>,<bytes32hex>,<height>
16,<value_sat>,<bytes32hex>,<height>
17,<value_sat>,<bytes32hex>,<height>
18,<value_sat>,<bytes32hex>,<height>
19,<value_sat>,<bytes32hex>,<height>
20,<value_sat>,<bytes32hex>,<height>
21,<value_sat>,<bytes32hex>,<height>
22,<value_sat>,<bytes32hex>,<height>
23,<value_sat>,<bytes32hex>,<height>
24,<value_sat>,<bytes32hex>,<height>
25,<value_sat>,<bytes32hex>,<height>
26,<value_sat>,<bytes32hex>,<height>
27,<value_sat>,<bytes32hex>,<height>
28,<value_sat>,<bytes32hex>,<height>
29,<value_sat>,<bytes32hex>,<height>
30,<value_sat>,<bytes32hex>,<height>
31,<value_sat>,<bytes32hex>,<height>
32,<value_sat>,<bytes32hex>,<height>
33,<value_sat>,<bytes32hex>,<height>
34,<value_sat>,<bytes32hex>,<height>
35,<value_sat>,<bytes32hex>,<height>
36,<value_sat>,<bytes32hex>,<height>
37,<value_sat>,<bytes32hex>,<height>
38,<value_sat>,<bytes32hex>,<height>
39,<value_sat>,<bytes32hex>,<height>
40,<value_sat>,<bytes32hex>,<height>
41,<value_sat>,<bytes32hex>,<height>
42,<value_sat>,<bytes32hex>,<height>
43,<value_sat>,<bytes32hex>,<height>
44,<value_sat>,<bytes32hex>,<height>
45,<value_sat>,<bytes32hex>,<height>
46,<value_sat>,<bytes32hex>,<height>
47,<value_sat>,<bytes32hex>,<height>
48,<value_sat>,<bytes32hex>,<height>
49,<value_sat>,<bytes32hex>,<height>
50,<value_sat>,<bytes32hex>,<height>
51,<value_sat>,<bytes32hex>,<height>
52,<value_sat>,<bytes32hex>,<height>
53,<value_sat>,<bytes32hex>,<height>
54,<value_sat>,<bytes32hex>,<height>
55,<value_sat>,<bytes32hex>,<height>
56,<value_sat>,<bytes32hex>,<height>
57,<value_sat>,<bytes32hex>,<height>
58,<value_sat>,<bytes32hex>,<height>
59,<value_sat>,<bytes32hex>,<height>
60,<value_sat>,<bytes32hex>,<height>
61,<value_sat>,<bytes32hex>,<height>
62,<value_sat>,<bytes32hex>,<height>
63,<value_sat>,<bytes32hex>,<height>
64,<value_sat>,<bytes32hex>,<height>
65,<value_sat>,<bytes32hex>,<height>
66,<value_sat>,<bytes32hex>,<height>
67,<value_sat>,<bytes32hex>,<height>
68,<value_sat>,<bytes32hex>,<height>
69,<value_sat>,<bytes32hex>,<height>
70,<value_sat>,<bytes32hex>,<height>
71,<value_sat>,<bytes32hex>,<height>
72,<value_sat>,<bytes32hex>,<height>
73,<value_sat>,<bytes32hex>,<height>
74,<value_sat>,<bytes32hex>,<height>
75,<value_sat>,<bytes32hex>,<height>
76,<value_sat>,<bytes32hex>,<height>
77,<value_sat>,<bytes32hex>,<height>
78,<value_sat>,<bytes32hex>,<height>
79,<value_sat>,<bytes32hex>,<height>
80,<value_sat>,<bytes32hex>,<height>
81,<value_sat>,<bytes32hex>,<height>
82,<value_sat>,<bytes32hex>,<height>
83,<value_sat>,<bytes32hex>,<height>
84,<value_sat>,<bytes32hex>,<height>
85,<value_sat>,<bytes32hex>,<height>
86,<value_sat>,<bytes32hex>,<height>
87,<value_sat>,<bytes32hex>,<height>
88,<value_sat>,<bytes32hex>,<height>
89,<value_sat>,<bytes32hex>,<height>
90,<value_sat>,<bytes32hex>,<height>
91,<value_sat>,<bytes32hex>,<height>
92,<value_sat>,<bytes32hex>,<height>
93,<value_sat>,<bytes32hex>,<height>
94,<value_sat>,<bytes32hex>,<height>
95,<value_sat>,<bytes32hex>,<height>
96,<value_sat>,<bytes32hex>,<height>
97,<value_sat>,<bytes32hex>,<height>
98,<value_sat>,<bytes32hex>,<height>
99,<value_sat>,<bytes32hex>,<height>
```

