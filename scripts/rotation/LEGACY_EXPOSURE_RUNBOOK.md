# Legacy Exposure Scanner Runbook

Status: operational guidance for optional native-rotation sunset readiness  
Scope: `clients/go/cmd/rubin-node`, `clients/rust/crates/rubin-node`, operator/council migration workflow

## 1) Purpose

This runbook makes legacy suite exposure measurable before any optional `H4`
sunset proposal. It is an ops package, not a consensus-rule change.

If anyone wants to use this package as the sole gate for an irreversible `H4`
decision: **НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА**.

## 2) Scanner Commands

Go node CLI:

```bash
go run ./clients/go/cmd/rubin-node \
  --datadir /path/to/datadir \
  --legacy-exposure-scan \
  --legacy-suite-id 0x01
```

Rust node CLI:

```bash
cargo run -p rubin-node -- \
  --datadir /path/to/datadir \
  --legacy-exposure-scan \
  --legacy-suite-id 0x01
```

Optional detail mode:

```bash
--legacy-exposure-include-outpoints
```

`--legacy-suite-id` is repeatable. Inputs accept decimal or `0xNN`.
The watched suite list is operator-supplied; this task does not auto-infer an
irreversible governance decision from a future `H4` artifact.

## 3) Report Fields

The scanner emits deterministic JSON with:

- `measurement_scope`: currently `explicit_suite_id_utxos`
- `indexed_suite_ids`: suite IDs currently visible in explicit UTXO covenant data
- `watched_legacy_suite_ids`: legacy suite IDs the operator asked to watch
- `legacy_exposure_total`: sum of current explicit UTXO exposure across watched legacy suite IDs
- `legacy_suite_reports[*].utxo_exposure_count`: per-suite exposure count
- `legacy_suite_reports[*].outpoint_count`: per-suite outpoint count
- `legacy_suite_reports[*].outpoints`: deterministic outpoint list when detail mode is enabled
- `sunset_readiness`, `warning_hook`, `grace_hook`: advisory ops hooks derived from current exposure only

Today this measurement surface covers UTXOs whose covenant data explicitly
stores a `suite_id` byte. In current node code that means the explicit suite-id
index surface, not every possible migration-related interpretation layer.
The scanner is chainstate-only: it reads the local datadir and exits without
starting runtime services, so this measurement mode does not require a genesis
file just to inspect an already indexed chainstate snapshot.

## 4) Explicit Trigger Criteria

This repository does **not** choose the final irreversible `H4` governance
policy in this task. The explicit scanner triggers are intentionally narrower:

1. Warning trigger:
   `legacy_exposure_total > 0`
2. Ready-to-start-grace trigger:
   `legacy_exposure_total == 0`
3. Advisory hook rule:
   when exposure is zero, the scanner reports `start_operator_defined_grace_window`
   but does **not** pick the grace-window length for the council.

In other words:

- non-zero exposure means watched legacy exposure remains in explicit suite-id UTXOs
- zero exposure means the council can begin its separately defined grace workflow
- zero exposure alone does not authorize an irreversible `H4`

## 5) Operator Workflow

1. Run the scanner against the candidate network datadir.
2. Record the JSON report with UTC timestamp and chainstate height.
3. If `warning_hook != "none"`, notify operators and council that legacy exposure remains.
4. If `grace_hook == "start_operator_defined_grace_window"`, begin the separately approved grace process.
5. Repeat the scan during the grace period until the council has enough evidence for its own approval flow.

## 6) Council Workflow Hooks

Before any irreversible sunset proposal, council review should have:

1. the latest scanner JSON report
2. the watched legacy suite IDs used for the scan
3. the chainstate height of the measurement
4. any optional detailed outpoint list needed for manual triage
5. an explicit statement of the grace policy being used

This task supplies the measurement hook. It does not define the final governance threshold by itself.
