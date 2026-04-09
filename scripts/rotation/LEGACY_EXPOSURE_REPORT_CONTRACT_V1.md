# Legacy exposure scanner — typed JSON report contract (v1)

Status: frozen operator-facing contract (advisory measurement only)  
Scope: `clients/go/cmd/rubin-node`, `clients/rust/crates/rubin-node`, orchestration runbooks  
Out of scope: governance thresholds, H4 policy engines, irreversible sunset authorization

## Version surface

| Artifact | Path |
|----------|------|
| Report version field | `report_version` (JSON integer), must be `1` for this contract |
| JSON Schema (machine validation) | `conformance/schemas/legacy_exposure_report_v1.json` |
| Example report (valid instance) | `conformance/fixtures/protocol/legacy_exposure_report_v1_example.json` |
| Hook parity vectors | `conformance/fixtures/protocol/legacy_exposure_hook_vectors.json` |

CI (`tools/check_legacy_exposure_report_contract.py`) validates the example against the JSON Schema and checks that every hook string in the parity fixture is a member of the schema enums (so typos fail in the policy job without relying on step ordering). Go/Rust tests still assert the fixture matches the implementation.

Any change to top-level keys, hook string values, or `measurement_scope`/`report_version` semantics requires:

1. Bumping `report_version` in Go (`legacyExposureReportVersion`) and Rust (`LEGACY_EXPOSURE_REPORT_VERSION`) together  
2. Updating the JSON Schema and example fixture  
3. Updating this document and `scripts/rotation/LEGACY_EXPOSURE_RUNBOOK.md`  
4. Refreshing the orchestration evidence pointer under `rubin-orchestration-private` (see that repo)

## Top-level JSON fields (v1)

All keys are required in emitted output (pretty-printed deterministic JSON).

| JSON key | Type | Meaning |
|----------|------|---------|
| `report_version` | integer | Contract version; `1` for this document |
| `measurement_scope` | string | Constant: `explicit_suite_id_utxos` |
| `network` | string | CLI `--network` value used for the scan |
| `data_dir` | string | Resolved datadir path |
| `chainstate_height` | integer | Height from loaded chainstate |
| `chainstate_has_tip` | boolean | Whether chainstate reports a tip |
| `indexed_suite_ids` | array of integers | Suite IDs present in explicit UTXO index (0–255) |
| `watched_legacy_suite_ids` | integer array | Sorted unique `--legacy-suite-id` values (0–255) |
| `legacy_exposure_total` | integer | Sum of exposure counts across watched legacy suite IDs |
| `sunset_readiness` | string | Advisory readiness label (see hooks below) |
| `warning_hook` | string | Advisory warning hook (see hooks below) |
| `grace_hook` | string | Advisory grace-process hook (see hooks below) |
| `include_outpoints` | boolean | Whether `--legacy-exposure-include-outpoints` was set |
| `legacy_suite_reports` | array | Per-suite breakdown (see below) |

Per-suite objects:

| Key | Type | Meaning |
|-----|------|---------|
| `suite_id` | integer | Watched legacy suite id |
| `utxo_exposure_count` | integer | Matching UTXO count for that suite |
| `outpoint_count` | integer | Same as exposure count in current implementations |
| `outpoints` | array of strings | Present only in detail mode; deterministic `txid_hex:vout` strings |

## Hook semantics (parity-locked)

Hooks are **advisory strings** for operators and council workflows. They do not encode governance thresholds or automatic H4 authorization.

The implementation function is `legacyExposureHooks(has_chainstate_tip, legacy_exposure_total)` in Go and `legacy_exposure_hooks` in Rust. Inputs are:

- `has_chainstate_tip`: from loaded chainstate (`chainstate_has_tip` in JSON)  
- `legacy_exposure_total`: the scalar total in the report

Canonical outputs are frozen in `conformance/fixtures/protocol/legacy_exposure_hook_vectors.json`. Go and Rust tests must stay aligned with that file.

### Truth table

| `has_chainstate_tip` | `legacy_exposure_total` | `sunset_readiness` | `warning_hook` | `grace_hook` |
|---------------------|-------------------------|--------------------|------------------|--------------|
| false | any | `invalid_no_chainstate_tip` | `none` | `not_applicable_no_chainstate_tip` |
| true | 0 | `ready_for_operator_defined_grace_window` | `none` | `start_operator_defined_grace_window` |
| true | > 0 | `not_ready_legacy_exposure_present` | `legacy_exposure_present_notify_operator_and_council` | `not_applicable_legacy_exposure_present` |

### Emitted JSON vs invalid scans

Successful CLI runs that print JSON use a chainstate snapshot **with a tip**; scans without a tip or without chainstate exit with an error and do not emit this report. The `invalid_no_chainstate_tip` hook row exists for parity with the shared hook helper and for tests; operators should treat **successful** JSON as having `chainstate_has_tip == true` when following the runbook.

## Advisory disclaimer

This report measures explicit `suite_id` exposure in local chainstate only. It is not a consensus rule, not a threshold engine, and not sufficient by itself for irreversible governance decisions without separate controller-approved process.
