from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


TXCTX_DIAGNOSTIC_DEFAULTS: Dict[str, Any] = {
    "abi_params_seen": [],
    "base_height": 0,
    "base_shared_across_calls": False,
    "base_total_in_hi": 0,
    "base_total_in_lo": 0,
    "base_total_out_hi": 0,
    "base_total_out_lo": 0,
    "build_txcontext_called": False,
    "bundle_present": False,
    "called_ext_ids": [],
    "continuing_ext_ids": [],
    "continuing_map_empty_after_reject": False,
    "continuing_shared_across_calls": False,
    "empty_payload_non_nil": False,
    "failing_ext_id": 0,
    "self_input_values_seen": [],
}


def normalize_txctx_diagnostics(value: Any) -> Dict[str, Any]:
    diag = dict(TXCTX_DIAGNOSTIC_DEFAULTS)
    if isinstance(value, dict):
        diag.update(value)
    diag["abi_params_seen"] = [int(x) for x in (diag.get("abi_params_seen") or [])]
    diag["called_ext_ids"] = [int(x) for x in (diag.get("called_ext_ids") or [])]
    diag["continuing_ext_ids"] = [int(x) for x in (diag.get("continuing_ext_ids") or [])]
    diag["self_input_values_seen"] = [int(x) for x in (diag.get("self_input_values_seen") or [])]
    for key in (
        "base_height",
        "base_total_in_hi",
        "base_total_in_lo",
        "base_total_out_hi",
        "base_total_out_lo",
        "failing_ext_id",
    ):
        diag[key] = int(diag.get(key, 0))
    for key in (
        "base_shared_across_calls",
        "build_txcontext_called",
        "bundle_present",
        "continuing_map_empty_after_reject",
        "continuing_shared_across_calls",
        "empty_payload_non_nil",
    ):
        diag[key] = bool(diag.get(key, False))
    return diag


def _intish(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value == "":
            return default
        return int(value, 0)
    raise ValueError(f"unsupported integer value: {value!r}")


def _normalize_hex(value: Any) -> str:
    if value is None:
        return ""
    raw = str(value).strip()
    for token in (" ", "\n", "\t", "\r", "_"):
        raw = raw.replace(token, "")
    raw = raw.replace("0x", "").replace("0X", "")
    return raw.lower()


def _parse_ext_id_key(name: str) -> Optional[int]:
    if not name.startswith("continuing_outputs_0x"):
        return None
    return int(name[len("continuing_outputs_0x") :], 16)


def _default_output_value(covenant_type: str) -> int:
    cov = str(covenant_type).strip().upper()
    if cov in {"CORE_ANCHOR", "CORE_DA_COMMIT"}:
        return 0
    return 1


def _verifier_mode(merged: Dict[str, Any], profile_name: str) -> str:
    verifier = str(merged.get("verifier", "")).strip().lower()
    logic = str(merged.get("verifier_logic", "")).strip().lower()
    if verifier == "test_amm_verifier":
        return "amm"
    if profile_name == "test_amm_profile":
        return "amm"
    if "amm" in logic or "reserve" in logic or "product" in logic:
        return "amm"
    return "passthrough"


def _resolve_profile(
    vector: Dict[str, Any],
    fixture_profiles: Dict[str, Dict[str, Any]],
    item: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    profile_name = ""
    if vector.get("profile"):
        profile_name = str(vector["profile"])
        merged.update(fixture_profiles.get(profile_name, {}))
    if item and item.get("profile"):
        profile_name = str(item["profile"])
        merged = dict(fixture_profiles.get(profile_name, {}))
    if vector.get("profile_override") and item is None:
        merged.update(vector["profile_override"])
    if item is None:
        for key in (
            "activation_height",
            "ext_id",
            "ext_id_hex",
            "suite_id",
            "suite_id_hex",
            "txcontext_enabled",
            "allowed_suite_ids",
            "allowed_sighash_set",
            "allowed_sighash_set_hex",
            "max_ext_payload_bytes",
            "binding_kind",
            "suite_count",
            "verifier_logic",
            "verifier",
            "abi",
        ):
            if key in vector:
                merged[key] = vector[key]
    if item:
        merged.update(item)
    activation_height = _intish(merged.get("activation_height", vector.get("activation_height", 0)))
    suite_id = _intish(merged.get("suite_id", fixture_profiles.get(profile_name, {}).get("suite_id", 0)))
    allowed_suite_ids = merged.get("allowed_suite_ids")
    if allowed_suite_ids is None:
        allowed_suite_ids = [suite_id] if suite_id else []
    allowed_suite_ids = [_intish(x) for x in allowed_suite_ids]
    ext_id = _intish(merged.get("ext_id", merged.get("ext_id_hex", 0)))
    return {
        "name": profile_name,
        "ext_id": ext_id,
        "activation_height": activation_height,
        "tx_context_enabled": _intish(merged.get("txcontext_enabled", 1 if profile_name != "test_disabled_profile" else 0)),
        "allowed_suite_ids": allowed_suite_ids,
        "allowed_sighash_set": _intish(merged.get("allowed_sighash_set", 0)),
        "max_ext_payload_bytes": _intish(merged.get("max_ext_payload_bytes", 0)),
        "binding_kind": _intish(merged.get("binding_kind", 2)),
        "suite_count": _intish(merged.get("suite_count", len(allowed_suite_ids) or 1)),
        "suite_id": suite_id,
        "verifier_mode": _verifier_mode(merged, profile_name),
    }


def _default_prevout(index: int) -> Tuple[str, int]:
    txid = f"{index + 1:064x}"
    return txid, 0


def _parse_prevout(value: str, index: int) -> Tuple[str, int]:
    if ":" not in value:
        return _default_prevout(index)
    prefix, vout_str = value.split(":", 1)
    txid = _normalize_hex(prefix)
    txid = (txid + ("0" * 64))[:64]
    return txid, _intish(vout_str)


def _build_inputs(
    vector: Dict[str, Any],
    fixture_profiles: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[int, Dict[str, Any]]]:
    inputs = vector.get("inputs") or [dict()]
    specs: List[Dict[str, Any]] = []
    profiles_by_ext: Dict[int, Dict[str, Any]] = {}
    for index, item in enumerate(inputs):
        profile = _resolve_profile(vector, fixture_profiles, item if item else None)
        prevout_txid_hex, prevout_vout = _parse_prevout(str(item.get("prevout", "")), index)
        covenant_type = str(item.get("covenant_type", "CORE_EXT"))
        if covenant_type.upper() not in {"CORE_EXT", "CORE_EXT_INACTIVE", "CORE_P2PK"}:
            # TXCTX harness treats non-CORE_EXT inputs as inert non-TxContext spends so
            # mixed-input vectors exercise txctx-only behavior and tx-wide totals without
            # pulling unrelated covenant-specific policy into this gate.
            covenant_type = "CORE_EXT_INACTIVE"
        ext_id = _intish(item.get("ext_id", profile["ext_id"])) if item else profile["ext_id"]
        if covenant_type.upper() == "CORE_EXT":
            profile["ext_id"] = ext_id
            profiles_by_ext[ext_id] = profile
        else:
            ext_id = _intish(item.get("ext_id", 0))
        utxo_value = _intish(item.get("utxo_value", item.get("self_input_value", vector.get("self_input_value", 0))))
        self_input_value = _intish(item.get("self_input_value", utxo_value))
        ext_payload_hex = _normalize_hex(item.get("ext_payload_hex", vector.get("ext_payload_hex", "")))
        raw_ext_payload_hex = _normalize_hex(item.get("raw_ext_payload", vector.get("raw_ext_payload", "")))
        suite_id = _intish(item.get("suite_id", profile["suite_id"]))
        pubkey_length = _intish(vector.get("pubkey_length_override", item.get("pubkey_length", 2592)))
        specs.append(
            {
                "prevout_txid_hex": prevout_txid_hex,
                "prevout_vout": prevout_vout,
                "covenant_type": covenant_type,
                "ext_id": ext_id,
                "utxo_value": utxo_value,
                "self_input_value": self_input_value,
                "ext_payload_hex": ext_payload_hex,
                "raw_ext_payload_hex": raw_ext_payload_hex,
                "suite_id": suite_id,
                "sighash_type": _intish(item.get("sighash_type", vector.get("sighash_type", 1))),
                "pubkey_length": pubkey_length,
            }
        )
    return specs, list(profiles_by_ext.values()), profiles_by_ext


def _build_outputs(
    vector: Dict[str, Any],
    primary_ext_id: int,
) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []

    for output in vector.get("continuing_outputs", []):
        outputs.append(
            {
                "covenant_type": "CORE_EXT",
                "ext_id": _intish(output.get("ext_id", vector.get("continuing_ext_id_override", primary_ext_id))),
                "value": _intish(output.get("value", 0)),
                "ext_payload_hex": _normalize_hex(output.get("ext_payload_hex", "")),
                "raw_ext_payload_hex": _normalize_hex(output.get("raw_ext_payload", "")),
                "raw_covenant_data_hex": "",
            }
        )

    for key, value in vector.items():
        ext_id = _parse_ext_id_key(key)
        if ext_id is None:
            continue
        for output in value:
            outputs.append(
                {
                    "covenant_type": "CORE_EXT",
                    "ext_id": _intish(output.get("ext_id", ext_id)),
                    "value": _intish(output.get("value", 0)),
                    "ext_payload_hex": _normalize_hex(output.get("ext_payload_hex", "")),
                    "raw_ext_payload_hex": _normalize_hex(output.get("raw_ext_payload", "")),
                    "raw_covenant_data_hex": "",
                }
            )

    if vector.get("raw_ext_payload") and not outputs and not vector.get("output_override"):
        outputs.append(
            {
                "covenant_type": "CORE_EXT",
                "ext_id": primary_ext_id,
                "value": _intish(vector.get("self_input_value", 0)),
                "ext_payload_hex": "",
                "raw_ext_payload_hex": _normalize_hex(vector.get("raw_ext_payload", "")),
                "raw_covenant_data_hex": "",
            }
        )

    if _intish(vector.get("continuing_output_count", 0)) > 0 and not outputs:
        for _ in range(_intish(vector.get("continuing_output_count", 0))):
            outputs.append(
                {
                    "covenant_type": "CORE_EXT",
                    "ext_id": primary_ext_id,
                    "value": 1,
                    "ext_payload_hex": "",
                    "raw_ext_payload_hex": "",
                    "raw_covenant_data_hex": "",
                }
            )

    if vector.get("output_override"):
        override = vector["output_override"]
        outputs.append(
            {
                "covenant_type": str(override.get("covenant_type", "CORE_EXT")),
                "ext_id": primary_ext_id,
                "value": _intish(override.get("value", 0)),
                "ext_payload_hex": "",
                "raw_ext_payload_hex": "",
                "raw_covenant_data_hex": _normalize_hex(override.get("covenant_data_hex", "")),
            }
        )

    for covenant_type in vector.get("output_covenant_types", []):
        outputs.append(
            {
                "covenant_type": str(covenant_type),
                "ext_id": 0,
                "value": _default_output_value(str(covenant_type)),
                "ext_payload_hex": "",
                "raw_ext_payload_hex": "",
                "raw_covenant_data_hex": "",
            }
        )

    for value in vector.get("output_values", []):
        outputs.append(
            {
                "covenant_type": "CORE_P2PK",
                "ext_id": 0,
                "value": _intish(value),
                "ext_payload_hex": "",
                "raw_ext_payload_hex": "",
                "raw_covenant_data_hex": "",
            }
        )

    output_count = _intish(vector.get("output_count", 0))
    while len(outputs) < output_count:
        outputs.append(
            {
                "covenant_type": "CORE_P2PK",
                "ext_id": 0,
                "value": 1,
                "ext_payload_hex": "",
                "raw_ext_payload_hex": "",
                "raw_covenant_data_hex": "",
            }
        )

    total_out = _intish(vector.get("total_out", 0))
    if total_out > 0:
        current_sum = sum(_intish(item.get("value", 0)) for item in outputs)
        if current_sum < total_out:
            outputs.append(
                {
                    "covenant_type": "CORE_P2PK",
                    "ext_id": 0,
                    "value": total_out - current_sum,
                    "ext_payload_hex": "",
                    "raw_ext_payload_hex": "",
                    "raw_covenant_data_hex": "",
                }
            )

    return outputs


def build_txctx_case(vector: Dict[str, Any], fixture: Dict[str, Any]) -> Dict[str, Any]:
    fixture_profiles = fixture.get("profiles", {})
    inputs, profiles, profiles_by_ext = _build_inputs(vector, fixture_profiles)
    primary_ext_id = inputs[0]["ext_id"] if inputs else 0
    outputs = _build_outputs(vector, primary_ext_id)
    case_height = _intish(vector.get("height", 0))
    explicit_height = "height" in vector and vector.get("height") is not None
    if not explicit_height and case_height == 0 and isinstance(vector.get("inputs"), list):
        for item in vector["inputs"]:
            if isinstance(item, dict):
                item_height = _intish(item.get("height", 0))
                if item_height != 0:
                    case_height = item_height
                    break
    if not explicit_height and case_height == 0 and profiles:
        case_height = max(_intish(profile.get("activation_height", 0)) for profile in profiles)

    input_total = sum(item["utxo_value"] for item in inputs)
    total_in = _intish(vector.get("total_in", 0))
    has_vault_inputs = bool(vector.get("has_vault_inputs", False))
    if total_in == 0 and has_vault_inputs and _intish(vector.get("vault_input_sum", 0)) > 0:
        total_in = input_total + _intish(vector.get("vault_input_sum", 0))
    if total_in > input_total:
        extra_value = total_in - input_total
        extra_index = len(inputs)
        prevout_txid_hex, prevout_vout = _default_prevout(extra_index)
        inputs.append(
            {
                "prevout_txid_hex": prevout_txid_hex,
                "prevout_vout": prevout_vout,
                # Harness-only synthetic input used to reach tx-wide totals without
                # introducing extra native/vault witness semantics into the vector.
                "covenant_type": "CORE_EXT_INACTIVE",
                "ext_id": 0,
                "utxo_value": extra_value,
                "self_input_value": extra_value,
                "ext_payload_hex": "",
                "raw_ext_payload_hex": "",
                "suite_id": 0,
                "sighash_type": 0,
                "pubkey_length": 0,
            }
        )

    return {
        "vector_id": str(vector.get("id", "")),
        "height": case_height,
        "profiles": profiles,
        "inputs": inputs,
        "outputs": outputs,
        "has_vault_inputs": has_vault_inputs,
        "vault_input_sum": _intish(vector.get("vault_input_sum", 0)),
        "force_step2_error": str(vector.get("inject_step2_error", "")),
        "force_step3_error": str(vector.get("inject_step3_error", "")),
        "force_missing_ctx_continuing_ext_id": primary_ext_id if vector.get("inject_missing_ctx_continuing") else 0,
        "verifier_access_index": _intish(vector.get("verifier_accesses_index", 0)),
        "warn_governance_failure": bool(vector.get("governance_failure_marker", False)),
    }


def validate_txctx_responses(
    gate: str,
    vector: Dict[str, Any],
    go_resp: Dict[str, Any],
    rust_resp: Dict[str, Any],
) -> List[str]:
    problems: List[str] = []
    vid = str(vector.get("id", "?"))
    go_diag = normalize_txctx_diagnostics(go_resp.get("diagnostics"))
    rust_diag = normalize_txctx_diagnostics(rust_resp.get("diagnostics"))

    if go_diag != rust_diag:
        problems.append(f"{gate}/{vid}: diagnostics mismatch go={go_diag} rust={rust_diag}")
        return problems

    if vector.get("not_expect_err") and go_resp.get("err") == vector["not_expect_err"]:
        problems.append(f"{gate}/{vid}: not_expect_err violated")

    harness_assertion = vector.get("harness_assertion") or {}
    if harness_assertion.get("verifier_called_with_6_params"):
        if not go_diag["abi_params_seen"] or any(v != 6 for v in go_diag["abi_params_seen"]):
            problems.append(f"{gate}/{vid}: expected 6-param ABI diagnostics")

    if vid == "CV-TXCTX-10":
        if not go_diag["base_shared_across_calls"]:
            problems.append(f"{gate}/{vid}: expected shared ctx_base")
        if not go_diag["continuing_shared_across_calls"]:
            problems.append(f"{gate}/{vid}: expected shared ctx_continuing")
        if go_diag["self_input_values_seen"] != [600, 400]:
            problems.append(f"{gate}/{vid}: self_input_values mismatch")

    if vid == "CV-TXCTX-11a":
        if not go_diag["base_shared_across_calls"]:
            problems.append(f"{gate}/{vid}: expected shared ctx_base")
        if go_diag["continuing_shared_across_calls"]:
            problems.append(f"{gate}/{vid}: expected distinct ctx_continuing per ext_id")

    if vid == "CV-TXCTX-30":
        want = vector.get("total_in_go_limbs", {})
        if go_diag["base_total_in_lo"] != _intish(want.get("lo", 0)):
            problems.append(f"{gate}/{vid}: total_in_lo mismatch")
        if go_diag["base_total_in_hi"] != _intish(want.get("hi", 0)):
            problems.append(f"{gate}/{vid}: total_in_hi mismatch")

    if vid == "CV-TXCTX-54" and not go_diag["empty_payload_non_nil"]:
        problems.append(f"{gate}/{vid}: empty payload must stay non-nil / Vec::new")

    if vid == "CV-TXCTX-70" and go_diag["build_txcontext_called"]:
        problems.append(f"{gate}/{vid}: BuildTxContext must not run after duplicate prevout reject")

    if _intish(vector.get("expected_failing_ext_id", 0)) > 0:
        if go_diag["failing_ext_id"] != _intish(vector["expected_failing_ext_id"]):
            problems.append(
                f"{gate}/{vid}: expected_failing_ext_id={vector['expected_failing_ext_id']} got={go_diag['failing_ext_id']}"
            )
        if vector.get("post_state_assertion") and not go_diag["continuing_map_empty_after_reject"]:
            problems.append(f"{gate}/{vid}: expected empty continuing map after reject")

    if _intish(vector.get("height", -1)) == 0 and vid in {"CV-TXCTX-71"}:
        if go_diag["base_height"] != 0:
            problems.append(f"{gate}/{vid}: expected TxContextBase.Height=0")

    return problems
