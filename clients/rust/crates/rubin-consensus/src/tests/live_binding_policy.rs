use super::{
    cached_live_binding_policy, default_live_binding_policy,
    live_binding_policy_binding_name_entry, live_binding_policy_binding_name_entry_not_found_error,
    live_binding_policy_runtime_entry, live_binding_policy_runtime_entry_not_found_error,
    load_live_binding_policy_from_json, LiveBindingPolicyLookupError, LIVE_BINDING_POLICY_V1_JSON,
    LIVE_BINDING_POLICY_VERSION,
};
use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

fn live_binding_policy_repo_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../../../");
    for part in parts {
        path.push(part);
    }
    path
}

#[test]
fn embedded_live_binding_policy_matches_canonical_fixture() {
    let path = live_binding_policy_repo_path(&[
        "conformance",
        "fixtures",
        "protocol",
        "live_binding_policy_v1.json",
    ]);
    let raw = fs::read(&path).expect("read canonical live binding policy fixture");
    assert_eq!(
        raw,
        LIVE_BINDING_POLICY_V1_JSON.as_bytes(),
        "embedded live binding policy drifted from canonical fixture"
    );
}

#[test]
fn load_default_live_binding_policy_accepts_embedded_manifest() {
    let manifest = default_live_binding_policy().expect("load default manifest");
    assert_eq!(manifest.version, LIVE_BINDING_POLICY_VERSION);
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].alg_name, "ML-DSA-87");
}

#[test]
fn live_binding_policy_rejects_unsupported_version() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 2,
            "entries": [{
                "alg_name": "ML-DSA-87",
                "pubkey_len": 2592,
                "sig_len": 4627,
                "runtime_binding": "openssl_digest32_v1",
                "openssl_alg": "ML-DSA-87",
                "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
            }]
        }"#,
    )
    .expect_err("must reject");
    assert_eq!(err, "live_binding_policy: unsupported version 2 (want 1)");
}

#[test]
fn live_binding_policy_rejects_unknown_runtime_binding() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 1,
            "entries": [{
                "alg_name": "ML-DSA-87",
                "pubkey_len": 2592,
                "sig_len": 4627,
                "runtime_binding": "unknown",
                "openssl_alg": "ML-DSA-87",
                "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
            }]
        }"#,
    )
    .expect_err("must reject");
    assert_eq!(
        err,
        r#"live_binding_policy: entries[0]: unsupported runtime_binding "unknown""#
    );
}

#[test]
fn live_binding_policy_rejects_duplicate_live_binding_name() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 1,
            "entries": [
                {
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                },
                {
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }
            ]
        }"#,
    )
    .expect_err("must reject");
    assert_eq!(
        err,
        r#"live_binding_policy: entries[1]: duplicate live_binding_name "verify_sig_ext_openssl_digest32_v1""#
    );
}

#[test]
fn live_binding_policy_rejects_duplicate_runtime_tuple() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 1,
            "entries": [
                {
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                },
                {
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
                }
            ]
        }"#,
    )
    .expect_err("must reject");
    assert_eq!(
        err,
        r#"live_binding_policy: entries[1]: duplicate runtime tuple alg="ML-DSA-87" pubkey_len=2592 sig_len=4627"#
    );
}

#[test]
fn live_binding_policy_rejects_missing_entries() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 1,
            "entries": []
        }"#,
    )
    .expect_err("must reject");
    assert_eq!(err, "live_binding_policy: entries missing");
}

#[test]
fn live_binding_policy_rejects_field_and_canonical_mismatches() {
    let cases = [
        (
            "alg_name_missing",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "live_binding_policy: entries[0]: alg_name missing",
        ),
        (
            "pubkey_len_zero",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 0,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "live_binding_policy: entries[0]: pubkey_len must be > 0",
        ),
        (
            "sig_len_zero",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 0,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "live_binding_policy: entries[0]: sig_len must be > 0",
        ),
        (
            "openssl_alg_missing",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "live_binding_policy: entries[0]: openssl_alg missing",
        ),
        (
            "runtime_binding_missing",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "live_binding_policy: entries[0]: runtime_binding missing",
        ),
        (
            "live_binding_name_missing",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": ""
                }]
            }"#,
            "live_binding_policy: entries[0]: live_binding_name missing",
        ),
        (
            "alg_name_mismatch",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-65",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires alg_name "ML-DSA-87""#,
        ),
        (
            "openssl_alg_mismatch",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-65",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires openssl_alg "ML-DSA-87""#,
        ),
        (
            "pubkey_len_mismatch",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2591,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires pubkey_len 2592"#,
        ),
        (
            "sig_len_mismatch",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4626,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires sig_len 4627"#,
        ),
        (
            "live_binding_name_mismatch",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
                }]
            }"#,
            r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires live_binding_name "verify_sig_ext_openssl_digest32_v1""#,
        ),
    ];

    for (name, raw, want) in cases {
        let err = load_live_binding_policy_from_json(raw).expect_err("must reject");
        assert_eq!(err, want, "{name}");
    }
}

#[test]
fn live_binding_policy_rejects_missing_and_unknown_fields() {
    let cases = [
        (
            "manifest_missing_version",
            r#"{
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `version`",
        ),
        (
            "manifest_unknown_field",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }],
                "unexpected": true
            }"#,
            "unknown field `unexpected`",
        ),
        (
            "entry_missing_alg_name",
            r#"{
                "version": 1,
                "entries": [{
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `alg_name`",
        ),
        (
            "entry_missing_pubkey_len",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `pubkey_len`",
        ),
        (
            "entry_missing_sig_len",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `sig_len`",
        ),
        (
            "entry_missing_runtime_binding",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `runtime_binding`",
        ),
        (
            "entry_missing_openssl_alg",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                }]
            }"#,
            "missing field `openssl_alg`",
        ),
        (
            "entry_missing_live_binding_name",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87"
                }]
            }"#,
            "missing field `live_binding_name`",
        ),
        (
            "entry_unknown_field",
            r#"{
                "version": 1,
                "entries": [{
                    "alg_name": "ML-DSA-87",
                    "pubkey_len": 2592,
                    "sig_len": 4627,
                    "runtime_binding": "openssl_digest32_v1",
                    "openssl_alg": "ML-DSA-87",
                    "live_binding_name": "verify_sig_ext_openssl_digest32_v1",
                    "unexpected": true
                }]
            }"#,
            "unknown field `unexpected`",
        ),
    ];

    for (name, raw, needle) in cases {
        let err = load_live_binding_policy_from_json(raw).expect_err("must reject");
        assert!(
            err.contains(needle),
            "{name}: err={err:?} missing substring {needle:?}"
        );
    }
}

#[test]
fn live_binding_policy_rejects_duplicate_json_keys() {
    let err = load_live_binding_policy_from_json(
        r#"{
            "version": 1,
            "version": 2,
            "entries": [{
                "alg_name": "ML-DSA-87",
                "pubkey_len": 2592,
                "sig_len": 4627,
                "runtime_binding": "openssl_digest32_v1",
                "openssl_alg": "ML-DSA-87",
                "live_binding_name": "verify_sig_ext_openssl_digest32_v1"
            }]
        }"#,
    )
    .expect_err("must reject duplicate JSON keys");
    assert!(
        err.contains(
            r#"live_binding_policy: parse embedded artifact: duplicate JSON key "version""#
        ),
        "err={err:?}"
    );
}

#[test]
fn cached_live_binding_policy_latches_first_error() {
    let cache = OnceLock::new();
    let calls = Cell::new(0);

    let first = cached_live_binding_policy(&cache, || {
        calls.set(calls.get() + 1);
        Err("boom".to_string())
    })
    .expect_err("first load must fail");
    let second = cached_live_binding_policy(&cache, || {
        calls.set(calls.get() + 1);
        load_live_binding_policy_from_json(LIVE_BINDING_POLICY_V1_JSON)
    })
    .expect_err("cached error must latch");

    assert_eq!(calls.get(), 1, "loader should run exactly once");
    assert_eq!(first, "boom");
    assert_eq!(second, "boom");
}

#[test]
fn live_binding_policy_lookup_helpers_match_embedded_manifest() {
    let runtime_entry = live_binding_policy_runtime_entry(
        "ML-DSA-87",
        crate::constants::ML_DSA_87_PUBKEY_BYTES,
        crate::constants::ML_DSA_87_SIG_BYTES,
    )
    .expect("lookup runtime entry");
    assert_eq!(runtime_entry.openssl_alg, "ML-DSA-87");

    let runtime_miss = live_binding_policy_runtime_entry(
        "ML-DSA-87",
        crate::constants::ML_DSA_87_PUBKEY_BYTES,
        crate::constants::ML_DSA_87_SIG_BYTES - 1,
    )
    .expect_err("lookup runtime miss");
    assert!(matches!(
        runtime_miss,
        LiveBindingPolicyLookupError::NotFound(_)
    ));
    assert_eq!(
        runtime_miss.to_string(),
        live_binding_policy_runtime_entry_not_found_error(
            "ML-DSA-87",
            crate::constants::ML_DSA_87_PUBKEY_BYTES,
            crate::constants::ML_DSA_87_SIG_BYTES - 1,
        )
    );

    let live_binding_entry =
        live_binding_policy_binding_name_entry("verify_sig_ext_openssl_digest32_v1")
            .expect("lookup live_binding entry");
    assert_eq!(live_binding_entry.runtime_binding, "openssl_digest32_v1");

    let live_binding_miss = live_binding_policy_binding_name_entry("verify_sig_ext_unknown")
        .expect_err("lookup live_binding miss");
    assert!(matches!(
        live_binding_miss,
        LiveBindingPolicyLookupError::NotFound(_)
    ));
    assert_eq!(
        live_binding_miss.to_string(),
        live_binding_policy_binding_name_entry_not_found_error("verify_sig_ext_unknown")
    );
}
