use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub(crate) const LIVE_BINDING_POLICY_VERSION: u64 = 1;
pub(crate) const LIVE_BINDING_POLICY_ERR_STEM: &str = "live_binding_policy";
pub(crate) const LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1: &str = "openssl_digest32_v1";
pub(crate) const LIVE_BINDING_POLICY_V1_JSON: &str =
    include_str!("live_binding_policy_v1_embedded.json");

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveBindingPolicyManifest {
    pub(crate) version: u64,
    pub(crate) entries: Vec<LiveBindingPolicyEntry>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveBindingPolicyEntry {
    pub(crate) alg_name: String,
    pub(crate) pubkey_len: u64,
    pub(crate) sig_len: u64,
    pub(crate) runtime_binding: String,
    pub(crate) openssl_alg: String,
    pub(crate) core_ext_live_binding_name: String,
}

fn live_binding_policy_error(message: impl Into<String>) -> String {
    format!("{LIVE_BINDING_POLICY_ERR_STEM}: {}", message.into())
}

pub(crate) fn live_binding_policy_runtime_entry_not_found_error(
    alg_name: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> String {
    live_binding_policy_error(format!(
        "runtime tuple not found alg={alg_name:?} pubkey_len={pubkey_len} sig_len={sig_len}"
    ))
}

pub(crate) fn live_binding_policy_core_ext_entry_not_found_error(binding_name: &str) -> String {
    live_binding_policy_error(format!(
        "core_ext_live_binding_name not found {binding_name:?}"
    ))
}

fn live_binding_policy_runtime_tuple_key(alg_name: &str, pubkey_len: u64, sig_len: u64) -> String {
    format!("{alg_name}|{pubkey_len}|{sig_len}")
}

pub(crate) fn load_live_binding_policy_from_json(
    raw: &str,
) -> Result<LiveBindingPolicyManifest, String> {
    let manifest: LiveBindingPolicyManifest = serde_json::from_str(raw)
        .map_err(|err| live_binding_policy_error(format!("parse embedded artifact: {err}")))?;
    if manifest.version != LIVE_BINDING_POLICY_VERSION {
        return Err(live_binding_policy_error(format!(
            "unsupported version {} (want {})",
            manifest.version, LIVE_BINDING_POLICY_VERSION
        )));
    }
    if manifest.entries.is_empty() {
        return Err(live_binding_policy_error("entries missing"));
    }
    let mut seen_runtime_tuples = BTreeSet::new();
    let mut seen_core_ext_bindings = BTreeSet::new();
    for (index, entry) in manifest.entries.iter().enumerate() {
        entry.validate(index, &mut seen_runtime_tuples, &mut seen_core_ext_bindings)?;
    }
    Ok(manifest)
}

impl LiveBindingPolicyEntry {
    fn validate(
        &self,
        index: usize,
        seen_runtime_tuples: &mut BTreeSet<String>,
        seen_core_ext_bindings: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if self.alg_name.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: alg_name missing"
            )));
        }
        if self.pubkey_len == 0 {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: pubkey_len must be > 0"
            )));
        }
        if self.sig_len == 0 {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: sig_len must be > 0"
            )));
        }
        if self.openssl_alg.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: openssl_alg missing"
            )));
        }
        if self.core_ext_live_binding_name.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: core_ext_live_binding_name missing"
            )));
        }
        if !seen_core_ext_bindings.insert(self.core_ext_live_binding_name.clone()) {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: duplicate core_ext_live_binding_name {:?}",
                self.core_ext_live_binding_name
            )));
        }
        let runtime_tuple_key =
            live_binding_policy_runtime_tuple_key(&self.alg_name, self.pubkey_len, self.sig_len);
        if !seen_runtime_tuples.insert(runtime_tuple_key.clone()) {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: duplicate runtime tuple alg={:?} pubkey_len={} sig_len={}",
                self.alg_name, self.pubkey_len, self.sig_len
            )));
        }
        match self.runtime_binding.as_str() {
            LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1 => {
                if self.alg_name != "ML-DSA-87" {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires alg_name {:?}",
                        self.runtime_binding, "ML-DSA-87"
                    )));
                }
                if self.openssl_alg != "ML-DSA-87" {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires openssl_alg {:?}",
                        self.runtime_binding, "ML-DSA-87"
                    )));
                }
                if self.pubkey_len != crate::constants::ML_DSA_87_PUBKEY_BYTES {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires pubkey_len {}",
                        self.runtime_binding,
                        crate::constants::ML_DSA_87_PUBKEY_BYTES
                    )));
                }
                if self.sig_len != crate::constants::ML_DSA_87_SIG_BYTES {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires sig_len {}",
                        self.runtime_binding,
                        crate::constants::ML_DSA_87_SIG_BYTES
                    )));
                }
                if self.core_ext_live_binding_name
                    != crate::core_ext::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
                {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires core_ext_live_binding_name {:?}",
                        self.runtime_binding,
                        crate::core_ext::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
                    )));
                }
            }
            other => {
                return Err(live_binding_policy_error(format!(
                    "entries[{index}]: unsupported runtime_binding {:?}",
                    other
                )));
            }
        }
        Ok(())
    }
}

pub(crate) fn default_live_binding_policy() -> Result<&'static LiveBindingPolicyManifest, String> {
    static DEFAULT: OnceLock<LiveBindingPolicyManifest> = OnceLock::new();
    if let Some(manifest) = DEFAULT.get() {
        return Ok(manifest);
    }
    let manifest = load_live_binding_policy_from_json(LIVE_BINDING_POLICY_V1_JSON)?;
    let _ = DEFAULT.set(manifest);
    Ok(DEFAULT.get().expect("live binding policy cached"))
}

pub(crate) fn live_binding_policy_runtime_entry(
    alg_name: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<&'static LiveBindingPolicyEntry, String> {
    let manifest = default_live_binding_policy()?;
    manifest
        .entries
        .iter()
        .find(|entry| {
            entry.alg_name == alg_name && entry.pubkey_len == pubkey_len && entry.sig_len == sig_len
        })
        .ok_or_else(|| {
            live_binding_policy_runtime_entry_not_found_error(alg_name, pubkey_len, sig_len)
        })
}

pub(crate) fn live_binding_policy_core_ext_entry(
    binding_name: &str,
) -> Result<&'static LiveBindingPolicyEntry, String> {
    let manifest = default_live_binding_policy()?;
    manifest
        .entries
        .iter()
        .find(|entry| entry.core_ext_live_binding_name == binding_name)
        .ok_or_else(|| live_binding_policy_core_ext_entry_not_found_error(binding_name))
}

#[cfg(test)]
mod tests {
    use super::{
        default_live_binding_policy, live_binding_policy_core_ext_entry,
        live_binding_policy_core_ext_entry_not_found_error, live_binding_policy_runtime_entry,
        live_binding_policy_runtime_entry_not_found_error, load_live_binding_policy_from_json,
        LIVE_BINDING_POLICY_V1_JSON, LIVE_BINDING_POLICY_VERSION,
    };
    use std::fs;
    use std::path::PathBuf;

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
                    "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                    "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
    fn live_binding_policy_rejects_duplicate_core_ext_binding_name() {
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    },
                    {
                        "alg_name": "ML-DSA-87",
                        "pubkey_len": 2592,
                        "sig_len": 4627,
                        "runtime_binding": "openssl_digest32_v1",
                        "openssl_alg": "ML-DSA-87",
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    }
                ]
            }"#,
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            r#"live_binding_policy: entries[1]: duplicate core_ext_live_binding_name "verify_sig_ext_openssl_digest32_v1""#
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    },
                    {
                        "alg_name": "ML-DSA-87",
                        "pubkey_len": 2592,
                        "sig_len": 4627,
                        "runtime_binding": "openssl_digest32_v1",
                        "openssl_alg": "ML-DSA-87",
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    }]
                }"#,
                "live_binding_policy: entries[0]: openssl_alg missing",
            ),
            (
                "core_ext_binding_missing",
                r#"{
                    "version": 1,
                    "entries": [{
                        "alg_name": "ML-DSA-87",
                        "pubkey_len": 2592,
                        "sig_len": 4627,
                        "runtime_binding": "openssl_digest32_v1",
                        "openssl_alg": "ML-DSA-87",
                        "core_ext_live_binding_name": ""
                    }]
                }"#,
                "live_binding_policy: entries[0]: core_ext_live_binding_name missing",
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    }]
                }"#,
                r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires sig_len 4627"#,
            ),
            (
                "core_ext_binding_mismatch",
                r#"{
                    "version": 1,
                    "entries": [{
                        "alg_name": "ML-DSA-87",
                        "pubkey_len": 2592,
                        "sig_len": 4627,
                        "runtime_binding": "openssl_digest32_v1",
                        "openssl_alg": "ML-DSA-87",
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1_alt"
                    }]
                }"#,
                r#"live_binding_policy: entries[0]: runtime_binding "openssl_digest32_v1" requires core_ext_live_binding_name "verify_sig_ext_openssl_digest32_v1""#,
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1"
                    }]
                }"#,
                "missing field `openssl_alg`",
            ),
            (
                "entry_missing_core_ext_live_binding_name",
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
                "missing field `core_ext_live_binding_name`",
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
                        "core_ext_live_binding_name": "verify_sig_ext_openssl_digest32_v1",
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
    fn live_binding_policy_lookup_helpers_match_embedded_manifest() {
        let runtime_entry = live_binding_policy_runtime_entry("ML-DSA-87", 2592, 4627)
            .expect("lookup runtime entry");
        assert_eq!(runtime_entry.openssl_alg, "ML-DSA-87");

        let runtime_miss = live_binding_policy_runtime_entry("ML-DSA-87", 2592, 4626)
            .expect_err("lookup runtime miss");
        assert_eq!(
            runtime_miss,
            live_binding_policy_runtime_entry_not_found_error("ML-DSA-87", 2592, 4626)
        );

        let core_ext_entry =
            live_binding_policy_core_ext_entry("verify_sig_ext_openssl_digest32_v1")
                .expect("lookup core_ext entry");
        assert_eq!(core_ext_entry.runtime_binding, "openssl_digest32_v1");

        let core_ext_miss = live_binding_policy_core_ext_entry("verify_sig_ext_unknown")
            .expect_err("lookup core_ext miss");
        assert_eq!(
            core_ext_miss,
            live_binding_policy_core_ext_entry_not_found_error("verify_sig_ext_unknown")
        );
    }
}
