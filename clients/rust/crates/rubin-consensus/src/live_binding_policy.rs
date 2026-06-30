use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt;
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
    pub(crate) live_binding_name: String,
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

pub(crate) fn live_binding_policy_binding_name_entry_not_found_error(binding_name: &str) -> String {
    live_binding_policy_error(format!("live_binding_name not found {binding_name:?}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LiveBindingPolicyLookupError {
    NotFound(String),
    Invalid(String),
}

impl fmt::Display for LiveBindingPolicyLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

fn live_binding_policy_runtime_tuple_key(alg_name: &str, pubkey_len: u64, sig_len: u64) -> String {
    format!("{alg_name}|{pubkey_len}|{sig_len}")
}

struct DuplicateKeySeed;

impl<'de> DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a valid JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateKeySeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(()) = seq.next_element_seed(DuplicateKeySeed)? {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {:?}", key)));
            }
            map.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }
}

fn reject_duplicate_live_binding_policy_json_keys(raw: &str) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    DuplicateKeySeed
        .deserialize(&mut deserializer)
        .map_err(|err| err.to_string())?;
    deserializer.end().map_err(|err| err.to_string())?;
    Ok(())
}

pub(crate) fn load_live_binding_policy_from_json(
    raw: &str,
) -> Result<LiveBindingPolicyManifest, String> {
    reject_duplicate_live_binding_policy_json_keys(raw)
        .map_err(|err| live_binding_policy_error(format!("parse embedded artifact: {err}")))?;
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
    let mut seen_live_bindings = BTreeSet::new();
    for (index, entry) in manifest.entries.iter().enumerate() {
        entry.validate(index, &mut seen_runtime_tuples, &mut seen_live_bindings)?;
    }
    Ok(manifest)
}

impl LiveBindingPolicyEntry {
    fn validate(
        &self,
        index: usize,
        seen_runtime_tuples: &mut BTreeSet<String>,
        seen_live_bindings: &mut BTreeSet<String>,
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
        if self.runtime_binding.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: runtime_binding missing"
            )));
        }
        if self.openssl_alg.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: openssl_alg missing"
            )));
        }
        if self.live_binding_name.is_empty() {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: live_binding_name missing"
            )));
        }
        if !seen_live_bindings.insert(self.live_binding_name.clone()) {
            return Err(live_binding_policy_error(format!(
                "entries[{index}]: duplicate live_binding_name {:?}",
                self.live_binding_name
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
                if self.live_binding_name
                    != crate::core_ext::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
                {
                    return Err(live_binding_policy_error(format!(
                        "entries[{index}]: runtime_binding {:?} requires live_binding_name {:?}",
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

fn cached_live_binding_policy<F>(
    cache: &OnceLock<Result<LiveBindingPolicyManifest, String>>,
    loader: F,
) -> Result<&LiveBindingPolicyManifest, String>
where
    F: FnOnce() -> Result<LiveBindingPolicyManifest, String>,
{
    match cache.get_or_init(loader) {
        Ok(manifest) => Ok(manifest),
        Err(err) => Err(err.clone()),
    }
}

pub(crate) fn default_live_binding_policy() -> Result<&'static LiveBindingPolicyManifest, String> {
    static DEFAULT: OnceLock<Result<LiveBindingPolicyManifest, String>> = OnceLock::new();
    cached_live_binding_policy(&DEFAULT, || {
        load_live_binding_policy_from_json(LIVE_BINDING_POLICY_V1_JSON)
    })
}

pub(crate) fn live_binding_policy_runtime_entry(
    alg_name: &str,
    pubkey_len: u64,
    sig_len: u64,
) -> Result<&'static LiveBindingPolicyEntry, LiveBindingPolicyLookupError> {
    let manifest = default_live_binding_policy().map_err(LiveBindingPolicyLookupError::Invalid)?;
    manifest
        .entries
        .iter()
        .find(|entry| {
            entry.alg_name == alg_name && entry.pubkey_len == pubkey_len && entry.sig_len == sig_len
        })
        .ok_or_else(|| {
            LiveBindingPolicyLookupError::NotFound(
                live_binding_policy_runtime_entry_not_found_error(alg_name, pubkey_len, sig_len),
            )
        })
}

pub(crate) fn live_binding_policy_binding_name_entry(
    binding_name: &str,
) -> Result<&'static LiveBindingPolicyEntry, LiveBindingPolicyLookupError> {
    let manifest = default_live_binding_policy().map_err(LiveBindingPolicyLookupError::Invalid)?;
    manifest
        .entries
        .iter()
        .find(|entry| entry.live_binding_name == binding_name)
        .ok_or_else(|| {
            LiveBindingPolicyLookupError::NotFound(
                live_binding_policy_binding_name_entry_not_found_error(binding_name),
            )
        })
}

#[cfg(test)]
#[path = "tests/live_binding_policy.rs"]
mod tests;
