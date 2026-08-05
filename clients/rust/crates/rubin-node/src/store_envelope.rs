//! store_envelope_v1 (RUB-1134): `chainstate.json` and the canonical blockstore
//! `index.json` are each stored as
//! `{"version":1,"payload_b64":"<b64>","checksum":"<64hex>"}\n` with
//! `checksum = SHA3-256(ASCII(domain_tag) || uint64_be(len(payload)) || payload)`
//! over the exact inner payload bytes (trailing LF excluded). The authoritative
//! rationale is `clients/go/node/store_envelope.go`; this is its byte-exact
//! mirror and the vectors below pin the bytes.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha3::{Digest, Sha3_256};

use crate::blockstore::valid_canonical_hash_hex;
use crate::undo::base64_encode;

/// Stable prefix of every envelope/version/base64/checksum/genesis-anchor
/// rejection class (Go: `ErrStoreIntegrity`). The channel here is `String`, so
/// the prefix IS the identity; the inner payload-decode class stays OUTSIDE it.
pub(crate) const STORE_INTEGRITY_PREFIX: &str = "STORE_INTEGRITY";

/// Pinned cross-client messages; no repair command (there is no `--reindex`).
pub(crate) const STORE_LEGACY_CHAINSTATE_ERR: &str = "STORE_INTEGRITY: legacy/unversioned chainstate; delete chainstate.json and restart to rebuild by validated replay.";
pub(crate) const STORE_LEGACY_BLOCK_INDEX_ERR: &str = "STORE_INTEGRITY: legacy/unversioned blockstore index; pre-devnet datadir reset and full resync required.";
pub(crate) const STORE_CHECKSUM_MISMATCH_ERR: &str = "STORE_INTEGRITY: checksum mismatch.";
pub(crate) const STORE_GENESIS_ANCHOR_ERR: &str =
    "STORE_INTEGRITY: canonical index genesis mismatch.";

const STORE_ENVELOPE_PREFIX: &[u8] = br#"{"version":1,"payload_b64":""#;
const STORE_ENVELOPE_CHECKSUM_SEP: &[u8] = br#"","checksum":""#;
const STORE_ENVELOPE_SUFFIX: &[u8] = b"\"}\n";

const STORE_ENVELOPE_VERSION: u32 = 1;
const STORE_CHECKSUM_HEX_LEN: usize = 64;
const STORE_ENVELOPE_FRAME_BYTES: usize = STORE_ENVELOPE_PREFIX.len()
    + STORE_ENVELOPE_CHECKSUM_SEP.len()
    + STORE_CHECKSUM_HEX_LEN
    + STORE_ENVELOPE_SUFFIX.len();

#[derive(Clone, Copy)]
pub(crate) struct StoreEnvelopeKind {
    domain: &'static [u8],
    noun: &'static str,
    legacy_err: &'static str,
}

pub(crate) const STORE_ENVELOPE_CHAIN_STATE: StoreEnvelopeKind = StoreEnvelopeKind {
    domain: b"RUBIN_CHAINSTATE_V1",
    noun: "chainstate",
    legacy_err: STORE_LEGACY_CHAINSTATE_ERR,
};

pub(crate) const STORE_ENVELOPE_BLOCK_INDEX: StoreEnvelopeKind = StoreEnvelopeKind {
    domain: b"RUBIN_BLOCKSTORE_INDEX_V1",
    noun: "blockstore index",
    legacy_err: STORE_LEGACY_BLOCK_INDEX_ERR,
};

/// Writer shape only; field ORDER is part of the format.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreEnvelopeDisk {
    version: u32,
    payload_b64: String,
    checksum: String,
}

fn store_envelope_checksum(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(domain);
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Wraps the exact payload bytes in v1; no size bound (RUB-1057).
pub(crate) fn marshal_store_envelope(
    kind: StoreEnvelopeKind,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let envelope = StoreEnvelopeDisk {
        version: STORE_ENVELOPE_VERSION,
        payload_b64: base64_encode(payload),
        checksum: hex::encode(store_envelope_checksum(kind.domain, payload)),
    };
    let mut raw =
        serde_json::to_vec(&envelope).map_err(|e| format!("encode {} envelope: {e}", kind.noun))?;
    raw.push(b'\n');
    Ok(raw)
}

/// The validation order for one protected file: strict canonical layout (which
/// subsumes shape, version, duplicate, unknown, missing, null, wrong-type,
/// ordering, whitespace and trailing-token rejection, legacy classified first),
/// canonical padded base64, then the constant-time checksum compare. Only then
/// may the caller decode the inner schema.
pub(crate) fn open_store_envelope(kind: StoreEnvelopeKind, raw: &[u8]) -> Result<Vec<u8>, String> {
    let (payload_b64, checksum_hex) = split_store_envelope(kind, raw)?;
    let payload = decode_canonical_store_base64(payload_b64)?;
    // `split_store_envelope` already proved this is 64 lowercase hex.
    let mut stored = [0u8; 32];
    hex::decode_to_slice(checksum_hex, &mut stored)
        .map_err(|_| format!("{STORE_INTEGRITY_PREFIX}: checksum is not hexadecimal"))?;
    if !constant_time_eq32(&stored, &store_envelope_checksum(kind.domain, &payload)) {
        return Err(STORE_CHECKSUM_MISMATCH_ERR.to_string());
    }
    Ok(payload)
}

/// Returns sub-slices of `raw`. The body length is DERIVED (`raw.len() -
/// frame`), never searched for, so any inserted, removed, reordered, duplicated
/// or renamed field shifts the tail and fails.
fn split_store_envelope(kind: StoreEnvelopeKind, raw: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let Some(body) = raw.len().checked_sub(STORE_ENVELOPE_FRAME_BYTES) else {
        return Err(classify_store_envelope_failure(kind, raw));
    };
    let payload_at = STORE_ENVELOPE_PREFIX.len();
    let checksum_sep_at = payload_at + body;
    let checksum_at = checksum_sep_at + STORE_ENVELOPE_CHECKSUM_SEP.len();
    let suffix_at = checksum_at + STORE_CHECKSUM_HEX_LEN;
    if &raw[..payload_at] != STORE_ENVELOPE_PREFIX
        || &raw[checksum_sep_at..checksum_at] != STORE_ENVELOPE_CHECKSUM_SEP
        || &raw[suffix_at..] != STORE_ENVELOPE_SUFFIX
    {
        return Err(classify_store_envelope_failure(kind, raw));
    }
    let checksum_hex = &raw[checksum_at..suffix_at];
    if !valid_canonical_hash_hex(&String::from_utf8_lossy(checksum_hex)) {
        return Err(format!(
            "{STORE_INTEGRITY_PREFIX}: checksum must be 64 lowercase hex characters"
        ));
    }
    Ok((&raw[payload_at..checksum_sep_at], checksum_hex))
}

/// Names WHY a file failed the layout check; runs only on already-rejected
/// files. It deserializes ONE value, does NOT require EOF, and duplicate keys
/// last-win (as in Go), so a legacy file with trailing garbage still reports the
/// legacy message. Legacy detection keys on the ENVELOPE fields and precedes
/// the version verdicts: both legacy schemas carry a top-level `"version": 1`.
fn classify_store_envelope_failure(kind: StoreEnvelopeKind, raw: &[u8]) -> String {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let Ok(probe) = Map::<String, Value>::deserialize(&mut deserializer) else {
        return format!(
            "{STORE_INTEGRITY_PREFIX}: {} is not a single JSON object",
            kind.noun
        );
    };
    if !probe.contains_key("payload_b64") && !probe.contains_key("checksum") {
        return kind.legacy_err.to_string();
    }
    // `as_u64` is None for null, strings and non-integral numbers, which fall
    // through to the generic verdict exactly as Go's probe does.
    match probe.get("version").and_then(Value::as_u64) {
        Some(version) if version != u64::from(STORE_ENVELOPE_VERSION) => {
            format!("{STORE_INTEGRITY_PREFIX}: unsupported store envelope version {version}")
        }
        _ => format!("{STORE_INTEGRITY_PREFIX}: envelope is not the canonical encoding"),
    }
}

/// Accepts only the one padded RFC 4648 spelling: non-alphabet bytes are
/// rejected symbol by symbol (JSON-escaped whitespace a permissive decoder would
/// skip cannot slip through) and the bits padding discards must be zero.
fn decode_canonical_store_base64(value: &[u8]) -> Result<Vec<u8>, String> {
    let not_canonical =
        || format!("{STORE_INTEGRITY_PREFIX}: payload_b64 is not canonical padded base64");
    if !value.len().is_multiple_of(4) {
        return Err(not_canonical());
    }
    let quads = value.len() / 4;
    let mut out = Vec::with_capacity(quads.saturating_mul(3));
    for (index, quad) in value.chunks_exact(4).enumerate() {
        // Padding is legal only in the final quad; elsewhere `=` fails below.
        let pad = if index + 1 != quads {
            0
        } else if quad[3] == b'=' {
            if quad[2] == b'=' {
                2
            } else {
                1
            }
        } else {
            0
        };
        let mut packed = 0u32;
        for symbol in &quad[..4 - pad] {
            packed = (packed << 6) | base64_symbol_value(*symbol).ok_or_else(not_canonical)?;
        }
        // A canonical encoder leaves the 2*pad discarded low bits zero.
        if packed & ((1u32 << (2 * pad)) - 1) != 0 {
            return Err(not_canonical());
        }
        packed <<= 6 * pad;
        out.push((packed >> 16) as u8);
        if pad < 2 {
            out.push((packed >> 8) as u8);
        }
        if pad < 1 {
            out.push(packed as u8);
        }
    }
    Ok(out)
}

fn base64_symbol_value(symbol: u8) -> Option<u32> {
    let value = match symbol {
        b'A'..=b'Z' => u32::from(symbol - b'A'),
        b'a'..=b'z' => u32::from(symbol - b'a') + 26,
        b'0'..=b'9' => u32::from(symbol - b'0') + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(value)
}

fn constant_time_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The RUB-1134 cross-client vectors; the Go suite embeds these SAME
    /// literals. Rows 1/3 differ only by domain tag (domain separation); rows
    /// 2/4 pin the length term and the base64 body, and row 4 is also the
    /// on-disk creation marker.
    #[rustfmt::skip]
    const VECTORS: &[(StoreEnvelopeKind, &str, &str, &str)] = &[
        (STORE_ENVELOPE_CHAIN_STATE, "", "51e3d3a67f6a7c4439465328314723099ea753c512f22a1f197e1528b1f24afe",
         "{\"version\":1,\"payload_b64\":\"\",\"checksum\":\"51e3d3a67f6a7c4439465328314723099ea753c512f22a1f197e1528b1f24afe\"}\n"),
        (STORE_ENVELOPE_CHAIN_STATE, "{\"version\":1}\n", "6d8ced24b9b3f05ed1aebb46c3bfe0a0bfc96508ce51e1ca6de3dc643ec659d0",
         "{\"version\":1,\"payload_b64\":\"eyJ2ZXJzaW9uIjoxfQo=\",\"checksum\":\"6d8ced24b9b3f05ed1aebb46c3bfe0a0bfc96508ce51e1ca6de3dc643ec659d0\"}\n"),
        (STORE_ENVELOPE_BLOCK_INDEX, "", "bf1cd3af0b95b8861e3abf40b776f315117e55b28b5c5dbdb811d3fd33018e5a",
         "{\"version\":1,\"payload_b64\":\"\",\"checksum\":\"bf1cd3af0b95b8861e3abf40b776f315117e55b28b5c5dbdb811d3fd33018e5a\"}\n"),
        (STORE_ENVELOPE_BLOCK_INDEX, "{\n  \"canonical\": [],\n  \"version\": 1\n}\n", "7c120c21bc3ffdda6482c8d18a3c669542e89d8500928ce166700a7c7a40fe15",
         "{\"version\":1,\"payload_b64\":\"ewogICJjYW5vbmljYWwiOiBbXSwKICAidmVyc2lvbiI6IDEKfQo=\",\"checksum\":\"7c120c21bc3ffdda6482c8d18a3c669542e89d8500928ce166700a7c7a40fe15\"}\n"),
    ];

    /// Pins the frame, preimage and checksum, recomputing the checksum locally
    /// so the pin cannot drift with the production helper.
    #[test]
    fn store_envelope_v1_cross_client_vectors() {
        for (kind, payload, want_checksum, want_envelope) in VECTORS {
            let mut hasher = Sha3_256::new();
            hasher.update(kind.domain);
            hasher.update((payload.len() as u64).to_be_bytes());
            hasher.update(payload.as_bytes());
            let independent: [u8; 32] = hasher.finalize().into();
            assert_eq!(hex::encode(independent), *want_checksum, "{payload:?}");
            assert_eq!(
                hex::encode(store_envelope_checksum(kind.domain, payload.as_bytes())),
                *want_checksum,
                "{payload:?}"
            );

            let raw = marshal_store_envelope(*kind, payload.as_bytes()).expect("marshal");
            assert_eq!(String::from_utf8_lossy(&raw), *want_envelope);
            assert!(
                raw.ends_with(b"\n"),
                "envelope must end with exactly one LF"
            );
            let back = open_store_envelope(*kind, &raw).expect("open");
            assert_eq!(back, payload.as_bytes());
        }

        // Domain separation: the same payload under the other tag must not verify.
        assert_ne!(VECTORS[0].2, VECTORS[2].2);
        let raw = marshal_store_envelope(STORE_ENVELOPE_CHAIN_STATE, b"{\"version\":1}\n")
            .expect("marshal");
        assert_eq!(
            open_store_envelope(STORE_ENVELOPE_BLOCK_INDEX, &raw).expect_err("cross-domain"),
            STORE_CHECKSUM_MISMATCH_ERR
        );
    }

    /// One malformed on-disk body. Go twin: `storeIntegrityRow`.
    pub(crate) struct StoreIntegrityRow {
        pub(crate) name: &'static str,
        #[allow(clippy::type_complexity)] // (valid envelope, valid payload) -> planted bytes
        pub(crate) body: Box<dyn Fn(&[u8], &[u8]) -> Vec<u8>>,
        pub(crate) want_msg: Option<&'static str>, // exact, when pinned
        pub(crate) want_sub: Option<&'static str>, // substring, when variable
        /// The inner-schema class is deliberately OUTSIDE STORE_INTEGRITY.
        pub(crate) not_integrity: bool,
    }

    fn replace_once(valid: &[u8], old: &str, new: &str) -> Vec<u8> {
        let text = String::from_utf8_lossy(valid).into_owned();
        let out = text.replacen(old, new, 1);
        assert_ne!(out, text, "row did not modify the envelope");
        out.into_bytes()
    }

    pub(crate) fn checksum_hex_of(valid: &[u8]) -> String {
        let envelope: StoreEnvelopeDisk =
            serde_json::from_slice(valid.strip_suffix(b"\n").unwrap_or(valid))
                .expect("decode valid envelope");
        envelope.checksum
    }

    pub(crate) fn payload_b64_of(valid: &[u8]) -> String {
        let envelope: StoreEnvelopeDisk =
            serde_json::from_slice(valid.strip_suffix(b"\n").unwrap_or(valid))
                .expect("decode valid envelope");
        envelope.payload_b64
    }

    pub(crate) fn rewrap(kind: StoreEnvelopeKind, payload: &[u8]) -> Vec<u8> {
        marshal_store_envelope(kind, payload).expect("marshal")
    }

    /// Replaces the base64 body WITHOUT touching the checksum.
    pub(crate) fn restamp_payload_keeping_checksum(valid: &[u8], payload: &[u8]) -> Vec<u8> {
        replace_once(valid, &payload_b64_of(valid), &base64_encode(payload))
    }

    /// The frame-level rows both protected files must reject identically;
    /// per-file rows are added by each caller.
    #[rustfmt::skip]
    pub(crate) fn shared_reject_rows() -> Vec<StoreIntegrityRow> {
        fn row(name: &'static str, body: fn(&[u8], &[u8]) -> Vec<u8>, want_sub: &'static str) -> StoreIntegrityRow {
            StoreIntegrityRow { name, body: Box::new(body), want_msg: None, want_sub: Some(want_sub), not_integrity: false }
        }
        vec![
            row("empty_file", |_, _| Vec::new(), "is not a single JSON object"),
            row("not_an_object", |_, _| b"[]\n".to_vec(), "is not a single JSON object"),
            row("json_null", |_, _| b"null\n".to_vec(), "is not a single JSON object"),
            row("version_zero", |valid, _| replace_once(valid, "{\"version\":1,", "{\"version\":0,"), "unsupported store envelope version 0"),
            row("version_two", |valid, _| replace_once(valid, "{\"version\":1,", "{\"version\":2,"), "unsupported store envelope version 2"),
            row("version_wrong_type", |valid, _| replace_once(valid, "{\"version\":1,", "{\"version\":\"1\","), "envelope is not the canonical encoding"),
            row("version_null", |valid, _| replace_once(valid, "{\"version\":1,", "{\"version\":null,"), "envelope is not the canonical encoding"),
            row("unknown_field", |valid, _| replace_once(valid, "{\"version\":1,", "{\"version\":1,\"extra\":0,"), "envelope is not the canonical encoding"),
            row("field_order_swapped", |_, payload| {
                format!("{{\"payload_b64\":\"{}\",\"version\":1,\"checksum\":\"{}\"}}\n",
                    base64_encode(payload),
                    hex::encode(store_envelope_checksum(STORE_ENVELOPE_CHAIN_STATE.domain, payload))).into_bytes()
            }, "envelope is not the canonical encoding"),
            // A duplicated field lands INSIDE the derived body slice, so the
            // canonical-base64 check refuses it, identically in both clients.
            row("duplicate_payload_b64_identical", |valid, _| replace_once(valid, ",\"checksum\":\"", ",\"payload_b64\":\"DUPLICATE\",\"checksum\":\""), "payload_b64 is not canonical padded base64"),
            row("duplicate_payload_b64_conflicting", |valid, payload| {
                let mut other = b"x".to_vec();
                other.extend_from_slice(payload);
                replace_once(valid, ",\"checksum\":\"", &format!(",\"payload_b64\":\"{}\",\"checksum\":\"", base64_encode(&other)))
            }, "payload_b64 is not canonical padded base64"),
            row("duplicate_checksum_identical", |valid, _| replace_once(valid, "\"}\n", &format!("\",\"checksum\":\"{}\"}}\n", "0".repeat(64))), "payload_b64 is not canonical padded base64"),
            row("duplicate_checksum_conflicting", |valid, _| replace_once(valid, "\"}\n", &format!("\",\"checksum\":\"{}\"}}\n", "b".repeat(64))), "payload_b64 is not canonical padded base64"),
            row("missing_checksum", |valid, _| replace_once(valid, "\",\"checksum\":\"", "\",\"checksu\":\""), "envelope is not the canonical encoding"),
            row("missing_payload_b64", |valid, _| replace_once(valid, ",\"payload_b64\":\"", ",\"payloadb64\":\""), "envelope is not the canonical encoding"),
            row("trailing_second_json_value", |valid, _| { let mut out = valid.to_vec(); out.extend_from_slice(b"{\"version\":1}"); out }, "envelope is not the canonical encoding"),
            row("no_trailing_newline", |valid, _| valid.strip_suffix(b"\n").unwrap_or(valid).to_vec(), "envelope is not the canonical encoding"),
            row("leading_whitespace", |valid, _| { let mut out = b" ".to_vec(); out.extend_from_slice(valid); out }, "envelope is not the canonical encoding"),
            row("checksum_uppercase_hex", |valid, _| replace_once(valid, &checksum_hex_of(valid), &checksum_hex_of(valid).to_uppercase()), "checksum must be 64 lowercase hex characters"),
            row("checksum_not_hex", |valid, _| replace_once(valid, &checksum_hex_of(valid), &"z".repeat(64)), "checksum must be 64 lowercase hex characters"),
            row("checksum_short", |valid, _| replace_once(valid, &checksum_hex_of(valid), &"a".repeat(63)), "envelope is not the canonical encoding"),
            row("payload_b64_unpadded", |_, payload| {
                format!("{{\"version\":1,\"payload_b64\":\"{}\",\"checksum\":\"{}\"}}\n",
                    base64_encode(payload).trim_end_matches('='),
                    hex::encode(store_envelope_checksum(STORE_ENVELOPE_CHAIN_STATE.domain, payload))).into_bytes()
            }, "payload_b64 is not canonical padded base64"),
            row("payload_b64_embedded_newline", |_, payload| {
                let encoded = base64_encode(payload);
                format!("{{\"version\":1,\"payload_b64\":\"{}\\n{}\",\"checksum\":\"{}\"}}\n",
                    &encoded[..4], &encoded[4..],
                    hex::encode(store_envelope_checksum(STORE_ENVELOPE_CHAIN_STATE.domain, payload))).into_bytes()
            }, "payload_b64 is not canonical padded base64"),
            StoreIntegrityRow { name: "checksum_mismatch_zeroed", body: Box::new(|valid, _| replace_once(valid, &checksum_hex_of(valid), &"0".repeat(64))), want_msg: Some(STORE_CHECKSUM_MISMATCH_ERR), want_sub: None, not_integrity: false },
            // Stays canonical base64, so only the checksum can catch it.
            StoreIntegrityRow { name: "payload_base64_bitflip", body: Box::new(|valid, _| { let encoded = payload_b64_of(valid); replace_once(valid, &encoded, &flip_base64_symbol(&encoded)) }), want_msg: Some(STORE_CHECKSUM_MISMATCH_ERR), want_sub: None, not_integrity: false },
        ]
    }

    fn flip_base64_symbol(value: &str) -> String {
        let replacement = if value.as_bytes()[1] == b'A' {
            'B'
        } else {
            'A'
        };
        format!("{}{replacement}{}", &value[..1], &value[2..])
    }

    /// Plants each row at `path`, calls `load`, and pins the message, the
    /// STORE_INTEGRITY identity, and that the refusal never rewrote the file.
    pub(crate) fn run_store_integrity_rows(
        path: &std::path::Path,
        valid: &[u8],
        payload: &[u8],
        mut load: impl FnMut() -> Result<(), String>,
        rows: &[StoreIntegrityRow],
    ) {
        for row in rows {
            let body = (row.body)(valid, payload);
            std::fs::write(path, &body).expect("plant body");
            let err = load().expect_err(row.name);
            if let Some(want) = row.want_msg {
                assert_eq!(err, want, "{}", row.name);
            }
            if let Some(want) = row.want_sub {
                assert!(err.contains(want), "{}: {err}", row.name);
            }
            assert_eq!(
                err.starts_with(STORE_INTEGRITY_PREFIX),
                !row.not_integrity,
                "{}: {err}",
                row.name
            );
            assert_eq!(
                std::fs::read(path).expect("read back"),
                body,
                "{}: a failed load rewrote the file",
                row.name
            );
        }
    }
}
