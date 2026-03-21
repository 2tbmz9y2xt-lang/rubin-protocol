use std::fs;
use std::path::Path;

use rubin_consensus::encode_compact_size;
use rubin_consensus::{
    core_ext_profile_set_anchor_v1, core_ext_verification_binding_from_name_and_descriptor,
    CoreExtDeploymentProfile, CoreExtDeploymentProfiles,
};
use serde::Deserialize;

const GENESIS_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000";
const GENESIS_TX_HEX: &str = "01000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd72790000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";
const GENESIS_CHAIN_ID_HEX: &str =
    "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103";
#[cfg(test)]
const GENESIS_MAGIC_SEPARATOR: &[u8] = b"RUBIN-GENESIS-v1";

#[derive(Deserialize)]
struct GenesisPack {
    chain_id_hex: String,
    #[serde(default)]
    core_ext_profile_set_anchor_hex: String,
    #[serde(default)]
    core_ext_profiles: Vec<GenesisCoreExtProfile>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct GenesisCoreExtProfile {
    ext_id: u16,
    activation_height: u64,
    #[serde(default)]
    tx_context_enabled: bool,
    #[serde(default)]
    allowed_suite_ids: Vec<u8>,
    #[serde(default)]
    binding: String,
    #[serde(default)]
    binding_descriptor_hex: String,
    #[serde(default)]
    ext_payload_schema_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedGenesisConfig {
    pub chain_id: [u8; 32],
    pub core_ext_deployments: CoreExtDeploymentProfiles,
}

pub fn devnet_genesis_block_bytes() -> Vec<u8> {
    let header = decode_hex_exact("genesis_header", GENESIS_HEADER_HEX, 116);
    let tx = decode_hex_exact("genesis_tx", GENESIS_TX_HEX, 149);
    let mut out = Vec::with_capacity(header.len() + tx.len() + 8);
    out.extend_from_slice(&header);
    encode_compact_size(1, &mut out);
    out.extend_from_slice(&tx);
    out
}

pub fn devnet_genesis_chain_id() -> [u8; 32] {
    decode_hex32("devnet_genesis_chain_id", GENESIS_CHAIN_ID_HEX)
}

pub fn load_genesis_config(path: Option<&Path>) -> Result<LoadedGenesisConfig, String> {
    let Some(path) = path else {
        return Ok(LoadedGenesisConfig {
            chain_id: devnet_genesis_chain_id(),
            core_ext_deployments: CoreExtDeploymentProfiles::empty(),
        });
    };
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("read genesis file {}: {e}", path.display()))?;
    let payload: GenesisPack = serde_json::from_str(&raw)
        .map_err(|e| format!("parse genesis file {}: {e}", path.display()))?;
    let mut trimmed = payload.chain_id_hex.trim();
    if trimmed.is_empty() {
        return Err("chain_id_hex missing".to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("0x") {
        trimmed = rest;
    } else if let Some(rest) = trimmed.strip_prefix("0X") {
        trimmed = rest;
    }
    let chain_id = parse_hex32("chain_id", trimmed)?;
    Ok(LoadedGenesisConfig {
        chain_id,
        core_ext_deployments: core_ext_deployments_from_json(
            chain_id,
            &payload.core_ext_profile_set_anchor_hex,
            &payload.core_ext_profiles,
        )?,
    })
}

pub fn load_chain_id_from_genesis_file(path: Option<&Path>) -> Result<[u8; 32], String> {
    Ok(load_genesis_config(path)?.chain_id)
}

pub fn validate_incoming_chain_id(block_height: u64, chain_id: [u8; 32]) -> Result<(), String> {
    let zero_chain_id = [0u8; 32];
    if block_height == 0 && chain_id != zero_chain_id && chain_id != devnet_genesis_chain_id() {
        return Err("genesis chain_id mismatch".to_string());
    }
    Ok(())
}

#[cfg(test)]
fn derive_devnet_genesis_chain_id() -> [u8; 32] {
    use sha3::{Digest, Sha3_256};

    let header = decode_hex_exact("genesis_header", GENESIS_HEADER_HEX, 116);
    let tx = decode_hex_exact("genesis_tx", GENESIS_TX_HEX, 149);
    let mut preimage =
        Vec::with_capacity(GENESIS_MAGIC_SEPARATOR.len() + header.len() + tx.len() + 8);
    preimage.extend_from_slice(GENESIS_MAGIC_SEPARATOR);
    preimage.extend_from_slice(&header);
    encode_compact_size(1, &mut preimage);
    preimage.extend_from_slice(&tx);
    Sha3_256::digest(&preimage).into()
}

fn decode_hex32(name: &str, value: &str) -> [u8; 32] {
    parse_hex32(name, value).unwrap_or_else(|e| panic!("{e}"))
}

fn decode_hex_exact(name: &str, value: &str, expected_len: usize) -> Vec<u8> {
    let bytes = hex::decode(value).unwrap_or_else(|e| panic!("{name}: {e}"));
    if bytes.len() != expected_len {
        panic!("{name}: expected {expected_len} bytes, got {}", bytes.len());
    }
    bytes
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32], String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(value).map_err(|e| format!("{name}: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("{name}: expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_optional_hex_bytes(name: &str, value: &str) -> Result<Vec<u8>, String> {
    const MAX_CORE_EXT_HEX_FIELD_BYTES: usize = 4096;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if trimmed.len() > MAX_CORE_EXT_HEX_FIELD_BYTES * 2 {
        return Err(format!("bad {name}"));
    }
    hex::decode(trimmed).map_err(|e| format!("{name}: {e}"))
}

fn genesis_core_ext_binding_supported(binding: &str) -> bool {
    let binding = binding.trim();
    matches!(
        binding,
        "" | "native_verify_sig"
            | rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
    )
}

fn core_ext_deployments_from_json(
    chain_id: [u8; 32],
    expected_set_anchor_hex: &str,
    items: &[GenesisCoreExtProfile],
) -> Result<CoreExtDeploymentProfiles, String> {
    let mut seen = std::collections::HashSet::new();
    let mut deployments = Vec::with_capacity(items.len());
    for item in items {
        let binding_name = item.binding.trim();
        if !seen.insert(item.ext_id) {
            return Err(format!(
                "duplicate core_ext deployment for ext_id={}",
                item.ext_id
            ));
        }
        if !genesis_core_ext_binding_supported(binding_name) {
            return Err(format!("unsupported core_ext binding: {}", item.binding));
        }
        let binding_descriptor =
            decode_optional_hex_bytes("binding_descriptor_hex", &item.binding_descriptor_hex)?;
        let ext_payload_schema =
            decode_optional_hex_bytes("ext_payload_schema_hex", &item.ext_payload_schema_hex)?;
        if binding_name == rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
            && ext_payload_schema.is_empty()
        {
            return Err(format!(
                "core_ext binding {} requires ext_payload_schema_hex",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1
            ));
        }
        if item.tx_context_enabled {
            return Err(format!(
                "core_ext ext_id={} txcontext-enabled profile requires runtime verifier wiring",
                item.ext_id
            ));
        }
        let verification_binding = core_ext_verification_binding_from_name_and_descriptor(
            binding_name,
            &binding_descriptor,
        )?;
        deployments.push(CoreExtDeploymentProfile {
            ext_id: item.ext_id,
            activation_height: item.activation_height,
            tx_context_enabled: item.tx_context_enabled,
            allowed_suite_ids: item.allowed_suite_ids.clone(),
            verification_binding,
            verify_sig_ext_tx_context_fn: None,
            binding_descriptor,
            ext_payload_schema,
        });
    }
    let profiles = CoreExtDeploymentProfiles { deployments };
    profiles.validate()?;
    if !expected_set_anchor_hex.trim().is_empty() {
        let expected = parse_hex32("core_ext_profile_set_anchor_hex", expected_set_anchor_hex)?;
        let actual = core_ext_profile_set_anchor_v1(chain_id, &profiles.deployments)?;
        if actual != expected {
            return Err("core_ext profile set anchor mismatch".to_string());
        }
    }
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use rubin_consensus::{
        core_ext_profile_set_anchor_v1, CoreExtDeploymentProfile, CoreExtVerificationBinding,
    };

    use super::{
        derive_devnet_genesis_chain_id, devnet_genesis_block_bytes, devnet_genesis_chain_id,
        load_chain_id_from_genesis_file, load_genesis_config, validate_incoming_chain_id,
    };

    #[test]
    fn derived_devnet_chain_id_matches_constant() {
        assert_eq!(derive_devnet_genesis_chain_id(), devnet_genesis_chain_id());
    }

    #[test]
    fn devnet_genesis_block_bytes_have_expected_frame() {
        let block = devnet_genesis_block_bytes();
        assert_eq!(block.len(), 116 + 1 + 149);
        assert_eq!(block[116], 0x01);
    }

    #[test]
    fn load_chain_id_defaults_to_devnet_when_genesis_file_absent() {
        let got = load_chain_id_from_genesis_file(None).expect("default chain_id");
        assert_eq!(got, devnet_genesis_chain_id());
    }

    #[test]
    fn load_chain_id_reads_chain_id_from_json() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\"}",
        )
        .expect("write");

        let got = load_chain_id_from_genesis_file(Some(&path)).expect("load");
        assert_eq!(got, devnet_genesis_chain_id());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_reads_core_ext_profiles() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let binding_descriptor =
            rubin_consensus::core_ext_openssl_digest32_binding_descriptor_bytes(
                "ML-DSA-87",
                rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            )
            .expect("descriptor");
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"{}\",\"binding_descriptor_hex\":\"{}\",\"ext_payload_schema_hex\":\"b2\"}}]}}",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                hex::encode(binding_descriptor),
            ),
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path)).expect("load");
        assert_eq!(cfg.chain_id, devnet_genesis_chain_id());
        assert_eq!(cfg.core_ext_deployments.deployments.len(), 1);
        assert_eq!(cfg.core_ext_deployments.deployments[0].ext_id, 7);
        assert_eq!(
            cfg.core_ext_deployments.deployments[0].activation_height,
            12
        );
        assert!(!cfg.core_ext_deployments.deployments[0].tx_context_enabled);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_empty_core_ext_allowed_suite_ids() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-empty-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[],\"binding\":\"native_verify_sig\"}]}",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("non-empty allowed_suite_ids"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_reads_openssl_digest32_core_ext_profile() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-openssl-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let binding_descriptor =
            rubin_consensus::core_ext_openssl_digest32_binding_descriptor_bytes(
                "ML-DSA-87",
                rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            )
            .expect("descriptor");
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"{}\",\"binding_descriptor_hex\":\"{}\",\"ext_payload_schema_hex\":\"b2\"}}]}}",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                hex::encode(binding_descriptor)
            ),
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path)).expect("load");
        assert_eq!(cfg.core_ext_deployments.deployments.len(), 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_tx_context_enabled_until_runtime_verifier_lands() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-txcontext-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{\"ext_id\":7,\"activation_height\":12,\"tx_context_enabled\":true,\"allowed_suite_ids\":[3],\"binding\":\"native_verify_sig\"}]}",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("requires runtime verifier wiring"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_non_boolean_tx_context_enabled() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-invalid-txcontext-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{\"ext_id\":7,\"activation_height\":12,\"tx_context_enabled\":1,\"allowed_suite_ids\":[3],\"binding\":\"native_verify_sig\"}]}",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("expected a boolean"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_openssl_digest32_binding_without_payload_schema() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-openssl-missing-schema-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let binding_descriptor =
            rubin_consensus::core_ext_openssl_digest32_binding_descriptor_bytes(
                "ML-DSA-87",
                rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            )
            .expect("descriptor");
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"{}\",\"binding_descriptor_hex\":\"{}\"}}]}}",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                hex::encode(binding_descriptor)
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("requires ext_payload_schema_hex"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_core_ext_profile_set_anchor_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-anchor-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let binding_descriptor =
            rubin_consensus::core_ext_openssl_digest32_binding_descriptor_bytes(
                "ML-DSA-87",
                rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            )
            .expect("descriptor");
        let descriptor = rubin_consensus::parse_core_ext_openssl_digest32_binding_descriptor(
            &binding_descriptor,
        )
        .expect("parse");
        let mut anchor = core_ext_profile_set_anchor_v1(
            devnet_genesis_chain_id(),
            &[CoreExtDeploymentProfile {
                ext_id: 7,
                activation_height: 12,
                tx_context_enabled: false,
                allowed_suite_ids: vec![3],
                verification_binding: CoreExtVerificationBinding::VerifySigExtOpenSslDigest32V1(
                    descriptor,
                ),
                verify_sig_ext_tx_context_fn: None,
                binding_descriptor: binding_descriptor.clone(),
                ext_payload_schema: vec![0xb2],
            }],
        )
        .expect("anchor");
        anchor[0] ^= 0xff;
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profile_set_anchor_hex\":\"0x{}\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"{}\",\"binding_descriptor_hex\":\"{}\",\"ext_payload_schema_hex\":\"b2\"}}]}}",
                hex::encode(anchor),
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                hex::encode(binding_descriptor),
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("anchor mismatch"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_oversized_core_ext_hex_fields() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-oversized-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"{}\",\"binding_descriptor_hex\":\"{}\",\"ext_payload_schema_hex\":\"b2\"}}]}}",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                "aa".repeat(4097)
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("bad binding_descriptor_hex"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_unsupported_binding_before_hex_decode() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-unsupported-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"unknown-binding\",\"binding_descriptor_hex\":\"zz\",\"ext_payload_schema_hex\":\"zz\"}]}",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path)).unwrap_err();
        assert!(err.contains("unsupported core_ext binding"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_accepts_whitespace_wrapped_binding() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-core-ext-whitespace-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let binding_descriptor =
            rubin_consensus::core_ext_openssl_digest32_binding_descriptor_bytes(
                "ML-DSA-87",
                rubin_consensus::constants::ML_DSA_87_PUBKEY_BYTES,
                rubin_consensus::constants::ML_DSA_87_SIG_BYTES,
            )
            .expect("descriptor");
        std::fs::write(
            &path,
            format!(
                "{{\"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\"core_ext_profiles\":[{{\"ext_id\":7,\"activation_height\":12,\"allowed_suite_ids\":[3],\"binding\":\"  {}\\n\",\"binding_descriptor_hex\":\"{}\",\"ext_payload_schema_hex\":\"b2\"}}]}}",
                rubin_consensus::CORE_EXT_BINDING_NAME_VERIFY_SIG_EXT_OPENSSL_DIGEST32_V1,
                hex::encode(binding_descriptor),
            ),
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path)).expect("load genesis");
        let profiles = cfg
            .core_ext_deployments
            .active_profiles_at_height(12)
            .expect("active profiles");
        assert_eq!(profiles.active.len(), 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn validate_incoming_chain_id_accepts_zero_chain_id_at_genesis() {
        validate_incoming_chain_id(0, [0u8; 32]).expect("zero chain_id should skip genesis guard");
    }

    #[test]
    fn validate_incoming_chain_id_rejects_wrong_non_zero_genesis_chain_id() {
        let err = validate_incoming_chain_id(0, [0x11; 32]).unwrap_err();
        assert_eq!(err, "genesis chain_id mismatch");
    }
}
