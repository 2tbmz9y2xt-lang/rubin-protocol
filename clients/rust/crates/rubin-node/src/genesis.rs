use std::fs;
use std::path::Path;

use rubin_consensus::constants::{
    MAX_WITNESS_BYTES_PER_TX, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87,
    SUITE_ID_SENTINEL, VERIFY_COST_ML_DSA_87,
};
use rubin_consensus::encode_compact_size;
use rubin_consensus::{
    block_hash, canonical_rotation_network_name_normalized, core_ext_profile_set_anchor_v1,
    core_ext_verification_binding_from_name_and_descriptor,
    is_v1_production_rotation_network_normalized, normalized_rotation_network_name,
    validate_rotation_descriptor_for_normalized_network, CoreExtDeploymentProfile,
    CoreExtDeploymentProfiles, CryptoRotationDescriptor, DefaultRotationProvider,
    DescriptorRotationProvider, SuiteParams, SuiteRegistry, BLOCK_HEADER_BYTES,
    SUPPORTED_ROTATION_NETWORK_NAMES_CSV,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const GENESIS_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000006f732e615e2f43337a53e9884adba7da32257d5bb5701adc7ed0bd406f2df91340e49e6900000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000";
const GENESIS_TX_HEX: &str = "01000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200407a10f35a0000000021018448b91b88d1a6fbb65e872b72c381b2a9f3ce286a232f56309667f639dd72790000000000000000020020b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8000000000000";
const GENESIS_CHAIN_ID_HEX: &str =
    "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103";
const MAX_SUITE_REGISTRY_PARAM_LEN: u64 = MAX_WITNESS_BYTES_PER_TX as u64;
pub const PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR: &str =
    "rotation_descriptor: production networks forbid local rotation_descriptor";
#[cfg(test)]
const GENESIS_MAGIC_SEPARATOR: &[u8] = b"RUBIN-GENESIS-v1";

#[derive(Deserialize)]
struct GenesisPack {
    chain_id_hex: String,
    #[serde(default)]
    genesis_hash_hex: String,
    #[serde(default)]
    core_ext_profile_set_anchor_hex: String,
    #[serde(default)]
    core_ext_profiles: Vec<GenesisCoreExtProfile>,
    #[serde(default)]
    rotation_descriptor: Option<GenesisRotationDescriptor>,
    #[serde(default)]
    suite_registry: Vec<GenesisSuiteParams>,
}

/// JSON-serializable rotation descriptor for genesis/config.
/// When present, constructs a DescriptorRotationProvider.
/// When absent, DefaultRotationProvider is used (ML-DSA-87 at all heights).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct GenesisRotationDescriptor {
    name: String,
    old_suite_id: u8,
    new_suite_id: u8,
    create_height: u64,
    spend_height: u64,
    #[serde(default)]
    sunset_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GenesisSuiteParams {
    suite_id: u8,
    pubkey_len: u64,
    sig_len: u64,
    verify_cost: u64,
    alg_name: String,
}

#[derive(Deserialize)]
struct GenesisSuiteParamsWire {
    suite_id: u8,
    pubkey_len: u64,
    sig_len: u64,
    verify_cost: u64,
    #[serde(default)]
    alg_name: Option<String>,
    #[serde(default)]
    openssl_alg: Option<String>,
}

impl<'de> Deserialize<'de> for GenesisSuiteParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = GenesisSuiteParamsWire::deserialize(deserializer)?;
        let alg_name = if let Some(value) = wire.alg_name {
            value
        } else {
            wire.openssl_alg.unwrap_or_default()
        };
        Ok(Self {
            suite_id: wire.suite_id,
            pubkey_len: wire.pubkey_len,
            sig_len: wire.sig_len,
            verify_cost: wire.verify_cost,
            alg_name,
        })
    }
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
    #[serde(default)]
    governance_nonce: u64,
}

#[derive(Clone, Debug)]
pub struct LoadedGenesisConfig {
    pub chain_id: [u8; 32],
    pub genesis_hash: Option<[u8; 32]>,
    pub core_ext_deployments: CoreExtDeploymentProfiles,
    /// Optional SuiteContext built from rotation_descriptor or suite_registry config.
    /// None means use the implicit default registry/provider with no explicit suite overlay.
    pub suite_context: Option<crate::sync::SuiteContext>,
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

pub fn devnet_genesis_hash() -> [u8; 32] {
    let bytes = devnet_genesis_block_bytes();
    block_hash(&bytes[..BLOCK_HEADER_BYTES]).expect("devnet genesis hash")
}

pub fn load_genesis_config(
    path: Option<&Path>,
    network: &str,
) -> Result<LoadedGenesisConfig, String> {
    let Some(path) = path else {
        return Ok(LoadedGenesisConfig {
            chain_id: devnet_genesis_chain_id(),
            genesis_hash: Some(devnet_genesis_hash()),
            core_ext_deployments: CoreExtDeploymentProfiles::empty(),
            suite_context: None,
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
    let genesis_hash = if payload.genesis_hash_hex.trim().is_empty() {
        if chain_id == devnet_genesis_chain_id() {
            Some(devnet_genesis_hash())
        } else {
            None
        }
    } else {
        Some(parse_hex32(
            "genesis_hash",
            payload.genesis_hash_hex.trim(),
        )?)
    };
    Ok(LoadedGenesisConfig {
        chain_id,
        genesis_hash,
        core_ext_deployments: core_ext_deployments_from_json(
            chain_id,
            &payload.core_ext_profile_set_anchor_hex,
            &payload.core_ext_profiles,
        )?,
        suite_context: build_suite_context_from_descriptor(
            &payload.rotation_descriptor,
            &payload.suite_registry,
            network,
        )?,
    })
}

fn normalize_suite_alg_name(value: &str) -> Result<&'static str, String> {
    match value.trim() {
        "ML-DSA-87" => Ok("ML-DSA-87"),
        _ => Err("bad suite_registry".to_string()),
    }
}

fn default_suite_registry_params() -> SuiteParams {
    SuiteParams {
        suite_id: SUITE_ID_ML_DSA_87,
        pubkey_len: ML_DSA_87_PUBKEY_BYTES,
        sig_len: ML_DSA_87_SIG_BYTES,
        verify_cost: VERIFY_COST_ML_DSA_87,
        alg_name: "ML-DSA-87",
    }
}

const MAX_EXPLICIT_SUITE_REGISTRY_ITEMS: usize = 16;

fn validate_suite_registry_param_len(value: u64) -> Result<u64, String> {
    if value == 0 || value > usize::MAX as u64 || value > MAX_SUITE_REGISTRY_PARAM_LEN {
        return Err("bad suite_registry".to_string());
    }
    Ok(value)
}

fn validate_suite_registry_item(item: &GenesisSuiteParams) -> Result<SuiteParams, String> {
    if item.suite_id == SUITE_ID_SENTINEL || item.verify_cost == 0 {
        return Err("bad suite_registry".to_string());
    }
    let pubkey_len = validate_suite_registry_param_len(item.pubkey_len)?;
    let sig_len = validate_suite_registry_param_len(item.sig_len)?;
    let params = SuiteParams {
        suite_id: item.suite_id,
        pubkey_len,
        sig_len,
        verify_cost: item.verify_cost,
        alg_name: normalize_suite_alg_name(&item.alg_name)?,
    };
    let want = default_suite_registry_params();
    if params.pubkey_len != want.pubkey_len
        || params.sig_len != want.sig_len
        || params.verify_cost != want.verify_cost
    {
        return Err("bad suite_registry".to_string());
    }
    Ok(params)
}

fn build_suite_registry_from_json(
    items: &[GenesisSuiteParams],
) -> Result<Option<SuiteRegistry>, String> {
    if items.is_empty() {
        return Ok(None);
    }
    if items.len() > MAX_EXPLICIT_SUITE_REGISTRY_ITEMS {
        return Err("bad suite_registry".to_string());
    }
    let mut suites = BTreeMap::new();
    suites.insert(SUITE_ID_ML_DSA_87, default_suite_registry_params());
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item.suite_id) {
            return Err("bad suite_registry".to_string());
        }
        suites.insert(item.suite_id, validate_suite_registry_item(item)?);
    }

    Ok(Some(SuiteRegistry::with_suites(suites)))
}

fn build_suite_context_from_descriptor(
    desc: &Option<GenesisRotationDescriptor>,
    suite_registry: &[GenesisSuiteParams],
    network: &str,
) -> Result<Option<crate::sync::SuiteContext>, String> {
    use std::sync::Arc;
    if network.trim().is_empty() {
        return Err("network is required".to_string());
    }
    let normalized_network = normalized_rotation_network_name(network);
    canonical_rotation_network_name_normalized(normalized_network.as_ref()).ok_or_else(|| {
        format!(
            "unknown network '{}' (expected: {})",
            normalized_network, SUPPORTED_ROTATION_NETWORK_NAMES_CSV,
        )
    })?;
    let registry = build_suite_registry_from_json(suite_registry)?
        .unwrap_or_else(SuiteRegistry::default_registry);
    let registry = Arc::new(registry);
    let rotation: Arc<dyn rubin_consensus::RotationProvider + Send + Sync> = match desc {
        Some(rd) => {
            if is_v1_production_rotation_network_normalized(normalized_network.as_ref()) {
                return Err(PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR.to_string());
            }
            let descriptor = CryptoRotationDescriptor {
                name: rd.name.clone(),
                old_suite_id: rd.old_suite_id,
                new_suite_id: rd.new_suite_id,
                create_height: rd.create_height,
                spend_height: rd.spend_height,
                sunset_height: rd.sunset_height,
            };
            validate_rotation_descriptor_for_normalized_network(
                normalized_network.as_ref(),
                &descriptor,
                &registry,
            )
            .map_err(|e| format!("rotation_descriptor: {e}"))?;
            Arc::new(DescriptorRotationProvider { descriptor })
        }
        None if !suite_registry.is_empty() => Arc::new(DefaultRotationProvider),
        None => return Ok(None),
    };
    Ok(Some(crate::sync::SuiteContext { rotation, registry }))
}

pub fn load_chain_id_from_genesis_file(path: Option<&Path>) -> Result<[u8; 32], String> {
    let Some(path) = path else {
        return Ok(devnet_genesis_chain_id());
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
    parse_hex32("chain_id", trimmed)
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
        if item.tx_context_enabled {
            return Err(format!(
                "tx_context_enabled core_ext profile for ext_id={} requires runtime txcontext verifier wiring",
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
            governance_nonce: item.governance_nonce,
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
    use rubin_consensus::constants::{
        ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
    };
    use rubin_consensus::{
        core_ext_profile_set_anchor_v1, CoreExtDeploymentProfile, CoreExtVerificationBinding,
    };

    use super::{
        derive_devnet_genesis_chain_id, devnet_genesis_block_bytes, devnet_genesis_chain_id,
        devnet_genesis_hash, load_chain_id_from_genesis_file, load_genesis_config,
        validate_incoming_chain_id, PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR,
    };

    fn suite_registry_entry_json(
        suite_id: u8,
        pubkey_len: u64,
        sig_len: u64,
        verify_cost: u64,
        alg_name: &str,
    ) -> String {
        format!(
            "{{\"suite_id\":{suite_id},\"pubkey_len\":{pubkey_len},\"sig_len\":{sig_len},\"verify_cost\":{verify_cost},\"alg_name\":\"{alg_name}\"}}"
        )
    }

    fn canonical_suite_registry_entry_json(suite_id: u8) -> String {
        suite_registry_entry_json(
            suite_id,
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
            VERIFY_COST_ML_DSA_87,
            "ML-DSA-87",
        )
    }

    fn production_rotation_networks() -> [&'static str; 4] {
        ["mainnet", "testnet", " MAINNET ", "\tTestNet\t"]
    }

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

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        assert_eq!(cfg.chain_id, devnet_genesis_chain_id());
        assert_eq!(cfg.genesis_hash, Some(devnet_genesis_hash()));
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
    fn load_genesis_config_accepts_rotation_descriptor_with_explicit_suite_registry_on_devnet() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-rotation-suite-registry-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[\
                    {},\
                    {}\
                  ],\
                  \"rotation_descriptor\":{{\
                    \"name\":\"test-rotation\",\
                    \"old_suite_id\":1,\
                    \"new_suite_id\":2,\
                    \"create_height\":1,\
                    \"spend_height\":5,\
                    \"sunset_height\":10\
                  }}\
                }}",
                canonical_suite_registry_entry_json(1),
                canonical_suite_registry_entry_json(2)
            ),
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        let suite_context = cfg.suite_context.expect("suite context");
        assert!(suite_context.registry.lookup(1).is_some());
        assert!(suite_context.registry.lookup(2).is_some());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_production_rotation_descriptor() {
        for (case_idx, network) in ["mainnet", "testnet", " MAINNET ", "\tTestNet\t"]
            .into_iter()
            .enumerate()
        {
            let dir = std::env::temp_dir().join(format!(
                "rubin-node-genesis-production-rotation-{}-{}",
                case_idx,
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
                    "{{\
                      \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                      \"suite_registry\":[\
                        {},\
                        {}\
                      ],\
                      \"rotation_descriptor\":{{\
                        \"name\":\"prod-rotation\",\
                        \"old_suite_id\":1,\
                        \"new_suite_id\":2,\
                        \"create_height\":1,\
                        \"spend_height\":5,\
                        \"sunset_height\":10\
                      }}\
                    }}",
                    canonical_suite_registry_entry_json(1),
                    canonical_suite_registry_entry_json(2)
                ),
            )
            .expect("write");

            let err = load_genesis_config(Some(&path), network).expect_err("must reject");
            assert_eq!(
                err, PRODUCTION_LOCAL_ROTATION_DESCRIPTOR_ERR,
                "unexpected error for {network}: {err}"
            );

            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn load_genesis_config_accepts_explicit_suite_registry_without_rotation_descriptor() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-only-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[{}]\
                }}",
                canonical_suite_registry_entry_json(66)
            ),
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        let suite_context = cfg.suite_context.expect("suite context");
        assert!(suite_context.registry.lookup(SUITE_ID_ML_DSA_87).is_some());
        let params = suite_context.registry.lookup(66).expect("suite 66");
        assert_eq!(params.verify_cost, VERIFY_COST_ML_DSA_87);
        assert!(suite_context
            .rotation
            .native_spend_suites(0)
            .contains(SUITE_ID_ML_DSA_87));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_accepts_production_suite_registry_without_rotation_descriptor() {
        for (case_idx, network) in production_rotation_networks().into_iter().enumerate() {
            let dir = std::env::temp_dir().join(format!(
                "rubin-node-genesis-suite-registry-production-{}-{}",
                case_idx,
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
                    "{{\
                      \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                      \"suite_registry\":[{}]\
                    }}",
                    canonical_suite_registry_entry_json(66)
                ),
            )
            .expect("write");

            let cfg = load_genesis_config(Some(&path), network).expect("load");
            let suite_context = cfg.suite_context.expect("suite context");
            assert!(suite_context.registry.lookup(SUITE_ID_ML_DSA_87).is_some());
            assert!(suite_context.registry.lookup(66).is_some());

            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn load_genesis_config_rejects_unknown_network_name() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-unknown-network-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\"\
            }",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), " private-net ").expect_err("must reject");
        assert!(
            err.contains("unknown network"),
            "unexpected error for unknown network: {err}"
        );

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_whitespace_only_network_name() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-whitespace-network-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\"\
            }",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "   ").expect_err("must reject");
        assert_eq!(err, "network is required");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_suite_registry_missing_required_field() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-missing-field-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
              \"suite_registry\":[\
                {\"suite_id\":66,\"pubkey_len\":64,\"sig_len\":96,\"alg_name\":\"ML-DSA-87\"}\
              ]\
            }",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert!(err.contains("missing field"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_bad_suite_registry_entry() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-bad-entry-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[\
                    {{\"suite_id\":{},\"pubkey_len\":{},\"sig_len\":{},\"verify_cost\":{},\"alg_name\":\"ML-DSA-87\"}}\
                  ]\
                }}",
                SUITE_ID_ML_DSA_87,
                ML_DSA_87_PUBKEY_BYTES - 1,
                ML_DSA_87_SIG_BYTES,
                VERIFY_COST_ML_DSA_87
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert_eq!(err, "bad suite_registry");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_suite_registry_length_overflow() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-overflow-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
              \"suite_registry\":[\
                {\"suite_id\":66,\"pubkey_len\":1,\"sig_len\":100001,\"verify_cost\":8,\"alg_name\":\"ML-DSA-87\"}\
              ]\
            }",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert_eq!(err, "bad suite_registry");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_empty_suite_registry_alg_name() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-empty-openssl-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[{}]\
                }}",
                suite_registry_entry_json(
                    66,
                    ML_DSA_87_PUBKEY_BYTES,
                    ML_DSA_87_SIG_BYTES,
                    VERIFY_COST_ML_DSA_87,
                    "",
                )
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert_eq!(err, "bad suite_registry");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_alias_suite_registry_alg_name() {
        for (case_idx, alg) in ["ml-dsa-87", "MLDSA87"].into_iter().enumerate() {
            let dir = std::env::temp_dir().join(format!(
                "rubin-node-genesis-suite-registry-alias-openssl-{}-{}",
                case_idx,
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
                    "{{\
                      \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                      \"suite_registry\":[{}]\
                    }}",
                    suite_registry_entry_json(
                        66,
                        ML_DSA_87_PUBKEY_BYTES,
                        ML_DSA_87_SIG_BYTES,
                        VERIFY_COST_ML_DSA_87,
                        alg,
                    )
                ),
            )
            .expect("write");

            let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
            assert_eq!(err, "bad suite_registry");

            std::fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn load_genesis_config_accepts_legacy_suite_registry_openssl_alg_alias() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-legacy-openssl-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[\
                    {{\"suite_id\":66,\"pubkey_len\":{},\"sig_len\":{},\"verify_cost\":{},\"openssl_alg\":\"ML-DSA-87\"}}\
                  ]\
                }}",
                ML_DSA_87_PUBKEY_BYTES,
                ML_DSA_87_SIG_BYTES,
                VERIFY_COST_ML_DSA_87
            ),
        )
        .expect("write");

        let loaded = load_genesis_config(Some(&path), "devnet").expect("must load");
        let ctx = loaded.suite_context.expect("suite context");
        let params = ctx.registry.lookup(66).expect("suite 66");
        assert_eq!(params.alg_name, "ML-DSA-87");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_accepts_dual_suite_registry_keys_with_alg_name_precedence() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-dual-keys-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[\
                    {{\"suite_id\":66,\"pubkey_len\":{},\"sig_len\":{},\"verify_cost\":{},\"alg_name\":\"ML-DSA-87\",\"openssl_alg\":\"ML-DSA-87\"}}\
                  ]\
                }}",
                ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, VERIFY_COST_ML_DSA_87
            ),
        )
        .expect("write");

        let loaded = load_genesis_config(Some(&path), "devnet").expect("must load");
        let ctx = loaded.suite_context.expect("suite context");
        let params = ctx.registry.lookup(66).expect("suite 66");
        assert_eq!(params.alg_name, "ML-DSA-87");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_empty_alg_name_even_with_legacy_alias() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-empty-dual-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[\
                    {{\"suite_id\":66,\"pubkey_len\":{},\"sig_len\":{},\"verify_cost\":{},\"alg_name\":\"\",\"openssl_alg\":\"ML-DSA-87\"}}\
                  ]\
                }}",
                ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, VERIFY_COST_ML_DSA_87
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert_eq!(err, "bad suite_registry");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_noncanonical_ml_dsa_lengths_for_custom_suite() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-noncanonical-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
              \"suite_registry\":[\
                {\"suite_id\":66,\"pubkey_len\":64,\"sig_len\":96,\"verify_cost\":321,\"alg_name\":\"ML-DSA-87\"}\
              ]\
            }",
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert_eq!(err, "bad suite_registry");

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_noncanonical_ml_dsa_verify_cost_for_custom_suite() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-verify-cost-{}",
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
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[{}]\
                }}",
                suite_registry_entry_json(
                    66,
                    ML_DSA_87_PUBKEY_BYTES,
                    ML_DSA_87_SIG_BYTES,
                    321,
                    "ML-DSA-87",
                )
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert!(err.contains("bad suite_registry"));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_oversized_suite_registry() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-suite-registry-too-many-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        let mut entries = String::new();
        for i in 0..(super::MAX_EXPLICIT_SUITE_REGISTRY_ITEMS + 1) {
            if i != 0 {
                entries.push(',');
            }
            entries.push_str(&canonical_suite_registry_entry_json((i + 2) as u8));
        }
        std::fs::write(
            &path,
            format!(
                "{{\
                  \"chain_id_hex\":\"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103\",\
                  \"suite_registry\":[{}]\
                }}",
                entries
            ),
        )
        .expect("write");

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert!(err.contains("bad suite_registry"));

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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        assert_eq!(cfg.genesis_hash, Some(devnet_genesis_hash()));
        assert_eq!(cfg.core_ext_deployments.deployments.len(), 1);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_rejects_tx_context_enabled_profile_without_runtime_verifier() {
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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
        assert!(err.contains(
            "tx_context_enabled core_ext profile for ext_id=7 requires runtime txcontext verifier wiring"
        ));

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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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
                governance_nonce: 0,
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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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

        let err = load_genesis_config(Some(&path), "devnet").unwrap_err();
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

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load genesis");
        assert_eq!(cfg.genesis_hash, Some(devnet_genesis_hash()));
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

    #[test]
    fn load_genesis_config_reads_explicit_genesis_hash() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-explicit-hash-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\
              \"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\",\
              \"genesis_hash_hex\":\"0x2222222222222222222222222222222222222222222222222222222222222222\"\
            }",
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        assert_eq!(cfg.chain_id, [0x11; 32]);
        assert_eq!(cfg.genesis_hash, Some([0x22; 32]));

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn load_genesis_config_leaves_custom_runtime_hash_unset_without_explicit_value() {
        let dir = std::env::temp_dir().join(format!(
            "rubin-node-genesis-missing-hash-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("genesis.json");
        std::fs::write(
            &path,
            "{\"chain_id_hex\":\"0x1111111111111111111111111111111111111111111111111111111111111111\"}",
        )
        .expect("write");

        let cfg = load_genesis_config(Some(&path), "devnet").expect("load");
        assert_eq!(cfg.chain_id, [0x11; 32]);
        assert_eq!(cfg.genesis_hash, None);

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
