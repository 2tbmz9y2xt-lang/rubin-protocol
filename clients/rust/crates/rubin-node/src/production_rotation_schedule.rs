use rubin_consensus::constants::SUITE_ID_SENTINEL;
use rubin_consensus::{
    validate_rotation_descriptor_for_normalized_network, CryptoRotationDescriptor, SuiteRegistry,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PRODUCTION_ROTATION_SCHEDULE_VERSION: u64 = 1;
pub(crate) const PRODUCTION_ROTATION_SCHEDULE_ERR_STEM: &str = "production_rotation_schedule";

// Derived runtime copy of conformance/fixtures/protocol/production_rotation_schedule_v1.json.
// Rust keeps a client-local embed, and tests pin JSON-equivalence to the
// canonical protocol fixture so Go/Rust update through the same rebuild path.
const PRODUCTION_ROTATION_SCHEDULE_V1_JSON: &str =
    include_str!("production_rotation_schedule_v1_embedded.json");

#[derive(Debug)]
pub(crate) struct ProductionRotationSchedule {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) version: u64,
    pub(crate) mainnet: Option<CryptoRotationDescriptor>,
    pub(crate) testnet: Option<CryptoRotationDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionRotationScheduleWire {
    version: u64,
    networks: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionRotationDescriptorWire {
    name: String,
    old_suite_id: u8,
    new_suite_id: u8,
    create_height: u64,
    spend_height: u64,
    sunset_height: Option<u64>,
}

fn production_rotation_schedule_error(message: impl Into<String>) -> String {
    format!(
        "{PRODUCTION_ROTATION_SCHEDULE_ERR_STEM}: {}",
        message.into()
    )
}

fn decode_single_json_value<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let value = T::deserialize(&mut deserializer).map_err(|err| err.to_string())?;
    match Value::deserialize(&mut deserializer) {
        Ok(_) => return Err("trailing JSON tokens".to_owned()),
        Err(err) if err.is_eof() => {}
        Err(err) => return Err(err.to_string()),
    }
    Ok(value)
}

fn parse_descriptor_slot_wire(
    value: Value,
    network: &str,
) -> Result<Option<ProductionRotationDescriptorWire>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let descriptor_wire: ProductionRotationDescriptorWire = serde_json::from_value(value)
        .map_err(|err| production_rotation_schedule_error(format!("networks.{network}: {err}")))?;
    reject_reserved_suite_id("old_suite_id", descriptor_wire.old_suite_id)
        .map_err(|err| production_rotation_schedule_error(format!("networks.{network}: {err}")))?;
    reject_reserved_suite_id("new_suite_id", descriptor_wire.new_suite_id)
        .map_err(|err| production_rotation_schedule_error(format!("networks.{network}: {err}")))?;
    Ok(Some(descriptor_wire))
}

fn reject_reserved_suite_id(field: &str, suite_id: u8) -> Result<(), String> {
    if suite_id == SUITE_ID_SENTINEL {
        return Err(format!("{field} 0x{suite_id:02x} reserved"));
    }
    Ok(())
}

fn validate_descriptor_wire(
    descriptor_wire: Option<ProductionRotationDescriptorWire>,
    network: &str,
    registry: &SuiteRegistry,
) -> Result<Option<CryptoRotationDescriptor>, String> {
    let Some(descriptor_wire) = descriptor_wire else {
        return Ok(None);
    };
    let descriptor = descriptor_wire.into_descriptor();
    validate_rotation_descriptor_for_normalized_network(network, &descriptor, registry).map_err(
        |err| {
            production_rotation_schedule_error(format!(
                "networks.{network}: rotation_descriptor: {err}"
            ))
        },
    )?;
    Ok(Some(descriptor))
}

fn parse_schedule_with_registry(
    raw: &str,
    registry: Option<SuiteRegistry>,
) -> Result<(ProductionRotationSchedule, SuiteRegistry), String> {
    let wire: ProductionRotationScheduleWire = decode_single_json_value(raw).map_err(|err| {
        production_rotation_schedule_error(format!("parse embedded artifact: {err}"))
    })?;
    if wire.version != PRODUCTION_ROTATION_SCHEDULE_VERSION {
        return Err(production_rotation_schedule_error(format!(
            "unsupported version {} (want {})",
            wire.version, PRODUCTION_ROTATION_SCHEDULE_VERSION
        )));
    }
    let mut networks = wire.networks;
    for key in networks.keys() {
        if key != "mainnet" && key != "testnet" {
            return Err(production_rotation_schedule_error(format!(
                "unknown networks.{key} entry"
            )));
        }
    }
    let mainnet_wire = parse_descriptor_slot_wire(
        networks
            .remove("mainnet")
            .ok_or_else(|| production_rotation_schedule_error("networks.mainnet missing"))?,
        "mainnet",
    )?;
    let testnet_wire = parse_descriptor_slot_wire(
        networks
            .remove("testnet")
            .ok_or_else(|| production_rotation_schedule_error("networks.testnet missing"))?,
        "testnet",
    )?;
    // The compiled production schedule is activation-only authority. Without an
    // explicit canonical registry contract from the caller, fail closed to the
    // default live manifest instead of synthesizing suite params from schedule
    // IDs.
    let registry = registry.unwrap_or_else(SuiteRegistry::default_registry);
    let mainnet = validate_descriptor_wire(mainnet_wire, "mainnet", &registry)?;
    let testnet = validate_descriptor_wire(testnet_wire, "testnet", &registry)?;
    Ok((
        ProductionRotationSchedule {
            version: wire.version,
            mainnet,
            testnet,
        },
        registry,
    ))
}

pub(crate) fn load_compiled_production_rotation_schedule(
) -> Result<(ProductionRotationSchedule, SuiteRegistry), String> {
    parse_schedule_with_registry(PRODUCTION_ROTATION_SCHEDULE_V1_JSON, None)
}

pub(crate) fn production_rotation_descriptor_for_network(
    network: &str,
) -> Result<(Option<CryptoRotationDescriptor>, SuiteRegistry), String> {
    let (schedule, registry) = load_compiled_production_rotation_schedule()?;
    let descriptor = match network {
        "mainnet" => schedule.mainnet,
        "testnet" => schedule.testnet,
        _ => {
            return Err(production_rotation_schedule_error(format!(
                "network '{network}' is not a production schedule caller"
            )))
        }
    };
    if descriptor.is_none() {
        // A null slot means this network has no authoritative production activation state.
        // Empty-slot callers must use the canonical default pre-rotation registry and must
        // not inherit foreign-network suites from the compiled schedule.
        return Ok((None, SuiteRegistry::default_registry()));
    }
    Ok((descriptor, registry))
}

#[cfg(test)]
pub(crate) fn production_rotation_descriptor_for_network_with_registry_for_test(
    raw: &str,
    network: &str,
    registry: SuiteRegistry,
) -> Result<(Option<CryptoRotationDescriptor>, SuiteRegistry), String> {
    let (schedule, registry) = parse_schedule_with_registry(raw, Some(registry))?;
    let descriptor = match network {
        "mainnet" => schedule.mainnet,
        "testnet" => schedule.testnet,
        _ => {
            return Err(production_rotation_schedule_error(format!(
                "network '{network}' is not a production schedule caller"
            )))
        }
    };
    if descriptor.is_none() {
        return Ok((None, SuiteRegistry::default_registry()));
    }
    Ok((descriptor, registry))
}

impl ProductionRotationDescriptorWire {
    fn into_descriptor(self) -> CryptoRotationDescriptor {
        CryptoRotationDescriptor {
            name: self.name,
            old_suite_id: self.old_suite_id,
            new_suite_id: self.new_suite_id,
            create_height: self.create_height,
            spend_height: self.spend_height,
            sunset_height: self.sunset_height.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        load_compiled_production_rotation_schedule, parse_schedule_with_registry,
        production_rotation_descriptor_for_network,
        production_rotation_descriptor_for_network_with_registry_for_test,
        PRODUCTION_ROTATION_SCHEDULE_ERR_STEM, PRODUCTION_ROTATION_SCHEDULE_V1_JSON,
        PRODUCTION_ROTATION_SCHEDULE_VERSION,
    };
    use rubin_consensus::constants::{
        ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
    };
    use rubin_consensus::{SuiteParams, SuiteRegistry};
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn production_rotation_schedule_repo_path(parts: &[&str]) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../../../");
        for part in parts {
            path.push(part);
        }
        path
    }

    fn compact_json_bytes(raw: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::from_str::<Value>(raw).expect("compact json"))
            .expect("serialize compact json")
    }

    fn canonical_production_schedule_registry() -> SuiteRegistry {
        let mut suites = BTreeMap::new();
        suites.insert(
            SUITE_ID_ML_DSA_87,
            SuiteParams {
                suite_id: SUITE_ID_ML_DSA_87,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            66,
            SuiteParams {
                suite_id: 66,
                pubkey_len: ML_DSA_87_PUBKEY_BYTES,
                sig_len: ML_DSA_87_SIG_BYTES,
                verify_cost: VERIFY_COST_ML_DSA_87,
                alg_name: "ML-DSA-87",
            },
        );
        SuiteRegistry::with_suites(suites)
    }

    #[test]
    fn load_compiled_production_rotation_schedule_accepts_explicit_empty_schedule() {
        let (schedule, registry) =
            load_compiled_production_rotation_schedule().expect("load compiled schedule");
        assert_eq!(schedule.version, PRODUCTION_ROTATION_SCHEDULE_VERSION);
        assert!(schedule.mainnet.is_none());
        assert!(schedule.testnet.is_none());
        assert!(registry.is_canonical_default_live_manifest());
    }

    #[test]
    fn embedded_production_rotation_schedule_matches_canonical_fixture() {
        let path = production_rotation_schedule_repo_path(&[
            "conformance",
            "fixtures",
            "protocol",
            "production_rotation_schedule_v1.json",
        ]);
        let raw = fs::read_to_string(&path).expect("read canonical production schedule fixture");
        assert_eq!(
            compact_json_bytes(&raw),
            compact_json_bytes(PRODUCTION_ROTATION_SCHEDULE_V1_JSON),
            "embedded production schedule drifted from canonical fixture"
        );
    }

    #[test]
    fn production_rotation_descriptor_for_network_returns_default_registry_for_explicit_empty_schedule(
    ) {
        let (mainnet_desc, mainnet_registry) =
            production_rotation_descriptor_for_network("mainnet").expect("mainnet schedule");
        assert!(mainnet_desc.is_none());
        assert!(mainnet_registry.is_canonical_default_live_manifest());
        assert!(mainnet_registry.lookup(66).is_none());

        let (testnet_desc, testnet_registry) =
            production_rotation_descriptor_for_network("testnet").expect("testnet schedule");
        assert!(testnet_desc.is_none());
        assert!(testnet_registry.is_canonical_default_live_manifest());
        assert!(testnet_registry.lookup(66).is_none());
    }

    #[test]
    fn production_rotation_schedule_rejects_unsupported_version() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 2,
                "networks": {"mainnet": null, "testnet": null}
            }"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: unsupported version 2 (want 1)"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_missing_network_key() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": null}
            }"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: networks.testnet missing"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_reserved_sentinel_suite_id() {
        for (field_name, old_suite_id, new_suite_id, want) in [
            (
                "old_suite_id",
                0,
                66,
                "production_rotation_schedule: networks.mainnet: old_suite_id 0x00 reserved",
            ),
            (
                "new_suite_id",
                1,
                0,
                "production_rotation_schedule: networks.mainnet: new_suite_id 0x00 reserved",
            ),
        ] {
            let err = production_rotation_descriptor_for_network_with_registry_for_test(
                &format!(
                    r#"{{
                        "version": 1,
                        "networks": {{
                            "mainnet": {{
                                "name": "rotation-v1",
                                "old_suite_id": {old_suite_id},
                                "new_suite_id": {new_suite_id},
                                "create_height": 10,
                                "spend_height": 20,
                                "sunset_height": 30
                            }},
                            "testnet": null
                        }}
                    }}"#
                ),
                "mainnet",
                canonical_production_schedule_registry(),
            )
            .expect_err("must reject");
            assert_eq!(err, want, "field {field_name}");
        }
    }

    #[test]
    fn production_rotation_schedule_rejects_unknown_network_key() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": null, "devnet": null}
            }"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: unknown networks.devnet entry"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_malformed_descriptor_shape() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": [], "testnet": null}
            }"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert!(err.contains("networks.mainnet"), "unexpected error: {err}");
        assert!(err.contains(PRODUCTION_ROTATION_SCHEDULE_ERR_STEM));
    }

    #[test]
    fn production_rotation_schedule_parses_single_descriptor_with_canonical_registry() {
        let loaded = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {
                    "mainnet": {
                        "name": "rotation-v1",
                        "old_suite_id": 1,
                        "new_suite_id": 66,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 30
                    },
                    "testnet": null
                }
            }"#,
            "mainnet",
            canonical_production_schedule_registry(),
        )
        .expect("must load");
        let descriptor = loaded.0.expect("descriptor");
        let registry = loaded.1;
        assert_eq!(descriptor.old_suite_id, 1);
        assert_eq!(descriptor.new_suite_id, 66);
        assert!(registry.lookup(66).is_some());
    }

    #[test]
    fn production_rotation_schedule_implicit_registry_rejects_unsanctioned_scheduled_suite() {
        let err = parse_schedule_with_registry(
            r#"{
                "version": 1,
                "networks": {
                    "mainnet": {
                        "name": "rotation-v1",
                        "old_suite_id": 1,
                        "new_suite_id": 66,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 30
                    },
                    "testnet": null
                }
            }"#,
            None,
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: networks.mainnet: rotation_descriptor: rotation: new suite 0x42 not registered"
        );
    }

    #[test]
    fn production_rotation_schedule_implicit_registry_rejects_foreign_slot_suite_ids() {
        let err = parse_schedule_with_registry(
            r#"{
                "version": 1,
                "networks": {
                    "mainnet": null,
                    "testnet": {
                        "name": "rotation-v1",
                        "old_suite_id": 1,
                        "new_suite_id": 66,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 30
                    }
                }
            }"#,
            None,
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: networks.testnet: rotation_descriptor: rotation: new suite 0x42 not registered"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_null_sunset_height_on_production_profile() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {
                    "mainnet": {
                        "name": "rotation-v1",
                        "old_suite_id": 1,
                        "new_suite_id": 66,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": null
                    },
                    "testnet": null
                }
            }"#,
            "mainnet",
            canonical_production_schedule_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: networks.mainnet: rotation_descriptor: rotation: v1 production profile requires finite sunset_height (H4)"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_trailing_json_tokens() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": null, "testnet": null}
            } true"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: parse embedded artifact: trailing JSON tokens"
        );
    }

    #[test]
    fn production_rotation_schedule_rejects_second_json_value() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": null, "testnet": null}
            } {"version":1,"networks":{"mainnet":null,"testnet":null}}"#,
            "mainnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: parse embedded artifact: trailing JSON tokens"
        );
    }

    #[test]
    fn production_rotation_descriptor_for_network_rejects_non_production_caller() {
        let err = production_rotation_descriptor_for_network_with_registry_for_test(
            r#"{
                "version": 1,
                "networks": {"mainnet": null, "testnet": null}
            }"#,
            "devnet",
            SuiteRegistry::default_registry(),
        )
        .expect_err("must reject");
        assert_eq!(
            err,
            "production_rotation_schedule: network 'devnet' is not a production schedule caller"
        );
    }
}
