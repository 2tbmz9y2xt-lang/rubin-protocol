use rubin_consensus::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
};
use rubin_consensus::{
    validate_rotation_descriptor_for_normalized_network, CryptoRotationDescriptor, SuiteParams,
    SuiteRegistry,
};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const PRODUCTION_ROTATION_SCHEDULE_VERSION: u64 = 1;
pub(crate) const PRODUCTION_ROTATION_SCHEDULE_ERR_STEM: &str = "production_rotation_schedule";

const PRODUCTION_ROTATION_SCHEDULE_V1_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../../conformance/fixtures/protocol/production_rotation_schedule_v1.json"
));

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
    match IgnoredAny::deserialize(&mut deserializer) {
        Ok(_) => Err("trailing JSON tokens".to_owned()),
        Err(err) if err.classify() == serde_json::error::Category::Eof => Ok(value),
        Err(err) => Err(err.to_string()),
    }
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
    Ok(Some(descriptor_wire))
}

fn canonical_production_schedule_suite_params(suite_id: u8) -> SuiteParams {
    SuiteParams {
        suite_id,
        pubkey_len: ML_DSA_87_PUBKEY_BYTES,
        sig_len: ML_DSA_87_SIG_BYTES,
        verify_cost: VERIFY_COST_ML_DSA_87,
        alg_name: "ML-DSA-87",
    }
}

fn derived_production_schedule_registry(
    mainnet: &Option<ProductionRotationDescriptorWire>,
    testnet: &Option<ProductionRotationDescriptorWire>,
) -> SuiteRegistry {
    let mut suites = BTreeMap::new();
    suites.insert(
        SUITE_ID_ML_DSA_87,
        canonical_production_schedule_suite_params(SUITE_ID_ML_DSA_87),
    );
    for descriptor in [mainnet.as_ref(), testnet.as_ref()].into_iter().flatten() {
        suites.insert(
            descriptor.old_suite_id,
            canonical_production_schedule_suite_params(descriptor.old_suite_id),
        );
        suites.insert(
            descriptor.new_suite_id,
            canonical_production_schedule_suite_params(descriptor.new_suite_id),
        );
    }
    SuiteRegistry::with_suites(suites)
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
    let registry = registry
        .unwrap_or_else(|| derived_production_schedule_registry(&mainnet_wire, &testnet_wire));
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
) -> Result<Option<(CryptoRotationDescriptor, SuiteRegistry)>, String> {
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
    // A null slot means this network has no authoritative production activation state.
    // The compiled registry is derived across schedule entries, so returning it here
    // would leak foreign-network suites into an empty-slot caller.
    Ok(descriptor.map(|descriptor| (descriptor, registry)))
}

#[cfg(test)]
pub(crate) fn production_rotation_descriptor_for_network_with_registry_for_test(
    raw: &str,
    network: &str,
    registry: SuiteRegistry,
) -> Result<Option<(CryptoRotationDescriptor, SuiteRegistry)>, String> {
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
    Ok(descriptor.map(|descriptor| (descriptor, registry)))
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
        PRODUCTION_ROTATION_SCHEDULE_ERR_STEM, PRODUCTION_ROTATION_SCHEDULE_VERSION,
    };
    use rubin_consensus::constants::{
        ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
    };
    use rubin_consensus::{SuiteParams, SuiteRegistry};
    use std::collections::BTreeMap;

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
    fn production_rotation_descriptor_for_network_returns_none_for_explicit_empty_schedule() {
        assert!(production_rotation_descriptor_for_network("mainnet")
            .expect("mainnet schedule")
            .is_none());
        assert!(production_rotation_descriptor_for_network("testnet")
            .expect("testnet schedule")
            .is_none());
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
        .expect("must load")
        .expect("descriptor");
        let (descriptor, registry) = loaded;
        assert_eq!(descriptor.old_suite_id, 1);
        assert_eq!(descriptor.new_suite_id, 66);
        assert!(registry.lookup(66).is_some());
    }

    #[test]
    fn production_rotation_schedule_derives_scheduled_suites_when_registry_is_implicit() {
        let (schedule, registry) = parse_schedule_with_registry(
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
        .expect("must load");
        let descriptor = schedule.mainnet.expect("mainnet descriptor");
        assert_eq!(descriptor.new_suite_id, 66);
        let params = registry.lookup(66).expect("suite 66");
        assert_eq!(params.pubkey_len, ML_DSA_87_PUBKEY_BYTES);
        assert_eq!(params.sig_len, ML_DSA_87_SIG_BYTES);
        assert_eq!(params.verify_cost, VERIFY_COST_ML_DSA_87);
        assert_eq!(params.alg_name, "ML-DSA-87");
    }

    #[test]
    fn production_rotation_schedule_empty_slot_does_not_erase_foreign_slot_suites() {
        let (schedule, registry) = parse_schedule_with_registry(
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
        .expect("must load");
        assert!(schedule.mainnet.is_none());
        assert!(schedule.testnet.is_some());
        assert!(registry.lookup(66).is_some());
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
