use rubin_consensus::{
    validate_rotation_descriptor_for_normalized_network, CryptoRotationDescriptor, SuiteRegistry,
};
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
    #[serde(default)]
    sunset_height: u64,
}

fn production_rotation_schedule_error(message: impl Into<String>) -> String {
    format!(
        "{PRODUCTION_ROTATION_SCHEDULE_ERR_STEM}: {}",
        message.into()
    )
}

fn parse_descriptor_slot(
    value: Value,
    network: &str,
    registry: &SuiteRegistry,
) -> Result<Option<CryptoRotationDescriptor>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let descriptor_wire: ProductionRotationDescriptorWire = serde_json::from_value(value)
        .map_err(|err| production_rotation_schedule_error(format!("networks.{network}: {err}")))?;
    let descriptor = CryptoRotationDescriptor {
        name: descriptor_wire.name,
        old_suite_id: descriptor_wire.old_suite_id,
        new_suite_id: descriptor_wire.new_suite_id,
        create_height: descriptor_wire.create_height,
        spend_height: descriptor_wire.spend_height,
        sunset_height: descriptor_wire.sunset_height,
    };
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
    registry: SuiteRegistry,
) -> Result<(ProductionRotationSchedule, SuiteRegistry), String> {
    let wire: ProductionRotationScheduleWire = serde_json::from_str(raw).map_err(|err| {
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
    let mainnet = parse_descriptor_slot(
        networks
            .remove("mainnet")
            .ok_or_else(|| production_rotation_schedule_error("networks.mainnet missing"))?,
        "mainnet",
        &registry,
    )?;
    let testnet = parse_descriptor_slot(
        networks
            .remove("testnet")
            .ok_or_else(|| production_rotation_schedule_error("networks.testnet missing"))?,
        "testnet",
        &registry,
    )?;
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
    parse_schedule_with_registry(
        PRODUCTION_ROTATION_SCHEDULE_V1_JSON,
        SuiteRegistry::default_registry(),
    )
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
    Ok(descriptor.map(|descriptor| (descriptor, registry)))
}

#[cfg(test)]
pub(crate) fn production_rotation_descriptor_for_network_with_registry_for_test(
    raw: &str,
    network: &str,
    registry: SuiteRegistry,
) -> Result<Option<(CryptoRotationDescriptor, SuiteRegistry)>, String> {
    let (schedule, registry) = parse_schedule_with_registry(raw, registry)?;
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

#[cfg(test)]
mod tests {
    use super::{
        load_compiled_production_rotation_schedule, production_rotation_descriptor_for_network,
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
        assert!(
            err.contains("parse embedded artifact"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("trailing characters"),
            "unexpected error: {err}"
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
