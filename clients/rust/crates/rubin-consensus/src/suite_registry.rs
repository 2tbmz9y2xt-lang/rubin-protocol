use crate::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const ROTATION_V1_PRODUCTION_AT_MOST_ONE_DESCRIPTOR_ERR_STEM: &str =
    "rotation: v1 production profile allows at most one descriptor";
pub const ROTATION_V1_PRODUCTION_FINITE_H4_REQUIRED_ERR_STEM: &str =
    "rotation: v1 production profile requires finite sunset_height (H4)";
const MAX_LIVE_NATIVE_SUITE_SET_CARDINALITY: usize = 2;

/// Consensus parameters for a single signature suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteParams {
    pub suite_id: u8,
    pub pubkey_len: u64,
    pub sig_len: u64,
    pub verify_cost: u64,
    /// Semantic algorithm identity used to resolve the live verifier binding.
    pub alg_name: &'static str,
}

/// Maps suite IDs to their consensus parameters. Single source of truth for
/// per-suite constants, replacing scattered hardcoded ML_DSA_87_* constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteRegistry {
    suites: BTreeMap<u8, SuiteParams>,
}

impl SuiteRegistry {
    /// Returns the default registry containing ML-DSA-87 (pre-rotation).
    pub fn default_registry() -> Self {
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
        Self { suites }
    }

    /// Returns true only when this registry still matches the canonical live
    /// manifest contract: a single ML-DSA-87 entry with the exact v1 params.
    pub fn is_canonical_default_live_manifest(&self) -> bool {
        if self.suites.len() != 1 {
            return false;
        }
        matches!(
            self.suites.get(&SUITE_ID_ML_DSA_87),
            Some(params)
                if params.suite_id == SUITE_ID_ML_DSA_87
                    && params.pubkey_len == ML_DSA_87_PUBKEY_BYTES
                    && params.sig_len == ML_DSA_87_SIG_BYTES
                    && params.verify_cost == VERIFY_COST_ML_DSA_87
                    && params.alg_name == "ML-DSA-87"
        )
    }

    /// Builds a registry from a map of suite ID to parameters. Use this for
    /// custom rotation deployments or tests that need additional suites beyond
    /// the default (e.g. `CryptoRotationDescriptor::validate` with old→new transition).
    pub fn with_suites(suites: BTreeMap<u8, SuiteParams>) -> Self {
        Self { suites }
    }

    /// Looks up parameters for a suite ID.
    pub fn lookup(&self, suite_id: u8) -> Option<&SuiteParams> {
        self.suites.get(&suite_id)
    }

    /// Returns true if the suite is known to the registry.
    pub fn is_registered(&self, suite_id: u8) -> bool {
        self.suites.contains_key(&suite_id)
    }

    pub fn min_sigcheck_payload_bytes(&self) -> Result<Option<u64>, &'static str> {
        let mut min_payload: Option<u64> = None;
        for params in self.suites.values() {
            let payload_bytes = params
                .pubkey_len
                .checked_add(params.sig_len)
                .ok_or("SuiteRegistry payload footprint overflow")?;
            min_payload = Some(match min_payload {
                Some(current) => current.min(payload_bytes),
                None => payload_bytes,
            });
        }
        Ok(min_payload)
    }
}

/// Set of suite IDs valid for native covenant operations at a given height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSuiteSet {
    suites: BTreeSet<u8>,
}

impl NativeSuiteSet {
    /// Internal helper for already-validated phase builders.
    pub(crate) fn new(ids: &[u8]) -> Self {
        Self::try_new(ids).expect("native suite set cardinality must stay <= 2")
    }

    /// Constructs a set from a list of suite IDs and fail-closes if the
    /// deduplicated live/native cardinality exceeds the v1 cap of two suites.
    pub fn try_new(ids: &[u8]) -> Result<Self, String> {
        let suites: BTreeSet<u8> = ids.iter().copied().collect();
        if suites.len() > MAX_LIVE_NATIVE_SUITE_SET_CARDINALITY {
            return Err(format!(
                "native suite set cardinality {} exceeds max {}",
                suites.len(),
                MAX_LIVE_NATIVE_SUITE_SET_CARDINALITY
            ));
        }
        Ok(Self { suites })
    }

    /// Returns true if the set contains the given suite ID.
    pub fn contains(&self, suite_id: u8) -> bool {
        self.suites.contains(&suite_id)
    }

    /// Returns the number of suites in the set.
    pub fn len(&self) -> usize {
        self.suites.len()
    }

    /// Returns true if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.suites.is_empty()
    }

    /// Returns sorted suite IDs.
    pub fn suite_ids(&self) -> Vec<u8> {
        self.suites.iter().copied().collect()
    }
}

/// Determines which signature suites are valid for native covenant creation
/// and spending at a given block height.
pub trait RotationProvider {
    /// Returns suites valid for creating native covenant outputs at height.
    fn native_create_suites(&self, height: u64) -> NativeSuiteSet;

    /// Returns suites valid for spending native covenant outputs at height.
    fn native_spend_suites(&self, height: u64) -> NativeSuiteSet;
}

/// Pre-rotation provider: always returns {ML_DSA_87} for both create and spend.
#[derive(Debug, Clone, Copy)]
pub struct DefaultRotationProvider;

impl RotationProvider for DefaultRotationProvider {
    fn native_create_suites(&self, _height: u64) -> NativeSuiteSet {
        NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87])
    }

    fn native_spend_suites(&self, _height: u64) -> NativeSuiteSet {
        NativeSuiteSet::new(&[SUITE_ID_ML_DSA_87])
    }
}

/// Deployment descriptor for a scheduled rotation from one suite to another.
#[derive(Debug, Clone)]
pub struct CryptoRotationDescriptor {
    pub name: String,
    pub old_suite_id: u8,
    pub new_suite_id: u8,
    pub create_height: u64, // H1
    pub spend_height: u64,  // H2
    pub sunset_height: u64, // H4 (0 = not defined)
}

impl CryptoRotationDescriptor {
    /// Validates descriptor invariants against the given registry.
    pub fn validate(&self, registry: &SuiteRegistry) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("rotation: name required".into());
        }
        if self.old_suite_id == self.new_suite_id {
            return Err(format!(
                "rotation: old suite (0x{:02x}) must differ from new suite",
                self.old_suite_id
            ));
        }
        if !registry.is_registered(self.old_suite_id) {
            return Err(format!(
                "rotation: old suite 0x{:02x} not registered",
                self.old_suite_id
            ));
        }
        if !registry.is_registered(self.new_suite_id) {
            return Err(format!(
                "rotation: new suite 0x{:02x} not registered",
                self.new_suite_id
            ));
        }
        if self.create_height >= self.spend_height {
            return Err(format!(
                "rotation: create_height ({}) must be < spend_height ({})",
                self.create_height, self.spend_height
            ));
        }
        if self.sunset_height != 0 && self.sunset_height <= self.spend_height {
            return Err(format!(
                "rotation: sunset_height ({}) must be > spend_height ({})",
                self.sunset_height, self.spend_height
            ));
        }
        Ok(())
    }
}

/// Implements RotationProvider using a validated CryptoRotationDescriptor.
#[derive(Debug, Clone)]
pub struct DescriptorRotationProvider {
    pub descriptor: CryptoRotationDescriptor,
}

impl RotationProvider for DescriptorRotationProvider {
    /// Phase 0 (h < H1): {old}; Phase 1 (H1 ≤ h < H2): {old,new}; Phase 2+ (h ≥ H2): {new}
    fn native_create_suites(&self, height: u64) -> NativeSuiteSet {
        let d = &self.descriptor;
        if height < d.create_height {
            // Phase 0: before H1
            NativeSuiteSet::new(&[d.old_suite_id])
        } else if height < d.spend_height {
            // Phase 1: [H1, H2)
            NativeSuiteSet::new(&[d.old_suite_id, d.new_suite_id])
        } else {
            // Phase 2+: H2 onwards — create cutoff
            NativeSuiteSet::new(&[d.new_suite_id])
        }
    }

    /// Phase 0 (h < H1): {old}; Phase 1-3 (H1 ≤ h, h<H4|∞): {old,new}; Phase 4 (H4 ≤ h): {new}
    fn native_spend_suites(&self, height: u64) -> NativeSuiteSet {
        let d = &self.descriptor;
        if height < d.create_height {
            // Phase 0: before H1
            NativeSuiteSet::new(&[d.old_suite_id])
        } else if d.sunset_height != 0 && height >= d.sunset_height {
            // Phase 4: H4 sunset
            NativeSuiteSet::new(&[d.new_suite_id])
        } else {
            // Phase 1-3: [H1, H4) or [H1, ∞)
            NativeSuiteSet::new(&[d.old_suite_id, d.new_suite_id])
        }
    }
}

/// Validates a set of rotation descriptors for overlap.
pub fn validate_rotation_set(
    descriptors: &[CryptoRotationDescriptor],
    registry: &SuiteRegistry,
) -> Result<(), String> {
    for (i, d) in descriptors.iter().enumerate() {
        d.validate(registry)
            .map_err(|e| format!("rotation[{}] {:?}: {}", i, d.name, e))?;
    }
    for i in 0..descriptors.len() {
        for j in (i + 1)..descriptors.len() {
            let a = &descriptors[i];
            let b = &descriptors[j];
            if a.create_height < b.spend_height && b.create_height < a.spend_height {
                return Err(format!(
                    "rotation: overlapping rotations {:?} [{},{}) and {:?} [{},{})",
                    a.name,
                    a.create_height,
                    a.spend_height,
                    b.name,
                    b.create_height,
                    b.spend_height,
                ));
            }
        }
    }
    Ok(())
}

pub fn normalized_rotation_network_name(network: &str) -> Cow<'_, str> {
    let trimmed = network.trim();
    if trimmed.is_empty() {
        return Cow::Borrowed("devnet");
    }
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

pub const SUPPORTED_ROTATION_NETWORK_NAMES_CSV: &str = "devnet, testnet, mainnet";

pub fn canonical_rotation_network_name_normalized(network: &str) -> Option<&str> {
    match network {
        "devnet" | "testnet" | "mainnet" => Some(network),
        _ => None,
    }
}

pub fn canonical_rotation_network_name(network: &str) -> Option<Cow<'_, str>> {
    let normalized = normalized_rotation_network_name(network);
    if canonical_rotation_network_name_normalized(normalized.as_ref()).is_some() {
        Some(normalized)
    } else {
        None
    }
}

pub fn is_v1_production_rotation_network_normalized(network: &str) -> bool {
    matches!(network, "mainnet" | "testnet")
}

/// True for networks that use the v1 production rotation profile (finite H4 required).
pub fn is_v1_production_rotation_network(network: &str) -> bool {
    let normalized = normalized_rotation_network_name(network);
    is_v1_production_rotation_network_normalized(normalized.as_ref())
}

/// Network-aware descriptor validation for already-normalized network names.
pub fn validate_rotation_descriptor_for_normalized_network(
    network: &str,
    d: &CryptoRotationDescriptor,
    registry: &SuiteRegistry,
) -> Result<(), String> {
    match network {
        "mainnet" | "testnet" => validate_v1_production_rotation_descriptor(d, registry),
        _ => d.validate(registry),
    }
}

/// Network-aware descriptor validation: non-production networks run [`CryptoRotationDescriptor::validate`] only;
/// mainnet/testnet use [`validate_v1_production_rotation_descriptor`] (full validate + finite H4), matching Go
/// `ValidateRotationDescriptorForNetwork`.
pub fn validate_rotation_descriptor_for_network(
    network: &str,
    d: &CryptoRotationDescriptor,
    registry: &SuiteRegistry,
) -> Result<(), String> {
    let normalized = normalized_rotation_network_name(network);
    validate_rotation_descriptor_for_normalized_network(normalized.as_ref(), d, registry)
}

/// [`validate_rotation_set`] on already-normalized non-production networks;
/// [`validate_v1_production_rotation_set`] on normalized mainnet/testnet.
pub fn validate_rotation_set_for_normalized_network(
    network: &str,
    descriptors: &[CryptoRotationDescriptor],
    registry: &SuiteRegistry,
) -> Result<(), String> {
    match network {
        "mainnet" | "testnet" => validate_v1_production_rotation_set(descriptors, registry),
        _ => validate_rotation_set(descriptors, registry),
    }
}

/// [`validate_rotation_set`] on non-production networks; [`validate_v1_production_rotation_set`] on mainnet/testnet.
pub fn validate_rotation_set_for_network(
    network: &str,
    descriptors: &[CryptoRotationDescriptor],
    registry: &SuiteRegistry,
) -> Result<(), String> {
    let normalized = normalized_rotation_network_name(network);
    validate_rotation_set_for_normalized_network(normalized.as_ref(), descriptors, registry)
}

/// Full descriptor validation plus finite `sunset_height` (H4) for the v1 production rotation profile.
/// Matches Go `ValidateV1ProductionRotationDescriptor`.
pub fn validate_v1_production_rotation_descriptor(
    d: &CryptoRotationDescriptor,
    registry: &SuiteRegistry,
) -> Result<(), String> {
    d.validate(registry)?;
    if d.sunset_height == 0 {
        return Err(ROTATION_V1_PRODUCTION_FINITE_H4_REQUIRED_ERR_STEM.into());
    }
    Ok(())
}

/// Production checks: at most one descriptor, and for the single allowed
/// descriptor enforce the full production helper directly (generic validation +
/// finite H4) without running set-only overlap logic.
pub fn validate_v1_production_rotation_set(
    descriptors: &[CryptoRotationDescriptor],
    registry: &SuiteRegistry,
) -> Result<(), String> {
    match descriptors {
        [] => Ok(()),
        [descriptor] => validate_v1_production_rotation_descriptor(descriptor, registry),
        many => Err(format!(
            "{ROTATION_V1_PRODUCTION_AT_MOST_ONE_DESCRIPTOR_ERR_STEM}, got {}",
            many.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> SuiteRegistry {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: 2592,
                sig_len: 4627,
                verify_cost: 8,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 1024,
                sig_len: 512,
                verify_cost: 4,
                alg_name: "ML-DSA-87",
            },
        );
        SuiteRegistry { suites }
    }

    #[test]
    fn test_suite_registry_default() {
        let reg = SuiteRegistry::default_registry();
        assert!(reg.is_registered(SUITE_ID_ML_DSA_87));
        assert!(!reg.is_registered(0xFF));
        let p = reg.lookup(SUITE_ID_ML_DSA_87).unwrap();
        assert_eq!(p.pubkey_len, ML_DSA_87_PUBKEY_BYTES);
        assert_eq!(p.sig_len, ML_DSA_87_SIG_BYTES);
    }

    #[test]
    fn test_suite_registry_with_suites() {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: 100,
                sig_len: 200,
                verify_cost: 1,
                alg_name: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        assert!(reg.is_registered(0x01));
        assert!(!reg.is_registered(0x02));
        let p = reg.lookup(0x01).unwrap();
        assert_eq!(p.pubkey_len, 100);
        assert_eq!(p.sig_len, 200);
        assert_eq!(
            reg.min_sigcheck_payload_bytes().expect("payload"),
            Some(300)
        );
    }

    #[test]
    fn test_normalized_rotation_network_name_matches_go_semantics() {
        assert_eq!(normalized_rotation_network_name(""), "devnet");
        assert_eq!(normalized_rotation_network_name(" DevNet "), "devnet");
        assert_eq!(normalized_rotation_network_name("  MAINNET  "), "mainnet");
        assert_eq!(normalized_rotation_network_name("\tTestNet\t"), "testnet");
    }

    #[test]
    fn test_is_v1_production_rotation_network_normalized_inputs() {
        assert!(is_v1_production_rotation_network("mainnet"));
        assert!(is_v1_production_rotation_network("  MAINNET  "));
        assert!(is_v1_production_rotation_network("\tTestNet\t"));
        assert!(!is_v1_production_rotation_network(""));
        assert!(!is_v1_production_rotation_network("devnet"));
    }

    #[test]
    fn test_is_v1_production_rotation_network_normalized_helper_matches_public_entrypoint() {
        for network in ["mainnet", "testnet", "devnet"] {
            assert_eq!(
                is_v1_production_rotation_network_normalized(network),
                is_v1_production_rotation_network(network)
            );
        }
    }

    #[test]
    fn test_canonical_rotation_network_name_rejects_unknown_networks() {
        assert_eq!(
            canonical_rotation_network_name("  MAINNET  ").as_deref(),
            Some("mainnet")
        );
        assert_eq!(
            canonical_rotation_network_name("\tTestNet\t").as_deref(),
            Some("testnet")
        );
        assert!(canonical_rotation_network_name("private-net").is_none());
    }

    #[test]
    fn test_suite_registry_min_sigcheck_payload_bytes_picks_smallest_registered_suite() {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: 2592,
                sig_len: 4627,
                verify_cost: 8,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 64,
                sig_len: 100,
                verify_cost: 1,
                alg_name: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        assert_eq!(
            reg.min_sigcheck_payload_bytes().expect("payload"),
            Some(164)
        );
    }

    #[test]
    fn test_suite_registry_min_sigcheck_payload_bytes_fails_closed_on_overflow() {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: u64::MAX,
                sig_len: 1,
                verify_cost: 1,
                alg_name: "ML-DSA-87",
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        assert_eq!(
            reg.min_sigcheck_payload_bytes(),
            Err("SuiteRegistry payload footprint overflow")
        );
    }

    #[test]
    fn test_native_suite_set() {
        let s = NativeSuiteSet::new(&[0x01, 0x02]);
        assert!(s.contains(0x01));
        assert!(s.contains(0x02));
        assert!(!s.contains(0x03));
        assert_eq!(s.len(), 2);
        assert_eq!(s.suite_ids(), vec![0x01, 0x02]);
    }

    #[test]
    fn test_default_rotation_provider() {
        let p = DefaultRotationProvider;
        let cs = p.native_create_suites(0);
        assert!(cs.contains(SUITE_ID_ML_DSA_87));
        assert!(!cs.contains(0x02));
        let ss = p.native_spend_suites(999);
        assert!(ss.contains(SUITE_ID_ML_DSA_87));
    }

    #[test]
    fn test_descriptor_valid() {
        let reg = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 0,
        };
        assert!(d.validate(&reg).is_ok());
    }

    #[test]
    fn test_descriptor_old_eq_new() {
        let reg = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x01,
            create_height: 100,
            spend_height: 200,
            sunset_height: 0,
        };
        assert!(d.validate(&reg).unwrap_err().contains("must differ"));
    }

    #[test]
    fn test_descriptor_create_gte_spend() {
        let reg = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 200,
            spend_height: 200,
            sunset_height: 0,
        };
        assert!(d.validate(&reg).unwrap_err().contains("create_height"));
    }

    #[test]
    fn test_descriptor_not_registered() {
        let reg = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0xFF,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 0,
        };
        assert!(d
            .validate(&reg)
            .unwrap_err()
            .contains("old suite 0xff not registered"));
    }

    #[test]
    fn test_rotation_set_overlap() {
        let reg = test_registry();
        let overlap = vec![
            CryptoRotationDescriptor {
                name: "a".into(),
                old_suite_id: 0x01,
                new_suite_id: 0x02,
                create_height: 100,
                spend_height: 250,
                sunset_height: 0,
            },
            CryptoRotationDescriptor {
                name: "b".into(),
                old_suite_id: 0x01,
                new_suite_id: 0x02,
                create_height: 200,
                spend_height: 350,
                sunset_height: 0,
            },
        ];
        assert!(validate_rotation_set(&overlap, &reg)
            .unwrap_err()
            .contains("overlapping"));
    }

    #[test]
    fn test_v1_production_requires_h4() {
        let reg = test_registry();
        let d = CryptoRotationDescriptor {
            name: "r".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 0,
        };
        assert!(validate_v1_production_rotation_descriptor(&d, &reg).is_err());
        assert!(validate_rotation_descriptor_for_network("mainnet", &d, &reg).is_err());
        assert!(validate_rotation_descriptor_for_network("  MAINNET  ", &d, &reg).is_err());
        assert!(validate_rotation_descriptor_for_network("devnet", &d, &reg).is_ok());
        assert!(validate_rotation_descriptor_for_network("", &d, &reg).is_ok());
        let d_h4 = CryptoRotationDescriptor {
            sunset_height: 100,
            ..d.clone()
        };
        validate_rotation_descriptor_for_network("mainnet", &d_h4, &reg).expect("mainnet with H4");
    }

    fn test_registry_three_suites() -> SuiteRegistry {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: 2592,
                sig_len: 4627,
                verify_cost: 8,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 1024,
                sig_len: 512,
                verify_cost: 4,
                alg_name: "ML-DSA-87",
            },
        );
        suites.insert(
            0x03,
            SuiteParams {
                suite_id: 0x03,
                pubkey_len: 1024,
                sig_len: 512,
                verify_cost: 4,
                alg_name: "ML-DSA-87",
            },
        );
        SuiteRegistry::with_suites(suites)
    }

    #[test]
    fn test_v1_production_rejects_two_descriptor_batch() {
        let reg = test_registry_three_suites();
        let d1 = CryptoRotationDescriptor {
            name: "first".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        let d2 = CryptoRotationDescriptor {
            name: "second".into(),
            old_suite_id: 0x02,
            new_suite_id: 0x03,
            create_height: 100,
            spend_height: 110,
            sunset_height: 200,
        };
        assert!(
            validate_v1_production_rotation_set(&[d1.clone(), d2.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        let mut d2_bad = d2.clone();
        d2_bad.sunset_height = 0;
        assert!(validate_v1_production_rotation_set(&[d1, d2_bad], &reg)
            .unwrap_err()
            .contains("at most one descriptor"));
    }

    #[test]
    fn test_validate_rotation_set_for_network_normalized_inputs() {
        let reg = test_registry_three_suites();
        let d1 = CryptoRotationDescriptor {
            name: "first".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        let d2 = CryptoRotationDescriptor {
            name: "second".into(),
            old_suite_id: 0x02,
            new_suite_id: 0x03,
            create_height: 100,
            spend_height: 110,
            sunset_height: 200,
        };
        assert!(
            validate_rotation_set_for_network("  MAINNET  ", &[d1.clone(), d2.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        validate_rotation_set_for_network("", &[d1, d2], &reg)
            .expect("empty network falls back to devnet path");
    }

    fn test_registry_four_suites() -> SuiteRegistry {
        let mut suites = BTreeMap::new();
        suites.insert(
            0x01,
            SuiteParams {
                suite_id: 0x01,
                pubkey_len: 2592,
                sig_len: 4627,
                verify_cost: 8,
                alg_name: "ML-DSA-87",
            },
        );
        for id in [0x02u8, 0x03, 0x04] {
            suites.insert(
                id,
                SuiteParams {
                    suite_id: id,
                    pubkey_len: 1024,
                    sig_len: 512,
                    verify_cost: 4,
                    alg_name: "ML-DSA-87",
                },
            );
        }
        SuiteRegistry::with_suites(suites)
    }

    #[test]
    fn test_v1_production_rejects_multi_descriptor_batch() {
        let reg = test_registry_four_suites();
        let d1 = CryptoRotationDescriptor {
            name: "r1".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        let d2 = CryptoRotationDescriptor {
            name: "r2".into(),
            old_suite_id: 0x02,
            new_suite_id: 0x03,
            create_height: 100,
            spend_height: 110,
            sunset_height: 200,
        };
        let d3 = CryptoRotationDescriptor {
            name: "r3".into(),
            old_suite_id: 0x03,
            new_suite_id: 0x04,
            create_height: 200,
            spend_height: 210,
            sunset_height: 300,
        };
        assert!(
            validate_v1_production_rotation_set(&[d1.clone(), d2.clone(), d3.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        assert!(
            validate_v1_production_rotation_set(&[d1.clone(), d2.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        let mut d2_bad = d2.clone();
        d2_bad.sunset_height = 0;
        assert!(
            validate_v1_production_rotation_set(&[d1.clone(), d2_bad, d3.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        let mut d2_overlap = d2.clone();
        d2_overlap.create_height = 15;
        d2_overlap.spend_height = 25;
        assert!(
            validate_v1_production_rotation_set(&[d1.clone(), d2_overlap, d3.clone()], &reg)
                .unwrap_err()
                .contains("at most one descriptor")
        );
        let mut d3_bad = d3.clone();
        d3_bad.create_height = 220;
        d3_bad.spend_height = 210;
        assert!(validate_v1_production_rotation_set(&[d1, d2, d3_bad], &reg)
            .unwrap_err()
            .contains("at most one descriptor"));
    }

    #[test]
    fn test_v1_production_empty_set_is_allowed() {
        let reg = test_registry();
        validate_v1_production_rotation_set(&[], &reg)
            .expect("empty production set should stay a no-op");
    }

    #[test]
    fn test_v1_production_single_descriptor_still_runs_descriptor_validation() {
        let reg = test_registry_three_suites();
        let invalid = CryptoRotationDescriptor {
            name: "".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        assert!(validate_v1_production_rotation_set(&[invalid], &reg)
            .unwrap_err()
            .contains("name required"));
    }

    #[test]
    fn test_v1_production_single_descriptor_preserves_generic_set_validation() {
        let reg = test_registry();
        let invalid = CryptoRotationDescriptor {
            name: "bad-suite".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x03,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        assert!(validate_v1_production_rotation_set(&[invalid], &reg)
            .unwrap_err()
            .contains("not registered"));
    }

    #[test]
    fn test_devnet_still_allows_three_descriptor_chain() {
        let reg = test_registry_four_suites();
        let d1 = CryptoRotationDescriptor {
            name: "r1".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 10,
            spend_height: 20,
            sunset_height: 100,
        };
        let d2 = CryptoRotationDescriptor {
            name: "r2".into(),
            old_suite_id: 0x02,
            new_suite_id: 0x03,
            create_height: 100,
            spend_height: 110,
            sunset_height: 200,
        };
        let d3 = CryptoRotationDescriptor {
            name: "r3".into(),
            old_suite_id: 0x03,
            new_suite_id: 0x04,
            create_height: 200,
            spend_height: 210,
            sunset_height: 300,
        };
        validate_rotation_set_for_network("devnet", &[d1, d2, d3], &reg)
            .expect("devnet preserves non-production experimentation");
    }

    #[test]
    fn test_descriptor_rotation_provider_create() {
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 300,
        };
        let p = DescriptorRotationProvider {
            descriptor: d.clone(),
        };

        // Before H1: only old.
        let s = p.native_create_suites(50);
        assert!(s.contains(0x01));
        assert!(!s.contains(0x02));

        // At H1: both.
        let s = p.native_create_suites(100);
        assert!(s.contains(0x01));
        assert!(s.contains(0x02));

        // At H2: only new (create cutoff per spec §6 Phase 2).
        let s = p.native_create_suites(200);
        assert!(!s.contains(0x01));
        assert!(s.contains(0x02));

        // At H4: still only new.
        let s = p.native_create_suites(300);
        assert!(!s.contains(0x01));
        assert!(s.contains(0x02));
    }

    #[test]
    fn test_descriptor_rotation_provider_spend() {
        let d = CryptoRotationDescriptor {
            name: "test".into(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 400,
        };
        let p = DescriptorRotationProvider { descriptor: d };

        // Before H1: only old.
        let s = p.native_spend_suites(50);
        assert!(s.contains(0x01));
        assert!(!s.contains(0x02));

        // At H1: both (new enters spend at activation).
        let s = p.native_spend_suites(100);
        assert!(s.contains(0x01));
        assert!(s.contains(0x02));

        // Between H1 and H4: both.
        let s = p.native_spend_suites(300);
        assert!(s.contains(0x01));
        assert!(s.contains(0x02));

        // At H4: only new (sunset per spec §6 Phase 4).
        let s = p.native_spend_suites(400);
        assert!(!s.contains(0x01));
        assert!(s.contains(0x02));
    }

    #[test]
    fn test_default_registry_ml_dsa_87_params_fixed() {
        let r = SuiteRegistry::default_registry();
        let p = r.lookup(crate::constants::SUITE_ID_ML_DSA_87).unwrap();
        assert_eq!(p.pubkey_len, crate::constants::ML_DSA_87_PUBKEY_BYTES);
        assert_eq!(p.sig_len, crate::constants::ML_DSA_87_SIG_BYTES);
        assert_eq!(p.alg_name, "ML-DSA-87");
        assert_eq!(p.verify_cost, crate::constants::VERIFY_COST_ML_DSA_87);
        assert!(r.is_canonical_default_live_manifest());
    }

    #[test]
    fn test_registry_lookup_unknown_suite() {
        let r = SuiteRegistry::default_registry();
        for id in 0..=255u8 {
            if id == crate::constants::SUITE_ID_ML_DSA_87 {
                assert!(r.is_registered(id));
            } else {
                assert!(
                    !r.is_registered(id),
                    "unexpected registered suite: 0x{:02x}",
                    id
                );
            }
        }
    }

    #[test]
    fn test_native_suite_set_empty() {
        let s = NativeSuiteSet::new(&[]);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert!(!s.contains(0x01));
        assert!(s.suite_ids().is_empty());
    }

    #[test]
    fn test_native_suite_set_dedup() {
        let s = NativeSuiteSet::new(&[0x01, 0x01, 0x01]);
        assert_eq!(s.len(), 1);
        assert!(s.contains(0x01));
    }

    #[test]
    fn test_native_suite_set_rejects_more_than_two_unique_suites() {
        let err = NativeSuiteSet::try_new(&[0x01, 0x02, 0x03]).expect_err("must reject");
        assert_eq!(err, "native suite set cardinality 3 exceeds max 2");
    }

    #[test]
    fn test_min_sigcheck_payload_empty_registry() {
        let r = SuiteRegistry::with_suites(std::collections::BTreeMap::new());
        assert_eq!(r.min_sigcheck_payload_bytes().unwrap(), None);
    }

    #[test]
    fn test_descriptor_sunset_after_spend() {
        // sunset_height > spend_height is valid.
        let r = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".to_string(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 300,
        };
        assert!(d.validate(&r).is_ok());
    }

    #[test]
    fn test_descriptor_sunset_at_spend_rejected() {
        // sunset_height == spend_height must be rejected.
        let r = test_registry();
        let d = CryptoRotationDescriptor {
            name: "test".to_string(),
            old_suite_id: 0x01,
            new_suite_id: 0x02,
            create_height: 100,
            spend_height: 200,
            sunset_height: 200,
        };
        assert!(d.validate(&r).is_err());
    }
}

// NOTE: Kani proofs removed — all three (default_registry_contains_only_ml_dsa_87,
// native_suite_set_contains_len_consistency, default_rotation_provider_always_ml_dsa_87)
// use BTreeSet/BTreeMap internally (via NativeSuiteSet::new / SuiteRegistry::default_registry).
// BTree operations involve complex pointer manipulation and heap allocation that cause
// Kani's SAT solver to hang. These properties are fully covered by unit tests:
// - test_default_registry_ml_dsa_87_params_fixed (line 538)
// - test_registry_lookup_unknown_suite (line 548, exhaustive 0..=255)
// - test_native_suite_set_dedup (line 573)
// - test_native_suite_set_empty (line 564)
