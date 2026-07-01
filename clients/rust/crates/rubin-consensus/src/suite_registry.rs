use crate::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, SUITE_ID_SIMPLICITY_ENVELOPE,
    VERIFY_COST_ML_DSA_87,
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
/// Reports whether `suite_id` is reserved for a structural witness carrier (e.g.
/// the §5.4 Simplicity envelope, 0xF0) rather than native cryptographic
/// verification. Mirror of Go `IsStructuralWitnessCarrierSuiteID`.
pub fn is_structural_witness_carrier_suite_id(suite_id: u8) -> bool {
    (SUITE_ID_SIMPLICITY_ENVELOPE..=0xfe).contains(&suite_id)
}

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
        // Structural-range guard (§5.4): suite IDs 0xF0..=0xFE are structural
        // witness carriers, not native cryptographic suites, and must never be
        // registered as one. Mirror of the Go suite-registry panic.
        for &suite_id in suites.keys() {
            assert!(
                !is_structural_witness_carrier_suite_id(suite_id),
                "structural witness carrier suite 0x{suite_id:02x} cannot be registered as native crypto suite",
            );
        }
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
    /// Legacy infallible constructor for external callers. Panics only if the
    /// deduplicated set exceeds the live/native v1 cap of two suites, which
    /// indicates a programming bug at the call site.
    pub fn new(ids: &[u8]) -> Self {
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

    /// Whether the CORE_SIMPLICITY (0x0106) deployment is active at `height`.
    ///
    /// Default is inactive (fail-closed): a rotation provider that does not
    /// wire a Simplicity deployment keeps 0x0106 creation rejected. This
    /// mirrors Go's optional `SimplicityDeploymentProvider` seam, where a
    /// `RotationProvider` that does not also implement it is treated as
    /// "deployment not active".
    ///
    /// The seam is intentionally infallible (`bool`). Go's interface returns
    /// `(bool, error)` and maps the error case to a distinct
    /// "CORE_SIMPLICITY deployment lookup failure" reject. No current provider
    /// performs a fallible lookup, so that third state is unrepresentable and
    /// unreachable here. When a real (fallible) deployment provider is wired
    /// (activation slice), this must widen to a `Result` to re-establish the
    /// lookup-failure error-string parity with Go.
    fn simplicity_active_at_height(&self, _height: u64) -> bool {
        false
    }
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
            descriptor_native_suite_set(&[d.old_suite_id])
        } else if height < d.spend_height {
            // Phase 1: [H1, H2)
            descriptor_native_suite_set(&[d.old_suite_id, d.new_suite_id])
        } else {
            // Phase 2+: H2 onwards — create cutoff
            descriptor_native_suite_set(&[d.new_suite_id])
        }
    }

    /// Phase 0 (h < H1): {old}; Phase 1-3 (H1 ≤ h, h<H4|∞): {old,new}; Phase 4 (H4 ≤ h): {new}
    fn native_spend_suites(&self, height: u64) -> NativeSuiteSet {
        let d = &self.descriptor;
        if height < d.create_height {
            // Phase 0: before H1
            descriptor_native_suite_set(&[d.old_suite_id])
        } else if d.sunset_height != 0 && height >= d.sunset_height {
            // Phase 4: H4 sunset
            descriptor_native_suite_set(&[d.new_suite_id])
        } else {
            // Phase 1-3: [H1, H4) or [H1, ∞)
            descriptor_native_suite_set(&[d.old_suite_id, d.new_suite_id])
        }
    }
}

fn descriptor_native_suite_set(ids: &[u8]) -> NativeSuiteSet {
    // Descriptor selectors are expected to emit only {old}, {new}, or
    // {old,new}. If a future caller widens that set unexpectedly, fail closed
    // instead of silently accepting a larger live/native suite-set surface.
    NativeSuiteSet::try_new(ids).unwrap_or_else(|_| NativeSuiteSet::new(&[]))
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
#[path = "tests/suite_registry.rs"]
mod tests;

// NOTE: Kani proofs removed — all three (default_registry_contains_only_ml_dsa_87,
// native_suite_set_contains_len_consistency, default_rotation_provider_always_ml_dsa_87)
// use BTreeSet/BTreeMap internally (via NativeSuiteSet::new / SuiteRegistry::default_registry).
// BTree operations involve complex pointer manipulation and heap allocation that cause
// Kani's SAT solver to hang. These properties are fully covered by unit tests:
// - test_default_registry_ml_dsa_87_params_fixed
// - test_registry_lookup_unknown_suite (exhaustive 0..=255)
// - test_native_suite_set_dedup
// - test_native_suite_set_empty
