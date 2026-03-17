use crate::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
};
use std::collections::{BTreeMap, BTreeSet};

/// Consensus parameters for a single signature suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiteParams {
    pub suite_id: u8,
    pub pubkey_len: u64,
    pub sig_len: u64,
    pub verify_cost: u64,
}

/// Maps suite IDs to their consensus parameters. Single source of truth for
/// per-suite constants, replacing scattered hardcoded ML_DSA_87_* constants.
#[derive(Debug, Clone)]
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
            },
        );
        Self { suites }
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
}

/// Set of suite IDs valid for native covenant operations at a given height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSuiteSet {
    suites: BTreeSet<u8>,
}

impl NativeSuiteSet {
    /// Constructs a set from a list of suite IDs.
    pub fn new(ids: &[u8]) -> Self {
        Self {
            suites: ids.iter().copied().collect(),
        }
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
    fn native_create_suites(&self, height: u64) -> NativeSuiteSet {
        let d = &self.descriptor;
        if height < d.create_height {
            NativeSuiteSet::new(&[d.old_suite_id])
        } else if d.sunset_height != 0 && height >= d.sunset_height {
            NativeSuiteSet::new(&[d.new_suite_id])
        } else {
            NativeSuiteSet::new(&[d.old_suite_id, d.new_suite_id])
        }
    }

    fn native_spend_suites(&self, height: u64) -> NativeSuiteSet {
        let d = &self.descriptor;
        if height < d.spend_height {
            NativeSuiteSet::new(&[d.old_suite_id])
        } else {
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
            },
        );
        suites.insert(
            0x02,
            SuiteParams {
                suite_id: 0x02,
                pubkey_len: 1024,
                sig_len: 512,
                verify_cost: 4,
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
            },
        );
        let reg = SuiteRegistry::with_suites(suites);
        assert!(reg.is_registered(0x01));
        assert!(!reg.is_registered(0x02));
        let p = reg.lookup(0x01).unwrap();
        assert_eq!(p.pubkey_len, 100);
        assert_eq!(p.sig_len, 200);
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

        // At H4: only new.
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
            sunset_height: 0,
        };
        let p = DescriptorRotationProvider { descriptor: d };

        // Before H2: only old.
        let s = p.native_spend_suites(150);
        assert!(s.contains(0x01));
        assert!(!s.contains(0x02));

        // At H2: both.
        let s = p.native_spend_suites(200);
        assert!(s.contains(0x01));
        assert!(s.contains(0x02));
    }
}
