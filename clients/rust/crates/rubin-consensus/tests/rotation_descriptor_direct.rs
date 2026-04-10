use rubin_consensus::suite_registry::validate_rotation_set;
use rubin_consensus::{
    CryptoRotationDescriptor, DefaultRotationProvider, DescriptorRotationProvider, NativeSuiteSet,
    RotationProvider, SuiteParams, SuiteRegistry,
};
use std::collections::BTreeMap;

// =============================================================
// helpers
// =============================================================

fn two_suite_registry() -> SuiteRegistry {
    let mut m = BTreeMap::new();
    m.insert(
        0x01,
        SuiteParams {
            suite_id: 0x01,
            pubkey_len: 2592,
            sig_len: 4627,
            verify_cost: 8,
            alg_name: "ML-DSA-87",
        },
    );
    m.insert(
        0x02,
        SuiteParams {
            suite_id: 0x02,
            pubkey_len: 1024,
            sig_len: 512,
            verify_cost: 4,
            alg_name: "SLH-DSA-256s",
        },
    );
    SuiteRegistry::with_suites(m)
}

fn valid_descriptor() -> CryptoRotationDescriptor {
    CryptoRotationDescriptor {
        name: "rotation-1".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 1000,
        spend_height: 2000,
        sunset_height: 3000,
    }
}

// =============================================================
// SuiteRegistry — crate-root re-export smoke
// =============================================================

#[test]
fn registry_default_has_ml_dsa_87() {
    let reg = SuiteRegistry::default_registry();
    // ML-DSA-87 suite_id is defined in constants; the default registry must contain it.
    let p = reg
        .lookup(0x01)
        .expect("default registry must contain suite 0x01");
    assert_eq!(p.suite_id, 0x01);
    assert_eq!(p.alg_name, "ML-DSA-87");
}

#[test]
fn registry_empty_returns_none_on_lookup() {
    let reg = SuiteRegistry::with_suites(BTreeMap::new());
    assert!(reg.lookup(0x01).is_none());
    assert!(!reg.is_registered(0x01));
}

#[test]
fn registry_min_sigcheck_empty_returns_none() {
    let reg = SuiteRegistry::with_suites(BTreeMap::new());
    assert_eq!(reg.min_sigcheck_payload_bytes().unwrap(), None);
}

#[test]
fn registry_min_sigcheck_picks_smallest() {
    let reg = two_suite_registry();
    // suite 0x01: 2592+4627=7219, suite 0x02: 1024+512=1536 → min=1536
    assert_eq!(reg.min_sigcheck_payload_bytes().unwrap(), Some(1536));
}

#[test]
fn registry_min_sigcheck_overflow() {
    let mut m = BTreeMap::new();
    m.insert(
        0xFF,
        SuiteParams {
            suite_id: 0xFF,
            pubkey_len: u64::MAX,
            sig_len: 1,
            verify_cost: 0,
            alg_name: "overflow",
        },
    );
    let reg = SuiteRegistry::with_suites(m);
    assert!(reg.min_sigcheck_payload_bytes().is_err());
}

// =============================================================
// NativeSuiteSet — dedup, sorted output, empty
// =============================================================

#[test]
fn native_suite_set_empty() {
    let s = NativeSuiteSet::new(&[]);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert!(!s.contains(0x01));
    assert!(s.suite_ids().is_empty());
}

#[test]
fn native_suite_set_dedup_and_sorted() {
    let s = NativeSuiteSet::new(&[0x03, 0x01, 0x02, 0x01, 0x03]);
    assert_eq!(s.len(), 3);
    assert_eq!(s.suite_ids(), vec![0x01, 0x02, 0x03]); // sorted by BTreeSet
}

#[test]
fn native_suite_set_single() {
    let s = NativeSuiteSet::new(&[0x42]);
    assert_eq!(s.len(), 1);
    assert!(s.contains(0x42));
    assert!(!s.contains(0x00));
}

// =============================================================
// DefaultRotationProvider — always ML-DSA-87
// =============================================================

#[test]
fn default_provider_create_at_zero() {
    let p = DefaultRotationProvider;
    let s = p.native_create_suites(0);
    assert_eq!(s.len(), 1);
    assert!(s.contains(0x01)); // SUITE_ID_ML_DSA_87
}

#[test]
fn default_provider_create_at_max() {
    let p = DefaultRotationProvider;
    let s = p.native_create_suites(u64::MAX);
    assert_eq!(s.len(), 1);
    assert!(s.contains(0x01));
}

#[test]
fn default_provider_spend_at_zero() {
    let p = DefaultRotationProvider;
    let s = p.native_spend_suites(0);
    assert_eq!(s.len(), 1);
    assert!(s.contains(0x01));
}

#[test]
fn default_provider_spend_at_max() {
    let p = DefaultRotationProvider;
    let s = p.native_spend_suites(u64::MAX);
    assert_eq!(s.len(), 1);
    assert!(s.contains(0x01));
}

// =============================================================
// CryptoRotationDescriptor::validate — error paths
// =============================================================

#[test]
fn descriptor_validate_empty_name() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.name = String::new();
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("name required"));
}

#[test]
fn descriptor_validate_old_eq_new() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.new_suite_id = d.old_suite_id;
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("must differ"));
}

#[test]
fn descriptor_validate_old_not_registered() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.old_suite_id = 0xFF;
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("old suite 0xff not registered"));
}

#[test]
fn descriptor_validate_new_not_registered() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.new_suite_id = 0xFF;
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("new suite 0xff not registered"));
}

#[test]
fn descriptor_validate_create_eq_spend() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.create_height = 1000;
    d.spend_height = 1000;
    d.sunset_height = 0;
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("create_height"));
}

#[test]
fn descriptor_validate_create_gt_spend() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.create_height = 5000;
    d.spend_height = 2000;
    d.sunset_height = 0;
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("create_height"));
}

#[test]
fn descriptor_validate_sunset_eq_spend() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.sunset_height = d.spend_height; // sunset == spend → rejected
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("sunset_height"));
}

#[test]
fn descriptor_validate_sunset_lt_spend() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.sunset_height = d.spend_height - 1; // sunset < spend → rejected
    let err = d.validate(&reg).unwrap_err();
    assert!(err.contains("sunset_height"));
}

#[test]
fn descriptor_validate_sunset_zero_is_ok() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.sunset_height = 0; // 0 means "not defined" → valid
    assert!(d.validate(&reg).is_ok());
}

#[test]
fn descriptor_validate_valid() {
    let reg = two_suite_registry();
    assert!(valid_descriptor().validate(&reg).is_ok());
}

// =============================================================
// DescriptorRotationProvider — create suites phase transitions
// =============================================================

#[test]
fn create_phase0_before_h1() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h < H1(1000): Phase 0 → {old}
    let s = p.native_create_suites(999);
    assert!(s.contains(0x01));
    assert!(!s.contains(0x02));
    assert_eq!(s.len(), 1);
}

#[test]
fn create_phase0_at_zero() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    let s = p.native_create_suites(0);
    assert!(s.contains(0x01));
    assert!(!s.contains(0x02));
}

#[test]
fn create_phase1_at_h1() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H1(1000): Phase 1 → {old, new}
    let s = p.native_create_suites(1000);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
    assert_eq!(s.len(), 2);
}

#[test]
fn create_phase1_between_h1_h2() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    let s = p.native_create_suites(1500);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn create_phase1_at_h2_minus_1() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H2-1(1999): still Phase 1 → {old, new}
    let s = p.native_create_suites(1999);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn create_phase2_at_h2() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H2(2000): Phase 2 → {new} only
    let s = p.native_create_suites(2000);
    assert!(!s.contains(0x01));
    assert!(s.contains(0x02));
    assert_eq!(s.len(), 1);
}

#[test]
fn create_phase2_well_after_h2() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    let s = p.native_create_suites(u64::MAX);
    assert!(!s.contains(0x01));
    assert!(s.contains(0x02));
}

// =============================================================
// DescriptorRotationProvider — spend suites phase transitions
// =============================================================

#[test]
fn spend_phase0_before_h1() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h < H1: Phase 0 → {old}
    let s = p.native_spend_suites(999);
    assert!(s.contains(0x01));
    assert!(!s.contains(0x02));
}

#[test]
fn spend_phase1_at_h1() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H1: Phase 1 → {old, new}
    let s = p.native_spend_suites(1000);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn spend_phase2_at_h2() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H2: Phase 2, but spend still allows both (no sunset yet)
    // spend: [H1, H4) → {old, new}
    let s = p.native_spend_suites(2000);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn spend_phase3_between_h2_h4() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // H2(2000) ≤ h < H4(3000): Phase 3 → {old, new}
    let s = p.native_spend_suites(2999);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn spend_phase4_at_h4_sunset() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    // h == H4(3000): Phase 4 sunset → {new} only
    let s = p.native_spend_suites(3000);
    assert!(!s.contains(0x01));
    assert!(s.contains(0x02));
    assert_eq!(s.len(), 1);
}

#[test]
fn spend_phase4_well_after_sunset() {
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    let s = p.native_spend_suites(u64::MAX);
    assert!(!s.contains(0x01));
    assert!(s.contains(0x02));
}

#[test]
fn spend_no_sunset_at_max_height() {
    // sunset_height = 0 means "never sunset" → spend always {old, new} after H1
    let d = CryptoRotationDescriptor {
        name: "no-sunset".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 100,
        spend_height: 200,
        sunset_height: 0,
    };
    let p = DescriptorRotationProvider { descriptor: d };
    let s = p.native_spend_suites(u64::MAX);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
    assert_eq!(s.len(), 2);
}

// =============================================================
// Create vs Spend divergence at H2
// =============================================================

#[test]
fn create_spend_diverge_at_h2() {
    // Key invariant: at H2, create={new} but spend={old,new}
    let p = DescriptorRotationProvider {
        descriptor: valid_descriptor(),
    };
    let create = p.native_create_suites(2000);
    let spend = p.native_spend_suites(2000);
    assert_eq!(create.len(), 1); // only new
    assert_eq!(spend.len(), 2); // old + new
    assert!(!create.contains(0x01));
    assert!(spend.contains(0x01));
}

// =============================================================
// validate_rotation_set
// =============================================================

#[test]
fn rotation_set_empty_ok() {
    let reg = two_suite_registry();
    assert!(validate_rotation_set(&[], &reg).is_ok());
}

#[test]
fn rotation_set_single_valid() {
    let reg = two_suite_registry();
    assert!(validate_rotation_set(&[valid_descriptor()], &reg).is_ok());
}

#[test]
fn rotation_set_single_invalid_propagates() {
    let reg = two_suite_registry();
    let mut d = valid_descriptor();
    d.name = String::new(); // invalid
    let err = validate_rotation_set(&[d], &reg).unwrap_err();
    assert!(err.contains("name required"));
}

#[test]
fn rotation_set_non_overlapping_ok() {
    let reg = two_suite_registry();
    let d1 = CryptoRotationDescriptor {
        name: "first".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 100,
        spend_height: 200,
        sunset_height: 0,
    };
    let d2 = CryptoRotationDescriptor {
        name: "second".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 200, // starts exactly where d1 ends
        spend_height: 300,
        sunset_height: 0,
    };
    assert!(validate_rotation_set(&[d1, d2], &reg).is_ok());
}

#[test]
fn rotation_set_adjacent_no_gap_ok() {
    // [100,200) and [200,300) — touching but not overlapping
    let reg = two_suite_registry();
    let d1 = CryptoRotationDescriptor {
        name: "a".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 100,
        spend_height: 200,
        sunset_height: 0,
    };
    let d2 = CryptoRotationDescriptor {
        name: "b".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 200,
        spend_height: 300,
        sunset_height: 0,
    };
    // Overlap check: a.create < b.spend && b.create < a.spend
    // 100 < 300 && 200 < 200 → false → no overlap
    assert!(validate_rotation_set(&[d1, d2], &reg).is_ok());
}

#[test]
fn rotation_set_overlapping_detected() {
    let reg = two_suite_registry();
    let d1 = CryptoRotationDescriptor {
        name: "a".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 100,
        spend_height: 250,
        sunset_height: 0,
    };
    let d2 = CryptoRotationDescriptor {
        name: "b".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 200,
        spend_height: 350,
        sunset_height: 0,
    };
    let err = validate_rotation_set(&[d1, d2], &reg).unwrap_err();
    assert!(err.contains("overlapping"));
}

#[test]
fn rotation_set_second_invalid_descriptor() {
    let reg = two_suite_registry();
    let d1 = valid_descriptor();
    let d2 = CryptoRotationDescriptor {
        name: "bad".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x01, // same → invalid
        create_height: 5000,
        spend_height: 6000,
        sunset_height: 0,
    };
    let err = validate_rotation_set(&[d1, d2], &reg).unwrap_err();
    assert!(err.contains("must differ"));
    assert!(err.contains("rotation[1]")); // index preserved
}

// =============================================================
// DescriptorRotationProvider — boundary height 0 and 1
// =============================================================

#[test]
fn descriptor_h1_at_zero() {
    // create_height=0 means Phase 1 starts immediately
    let d = CryptoRotationDescriptor {
        name: "immediate".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 0,
        spend_height: 100,
        sunset_height: 200,
    };
    let p = DescriptorRotationProvider { descriptor: d };
    // At height 0: h >= H1(0) && h < H2(100) → Phase 1
    let cs = p.native_create_suites(0);
    assert!(cs.contains(0x01));
    assert!(cs.contains(0x02));
    let ss = p.native_spend_suites(0);
    assert!(ss.contains(0x01));
    assert!(ss.contains(0x02));
}

#[test]
fn descriptor_h1_at_one() {
    let d = CryptoRotationDescriptor {
        name: "h1-one".into(),
        old_suite_id: 0x01,
        new_suite_id: 0x02,
        create_height: 1,
        spend_height: 100,
        sunset_height: 0,
    };
    let p = DescriptorRotationProvider { descriptor: d };
    // h=0: Phase 0 → {old}
    let s = p.native_create_suites(0);
    assert!(s.contains(0x01));
    assert!(!s.contains(0x02));
    // h=1: Phase 1 → {old,new}
    let s = p.native_create_suites(1);
    assert!(s.contains(0x01));
    assert!(s.contains(0x02));
}

// =============================================================
// Clone / Debug derives via crate-external API
// =============================================================

#[test]
fn descriptor_clone() {
    let d = valid_descriptor();
    let d2 = d.clone();
    assert_eq!(d.name, d2.name);
    assert_eq!(d.old_suite_id, d2.old_suite_id);
    assert_eq!(d.create_height, d2.create_height);
}

#[test]
fn descriptor_debug() {
    let d = valid_descriptor();
    let dbg = format!("{:?}", d);
    assert!(dbg.contains("CryptoRotationDescriptor"));
    assert!(dbg.contains("rotation-1"));
}

#[test]
fn suite_params_clone_eq() {
    let reg = two_suite_registry();
    let p1 = reg.lookup(0x01).unwrap().clone();
    let p2 = reg.lookup(0x01).unwrap().clone();
    assert_eq!(p1, p2);
}

#[test]
fn native_suite_set_clone_eq() {
    let s1 = NativeSuiteSet::new(&[0x01, 0x02]);
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}
