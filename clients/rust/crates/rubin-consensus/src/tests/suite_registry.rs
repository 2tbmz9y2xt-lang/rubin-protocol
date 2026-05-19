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
fn test_descriptor_native_suite_set_fails_closed_on_unexpected_cardinality() {
    let s = descriptor_native_suite_set(&[0x01, 0x02, 0x03]);
    assert_eq!(s.len(), 0);
    assert!(!s.contains(0x01));
    assert!(!s.contains(0x02));
    assert!(!s.contains(0x03));
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
