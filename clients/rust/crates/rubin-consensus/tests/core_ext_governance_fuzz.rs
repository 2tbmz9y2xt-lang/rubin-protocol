//! Deterministic fuzz-style tests for core_ext governance:
//! GovernanceReplayToken, featurebit_state_at_height_from_window_counts,
//! flagday_active_at_height, validate_deployment_bit_uniqueness.
//!
//! Mirrors Go FuzzGovernanceReplayToken, FuzzFeatureBitStateAtHeightFromWindowCounts,
//! FuzzFlagDayHelpers.
//!
//! Invariant: no panic; deterministic; roundtrip canonicality.

use rubin_consensus::flagday::validate_deployment_bit_uniqueness;
use rubin_consensus::{
    constants::{SIGNAL_THRESHOLD, SIGNAL_WINDOW},
    featurebit_state_at_height_from_window_counts, flagday_active_at_height, FeatureBitDeployment,
    FlagDayDeployment, GovernanceReplayToken,
};

// =============================================================
// GovernanceReplayToken — roundtrip, determinism, validation
// =============================================================

#[test]
fn token_roundtrip_basic() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let encoded = token.to_bytes();
    assert_eq!(encoded.len(), 26);
    let decoded = GovernanceReplayToken::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, token);
}

#[test]
fn token_roundtrip_zeros() {
    let token = GovernanceReplayToken::issue(0, 0, 0, 0);
    let encoded = token.to_bytes();
    let decoded = GovernanceReplayToken::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, token);
}

#[test]
fn token_roundtrip_max_values() {
    let token = GovernanceReplayToken::issue(u16::MAX, u64::MAX, u64::MAX, u64::MAX);
    let encoded = token.to_bytes();
    let decoded = GovernanceReplayToken::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, token);
}

#[test]
fn token_from_bytes_wrong_len() {
    assert!(GovernanceReplayToken::from_bytes(&[]).is_err());
    assert!(GovernanceReplayToken::from_bytes(&[0u8; 25]).is_err());
    assert!(GovernanceReplayToken::from_bytes(&[0u8; 27]).is_err());
}

#[test]
fn token_from_bytes_all_zeros() {
    let token = GovernanceReplayToken::from_bytes(&[0u8; 26]).unwrap();
    assert_eq!(token.ext_id, 0);
    assert_eq!(token.nonce, 0);
    assert_eq!(token.issued_at_height, 0);
    assert_eq!(token.validity_window, 0);
}

#[test]
fn token_from_bytes_all_ff() {
    let token = GovernanceReplayToken::from_bytes(&[0xFF; 26]).unwrap();
    assert_eq!(token.ext_id, u16::MAX);
    assert_eq!(token.nonce, u64::MAX);
    assert_eq!(token.issued_at_height, u64::MAX);
    assert_eq!(token.validity_window, u64::MAX);
}

#[test]
fn token_validate_valid() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    assert!(token.validate(7, 100, 1).is_ok());
    assert!(token.validate(7, 149, 1).is_ok());
}

#[test]
fn token_validate_ext_id_mismatch() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let err = token.validate(8, 100, 1).unwrap_err();
    assert!(err.contains("ext_id mismatch"));
}

#[test]
fn token_validate_nonce_mismatch() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let err = token.validate(7, 100, 2).unwrap_err();
    assert!(err.contains("nonce mismatch"));
}

#[test]
fn token_validate_not_yet_valid() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let err = token.validate(7, 99, 1).unwrap_err();
    assert!(err.contains("not yet valid"));
}

#[test]
fn token_validate_expired() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let err = token.validate(7, 150, 1).unwrap_err();
    assert!(err.contains("expired"));
}

#[test]
fn token_validate_saturation_no_overflow() {
    // validity_window = u64::MAX → expiry saturates, never wraps
    let token = GovernanceReplayToken::issue(7, 1, u64::MAX, u64::MAX);
    // At u64::MAX height, should NOT be expired (saturated expiry = u64::MAX)
    // Actually issued_at_height = u64::MAX, so current_height = u64::MAX is valid (not before)
    // But expiry = u64::MAX.saturating_add(u64::MAX) = u64::MAX, so current >= expiry → expired
    let r = token.validate(7, u64::MAX, 1);
    assert!(r.is_err()); // expired because expiry == current
}

#[test]
fn token_roundtrip_then_validate_deterministic() {
    let token = GovernanceReplayToken::issue(7, 1, 100, 50);
    let encoded = token.to_bytes();
    let decoded = GovernanceReplayToken::from_bytes(&encoded).unwrap();

    let r1 = token.validate(7, 120, 1);
    let r2 = decoded.validate(7, 120, 1);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

#[test]
fn token_raw_bytes_roundtrip_canonical() {
    // Test with raw 26-byte data
    let raw = [0x42u8; 26];
    let decoded = GovernanceReplayToken::from_bytes(&raw).unwrap();
    let reencoded = decoded.to_bytes();
    assert_eq!(&raw[..], &reencoded[..]);
}

#[test]
fn token_incremental_raw_lengths_no_panic() {
    for len in 0..=50 {
        let buf = vec![0x55u8; len];
        let _ = GovernanceReplayToken::from_bytes(&buf);
    }
}

// =============================================================
// FeatureBitStateAtHeightFromWindowCounts — determinism, invariants
// =============================================================

fn basic_deployment() -> FeatureBitDeployment {
    FeatureBitDeployment {
        name: "fb".to_string(),
        bit: 1,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW * 4,
    }
}

#[test]
fn featurebit_basic_started() {
    let d = basic_deployment();
    let ev = featurebit_state_at_height_from_window_counts(&d, 0, &[]).unwrap();
    assert_eq!(ev.boundary_height, 0);
    assert_eq!(ev.signal_window, SIGNAL_WINDOW);
    assert_eq!(ev.signal_threshold, SIGNAL_THRESHOLD);
}

#[test]
fn featurebit_locked_in_on_threshold() {
    let d = basic_deployment();
    let ev = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &[SIGNAL_THRESHOLD])
        .unwrap();
    assert_eq!(ev.state, rubin_consensus::FeatureBitState::LockedIn);
    assert_eq!(ev.prev_window_signal_count, SIGNAL_THRESHOLD);
}

#[test]
fn featurebit_failed_on_timeout() {
    let d = FeatureBitDeployment {
        name: "fb".to_string(),
        bit: 1,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW,
    };
    let ev = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &[0]).unwrap();
    assert_eq!(ev.state, rubin_consensus::FeatureBitState::Failed);
}

#[test]
fn featurebit_empty_name_rejected() {
    let d = FeatureBitDeployment {
        name: String::new(),
        bit: 1,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW,
    };
    assert!(featurebit_state_at_height_from_window_counts(&d, 0, &[]).is_err());
}

#[test]
fn featurebit_bit_out_of_range() {
    let d = FeatureBitDeployment {
        name: "fb".to_string(),
        bit: 32,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW,
    };
    assert!(featurebit_state_at_height_from_window_counts(&d, 0, &[]).is_err());
}

#[test]
fn featurebit_timeout_before_start() {
    let d = FeatureBitDeployment {
        name: "fb".to_string(),
        bit: 1,
        start_height: SIGNAL_WINDOW,
        timeout_height: SIGNAL_WINDOW - 1,
    };
    assert!(featurebit_state_at_height_from_window_counts(&d, 0, &[]).is_err());
}

#[test]
fn featurebit_deterministic() {
    let d = basic_deployment();
    let counts = [100u32, 200, 300];
    let r1 = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW * 2 + 10, &counts);
    let r2 = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW * 2 + 10, &counts);
    assert_eq!(r1.is_ok(), r2.is_ok());
    if let (Ok(e1), Ok(e2)) = (r1, r2) {
        assert_eq!(e1, e2);
    }
}

#[test]
fn featurebit_boundary_height_calculation() {
    let d = basic_deployment();
    for h in [0, 1, SIGNAL_WINDOW - 1, SIGNAL_WINDOW, SIGNAL_WINDOW + 1] {
        let counts_needed = (h / SIGNAL_WINDOW) as usize;
        let counts: Vec<u32> = vec![0; counts_needed];
        if let Ok(ev) = featurebit_state_at_height_from_window_counts(&d, h, &counts) {
            let expected_boundary = h - (h % SIGNAL_WINDOW);
            assert_eq!(ev.boundary_height, expected_boundary);
        }
    }
}

#[test]
fn featurebit_prev_window_count_zero_below_first_boundary() {
    let d = basic_deployment();
    // Height within first window: prev_window_signal_count should be 0
    let ev = featurebit_state_at_height_from_window_counts(&d, 100, &[]).unwrap();
    assert_eq!(ev.prev_window_signal_count, 0);
}

#[test]
fn featurebit_insufficient_counts_rejected() {
    let d = basic_deployment();
    // Need 1 count for boundary_index=1, but provide 0
    let r = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW + 1, &[]);
    assert!(r.is_err());
}

// =============================================================
// FlagDay — determinism, validation
// =============================================================

#[test]
fn flagday_active_before_activation() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 100,
        bit: Some(7),
    };
    assert!(!flagday_active_at_height(&d, 99).unwrap());
}

#[test]
fn flagday_active_at_activation() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 100,
        bit: Some(7),
    };
    assert!(flagday_active_at_height(&d, 100).unwrap());
}

#[test]
fn flagday_active_after_activation() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 100,
        bit: Some(7),
    };
    assert!(flagday_active_at_height(&d, u64::MAX).unwrap());
}

#[test]
fn flagday_empty_name_rejected() {
    let d = FlagDayDeployment {
        name: String::new(),
        activation_height: 0,
        bit: None,
    };
    assert!(flagday_active_at_height(&d, 0).is_err());
}

#[test]
fn flagday_bit_out_of_range() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 0,
        bit: Some(32),
    };
    assert!(flagday_active_at_height(&d, 0).is_err());
}

#[test]
fn flagday_bit_31_valid() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 0,
        bit: Some(31),
    };
    assert!(flagday_active_at_height(&d, 0).is_ok());
}

#[test]
fn flagday_no_bit_valid() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 0,
        bit: None,
    };
    assert!(flagday_active_at_height(&d, 0).unwrap());
}

#[test]
fn flagday_deterministic() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 100,
        bit: Some(7),
    };
    let r1 = flagday_active_at_height(&d, 99);
    let r2 = flagday_active_at_height(&d, 99);
    assert_eq!(r1.is_ok(), r2.is_ok());
    assert_eq!(r1.unwrap(), r2.unwrap());
}

#[test]
fn flagday_height_zero_activation_zero() {
    let d = FlagDayDeployment {
        name: "flag".to_string(),
        activation_height: 0,
        bit: Some(0),
    };
    assert!(flagday_active_at_height(&d, 0).unwrap());
}

// =============================================================
// validate_deployment_bit_uniqueness — determinism, conflicts
// =============================================================

#[test]
fn bit_uniqueness_empty() {
    assert!(validate_deployment_bit_uniqueness(&[]).is_empty());
}

#[test]
fn bit_uniqueness_no_conflict_different_bits() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: Some(3),
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 1000,
            bit: Some(5),
        },
    ];
    assert!(validate_deployment_bit_uniqueness(&ds).is_empty());
}

#[test]
fn bit_uniqueness_overlap_same_bit() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: Some(3),
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 2000,
            bit: Some(3),
        },
    ];
    let w = validate_deployment_bit_uniqueness(&ds);
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("bit 3 reuse overlap"));
}

#[test]
fn bit_uniqueness_no_overlap_far_apart() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: Some(3),
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 4000,
            bit: Some(3),
        },
    ];
    assert!(validate_deployment_bit_uniqueness(&ds).is_empty());
}

#[test]
fn bit_uniqueness_no_bit_skipped() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: None,
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 1000,
            bit: None,
        },
    ];
    assert!(validate_deployment_bit_uniqueness(&ds).is_empty());
}

#[test]
fn bit_uniqueness_three_way_overlap() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: Some(7),
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 1500,
            bit: Some(7),
        },
        FlagDayDeployment {
            name: "C".into(),
            activation_height: 2000,
            bit: Some(7),
        },
    ];
    assert_eq!(validate_deployment_bit_uniqueness(&ds).len(), 3);
}

#[test]
fn bit_uniqueness_deterministic() {
    let ds = vec![
        FlagDayDeployment {
            name: "A".into(),
            activation_height: 1000,
            bit: Some(3),
        },
        FlagDayDeployment {
            name: "B".into(),
            activation_height: 2000,
            bit: Some(3),
        },
    ];
    let w1 = validate_deployment_bit_uniqueness(&ds);
    let w2 = validate_deployment_bit_uniqueness(&ds);
    assert_eq!(w1, w2);
}
