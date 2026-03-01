use crate::constants::{SIGNAL_THRESHOLD, SIGNAL_WINDOW};
use crate::featurebits::{
    featurebit_state_at_height_from_window_counts, FeatureBitDeployment, FeatureBitState,
};

#[test]
fn featurebits_single_step_no_double_transition() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 0,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW * 10,
    };

    // Window 0 signals above threshold; at boundary 0 we still must only enter STARTED.
    let counts: Vec<u32> = vec![SIGNAL_THRESHOLD, 0];

    let ev0 = featurebit_state_at_height_from_window_counts(&d, 0, &counts[0..0]).unwrap();
    assert_eq!(ev0.state, FeatureBitState::Started);

    let ev1 =
        featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &counts[0..1]).unwrap();
    assert_eq!(ev1.state, FeatureBitState::LockedIn);
}

#[test]
fn featurebits_lockin_wins_over_timeout() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 0,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW,
    };
    let counts: Vec<u32> = vec![SIGNAL_THRESHOLD];

    let ev = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &counts).unwrap();
    assert_eq!(ev.state, FeatureBitState::LockedIn);
}

#[test]
fn featurebits_timeout_to_failed() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 0,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW,
    };
    let counts: Vec<u32> = vec![0];

    let ev = featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &counts).unwrap();
    assert_eq!(ev.state, FeatureBitState::Failed);
}

#[test]
fn featurebits_locked_in_to_active_after_one_window() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 0,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW * 10,
    };
    let counts: Vec<u32> = vec![SIGNAL_THRESHOLD, 0];

    let ev_locked =
        featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW, &counts[0..1]).unwrap();
    assert_eq!(ev_locked.state, FeatureBitState::LockedIn);

    let ev_active =
        featurebit_state_at_height_from_window_counts(&d, 2 * SIGNAL_WINDOW, &counts).unwrap();
    assert_eq!(ev_active.state, FeatureBitState::Active);
}

#[test]
fn featurebits_state_between_boundaries() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 0,
        start_height: 0,
        timeout_height: SIGNAL_WINDOW * 10,
    };
    let counts: Vec<u32> = vec![0];

    let ev =
        featurebit_state_at_height_from_window_counts(&d, SIGNAL_WINDOW + 123, &counts).unwrap();
    assert_eq!(ev.boundary_height, SIGNAL_WINDOW);
    assert_eq!(ev.state, FeatureBitState::Started);
}

#[test]
fn featurebits_bit_range() {
    let d = FeatureBitDeployment {
        name: "X".to_string(),
        bit: 32,
        start_height: 0,
        timeout_height: 1,
    };
    let err = featurebit_state_at_height_from_window_counts(&d, 0, &[]).unwrap_err();
    assert!(err.contains("out of range"));
}
