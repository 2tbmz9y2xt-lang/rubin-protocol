use crate::constants::{SIGNAL_THRESHOLD, SIGNAL_WINDOW};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureBitState {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

impl FeatureBitState {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeatureBitState::Defined => "DEFINED",
            FeatureBitState::Started => "STARTED",
            FeatureBitState::LockedIn => "LOCKED_IN",
            FeatureBitState::Active => "ACTIVE",
            FeatureBitState::Failed => "FAILED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct FeatureBitDeployment {
    pub name: String,
    pub bit: u8,
    pub start_height: u64,
    pub timeout_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureBitEval {
    pub state: FeatureBitState,
    pub boundary_height: u64,
    pub prev_window_signal_count: u32,
    pub signal_window: u64,
    pub signal_threshold: u32,
}

fn next_state(
    prev: FeatureBitState,
    boundary_height: u64,
    prev_window_signal_count: u32,
    d: &FeatureBitDeployment,
) -> FeatureBitState {
    match prev {
        FeatureBitState::Defined => {
            if boundary_height >= d.start_height {
                FeatureBitState::Started
            } else {
                FeatureBitState::Defined
            }
        }
        FeatureBitState::Started => {
            if prev_window_signal_count >= SIGNAL_THRESHOLD {
                FeatureBitState::LockedIn
            } else if boundary_height >= d.timeout_height {
                FeatureBitState::Failed
            } else {
                FeatureBitState::Started
            }
        }
        FeatureBitState::LockedIn => FeatureBitState::Active,
        FeatureBitState::Active => FeatureBitState::Active,
        FeatureBitState::Failed => FeatureBitState::Failed,
    }
}

pub fn featurebit_state_at_height_from_window_counts(
    d: &FeatureBitDeployment,
    height: u64,
    window_signal_counts: &[u32],
) -> Result<FeatureBitEval, String> {
    if d.name.is_empty() {
        return Err("featurebits: name required".to_string());
    }
    if d.bit > 31 {
        return Err(format!("featurebits: bit out of range: {}", d.bit));
    }
    if d.timeout_height < d.start_height {
        return Err("featurebits: timeout_height < start_height".to_string());
    }

    let boundary_height = height - (height % SIGNAL_WINDOW);
    let target_boundary_index = boundary_height / SIGNAL_WINDOW;

    let need_windows = target_boundary_index as usize;
    if window_signal_counts.len() < need_windows {
        return Err(format!(
            "featurebits: need {} window_signal_counts entries, got {}",
            need_windows,
            window_signal_counts.len()
        ));
    }

    let mut state = FeatureBitState::Defined;
    for boundary_index in 0..=target_boundary_index {
        let bh = boundary_index * SIGNAL_WINDOW;
        let prev_cnt = if bh < SIGNAL_WINDOW {
            0
        } else {
            window_signal_counts[(boundary_index - 1) as usize]
        };
        state = next_state(state, bh, prev_cnt, d);
    }

    let prev_cnt = if boundary_height < SIGNAL_WINDOW {
        0
    } else {
        window_signal_counts[(target_boundary_index - 1) as usize]
    };

    Ok(FeatureBitEval {
        state,
        boundary_height,
        prev_window_signal_count: prev_cnt,
        signal_window: SIGNAL_WINDOW,
        signal_threshold: SIGNAL_THRESHOLD,
    })
}
