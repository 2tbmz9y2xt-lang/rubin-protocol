#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlagDayDeployment {
    pub name: String,
    pub activation_height: u64,
    // Telemetry-only (0..31).
    pub bit: Option<u8>,
}

impl FlagDayDeployment {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("flagday: name required".to_string());
        }
        if let Some(b) = self.bit {
            if b > 31 {
                return Err(format!("flagday: bit out of range: {b}"));
            }
        }
        Ok(())
    }
}

/// Check a set of FlagDayDeployments for telemetry-bit reuse conflicts per
/// CANONICAL §23.2.3. Returns a list of human-readable warnings. An empty Vec
/// means no conflicts detected.
///
/// This is non-consensus: bit collisions do not invalidate blocks.
/// Implementations SHOULD log returned warnings at startup.
pub fn validate_deployment_bit_uniqueness(deployments: &[FlagDayDeployment]) -> Vec<String> {
    use crate::constants::FALLOW_PERIOD;

    struct Entry {
        name: String,
        bit: u8,
        reserve_end: u64,
    }

    let mut with_bit: Vec<Entry> = deployments
        .iter()
        .filter_map(|d| {
            d.bit.map(|b| Entry {
                name: d.name.clone(),
                bit: b,
                reserve_end: d.activation_height.saturating_add(FALLOW_PERIOD),
            })
        })
        .collect();

    // Sort by bit, then by reserve_end for deterministic output.
    with_bit.sort_by(|a, b| a.bit.cmp(&b.bit).then(a.reserve_end.cmp(&b.reserve_end)));

    let mut warnings = Vec::new();
    for i in 0..with_bit.len() {
        for j in (i + 1)..with_bit.len() {
            if with_bit[i].bit != with_bit[j].bit {
                break; // sorted by bit — no more matches
            }
            warnings.push(format!(
                "flagday: bit {} reuse overlap between {:?} (reserved until height {}) and {:?} (reserved until height {}) — §23.2.3 FALLOW_PERIOD violation",
                with_bit[i].bit,
                with_bit[i].name, with_bit[i].reserve_end,
                with_bit[j].name, with_bit[j].reserve_end,
            ));
        }
    }
    warnings
}

pub fn flagday_active_at_height(d: &FlagDayDeployment, height: u64) -> Result<bool, String> {
    d.validate()?;
    Ok(height >= d.activation_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flagday_active_at_height_basic() {
        let d = FlagDayDeployment {
            name: "X".to_string(),
            activation_height: 100,
            bit: Some(5),
        };
        assert!(!flagday_active_at_height(&d, 99).unwrap());
        assert!(flagday_active_at_height(&d, 100).unwrap());
    }

    #[test]
    fn flagday_bit_range() {
        let d = FlagDayDeployment {
            name: "X".to_string(),
            activation_height: 0,
            bit: Some(32),
        };
        let err = flagday_active_at_height(&d, 0).unwrap_err();
        assert_eq!(err, "flagday: bit out of range: 32");
    }

    #[test]
    fn bit_uniqueness_no_conflict() {
        let ds = vec![
            FlagDayDeployment { name: "A".into(), activation_height: 1000, bit: Some(3) },
            FlagDayDeployment { name: "B".into(), activation_height: 5000, bit: Some(5) },
        ];
        assert!(validate_deployment_bit_uniqueness(&ds).is_empty());
    }

    #[test]
    fn bit_uniqueness_same_bit_overlap() {
        let ds = vec![
            FlagDayDeployment { name: "A".into(), activation_height: 1000, bit: Some(3) },
            FlagDayDeployment { name: "B".into(), activation_height: 2000, bit: Some(3) },
        ];
        let w = validate_deployment_bit_uniqueness(&ds);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("bit 3 reuse overlap"));
    }

    #[test]
    fn bit_uniqueness_no_bit_skipped() {
        let ds = vec![
            FlagDayDeployment { name: "A".into(), activation_height: 1000, bit: None },
            FlagDayDeployment { name: "B".into(), activation_height: 1000, bit: None },
        ];
        assert!(validate_deployment_bit_uniqueness(&ds).is_empty());
    }

    #[test]
    fn bit_uniqueness_three_way_overlap() {
        let ds = vec![
            FlagDayDeployment { name: "A".into(), activation_height: 1000, bit: Some(7) },
            FlagDayDeployment { name: "B".into(), activation_height: 1500, bit: Some(7) },
            FlagDayDeployment { name: "C".into(), activation_height: 2000, bit: Some(7) },
        ];
        assert_eq!(validate_deployment_bit_uniqueness(&ds).len(), 3);
    }

    #[test]
    fn bit_uniqueness_empty() {
        assert!(validate_deployment_bit_uniqueness(&[]).is_empty());
    }
}
