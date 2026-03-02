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
}
