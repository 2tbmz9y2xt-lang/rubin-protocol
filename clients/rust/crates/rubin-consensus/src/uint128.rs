#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint128 {
    pub lo: u64,
    pub hi: u64,
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_uint128_from_native_to_native_roundtrips_full_domain() {
        let value: u128 = kani::any();
        let split = Uint128::from_native(value);
        assert_eq!(split.to_native(), value);
    }

    #[kani::proof]
    fn verify_uint128_to_native_from_native_roundtrips_full_domain() {
        let lo: u64 = kani::any();
        let hi: u64 = kani::any();
        let split = Uint128 { lo, hi };
        assert_eq!(Uint128::from_native(split.to_native()), split);
    }
}

impl Uint128 {
    pub fn from_native(value: u128) -> Self {
        Self {
            lo: value as u64,
            hi: (value >> 64) as u64,
        }
    }

    pub fn to_native(self) -> u128 {
        ((self.hi as u128) << 64) | (self.lo as u128)
    }
}
