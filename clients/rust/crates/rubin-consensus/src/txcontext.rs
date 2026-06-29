use crate::error::{ErrorCode, TxError};
use std::sync::Arc;

pub const TXCONTEXT_MAX_CONTINUING_OUTPUTS: usize = 2;

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

    #[kani::proof]
    fn verify_txcontext_get_output_checked_accepts_highest_valid_index() {
        let mut continuing = TxContextContinuing::default();
        continuing.continuing_output_count = 2;
        continuing.continuing_outputs[0] = Some(TxOutputView {
            value: 11,
            ext_payload: Arc::from(&[0x71][..]),
        });
        continuing.continuing_outputs[1] = Some(TxOutputView {
            value: 12,
            ext_payload: Arc::from(&[0x72][..]),
        });

        let output = continuing.get_output_checked(1).expect("index 1");
        assert_eq!(output.value, 12);
        assert_eq!(output.ext_payload.as_ref(), &[0x72]);
    }

    #[kani::proof]
    fn verify_txcontext_get_output_checked_rejects_count_boundary_index() {
        let mut continuing = TxContextContinuing::default();
        continuing.continuing_output_count = 2;
        continuing.continuing_outputs[0] = Some(TxOutputView {
            value: 11,
            ext_payload: Arc::from(&[0x71][..]),
        });
        continuing.continuing_outputs[1] = Some(TxOutputView {
            value: 12,
            ext_payload: Arc::from(&[0x72][..]),
        });

        let err = continuing
            .get_output_checked(TXCONTEXT_MAX_CONTINUING_OUTPUTS)
            .expect_err("boundary index must fail");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "txcontext continuing output index out of bounds");
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxContextBase {
    pub total_in: Uint128,
    pub total_out: Uint128,
    pub height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOutputView {
    pub value: u64,
    pub ext_payload: Arc<[u8]>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxContextContinuing {
    pub continuing_output_count: u8,
    pub continuing_outputs: [Option<TxOutputView>; TXCONTEXT_MAX_CONTINUING_OUTPUTS],
}

impl TxContextContinuing {
    pub fn valid_outputs(&self) -> &[Option<TxOutputView>] {
        &self.continuing_outputs[..self.continuing_output_count as usize]
    }

    pub fn get_output_checked(&self, index: usize) -> Result<&TxOutputView, TxError> {
        if index >= self.continuing_output_count as usize {
            return Err(TxError::new(
                ErrorCode::TxErrSigInvalid,
                "txcontext continuing output index out of bounds",
            ));
        }
        self.continuing_outputs[index].as_ref().ok_or_else(|| {
            TxError::new(
                ErrorCode::TxErrSigInvalid,
                "txcontext continuing output missing",
            )
        })
    }
}
