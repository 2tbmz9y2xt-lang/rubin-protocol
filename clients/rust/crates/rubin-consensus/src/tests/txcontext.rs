use crate::error::ErrorCode;
use crate::txcontext::{TxContextContinuing, Uint128};

#[test]
fn txcontext_get_output_checked_rejects_missing_slot() {
    let continuing = TxContextContinuing {
        continuing_output_count: 1,
        continuing_outputs: [None, None],
    };

    let err = continuing.get_output_checked(0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "txcontext continuing output missing");
}

#[test]
fn txcontext_get_output_checked_rejects_out_of_bounds_index() {
    let continuing = TxContextContinuing::default();
    let err = continuing.get_output_checked(0).unwrap_err();
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
    assert_eq!(err.msg, "txcontext continuing output index out of bounds");
}

#[test]
fn uint128_roundtrips_native() {
    for value in [
        0u128,
        1,
        u64::MAX as u128,
        (u64::MAX as u128) + 1,
        u128::MAX,
    ] {
        assert_eq!(Uint128::from_native(value).to_native(), value);
    }
}
