use crate::txcontext::Uint128;

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
