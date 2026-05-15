mod alg;
mod binding;
mod bootstrap;
mod digest;
mod ffi;
mod keypair;

pub use binding::{verify_sig, verify_sig_with_registry};
pub(crate) use bootstrap::ensure_openssl_consensus_init;
pub(crate) use digest::openssl_verify_sig_digest_oneshot;
pub use keypair::Mldsa87Keypair;

#[cfg(test)]
pub(crate) use alg::test_suite_alg_name;
#[cfg(test)]
pub(crate) use bootstrap::{
    test_ensure_openssl_bootstrap_for_mode, test_openssl_check_sigalg_bad_alg,
    test_set_env_if_empty,
};
#[cfg(test)]
pub(crate) use digest::{
    test_openssl_verify_sig_digest_oneshot_bad_alg,
    test_openssl_verify_sig_digest_oneshot_empty_input,
};
#[cfg(test)]
mod tests;
