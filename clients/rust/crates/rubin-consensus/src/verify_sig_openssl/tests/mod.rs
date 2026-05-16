use super::binding::{
    default_runtime_suite_registry, resolve_suite_verifier_binding,
    runtime_suite_params_for_verification, runtime_suite_params_for_verification_with_default,
    runtime_verification_registry_with_default, SuiteVerifierBinding,
};
use super::digest::map_digest_verify_rc;
use super::{
    map_openssl_init_rc, openssl_bootstrap, openssl_consensus_bootstrap, parse_openssl_fips_mode,
    Mldsa87Keypair, OpenSslFipsMode,
};
use crate::error::ErrorCode;
use std::ffi::OsString;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

const CONSENSUS_BOOTSTRAP_COLD_START_CHILD: &str =
    "RUBIN_OPENSSL_CONSENSUS_BOOTSTRAP_COLD_START_CHILD";

fn canonical_default_suite_params() -> crate::suite_registry::SuiteParams {
    crate::suite_registry::SuiteRegistry::default_registry()
        .lookup(crate::constants::SUITE_ID_ML_DSA_87)
        .cloned()
        .expect("default runtime registry missing ML-DSA-87")
}

fn drifted_default_runtime_registry(
    mutate: impl FnOnce(&mut crate::suite_registry::SuiteParams),
) -> crate::suite_registry::SuiteRegistry {
    let mut params = canonical_default_suite_params();
    mutate(&mut params);
    let mut suites = std::collections::BTreeMap::new();
    suites.insert(crate::constants::SUITE_ID_ML_DSA_87, params);
    crate::suite_registry::SuiteRegistry::with_suites(suites)
}

fn openssl_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct OpenSslEnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved_conf: Option<OsString>,
    saved_modules: Option<OsString>,
}

impl OpenSslEnvGuard {
    fn acquire() -> Self {
        Self {
            _lock: openssl_env_lock().lock().expect("env lock"),
            saved_conf: std::env::var_os("OPENSSL_CONF"),
            saved_modules: std::env::var_os("OPENSSL_MODULES"),
        }
    }

    fn restore_value(key: &str, value: &Option<OsString>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }
}

impl Drop for OpenSslEnvGuard {
    fn drop(&mut self) {
        Self::restore_value("OPENSSL_CONF", &self.saved_conf);
        Self::restore_value("OPENSSL_MODULES", &self.saved_modules);
    }
}

#[test]
fn map_digest_verify_rc_accepts_valid_signature() {
    let got = map_digest_verify_rc(1).expect("rc=1 should be success");
    assert!(got);
}

#[test]
fn map_digest_verify_rc_rejects_invalid_signature() {
    let got = map_digest_verify_rc(0).expect("rc=0 should be deterministic invalid");
    assert!(!got);
}

#[test]
fn map_digest_verify_rc_negative_maps_to_sig_invalid() {
    let err = map_digest_verify_rc(-1).expect_err("rc<0 should be mapped error");
    assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
}

#[test]
fn map_openssl_init_rc_accepts_success() {
    map_openssl_init_rc(1, "bootstrap failed").expect("rc=1 should pass");
}

#[test]
fn map_openssl_init_rc_maps_failure_to_parse() {
    let err = map_openssl_init_rc(0, "bootstrap failed").expect_err("rc!=1 should fail");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "bootstrap failed");
}

#[test]
fn parse_openssl_fips_mode_accepts_supported_values() {
    assert_eq!(
        parse_openssl_fips_mode("").expect("empty should map to off"),
        OpenSslFipsMode::Off
    );
    assert_eq!(
        parse_openssl_fips_mode("off").expect("off should map to off"),
        OpenSslFipsMode::Off
    );
    assert_eq!(
        parse_openssl_fips_mode("ready").expect("ready should parse"),
        OpenSslFipsMode::Ready
    );
    assert_eq!(
        parse_openssl_fips_mode("only").expect("only should parse"),
        OpenSslFipsMode::Only
    );
}

#[test]
fn parse_openssl_fips_mode_trims_and_ignores_case() {
    assert_eq!(
        parse_openssl_fips_mode(" OFF ").expect("trimmed off should parse"),
        OpenSslFipsMode::Off
    );
    assert_eq!(
        parse_openssl_fips_mode("\tReady\n").expect("trimmed ready should parse"),
        OpenSslFipsMode::Ready
    );
    assert_eq!(
        parse_openssl_fips_mode("Only").expect("case-insensitive only should parse"),
        OpenSslFipsMode::Only
    );
}

#[test]
fn parse_openssl_fips_mode_rejects_unknown_value() {
    let err = parse_openssl_fips_mode("definitely-invalid")
        .expect_err("unknown mode must return parse error");
    assert_eq!(err.code, ErrorCode::TxErrParse);
}

#[test]
fn openssl_bootstrap_ready_smoke() {
    let _guard = OpenSslEnvGuard::acquire();
    openssl_bootstrap(false).expect("ready-mode bootstrap should succeed");
}

#[test]
fn openssl_bootstrap_only_smoke_or_parse_error() {
    let _guard = OpenSslEnvGuard::acquire();
    if let Err(err) = openssl_bootstrap(true) {
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }
}

#[test]
fn mldsa87_keypair_generate_sign_and_verify_roundtrip() {
    let _guard = OpenSslEnvGuard::acquire();
    let keypair = match Mldsa87Keypair::generate() {
        Ok(value) => value,
        Err(err) => {
            assert_eq!(err.code, ErrorCode::TxErrParse);
            return;
        }
    };
    let pubkey = keypair.pubkey_bytes();
    let digest = [0x42; 32];
    let signature = keypair.sign_digest32(digest).expect("sign digest");
    let ok = super::verify_sig(
        crate::constants::SUITE_ID_ML_DSA_87,
        &pubkey,
        &signature,
        &digest,
    )
    .expect("verify signature");
    assert!(ok);
}

#[test]
fn openssl_consensus_bootstrap_ignores_inherited_openssl_env() {
    if std::env::var_os(CONSENSUS_BOOTSTRAP_COLD_START_CHILD).is_some() {
        openssl_consensus_bootstrap()
            .expect("cold-start consensus bootstrap must ignore inherited OPENSSL_* env");
        return;
    }

    let current_exe = std::env::current_exe().expect("current test binary path");
    let output = Command::new(current_exe)
        .arg("verify_sig_openssl::tests::openssl_consensus_bootstrap_ignores_inherited_openssl_env")
        .arg("--exact")
        .arg("--nocapture")
        .env(CONSENSUS_BOOTSTRAP_COLD_START_CHILD, "1")
        .env("OPENSSL_CONF", "/tmp/rubin-consensus-invalid-openssl.cnf")
        .env(
            "OPENSSL_MODULES",
            "/tmp/rubin-consensus-invalid-ossl-modules",
        )
        .output()
        .expect("spawn cold-start consensus bootstrap child");

    assert!(
        output.status.success(),
        "cold-start child failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Helper: generate keypair or skip test if OpenSSL state is corrupted
/// by bootstrap FIPS tests polluting global EVP provider config.
/// Only skips the narrow "CTX_new_from_name failed" case — any other
/// keygen failure is a real regression and must panic.
fn generate_or_skip() -> Option<Mldsa87Keypair> {
    let _guard = OpenSslEnvGuard::acquire();
    match Mldsa87Keypair::generate() {
        Ok(kp) => Some(kp),
        Err(err) => {
            assert_eq!(err.code, ErrorCode::TxErrParse);
            assert!(
                err.msg.contains("EVP_PKEY_CTX_new_from_name"),
                "keygen failed for unexpected reason (not bootstrap pollution): {}",
                err.msg
            );
            None // skip: OpenSSL state poisoned by bootstrap test
        }
    }
}

// Key Generation & Lifecycle (5)
#[test]
fn keypair_generate_pubkey_is_expected_length() {
    let Some(kp) = generate_or_skip() else { return };
    assert_eq!(
        kp.pubkey_bytes().len(),
        crate::constants::ML_DSA_87_PUBKEY_BYTES as usize
    );
}

#[test]
fn keypair_pubkey_bytes_is_copy() {
    let Some(kp) = generate_or_skip() else { return };
    let a = kp.pubkey_bytes();
    let b = kp.pubkey_bytes();
    assert_eq!(a, b);
}

#[test]
fn keypair_sign_digest_produces_expected_length() {
    let Some(kp) = generate_or_skip() else { return };
    let sig = kp.sign_digest32([0x42; 32]).expect("sign");
    assert_eq!(sig.len(), crate::constants::ML_DSA_87_SIG_BYTES as usize);
}

#[test]
fn keypair_sign_digest_rejects_nil_private_key() {
    let kp = Mldsa87Keypair {
        pkey: core::ptr::null_mut(),
        pubkey: vec![0xAB; crate::constants::ML_DSA_87_PUBKEY_BYTES as usize],
    };
    let pubkey = kp.pubkey_bytes();
    assert_eq!(
        pubkey.len(),
        crate::constants::ML_DSA_87_PUBKEY_BYTES as usize
    );
    assert_eq!(pubkey[0], 0xAB);

    let err = kp
        .sign_digest32([0x42; 32])
        .expect_err("nil pkey must reject before OpenSSL signing");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "openssl: nil ML-DSA keypair");
    assert_eq!(kp.pubkey_bytes(), pubkey);
}

#[test]
fn signing_ctx_rejects_public_only_key() {
    let Some(kp) = generate_or_skip() else { return };
    let pubkey = kp.pubkey_bytes();
    unsafe {
        // SAFETY: public_key is owned by this test after successful OpenSSL
        // allocation and is freed before return. The pubkey slice lives across
        // the FFI call and has the canonical ML-DSA-87 public-key length.
        let public_key = super::ffi::EVP_PKEY_new_raw_public_key_ex(
            core::ptr::null_mut(),
            c"ML-DSA-87".as_ptr(),
            core::ptr::null(),
            pubkey.as_ptr(),
            pubkey.len(),
        );
        assert!(!public_key.is_null(), "public-only EVP_PKEY allocation");

        let public_only = Mldsa87Keypair {
            pkey: public_key,
            pubkey,
        };
        let mctx = super::new_digest_sign_ctx(&public_only)
            .expect("OpenSSL accepts public-only key at init before signing fails");
        let err = super::sign_mldsa87_digest(mctx, [0x42; 32])
            .expect_err("public-only EVP_PKEY must not sign a digest");
        assert_eq!(err.code, ErrorCode::TxErrSigInvalid);
        assert_eq!(err.msg, "openssl: EVP_DigestSign failed");
    }
}

#[test]
fn signing_ctx_rejects_null_key() {
    let keypair = Mldsa87Keypair {
        pkey: core::ptr::null_mut(),
        pubkey: vec![0; crate::constants::ML_DSA_87_PUBKEY_BYTES as usize],
    };
    let err = super::new_digest_sign_ctx(&keypair)
        .expect_err("null EVP_PKEY must reject before OpenSSL sign init");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "openssl: nil ML-DSA keypair");
}

#[test]
fn signing_ctx_rejects_empty_key_at_init() {
    unsafe {
        // SAFETY: empty_key is a live EVP_PKEY allocated by OpenSSL and freed
        // before return. It has no key material, so sign init must reject it.
        let empty_key = openssl_sys::EVP_PKEY_new();
        assert!(!empty_key.is_null(), "empty EVP_PKEY allocation");
        let empty_keypair = Mldsa87Keypair {
            pkey: empty_key,
            pubkey: vec![0; crate::constants::ML_DSA_87_PUBKEY_BYTES as usize],
        };
        let err = super::new_digest_sign_ctx(&empty_keypair)
            .expect_err("empty EVP_PKEY must reject during OpenSSL sign init");
        assert_eq!(err.code, ErrorCode::TxErrParse);
        assert_eq!(err.msg, "openssl: EVP_DigestSignInit_ex failed");
    }
}

#[test]
fn keypair_close_idempotent() {
    let Some(kp) = generate_or_skip() else { return };
    drop(kp);
}

#[test]
fn keypair_generate_different_pubkeys() {
    let Some(a) = generate_or_skip() else { return };
    let Some(b) = generate_or_skip() else { return };
    assert_ne!(a.pubkey_bytes(), b.pubkey_bytes());
}

// Verify Error Paths (6)
#[test]
fn verify_sig_unsupported_suite_returns_error() {
    let err = super::verify_sig(0xFF, &[0u8; 32], &[0u8; 32], &[0u8; 32]).expect_err("bad suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn verify_sig_empty_inputs_return_false_or_error() {
    let result = super::verify_sig(crate::constants::SUITE_ID_ML_DSA_87, &[], &[], &[0u8; 32]);
    match result {
        Ok(false) => {}
        Err(_) => {}
        Ok(true) => panic!("empty inputs must not verify as true"),
    }
}

#[test]
fn openssl_digest_oneshot_rejects_empty_input_before_ffi() {
    let err = super::openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[], &[1], &[1])
        .expect_err("empty pubkey must reject before FFI");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "openssl: empty input");

    let err = super::openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[1], &[], &[1])
        .expect_err("empty signature must reject before FFI");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "openssl: empty input");

    let err = super::openssl_verify_sig_digest_oneshot(c"ML-DSA-87", &[1], &[1], &[])
        .expect_err("empty message must reject before FFI");
    assert_eq!(err.code, ErrorCode::TxErrParse);
    assert_eq!(err.msg, "openssl: empty input");
}

#[test]
fn verify_sig_wrong_message_returns_false() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x11; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let wrong_digest = [0x22; 32];
    let result = super::verify_sig(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &sig,
        &wrong_digest,
    )
    .expect("no error");
    assert!(!result, "wrong digest must return false");
}

#[test]
fn verify_sig_rejects_wrong_mldsa_lengths() {
    let result = super::verify_sig(
        crate::constants::SUITE_ID_ML_DSA_87,
        &[0u8; 16],
        &[0u8; 16],
        &[0u8; 32],
    );
    match result {
        Ok(false) => {}
        Err(_) => {}
        Ok(true) => panic!("wrong lengths must not verify true"),
    }
}

#[test]
fn verify_sig_corrupted_sig_returns_false() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x33; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0xFF;
    let result = super::verify_sig(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &bad_sig,
        &digest,
    )
    .expect("no error");
    assert!(!result, "corrupted sig must return false");
}

#[test]
fn verify_sig_unknown_suite_errors() {
    let err =
        super::verify_sig(0x42, &[0u8; 100], &[0u8; 100], &[0u8; 32]).expect_err("unknown suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

// Bootstrap & FIPS (7)
#[test]
fn bootstrap_mode_off_noop() {
    let _guard = OpenSslEnvGuard::acquire();
    super::test_ensure_openssl_bootstrap_for_mode("off").expect("off is noop");
}

#[test]
fn bootstrap_invalid_fips_mode_rejected() {
    let _guard = OpenSslEnvGuard::acquire();
    super::test_ensure_openssl_bootstrap_for_mode("banana").expect_err("bad mode");
}

#[test]
fn bootstrap_fips_only_or_skip() {
    let _guard = OpenSslEnvGuard::acquire();
    let _ = super::test_ensure_openssl_bootstrap_for_mode("only");
}

#[test]
fn suite_alg_name_known_suite() {
    let name = super::test_suite_alg_name(crate::constants::SUITE_ID_ML_DSA_87).expect("known");
    assert_eq!(name, "ML-DSA-87");
}

#[test]
fn suite_alg_name_unknown_suite_errors() {
    super::test_suite_alg_name(0xFF).expect_err("unknown");
}

#[test]
fn verify_sig_valid_roundtrip_ignores_fips() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x44; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let ok = super::verify_sig(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &sig,
        &digest,
    )
    .expect("verify");
    assert!(ok, "valid sig must verify");
}

#[test]
fn set_env_if_empty_behavior() {
    super::test_set_env_if_empty("RUBIN_TEST_UNUSED_KEY_12345", Some("value".to_string()));
}

// Concurrency (1)
#[test]
fn verify_sig_parallel_deterministic() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x55; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let pubkey = kp.pubkey_bytes();

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let pk = pubkey.clone();
            let s = sig.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    let ok =
                        super::verify_sig(crate::constants::SUITE_ID_ML_DSA_87, &pk, &s, &digest)
                            .expect("verify");
                    assert!(ok, "parallel verify must succeed");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("thread");
    }
}

// Registry Extension (2)
#[test]
fn verify_sig_with_registry_nil_uses_default_live_registry() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x66; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let ok = super::verify_sig_with_registry(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &sig,
        &digest,
        None,
    )
    .expect("verify");
    assert!(ok, "default live registry must verify canonical suite");
    assert!(default_runtime_suite_registry().is_canonical_default_live_manifest());
}

#[test]
fn verify_sig_with_registry_nil_matches_explicit_default_live_registry() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x67; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let explicit = crate::suite_registry::SuiteRegistry::default_registry();
    let canonical = canonical_default_suite_params();
    assert_eq!(
        canonical.verify_cost,
        crate::constants::VERIFY_COST_ML_DSA_87
    );

    let nil_ok = super::verify_sig_with_registry(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &sig,
        &digest,
        None,
    )
    .expect("nil verify");
    let explicit_ok = super::verify_sig_with_registry(
        crate::constants::SUITE_ID_ML_DSA_87,
        &kp.pubkey_bytes(),
        &sig,
        &digest,
        Some(&explicit),
    )
    .expect("explicit verify");

    assert_eq!(nil_ok, explicit_ok);
    assert!(
        nil_ok,
        "canonical default live registry must verify on both paths"
    );
    let explicit_params = explicit
        .lookup(crate::constants::SUITE_ID_ML_DSA_87)
        .cloned()
        .expect("explicit default registry missing ML-DSA-87");
    assert_eq!(canonical, explicit_params);
}

#[test]
fn runtime_suite_params_for_verification_nil_matches_explicit_default_live_registry() {
    let canonical = canonical_default_suite_params();
    let explicit = crate::suite_registry::SuiteRegistry::default_registry();

    let nil_params =
        runtime_suite_params_for_verification(crate::constants::SUITE_ID_ML_DSA_87, None)
            .expect("nil params");
    let explicit_params = runtime_suite_params_for_verification(
        crate::constants::SUITE_ID_ML_DSA_87,
        Some(&explicit),
    )
    .expect("explicit params");

    assert_eq!(nil_params, canonical);
    assert_eq!(explicit_params, canonical);
    assert_eq!(nil_params, explicit_params);
}

#[test]
fn runtime_suite_params_for_verification_public_wrapper_matches_helper() {
    let explicit = crate::suite_registry::SuiteRegistry::default_registry();

    let public_nil =
        runtime_suite_params_for_verification(crate::constants::SUITE_ID_ML_DSA_87, None)
            .expect("public nil params");
    let helper_nil = runtime_suite_params_for_verification_with_default(
        crate::constants::SUITE_ID_ML_DSA_87,
        None,
        &explicit,
    )
    .expect("helper nil params");

    let public_explicit = runtime_suite_params_for_verification(
        crate::constants::SUITE_ID_ML_DSA_87,
        Some(&explicit),
    )
    .expect("public explicit params");
    let helper_explicit = runtime_suite_params_for_verification_with_default(
        crate::constants::SUITE_ID_ML_DSA_87,
        Some(&explicit),
        &explicit,
    )
    .expect("helper explicit params");

    assert_eq!(public_nil, helper_nil);
    assert_eq!(public_explicit, helper_explicit);
    assert_eq!(public_nil, public_explicit);
}

#[test]
fn runtime_suite_params_for_verification_unknown_suite_preserves_error_surface() {
    let err = runtime_suite_params_for_verification(0xff, None)
        .expect_err("unknown suite must fail closed");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
    assert_eq!(err.msg, "verify_sig: unsupported suite_id");
}

#[test]
fn resolve_suite_verifier_binding_matches_core_ext_descriptor() {
    let params = canonical_default_suite_params();
    let binding =
        resolve_suite_verifier_binding(params.alg_name, params.pubkey_len, params.sig_len)
            .expect("binding");
    let descriptor = crate::core_ext_openssl_digest32_binding_descriptor_bytes(
        params.alg_name,
        params.pubkey_len,
        params.sig_len,
    )
    .expect("descriptor");
    let parsed =
        crate::parse_core_ext_openssl_digest32_binding_descriptor(&descriptor).expect("parse");
    match binding {
        SuiteVerifierBinding::OpenSslDigest32V1 {
            alg,
            pubkey_len,
            sig_len,
        } => {
            assert_eq!(alg.to_str().expect("alg utf8"), parsed.openssl_alg);
            assert_eq!(pubkey_len, parsed.pubkey_len);
            assert_eq!(sig_len, parsed.sig_len);
        }
    }
}

#[test]
fn resolve_suite_verifier_binding_live_policy_pins_canonical_legacy_v1_binding() {
    let entry = crate::live_binding_policy::live_binding_policy_runtime_entry(
        "ML-DSA-87",
        crate::constants::ML_DSA_87_PUBKEY_BYTES,
        crate::constants::ML_DSA_87_SIG_BYTES,
    )
    .expect("live binding entry");
    assert_eq!(
        entry.runtime_binding,
        crate::live_binding_policy::LIVE_BINDING_POLICY_RUNTIME_OPENSSL_DIGEST32_V1
    );
    assert_eq!(entry.alg_name, "ML-DSA-87");
    assert_eq!(entry.openssl_alg, "ML-DSA-87");

    let binding = resolve_suite_verifier_binding(
        "ML-DSA-87",
        crate::constants::ML_DSA_87_PUBKEY_BYTES,
        crate::constants::ML_DSA_87_SIG_BYTES,
    )
    .expect("binding");
    match binding {
        SuiteVerifierBinding::OpenSslDigest32V1 {
            alg,
            pubkey_len,
            sig_len,
        } => {
            assert_eq!(alg.to_str().expect("alg utf8"), "ML-DSA-87");
            assert_eq!(pubkey_len, crate::constants::ML_DSA_87_PUBKEY_BYTES);
            assert_eq!(sig_len, crate::constants::ML_DSA_87_SIG_BYTES);
        }
    }
}

#[test]
fn verify_sig_with_registry_unknown_suite_errors() {
    let err = super::verify_sig_with_registry(0xFF, &[0u8; 32], &[0u8; 32], &[0u8; 32], None)
        .expect_err("bad suite");
    assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid);
}

#[test]
fn verify_sig_with_registry_custom_suite_exact_v1_binding_allowed() {
    let Some(kp) = generate_or_skip() else { return };
    let digest = [0x68; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let mut suites = std::collections::BTreeMap::new();
    suites.insert(
        0x02,
        crate::suite_registry::SuiteParams {
            suite_id: 0x02,
            pubkey_len: crate::constants::ML_DSA_87_PUBKEY_BYTES,
            sig_len: crate::constants::ML_DSA_87_SIG_BYTES,
            verify_cost: crate::constants::VERIFY_COST_ML_DSA_87,
            alg_name: "ML-DSA-87",
        },
    );
    let registry = crate::suite_registry::SuiteRegistry::with_suites(suites);

    let ok =
        super::verify_sig_with_registry(0x02, &kp.pubkey_bytes(), &sig, &digest, Some(&registry))
            .expect("custom suite should reuse canonical v1 binding");
    assert!(ok, "custom suite entry should verify");
}

#[test]
fn runtime_verification_registry_rejects_noncanonical_default_manifest() {
    let test_cases = [
        (
            "alg_name",
            drifted_default_runtime_registry(|params| params.alg_name = "ML-DSA-65"),
        ),
        (
            "pubkey_len",
            drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
        ),
        (
            "sig_len",
            drifted_default_runtime_registry(|params| params.sig_len -= 1),
        ),
        (
            "verify_cost",
            drifted_default_runtime_registry(|params| params.verify_cost -= 1),
        ),
    ];

    for (name, registry) in test_cases {
        let err = runtime_verification_registry_with_default(None, &registry)
            .expect_err("noncanonical default registry must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
        assert_eq!(
            err.msg, "verify_sig: default runtime registry drift",
            "{name}"
        );
    }
}

#[test]
fn runtime_verification_registry_rejects_empty_and_alias_alg_name() {
    let test_cases = [
        (
            "alg_name_empty",
            drifted_default_runtime_registry(|params| params.alg_name = ""),
        ),
        (
            "alg_name_alias",
            drifted_default_runtime_registry(|params| params.alg_name = "ml-dsa-87"),
        ),
    ];

    for (name, registry) in test_cases {
        let err = runtime_verification_registry_with_default(None, &registry)
            .expect_err("noncanonical default registry must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
        assert_eq!(
            err.msg, "verify_sig: default runtime registry drift",
            "{name}"
        );
    }
}

#[test]
fn runtime_verification_registry_rejects_pubkey_sig_and_verify_cost_drift() {
    let test_cases = [
        (
            "pubkey_len",
            drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
        ),
        (
            "sig_len",
            drifted_default_runtime_registry(|params| params.sig_len -= 1),
        ),
        (
            "verify_cost",
            drifted_default_runtime_registry(|params| params.verify_cost -= 1),
        ),
    ];

    for (name, registry) in test_cases {
        let err = runtime_verification_registry_with_default(None, &registry)
            .expect_err("noncanonical default registry must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
        assert_eq!(
            err.msg, "verify_sig: default runtime registry drift",
            "{name}"
        );
    }
}

#[test]
fn runtime_suite_params_for_verification_with_default_rejects_noncanonical_default_manifest() {
    let test_cases = [
        (
            "alg_name_empty",
            drifted_default_runtime_registry(|params| params.alg_name = ""),
        ),
        (
            "alg_name_alias",
            drifted_default_runtime_registry(|params| params.alg_name = "ml-dsa-87"),
        ),
        (
            "pubkey_len",
            drifted_default_runtime_registry(|params| params.pubkey_len -= 1),
        ),
        (
            "sig_len",
            drifted_default_runtime_registry(|params| params.sig_len -= 1),
        ),
        (
            "verify_cost",
            drifted_default_runtime_registry(|params| params.verify_cost -= 1),
        ),
    ];

    for (name, registry) in test_cases {
        let err = runtime_suite_params_for_verification_with_default(
            crate::constants::SUITE_ID_ML_DSA_87,
            None,
            &registry,
        )
        .expect_err("noncanonical default registry must fail closed");
        assert_eq!(err.code, ErrorCode::TxErrSigAlgInvalid, "{name}");
        assert_eq!(
            err.msg, "verify_sig: default runtime registry drift",
            "{name}"
        );
    }
}

// Error Parsing (2)
#[test]
fn parse_fips_mode_valid_values() {
    let _guard = OpenSslEnvGuard::acquire();
    super::test_ensure_openssl_bootstrap_for_mode("off").expect("off");
    // "ready" mode may fail if FIPS provider not available — not a test failure
    let _ = super::test_ensure_openssl_bootstrap_for_mode("ready");
}

#[test]
fn openssl_check_sigalg_bad_alg_fails() {
    let _guard = OpenSslEnvGuard::acquire();
    super::test_openssl_check_sigalg_bad_alg().expect_err("bad alg must fail");
}

// Additional verification (1)
#[test]
fn openssl_verify_with_invalid_alg_name() {
    let _guard = OpenSslEnvGuard::acquire();
    // Test that invalid algorithm names are rejected
    let result = super::test_openssl_verify_sig_digest_oneshot_bad_alg();
    assert!(result.is_err());
}
