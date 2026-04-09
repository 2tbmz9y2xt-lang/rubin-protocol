#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_crypto_backend_policy as m


class CryptoBackendPolicyTests(unittest.TestCase):
    def test_go_required_snippet_groups_accept_legacy_direct_dispatch(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        return opensslVerifySigOneShot("ML-DSA-87", pubkey, signature, digest32[:])
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                text,
            ),
            [],
        )

    def test_go_required_snippet_groups_accept_binding_resolution_path(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        return verifySigWithBinding(binding, pubkey, signature, digest32)
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                text,
            ),
            [],
        )

    def test_go_binding_resolution_without_handoff_fails(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        return false, err
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            text,
        )
        self.assertTrue(
            any("missing required binding handoff snippet" in err for err in errors)
        )

    def test_go_binding_handoff_without_resolution_fails(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        return verifySigWithBinding(binding, pubkey, signature, digest32)
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            text,
        )
        self.assertTrue(
            any("missing required binding resolution snippet" in err for err in errors)
        )

    def test_go_binding_resolution_path_accepts_last_switch_arm(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        return verifySigWithBinding(binding, pubkey, signature, digest32)
    }
    return false, nil
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                text,
            ),
            [],
        )

    def test_go_binding_resolution_path_ignores_nested_default(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        switch len(signature) {
        default:
            binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
            if err != nil {
                return false, err
            }
            return verifySigWithBinding(binding, pubkey, signature, digest32)
        }
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                text,
            ),
            [],
        )

    def test_go_comment_braces_do_not_break_case_extraction(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        // } comment-only brace must not terminate the function early
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        return verifySigWithBinding(binding, pubkey, signature, digest32)
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                text,
            ),
            [],
        )

    def test_go_comment_spoofed_handoff_does_not_count(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        // return verifySigWithBinding(binding, pubkey, signature, digest32)
        return false, err
    default:
        return false, nil
    }
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
    EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
    return true, nil
}
"""
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            text,
        )
        self.assertTrue(
            any("missing required binding handoff snippet" in err for err in errors)
        )


if __name__ == "__main__":
    unittest.main()
