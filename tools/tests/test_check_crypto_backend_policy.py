#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_crypto_backend_policy as m


CGO_PREAMBLE = """
/*
static int rubin_verify_sig_oneshot() {
    EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL);
    return EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);
}
*/
import "C"
"""


CGO_LINE_PREAMBLE = """
// static int rubin_verify_sig_oneshot() {
//     EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL);
//     return EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);
// }
import "C"
"""


def go_fixture(text: str) -> str:
    return CGO_PREAMBLE + "\n" + text


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
                    go_fixture(text),
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
                go_fixture(text),
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
            go_fixture(text),
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
            go_fixture(text),
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
                    go_fixture(text),
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
                    go_fixture(text),
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
                    go_fixture(text),
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
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required binding handoff snippet" in err for err in errors)
        )

    def test_go_string_literal_spoofed_handoff_does_not_count(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
        if err != nil {
            return false, err
        }
        _ = "return verifySigWithBinding(binding, pubkey, signature, digest32)"
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
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required binding handoff snippet" in err for err in errors)
        )

    def test_go_multiline_binding_resolution_and_handoff_are_accepted(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding(
            "ML-DSA-87",
            ML_DSA_87_PUBKEY_BYTES,
            ML_DSA_87_SIG_BYTES,
        )
        if err != nil {
            return false, err
        }
        return verifySigWithBinding(
            binding,
            pubkey,
            signature,
            digest32,
        )
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
                    go_fixture(text),
                ),
                [],
            )

    def test_go_global_verify_helper_snippet_in_string_does_not_count(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        return opensslVerifySigOneShot("ML-DSA-87", pubkey, signature, digest32[:])
    default:
        return false, nil
    }
}

var spoof = "func opensslVerifySigOneShot("

/*
EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)
EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)
*/
"""
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required snippet group" in err for err in errors)
        )

    def test_go_binding_resolution_requires_exact_alg_literal(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        binding, err := resolveSuiteVerifierBinding("WRONG-ALG", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
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
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required binding resolution snippet" in err for err in errors)
        )

    def test_go_direct_dispatch_requires_exact_alg_literal(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        return opensslVerifySigOneShot("WRONG-ALG", pubkey, signature, digest32[:])
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
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required dispatch group" in err for err in errors)
        )

    def test_go_raw_string_binding_snippet_does_not_spoof_exact_literal(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        _ = `binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)`
        binding, err := resolveSuiteVerifierBinding("WRONG-ALG", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
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
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            go_fixture(text),
        )
        self.assertTrue(
            any("missing required binding resolution snippet" in err for err in errors)
        )

    def test_go_cgo_required_snippet_in_go_string_does_not_count(self):
        text = """
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
    switch suiteID {
    case SUITE_ID_ML_DSA_87:
        return opensslVerifySigOneShot("ML-DSA-87", pubkey, signature, digest32[:])
    default:
        return false, nil
    }
}

var spoof = "EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)"
"""
        errors = m.check_go_verify_required_snippets(
            Path("clients/go/consensus/verify_sig_openssl.go"),
            text,
        )
        self.assertTrue(
            any("missing cgo preamble" in err for err in errors)
        )
        self.assertTrue(
            any("missing required snippet group" in err for err in errors)
        )

    def test_go_line_comment_cgo_preamble_is_accepted(self):
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
    return true, nil
}
"""
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                CGO_LINE_PREAMBLE + "\n" + text,
            ),
            [],
        )

    def test_go_string_literal_func_verify_sig_does_not_confuse_parser(self):
        text = '''
var banner = "func verifySig("

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
'''
        self.assertEqual(
            m.check_go_verify_required_snippets(
                Path("clients/go/consensus/verify_sig_openssl.go"),
                go_fixture(text),
            ),
            [],
        )


class RustModuleResolutionTests(unittest.TestCase):
    """The Rust verify path is a split module (a `verify_sig_openssl.rs` facade
    plus a sibling `verify_sig_openssl/` directory of submodules). The binding
    policy resolves the module from its `mod NAME;` declarations so a required
    snippet living in a referenced submodule (the RUB-263/264 split) is found,
    without weakening the check: a removed snippet, a snippet only in an
    undeclared/stray file, and a snippet only in a `#[cfg(test)]` module must
    all still fail."""

    # A split layout that distributes every RUST_VERIFY_REQUIRED_SNIPPET across
    # the facade + declared submodule files, mirroring the real module shape.
    FACADE = "pub fn verify_sig() {}\npub mod alg;\npub mod bootstrap;\npub mod digest;\n"
    ALG = 'fn suite_id() { SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"), }\n'
    BOOTSTRAP = (
        "fn parse_openssl_fips_mode() {}\n"
        "fn ensure_openssl_bootstrap() {}\n"
        "OPENSSL_init_crypto();\nOSSL_PROVIDER_load();\nEVP_set_default_properties();\n"
    )
    DIGEST = (
        "fn openssl_verify_sig_digest_oneshot() {\n"
        "    EVP_DigestVerifyInit_ex();\n    core::ptr::null();\n    EVP_DigestVerify();\n}\n"
    )

    def _write_split_module(
        self, root: Path, *, bootstrap: str | None = None, facade: str | None = None
    ) -> Path:
        src = root / "src"
        module_dir = src / "verify_sig_openssl"
        module_dir.mkdir(parents=True)
        facade_path = src / "verify_sig_openssl.rs"
        facade_path.write_text(self.FACADE if facade is None else facade, encoding="utf-8")
        (module_dir / "alg.rs").write_text(self.ALG, encoding="utf-8")
        (module_dir / "bootstrap.rs").write_text(
            self.BOOTSTRAP if bootstrap is None else bootstrap, encoding="utf-8"
        )
        (module_dir / "digest.rs").write_text(self.DIGEST, encoding="utf-8")
        return facade_path

    def _module_text(self, facade: Path) -> str:
        return "\n".join(m.read_text(p) for p in m.rust_module_sources(facade))

    def test_single_file_module_resolves_to_just_the_facade(self):
        with tempfile.TemporaryDirectory() as tmp:
            facade = Path(tmp) / "verify_sig_openssl.rs"
            facade.write_text(self.FACADE, encoding="utf-8")
            self.assertEqual(m.rust_module_sources(facade), [facade])

    def test_missing_module_resolves_to_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            facade = Path(tmp) / "verify_sig_openssl.rs"
            self.assertEqual(m.rust_module_sources(facade), [])

    def test_split_module_resolves_facade_first_then_declared_submodules(self):
        # Sources are the facade followed by its `mod NAME;` declarations in
        # declaration order (alg, bootstrap, digest), resolved to files on disk.
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp))
            module_dir = facade.with_suffix("")
            self.assertEqual(
                m.rust_module_sources(facade),
                [
                    facade,
                    module_dir / "alg.rs",
                    module_dir / "bootstrap.rs",
                    module_dir / "digest.rs",
                ],
            )

    def test_dir_only_fallback_scans_directory_when_no_entry_file(self):
        # Directory-only fallback: neither a `verify_sig_openssl.rs` facade nor a
        # `verify_sig_openssl/mod.rs` entry exists, so there are no `mod`
        # declarations to resolve -- the directory is scanned (tests/ excluded)
        # rather than treating the module as empty.
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp))
            facade.unlink()
            module_dir = facade.with_suffix("")
            self.assertEqual(
                m.rust_module_sources(facade),
                [
                    module_dir / "alg.rs",
                    module_dir / "bootstrap.rs",
                    module_dir / "digest.rs",
                ],
            )

    def test_dir_only_mod_rs_entry_resolves_from_declarations(self):
        # A directory-only module whose entry is `verify_sig_openssl/mod.rs`
        # resolves submodules from that file's `mod NAME;` declarations, and an
        # undeclared sibling file is NOT included.
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp))
            facade.unlink()
            module_dir = facade.with_suffix("")
            (module_dir / "mod.rs").write_text(
                "pub mod alg;\npub mod bootstrap;\npub mod digest;\n", encoding="utf-8"
            )
            undeclared = module_dir / "orphan.rs"
            undeclared.write_text("// not referenced by any mod\n", encoding="utf-8")
            sources = m.rust_module_sources(facade)
            self.assertEqual(
                sources,
                [
                    module_dir / "mod.rs",
                    module_dir / "alg.rs",
                    module_dir / "bootstrap.rs",
                    module_dir / "digest.rs",
                ],
            )
            self.assertNotIn(undeclared, sources)

    def test_undeclared_submodule_file_is_excluded(self):
        # A required snippet moved into a `.rs` file that no `mod NAME;`
        # declaration references is NOT part of the compiled verify path, so it
        # must not satisfy the policy: the snippet must still be reported missing.
        alg_without_snippet = self.ALG.replace(
            'SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87")', "suite_other()"
        )
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp))
            module_dir = facade.with_suffix("")
            (module_dir / "alg.rs").write_text(alg_without_snippet, encoding="utf-8")
            orphan = module_dir / "orphan.rs"  # present on disk, declared by nothing
            orphan.write_text(
                'fn o() { SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"); }\n', encoding="utf-8"
            )
            sources = m.rust_module_sources(facade)
            self.assertNotIn(orphan, sources)
            errors = m.check_required_snippets(
                facade, self._module_text(facade), m.RUST_VERIFY_REQUIRED_SNIPPETS
            )
            joined = "\n".join(errors)
            self.assertIn("missing required snippet", joined)
            self.assertIn('SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87")', joined)

    def test_declared_child_modules_excludes_cfg_test_and_inline(self):
        text = (
            "pub mod alg;\n"
            "pub(crate) mod binding;\n"
            "#[cfg(test)]\nmod tests;\n"
            "#[cfg(test)]\npub mod test_helpers;\n"
            "mod inline { fn f() {} }\n"
        )
        self.assertEqual(m.declared_child_modules(text), ["alg", "binding"])

    def test_declared_child_modules_keeps_cfg_test_across_intervening_comments(self):
        # In Rust, comments/doc comments between `#[cfg(test)]` and `mod tests;`
        # are trivia and do not detach the attribute, so the module is still
        # test-only and must be excluded. Covers line, doc, and block comments.
        text = (
            "pub mod alg;\n"
            "#[cfg(test)]\n"
            "/// doc comment between attribute and item\n"
            "// another line comment\n"
            "mod tests;\n"
            "#[cfg(test)]\n"
            "/* block comment\n   spanning two lines */\n"
            "mod more_tests;\n"
            "pub mod binding;\n"
        )
        self.assertEqual(m.declared_child_modules(text), ["alg", "binding"])

    def test_required_snippets_found_across_split_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp))
            self.assertEqual(
                m.check_required_snippets(
                    facade, self._module_text(facade), m.RUST_VERIFY_REQUIRED_SNIPPETS
                ),
                [],
            )

    def test_removed_snippet_in_split_module_still_fails(self):
        # Drop `fn ensure_openssl_bootstrap()` from the submodule entirely: the
        # union-of-module check must still report it missing (no weakening).
        bootstrap_without_snippet = self.BOOTSTRAP.replace(
            "fn ensure_openssl_bootstrap() {}\n", ""
        )
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(
                Path(tmp), bootstrap=bootstrap_without_snippet
            )
            errors = m.check_required_snippets(
                facade, self._module_text(facade), m.RUST_VERIFY_REQUIRED_SNIPPETS
            )
            self.assertTrue(
                any("fn ensure_openssl_bootstrap()" in err for err in errors),
                errors,
            )

    def test_cfg_test_module_sources_are_excluded(self):
        # A `#[cfg(test)] mod tests;` declaration is test-only and not the
        # production verify path: a required snippet living ONLY in that module
        # must not satisfy the binding policy, and resolution must drop it.
        facade_with_tests = self.FACADE + "#[cfg(test)]\nmod tests;\n"
        alg_without_snippet = self.ALG.replace(
            'SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87")', "suite_other()"
        )
        with tempfile.TemporaryDirectory() as tmp:
            facade = self._write_split_module(Path(tmp), facade=facade_with_tests)
            module_dir = facade.with_suffix("")
            # remove the snippet from the production submodule ...
            (module_dir / "alg.rs").write_text(alg_without_snippet, encoding="utf-8")
            # ... and (spuriously) place it only in the cfg(test) module.
            tests_dir = module_dir / "tests"
            tests_dir.mkdir()
            test_file = tests_dir / "mod.rs"
            test_file.write_text(
                'fn t() { SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87"); }\n', encoding="utf-8"
            )
            sources = m.rust_module_sources(facade)
            self.assertNotIn(test_file, sources)
            errors = m.check_required_snippets(
                facade, self._module_text(facade), m.RUST_VERIFY_REQUIRED_SNIPPETS
            )
            # Pin the owning diagnostic: the snippet that exists only in the
            # cfg(test) module must be reported missing by name.
            joined = "\n".join(errors)
            self.assertIn("missing required snippet", joined)
            self.assertIn('SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87")', joined)

    def test_repo_rust_verify_module_satisfies_required_snippets(self):
        # Guard against future drift: the real in-tree module must satisfy every
        # required snippet through the union resolution.
        repo_root = TOOLS_DIR.parent
        facade = (
            repo_root
            / "clients"
            / "rust"
            / "crates"
            / "rubin-consensus"
            / "src"
            / "verify_sig_openssl.rs"
        )
        sources = m.rust_module_sources(facade)
        self.assertTrue(sources, f"no Rust verify module sources found at {facade}")
        text = "\n".join(m.read_text(p) for p in sources)
        self.assertEqual(
            m.check_required_snippets(facade, text, m.RUST_VERIFY_REQUIRED_SNIPPETS),
            [],
        )


if __name__ == "__main__":
    unittest.main()
