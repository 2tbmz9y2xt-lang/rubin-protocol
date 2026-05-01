package consensus

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSignDigest32ForConformanceFixture_Deterministic proves that the
// conformance-fixture-only signing helper produces byte-identical
// signatures for the same (key, digest) pair across two calls AND
// that the resulting signature passes the production verifier under
// the same public key. The combined assertion is the core fixture
// contract: deterministic AND consensus-valid.
//
// Proof assertions:
//  1. bytes.Equal(sig1, sig2) — same key + same digest → same signature.
//     Without OSSL_SIGNATURE_PARAM_DETERMINISTIC=1, OpenSSL ML-DSA
//     mixes fresh randomness per signature and the assertion fails;
//     empirically reproduced before the deterministic mode landed.
//  2. opensslVerifySigOneShot("ML-DSA-87", kp.PubkeyBytes(), sig1,
//     digest) returns (true, nil). Determinism alone does not prove
//     the signature is valid — a deterministic-but-bogus runtime
//     would still satisfy bytes.Equal. The verifier roundtrip pins
//     that the fixture-only helper produces signatures the same
//     verifier path accepts as the hedged production signer's.
func TestSignDigest32ForConformanceFixture_Deterministic(t *testing.T) {
	t.Parallel()
	// mustMLDSA87Keypair skips the test on OpenSSL builds that do
	// not expose the ML-DSA provider (matching the package-wide
	// pattern in sig_test_helpers_test.go); a hard t.Fatalf here
	// would regress the package's existing skip-on-unavailable
	// behaviour for capability-dependent crypto.
	kp := mustMLDSA87Keypair(t)

	digest := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	sig1, err := kp.SignDigest32ForConformanceFixture(digest)
	if err != nil {
		t.Fatalf("SignDigest32ForConformanceFixture(1): %v", err)
	}
	sig2, err := kp.SignDigest32ForConformanceFixture(digest)
	if err != nil {
		t.Fatalf("SignDigest32ForConformanceFixture(2): %v", err)
	}
	if len(sig1) != ML_DSA_87_SIG_BYTES {
		t.Fatalf("sig1 len=%d, want %d", len(sig1), ML_DSA_87_SIG_BYTES)
	}
	if len(sig2) != ML_DSA_87_SIG_BYTES {
		t.Fatalf("sig2 len=%d, want %d", len(sig2), ML_DSA_87_SIG_BYTES)
	}
	if !bytes.Equal(sig1, sig2) {
		// previewLen guards the failure-path %x format below so a
		// degenerate runtime that returns a short signature does not
		// turn an honest assertion failure into a slice-out-of-range
		// panic. previewLen is bounded by min(32, len(sig*)) so the
		// preview shows what we have without exceeding either slice.
		previewLen := 32
		if len(sig1) < previewLen {
			previewLen = len(sig1)
		}
		if len(sig2) < previewLen {
			previewLen = len(sig2)
		}
		t.Fatalf(
			"deterministic-mode sigs differ: sig1[:%d]=%x sig2[:%d]=%x (lens=%d,%d)",
			previewLen, sig1[:previewLen], previewLen, sig2[:previewLen],
			len(sig1), len(sig2),
		)
	}

	// Verifier roundtrip: deterministic signature must be accepted by
	// the production verifier under the same public key. This rejects
	// a degenerate runtime that emits identical-but-invalid bytes.
	ok, vErr := opensslVerifySigOneShot("ML-DSA-87", kp.PubkeyBytes(), sig1, digest[:])
	if vErr != nil {
		t.Fatalf("opensslVerifySigOneShot: %v", vErr)
	}
	if !ok {
		t.Fatalf("deterministic-mode signature rejected by production verifier under same pubkey")
	}
}

// TestSignDigest32ForConformanceFixture_DeterministicAcrossDERReimport
// closes the issue/PR contract loop: same DER import + same digest
// produces byte-identical signatures across two independent
// re-imported keypair instances, and the resulting signature
// verifies under the original (pre-export) public key.
//
// This is a stronger contract than the in-memory determinism test
// alone — the fixture generator's real path is "load DER from disk
// → sign", and an OpenSSL implementation could in principle diverge
// between the keygen-then-sign path (in-memory keypair) and the
// DER-import-then-sign path (re-loaded keypair). This test makes
// that divergence empirically detectable.
//
// Proof assertions:
//  1. PrivateKeyDER on kp1 round-trips through NewMLDSA87KeypairFromDER
//     to two independent keypair instances kp2, kp3.
//  2. Both kp2 and kp3 produce byte-identical signatures for the
//     same digest (signer-side determinism is preserved across DER
//     import).
//  3. The signature kp2 emits is byte-identical to the signature
//     kp1 emits — DER export/import is a no-op on the deterministic
//     output.
//  4. The signature is accepted by opensslVerifySigOneShot under
//     kp1.PubkeyBytes() — DER-imported keypair's signature remains
//     consensus-valid under the original public key.
func TestSignDigest32ForConformanceFixture_DeterministicAcrossDERReimport(t *testing.T) {
	t.Parallel()
	// Skip-on-unavailable handled by mustMLDSA87Keypair (mirrors
	// the package convention for capability-dependent ML-DSA
	// tests); subsequent NewMLDSA87KeypairFromDER calls reuse the
	// same OpenSSL build, so any failure there is a real regression
	// rather than a provider-unavailability skip.
	kp1 := mustMLDSA87Keypair(t)

	der, err := kp1.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}
	if len(der) == 0 {
		t.Fatalf("PrivateKeyDER returned empty bytes")
	}

	kp2, err := NewMLDSA87KeypairFromDER(der)
	if err != nil {
		t.Fatalf("NewMLDSA87KeypairFromDER(2): %v", err)
	}
	defer kp2.Close()

	kp3, err := NewMLDSA87KeypairFromDER(der)
	if err != nil {
		t.Fatalf("NewMLDSA87KeypairFromDER(3): %v", err)
	}
	defer kp3.Close()

	digest := [32]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04}
	sig1, err := kp1.SignDigest32ForConformanceFixture(digest)
	if err != nil {
		t.Fatalf("kp1.SignDigest32ForConformanceFixture: %v", err)
	}
	sig2, err := kp2.SignDigest32ForConformanceFixture(digest)
	if err != nil {
		t.Fatalf("kp2.SignDigest32ForConformanceFixture: %v", err)
	}
	sig3, err := kp3.SignDigest32ForConformanceFixture(digest)
	if err != nil {
		t.Fatalf("kp3.SignDigest32ForConformanceFixture: %v", err)
	}

	for name, sig := range map[string][]byte{"sig1": sig1, "sig2": sig2, "sig3": sig3} {
		if len(sig) != ML_DSA_87_SIG_BYTES {
			t.Fatalf("%s len=%d, want %d", name, len(sig), ML_DSA_87_SIG_BYTES)
		}
	}
	if !bytes.Equal(sig2, sig3) {
		t.Fatalf("DER-roundtrip determinism failed: kp2 and kp3 (both built from same DER) produce different sigs")
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("DER-roundtrip identity failed: kp1 (in-memory) and kp2 (DER-reimport) produce different sigs for same digest")
	}

	// Verify under the ORIGINAL pubkey: proves that DER round-trip
	// did not silently substitute a different keypair.
	ok, vErr := opensslVerifySigOneShot("ML-DSA-87", kp1.PubkeyBytes(), sig2, digest[:])
	if vErr != nil {
		t.Fatalf("opensslVerifySigOneShot under kp1 pubkey: %v", vErr)
	}
	if !ok {
		t.Fatalf("DER-reimport signature rejected by verifier under original public key")
	}
}

// TestValidateConformanceSignResult exercises the testable
// validation helper extracted from
// SignDigest32ForConformanceFixture. The defensive crypto branches
// (rc != 0 from EVP_DigestSign, sigLen mismatch from a degenerate
// OpenSSL ML-DSA implementation) cannot be triggered from the public
// Sign entrypoint without a working fault injector, so this test
// asserts the helper's contract directly with crafted inputs.
//
// Cases:
//   - happy path: ret=0, sigLen=ML_DSA_87_SIG_BYTES → nil.
//   - rc!=0 path: ret=-1, errBuf carries an OpenSSL error string →
//     wrapped error containing the OpenSSL text.
//   - sigLen mismatch path: ret=0, sigLen=ML_DSA_87_SIG_BYTES-1 →
//     wrapped error naming actual + expected lengths.
func TestValidateConformanceSignResult(t *testing.T) {
	t.Parallel()
	emptyBuf := make([]byte, 16)
	if err := validateConformanceSignResult(0, ML_DSA_87_SIG_BYTES, emptyBuf); err != nil {
		t.Fatalf("happy path err=%v, want nil", err)
	}

	openSSLErr := []byte("EVP_DigestSign(deterministic) failed: simulated\x00")
	err := validateConformanceSignResult(-1, 0, openSSLErr)
	if err == nil {
		t.Fatalf("rc!=0 path returned nil, want error")
	}
	if !strings.Contains(err.Error(), "EVP_DigestSign(deterministic) failed") {
		t.Fatalf("rc!=0 path err=%q, want substring %q", err.Error(), "EVP_DigestSign(deterministic) failed")
	}

	err = validateConformanceSignResult(0, ML_DSA_87_SIG_BYTES-1, emptyBuf)
	if err == nil {
		t.Fatalf("sigLen mismatch path returned nil, want error")
	}
	if !strings.Contains(err.Error(), "unexpected signature length") {
		t.Fatalf("sigLen mismatch err=%q, want substring %q", err.Error(), "unexpected signature length")
	}
	wantSuffix := fmt.Sprintf("%d, want %d", ML_DSA_87_SIG_BYTES-1, ML_DSA_87_SIG_BYTES)
	if !strings.Contains(err.Error(), wantSuffix) {
		t.Fatalf("sigLen mismatch err=%q, want substring %q", err.Error(), wantSuffix)
	}
}

// TestSignDigest32ForConformanceFixture_NilKeypair covers the nil
// guard at the top of the helper for both nil-receiver and zero-pkey
// keypairs. Mirrors the established
// TestMLDSA87Keypair_SignDigest32_NilKeypairErrors pattern in
// openssl_signer_additional_test.go so the conformance helper has the
// same defensive coverage as the production hedged path.
func TestSignDigest32ForConformanceFixture_NilKeypair(t *testing.T) {
	t.Parallel()
	var digest [32]byte

	var nilKP *MLDSA87Keypair
	if _, err := nilKP.SignDigest32ForConformanceFixture(digest); err == nil {
		t.Fatalf("expected error from nil receiver, got nil")
	}

	zeroKP := &MLDSA87Keypair{}
	if _, err := zeroKP.SignDigest32ForConformanceFixture(digest); err == nil {
		t.Fatalf("expected error from zero-pkey keypair, got nil")
	}
}

// TestSignDigest32_HedgedNotAssertedDeterministic asserts that the
// production SignDigest32 path REMAINS valid (signs without error and
// returns full-length signatures) — without claiming it is deterministic.
// The hedged-vs-deterministic invariant is signer-side only, so this
// test only checks that production signing was not regressed by the new
// conformance-fixture helper. It deliberately does NOT compare sig
// bytes for equality.
//
// Proof assertion: two SignDigest32 calls return non-empty, full-length
// signatures with no error. The function does not pin determinism; the
// hedged contract is preserved.
func TestSignDigest32_HedgedNotAssertedDeterministic(t *testing.T) {
	t.Parallel()
	// Skip-on-unavailable for the same reason as the deterministic
	// tests; this test verifies the production hedged path is
	// still functional, which is moot when the ML-DSA provider is
	// unavailable.
	kp := mustMLDSA87Keypair(t)

	digest := [32]byte{0xAB}
	sig1, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32(1): %v", err)
	}
	sig2, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32(2): %v", err)
	}
	if len(sig1) != ML_DSA_87_SIG_BYTES || len(sig2) != ML_DSA_87_SIG_BYTES {
		t.Fatalf("sig lens=%d,%d want %d", len(sig1), len(sig2), ML_DSA_87_SIG_BYTES)
	}
	// Intentionally no bytes.Equal assertion: the hedged production
	// path may or may not emit identical bytes, depending on OpenSSL
	// internals; pinning either branch would couple this test to an
	// implementation detail we are explicitly not changing.
}

// TestSignDigest32ForConformanceFixture_ConformanceOnlyCallerGuard
// enforces the documented package contract that
// SignDigest32ForConformanceFixture is reachable only from a small,
// explicit allowlist:
//   - the declaration file itself
//     (clients/go/consensus/openssl_signer_conformance_fixture.go),
//   - the matching test file (this file), which exercises the helper
//     and owns the caller-guard logic,
//   - any file (production OR test) under
//     clients/go/cmd/gen-conformance-fixtures/, the conformance
//     fixture generator that consumes the helper.
//
// Any other Go source file that references the identifier
// SignDigest32ForConformanceFixture — including other consensus/
// _test.go files, other consensus/ production files, node, wallet,
// or any clients/go subtree outside the generator — is treated as
// a contract violation. The earlier "skip every _test.go" rule was
// too lax: it would silently accept a node/wallet test that pulled
// in the deterministic helper.
//
// Detection uses go/parser + ast.Inspect to match the identifier
// at the AST level; this rejects substring false positives (e.g.,
// "SignDigest32ForConformanceFixtureBuilder" no longer matches),
// rejects comment / string-literal mentions outright, and detects
// both bare references and selector-qualified references such as
// "consensus.SignDigest32ForConformanceFixture".
//
// Proof assertion: walking the repo's clients/go tree and
// AST-scanning every .go file (production AND test) outside the
// allowlist returns the empty violator set.
func TestSignDigest32ForConformanceFixture_ConformanceOnlyCallerGuard(t *testing.T) {
	t.Parallel()
	clientsGoRoot := findClientsGoRoot(t)
	allowedCallerPrefix := filepath.Join(clientsGoRoot, "cmd", "gen-conformance-fixtures") + string(os.PathSeparator)
	declarationFile := filepath.Join(clientsGoRoot, "consensus", "openssl_signer_conformance_fixture.go")
	guardTestFile := filepath.Join(clientsGoRoot, "consensus", "openssl_signer_conformance_fixture_test.go")

	const symbol = "SignDigest32ForConformanceFixture"
	var violations []string

	walkErr := filepath.Walk(clientsGoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Allowlist: declaration owns the symbol; this test owns
		// the caller-guard logic and exercises the helper; the
		// gen-conformance-fixtures cmd is the documented consumer.
		// Every other clients/go file (production AND test) is
		// scanned.
		if path == declarationFile || path == guardTestFile {
			return nil
		}
		if strings.HasPrefix(path, allowedCallerPrefix) {
			return nil
		}
		// #nosec G304 -- path comes from filepath.Walk under repo-rooted clients/go tree.
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		found, parseErr := astContainsIdent(path, raw, symbol)
		if parseErr != nil {
			// Surface parse errors loudly: every clients/go .go
			// file is expected to parse. A degenerate file would
			// silently bypass the guard if we swallowed parseErr.
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}
		if found {
			rel, _ := filepath.Rel(clientsGoRoot, path)
			violations = append(violations, rel)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk clients/go: %v", walkErr)
	}
	if len(violations) > 0 {
		t.Fatalf(
			"%s referenced outside the conformance-only allowlist (declaration file, this test file, cmd/gen-conformance-fixtures tree); violators: %v\n"+
				"This API is conformance-only; production / node / wallet / consensus paths must use SignDigest32 (hedged).",
			symbol, violations,
		)
	}
}

// TestASTContainsIdent_RealReferencesOnly pins the matcher contract
// for astContainsIdent. The AST-based implementation must:
//   - match exact identifier references (bare and selector-qualified),
//   - reject substring matches (Symbol does NOT contain Sym),
//   - reject identifiers that appear only inside comments or string
//     literals,
//   - parse modern Go grammar (selectors, function bodies, var decls)
//     without raising false positives or false negatives.
//
// Each row exercises one shape that the prior byte-level mini-scanner
// got wrong or only handled via brittle workarounds.
func TestASTContainsIdent_RealReferencesOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		src    string
		symbol string
		want   bool
	}{
		{"bare call", "package x\nfunc f() { Sym() }", "Sym", true},
		{"selector Sel matches", "package x\nfunc f(c X) { c.Sym() }\ntype X struct{}\nfunc (X) Sym() {}", "Sym", true},
		{"selector X matches", "package x\nvar y = Sym.Other\nvar Sym struct{ Other int }", "Sym", true},
		{"substring does NOT match", "package x\nvar Symbol int", "Sym", false},
		{"line comment hides match", "package x\n// Sym in line comment\nvar y int", "Sym", false},
		{"block comment hides match", "package x\n/* Sym in block comment */\nvar y int", "Sym", false},
		{"string hides match", "package x\nvar s = \"Sym in string\"\n", "Sym", false},
		{"raw string hides match", "package x\nvar s = `Sym in raw`\n", "Sym", false},
		{"declaration matches", "package x\nfunc Sym() {}", "Sym", true},
		{"unrelated identifier", "package x\nfunc Other() {}", "Sym", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := astContainsIdent("synthetic.go", []byte(tc.src), tc.symbol)
			if err != nil {
				t.Fatalf("astContainsIdent parse error on %q: %v", tc.src, err)
			}
			if got != tc.want {
				t.Fatalf("astContainsIdent(symbol=%q, src=%q)=%v, want %v", tc.symbol, tc.src, got, tc.want)
			}
		})
	}
}

// findClientsGoRoot walks up from the test's working directory looking
// for go.mod marking clients/go. Used by the caller-grep guard so it
// works whether `go test` is invoked from clients/go, the repo root,
// or the consensus package directly.
func findClientsGoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if filepath.Base(dir) == "go" && filepath.Base(filepath.Dir(dir)) == "clients" {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate clients/go module root from wd=%s", wd)
	return ""
}

// astContainsIdent reports whether `src` (Go source for `path`)
// contains an *ast.Ident with the exact name `symbol`. The match
// is performed against the parsed AST, so:
//   - identifiers inside line comments, block comments, double-quoted
//     string literals, and back-quoted raw string literals are NOT
//     visited (the parser drops comments and stores literals as
//     *ast.BasicLit, not *ast.Ident);
//   - matching is by exact name equality, so substrings like
//     "Symbol" do NOT match the symbol "Sym" (rejecting substring
//     false positives the prior byte-level scanner could not avoid);
//   - both bare references (Sym(), &Sym, var Sym int, func Sym()) and
//     selector forms (c.Sym(), Sym.Other) match because ast.Inspect
//     visits *ast.Ident under both *ast.SelectorExpr.X and .Sel.
//
// Returns the parser error if the file fails to parse. Callers
// should surface the error rather than silently treating it as
// "no match"; a degenerate file would otherwise bypass the guard.
func astContainsIdent(path string, src []byte, symbol string) (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		if ident, ok := n.(*ast.Ident); ok && ident.Name == symbol {
			found = true
			return false
		}
		return true
	})
	return found, nil
}
