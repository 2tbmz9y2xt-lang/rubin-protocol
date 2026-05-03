package main

import (
	"bytes"
	"crypto/sha3"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// embeddedTestKeysFS holds deterministic ML-DSA-87 private keys in DER
// form, one per label used by the conformance fixture generator. The
// keys were generated once offline (via consensus.NewMLDSA87Keypair() +
// PrivateKeyDER()) and committed under testdata/keys/. Loading from
// embed.FS instead of calling NewMLDSA87Keypair() at runtime makes the
// (label -> keypair) mapping byte-stable across runs and across CI cwd
// contexts; together with deterministic signing via
// (*consensus.MLDSA87Keypair).SignDigest32ForConformanceFixture
// (reached in this generator through the conformanceFixtureKeypair.SignDigest32
// override), it makes generator output byte-reproducible from the same
// origin/main input.
//
// These DER blobs are conformance-only test material. They are NOT
// production keys, NOT used by the node, wallet, or any signing-rpc
// path. The selection mapping (label -> committed DER) is the
// documented determinism interface for #1366; it is not a runtime
// label->seed->keypair derivation API.
//
//go:embed testdata/keys/*.der
var embeddedTestKeysFS embed.FS

// This generator updates a small set of conformance fixtures to use *real* ML-DSA
// witness signatures (OpenSSL backend) so that spend-path crypto verification is
// exercised end-to-end.
//
// It intentionally mutates only the vectors that previously used a dummy suite_id=0
// witness item and now fail with TX_ERR_SIG_ALG_INVALID after Q-R006.

// runGeneratorCLI parses CLI flags and runs the conformance fixture
// generator. The --output-dir flag selects between two write surfaces:
//
//   - Default (no --output-dir): writes to repoRoot/conformance/fixtures/**
//     (the legacy manual-update flow). Existing committed paths.
//   - --output-dir=/abs/path: writes ONLY under /abs/path, never under
//     conformance/fixtures/**. Used by the conformance fixture drift
//     check (Q-CONF-FIXTURE-DRIFT-CHECK-01 / #1358) to compare candidate
//     bytes against committed bytes without mutating the repo.
//
// --output-dir must be absolute. A relative value would be implicitly
// resolved against the process cwd, which contradicts the cwd
// independence contract proven by TestGenerator_CwdIndependence.
func runGeneratorCLI() {
	runGeneratorCLIWithArgs(stripGoTestFlags(os.Args[1:]))
}

// stripGoTestFlags removes -test.* arguments inserted by the Go test
// harness so a `go test` invocation that calls main() (e.g. for
// coverage) does not feed them into the generator's FlagSet. Real
// command-line invocations never carry -test.* arguments, so this
// stripping is a no-op for production usage.
func stripGoTestFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "-test.") || strings.HasPrefix(a, "--test.") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// runGeneratorCLIWithArgs runs the generator with an explicit args
// slice. The exported runGeneratorCLI wrapper reads os.Args[1:]; tests
// pass an explicit slice (typically empty for default mutating mode or
// {"-output-dir", absPath} for check-only mode) so the generator's
// FlagSet does not inherit `go test` flags such as -test.paniconexit0.
func runGeneratorCLIWithArgs(args []string) {
	fs := flag.NewFlagSet("gen-conformance-fixtures", flag.ContinueOnError)
	outputDir := fs.String("output-dir", "", "absolute path to write candidate fixtures into; if set, conformance/fixtures/** is NOT mutated")
	if err := fs.Parse(args); err != nil {
		fatalf("flag parse: %v", err)
	}

	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		fatalf("repo root: %v", err)
	}

	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	writeRoot := mustResolveWriteRoot(*outputDir, committedFixturesRoot)

	// remapWritePath maps a committed-tree fixture path to the active
	// write root. In default (mutating) mode writeRoot == committedFixturesRoot
	// and remapWritePath is identity. In --output-dir mode it relocates
	// writes under the user-supplied absolute path while LOAD paths
	// continue to read from the committed tree.
	remapWritePath := func(committedPath string) string {
		rel, relErr := filepath.Rel(committedFixturesRoot, committedPath)
		if relErr != nil {
			fatalf("internal: filepath.Rel(%q, %q): %v", committedFixturesRoot, committedPath, relErr)
		}
		if rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
			fatalf("internal: write path %q escapes committed fixtures root %q", committedPath, committedFixturesRoot)
		}
		return filepath.Join(writeRoot, rel)
	}

	// Key material (loaded from embedded testdata; deterministic per label).
	ownerKP := mustKeypair("owner")
	defer ownerKP.Close()
	vaultKP := mustKeypair("vault")
	defer vaultKP.Close()
	sponsorKP := mustKeypair("sponsor")
	defer sponsorKP.Close()
	destKP := mustKeypair("dest")
	defer destKP.Close()
	dest2KP := mustKeypair("dest2")
	defer dest2KP.Close()
	multisigKP := mustKeypair("multisig")
	defer multisigKP.Close()
	htlcClaimKP := mustKeypair("htlc-claim")
	defer htlcClaimKP.Close()
	htlcRefundKP := mustKeypair("htlc-refund")
	defer htlcRefundKP.Close()

	zeroChainID := [32]byte{}

	// CV-UTXO-BASIC updates.
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-UTXO-BASIC.json")
		f := mustLoadFixture(path)

		updateP2PKVector(f, "CV-U-05", zeroChainID, ownerKP, 100, 101) // sum_out > sum_in
		updateP2PKVector(f, "CV-U-06", zeroChainID, ownerKP, 100, 90)  // fee=10

		updateMultisigVector1of1(f, "CV-U-09", zeroChainID, multisigKP, 100, 90) // fee=10

		{
			path := filepath.Join(repoRoot, "conformance/fixtures/CV-MULTISIG.json")
			fm := mustLoadFixture(path)
			updateMultisigVector1of1(fm, "CV-M-01", zeroChainID, multisigKP, 100, 90)
			mustWriteFixture(remapWritePath(path), fm)
		}

		updateVaultSpendVectorsUTXO(
			f,
			zeroChainID,
			ownerKP,
			vaultKP,
			destKP,
			dest2KP,
			100, // vault_value
			10,  // owner_fee_input_value
		)

		updateP2PKBurnToFeeVector(f, "CV-U-19", zeroChainID, ownerKP, 100) // burn-to-fee, output_count=0
		updateCoreExtRealBindingVector(f, "CV-U-EXT-05", zeroChainID, ownerKP, 100, 90)

		mustWriteFixture(remapWritePath(path), f)
	}

	// CV-EXT metadata update for strict real binding ingestion.
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-EXT.json")
		f := mustLoadFixture(path)
		updateCoreExtEnforcementVector(f, "CV-EXT-ENF-04")
		mustWriteFixture(remapWritePath(path), f)
	}

	// CV-VAULT updates.
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-VAULT.json")
		f := mustLoadFixture(path)

		updateVaultCreateVectors(
			f,
			zeroChainID,
			ownerKP,
			sponsorKP, // used as "non-owner" for negative case
			vaultKP,
			destKP,
			100, // input_value
			90,  // vault_output_value (fee=10)
		)

		updateVaultSpendVectorsVaultFixture(
			f,
			zeroChainID,
			ownerKP,
			sponsorKP,
			vaultKP,
			destKP,
			dest2KP,
			100, // vault_value
			10,  // owner_fee_input_value
			10,  // sponsor_input_value
		)

		mustWriteFixture(remapWritePath(path), f)
	}

	// CV-HTLC updates (single vector that needs real signature witness).
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-HTLC.json")
		f := mustLoadFixture(path)
		updateHTLCVector(f, "CV-HTLC-13", zeroChainID, htlcClaimKP, htlcRefundKP, destKP)
		mustWriteFixture(remapWritePath(path), f)
	}

	// Devnet-signed CORE_VAULT operator-evidence artifact for live
	// rubin-node consumption. Lives under conformance/fixtures/devnet/
	// — INTENTIONALLY OUT of the auto-discovered CV-*.json conformance
	// namespace (top-level glob in conformance/runner/run_cv_bundle.py,
	// tools/gen_conformance_matrix.py, tools/check_formal_coverage.py)
	// because the artifact is signed under the canonical devnet
	// chain_id and would not pass the zero-chain-domain conformance
	// replay contract those tools enforce. Distinct from CV-VAULT.json
	// which stays signed under zeroChainID for cross-client conformance
	// replay; this artifact is the canonical input for #1240 live
	// devnet operator evidence (issue #1312).
	{
		path := filepath.Join(repoRoot, "conformance", "fixtures", "devnet", "devnet-vault-create-01.json")
		f := mustLoadFixture(path)
		updateDevnetVaultCreateVector(
			f,
			node.DevnetGenesisChainID(),
			ownerKP,
			vaultKP,
			destKP,
			100, // input_value
			90,  // vault_output_value (fee=10)
		)
		mustWriteFixture(remapWritePath(path), f)
	}

	// Devnet-signed CORE_HTLC claim operator-evidence artifact for live
	// rubin-node consumption. Same non-conformance-namespace rationale
	// as the CORE_VAULT artifact above (lives under
	// conformance/fixtures/devnet/, escapes the top-level CV-*.json
	// auto-discovery glob in conformance/runner/run_cv_bundle.py /
	// tools/gen_conformance_matrix.py / tools/check_formal_coverage.py).
	// Reuses the existing updateHTLCVector helper as-is — it is already
	// parameterised on (id, chainID), so signing under the canonical
	// devnet chain_id is a single arg swap; chain_id_hex is pinned on
	// the vector immediately after the helper returns so the artifact
	// metadata matches what was actually signed. Prerequisite for
	// #1241 live operator evidence.
	{
		path := filepath.Join(repoRoot, "conformance", "fixtures", "devnet", "devnet-htlc-claim-01.json")
		f := mustLoadFixture(path)
		devnetChainID := node.DevnetGenesisChainID()
		updateHTLCVector(f, "DEVNET-HTLC-CLAIM-01", devnetChainID, htlcClaimKP, htlcRefundKP, destKP)
		// Pin chain_id_hex on the vector so the artifact carries
		// explicit metadata matching the chainID just used to sign.
		findVector(f, "DEVNET-HTLC-CLAIM-01")["chain_id_hex"] = hex.EncodeToString(devnetChainID[:])
		mustWriteFixture(remapWritePath(path), f)
	}

	// Devnet-signed CORE_MULTISIG 1-of-1 spend operator-evidence
	// artifact for live rubin-node consumption. Same non-conformance-
	// namespace rationale as the CORE_VAULT and CORE_HTLC artifacts
	// above (lives under conformance/fixtures/devnet/, escapes the
	// top-level CV-*.json auto-discovery glob in
	// conformance/runner/run_cv_bundle.py /
	// tools/gen_conformance_matrix.py /
	// tools/check_formal_coverage.py). Reuses the existing
	// updateMultisigVector1of1 helper as-is — it is already
	// parameterised on (id, chainID, signer, inValue, outValue), so
	// signing under the canonical devnet chain_id is a single arg
	// swap; chain_id_hex is pinned on the vector after the helper
	// returns. Prerequisite for #1242 live operator evidence.
	{
		path := filepath.Join(repoRoot, "conformance", "fixtures", "devnet", "devnet-multisig-spend-01.json")
		f := mustLoadFixture(path)
		devnetChainID := node.DevnetGenesisChainID()
		updateMultisigVector1of1(f, "DEVNET-MULTISIG-SPEND-01", devnetChainID, multisigKP, 100, 90)
		// Pin chain_id_hex on the vector so the artifact carries
		// explicit metadata matching the chainID just used to sign.
		findVector(f, "DEVNET-MULTISIG-SPEND-01")["chain_id_hex"] = hex.EncodeToString(devnetChainID[:])
		mustWriteFixture(remapWritePath(path), f)
	}

	// CV-SUBSIDY updates (block-level coinbase bound; requires valid non-coinbase sig).
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-SUBSIDY.json")
		f := mustLoadFixture(path)
		updateSubsidyBlocks(f, zeroChainID, ownerKP, destKP)
		mustWriteFixture(remapWritePath(path), f)
	}

	fmt.Println("ok: updated fixtures with real ML-DSA signatures")
}

type fixtureFile struct {
	Gate    string           `json:"gate"`
	Vectors []map[string]any `json:"vectors"`
}

type digestSigner interface {
	PubkeyBytes() []byte
	SignDigest32([32]byte) ([]byte, error)
}

func mustSignInputDigest(id string, label string, signer digestSigner, tx *consensus.Tx, inputIndex uint32, inputValue uint64, chainID [32]byte) []byte {
	digest, err := consensus.SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, consensus.SIGHASH_ALL)
	if err != nil {
		fatalf("%s: sighash %s: %v", id, label, err)
	}
	signature, err := signer.SignDigest32(digest)
	if err != nil {
		fatalf("%s: sign %s: %v", id, label, err)
	}
	return append(signature, consensus.SIGHASH_ALL)
}

func mustLoadFixture(path string) *fixtureFile {
	path = mustCanonicalFixturePath(path)
	// #nosec G304 -- path is validated to a repo-local JSON fixture under conformance/fixtures.
	b, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		fatalf("parse %s: %v", path, err)
	}
	return &f
}

func mustCanonicalFixturePath(path string) string {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		fatalf("repo root: %v", err)
	}
	clean := filepath.Clean(path)
	fixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	rel, err := filepath.Rel(fixturesRoot, clean)
	if err != nil {
		fatalf("fixture path %s: %v", path, err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		fatalf("fixture path %s escapes %s", path, fixturesRoot)
	}
	if filepath.Ext(clean) != ".json" {
		fatalf("fixture path %s must be a .json file", path)
	}
	return clean
}

func mustWriteFixture(path string, f *fixtureFile) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		fatalf("marshal %s: %v", path, err)
	}
	b = append(b, '\n')
	// MkdirAll the parent so --output-dir writes can land in nested
	// targets (e.g. devnet/) without requiring the caller to pre-create
	// them. In default mutating mode the parent always already exists,
	// so MkdirAll is a no-op.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

// mustResolveWriteRoot is the CLI-boundary wrapper around
// resolveWriteRoot: it validates --output-dir via the testable
// error-returning function and converts a rejection into a fatalf so
// the generator process exits non-zero with a clear operator message.
// Tests should exercise resolveWriteRoot directly so the containment
// rules can be asserted by error string without subprocess wrapping.
func mustResolveWriteRoot(outputDir string, committedFixturesRoot string) string {
	root, err := resolveWriteRoot(outputDir, committedFixturesRoot)
	if err != nil {
		fatalf("%v", err)
	}
	return root
}

// resolveWriteRoot validates the --output-dir CLI value and returns
// the canonical write root for this generator run.
//
// Behavior:
//   - empty string (no --output-dir) returns committedFixturesRoot,
//     preserving the legacy mutating manual-update flow.
//   - non-empty string MUST be absolute (filepath.IsAbs == true) so the
//     resolved write target does not depend on the process cwd. A
//     relative value returns an error.
//   - non-empty string MUST NOT alias the committed fixtures root or
//     any path under it; allowing this would let --output-dir
//     accidentally mutate conformance/fixtures/**, defeating the
//     check-only contract for #1358. The containment check is run
//     against four (output, committed) variants — lexical-vs-lexical,
//     resolved-vs-resolved, and the two cross combinations — so a
//     symlink that points an out-of-tree path back into
//     conformance/fixtures/** is rejected regardless of which side
//     carries the symlink. EvalSymlinks errors are tolerated: an
//     absent --output-dir path falls back to its lexical clean form
//     (which is still subject to the same containment rule), and the
//     committed fixtures root always exists in the working tree.
func resolveWriteRoot(outputDir string, committedFixturesRoot string) (string, error) {
	if outputDir == "" {
		return committedFixturesRoot, nil
	}
	if !filepath.IsAbs(outputDir) {
		return "", fmt.Errorf("--output-dir must be absolute, got %q", outputDir)
	}
	cleanOutput := filepath.Clean(outputDir)
	cleanCommitted := filepath.Clean(committedFixturesRoot)
	// resolveAncestorOrSelf handles the case where --output-dir does
	// not yet exist on disk (typical for a freshly created temp
	// directory) but its parent chain may contain a symlink that
	// points back into conformance/fixtures/**. Plain
	// filepath.EvalSymlinks on the full path returns an error in
	// that case; we instead walk up to the deepest existing ancestor,
	// resolve its symlink target, and re-attach the unresolved
	// remainder so the containment check sees the real on-disk
	// target the eventual MkdirAll / WriteFile would follow.
	resolvedOutput := resolveAncestorOrSelf(cleanOutput)
	resolvedCommitted := cleanCommitted
	if r, evalErr := filepath.EvalSymlinks(cleanCommitted); evalErr == nil {
		resolvedCommitted = r
	}
	for _, pair := range [...][2]string{
		{cleanOutput, cleanCommitted},
		{resolvedOutput, resolvedCommitted},
		{resolvedOutput, cleanCommitted},
		{cleanOutput, resolvedCommitted},
	} {
		out, committed := pair[0], pair[1]
		if out == committed {
			return "", fmt.Errorf("--output-dir must not equal the committed fixtures root %q (input %q resolved to %q); this is the check-only contract for issue #1358", cleanCommitted, cleanOutput, resolvedOutput)
		}
		rel, err := filepath.Rel(committed, out)
		if err != nil {
			continue
		}
		if rel == "." || rel == "" {
			return "", fmt.Errorf("--output-dir %q (resolved %q) aliases the committed fixtures root %q", cleanOutput, resolvedOutput, cleanCommitted)
		}
		if !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
			return "", fmt.Errorf("--output-dir %q (resolved %q) is inside committed fixtures root %q (rel=%q); refusing to mutate conformance/fixtures/**", cleanOutput, resolvedOutput, cleanCommitted, rel)
		}
	}
	return cleanOutput, nil
}

// resolveAncestorOrSelf walks up the directory chain of p looking
// for the deepest existing ancestor; when found it runs
// filepath.EvalSymlinks on that ancestor and re-attaches the
// previously-unresolved remainder so the on-disk target an eventual
// MkdirAll / WriteFile would land on becomes visible to containment
// checks. If no ancestor resolves cleanly (extremely unusual on a
// running system because root always exists) the function returns p
// unchanged and the lexical containment check applies.
func resolveAncestorOrSelf(p string) string {
	cur := p
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			rel, relErr := filepath.Rel(cur, p)
			if relErr != nil || rel == "." || rel == "" {
				return resolved
			}
			return filepath.Join(resolved, rel)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		cur = parent
	}
}

func findVector(f *fixtureFile, id string) map[string]any {
	for _, v := range f.Vectors {
		if v["id"] == id {
			return v
		}
	}
	fatalf("missing vector id=%s", id)
	return nil
}

// conformanceFixtureKeypair wraps consensus.MLDSA87Keypair so the
// generator's existing digestSigner interface delegates to the
// deterministic conformance-fixture signing path. PubkeyBytes and
// Close are inherited via embedded promotion; SignDigest32 is
// overridden to call SignDigest32ForConformanceFixture so the
// generator's emitted signatures are byte-reproducible.
//
// This wrapper is the only mechanism by which the deterministic
// signing helper is reached — see TestSignDigest32ForConformanceFixture_ConformanceOnlyCallerGuard
// in clients/go/consensus for the static caller-grep enforcing this
// boundary.
type conformanceFixtureKeypair struct {
	*consensus.MLDSA87Keypair
}

func (k *conformanceFixtureKeypair) SignDigest32(digest [32]byte) ([]byte, error) {
	// Promoted method from the embedded *consensus.MLDSA87Keypair;
	// the wrapper's own SignDigest32 (this method) shadows the
	// embedded promotion, so calling SignDigest32ForConformanceFixture
	// directly here goes to the deterministic helper without
	// recursing through the wrapper.
	return k.SignDigest32ForConformanceFixture(digest)
}

func mustKeypair(label string) *conformanceFixtureKeypair {
	der, err := embeddedTestKeysFS.ReadFile(filepath.ToSlash(filepath.Join("testdata", "keys", label+".der")))
	if err != nil {
		fatalf("conformance fixture key %q: embedded testdata/keys/%s.der not available: %v", label, label, err)
	}
	kp, err := consensus.NewMLDSA87KeypairFromDER(der)
	if err != nil {
		// "DECODER routines::unsupported" / "unsupported" surfaces
		// when the runtime OpenSSL build does not expose an ML-DSA
		// DER decoder (e.g. OpenSSL 3.0.x without the ML-DSA
		// provider OIDs registered for d2i_AutoPrivateKey). The
		// generator's byte-reproducibility contract requires the
		// committed DER blobs to round-trip identically, so falling
		// back to runtime keygen is not a valid option. Surface a
		// clear operator message instead so the toolchain
		// requirement is visible at the failure site.
		msg := err.Error()
		if strings.Contains(msg, "unsupported") || strings.Contains(msg, "DECODER") {
			fatalf("conformance fixture key %q: NewMLDSA87KeypairFromDER reports the runtime OpenSSL build cannot decode ML-DSA-87 PKCS#8 DER (OpenSSL ≥3.5 with ML-DSA provider required). Original error: %v", label, err)
		}
		fatalf("conformance fixture key %q: NewMLDSA87KeypairFromDER: %v", label, err)
	}
	return &conformanceFixtureKeypair{MLDSA87Keypair: kp}
}

func sha3_256(b []byte) [32]byte { return sha3.Sum256(b) }

func keyIDForPub(pub []byte) [32]byte { return sha3_256(pub) }

func p2pkCovenantDataWithSuite(suiteID byte, pub []byte) []byte {
	kid := keyIDForPub(pub)
	out := make([]byte, 0, consensus.MAX_P2PK_COVENANT_DATA)
	out = append(out, suiteID)
	out = append(out, kid[:]...)
	return out
}

func p2pkCovenantData(pub []byte) []byte {
	return p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)
}

func mustCoreExtOpenSSLDigest32BindingDescriptorHex() string {
	raw, err := consensus.CoreExtOpenSSLDigest32BindingDescriptorBytes(
		"ML-DSA-87",
		consensus.ML_DSA_87_PUBKEY_BYTES,
		consensus.ML_DSA_87_SIG_BYTES,
	)
	if err != nil {
		fatalf("core_ext binding descriptor: %v", err)
	}
	return hex.EncodeToString(raw)
}

func setCoreExtOpenSSLDigest32Binding(v map[string]any) {
	profiles := anyToSliceMap(v["core_ext_profiles"])
	if len(profiles) != 1 {
		fatalf("%s: want 1 core_ext profile", v["id"])
	}
	profiles[0]["binding"] = consensus.CoreExtBindingNameVerifySigExtOpenSSLDigest32V1
	profiles[0]["binding_descriptor_hex"] = mustCoreExtOpenSSLDigest32BindingDescriptorHex()
	profiles[0]["ext_payload_schema_hex"] = "b2"
	v["core_ext_profiles"] = profiles
}

func parseJSONUint32(name string, value any) (uint32, error) {
	n, ok := value.(float64)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > math.MaxUint32 || math.Trunc(n) != n {
		return 0, fmt.Errorf("%s: want uint32-compatible JSON number", name)
	}
	return uint32(n), nil
}

func mustJSONUint32(name string, value any) uint32 {
	out, err := parseJSONUint32(name, value)
	if err != nil {
		fatalf("%v", err)
	}
	return out
}

func multisigCovenantData1of1(pub []byte) []byte {
	kid := keyIDForPub(pub)
	out := make([]byte, 0, 34)
	out = append(out, 0x01) // threshold
	out = append(out, 0x01) // key_count
	out = append(out, kid[:]...)
	return out
}

func vaultCovenantData(ownerLockID [32]byte, vaultKeyID [32]byte, whitelist [32]byte) []byte {
	out := make([]byte, 0, 32+1+1+32+2+32)
	out = append(out, ownerLockID[:]...)
	out = append(out, 0x01) // threshold
	out = append(out, 0x01) // key_count
	out = append(out, vaultKeyID[:]...)
	var wc [2]byte
	binary.LittleEndian.PutUint16(wc[:], 1)
	out = append(out, wc[:]...)
	out = append(out, whitelist[:]...)
	return out
}

func updateSingleInputSignedVector(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	suiteID byte,
	inCov []byte,
	outCov []byte,
	inValue uint64,
	outValue uint64,
	signer digestSigner,
) {
	v := findVector(f, id)
	pub := signer.PubkeyBytes()

	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo, got %d", id, len(utxos))
	}
	utxos[0]["covenant_data"] = hex.EncodeToString(inCov)

	prevTxid := mustHex32(utxos[0]["txid"].(string))
	prevVout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevTxid, PrevVout: prevVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		Locktime: 0,
	}

	sig := mustSignInputDigest(id, "input0", signer, tx, 0, inValue, chainID)
	tx.Witness = []consensus.WitnessItem{{SuiteID: suiteID, Pubkey: pub, Signature: sig}}

	b := mustTxBytes(tx)
	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
}

func updateP2PKVector(f *fixtureFile, id string, chainID [32]byte, signer digestSigner, inValue uint64, outValue uint64) {
	pub := signer.PubkeyBytes()
	cov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)
	updateSingleInputSignedVector(
		f,
		id,
		chainID,
		consensus.SUITE_ID_ML_DSA_87,
		cov,
		cov,
		inValue,
		outValue,
		signer,
	)
}

func updateMultisigVector1of1(f *fixtureFile, id string, chainID [32]byte, signer digestSigner, inValue uint64, outValue uint64) {
	pub := signer.PubkeyBytes()
	inCov := multisigCovenantData1of1(pub)
	outCov := p2pkCovenantData(pub) // any valid output
	updateSingleInputSignedVector(
		f,
		id,
		chainID,
		consensus.SUITE_ID_ML_DSA_87,
		inCov,
		outCov,
		inValue,
		outValue,
		signer,
	)
}

func updateP2PKBurnToFeeVector(f *fixtureFile, id string, chainID [32]byte, signer digestSigner, inValue uint64) {
	v := findVector(f, id)
	pub := signer.PubkeyBytes()
	cov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)

	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo, got %d", id, len(utxos))
	}
	utxos[0]["covenant_data"] = hex.EncodeToString(cov)

	prevTxid := mustHex32(utxos[0]["txid"].(string))
	prevVout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevTxid, PrevVout: prevVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  nil, // zero outputs: burn-to-fee
		Locktime: 0,
	}

	sig := mustSignInputDigest(id, "input0", signer, tx, 0, inValue, chainID)
	tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: pub, Signature: sig}}

	b := mustTxBytes(tx)
	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
}

func updateCoreExtRealBindingVector(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	signer digestSigner,
	inValue uint64,
	outValue uint64,
) {
	v := findVector(f, id)
	setCoreExtOpenSSLDigest32Binding(v)

	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo, got %d", id, len(utxos))
	}

	prevTxid := mustHex32(utxos[0]["txid"].(string))
	prevVout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
	pub := signer.PubkeyBytes()
	outCov := p2pkCovenantData(pub)

	// CORE_EXT real-binding witnesses must carry the suite_id that
	// the vector's core_ext_profiles binding actually allows, NOT a
	// generic ML-DSA default. The vector pins exactly one allowed
	// suite for the bound profile (see CV-U-EXT-05.allowed_suite_ids
	// = [3]); emitting consensus.SUITE_ID_ML_DSA_87 (= 0x01) silently
	// produced a witness that fails replay with TX_ERR_SIG_ALG_INVALID
	// once deterministic regen brought the bytes back to current
	// generator output. Read the suite from the vector contract
	// directly and assert it is the single allowed suite.
	witnessSuiteID := mustCoreExtAllowedSuiteID(id, v)

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevTxid, PrevVout: prevVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		Locktime: 0,
	}

	sig := mustSignInputDigest(id, "input0", signer, tx, 0, inValue, chainID)
	tx.Witness = []consensus.WitnessItem{{
		SuiteID:   witnessSuiteID,
		Pubkey:    pub,
		Signature: sig,
	}}

	v["tx_hex"] = hex.EncodeToString(mustTxBytes(tx))
	v["utxos"] = utxos
}

// coreExtAllowedSuiteID is the error-returning core of the witness
// suite-id derivation: given a CORE_EXT real-binding vector, extract
// the single allowed suite from `core_ext_profiles[0].allowed_suite_ids`
// after asserting the contract shape (one bound profile, one allowed
// suite, fits in a byte, not SENTINEL). Splitting the error path off
// from the fatalf wrapper mirrors the existing parseJSONUint32 vs
// mustJSONUint32 pattern and lets unit tests exercise every guard
// branch without subprocess-wrapping a CLI fatalf.
func coreExtAllowedSuiteID(id string, v map[string]any) (byte, error) {
	rawProfiles, hasProfiles := v["core_ext_profiles"]
	if !hasProfiles || rawProfiles == nil {
		return 0, fmt.Errorf("%s: core_ext_profiles is missing or null; expected a JSON array with exactly one bound profile", id)
	}
	// Accept both shapes the generator produces in-process:
	//   - []any (json.Unmarshal default for generic JSON arrays — what the
	//     test reads back from disk after mustWriteFixture round-trips
	//     the vector through encoding/json), and
	//   - []map[string]any (what setCoreExtOpenSSLDigest32Binding writes
	//     back via anyToSliceMap before the marshal step).
	// Anything else is a contract violation and surfaces a typed error.
	var profile map[string]any
	switch profiles := rawProfiles.(type) {
	case []any:
		if len(profiles) != 1 {
			return 0, fmt.Errorf("%s: core_ext_profiles must have exactly one bound profile, got %d", id, len(profiles))
		}
		got, ok := profiles[0].(map[string]any)
		if !ok {
			return 0, fmt.Errorf("%s: core_ext_profiles[0] must be a JSON object, got %T", id, profiles[0])
		}
		profile = got
	case []map[string]any:
		if len(profiles) != 1 {
			return 0, fmt.Errorf("%s: core_ext_profiles must have exactly one bound profile, got %d", id, len(profiles))
		}
		profile = profiles[0]
	default:
		return 0, fmt.Errorf("%s: core_ext_profiles must be a JSON array, got %T", id, rawProfiles)
	}
	allowedAny, ok := profile["allowed_suite_ids"].([]any)
	if !ok || len(allowedAny) == 0 {
		return 0, fmt.Errorf("%s: core_ext_profiles[0].allowed_suite_ids must be a non-empty JSON array", id)
	}
	if len(allowedAny) != 1 {
		return 0, fmt.Errorf("%s: core_ext_profiles[0].allowed_suite_ids must pin exactly one suite for the real-binding witness, got %d entries", id, len(allowedAny))
	}
	suite32, err := parseJSONUint32(id+".core_ext_profiles[0].allowed_suite_ids[0]", allowedAny[0])
	if err != nil {
		return 0, err
	}
	if suite32 > 0xff {
		return 0, fmt.Errorf("%s: core_ext_profiles[0].allowed_suite_ids[0]=%d does not fit in a single suite_id byte", id, suite32)
	}
	if suite32 == uint32(consensus.SUITE_ID_SENTINEL) {
		return 0, fmt.Errorf("%s: core_ext_profiles[0].allowed_suite_ids[0]=0x00 (SENTINEL) is not a valid witness suite", id)
	}
	return byte(suite32), nil
}

// mustCoreExtAllowedSuiteID is the CLI-boundary fatalf wrapper around
// coreExtAllowedSuiteID. The contract for the vectors this helper
// supports is exactly one bound profile with exactly one allowed
// suite — that suite is what the witness must carry, otherwise the
// runtime verifier rejects with TX_ERR_SIG_ALG_INVALID before any
// signature work happens. This stays purely vector-driven; no new
// magic constant lives in the generator.
func mustCoreExtAllowedSuiteID(id string, v map[string]any) byte {
	suite, err := coreExtAllowedSuiteID(id, v)
	if err != nil {
		fatalf("%v", err)
	}
	return suite
}

func updateCoreExtEnforcementVector(f *fixtureFile, id string) {
	v := findVector(f, id)
	v["description"] = "verify_sig_ext_openssl_digest32_v1 binding: allowed suite, real ML-DSA-87 verifier"
	setCoreExtOpenSSLDigest32Binding(v)
}

func updateVaultSpendVectorsUTXO(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP digestSigner,
	vaultKP digestSigner,
	destKP digestSigner,
	dest2KP digestSigner,
	vaultValue uint64,
	ownerFeeInValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultPub := vaultKP.PubkeyBytes()
	vaultKeyID := keyIDForPub(vaultPub)

	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// Helper to build/patch one vector with (outValue, destCovData).
	build := func(id string, outValue uint64, outCov []byte) {
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 2 {
			fatalf("%s: want 2 utxos", id)
		}
		// vault input first
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[0]["covenant_type"] = float64(consensus.COV_TYPE_VAULT)
		// owner fee input second
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)
		utxos[1]["covenant_type"] = float64(consensus.COV_TYPE_P2PK)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		vout0 := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
		vout1 := mustJSONUint32(id+".utxos[1].vout", utxos[1]["vout"])

		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
			Locktime: 0,
		}

		vaultSig := mustSignInputDigest(id, "vault_input", vaultKP, tx, 0, vaultValue, chainID)
		ownerSig := mustSignInputDigest(id, "owner_input", ownerKP, tx, 1, ownerFeeInValue, chainID)
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: vaultPub, Signature: vaultSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
		}

		b := mustTxBytes(tx)

		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// CV-U-10: vault funds fee -> reject value conservation.
	build("CV-U-10", 95, destCov)
	// CV-U-11: vault preserved exactly; owner funds fee.
	build("CV-U-11", vaultValue, destCov)
	// CV-U-12: output not whitelisted.
	build("CV-U-12", vaultValue, p2pkCovenantData(dest2KP.PubkeyBytes()))
	// CV-U-13: owner top-up; sum_out > sum_in_vault.
	build("CV-U-13", 105, destCov)
}

func updateVaultCreateVectors(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP digestSigner,
	nonOwnerKP digestSigner,
	vaultKP digestSigner,
	destKP digestSigner,
	inValue uint64,
	vaultOutValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultKeyID := keyIDForPub(vaultKP.PubkeyBytes())
	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// Negative: input is non-owner; creates vault output with ownerLockID -> missing owner auth.
	{
		id := "VAULT-CREATE-01"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 1 {
			fatalf("%s: want 1 utxo", id)
		}
		nonOwnerPub := nonOwnerKP.PubkeyBytes()
		nonOwnerCov := p2pkCovenantData(nonOwnerPub)
		utxos[0]["covenant_data"] = hex.EncodeToString(nonOwnerCov)
		utxos[0]["value"] = float64(inValue)

		prev := mustHex32(utxos[0]["txid"].(string))
		vout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
		tx := &consensus.Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  1,
			Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
			Outputs:  []consensus.TxOutput{{Value: vaultOutValue, CovenantType: consensus.COV_TYPE_VAULT, CovenantData: vaultCov}},
			Locktime: 0,
		}
		sig := mustSignInputDigest(id, "input0_non_owner", nonOwnerKP, tx, 0, inValue, chainID)
		tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: nonOwnerPub, Signature: sig}}
		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// Positive: input is owner-authorized; creates vault output.
	{
		id := "VAULT-CREATE-02"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 1 {
			fatalf("%s: want 1 utxo", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[0]["value"] = float64(inValue)

		prev := mustHex32(utxos[0]["txid"].(string))
		vout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
		tx := &consensus.Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  1,
			Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
			Outputs:  []consensus.TxOutput{{Value: vaultOutValue, CovenantType: consensus.COV_TYPE_VAULT, CovenantData: vaultCov}},
			Locktime: 0,
		}
		sig := mustSignInputDigest(id, "input0_owner", ownerKP, tx, 0, inValue, chainID)
		tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: sig}}
		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}
}

// updateDevnetVaultCreateVector populates the positive owner-authorized
// CORE_VAULT create transaction in
// conformance/fixtures/devnet/devnet-vault-create-01.json, signed under
// the canonical devnet chain_id (see node.DevnetGenesisChainID). The
// resulting tx is the canonical input artifact for #1240 live
// devnet-mode operator evidence; submitting it through
// `rubin-node --network devnet /submit_tx` accepts it because its
// signature domain matches the live node's chain_id, unlike the
// zero-chain VAULT-CREATE-02 vector in CV-VAULT.json which targets
// cross-client conformance replay only. The artifact intentionally
// lives outside the top-level CV-*.json conformance namespace so the
// existing conformance runner/matrix/formal glob does not auto-discover
// it (devnet-domain signatures would fail the zero-chain replay those
// tools enforce). The vector pins the signing chain_id explicitly via
// the chain_id_hex field so an operator/orchestrator can verify the
// artifact metadata without re-deriving it from tx_hex.
func updateDevnetVaultCreateVector(
	f *fixtureFile,
	devnetChainID [32]byte,
	ownerKP digestSigner,
	vaultKP digestSigner,
	destKP digestSigner,
	inValue uint64,
	vaultOutValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultKeyID := keyIDForPub(vaultKP.PubkeyBytes())
	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	id := "DEVNET-VAULT-CREATE-01"
	v := findVector(f, id)
	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo", id)
	}
	utxos[0]["covenant_data"] = hex.EncodeToString(ownerInCov)
	utxos[0]["value"] = float64(inValue)

	prevTxidStr, ok := utxos[0]["txid"].(string)
	if !ok {
		fatalf("%s: utxos[0].txid is not a string", id)
	}
	prev := mustHex32(prevTxidStr)
	vout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: vaultOutValue, CovenantType: consensus.COV_TYPE_VAULT, CovenantData: vaultCov}},
		Locktime: 0,
	}
	sig := mustSignInputDigest(id, "input0_owner_devnet", ownerKP, tx, 0, inValue, devnetChainID)
	tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: sig}}
	b := mustTxBytes(tx)
	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
	// Pin the signing chain_id on the vector so the artifact carries
	// explicit metadata for live-evidence consumers; the regenerator
	// always writes the canonical devnet chain_id here, matching the
	// chainID parameter used to sign.
	v["chain_id_hex"] = hex.EncodeToString(devnetChainID[:])
}

func updateVaultSpendVectorsVaultFixture(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP digestSigner,
	sponsorKP digestSigner,
	vaultKP digestSigner,
	destKP digestSigner,
	dest2KP digestSigner,
	vaultValue uint64,
	ownerFeeInValue uint64,
	sponsorInValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultPub := vaultKP.PubkeyBytes()
	vaultKeyID := keyIDForPub(vaultPub)
	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// VAULT-SPEND-02: include a non-owner P2PK input (valid sig) to trigger sponsorship forbidden.
	{
		id := "VAULT-SPEND-02"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 3 {
			fatalf("%s: want 3 utxos", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)

		sponsorPub := sponsorKP.PubkeyBytes()
		sponsorCov := p2pkCovenantData(sponsorPub)
		utxos[2]["covenant_data"] = hex.EncodeToString(sponsorCov)
		utxos[2]["value"] = float64(sponsorInValue)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		prev2 := mustHex32(utxos[2]["txid"].(string))
		vout0 := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
		vout1 := mustJSONUint32(id+".utxos[1].vout", utxos[1]["vout"])
		vout2 := mustJSONUint32(id+".utxos[2].vout", utxos[2]["vout"])

		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev2, PrevVout: vout2, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: vaultValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: destCov}},
			Locktime: 0,
		}

		// Witness cursor: vault(1) + owner(1) + sponsor(1) = 3 witness items.
		// For this vector, vault threshold is checked *after* sponsorship, so we can keep the vault witness as sentinel (smaller).
		ownerSig := mustSignInputDigest(id, "owner_input", ownerKP, tx, 1, ownerFeeInValue, chainID)
		sponsorSig := mustSignInputDigest(id, "sponsor_input", sponsorKP, tx, 2, sponsorInValue, chainID)
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: sponsorPub, Signature: sponsorSig},
		}

		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// VAULT-SPEND-04: output not whitelisted (must pass vault threshold first).
	{
		id := "VAULT-SPEND-04"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 2 {
			fatalf("%s: want 2 utxos", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		vout0 := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])
		vout1 := mustJSONUint32(id+".utxos[1].vout", utxos[1]["vout"])

		nonWL := p2pkCovenantData(dest2KP.PubkeyBytes())
		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: vaultValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: nonWL}},
			Locktime: 0,
		}

		vaultSig := mustSignInputDigest(id, "vault_input", vaultKP, tx, 0, vaultValue, chainID)
		ownerSig := mustSignInputDigest(id, "owner_input", ownerKP, tx, 1, ownerFeeInValue, chainID)
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: vaultPub, Signature: vaultSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
		}

		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}
}

func updateHTLCVector(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	claimKP digestSigner,
	refundKP digestSigner,
	destKP digestSigner,
) {
	v := findVector(f, id)
	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo", id)
	}

	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := keyIDForPub(claimPub)
	refundKeyID := keyIDForPub(refundPub)

	preimage := []byte("rubin-htlc-claim-preimage")
	hash := sha3_256(preimage)

	lockMode := byte(consensus.LOCK_MODE_TIMESTAMP)
	lockValue := uint64(2500) // must be > 0, but claim path doesn't enforce it further.

	htlcCov := make([]byte, 0, consensus.MAX_HTLC_COVENANT_DATA)
	htlcCov = append(htlcCov, hash[:]...)
	htlcCov = append(htlcCov, lockMode)
	var lv [8]byte
	binary.LittleEndian.PutUint64(lv[:], lockValue)
	htlcCov = append(htlcCov, lv[:]...)
	htlcCov = append(htlcCov, claimKeyID[:]...)
	htlcCov = append(htlcCov, refundKeyID[:]...)
	if len(htlcCov) != consensus.MAX_HTLC_COVENANT_DATA {
		fatalf("%s: bad htlc cov len=%d", id, len(htlcCov))
	}

	utxos[0]["covenant_data"] = hex.EncodeToString(htlcCov)
	utxos[0]["covenant_type"] = float64(consensus.COV_TYPE_HTLC)
	utxos[0]["value"] = float64(100)

	prev := mustHex32(utxos[0]["txid"].(string))
	vout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])

	outCov := p2pkCovenantData(destKP.PubkeyBytes())
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
		Outputs: []consensus.TxOutput{{Value: 90, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		// Keep locktime=0 for non-coinbase.
		Locktime: 0,
	}

	sig := mustSignInputDigest(id, "claim_input", claimKP, tx, 0, 100, chainID)

	// Witness items for HTLC input:
	//  - path selector (sentinel): pubkey=key_id (32), signature=claim payload
	//  - crypto signature (ML-DSA): pubkey + signature
	var selSig []byte
	selSig = append(selSig, 0x00) // pathID=claim
	if len(preimage) > math.MaxUint16 {
		fatalf("%s: preimage too large", id)
	}
	var preLen [2]byte
	binary.LittleEndian.PutUint16(preLen[:], uint16(len(preimage))) // #nosec G115 -- preimage length is checked against math.MaxUint16 above.
	selSig = append(selSig, preLen[:]...)
	selSig = append(selSig, preimage...)

	tx.Witness = []consensus.WitnessItem{
		{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: claimKeyID[:], Signature: selSig},
		{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: claimPub, Signature: sig},
	}

	b := mustTxBytes(tx)

	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
}

func updateSubsidyBlocks(
	f *fixtureFile,
	chainID [32]byte,
	spendKP digestSigner,
	coinbaseDestKP digestSigner,
) {
	// Both vectors use the same header prev hash/target in the fixtures.
	sub1 := findVector(f, "CV-SUB-01")
	sub2 := findVector(f, "CV-SUB-02")

	blockHeight := uint32(1)
	alreadyGenerated := uint64(0)
	sumFees := uint64(10)
	subsidy := consensus.BlockSubsidy(uint64(blockHeight), alreadyGenerated)

	spendPub := spendKP.PubkeyBytes()
	spendInCov := p2pkCovenantData(spendPub)
	spendUTXO := anyToSliceMap(sub1["utxos"])
	if len(spendUTXO) != 1 {
		fatalf("CV-SUB-01: want 1 utxo")
	}
	spendUTXO[0]["covenant_data"] = hex.EncodeToString(spendInCov)

	prevSpend := mustHex32(spendUTXO[0]["txid"].(string))
	prevSpendVout := mustJSONUint32("CV-SUB-01.spend_utxo[0].vout", spendUTXO[0]["vout"])

	// Build the non-coinbase tx: 100 -> 90 (fee=10).
	outCov := p2pkCovenantData(coinbaseDestKP.PubkeyBytes())
	nonCoinbase := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevSpend, PrevVout: prevSpendVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 90, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		Locktime: 0,
	}
	sig := mustSignInputDigest("subsidy", "spend_input", spendKP, nonCoinbase, 0, 100, chainID)
	nonCoinbase.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: spendPub, Signature: sig}}
	nonCoinbaseBytes := mustTxBytes(nonCoinbase)

	// Coinbase destination output covenant data can be any valid P2PK (no sig required).
	cbDestCov := p2pkCovenantData(coinbaseDestKP.PubkeyBytes())

	buildBlock := func(coinbaseValue uint64) string {
		coinbase := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 0,
			Inputs: []consensus.TxInput{{
				PrevTxid:  [32]byte{},
				PrevVout:  ^uint32(0),
				ScriptSig: nil,
				Sequence:  ^uint32(0),
			}},
			Outputs: []consensus.TxOutput{
				{Value: coinbaseValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: cbDestCov},
				{Value: 0, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: bytes.Repeat([]byte{0x00}, 32)}, // placeholder
			},
			Locktime:  blockHeight,
			Witness:   nil,
			DaPayload: nil,
		}

		// Compute witness commitment from wtxids (coinbase + non-coinbase).
		coinbaseBytes := mustTxBytes(coinbase)
		_, _, cbWtxid, n, err := consensus.ParseTx(coinbaseBytes)
		if err != nil || n != len(coinbaseBytes) {
			fatalf("subsidy: parse coinbase: err=%v consumed=%d", err, n)
		}
		_, _, ncWtxid, n, err := consensus.ParseTx(nonCoinbaseBytes)
		if err != nil || n != len(nonCoinbaseBytes) {
			fatalf("subsidy: parse non-coinbase: err=%v consumed=%d", err, n)
		}
		wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{cbWtxid, ncWtxid})
		if err != nil {
			fatalf("subsidy: witness root: %v", err)
		}
		wc := consensus.WitnessCommitmentHash(wroot)
		coinbase.Outputs[1].CovenantData = wc[:]
		coinbaseBytes = mustTxBytes(coinbase)

		_, cbTxid, _, n, err := consensus.ParseTx(coinbaseBytes)
		if err != nil || n != len(coinbaseBytes) {
			fatalf("subsidy: parse coinbase(2): err=%v consumed=%d", err, n)
		}
		_, ncTxid, _, n, err := consensus.ParseTx(nonCoinbaseBytes)
		if err != nil || n != len(nonCoinbaseBytes) {
			fatalf("subsidy: parse non-coinbase(2): err=%v consumed=%d", err, n)
		}
		merkle, err := consensus.MerkleRootTxids([][32]byte{cbTxid, ncTxid})
		if err != nil {
			fatalf("subsidy: merkle root: %v", err)
		}

		prevHash := mustHex32(sub1["expected_prev_hash"].(string))
		header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
		header = consensus.AppendU32le(header, 1)
		header = append(header, prevHash[:]...)
		header = append(header, merkle[:]...)
		header = consensus.AppendU64le(header, 123) // timestamp (matches prior fixture style)
		header = append(header, bytes.Repeat([]byte{0xff}, 32)...)
		header = consensus.AppendU64le(header, 123) // nonce
		if len(header) != consensus.BLOCK_HEADER_BYTES {
			fatalf("subsidy: header len=%d", len(header))
		}

		var block []byte
		block = append(block, header...)
		block = consensus.AppendCompactSize(block, 2)
		block = append(block, coinbaseBytes...)
		block = append(block, nonCoinbaseBytes...)

		if _, err := consensus.ValidateBlockBasicWithContextAtHeight(block, nil, nil, uint64(blockHeight), nil); err != nil {
			fatalf("subsidy: generated block fails basic validation: %v", err)
		}

		return hex.EncodeToString(block)
	}

	sub1["block_hex"] = buildBlock(subsidy + sumFees)
	sub1["utxos"] = spendUTXO
	sub1["already_generated"] = float64(alreadyGenerated)

	sub2["block_hex"] = buildBlock(subsidy + sumFees + 1)
	sub2["utxos"] = spendUTXO
	sub2["already_generated"] = float64(alreadyGenerated)
}

func mustTxBytes(tx *consensus.Tx) []byte {
	b, err := consensus.MarshalTx(tx)
	if err != nil {
		fatalf("MarshalTx: %v", err)
	}
	if _, _, _, n, err := consensus.ParseTx(b); err != nil || n != len(b) {
		fatalf("MarshalTx sanity: err=%v consumed=%d len=%d", err, n, len(b))
	}
	return b
}

func anyToSliceMap(v any) []map[string]any {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		// json.Unmarshal uses []any, not []map. Handle already-converted.
		if m2, ok2 := v.([]map[string]any); ok2 {
			return m2
		}
		fatalf("unexpected list type %T", v)
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			fatalf("unexpected item type %T", item)
		}
		out = append(out, m)
	}
	return out
}

func mustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		fatalf("bad hex32: %q", s)
	}
	copy(out[:], b)
	return out
}

func repoRootFromGoModule() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// We run under clients/go; repo root is two levels up from that module root.
	// Be strict: ensure go.mod exists in cwd or parent chain.
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// module root is dir; repo root is two parents.
			return filepath.Clean(filepath.Join(dir, "../..")), nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return "", fmt.Errorf("could not locate go.mod from %s", wd)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}

// Ensure whitelist/keys ordering is canonical for any future extension.
func sortedUnique32(xs [][32]byte) [][32]byte {
	sort.Slice(xs, func(i, j int) bool {
		return bytes.Compare(xs[i][:], xs[j][:]) < 0
	})
	out := make([][32]byte, 0, len(xs))
	var last *[32]byte
	for i := range xs {
		if last != nil && *last == xs[i] {
			continue
		}
		x := xs[i]
		out = append(out, x)
		last = &x
	}
	return out
}
