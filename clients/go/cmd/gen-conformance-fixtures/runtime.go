package main

import (
	"bytes"
	"crypto/sha3"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// Devnet operator-evidence value constants.
//
// The three conformance/fixtures/devnet/* vectors are the only
// generator-owned artifacts replayed against a LIVE node: the
// scripts/devnet-core-{htlc,multisig,vault}-evidence.sh harnesses seed
// utxos[0] and submit tx_hex through the node's real /submit_tx path.
// That path enforces the mempool rolling fee floor and rejects any
// transaction whose fee is below tx_weight * DefaultMempoolMinFeeRate
// (clients/go/node/mempool.go, clients/go/node/mempool_fee_floor.go).
// An ML-DSA-87-signed single-input vector weighs ~7.7k weight units,
// so the 100/90 values these vectors inherited from the offline
// conformance vectors put their fee two orders of magnitude below the
// floor.
//
// fee = 1_000_000 - 900_000 = 100_000 clears a ~7.7k floor by >10x, so
// the artifacts absorb both re-signing weight growth and a modest
// future floor raise. That headroom is not itself enforced:
// pinDevnetEvidenceFeeMetadata re-derives the real weight from the
// emitted transaction and fails generation only once the fee drops
// below the 2x devnetEvidenceMinFeeMarginFactor bound.
//
// The zero-chain CV-*.json vectors deliberately keep their historical
// 100/90 values: they are replayed by the offline conformance harness,
// which has no mempool and no fee floor.
const (
	devnetEvidenceInputValue  = uint64(1_000_000)
	devnetEvidenceOutputValue = uint64(900_000)

	// devnetEvidenceMinFeeMarginFactor is the multiple of the live
	// admission floor a generated devnet fee must clear.
	devnetEvidenceMinFeeMarginFactor = uint64(2)
)

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

		// Shared widened-fee vector: fee = 2^64, one above the u64 domain.
		updateWideFeeVector(f, "CV-U-FEE-U128-01", zeroChainID, ownerKP)
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
		updateHTLCVector(f, "CV-HTLC-13", zeroChainID, htlcClaimKP, htlcRefundKP, destKP, 100, 90) // fee=10
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
			devnetEvidenceInputValue,
			devnetEvidenceOutputValue,
		)
		// Live-admission values: see devnetEvidenceInputValue.
		pinDevnetEvidenceFeeMetadata(f, "DEVNET-VAULT-CREATE-01", devnetEvidenceInputValue, devnetEvidenceOutputValue)
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
		// Live-admission values: see devnetEvidenceInputValue.
		updateHTLCVector(f, "DEVNET-HTLC-CLAIM-01", devnetChainID, htlcClaimKP, htlcRefundKP, destKP, devnetEvidenceInputValue, devnetEvidenceOutputValue)
		// Pin chain_id_hex on the vector so the artifact carries
		// explicit metadata matching the chainID just used to sign.
		findVector(f, "DEVNET-HTLC-CLAIM-01")["chain_id_hex"] = hex.EncodeToString(devnetChainID[:])
		pinDevnetEvidenceFeeMetadata(f, "DEVNET-HTLC-CLAIM-01", devnetEvidenceInputValue, devnetEvidenceOutputValue)
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
		// Live-admission values: see devnetEvidenceInputValue.
		updateMultisigVector1of1(f, "DEVNET-MULTISIG-SPEND-01", devnetChainID, multisigKP, devnetEvidenceInputValue, devnetEvidenceOutputValue)
		// Pin chain_id_hex on the vector so the artifact carries
		// explicit metadata matching the chainID just used to sign.
		findVector(f, "DEVNET-MULTISIG-SPEND-01")["chain_id_hex"] = hex.EncodeToString(devnetChainID[:])
		pinDevnetEvidenceFeeMetadata(f, "DEVNET-MULTISIG-SPEND-01", devnetEvidenceInputValue, devnetEvidenceOutputValue)
		mustWriteFixture(remapWritePath(path), f)
	}

	// CV-SUBSIDY updates (block-level coinbase bound; requires valid non-coinbase sig).
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-SUBSIDY.json")
		f := mustLoadFixture(path)
		updateSubsidyBlocks(f, zeroChainID, ownerKP, destKP)
		mustWriteFixture(remapWritePath(path), f)
	}

	// RUB-922 / C01 canonical publication observables corpus: authored
	// architecture authority, never measured from a node production path.
	mustWriteCanonicalPipelineCorpus(remapWritePath(filepath.Join(repoRoot, "conformance/fixtures/protocol/canonical_pipeline_v1.json")))

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
	f, err := decodeFixture(b)
	if err != nil {
		fatalf("parse %s: %v", path, err)
	}
	return f
}

// decodeFixture reads exactly one fixture document from b.
//
// UseNumber keeps every JSON integer as its exact literal instead of decoding
// it into float64. Vectors are loaded into map[string]any and written straight
// back out, so a float64 round-trip would silently corrupt any value above
// 2^53 — including the u64-max UTXO values the widened-fee vectors depend on.
//
// Decode stops at the end of the first JSON value, so a second value or
// trailing garbage would be accepted and then dropped when the file is written
// back. json.Unmarshal (the pre-UseNumber reader) rejected that; requiring
// io.EOF from a second Decode keeps the same strictness.
func decodeFixture(b []byte) (*fixtureFile, error) {
	var f fixtureFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing content after top-level JSON value")
	}
	return &f, nil
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

func parseJSONUint32(name string, value any) (uint32, error) {
	// json.Number (the UseNumber decode path) is parsed exactly; float64 is
	// still accepted for values the generator itself wrote back into a vector.
	if num, ok := value.(json.Number); ok {
		parsed, err := strconv.ParseUint(num.String(), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%s: want uint32-compatible JSON number", name)
		}
		return uint32(parsed), nil
	}
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

// wideFeeInputValue is the per-input value of the widened-fee vectors:
// 2^63, so two inputs sum to exactly 2^64 and a zero-output (burn-to-fee)
// transaction has a fee of exactly 2^64 — one above the u64 domain.
const wideFeeInputValue = uint64(1) << 63

// upsertVector installs the authoritative skeleton at the vector's existing
// slot, or appends it when the id does not exist yet.
func upsertVector(f *fixtureFile, id string, skeleton map[string]any) map[string]any {
	skeleton["id"] = id
	for i, v := range f.Vectors {
		if v["id"] == id {
			f.Vectors[i] = skeleton
			return skeleton
		}
	}
	f.Vectors = append(f.Vectors, skeleton)
	return skeleton
}

// updateWideFeeVector authors the shared >u64 fee vector: two 2^63 P2PK
// inputs and zero outputs, so the derived fee is exactly 2^64. The expected
// fee is written as a canonical decimal string because a widened monetary
// integer must not depend on interoperable JSON-number precision.
func updateWideFeeVector(f *fixtureFile, id string, chainID [32]byte, signer digestSigner) {
	pub := signer.PubkeyBytes()
	cov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)
	prevTxids := [2][32]byte{{0xe1}, {0xe2}}

	utxos := make([]map[string]any, 0, len(prevTxids))
	inputs := make([]consensus.TxInput, 0, len(prevTxids))
	for _, prev := range prevTxids {
		utxos = append(utxos, map[string]any{
			"txid":                hex.EncodeToString(prev[:]),
			"vout":                json.Number("0"),
			"value":               json.Number(strconv.FormatUint(wideFeeInputValue, 10)),
			"covenant_type":       json.Number(strconv.FormatUint(uint64(consensus.COV_TYPE_P2PK), 10)),
			"covenant_data":       hex.EncodeToString(cov),
			"creation_height":     json.Number("0"),
			"created_by_coinbase": false,
		})
		inputs = append(inputs, consensus.TxInput{PrevTxid: prev, PrevVout: 0})
	}

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   inputs,
		Outputs:  nil, // zero outputs: the whole input sum becomes fee
		Locktime: 0,
	}
	witness := make([]consensus.WitnessItem, 0, len(inputs))
	for i := range inputs {
		sig := mustSignInputDigest(id, "input", signer, tx, uint32(i), wideFeeInputValue, chainID)
		witness = append(witness, consensus.WitnessItem{
			SuiteID:   consensus.SUITE_ID_ML_DSA_87,
			Pubkey:    pub,
			Signature: sig,
		})
	}
	tx.Witness = witness

	wideFee := consensus.Uint128FromU64(wideFeeInputValue)
	wideFee, ok := wideFee.CheckedAdd(consensus.Uint128FromU64(wideFeeInputValue))
	if !ok {
		fatalf("%s: wide fee overflow", id)
	}
	if wideFee.Cmp(consensus.Uint128FromU64(^uint64(0))) <= 0 {
		fatalf("%s: wide fee must exceed u64", id)
	}

	v := upsertVector(f, id, map[string]any{
		"op":              "utxo_apply_basic",
		"height":          json.Number("200"),
		"block_timestamp": json.Number("1000"),
		"expect_ok":       true,
	})
	v["tx_hex"] = hex.EncodeToString(mustTxBytes(tx))
	v["utxos"] = utxos
	v["expect_fee"] = wideFee.String()
	v["expect_utxo_count"] = json.Number("0")
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

// pinDevnetEvidenceFeeMetadata writes the input value and the derived
// expect_fee onto a devnet operator-evidence vector, then fails
// generation unless the resulting fee clears live mempool admission by
// devnetEvidenceMinFeeMarginFactor.
//
// The value must be pinned by the generator, not left in the JSON: the
// shared updateSingleInputSignedVector helper writes only tx_hex and
// covenant_data, the evidence scripts seed the node's UTXO set from
// utxos[0].value, and a value disagreeing with the one signed over
// yields a different sighash and an invalid signature.
//
// outValue is cross-checked against the transaction the caller's
// update* helper actually signed, so a call site whose arguments drift
// from the emitted bytes fails here rather than only at /submit_tx.
//
// The floor is re-derived from the emitted transaction rather than
// assumed. The comparison mirrors feeRateBelowFloor in
// clients/go/node/mempool_fee_floor.go, including its weight==0
// fail-closed arm.
func pinDevnetEvidenceFeeMetadata(f *fixtureFile, id string, inValue uint64, outValue uint64) {
	if outValue > inValue {
		fatalf("%s: output value %d exceeds input value %d", id, outValue, inValue)
	}
	fee := inValue - outValue

	v := findVector(f, id)
	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo, got %d", id, len(utxos))
	}
	utxos[0]["value"] = float64(inValue)
	v["utxos"] = utxos
	v["expect_fee"] = float64(fee)

	txHex, ok := v["tx_hex"].(string)
	if !ok {
		fatalf("%s: tx_hex is not a string", id)
	}
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		fatalf("%s: decode tx_hex: %v", id, err)
	}
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		fatalf("%s: parse emitted tx: %v", id, err)
	}

	var sumOut uint64
	for i, out := range tx.Outputs {
		if sumOut > math.MaxUint64-out.Value {
			fatalf("%s: emitted tx output value sum overflows at index %d", id, i)
		}
		sumOut += out.Value
	}
	if sumOut != outValue {
		fatalf("%s: emitted tx output sum %d does not match outValue %d", id, sumOut, outValue)
	}

	weight, _, _, err := consensus.TxWeightAndStats(tx)
	if err != nil {
		fatalf("%s: tx weight: %v", id, err)
	}
	if weight == 0 {
		fatalf("%s: emitted tx has zero weight", id)
	}
	hi, required := bits.Mul64(weight, node.DefaultMempoolMinFeeRate*devnetEvidenceMinFeeMarginFactor)
	if hi != 0 || fee < required {
		fatalf(
			"%s: fee=%d below required=%d (weight=%d min_fee_rate=%d margin=%dx); raise devnetEvidenceInputValue",
			id, fee, required, weight, node.DefaultMempoolMinFeeRate, devnetEvidenceMinFeeMarginFactor,
		)
	}
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
	inValue uint64,
	outValue uint64,
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
	utxos[0]["value"] = float64(inValue)

	prev := mustHex32(utxos[0]["txid"].(string))
	vout := mustJSONUint32(id+".utxos[0].vout", utxos[0]["vout"])

	outCov := p2pkCovenantData(destKP.PubkeyBytes())
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
		Outputs: []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		// Keep locktime=0 for non-coinbase.
		Locktime: 0,
	}

	sig := mustSignInputDigest(id, "claim_input", claimKP, tx, 0, inValue, chainID)

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

	buildBlock := func(height uint32, coinbaseValue uint64) string {
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
			Locktime:  height,
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

		if _, err := consensus.ValidateBlockBasicWithContextAtHeight(block, nil, nil, uint64(height), nil); err != nil {
			fatalf("subsidy: generated block fails basic validation: %v", err)
		}

		return hex.EncodeToString(block)
	}

	updateWideSumFeesBlocks(f, chainID, spendKP, coinbaseDestKP, sub1)

	sub1["block_hex"] = buildBlock(blockHeight, subsidy+sumFees)
	sub1["utxos"] = spendUTXO
	sub1["already_generated"] = json.Number(strconv.FormatUint(alreadyGenerated, 10))

	sub2["block_hex"] = buildBlock(blockHeight, subsidy+sumFees+1)
	sub2["utxos"] = spendUTXO
	sub2["already_generated"] = json.Number(strconv.FormatUint(alreadyGenerated, 10))

	const (
		firstTailSubsidyHeight = uint32(5_771_107)
		crossingSupply         = "18446744073699181041"
		crossedSupply          = "18446744073718206916"
		legacyU64MaxSupply     = "18446744073709551615"
		legacyU64MaxSupplyN1   = "18446744073728577490"
		maxU128Supply          = "340282366920938463463374607431768211455"
	)
	supplyBlock := buildBlock(firstTailSubsidyHeight, consensus.TAIL_EMISSION_PER_BLOCK+sumFees)

	crossing := upsertVector(f, "CV-SUB-SUPPLY-U128-01", map[string]any{
		"op":                          "connect_block_basic",
		"height":                      json.Number(strconv.FormatUint(uint64(firstTailSubsidyHeight), 10)),
		"expected_prev_hash":          sub1["expected_prev_hash"],
		"expected_target":             sub1["expected_target"],
		"already_generated":           crossingSupply,
		"expect_ok":                   true,
		"expect_sum_fees":             json.Number(strconv.FormatUint(sumFees, 10)),
		"expect_utxo_count":           json.Number("2"),
		"expect_already_generated":    crossingSupply,
		"expect_already_generated_n1": crossedSupply,
	})
	crossing["block_hex"] = supplyBlock
	crossing["utxos"] = spendUTXO

	legacy := upsertVector(f, "CV-SUB-SUPPLY-U128-02", map[string]any{
		"op":                          "connect_block_basic",
		"height":                      json.Number(strconv.FormatUint(uint64(firstTailSubsidyHeight), 10)),
		"expected_prev_hash":          sub1["expected_prev_hash"],
		"expected_target":             sub1["expected_target"],
		"already_generated":           json.Number(legacyU64MaxSupply),
		"expect_ok":                   true,
		"expect_sum_fees":             json.Number(strconv.FormatUint(sumFees, 10)),
		"expect_utxo_count":           json.Number("2"),
		"expect_already_generated":    legacyU64MaxSupply,
		"expect_already_generated_n1": legacyU64MaxSupplyN1,
	})
	legacy["block_hex"] = supplyBlock
	legacy["utxos"] = spendUTXO

	overflow := upsertVector(f, "CV-SUB-SUPPLY-U128-03", map[string]any{
		"op":                 "connect_block_basic",
		"height":             json.Number(strconv.FormatUint(uint64(firstTailSubsidyHeight), 10)),
		"expected_prev_hash": sub1["expected_prev_hash"],
		"expected_target":    sub1["expected_target"],
		"already_generated":  maxU128Supply,
		"expect_ok":          false,
		"expect_err":         "BLOCK_ERR_PARSE",
	})
	overflow["block_hex"] = supplyBlock
	overflow["utxos"] = spendUTXO
}

// updateWideSumFeesBlocks authors the shared widened-aggregate block rows.
//
// Two non-coinbase transactions each burn a 2^63 input to fee, so the block
// sum_fees is exactly 2^64 — above u64, and above either individual fee. The
// coinbase pays block_subsidy(1)+sum_fees across two outputs, because that
// total no longer fits in a single u64 output value.
//
//   - the exact bound is accepted and reports sum_fees as a canonical
//     decimal string;
//   - the same block with one extra unit is BLOCK_ERR_SUBSIDY_EXCEEDED.
//
// #lizard forgive
func updateWideSumFeesBlocks(
	f *fixtureFile,
	chainID [32]byte,
	spendKP digestSigner,
	coinbaseDestKP digestSigner,
	sub1 map[string]any,
) {
	const blockHeight = uint32(1)
	subsidy := consensus.BlockSubsidy(uint64(blockHeight), 0)
	spendPub := spendKP.PubkeyBytes()
	spendCov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, spendPub)
	cbDestCov := p2pkCovenantData(coinbaseDestKP.PubkeyBytes())
	prevTxids := [2][32]byte{{0xf1}, {0xf2}}

	utxos := make([]map[string]any, 0, len(prevTxids))
	nonCoinbaseBytes := make([][]byte, 0, len(prevTxids))
	sumFees := consensus.Uint128{}
	for i, prev := range prevTxids {
		utxos = append(utxos, map[string]any{
			"txid":                hex.EncodeToString(prev[:]),
			"vout":                json.Number("0"),
			"value":               json.Number(strconv.FormatUint(wideFeeInputValue, 10)),
			"covenant_type":       json.Number(strconv.FormatUint(uint64(consensus.COV_TYPE_P2PK), 10)),
			"covenant_data":       hex.EncodeToString(spendCov),
			"creation_height":     json.Number("0"),
			"created_by_coinbase": false,
		})
		tx := &consensus.Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  uint64(i) + 1,
			Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: 0}},
			Outputs:  nil, // zero outputs: the whole input becomes fee
			Locktime: 0,
		}
		sig := mustSignInputDigest("wide-sum-fees", "input0", spendKP, tx, 0, wideFeeInputValue, chainID)
		tx.Witness = []consensus.WitnessItem{{
			SuiteID:   consensus.SUITE_ID_ML_DSA_87,
			Pubkey:    spendPub,
			Signature: sig,
		}}
		nonCoinbaseBytes = append(nonCoinbaseBytes, mustTxBytes(tx))
		next, ok := sumFees.CheckedAdd(consensus.Uint128FromU64(wideFeeInputValue))
		if !ok {
			fatalf("wide-sum-fees: sum_fees overflow")
		}
		sumFees = next
	}
	if sumFees.Cmp(consensus.Uint128FromU64(^uint64(0))) <= 0 {
		fatalf("wide-sum-fees: aggregate must exceed u64")
	}
	limit, ok := sumFees.CheckedAdd(consensus.Uint128FromU64(subsidy))
	if !ok {
		fatalf("wide-sum-fees: coinbase limit overflow")
	}

	prevHashStr, ok := sub1["expected_prev_hash"].(string)
	if !ok {
		fatalf("wide-sum-fees: expected_prev_hash is not a string")
	}
	prevHash := mustHex32(prevHashStr)
	build := func(extra uint64) string {
		// The bound exceeds u64, so it is paid across two coinbase outputs.
		high := wideFeeInputValue
		low, ok := limit.CheckedSub(consensus.Uint128FromU64(high))
		if !ok || low.Hi != 0 {
			fatalf("wide-sum-fees: coinbase split does not fit u64")
		}
		return buildWideSumFeesBlock(wideSumFeesBlockInput{
			blockHeight:      blockHeight,
			prevHash:         prevHash,
			cbDestCov:        cbDestCov,
			coinbaseValues:   []uint64{high, low.Lo + extra},
			nonCoinbaseBytes: nonCoinbaseBytes,
		})
	}

	ok1 := upsertVector(f, "CV-SUB-U128-01", map[string]any{
		"op":                 "connect_block_basic",
		"height":             json.Number("1"),
		"expected_prev_hash": sub1["expected_prev_hash"],
		"expected_target":    sub1["expected_target"],
		"already_generated":  json.Number("0"),
		"expect_ok":          true,
	})
	ok1["block_hex"] = build(0)
	ok1["utxos"] = utxos
	ok1["expect_sum_fees"] = sumFees.String()
	ok1["expect_utxo_count"] = json.Number("2")

	bad := upsertVector(f, "CV-SUB-U128-02", map[string]any{
		"op":                 "connect_block_basic",
		"height":             json.Number("1"),
		"expected_prev_hash": sub1["expected_prev_hash"],
		"expected_target":    sub1["expected_target"],
		"already_generated":  json.Number("0"),
		"expect_ok":          false,
		"expect_err":         "BLOCK_ERR_SUBSIDY_EXCEEDED",
	})
	bad["block_hex"] = build(1)
	bad["utxos"] = utxos

	// sum_fees is the only widened value a vector supplies as INPUT, and
	// block_basic_check_with_fees is the only op that reads it. Authoring it
	// as a canonical decimal string above u64 binds the request path end to
	// end: the runner must forward the string unchanged, and both CLIs must
	// read it back as exactly 2^64. Re-encoding it as a bare JSON number puts
	// a numeric token above u64 on the wire, which both readers reject.
	inputSide := upsertVector(f, "CV-SUB-U128-03", map[string]any{
		"op":                 "block_basic_check_with_fees",
		"height":             json.Number("1"),
		"expected_prev_hash": sub1["expected_prev_hash"],
		"expected_target":    sub1["expected_target"],
		"already_generated":  json.Number("0"),
		"expect_ok":          true,
	})
	inputSide["block_hex"] = build(0)
	inputSide["sum_fees"] = sumFees.String()
}

type wideSumFeesBlockInput struct {
	prevHash         [32]byte
	cbDestCov        []byte
	coinbaseValues   []uint64
	nonCoinbaseBytes [][]byte
	blockHeight      uint32
}

func buildWideSumFeesBlock(in wideSumFeesBlockInput) string {
	outputs := make([]consensus.TxOutput, 0, len(in.coinbaseValues)+1)
	for _, value := range in.coinbaseValues {
		outputs = append(outputs, consensus.TxOutput{
			Value:        value,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: in.cbDestCov,
		})
	}
	outputs = append(outputs, consensus.TxOutput{
		Value:        0,
		CovenantType: consensus.COV_TYPE_ANCHOR,
		CovenantData: bytes.Repeat([]byte{0x00}, 32),
	})
	coinbase := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  0,
		Inputs:   []consensus.TxInput{{PrevVout: ^uint32(0), Sequence: ^uint32(0)}},
		Outputs:  outputs,
		Locktime: in.blockHeight,
	}

	wtxids := make([][32]byte, 0, len(in.nonCoinbaseBytes)+1)
	_, _, cbWtxid := mustParseFixtureTx(mustTxBytes(coinbase))
	wtxids = append(wtxids, cbWtxid)
	for _, raw := range in.nonCoinbaseBytes {
		_, _, wtxid := mustParseFixtureTx(raw)
		wtxids = append(wtxids, wtxid)
	}
	wroot, err := consensus.WitnessMerkleRootWtxids(wtxids)
	if err != nil {
		fatalf("wide-sum-fees: witness root: %v", err)
	}
	wc := consensus.WitnessCommitmentHash(wroot)
	coinbase.Outputs[len(coinbase.Outputs)-1].CovenantData = wc[:]
	coinbaseBytes := mustTxBytes(coinbase)

	txids := make([][32]byte, 0, len(in.nonCoinbaseBytes)+1)
	_, cbTxid, _ := mustParseFixtureTx(coinbaseBytes)
	txids = append(txids, cbTxid)
	for _, raw := range in.nonCoinbaseBytes {
		_, txid, _ := mustParseFixtureTx(raw)
		txids = append(txids, txid)
	}
	merkle, err := consensus.MerkleRootTxids(txids)
	if err != nil {
		fatalf("wide-sum-fees: merkle root: %v", err)
	}

	header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
	header = consensus.AppendU32le(header, 1)
	header = append(header, in.prevHash[:]...)
	header = append(header, merkle[:]...)
	header = consensus.AppendU64le(header, 123)
	header = append(header, bytes.Repeat([]byte{0xff}, 32)...)
	header = consensus.AppendU64le(header, 123)
	if len(header) != consensus.BLOCK_HEADER_BYTES {
		fatalf("wide-sum-fees: header len=%d", len(header))
	}

	block := append([]byte(nil), header...)
	block = consensus.AppendCompactSize(block, uint64(len(in.nonCoinbaseBytes))+1)
	block = append(block, coinbaseBytes...)
	for _, raw := range in.nonCoinbaseBytes {
		block = append(block, raw...)
	}
	return hex.EncodeToString(block)
}

func mustParseFixtureTx(raw []byte) (*consensus.Tx, [32]byte, [32]byte) {
	tx, txid, wtxid, n, err := consensus.ParseTx(raw)
	if err != nil || n != len(raw) {
		fatalf("parse fixture tx: err=%v consumed=%d len=%d", err, n, len(raw))
	}
	return tx, txid, wtxid
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

// ---------------------------------------------------------------------------
// RUB-922 / C01 — frozen canonical publication observables corpus.
//
// Every expected value below is transcribed from the RUB-882 architecture
// parent AS SUPERSEDED by RUB-1180; no expected value is computed by calling a
// Go or Rust node production path, and no row prescribes a mutex name, an
// internal struct, allocator behavior, or a second persistent state machine.
// Provenance, INERT status and the POST-RUB-911 consume freeze point are stated
// once, in the emitted artifact's authority block and conformance/README.md.
// ---------------------------------------------------------------------------

const (
	canonicalPipelineArtifactName = "canonical_pipeline_v1"
	canonicalPipelineSchemaRel    = "conformance/schemas/cv-canonical-pipeline-v1.json"
	canonicalPipelineSchemaVer    = 1
	// pendingOwnerRUB910 marks a row whose machinery no slice of the
	// RUB-922 -> RUB-890 -> RUB-908 -> RUB-1200 -> RUB-1201 -> RUB-1202 ->
	// RUB-911 -> RUB-678 -> RUB-679 -> RUB-680 chain delivers.
	pendingOwnerRUB910 = "RUB-910"
)

type cpMap = map[string]any

type cpRow struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Scenario     string   `json:"scenario,omitempty"`
	Result       string   `json:"result,omitempty"`
	CommitTruth  string   `json:"commit_truth,omitempty"`
	RPC          string   `json:"rpc_projection,omitempty"`
	Forbidden    string   `json:"forbidden_observation,omitempty"`
	Counters     cpMap    `json:"canonical_counters,omitempty"`
	Effects      cpMap    `json:"effects,omitempty"`
	Detail       cpMap    `json:"detail,omitempty"`
	PendingOwner string   `json:"pending_owner,omitempty"`
	Covers       []string `json:"-"`
}

type cpArtifact struct {
	Artifact          string            `json:"artifact"`
	SchemaVersion     int               `json:"schema_version"`
	Schema            string            `json:"schema"`
	Meta              cpMap             `json:"_meta"`
	Authority         cpMap             `json:"authority"`
	ResultTaxonomy    []string          `json:"result_taxonomy"`
	CommitTruthValues []string          `json:"commit_truth_values"`
	CoverageReceipt   map[string]string `json:"coverage_receipt"`
	Rows              []cpRow           `json:"rows"`
}

// canonicalPipelineTaxonomy is the closed result taxonomy. A row result is a
// member name optionally followed by its exact parenthesized argument.
var canonicalPipelineTaxonomy = []string{
	"ACCEPTED", "STORED_NONCANONICAL", "KNOWN_BLOCK_NOOP(CANONICAL|STORED_NONCANONICAL)",
	"MISSING_PARENT", "ORPHAN_RETAINED", "ORPHAN_ALREADY_RETAINED", "CONSENSUS_INVALID(exact_error)",
	"LOCAL_BUSY", "LOCAL_RESOURCE_UNAVAILABLE(resource)", "STALE_LOCAL_PLAN", "LOCAL_CANCELLED",
	"LOCAL_STORE_ERROR(noncanonical)", "LOCAL_PERSISTENCE_ERROR(precommit)",
	"TERMINAL_STORE_INTEGRITY(canonical)", "TERMINAL_LOCAL_INVARIANT(evidence)",
	"TERMINAL_PERSISTENCE(old|new|neither_or_unreadable)",
}

var canonicalPipelineCommitTruth = []string{"OLD", "NEW", "UNKNOWN", "NOT_APPLICABLE"}

// canonicalPipelineClasses enumerates every class the coverage receipt must map
// to at least one row: the closed result taxonomy plus every named bullet of
// observable_rows, accepted_cases, rejected_cases and hostile_cases in RUB-922.
var canonicalPipelineClasses = []string{
	"taxonomy:ACCEPTED", "taxonomy:STORED_NONCANONICAL", "taxonomy:KNOWN_BLOCK_NOOP",
	"taxonomy:MISSING_PARENT", "taxonomy:ORPHAN_RETAINED", "taxonomy:ORPHAN_ALREADY_RETAINED",
	"taxonomy:CONSENSUS_INVALID", "taxonomy:LOCAL_BUSY", "taxonomy:LOCAL_RESOURCE_UNAVAILABLE",
	"taxonomy:STALE_LOCAL_PLAN", "taxonomy:LOCAL_CANCELLED", "taxonomy:LOCAL_STORE_ERROR",
	"taxonomy:LOCAL_PERSISTENCE_ERROR", "taxonomy:TERMINAL_STORE_INTEGRITY",
	"taxonomy:TERMINAL_LOCAL_INVARIANT", "taxonomy:TERMINAL_PERSISTENCE",
	"observable:paths", "observable:path_precedence", "observable:p2p_precedence",
	"observable:counter_deltas", "observable:final_state_atomicity",
	"observable:presence_truth_table", "observable:gc_damage_order",
	"observable:known_block_noop", "observable:frozen_effect_order",
	"observable:block_seen_inventory", "observable:no_penalty_bounds",
	"observable:permit_retry_budget", "observable:orphan_pool",
	"observable:source_quota_key", "observable:resource_identities",
	"observable:checkpoint_rows", "observable:postcommit_effects",
	"accepted:coherent_capture_publication", "accepted:lazy_memoized_provider",
	"accepted:pre_namespace_index_failure", "accepted:post_namespace_terminal_class",
	"accepted:reorg_metadata_charge", "accepted:go_resource_authority",
	"accepted:rust_repeat_corpus",
	"rejected:intermediate_or_duplicate_visibility", "rejected:late_or_retaining_busy",
	"rejected:presence_authority_misuse", "rejected:retry_and_pool_shape",
	"rejected:persistent_state_machinery", "rejected:foreign_surface_mutation",
	"hostile:postcommit_fault_boundaries", "hostile:apply_plan_metadata_caps",
	"hostile:orphan_admission_eviction_refusal", "hostile:equal_work_opposite_orders",
	"hostile:paired_first_errors", "hostile:permit_budget_races",
	"hostile:late_consensus_invalid_wins", "hostile:canonical_ambiguity_and_readers",
	"hostile:duplicate_and_corrupt_combinations", "hostile:orphan_cap_boundaries_and_source_keys",
	"hostile:inbound_reservation_and_wire_errors", "hostile:quota_crash_and_reclassification",
	"hostile:miner_reorg_peak_cancellation",
}

func cpObs(id, result, truth, scenario string, covers ...string) cpRow {
	return cpRow{ID: id, Kind: "observation", Scenario: scenario, Result: result, CommitTruth: truth, Covers: covers}
}

func cpAuth(id, scenario string, detail cpMap, covers ...string) cpRow {
	return cpRow{ID: id, Kind: "authority", Scenario: scenario, Detail: detail, Covers: covers}
}

func cpNo(id, forbidden string, covers ...string) cpRow {
	return cpRow{ID: id, Kind: "forbidden", Forbidden: forbidden, Covers: covers}
}

// counters pins the exact planner-owned canonical counter deltas as exact
// decimal or symbolic tokens ("+1", "0", "+connect_count").
func (r cpRow) counters(accepted, rejected string) cpRow {
	r.Counters = cpMap{"accepted_delta": accepted, "rejected_delta": rejected}
	return r
}

func (r cpRow) effects(effects cpMap) cpRow { r.Effects = effects; return r }

func (r cpRow) detail(detail cpMap) cpRow { r.Detail = detail; return r }

func (r cpRow) rpc(projection string) cpRow { r.RPC = projection; return r }

func (r cpRow) pending() cpRow { r.PendingOwner = pendingOwnerRUB910; return r }

func cpPathRows() []cpRow {
	return []cpRow{
		cpAuth("C01-PATHS-001", "Closed set of canonical-pipeline entry paths and their path-specific first-error precedence, including the exact fork choice every side path uses during branch collection.", cpMap{
			"paths":                "direct, genesis, losing_side, reorg, disconnect, miner, p2p_full, p2p_compact_probe, p2p_compact_reconstructed, p2p_relay_fallback, orphan_resolved",
			"direct_or_genesis":    "target, genesis_guard_when_applicable, strict_initial_canonical_index_preflight, mtp, validation",
			"losing_side":          "strict_index_read_during_branch_collection, fork_choice, target, mtp, basic_validation, store_block",
			"reorg":                "initial_mtp_snapshot, per_connect_row_target, connect_block_with_sliding_mtp, advance_mtp",
			"fork_choice":          "maximum cumulative ChainWork, then lexicographically lower canonical tip-hash bytes; independent of arrival order, worker schedule, validation completion and best-ready status",
			"p2p":                  "frame_length, frame_read, frame_checksum, documented_early_parse, header_check, pow_check, try_acquire_result, lease_owned_strict_presence, stateful_target_mtp_provider_consensus",
			"compact_absent_cycle": "release_first_lease, reconstruction_or_network, reacquire_lease, repeat_strict_presence",
		}, "observable:paths", "observable:path_precedence", "observable:p2p_precedence"),
		cpObs("C01-DIRECT-001", "ACCEPTED", "NEW", "One coherent A capture, one rolling private B, one process-local capacity-1 permit and one durable canonical-index commit publish the complete chain, standard, DA and owner image with no-fail RAM publication.",
			"taxonomy:ACCEPTED", "observable:counter_deltas", "accepted:coherent_capture_publication").counters("+1", "0"),
		cpObs("C01-GENESIS-001", "ACCEPTED", "NEW", "Genesis bootstrap from the exact empty pre-genesis state; the genesis guard runs after the direct target check and before the strict initial canonical-index preflight.",
			"observable:path_precedence").counters("+1", "0").rpc("bootstrap: continuation-only"),
		cpObs("C01-SIDE-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A losing side block passes target, MTP and basic validation and is stored; no canonical mutation and no counter change.",
			"taxonomy:STORED_NONCANONICAL", "observable:counter_deltas").counters("0", "0"),
		cpObs("C01-REORG-001", "ACCEPTED", "NEW", "A winning multi-block reorg is one plan: the whole transition is externally old or new and never row-wise intermediate.",
			"observable:counter_deltas", "observable:final_state_atomicity", "accepted:coherent_capture_publication").counters("+connect_count", "0").
			detail(cpMap{"external_visibility": "old_or_new", "intermediate_tip_rows": 0, "summary_rows": "one per newly canonical block", "observed_final_fields": "tip_hash, height, cumulative_chainwork, utxo_digest, supply_digest", "publication_events": 1}),
		cpObs("C01-DISCONNECT-001", "ACCEPTED", "NEW", "An explicit standalone disconnect publishes proven NEW with an empty canonical-applied summary and zero connected-block fee-floor decay events.",
			"observable:counter_deltas").counters("0", "0").detail(cpMap{"summary_rows": 0, "connected_block_decay_events": 0}),
		cpAuth("C01-NEUTRAL-001", "Results that change neither planner-owned canonical counter, carry no peer penalty and perform no unauthorized canonical mutation, plus the exact plan and candidate-queue bounds.", cpMap{
			"neutral_results":                    "LOCAL_BUSY, LOCAL_RESOURCE_UNAVAILABLE, STALE_LOCAL_PLAN, LOCAL_CANCELLED, KNOWN_BLOCK_NOOP, STORED_NONCANONICAL, ORPHAN_RETAINED, ORPHAN_ALREADY_RETAINED, MISSING_PARENT",
			"no_peer_penalty_results":            "every neutral result above plus LOCAL_STORE_ERROR(noncanonical), LOCAL_PERSISTENCE_ERROR(precommit), TERMINAL_STORE_INTEGRITY(canonical), TERMINAL_LOCAL_INVARIANT(evidence) and TERMINAL_PERSISTENCE",
			"p2p_duplicate_counter_mutations":    0,
			"peer_penalty":                       0,
			"unauthorized_canonical_mutations":   0,
			"active_stateful_plans_max":          1,
			"queued_candidate_bytes":             0,
			"queued_candidate_objects":           0,
			"wholly_unpublished_selected_branch": "accepted +0",
		}, "observable:counter_deltas", "observable:no_penalty_bounds"),
		cpObs("C01-FIRSTERR-INDEX-001", "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", "A malformed canonical index paired with an invalid candidate: the strict initial canonical-index preflight owns the first error and the candidate is never validated.",
			"hostile:paired_first_errors", "observable:path_precedence", "taxonomy:TERMINAL_STORE_INTEGRITY").counters("0", "0").
			rpc("not_committed with the existing terminal result surface").detail(cpMap{"first_error_source": "strict_initial_canonical_index_preflight", "admission": "latched"}),
		cpObs("C01-FIRSTERR-LATE-001", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)", "OLD", "A late consensus-invalid candidate paired with an earlier best-effort artifact-write failure: the exact consensus error wins whenever validation can complete.",
			"hostile:late_consensus_invalid_wins", "taxonomy:CONSENSUS_INVALID").counters("0", "+1").rpc("not_committed"),
		cpObs("C01-EQUALWORK-001", "ACCEPTED", "NEW", "Two equal-cumulative-work candidates delivered and validation-completed in opposite orders select the same lexicographically lower canonical tip hash in both clients.",
			"hostile:equal_work_opposite_orders").detail(cpMap{"stable_under": "reversed delivery order, reversed validation completion, reversed worker schedule, best-ready status"}),
	}
}

func cpPresenceRows() []cpRow {
	return []cpRow{
		cpAuth("C01-PRESENCE-001", "The strict presence truth table is closed and no repair is observable.", cpMap{
			"canonical_member":     "block=valid|header=match|undo=valid => CANONICAL; every other recognized canonical combination => TERMINAL_STORE_INTEGRITY(canonical)",
			"noncanonical_absent":  "block=absent|header=absent|undo=absent => ABSENT",
			"noncanonical_stored":  "block=valid|header=absent|undo=absent; block=valid|header=match|undo=absent; block=valid|header=match|undo=valid",
			"noncanonical_other":   "every other recognized combination => LOCAL_STORE_ERROR(noncanonical)",
			"repair_or_truncation": false,
		}, "observable:presence_truth_table"),
		cpObs("C01-PRESENCE-TERMINAL-001", "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", "A canonical member with a missing, partial, corrupt or mismatched artifact is terminal and keeps mutation admission latched.",
			"observable:presence_truth_table", "hostile:duplicate_and_corrupt_combinations").counters("0", "0").
			detail(cpMap{"combinations": "block=absent|header=match|undo=valid; block=valid|header=absent|undo=valid; block=valid|header=mismatch|undo=valid; block=valid|header=match|undo=absent; block=valid|header=match|undo=invalid; block=corrupt|header=match|undo=valid", "admission": "latched"}),
		cpObs("C01-PRESENCE-STOREERR-001", "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE", "Every other recognized noncanonical combination is a local store error and leaves the canonical images unchanged.",
			"taxonomy:LOCAL_STORE_ERROR", "observable:presence_truth_table", "hostile:duplicate_and_corrupt_combinations").rpc("no committed mine result").
			detail(cpMap{"combinations": "block=absent|header=present|undo=absent; block=absent|header=absent|undo=present; block=valid|header=mismatch|undo=absent; block=valid|header=match|undo=invalid"}),
		cpObs("C01-GC-ORDER-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "Damaged-noncanonical GC ranks candidates by the closed ascending damage class order, then by lexicographic hash; the first matching class owns a multi-fault row and healthy rows are never candidates.",
			"observable:gc_damage_order", "hostile:quota_crash_and_reclassification").detail(cpMap{
			"class_order":        "D0_INVALID_BLOCK, D1_HEADER_WITHOUT_VALID_BLOCK, D2_UNDO_WITHOUT_BLOCK_OR_HEADER, D3_INVALID_HEADER, D4_UNDO_WITHOUT_VALID_HEADER, D5_INVALID_UNDO",
			"class_predicates":   "D0_INVALID_BLOCK: block leaf exists but strict parse or hash fails; D1_HEADER_WITHOUT_VALID_BLOCK: block leaf missing or failing strict parse or hash (a valid block is absent) AND a header leaf is present on disk, regardless of the header's own validity and regardless of undo presence or validity; D2_UNDO_WITHOUT_BLOCK_OR_HEADER: no valid block, no header, undo exists; D3_INVALID_HEADER: valid block and header exists but is malformed or mismatched; D4_UNDO_WITHOUT_VALID_HEADER: valid block, header absent, undo exists; D5_INVALID_UNDO: valid block and matching header and the undo envelope, binding or exact rederived bytes are invalid",
			"candidates":         "D0+D5 at hash 0x..02, D1 at hash 0x..01, D1 at hash 0x..03, D5 at hash 0x..00",
			"expected_victim":    "D0+D5 at hash 0x..02",
			"tie_break":          "lexicographically lower hash inside one class (D1 0x..01 before D1 0x..03)",
			"fail_closed_leaves": "strict read failure, non-regular, unexpected leaves are never GC candidates",
		}),
		cpObs("C01-GC-HEALTHY-001", "LOCAL_RESOURCE_UNAVAILABLE(noncanonical_bytes)", "OLD", "Quota exhaustion with only healthy rows returns the non-retriable resource result after the damaged-only GC attempt; noncanonical_count behaves identically.",
			"taxonomy:LOCAL_RESOURCE_UNAVAILABLE", "observable:resource_identities", "observable:gc_damage_order").counters("0", "0").
			detail(cpMap{"retriable": false, "gc_attempted": true, "rows_reclaimed": 0, "release_notification": false}),
		cpAuth("C01-GC-CRASH-001", "Quota cap+1, partial create and a crash at each delete or fsync boundary stay fail-closed; a canonical-to-side reclassification with an open reader keeps that reader's artifact readable.", cpMap{
			"crash_boundaries":                  "before_delete, after_delete_before_fsync, after_fsync",
			"partial_create":                    "reclaimed, never counted as healthy",
			"reclassification_with_open_reader": "stable reader registry, no truncation",
			"canonical_state_mutations":         0,
		}, "hostile:quota_crash_and_reclassification"),
	}
}

func cpEffectRows() []cpRow {
	frozenOrder := []string{"record_candidate_best_height", "set_block_seen", "block_inventory_relay_per_section_19", "attempt_one_da_orphan_ttl_advance", "wake_resolver_once"}
	relayDisposition := "per specification section 19; disposition frozen in C01-RELAY-STORED-001 / C01-RELAY-ACCEPTED-001 (pending_owner RUB-910)"
	return []cpRow{
		cpObs("C01-NOOP-FULL-001", "KNOWN_BLOCK_NOOP(CANONICAL)", "NOT_APPLICABLE", "A duplicate full receive with blockSeen already set is a strict no-op: it clears only matching compact outstanding state, even though the production helper returns nil and sends no wire response.",
			"observable:known_block_noop", "taxonomy:KNOWN_BLOCK_NOOP", "hostile:duplicate_and_corrupt_combinations").counters("0", "0").
			effects(cpMap{"block_seen": "preserved", "record_best_height": 0, "inv_attempt": 0, "da_ttl_attempt": 0, "resolver_wake": 0, "canonical_da_sets_consumed": 0, "broadcast": 0, "wire_response": 0, "peer_penalty": 0, "provider_reads": 0}).
			detail(cpMap{"derivation": "strict presence plus proven no-effect behavior"}),
		cpObs("C01-NOOP-CMPCT-001", "KNOWN_BLOCK_NOOP(STORED_NONCANONICAL)", "NOT_APPLICABLE", "A duplicate compact receive whose blockSeen is unset leaves it unset: blockSeen is relay dedup only and is neither residency nor invalidity authority.",
			"observable:known_block_noop", "observable:block_seen_inventory").counters("0", "0").effects(cpMap{"block_seen": "unset", "inv_attempt": 0, "resolver_wake": 0}),
		cpObs("C01-NOOP-RECLAIMED-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A reclaimed row with a stale blockSeen is ABSENT under strict presence, so the receive stores it again and preserves the stale blockSeen value.",
			"observable:block_seen_inventory", "hostile:duplicate_and_corrupt_combinations").effects(cpMap{"block_seen": "preserved"}),
		cpObs("C01-EFFECT-STORED-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A fresh STORED_NONCANONICAL freezes the POST-RUB-911 P2P-owned effect order, which has no consume step; the side block consumes zero canonical-DA sets.",
			"observable:frozen_effect_order", "observable:postcommit_effects", "taxonomy:STORED_NONCANONICAL").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "block_seen": "set", "block_inventory_relay": relayDisposition, "da_ttl_attempt": 1, "resolver_wake": 1, "canonical_da_sets_consumed": 0}),
		cpObs("C01-EFFECT-ACCEPTED-001", "ACCEPTED", "NEW", "A fresh ACCEPTED freezes the same P2P-owned effect order; canonical-DA consumption is not a step of it but an identity of the transition image, consuming every nonempty canonical-applied summary entry exactly once and never from a post-return caller.",
			"observable:frozen_effect_order", "taxonomy:ACCEPTED").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "block_seen": "set", "block_inventory_relay": relayDisposition, "da_ttl_attempt": 1, "resolver_wake": 1, "canonical_da_sets_consumed": "every nonempty summary entry exactly once, inside the published image"}).
			detail(cpMap{"da_ttl_fence": "the DA-orphan TTL advance never interleaves with a canonical transition", "post_return_consume_callers": 0}),
		cpObs("C01-FAULT-STORED-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A fault injected at each fallible post-store effect boundary still runs every subsequent best-effort effect and the final resolver wake exactly once, in the frozen order.",
			"hostile:postcommit_fault_boundaries").effects(cpMap{"record_best_height": 1, "da_ttl_attempt": 1, "resolver_wake": 1}).
			detail(cpMap{"fault_boundaries": "record_best_height, block_seen, block_inventory_relay, da_ttl_attempt", "short_circuit": false, "replay": false, "reordered_continuation": false, "result_changed_by_failure": false}),
		cpObs("C01-FAULT-ACCEPTED-001", "ACCEPTED", "NEW", "The same fault matrix on an ACCEPTED row with a nonempty canonical-applied summary: failures add bounded diagnostics only and never duplicate the planner-owned counter or re-consume a DA set.",
			"hostile:postcommit_fault_boundaries").counters("+1", "0").effects(cpMap{"resolver_wake": 1, "canonical_da_sets_consumed": "unchanged by any post-store failure"}).
			detail(cpMap{"duplicate_counter_mutation": false, "artifact_state_changed_by_failure": false, "peer_policy_changed_by_failure": false}),
		cpAuth("C01-POSTCOMMIT-001", "Complete postcommit effect enumeration with exact zero, once or count dispositions; there is no durable outbox.", cpMap{
			"metrics":               "once",
			"checkpoint":            "derived cadence, never canonical authority",
			"requeue_attempt":       "ordered best-effort normal admission, after publication",
			"record_best_height":    "once per fresh row",
			"canonical_da_consume":  "identity of the published image, never a post-return step",
			"block_seen":            "once per fresh row",
			"block_inventory_relay": relayDisposition,
			"da_ttl_attempt":        "once, fenced",
			"resolver_wake":         "once",
			"durable_outbox":        false,
		}, "observable:postcommit_effects"),
		cpAuth("C01-RELAY-STORED-001", "Block inventory relay authority under the pinned specification section 19: stored side-branch processing, a proven NEW carrying an empty canonical-applied summary (a standalone disconnect), and every non-NEW commit truth grant no authority and make no attempt.", cpMap{
			"relay_authority":    false,
			"inv_attempt":        0,
			"no_authority_cases": "STORED_NONCANONICAL side-branch processing; NEW with an empty, unresolved, duplicate or absent summary, including a standalone disconnect; every non-NEW commit truth",
			"spec_ref":           "rubin-spec@c14b0100 RUBIN_COMPACT_BLOCKS.md section 19",
		}, "observable:frozen_effect_order", "observable:postcommit_effects").pending(),
		cpAuth("C01-RELAY-ACCEPTED-001", "The section-19 relay disposition for one authorized publication: proven NEW with a non-empty ordered canonical-applied summary.", cpMap{
			"ibd":            "sampled after the transition publication; if IBD, no attempt",
			"owner_snapshot": "one snapshot of post-handshake send owners, deduplicated by owner identity; a captured handle is never re-resolved or retargeted",
			"frames":         "per summary row in canonical order, exactly one ordinary single-vector MSG_BLOCK inv frame per (owner x row)",
			"exclusion":      "only the invocation-local (captured source owner, exact row hash) pair; never another owner and never another row",
			"write_failure":  "stops only that owner's remaining suffix; other owners remain eligible",
			"best_effort":    "no retry and no rollback; a relay result cannot change commit truth or the published summary",
			"spec_ref":       "rubin-spec@c14b0100 RUBIN_COMPACT_BLOCKS.md section 19",
		}, "observable:frozen_effect_order", "observable:postcommit_effects").pending(),
		cpAuth("C01-INVENTORY-001", "Inventory answers from current complete BlockStore or orphan residency; a partial or corrupt row returns its local store disposition without entering a receive loop.", cpMap{
			"block_seen_role": "relay dedup only", "residency_authority": "current BlockStore/orphan", "partial_or_corrupt": "local store disposition, no receive loop",
		}, "observable:block_seen_inventory", "rejected:presence_authority_misuse"),
		cpAuth("C01-INVENTORY-RECLAIMED-001", "A reclaimed or ABSENT hash stays requestable without a GC callback or tombstone; RUB-908 exposes current strict presence only and assigns this observable to RUB-910.", cpMap{
			"requestable_after_reclaim": true, "gc_callback": false, "tombstone": false,
		}, "observable:block_seen_inventory").pending(),
	}
}

func cpOrphanRows() []cpRow {
	return []cpRow{
		cpObs("C01-ORPH-RETAIN-001", "ORPHAN_RETAINED", "OLD", "One service-global orphan pool uses insert-then-evict semantics: a unique entry of at most 64 MiB with an empty source key, or a current nonempty normalized-source count below 50, is inserted and marked in blockSeen.",
			"taxonomy:ORPHAN_RETAINED", "observable:orphan_pool").effects(cpMap{"block_seen": "set", "evictions": 0}).
			detail(cpMap{"pool_scope": "one service-global pool", "entry_max_bytes": 67108864, "unique_entry_cap": 500, "aggregate_byte_cap": 67108864, "nonempty_source_cap": 50, "empty_source_key": "unmetered, admitted beyond 50"}),
		cpObs("C01-ORPH-DUP-001", "ORPHAN_ALREADY_RETAINED", "OLD", "A duplicate orphan is already-retained: no copy, no effect and no eviction.",
			"taxonomy:ORPHAN_ALREADY_RETAINED", "observable:orphan_pool").effects(cpMap{"evictions": 0, "block_seen": "unchanged"}),
		cpObs("C01-ORPH-EVICT-001", "ORPHAN_RETAINED", "OLD", "Crossing 500 to 501 unique entries, or 64 MiB to cap+1 raw bytes, retains the newest row and evicts oldest FIFO rows until both caps hold; each eviction removes that row and clears its blockSeen.",
			"observable:orphan_pool", "hostile:orphan_cap_boundaries_and_source_keys").effects(cpMap{"evictions": 1, "block_seen": "set for the new row, cleared for the evicted row"}).
			detail(cpMap{"boundaries": "unique_count 500->501 and raw_bytes 64MiB->cap+1", "retained": "newest", "eviction_policy": "oldest FIFO first"}),
		cpObs("C01-ORPH-INFLIGHT-001", "ORPHAN_RETAINED", "OLD", "Eviction is unconditional and there is no pin set: a row under resolution has already been removed from the pool before the resolver sees it, so no in-pool row is pin-protected and no cap infeasibility can arise.",
			"hostile:orphan_admission_eviction_refusal", "observable:orphan_pool").
			detail(cpMap{"pin_set": false, "pre_insertion_feasibility_proof": false, "resolving_row_in_pool": false}),
		cpObs("C01-ORPH-OVERSIZE-001", "LOCAL_RESOURCE_UNAVAILABLE(orphan_pool)", "OLD", "A single entry larger than 64 MiB is a non-retriable orphan_pool refusal: no insertion, no eviction, and blockSeen unchanged in both the initially unset and the stale-set case.",
			"hostile:orphan_admission_eviction_refusal").effects(cpMap{"evictions": 0, "block_seen": "unchanged", "retry_slots": 0}).
			detail(cpMap{"retriable": false, "initial_unset_stays": "unset", "stale_set_stays": "set", "pool_bytes_delta": 0}),
		cpObs("C01-ORPH-SOURCE51-001", "LOCAL_RESOURCE_UNAVAILABLE(orphan_pool)", "OLD", "Entry 51 for one nonempty normalized source is a non-retriable refusal with the entire prior pool, FIFO, source counts and blockSeen byte-for-byte unchanged.",
			"hostile:orphan_admission_eviction_refusal", "hostile:orphan_cap_boundaries_and_source_keys").
			effects(cpMap{"evictions": 0, "block_seen": "unchanged", "retry_slots": 0}).detail(cpMap{"retriable": false, "source_count_delta": 0, "fifo_delta": 0}),
		cpObs("C01-ORPH-MISSING-PARENT-001", "MISSING_PARENT", "OLD", "An apply entered without orphan retention whose parent is neither canonical nor stored returns MISSING_PARENT and preserves the exact old image.",
			"taxonomy:MISSING_PARENT").counters("0", "0").rpc("not_committed only when reached by a mining entrypoint"),
		cpAuth("C01-SRCKEY-001", "The orphan source-quota key mapping is frozen byte-for-byte: SplitHostPort success selects the host regardless of a numeric, nonnumeric or empty port and of bracketed non-IP spelling, its failure keeps the complete input, ParseAddr success returns WithZone(\"\").String() without Unmap, and its failure preserves host bytes and case. Rust must reproduce these bytes and may not substitute a socket-address grammar.", cpMap{
			"cases": []string{
				"\"\" => \"\"",
				"\"192.0.2.7:8333\" => \"192.0.2.7\"",
				"\"192.0.2.7:notaport\" => \"192.0.2.7\"",
				"\"192.0.2.7:\" => \"192.0.2.7\"",
				"\":8333\" => \"\"",
				"\"[example.com]:8333\" => \"example.com\"",
				"\"[2001:db8::1]\" => \"[2001:db8::1]\"",
				"\"2001:db8::1\" => \"2001:db8::1\"",
				"\"[fe80::1%eth0]:8333\" => \"fe80::1\"",
				"\"[2001:0db8:0000:0000:0000:0000:0000:0001]:8333\" => \"2001:db8::1\"",
				"\"[::ffff:192.0.2.7]:8333\" => \"::ffff:192.0.2.7\"",
				"\"Example.COM:8333\" => \"Example.COM\"",
				"\"example.com:8333\" => \"example.com\"",
			},
			"empty_key_exempt_from_source_cap": true,
		}, "observable:source_quota_key", "hostile:orphan_cap_boundaries_and_source_keys"),
	}
}

func cpResourceRows() []cpRow {
	return []cpRow{
		cpAuth("C01-RES-IDENTITIES-001", "The owned resource identities. Every resource identity is LOCAL_RESOURCE_UNAVAILABLE and never consensus invalidity, and invalid configured bounds are startup or config failures outside peer retry. The identities no chain slice delivers are frozen separately in C01-RES-IDENTITIES-PENDING-001.", cpMap{
			"identities":                "noncanonical_bytes, noncanonical_count, orphan_pool, recovery_artifact",
			"recovery_artifact":         "non-retriable; profile-permitted pruned suffix awaiting validated reacquisition; distinct from bounded-storage reservation failure",
			"admission":                 "never latched for any resource identity; preserves OLD",
			"invalid_configured_bounds": "startup/config failure, outside peer retry",
		}, "observable:resource_identities", "taxonomy:LOCAL_RESOURCE_UNAVAILABLE"),
		cpAuth("C01-RES-IDENTITIES-PENDING-001", "The resource identities whose machinery no slice of this chain delivers; they are excluded from the RUB-926 zero-mismatch acceptance until RUB-910 is Done.", cpMap{
			"identities": "inbound_budget_capacity, inbound_budget_overflow, apply_plan_metadata",
			"retriable":  "inbound_budget_capacity only, and only with an independently proven exact block hash",
		}, "observable:resource_identities", "taxonomy:LOCAL_RESOURCE_UNAVAILABLE").pending(),
		cpObs("C01-APPLYMETA-CAP-001", "ACCEPTED", "NEW", "An apply plan whose checked metadata charge lands exactly on the 64 MiB cap succeeds.",
			"hostile:apply_plan_metadata_caps").counters("+connect_count", "0").
			detail(cpMap{"charge_formula": "48+40*(disconnect_rows+connect_rows)+32*complete_da_ids", "cap_bytes": 67108864, "charge_bytes": "exactly cap"}).pending(),
		cpObs("C01-APPLYMETA-OVER-001", "LOCAL_RESOURCE_UNAVAILABLE(apply_plan_metadata)", "OLD", "Cap+1 is non-retriable and preserves canonical, store, mempool, counter and effect state completely; it creates no peer penalty, no retry slot and no release notification.",
			"hostile:apply_plan_metadata_caps").counters("0", "0").
			effects(cpMap{"peer_penalty": 0, "retry_slots": 0, "getdata_sent": 0, "record_best_height": 0, "block_seen": "unchanged"}).
			detail(cpMap{"retriable": false, "release_notification": false}).pending(),
		cpObs("C01-BUSY-001", "LOCAL_BUSY", "OLD", "LOCAL_BUSY carries the canonical-permit observed-generation notification and arms the single peer retry slot with one joined waiter; it retains no candidate, never blocks the socket reader and never follows strict presence or stateful consensus.",
			"taxonomy:LOCAL_BUSY", "observable:permit_retry_budget").counters("0", "0").effects(cpMap{"retry_slots": 1, "getdata_sent": 1, "peer_penalty": 0}).
			detail(cpMap{"joined_waiters_max": 1, "deadline": "original receive-start +30 second absolute deadline", "fixed_backoff": false, "candidate_retained": false}).pending(),
		cpObs("C01-BUDGET-RACE-001", "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_capacity)", "OLD", "Registration-versus-release races, an already-closed notification, capacity released before the waiter is scheduled, a duplicate or different hash while the slot is armed, and disconnect or deadline races all resolve deterministically.",
			"hostile:permit_budget_races", "observable:permit_retry_budget").effects(cpMap{"retry_slots": 1, "peer_penalty": 0}).
			detail(cpMap{"retriable": true, "requires_proven_exact_hash": true, "non_retriable_classes_arm_no_slot_and_no_getdata": "inbound_budget_overflow, apply_plan_metadata, noncanonical_bytes, noncanonical_count, orphan_pool"}).pending(),
		cpObs("C01-WIRE-OVERFLOW-001", "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "OLD", "A checked inbound reservation overflow or replacement failure is non-retriable; a valid payload discarded because of a bad checksum, read or declared length keeps the documented wire-error precedence and never becomes a resource result.",
			"hostile:inbound_reservation_and_wire_errors").effects(cpMap{"retry_slots": 0, "getdata_sent": 0}).
			detail(cpMap{"retriable": false, "wire_error_precedence": "frame_length, frame_read, frame_checksum"}).pending(),
		cpAuth("C01-GO-CONSTANTS-001", "Go resource authority constants for this corpus. C01 freezes behavior and formulas, not imported Go heap coefficients: the Rust rows require a fresh identical runtime corpus repeated after the Go freeze.", cpMap{
			"inbound_default_bytes": 1073741824, "inbound_hard_bytes": 8589934592,
			"charge_full": "6x", "charge_compact": "12x", "charge_relay_fallback": "3x",
			"noncanonical_default_bytes": 8589934592, "noncanonical_hard_bytes": 34359738368,
			"noncanonical_unique_hashes": 524288, "compact_inventory_row_max_bytes": 128,
			"inventory_metadata_max_bytes": 67108864, "rust_repeat_required": true,
		}, "accepted:go_resource_authority", "accepted:rust_repeat_corpus"),
	}
}

func cpTerminalRows() []cpRow {
	return []cpRow{
		cpObs("C01-PRENS-001", "LOCAL_PERSISTENCE_ERROR(precommit)", "OLD", "A canonical-index failure before the namespace change reports the exact old state with no admission latch, no counter change and no retry.",
			"accepted:pre_namespace_index_failure", "taxonomy:LOCAL_PERSISTENCE_ERROR").counters("0", "0").rpc("not_committed").
			detail(cpMap{"admission": "not latched", "retry_slots": 0, "old_image": "exact"}),
		cpObs("C01-TP-OLD-001", "TERMINAL_PERSISTENCE(old)", "OLD", "One strict readback after a fault that may have crossed the commit point sees the exact old canonical-index identity; no rollback, retry, rewrite or heuristic classification follows.",
			"taxonomy:TERMINAL_PERSISTENCE", "accepted:post_namespace_terminal_class").counters("0", "0").
			rpc("not_committed, never ordinary retry").detail(cpMap{"admission": "latched", "rollback_attempted": false}),
		cpObs("C01-TP-NEW-001", "TERMINAL_PERSISTENCE(new)", "NEW", "The strict readback sees the exact planned-new identity: the new chain, standard, DA and owner images are truth and the committed identity is reported.",
			"accepted:post_namespace_terminal_class").detail(cpMap{"admission": "latched"}).
			rpc("committed; mined candidate identity only when the result-selecting mined candidate apply committed"),
		cpObs("C01-TP-UNKNOWN-001", "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", "Every other or unreadable readback publishes neither guessed image and exposes no summary and no relay authority.",
			"accepted:post_namespace_terminal_class", "hostile:canonical_ambiguity_and_readers").counters("0", "0").
			rpc("unknown; legacy mined absent").detail(cpMap{"admission": "latched", "summary_rows": 0, "relay_authority": false, "guessed_image": false, "stable_live_aliases": "a malformed live cache against a valid disk image, a retained-alias mutation under a continuously held permit, and admission readers active at terminal detection all keep stable aliases", "final_ram_cache_drift_check": "against the committed index bytes"}),
		cpObs("C01-TERMINV-001", "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", "A missing or corrupt selected retained record or accounting value, an exact-token mismatch, a duplicate claim, or a checked arithmetic underflow or overflow preserves OLD, publishes no candidate delta and keeps mutation admission latched.",
			"taxonomy:TERMINAL_LOCAL_INVARIANT").counters("0", "0").rpc("not_committed with the existing terminal result surface").
			detail(cpMap{"triggers": "missing or corrupt selected retained record, missing or corrupt accounting value, exact-token mismatch, duplicate claim, checked arithmetic underflow or overflow", "admission": "latched", "never_reclassified_as": "LOCAL_RESOURCE_UNAVAILABLE(resource), which preserves OLD and does not latch, or STALE_LOCAL_PLAN"}),
		cpObs("C01-TERMINV-BOOT-001", "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", "At the bootstrap boundary a STORED_NONCANONICAL result, or a KNOWN_BLOCK_NOOP(STORED_NONCANONICAL), is a terminal local invariant that publishes no candidate delta and keeps mutation admission latched; bootstrap ACCEPTED and KNOWN_BLOCK_NOOP(CANONICAL) remain continuation-only.",
			"taxonomy:TERMINAL_LOCAL_INVARIANT", "taxonomy:KNOWN_BLOCK_NOOP").counters("0", "0").rpc("not_committed with the existing terminal result surface"),
		cpObs("C01-STALE-001", "STALE_LOCAL_PLAN", "OLD", "At the result-selecting mined candidate boundary, STORED_NONCANONICAL and either KNOWN_BLOCK_NOOP variant map to STALE_LOCAL_PLAN and the exact old image is preserved.",
			"taxonomy:STALE_LOCAL_PLAN").counters("0", "0").rpc("not_committed"),
		cpObs("C01-CANCEL-001", "LOCAL_CANCELLED", "OLD", "A miner snapshot cancelled or released before PoW at the reorg peak returns LOCAL_CANCELLED with the exact old image, no canonical mutation and no peer effect.",
			"taxonomy:LOCAL_CANCELLED", "hostile:miner_reorg_peak_cancellation").counters("0", "0").effects(cpMap{"peer_penalty": 0}).rpc("not_committed"),
		cpAuth("C01-CKPT-001", "The derived checkpoint is not canonical authority: an accepted transition may report degraded, a subsequent success clears it, startup is fail-closed, and a multi-row cadence writes only the final state once.", cpMap{
			"accepted_with_degraded": true, "subsequent_success_clears_degraded": true,
			"startup_on_missing_or_corrupt_required_artifact": "fail-closed as TERMINAL_STORE_INTEGRITY(canonical); no reader, admission or relay exposure",
			"multi_row_cadence_writes":                        1,
			"multi_row_cadence_degraded":                      "logical OR across every row of the transition",
		}, "observable:checkpoint_rows"),
		cpAuth("C01-PROVIDER-001", "Provider reads are plan-local, lazy and memoized once per plan and preserve the path-specific first-error order; rotation create and spend stay separate by exact height.", cpMap{
			"provider_reads_per_plan": 1, "lazy": true, "rotation_create_and_spend": "separate by exact height",
		}, "accepted:lazy_memoized_provider"),
		cpAuth("C01-REORGMETA-001", "Reorg metadata charges the disconnect and connect rows plus the complete DA identifiers and retains no depth-proportional raw block, parse, undo or delta payload.", cpMap{
			"charge_formula": "48+40*(disconnect_rows+connect_rows)+32*complete_da_ids", "cap_bytes": 67108864, "depth_proportional_retention": false,
		}, "accepted:reorg_metadata_charge"),
	}
}

func cpForbiddenRows() []cpRow {
	return []cpRow{
		cpNo("C01-FORBID-INTERMEDIATE-001", "An intermediate reorg tip, an accepted-counter mutation per prepared row, or a duplicate receive that reprocesses, broadcasts or changes a counter.",
			"rejected:intermediate_or_duplicate_visibility"),
		cpNo("C01-FORBID-BUSY-001", "LOCAL_BUSY after strict presence or stateful consensus, or a BUSY that retains candidate data, penalizes a peer, or blocks the socket reader.",
			"rejected:late_or_retaining_busy"),
		cpNo("C01-FORBID-PRESENCE-001", "Header existence used as complete presence, blockSeen used as residency or invalidity authority, or a stored-noncanonical artifact used as a validation cache.",
			"rejected:presence_authority_misuse"),
		cpNo("C01-FORBID-RETRY-001", "A fixed retry sleep, more than one peer retry slot or waiter, a per-peer orphan pool, a new invalid-block cache, or a second candidate queue.",
			"rejected:retry_and_pool_shape"),
		cpNo("C01-FORBID-PERSIST-001", "Any persistent StateGeneration, CandidateLog, coordinator, durable outbox, plan directory, generic ReadView, new scratch parent, or implementation-specific schema field.",
			"rejected:persistent_state_machinery"),
		cpNo("C01-FORBID-SURFACE-001", "Any specification, Lean, client implementation, adapter, acceptance-runner or final-comparator mutation attributed to the C01 freeze.",
			"rejected:foreign_surface_mutation"),
	}
}

// canonicalPipelineRows returns the frozen corpus in stable authored order.
func canonicalPipelineRows() []cpRow {
	var rows []cpRow
	for _, family := range [][]cpRow{
		cpPathRows(), cpPresenceRows(), cpEffectRows(),
		cpOrphanRows(), cpResourceRows(), cpTerminalRows(), cpForbiddenRows(),
	} {
		rows = append(rows, family...)
	}
	return rows
}

// mustValidateCanonicalPipelineRows fails generation on any structural defect a
// downstream adapter could not repair: a duplicate row id, a result outside the
// closed taxonomy, an unknown commit-truth value, an unknown coverage class, or
// a kind missing its required payload.
func mustValidateCanonicalPipelineRows(rows []cpRow) {
	taxonomy := make(map[string]bool, len(canonicalPipelineTaxonomy))
	for _, value := range canonicalPipelineTaxonomy {
		taxonomy[strings.SplitN(value, "(", 2)[0]] = true
	}
	truths := make(map[string]bool, len(canonicalPipelineCommitTruth))
	for _, value := range canonicalPipelineCommitTruth {
		truths[value] = true
	}
	classes := make(map[string]bool, len(canonicalPipelineClasses))
	for _, class := range canonicalPipelineClasses {
		classes[class] = true
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !strings.HasPrefix(row.ID, "C01-") || seen[row.ID] {
			fatalf("canonical pipeline: row id %q must start with C01- and be unique", row.ID)
		}
		seen[row.ID] = true
		mustValidateCanonicalPipelineKind(row, taxonomy, truths)
		if len(row.Covers) == 0 {
			fatalf("canonical pipeline: row %s covers no enumerated class", row.ID)
		}
		for _, class := range row.Covers {
			if !classes[class] {
				fatalf("canonical pipeline: row %s covers unknown class %q", row.ID, class)
			}
		}
	}
}

// mustValidateCanonicalPipelineKind checks only what the JSON schema cannot:
// closed-taxonomy and commit-truth membership. Row shapes (which fields each
// kind requires and forbids) are owned by the schema's allOf/if-then rules and
// asserted by tools/tests/test_check_conformance_fixtures_drift.py.
func mustValidateCanonicalPipelineKind(row cpRow, taxonomy, truths map[string]bool) {
	switch row.Kind {
	case "observation":
		if !taxonomy[strings.SplitN(row.Result, "(", 2)[0]] {
			fatalf("canonical pipeline: row %s result %q is outside the closed taxonomy", row.ID, row.Result)
		}
		if !truths[row.CommitTruth] {
			fatalf("canonical pipeline: row %s commit truth %q is unknown", row.ID, row.CommitTruth)
		}
	case "authority", "forbidden":
	default:
		fatalf("canonical pipeline: row %s has unknown kind %q", row.ID, row.Kind)
	}
}

// canonicalPipelineCoverage maps every enumerated class to the row ids that
// define it. A class with zero rows is a generation failure: the corpus would
// otherwise freeze a value that no row anywhere defines.
func canonicalPipelineCoverage(rows []cpRow) map[string]string {
	byClass := make(map[string][]string, len(canonicalPipelineClasses))
	for _, row := range rows {
		for _, class := range row.Covers {
			byClass[class] = append(byClass[class], row.ID)
		}
	}
	out := make(map[string]string, len(canonicalPipelineClasses))
	for _, class := range canonicalPipelineClasses {
		ids := byClass[class]
		if len(ids) == 0 {
			fatalf("canonical pipeline: enumerated class %q maps to zero rows", class)
		}
		out[class] = strings.Join(ids, ", ")
	}
	return out
}

func mustWriteCanonicalPipelineCorpus(path string) {
	rows := canonicalPipelineRows()
	mustValidateCanonicalPipelineRows(rows)
	coverage := canonicalPipelineCoverage(rows)
	artifact := cpArtifact{
		Artifact:      canonicalPipelineArtifactName,
		SchemaVersion: canonicalPipelineSchemaVer,
		Schema:        canonicalPipelineSchemaRel,
		Meta: cpMap{
			"generated_by": "clients/go/cmd/gen-conformance-fixtures",
			"warning":      "MACHINE-GENERATED FILE. Do not edit manually.",
		},
		Authority: cpMap{
			"issue":                "RUB-922",
			"architecture_parent":  "RUB-882 as superseded by RUB-1180",
			"normative_spec_ref":   "2tbmz9y2xt-lang/rubin-spec@c14b010024ce633e1027bf891af3c49741db544a",
			"baseline_ref":         "2tbmz9y2xt-lang/rubin-protocol@86571857571736862e3194daa61491639cea5138",
			"expected_row_origin":  "authored architecture authority; no Go or Rust node production path is called to compute an expected value",
			"executors":            "RUB-923, RUB-926, RUB-924, RUB-901",
			"status":               "INERT until its adapters and comparator land; no canonical-publication slice may claim it as a passing gate",
			"consume_freeze_point": "POST-RUB-911 target: the frozen P2P effect order carries no canonical-DA consume step",
		},
		ResultTaxonomy:    canonicalPipelineTaxonomy,
		CommitTruthValues: canonicalPipelineCommitTruth,
		CoverageReceipt:   coverage,
		Rows:              rows,
	}
	b, err := json.MarshalIndent(&artifact, "", "  ")
	if err != nil {
		fatalf("canonical pipeline: marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatalf("canonical pipeline: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatalf("canonical pipeline: write %s: %v", path, err)
	}
}
