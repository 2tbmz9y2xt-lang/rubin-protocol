package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/sha3"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

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
	mustWriteCanonicalPipelineCorpus(remapWritePath(filepath.Join(repoRoot, "conformance", "fixtures", "protocol", "canonical_pipeline_v1.json")))

	// RUB-1207 / C01-R2: the dormant BUILDING successor pair. Same provenance
	// rule as v1; it carries identity and shape only, never a migrated row.
	mustWriteCanonicalPipelineV2Corpus(remapWritePath(filepath.Join(repoRoot, "conformance", "fixtures", "protocol", "canonical_pipeline_v2.json")))

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

// mustWriteJSON marshals v as indented JSON with a trailing newline and
// writes it to path, creating parent directories as needed (a no-op in
// default mutating mode; needed for nested --output-dir targets, e.g.
// devnet/). Fails closed via fatalf.
func mustWriteJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("marshal %s: %v", path, err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func mustWriteFixture(path string, f *fixtureFile) {
	mustWriteJSON(path, f)
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
// once, in the emitted artifact's authority block and conformance/fixtures/CHANGELOG.md.
// ---------------------------------------------------------------------------

const (
	canonicalPipelineArtifactName = "canonical_pipeline_v1"
	canonicalPipelineSchemaRel    = "conformance/schemas/cv-canonical-pipeline-v1.json"
	canonicalPipelineSchemaVer    = 1
	// pendingOwnerRUB1195, pendingOwnerRUB893 and pendingOwnerRUB910 name the
	// owner of a row whose machinery no slice of the RUB-922 -> RUB-890 ->
	// RUB-908 -> RUB-1200 -> RUB-1201 -> RUB-1202 -> RUB-911 -> RUB-678 ->
	// RUB-679 -> RUB-680 chain delivers: RUB-1195 owns the section-19 relay
	// rows; RUB-893 the inbound-budget identities, the inbound-budget races
	// and reservation overflow; RUB-910 permit/LOCAL_BUSY, retry-slot races,
	// reclaimed-hash inventory and the orphan-pool result classification
	// (duplicate / oversize / source-51 refusal), which production returns as one bit.
	pendingOwnerRUB1195 = "RUB-1195"
	pendingOwnerRUB893  = "RUB-893"
	pendingOwnerRUB910  = "RUB-910"
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
	"LOCAL_BUSY", "LOCAL_RESOURCE_UNAVAILABLE(resource)", "STALE_LOCAL_PLAN", "LOCAL_CANCELLED", //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
	"LOCAL_STORE_ERROR(noncanonical)", "LOCAL_PERSISTENCE_ERROR(precommit)",
	"TERMINAL_STORE_INTEGRITY(canonical)", "TERMINAL_LOCAL_INVARIANT(evidence)",
	"TERMINAL_PERSISTENCE(old|new|neither_or_unreadable)",
}

// canonicalPipelineResultPattern anchors the full result string (not just the
// prefix before "("); hand-mirrored in the schema's result.pattern, both pinned by tests.
const canonicalPipelineResultPattern = `^(ACCEPTED|STORED_NONCANONICAL|KNOWN_BLOCK_NOOP\((CANONICAL|STORED_NONCANONICAL)\)|MISSING_PARENT|ORPHAN_RETAINED|ORPHAN_ALREADY_RETAINED|CONSENSUS_INVALID\([A-Z][A-Z0-9_]*\)|LOCAL_BUSY|LOCAL_RESOURCE_UNAVAILABLE\((inbound_budget_capacity|inbound_budget_overflow|apply_plan_metadata|noncanonical_bytes|noncanonical_count|orphan_pool|recovery_artifact)\)|STALE_LOCAL_PLAN|LOCAL_CANCELLED|LOCAL_STORE_ERROR\(noncanonical\)|LOCAL_PERSISTENCE_ERROR\(precommit\)|TERMINAL_STORE_INTEGRITY\(canonical\)|TERMINAL_LOCAL_INVARIANT\(evidence\)|TERMINAL_PERSISTENCE\((old|new|neither_or_unreadable)\))$` //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling

var canonicalPipelineResultRE = regexp.MustCompile(canonicalPipelineResultPattern)

var canonicalPipelineCommitTruth = []string{"OLD", "NEW", "UNKNOWN", "NOT_APPLICABLE"}

// canonicalPipelineClasses enumerates every class the coverage receipt must map
// to at least one row: the closed result taxonomy plus every named bullet of
// observable_rows, accepted_cases, rejected_cases and hostile_cases in RUB-922.
var canonicalPipelineClasses = []string{
	"taxonomy:ACCEPTED", "taxonomy:STORED_NONCANONICAL", "taxonomy:KNOWN_BLOCK_NOOP",
	"taxonomy:MISSING_PARENT", "taxonomy:ORPHAN_RETAINED", "taxonomy:ORPHAN_ALREADY_RETAINED",
	"taxonomy:CONSENSUS_INVALID", "taxonomy:LOCAL_BUSY", "taxonomy:LOCAL_RESOURCE_UNAVAILABLE",
	"taxonomy:STALE_LOCAL_PLAN", "taxonomy:LOCAL_CANCELLED", "taxonomy:LOCAL_STORE_ERROR", //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
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

func (r cpRow) pending(owner string) cpRow { r.PendingOwner = owner; return r }

func cpPathRows() []cpRow {
	return []cpRow{
		cpAuth("C01-PATHS-001", "Closed set of canonical-pipeline entry paths and their path-specific first-error precedence, including the exact fork choice every side path uses during branch collection.", cpMap{
			"paths":                "direct, genesis, losing_side, reorg, disconnect, miner, p2p_full, p2p_compact_probe, p2p_compact_reconstructed, p2p_relay_fallback, orphan_resolved",
			"direct_or_genesis":    "target, genesis_guard_when_applicable, strict_initial_canonical_index_preflight, mtp, validation",
			"losing_side":          "strict_index_read_during_branch_collection, fork_choice, target, mtp, basic_validation, store_block",
			"reorg":                "strict_index_read_during_branch_collection, fork_choice, initial_mtp_snapshot, per_connect_row_target, connect_block_with_sliding_mtp, advance_mtp",
			"fork_choice":          "maximum cumulative ChainWork, then lexicographically lower canonical tip-hash bytes; independent of arrival order, worker schedule, validation completion and best-ready status",
			"p2p":                  "frame_length, frame_read, frame_checksum, documented_early_parse, header_check, pow_check, try_acquire_result, lease_owned_strict_presence, stateful_target_mtp_provider_consensus",
			"compact_absent_cycle": "release_first_lease, reconstruction_or_network, reacquire_lease, repeat_strict_presence",
		}, "observable:paths", "observable:path_precedence", "observable:p2p_precedence"),
		cpObs("C01-DIRECT-001", "ACCEPTED", "NEW", "A direct child of the canonical tip commits one durable canonical index and then publishes the complete chain, standard-mempool, DA and owner image; readers see either the exact old image or the complete new one, never a partial one, and the accepted counter moves by exactly one.",
			"taxonomy:ACCEPTED", "observable:counter_deltas", "accepted:coherent_capture_publication").counters("+1", "0").
			rpc("result-selecting mined candidate: committed with identity; bootstrap: continuation-only"),
		cpObs("C01-GENESIS-001", "ACCEPTED", "NEW", "Genesis bootstrap from the exact empty pre-genesis state; the genesis guard runs after the direct target check and before the strict initial canonical-index preflight.",
			"observable:path_precedence").counters("+1", "0").rpc("bootstrap: continuation-only"),
		cpObs("C01-SIDE-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A losing side block passes target, MTP and basic validation and is stored; no canonical mutation and no counter change.",
			"taxonomy:STORED_NONCANONICAL", "observable:counter_deltas").counters("0", "0"),
		cpObs("C01-REORG-001", "ACCEPTED", "NEW", "A winning multi-block reorg is one plan: the whole transition is externally old or new and never row-wise intermediate.",
			"observable:counter_deltas", "observable:final_state_atomicity", "accepted:coherent_capture_publication").counters("+connect_count", "0").
			effects(cpMap{"final_state_fields": "tip_hash, height, cumulative_chainwork, utxo_digest, supply_digest", "summary_rows": "+connect_count", "intermediate_tip_rows": 0, "publication_events": 1, "external_visibility": "old_or_new"}),
		cpObs("C01-DISCONNECT-001", "ACCEPTED", "NEW", "An explicit standalone disconnect publishes proven NEW with an empty canonical-applied summary and zero connected-block fee-floor decay events.",
			"observable:counter_deltas").counters("0", "0").effects(cpMap{"summary_rows": "0", "connected_block_decay_events": 0}).
			detail(cpMap{"precondition": "the rolling standard fee floor is raised above the default before the disconnect (a decay event is falsifiable only then)"}),
		cpAuth("C01-NEUTRAL-001", "Results that change neither planner-owned canonical counter, carry no peer penalty and perform no unauthorized canonical mutation and do not latch mutation admission, plus the exact plan and candidate-queue bounds.", cpMap{
			"neutral_results":                    "LOCAL_BUSY, LOCAL_RESOURCE_UNAVAILABLE, STALE_LOCAL_PLAN, LOCAL_CANCELLED, KNOWN_BLOCK_NOOP, STORED_NONCANONICAL, ORPHAN_RETAINED, ORPHAN_ALREADY_RETAINED, MISSING_PARENT, LOCAL_STORE_ERROR(noncanonical), LOCAL_PERSISTENCE_ERROR(precommit)", //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
			"no_peer_penalty_results":            "every neutral result above plus TERMINAL_STORE_INTEGRITY(canonical), TERMINAL_LOCAL_INVARIANT(evidence) and TERMINAL_PERSISTENCE",
			"p2p_duplicate_counter_mutations":    0,
			"peer_penalty":                       0,
			"unauthorized_canonical_mutations":   0,
			"active_stateful_plans_max":          1,
			"queued_candidate_bytes":             0,
			"queued_candidate_objects":           0,
			"wholly_unpublished_selected_branch": "accepted +0",
		}, "observable:counter_deltas", "observable:no_penalty_bounds"),
		cpObs("C01-FIRSTERR-INDEX-001", "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", "A malformed canonical index paired with a candidate whose defect is detected only at MTP or validation (a target defect precedes the preflight per C01-PATHS-001): the strict initial canonical-index preflight owns the first error and the candidate is never validated.",
			"hostile:paired_first_errors", "observable:path_precedence", "taxonomy:TERMINAL_STORE_INTEGRITY").counters("0", "0").
			rpc("not_committed with the existing terminal result surface").effects(cpMap{"admission": "latched", "first_error_source": "strict_initial_canonical_index_preflight"}),
		cpObs("C01-FIRSTERR-LATE-001", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)", "OLD", "A late consensus-invalid candidate paired with an earlier best-effort artifact-write failure: the exact consensus error wins whenever validation can complete.",
			"hostile:late_consensus_invalid_wins", "taxonomy:CONSENSUS_INVALID", "observable:counter_deltas").counters("0", "+1").rpc("not_committed"),
		cpObs("C01-EQUALWORK-001", "ACCEPTED", "NEW", "Two equal-cumulative-work candidates delivered and validation-completed in opposite orders select the same lexicographically lower canonical tip hash in both clients.",
			"hostile:equal_work_opposite_orders").effects(cpMap{"winning_tip": "lexicographically_lower"}).
			detail(cpMap{"stable_under": "reversed delivery order, reversed validation completion, reversed worker schedule, best-ready status"}),
	}
}

func cpPresenceRows() []cpRow {
	return []cpRow{
		cpAuth("C01-PRESENCE-001", "The strict presence truth table is closed and no repair is observable.", cpMap{
			"canonical_member":     "block=valid|header=match|undo=valid => CANONICAL; every other recognized canonical combination of an artifact the active retention profile requires to be present (or already validated and retained) => TERMINAL_STORE_INTEGRITY(canonical); profile-permitted pruned suffix data => LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)",
			"noncanonical_absent":  "block=absent|header=absent|undo=absent => ABSENT",
			"noncanonical_stored":  "block=valid|header=absent|undo=absent; block=valid|header=match|undo=absent; block=valid|header=match|undo=valid",
			"noncanonical_other":   "every other recognized combination => LOCAL_STORE_ERROR(noncanonical)",
			"repair_or_truncation": false,
		}, "observable:presence_truth_table"),
		cpObs("C01-PRESENCE-TERMINAL-001", "TERMINAL_STORE_INTEGRITY(canonical)", "OLD", "A canonical member whose artifact the active retention profile requires is missing, partial, corrupt or mismatched: terminal, and mutation admission stays latched.",
			"observable:presence_truth_table", "hostile:duplicate_and_corrupt_combinations").counters("0", "0").
			effects(cpMap{"admission": "latched"}).
			detail(cpMap{"combinations": "block=absent|header=match|undo=valid; block=valid|header=absent|undo=valid; block=valid|header=mismatch|undo=valid; block=valid|header=match|undo=absent; block=valid|header=match|undo=invalid; block=corrupt|header=match|undo=valid"}),
		cpObs("C01-PRESENCE-STOREERR-001", "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE", "Every other recognized noncanonical combination is a local store error and leaves the canonical images unchanged.",
			"taxonomy:LOCAL_STORE_ERROR", "observable:presence_truth_table", "hostile:duplicate_and_corrupt_combinations").rpc("no committed mine result").
			detail(cpMap{"combinations": "block=absent|header=present|undo=absent; block=absent|header=absent|undo=present; block=valid|header=mismatch|undo=absent; block=valid|header=match|undo=invalid"}),
		cpObs("C01-GC-ORDER-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "Damaged-noncanonical GC ranks candidates by the closed ascending damage class order, then by lexicographic hash; the first matching class owns a multi-fault row and healthy rows are never candidates.",
			"observable:gc_damage_order", "hostile:quota_crash_and_reclassification").
			effects(cpMap{"expected_victim": "0x..02"}).
			detail(cpMap{
				"class_order":        "D0_INVALID_BLOCK, D1_HEADER_WITHOUT_VALID_BLOCK, D2_UNDO_WITHOUT_BLOCK_OR_HEADER, D3_INVALID_HEADER, D4_UNDO_WITHOUT_VALID_HEADER, D5_INVALID_UNDO",
				"class_predicates":   "D0_INVALID_BLOCK: block leaf exists but strict parse or hash fails; D1_HEADER_WITHOUT_VALID_BLOCK: block leaf missing or failing strict parse or hash (a valid block is absent) AND a header leaf is present on disk, regardless of the header's own validity and regardless of undo presence or validity; D2_UNDO_WITHOUT_BLOCK_OR_HEADER: no valid block, no header, undo exists; D3_INVALID_HEADER: valid block and header exists but is malformed or mismatched; D4_UNDO_WITHOUT_VALID_HEADER: valid block, header absent, undo exists; D5_INVALID_UNDO: valid block and matching header and the undo envelope, binding or exact rederived bytes are invalid",
				"candidates":         "D0+D1 at hash 0x..02, D1 at hash 0x..01, D1 at hash 0x..03, D5 at hash 0x..00",
				"tie_break":          "lexicographically lower hash inside one class (D1 0x..01 before D1 0x..03)",
				"fail_closed_leaves": "strict read failure, non-regular, unexpected leaves are never GC candidates",
			}),
		cpObs("C01-GC-HEALTHY-001", "LOCAL_RESOURCE_UNAVAILABLE(noncanonical_bytes)", "OLD", "Quota exhaustion with only healthy rows returns the non-retriable resource result after the damaged-only GC attempt; noncanonical_count behaves identically.",
			"taxonomy:LOCAL_RESOURCE_UNAVAILABLE", "observable:resource_identities", "observable:gc_damage_order").counters("0", "0").
			effects(cpMap{"retry_slots": 0, "release_notification": false, "rows_reclaimed": 0, "gc_attempted": true, "admission": "not_latched"}).
			detail(cpMap{"retriable": false}),
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
	relayDisposition := "per specification section 19; disposition frozen in C01-RELAY-STORED-001 / C01-RELAY-ACCEPTED-001 (pending_owner RUB-1195)"
	return []cpRow{
		cpObs("C01-NOOP-FULL-001", "KNOWN_BLOCK_NOOP(CANONICAL)", "NOT_APPLICABLE", "A duplicate full receive with blockSeen already set is a strict no-op: it clears only matching compact outstanding state, even though the production helper returns nil and sends no wire response.",
			"observable:known_block_noop", "taxonomy:KNOWN_BLOCK_NOOP", "hostile:duplicate_and_corrupt_combinations").counters("0", "0").
			effects(cpMap{"block_seen": "unchanged", "record_best_height": 0, "inv_attempt": 0, "da_ttl_attempt": 0, "resolver_wake": 0, "canonical_da_sets_consumed": "0", "broadcast": 0, "wire_response": 0, "peer_penalty": 0, "provider_reads": 0, "compact_outstanding_cleared": "matching_only"}).
			detail(cpMap{"derivation": "strict presence plus proven no-effect behavior"}),
		cpObs("C01-NOOP-CMPCT-001", "KNOWN_BLOCK_NOOP(STORED_NONCANONICAL)", "NOT_APPLICABLE", "A duplicate compact receive whose blockSeen is unset leaves it unset: blockSeen is relay dedup only and is neither residency nor invalidity authority.",
			"observable:known_block_noop", "observable:block_seen_inventory", "taxonomy:KNOWN_BLOCK_NOOP", "hostile:duplicate_and_corrupt_combinations").counters("0", "0").effects(cpMap{"block_seen": "unchanged", "inv_attempt": 0, "resolver_wake": 0}),
		cpObs("C01-RECLAIMED-RECEIVE-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A reclaimed row with a stale blockSeen is ABSENT under strict presence, so the receive stores it again and preserves the stale blockSeen value.",
			"observable:block_seen_inventory", "hostile:duplicate_and_corrupt_combinations").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "block_seen": "unchanged", "da_ttl_attempt": 1, "resolver_wake": 1, "canonical_da_sets_consumed": "0"}),
		cpObs("C01-EFFECT-STORED-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A fresh STORED_NONCANONICAL freezes the POST-RUB-911 P2P-owned effect order, which has no consume step; the side block consumes zero canonical-DA sets.",
			"observable:frozen_effect_order", "observable:postcommit_effects", "taxonomy:STORED_NONCANONICAL").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "block_seen": "set", "da_ttl_attempt": 1, "resolver_wake": 1, "canonical_da_sets_consumed": "0"}),
		cpObs("C01-EFFECT-ACCEPTED-001", "ACCEPTED", "NEW", "A fresh ACCEPTED freezes the same P2P-owned effect order; canonical-DA consumption is not a step of it but an identity of the transition image, consuming each exact included-matching retained COMPLETE_SET once, deduplicated by `set_identity` across the full plan, and never from a post-return caller.",
			"observable:frozen_effect_order", "taxonomy:ACCEPTED").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "block_seen": "set", "da_ttl_attempt": 1, "resolver_wake": 1, "canonical_da_sets_consumed": "+included_matching_sets", "da_ttl_fenced": true}).
			detail(cpMap{"post_return_consume_callers": "none: RUB-911 deletes every post-return consume caller; a source-level prohibition, not a value a scenario run observes"}),
		cpObs("C01-FAULT-STORED-001", "STORED_NONCANONICAL", "NOT_APPLICABLE", "A fault injected at each fallible post-store effect boundary still runs every subsequent best-effort effect and the final resolver wake exactly once, in the frozen order.",
			"hostile:postcommit_fault_boundaries").effects(cpMap{"order": frozenOrder, "record_best_height": 1, "da_ttl_attempt": 1, "resolver_wake": 1, "short_circuit": false, "replay": false, "result_changed_by_failure": false, "artifact_state_changed_by_failure": false, "peer_policy_changed_by_failure": false}).
			detail(cpMap{"fault_boundaries": "record_best_height, block_seen, block_inventory_relay, da_ttl_attempt"}),
		cpObs("C01-FAULT-ACCEPTED-001", "ACCEPTED", "NEW", "The same fault matrix on an ACCEPTED row with a nonempty canonical-applied summary: failures add bounded diagnostics only and never duplicate the planner-owned counter or re-consume a DA set.",
			"hostile:postcommit_fault_boundaries").counters("+1", "0").
			effects(cpMap{"order": frozenOrder, "record_best_height": 1, "da_ttl_attempt": 1, "resolver_wake": 1, "duplicate_counter_mutation": false, "artifact_state_changed_by_failure": false, "peer_policy_changed_by_failure": false, "short_circuit": false, "replay": false, "canonical_da_reconsumed": false}).
			detail(cpMap{"fault_boundaries": "record_best_height, block_seen, block_inventory_relay, da_ttl_attempt"}),
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
		}, "observable:frozen_effect_order", "observable:postcommit_effects").pending(pendingOwnerRUB1195),
		cpAuth("C01-RELAY-ACCEPTED-001", "The section-19 relay disposition for one authorized publication: proven NEW with a non-empty ordered canonical-applied summary.", cpMap{
			"ibd":             "sampled after the transition publication; if IBD, no attempt",
			"owner_snapshot":  "one snapshot of post-handshake send owners, deduplicated by owner identity; a captured handle is never re-resolved or retargeted",
			"frames":          "per summary row in canonical order, exactly one ordinary single-vector MSG_BLOCK inv frame per (owner x row)",
			"exclusion":       "only the invocation-local (captured source owner, exact row hash) pair; never another owner and never another row",
			"write_failure":   "stops only that owner's remaining suffix; other owners remain eligible",
			"best_effort":     "no retry and no rollback; a relay result cannot change canonical state, cleanup, commit truth or the published summary",
			"compact_modes":   "compact modes 0, 1 and 2 are additive and MUST NOT replace or suppress this ordinary block inventory",
			"orphan_apply":    "a separately accepted orphan apply uses its existing client schedule and, if it publishes an eligible new summary, is evaluated as a separate publication",
			"client_specific": "cross-peer scheduling and the client-local boundary of an immediate send-owner attempt remain client-specific (not a comparator mismatch)",
			"spec_ref":        "rubin-spec@c14b0100 RUBIN_COMPACT_BLOCKS.md section 19",
		}, "observable:frozen_effect_order", "observable:postcommit_effects").pending(pendingOwnerRUB1195),
		cpAuth("C01-INVENTORY-001", "Inventory answers from current complete BlockStore or orphan residency; a partial or corrupt row returns its local store disposition without entering a receive loop.", cpMap{
			"block_seen_role": "relay dedup only", "residency_authority": "current BlockStore/orphan", "partial_or_corrupt": "local store disposition, no receive loop",
		}, "observable:block_seen_inventory", "rejected:presence_authority_misuse"),
		cpAuth("C01-INVENTORY-RECLAIMED-001", "A reclaimed or ABSENT hash stays requestable without a GC callback or tombstone; RUB-908 exposes current strict presence only and assigns this observable to RUB-910.", cpMap{
			"requestable_after_reclaim": true, "gc_callback": false, "tombstone": false,
		}, "observable:block_seen_inventory").pending(pendingOwnerRUB910),
	}
}

func cpOrphanRows() []cpRow {
	return []cpRow{
		cpObs("C01-ORPH-RETAIN-001", "ORPHAN_RETAINED", "OLD", "One service-global orphan pool uses insert-then-evict semantics: a unique entry of at most 64 MiB with an empty source key, or a current nonempty normalized-source count below 50, is inserted and marked in blockSeen.",
			"taxonomy:ORPHAN_RETAINED", "observable:orphan_pool").effects(cpMap{"block_seen": "set", "evictions": 0}).
			detail(cpMap{"pool_scope": "one service-global pool", "entry_max_bytes": 67108864, "unique_entry_cap": 500, "aggregate_byte_cap": 67108864, "nonempty_source_cap": 50, "empty_source_key": "unmetered, admitted beyond 50"}),
		cpObs("C01-ORPH-DUP-001", "ORPHAN_ALREADY_RETAINED", "OLD", "A duplicate orphan is already-retained: no copy, no effect and no eviction.",
			"taxonomy:ORPHAN_ALREADY_RETAINED", "observable:orphan_pool").effects(cpMap{"evictions": 0, "block_seen": "unchanged"}).pending(pendingOwnerRUB910),
		cpObs("C01-ORPH-EVICT-001", "ORPHAN_RETAINED", "OLD", "Crossing 500 to 501 unique entries, or 64 MiB to cap+1 raw bytes, retains the newest row and evicts oldest FIFO rows until both caps hold; each eviction removes that row and clears its blockSeen.",
			"observable:orphan_pool", "hostile:orphan_cap_boundaries_and_source_keys").effects(cpMap{"evictions": 1, "block_seen": "set", "evicted_block_seen": "cleared", "victim": "oldest_fifo"}).
			detail(cpMap{"boundaries": "unique_count 500->501 and raw_bytes 64MiB->cap+1", "retained": "newest", "eviction_policy": "oldest FIFO first"}),
		cpObs("C01-ORPH-INFLIGHT-001", "ORPHAN_RETAINED", "OLD", "Eviction is unconditional and there is no pin set: a row under resolution has already been removed from the pool before the resolver sees it, so no in-pool row is pin-protected and no cap infeasibility can arise.",
			"hostile:orphan_admission_eviction_refusal", "observable:orphan_pool").
			effects(cpMap{"resolving_row_in_pool": false}).detail(cpMap{"pin_set": false, "pre_insertion_feasibility_proof": false}),
		cpObs("C01-ORPH-OVERSIZE-001", "LOCAL_RESOURCE_UNAVAILABLE(orphan_pool)", "OLD", "A single entry larger than 64 MiB is a non-retriable orphan_pool refusal: no insertion, no eviction, and blockSeen unchanged in both the initially unset and the stale-set case.",
			"hostile:orphan_admission_eviction_refusal").effects(cpMap{"evictions": 0, "block_seen": "unchanged", "retry_slots": 0, "pool_bytes_delta": 0, "fifo_delta": 0, "source_count_delta": 0, "admission": "not_latched"}).
			detail(cpMap{"retriable": false, "initial_unset_stays": "unset", "stale_set_stays": "set"}).pending(pendingOwnerRUB910),
		cpObs("C01-ORPH-SOURCE51-001", "LOCAL_RESOURCE_UNAVAILABLE(orphan_pool)", "OLD", "Entry 51 for one nonempty normalized source is a non-retriable refusal with the entire prior pool, FIFO, source counts and blockSeen byte-for-byte unchanged.",
			"hostile:orphan_admission_eviction_refusal", "hostile:orphan_cap_boundaries_and_source_keys").
			effects(cpMap{"evictions": 0, "block_seen": "unchanged", "retry_slots": 0, "source_count_delta": 0, "fifo_delta": 0, "pool_bytes_delta": 0, "admission": "not_latched"}).
			detail(cpMap{"retriable": false}).pending(pendingOwnerRUB910),
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
		cpAuth("C01-RES-IDENTITIES-001", "The resource identities are exact and closed across this row and C01-RES-IDENTITIES-PENDING-001; this row carries the owned identities. Every resource identity is LOCAL_RESOURCE_UNAVAILABLE and never consensus invalidity, and invalid configured bounds are startup or config failures outside peer retry.", cpMap{
			"identities":                "noncanonical_bytes, noncanonical_count, orphan_pool, recovery_artifact, apply_plan_metadata",
			"recovery_artifact":         "non-retriable; profile-permitted pruned suffix awaiting validated reacquisition; distinct from bounded-storage reservation failure",
			"admission":                 "never latched for any resource identity; preserves OLD",
			"invalid_configured_bounds": "startup/config failure, outside peer retry",
		}, "observable:resource_identities"),
		cpObs("C01-RES-RECOVERY-001", "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)", "OLD", "Profile-permitted pruned suffix data awaiting validated reacquisition is non-retriable, preserves OLD, does not latch admission and arms no peer retry; it is distinct from bounded-storage reservation failure and from loss of an artifact the active retention profile already required.",
			"observable:resource_identities", "taxonomy:LOCAL_RESOURCE_UNAVAILABLE").counters("0", "0").effects(cpMap{"retry_slots": 0, "peer_penalty": 0, "admission": "not_latched"}),
		cpAuth("C01-RES-IDENTITIES-PENDING-001", "The resource identities whose machinery no slice of this chain delivers; RUB-893 is the delivering owner (provenance marker — an authority row is never compared; the gate-bearing exclusions live on the observation rows C01-BUDGET-RACE-001 / C01-WIRE-OVERFLOW-001).", cpMap{
			"identities": "inbound_budget_capacity, inbound_budget_overflow",
			"retriable":  "inbound_budget_capacity only, and only with an independently proven exact block hash",
		}, "observable:resource_identities").pending(pendingOwnerRUB893),
		cpObs("C01-APPLYMETA-CAP-001", "ACCEPTED", "NEW", "An apply plan whose checked metadata charge lands exactly on the 64 MiB cap succeeds.",
			"hostile:apply_plan_metadata_caps").counters("+connect_count", "0").
			detail(cpMap{"charge_formula": "48+40*(disconnect_rows+connect_rows)+32*complete_da_ids", "cap_bytes": 67108864, "charge_bytes": "exactly cap"}),
		cpObs("C01-APPLYMETA-OVER-001", "LOCAL_RESOURCE_UNAVAILABLE(apply_plan_metadata)", "OLD", "The smallest realizable charge above the cap (cap+8 under the frozen 8-byte-granular formula 48+40*rows+32*complete_da_ids) is non-retriable and preserves canonical, store, mempool, counter and effect state completely; it creates no peer penalty, no retry slot and no release notification.",
			"hostile:apply_plan_metadata_caps").counters("0", "0").
			effects(cpMap{"peer_penalty": 0, "retry_slots": 0, "getdata_sent": 0, "record_best_height": 0, "block_seen": "unchanged", "release_notification": false, "admission": "not_latched"}).
			detail(cpMap{"retriable": false, "overflow_charge": "cap+8 = 67108872 (every charge is a multiple of 8; cap+1 is unreachable)"}),
		cpObs("C01-BUSY-001", "LOCAL_BUSY", "OLD", "LOCAL_BUSY carries the canonical-permit observed-generation notification and arms the single peer retry slot with one joined waiter; it retains no candidate, never blocks the socket reader and never follows strict presence or stateful consensus. A duplicate or different hash while the slot is armed and disconnect or deadline races resolve deterministically, and non-retriable resource classes arm no slot and send no getdata.",
			"taxonomy:LOCAL_BUSY", "observable:permit_retry_budget", "hostile:permit_budget_races").counters("0", "0").effects(cpMap{"retry_slots": 1, "peer_penalty": 0, "joined_waiters_max": 1, "fixed_backoff": false, "candidate_retained": false, "observed_generation_notification": true}).
			detail(cpMap{"deadline": "original receive-start +30 second absolute deadline", "non_retriable_classes_arm_no_slot_and_no_getdata": "inbound_budget_overflow, apply_plan_metadata, noncanonical_bytes, noncanonical_count, orphan_pool, recovery_artifact"}).pending(pendingOwnerRUB910),
		cpObs("C01-BUDGET-RACE-001", "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_capacity)", "OLD", "Inbound-budget registration-versus-release races, an already-closed notification and capacity released before the waiter is scheduled all resolve deterministically; the retriable result carries the inbound-budget observed-generation notification and requires an independently proven exact block hash.",
			"hostile:permit_budget_races", "observable:permit_retry_budget").effects(cpMap{"peer_penalty": 0, "observed_generation_notification": true, "admission": "not_latched"}).
			detail(cpMap{"retriable": true, "requires_proven_exact_hash": true}).pending(pendingOwnerRUB893),
		cpObs("C01-WIRE-OVERFLOW-001", "LOCAL_RESOURCE_UNAVAILABLE(inbound_budget_overflow)", "OLD", "A checked inbound reservation overflow or replacement failure is non-retriable; a valid payload discarded because of a bad checksum, read or declared length keeps the documented wire-error precedence and never becomes a resource result.",
			"hostile:inbound_reservation_and_wire_errors").effects(cpMap{"retry_slots": 0, "getdata_sent": 0, "admission": "not_latched"}).
			detail(cpMap{"retriable": false, "wire_error_precedence": "frame_length, frame_read, frame_checksum"}).pending(pendingOwnerRUB893),
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
			effects(cpMap{"admission": "not_latched", "retry_slots": 0, "published_image": "old"}).
			detail(cpMap{"triggers": "canonical-index atomic write before the namespace change; durable write of the verified precommit recovery checkpoint or either suffix proof set"}),
		cpObs("C01-TP-OLD-001", "TERMINAL_PERSISTENCE(old)", "OLD", "One strict readback after a fault that may have crossed the commit point sees the exact old canonical-index identity; no rollback, retry, rewrite or heuristic classification follows.",
			"taxonomy:TERMINAL_PERSISTENCE", "accepted:post_namespace_terminal_class").counters("0", "0").
			rpc("not_committed, never ordinary retry").effects(cpMap{"admission": "latched", "rollback_attempted": false, "published_image": "old"}),
		cpObs("C01-TP-NEW-001", "TERMINAL_PERSISTENCE(new)", "NEW", "The strict readback sees the exact planned-new identity: the new chain, standard, DA and owner images are truth and the committed identity is reported.",
			"accepted:post_namespace_terminal_class", "taxonomy:TERMINAL_PERSISTENCE").effects(cpMap{"admission": "latched", "published_image": "new"}).
			rpc("committed; mined candidate identity only when the result-selecting mined candidate apply committed"),
		cpObs("C01-TP-UNKNOWN-001", "TERMINAL_PERSISTENCE(neither_or_unreadable)", "UNKNOWN", "Every other or unreadable readback publishes neither guessed image and exposes no summary and no relay authority.",
			"accepted:post_namespace_terminal_class", "hostile:canonical_ambiguity_and_readers", "taxonomy:TERMINAL_PERSISTENCE").counters("0", "0").
			rpc("unknown; legacy mined absent").effects(cpMap{"admission": "latched", "guessed_image": false, "published_image": "withheld", "relay_authority": false, "summary_rows": "0"}).
			detail(cpMap{"stable_live_aliases": "a malformed live cache against a valid disk image, a retained-alias mutation under a continuously held permit, and admission readers active at terminal detection all keep stable aliases", "final_ram_cache_drift_check": "against the committed index bytes"}),
		cpObs("C01-TERMINV-001", "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", "A missing or corrupt selected retained record or accounting value, an exact-token mismatch, a duplicate claim, or a checked arithmetic underflow or overflow preserves OLD, publishes no candidate delta and keeps mutation admission latched.",
			"taxonomy:TERMINAL_LOCAL_INVARIANT").counters("0", "0").rpc("not_committed with the existing terminal result surface").
			effects(cpMap{"admission": "latched"}).
			detail(cpMap{"triggers": "missing or corrupt selected retained record, missing or corrupt accounting value, exact-token mismatch, duplicate claim, checked arithmetic underflow or overflow", "never_reclassified_as": "LOCAL_RESOURCE_UNAVAILABLE(resource), which preserves OLD and does not latch, or STALE_LOCAL_PLAN"}),
		cpObs("C01-TERMINV-BOOT-001", "TERMINAL_LOCAL_INVARIANT(evidence)", "OLD", "At the bootstrap boundary a STORED_NONCANONICAL result, or a KNOWN_BLOCK_NOOP(STORED_NONCANONICAL), is a terminal local invariant that publishes no candidate delta and keeps mutation admission latched; bootstrap ACCEPTED and KNOWN_BLOCK_NOOP(CANONICAL) remain continuation-only.",
			"taxonomy:TERMINAL_LOCAL_INVARIANT").counters("0", "0").rpc("not_committed with the existing terminal result surface").
			effects(cpMap{"admission": "latched"}),
		cpObs("C01-STALE-001", "STALE_LOCAL_PLAN", "OLD", "At the result-selecting mined candidate boundary, STORED_NONCANONICAL and either KNOWN_BLOCK_NOOP variant map to STALE_LOCAL_PLAN and the exact old image is preserved.",
			"taxonomy:STALE_LOCAL_PLAN").counters("0", "0").rpc("not_committed"),
		cpObs("C01-CANCEL-001", "LOCAL_CANCELLED", "OLD", "A miner snapshot cancelled or released before PoW at the reorg peak returns LOCAL_CANCELLED with the exact old image, no canonical mutation and no peer effect.", //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
			"taxonomy:LOCAL_CANCELLED", "hostile:miner_reorg_peak_cancellation").counters("0", "0").rpc("not_committed"), //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
		cpAuth("C01-CKPT-001", "The derived post-commit checkpoint is not canonical authority: an accepted transition may report degraded, a subsequent success clears it, startup is fail-closed, and a multi-row cadence writes only the final state once.", cpMap{
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
// closed taxonomy, an unknown commit-truth value, or a coverage class unknown or repeated
// in one row; per-kind payload shapes are schema-owned (see mustValidateCanonicalPipelineKind).
func mustValidateCanonicalPipelineRows(rows []cpRow) {
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
		mustValidateCanonicalPipelineKind(row, truths)
		if len(row.Covers) == 0 {
			fatalf("canonical pipeline: row %s covers no enumerated class", row.ID)
		}
		covered := make(map[string]bool, len(row.Covers))
		for _, class := range row.Covers {
			if !classes[class] {
				fatalf("canonical pipeline: row %s covers unknown class %q", row.ID, class)
			}
			if covered[class] {
				fatalf("canonical pipeline: row %s covers class %q twice", row.ID, class)
			}
			covered[class] = true
		}
	}
}

// mustValidateCanonicalPipelineKind mirrors, in the generator, the two
// schema constraints — closed-taxonomy via result.pattern and commit-truth
// via commit_truth.enum — so generation fails closed before the artifact
// is written; both layers are deliberate. Row shapes stay schema-owned
// (required fields per kind), asserted by test_check_conformance_fixtures_drift.py.
func mustValidateCanonicalPipelineKind(row cpRow, truths map[string]bool) {
	switch row.Kind {
	case "observation":
		if !canonicalPipelineResultRE.MatchString(row.Result) {
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
	mustWriteJSON(path, &artifact)
}

// ---------------------------------------------------------------------------
// RUB-1207 / C01-R2 — dormant BUILDING successor of the v1 pair.
//
// This revision carries IDENTITY and SHAPE only: the closure epoch that binds
// it, the frozen 79-entry row registry, the closed token domains, and the
// validators RUB-1208..RUB-1212 land their migrated rows against. `rows` is
// empty by contract; the byte-frozen v1 pair stays the inert authority until
// RUB-1204 activates v2. No expected value is computed by calling a Go or Rust
// node production path, and no row carries `pending_owner` or `detail`.
// ---------------------------------------------------------------------------

const (
	cp2ArtifactName   = "canonical_pipeline_v2"
	cp2SchemaRel      = "conformance/schemas/cv-canonical-pipeline-v2.json"
	cp2SchemaVer      = 2
	cp2CorpusRev      = "C01-R2"
	cp2RegistrySize   = 79 // 62 inherited R1 identities + 17 closure-authorized R2 rows
	cp2RPCUnavailable = "RPC_UNAVAILABLE"

	// Closure epoch: the RUB-1206 design-closure manifest identity this
	// revision is bound to (snapshot rub1206-closure-snapshot.tar.gz, verified
	// at claim). Every value below is mirrored as a schema `const`, so a drift
	// on either side fails generation or validation rather than shipping a
	// revision bound to a manifest nobody closed.
	cp2ClosureManifestVersion       = "rubin-c01-design-closure-v8"
	cp2ManifestRootSHA256           = "e9b4bbfa09b4cf939973b229b59105f8996282b6fc2ffaa094362e76948bbc89"
	cp2ObligationSetHash            = "4af7520a185bfa732ece69f5a6c12f4d012917b9c6fd1d8f42b98195284f59b0"
	cp2RowCaseDesignHash            = "8b70ba6d504a7e7ed92bf7bd0b769cb9eeb48356bdf356247520916629cc1216"
	cp2StageOwnerRelationHash       = "4513e667a03dabca78e7369e989676ea5ab3d75d59a817493d84fe968b3a8518"
	cp2MutationAssignmentHash       = "94f846a9b454e019a2b1c7b833c75862151d1e66f91216e107b2478d0f0cb4a5"
	cp2ImageManifestHash            = "08fbabf558f3df10e89bd6160804db8efc814378140ae4514717952c7d913116"
	cp2SummaryManifestHash          = "39e39d94593d434e7051a3f77ca94d3dd31a5a8d65a3f12a764e29a5fde041dd"
	cp2RelationSnapshotHash         = "3e7db40fa6917b5a7d61ab113a74f7107f8f166080393e1c9789dbd927b24edb"
	cp2InputSchemaDesignHash        = "468b2b5401e12915b9bcdd76cb2714eda837fcd9401324ac7677770bb7069f57"
	cp2ExpectedProjectionDesignHash = "b1e539c3cb7155c5821b5788c4de9aea40cf706fb9faf4c44af7e4ae21586d8c"
	cp2R1208PayloadSHA256           = "23691c8bd96cf75797b6b884175824dbd03a80e183a55d6a4c617cf9f5ded50c"
	cp2ClosureStatus                = "building"

	// Byte-frozen R1 parent identity. RUB-1204 activates v2 and deletes the
	// parent in one PR; until then v1 is reachable by these pins only.
	cp2ParentSourceOID   = "1e24b0249dab04b21de492ad307b6a47c63f12b5"
	cp2ParentMergeOID    = "3b1e45590b18994b4ce5f6e3ec2d9dc6b416e880"
	cp2ParentArtifactSHA = "68a1f551333ca17b93ebe3e6d737658cc661e40b40a3b41dbe27b37b74537246"
	cp2ParentSchemaSHA   = "c962f5434d373ac5268527cc82ef8eb68fd45ddac50c849da32b3f8ef87cdca7"
	cp2GoverningSpecOID  = "c14b010024ce633e1027bf891af3c49741db544a"
)

const cp2R1208PayloadGzipBase64 = `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`

// cp2RPCClasses is the closed RPC projection class enum (RUB-1206 DD-009). The
// class is authored, not computed: one (phase, http, commit_state, mined) tuple
// maps to two classes in the bound design, so the tuple does not determine it.
var cp2RPCClasses = []string{
	"NOT_REACHED", "STARTUP_UNAVAILABLE_503", "BOOTSTRAP_CONTINUATION_ONLY",
	"BOOTSTRAP_TERMINAL_INVARIANT_503", "BOOTSTRAP_TERMINAL_NEW_503_COMMITTED",
	"MINED_200_COMMITTED", "MINED_422_NOT_COMMITTED", "MINED_503_NOT_COMMITTED",
	"MINED_503_COMMITTED_TERMINAL_NEW", "MINED_503_UNKNOWN",
}

// cp2WireDispositionValues (DD-001) and cp2RecoveryOutcomeValues (DD-002) are
// the closed dispositions of cases that terminate before a consensus
// classification, where `result` is null: the P2P frame/message layer and the
// startup/recovery boundary respectively.
var (
	cp2WireDispositionValues = []string{"CHECKSUM_REJECT", "CMPCT_DECODE_REJECT", "EXACT_HASH_MISMATCH", "FRAME_LENGTH_REJECT", "FRAME_READ_ERROR"}
	cp2RecoveryOutcomeValues = []string{"bootstrap_only_pregenesis", "fail_closed_no_exposure", "identity_proven_route1"}

	cp2MinedValues           = []string{"true", "false", "absent", "not_applicable"}
	cp2SuccessIdentityValues = []string{"present", "absent", "not_applicable"}
	cp2CommitStateValues     = []string{"committed", "not_committed", "unknown"}
	cp2PhaseValues           = []string{"result_selecting_mined_candidate", "continuation_only_bootstrap", "startup", "not_reached"}
	cp2HTTPValues            = []int{200, 422, 503}
)

// cp2ClassTuple pins each derived RPC class to its exact
// (phase, http, commit_state, mined, success_identity, error_class-present)
// tuple, mirroring the schema's per-class arms. "" is JSON null. NOT_REACHED is
// deliberately absent: it is the one open class and the schema pins its bounds.
var cp2ClassTuple = map[string][6]string{
	"BOOTSTRAP_CONTINUATION_ONLY":          {"continuation_only_bootstrap", "", "", "not_applicable", "not_applicable", "no"},
	"BOOTSTRAP_TERMINAL_INVARIANT_503":     {"continuation_only_bootstrap", "503", "not_committed", "false", "absent", "yes"},
	"BOOTSTRAP_TERMINAL_NEW_503_COMMITTED": {"continuation_only_bootstrap", "503", "committed", "false", "absent", "yes"},
	"MINED_200_COMMITTED":                  {"result_selecting_mined_candidate", "200", "committed", "true", "present", "no"},
	"MINED_422_NOT_COMMITTED":              {"result_selecting_mined_candidate", "422", "not_committed", "false", "absent", "yes"},
	"MINED_503_COMMITTED_TERMINAL_NEW":     {"result_selecting_mined_candidate", "503", "committed", "true", "present", "yes"},
	"MINED_503_NOT_COMMITTED":              {"result_selecting_mined_candidate", "503", "not_committed", "false", "absent", "yes"},
	"MINED_503_UNKNOWN":                    {"result_selecting_mined_candidate", "503", "unknown", "absent", "absent", "yes"},
	"STARTUP_UNAVAILABLE_503":              {"startup", "503", "", "absent", "not_applicable", "yes"},
}

// cp2InputTypes and cp2Provenances mirror the schema's closed stimulus vocabulary.
var (
	cp2InputTypes  = []string{"alias", "array<alias>", "array<bool>", "array<bytes32_hex>", "array<object>", "array<token>", "array<u64>", "bool", "bytes", "bytes32_hex", "object", "token", "u16", "u64"}
	cp2Provenances = []string{"normative_boundary", "witness_fixture", "deterministic_schedule_control", "configured_bound"}
)

var (
	cp2UpperTokenRE          = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`) // one grammar for a case id and a fixtures alias
	cp2TokenRE               = regexp.MustCompile(`^[A-Za-z0-9_@/:()|+.-]+$`)
	cp2BytesRE, cp2HexRE     = regexp.MustCompile(`^([0-9a-f]{2})*$`), regexp.MustCompile(`^[0-9a-f]{64}$`)
	cp2SnakeRE               = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	cp2PointerRE, cp2IssueRE = regexp.MustCompile(`^/input/[a-z][a-z0-9_]*$`), regexp.MustCompile(`^RUB-[1-9][0-9]*$`)
)

// cp2LiteralOf maps an element tag to its literal predicate, mirroring the
// schema's per-tag arms. `object` is absent on purpose: a structured stimulus is
// an alias, and a structured fixture's grammar is schema-owned (closedObject).
// ponytail: only a float64 input loses precision above 2^53 (uint64 and
// json.Number are exact to MaxUint64); decode JSON with UseNumber to keep u64.
var cp2LiteralOf = map[string]func(any) bool{
	"bool": func(v any) bool { _, ok := v.(bool); return ok },
	"u16":  func(v any) bool { return cp2UintOK(v, 65535) }, "u64": func(v any) bool { return cp2UintOK(v, math.MaxUint64) },
	"token": func(v any) bool { return cp2MatchOK(v, cp2TokenRE) }, "bytes": func(v any) bool { return cp2MatchOK(v, cp2BytesRE) },
	"bytes32_hex": func(v any) bool { return cp2MatchOK(v, cp2HexRE) },
}

// cp2RetiredKeys are the v1 field names the v2 shape retires: they may not
// reappear as a key inside any open map either.
var cp2RetiredKeys = []string{"pending_owner", "detail", "scenario"}

// cp2FixtureTypes is cp2InputTypes minus the alias tags: an entry is a literal.
var cp2FixtureTypes = slices.DeleteFunc(slices.Clone(cp2InputTypes), func(t string) bool { return strings.Contains(t, "alias") })

func cp2MatchOK(v any, re *regexp.Regexp) bool { s, ok := v.(string); return ok && re.MatchString(s) }

// cp2JSONImage returns a value as it will appear in the artifact. The round trip
// collapses every Go shape ([]string, []bool, []uint64, a struct, cpMap) to the
// JSON kinds map[string]any / []any / json.Number / string / bool / nil, so one
// predicate set covers them all and no Go-only shape can slip past. A value that
// cannot marshal returns a sentinel no predicate accepts.
func cp2JSONImage(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return struct{}{}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var image any
	if err := decoder.Decode(&image); err != nil {
		return struct{}{}
	}
	return image
}

// cp2UintOf reads an unsigned integer EXACTLY from a JSON image: json.Number is
// parsed without a float round trip, so 2^64-1 survives. float64 is kept for a
// direct caller and accepted only when integral, non-negative and below 2^64
// (math.MaxUint64 rounds UP to 2^64 as a float64).
func cp2UintOf(v any) (uint64, bool) {
	if n, ok := v.(json.Number); ok {
		u, err := strconv.ParseUint(n.String(), 10, 64)
		return u, err == nil
	}
	f, ok := v.(float64)
	if !ok || f < 0 || f != math.Trunc(f) || f >= math.Exp2(64) {
		return 0, false
	}
	return uint64(f), true
}

func cp2UintOK(v any, max uint64) bool {
	u, ok := cp2UintOf(v)
	return ok && u <= max
}

// cp2ClosedObjectOK mirrors the schema's closedObject: non-empty, snake_case
// keys, closed values. cpMap is an alias of map[string]any, so both shapes hit
// the same assertion.
func cp2ClosedObjectOK(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return false
	}
	for key, value := range m {
		if !cp2SnakeRE.MatchString(key) || slices.Contains(cp2RetiredKeys, key) || !cp2ClosedValueOK(value) {
			return false
		}
	}
	return true
}

// cp2ClosedValueOK mirrors closedValue: bool, integral number, machine token,
// array of those, or a nested closed object.
func cp2ClosedValueOK(v any) bool {
	switch t := v.(type) {
	case bool:
		return true
	case string:
		return cp2TokenRE.MatchString(t)
	case []any:
		return !slices.ContainsFunc(t, func(e any) bool { return !cp2ClosedValueOK(e) })
	case map[string]any:
		return cp2ClosedObjectOK(t)
	}
	_, ok := cp2UintOf(v)
	return ok
}

// cp2ValueOK mirrors the schema over a JSON image: every tag admits its literal form or an alias
// (aliasOK), an array tag admits an array of those, and a tag with no literal
// predicate is alias-only.
func cp2ValueOK(tag string, v any, aliasOK bool) bool {
	elem, isArray := strings.CutPrefix(tag, "array<")
	if !isArray {
		return cp2ElemOK(elem, v, aliasOK)
	}
	items, ok := v.([]any)
	if !ok {
		return false
	}
	elem = strings.TrimSuffix(elem, ">")
	for _, item := range items {
		if !cp2ElemOK(elem, item, aliasOK) {
			return false
		}
	}
	return true
}

func cp2ElemOK(elem string, v any, aliasOK bool) bool {
	if aliasOK && cp2MatchOK(v, cp2UpperTokenRE) {
		return true
	}
	lit, ok := cp2LiteralOf[elem]
	return ok && lit(v)
}

// cp2Blank reports whether s carries no visible character: whitespace, a BOM or
// a zero-width mark does not make a production setup sink real.
func cp2Blank(s string) bool {
	return strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == '\uFEFF' || (r >= '\u200B' && r <= '\u200D') || r == '\u2060'
	}) == ""
}

// cp2InputOK mirrors every schema constraint on one stimulus pointer.
func cp2InputOK(in cp2Input) error {
	if !cp2PointerRE.MatchString(in.Pointer) {
		return fmt.Errorf("input pointer %q is malformed", in.Pointer)
	}
	if !cp2IssueRE.MatchString(in.ConsumptionProofOwner) {
		return fmt.Errorf("input %s has a malformed consumption owner %q", in.Pointer, in.ConsumptionProofOwner)
	}
	if cp2Blank(in.ProductionSetupSink) {
		return fmt.Errorf("input %s has a blank production setup sink", in.Pointer)
	}
	if !cp2ValueOK(in.Type, cp2JSONImage(in.ValueOrAlias), true) {
		return fmt.Errorf("input %s value is not a %s literal or alias", in.Pointer, in.Type)
	}
	return nil
}

// cp2FixtureValueOK routes a structured entry to the closed-object grammar and
// every other entry to its literal predicate.
func cp2FixtureValueOK(f cp2Fixture) bool {
	value := cp2JSONImage(f.Value)
	switch f.Type {
	case "object":
		return cp2ClosedObjectOK(value)
	case "array<object>":
		items, ok := value.([]any)
		return ok && !slices.ContainsFunc(items, func(e any) bool { return !cp2ClosedObjectOK(e) })
	}
	return cp2ValueOK(f.Type, value, false)
}

// cp2ValidateFixtures closes the catalog: an alias key, a literal type, and a
// value of that type.
func cp2ValidateFixtures(fixtures map[string]cp2Fixture) error {
	for _, alias := range slices.Sorted(maps.Keys(fixtures)) {
		f := fixtures[alias]
		if !cp2UpperTokenRE.MatchString(alias) || !slices.Contains(cp2FixtureTypes, f.Type) {
			return fmt.Errorf("fixtures: entry %q has a non-alias key or a non-literal type %q", alias, f.Type)
		}
		if !cp2FixtureValueOK(f) {
			return fmt.Errorf("fixtures: entry %q value is not a %s literal", alias, f.Type)
		}
	}
	return nil
}

// cp2NewRows are the 17 R2 rows the closure epoch authorizes on top of the 62
// inherited identities, which are derived from canonicalPipelineRows() rather
// than restated: a rename, removal or kind change on the R1 side therefore
// fails the registry pin instead of silently forking the identity map.
var cp2NewRows = map[string]string{
	"C01-CKPT-CASES-001":      "observation",
	"C01-DACLEAN-001":         "observation",
	"C01-GC-CRASH-CASES-001":  "observation",
	"C01-INVENTORY-CASES-001": "observation",
	"C01-PATH-COMPACT-001":    "observation",
	"C01-PATH-FALLBACK-001":   "observation",
	"C01-PATH-FULL-001":       "observation",
	"C01-PRESENCE-STORED-001": "observation",
	"C01-PROVIDER-CASES-001":  "observation",
	"C01-RECOVERY-001":        "observation",
	"C01-RELAY-OBS-001":       "observation",
	"C01-REORGMETA-CASES-001": "observation",
	"C01-RESOLVER-001":        "observation",
	"C01-RPC-PHASE-001":       "observation",
	"C01-SRCKEY-CASES-001":    "observation",
	"C01-SUMMARY-001":         "observation",
	"C01-TTLFENCE-001":        "observation",
}

// cp2RPC is the typed RPC projection (DD-009). A nil pointer is JSON `null`:
// legal for http, commit_state and error_class only.
type cp2RPC struct {
	Class           string  `json:"class"`
	HTTP            *int    `json:"http"`
	CommitState     *string `json:"commit_state"`
	Mined           string  `json:"mined"`
	SuccessIdentity string  `json:"success_identity"`
	ErrorClass      *string `json:"error_class"`
	Phase           string  `json:"phase"`
}

// cp2Expected carries the generator-validated projection of a case's expected
// output. The complete expected/input shape is owned by the v2 schema; the
// fields below are the ones the generator itself decides, so RUB-1208..1212
// extend this struct as they migrate the remaining projections.
type cp2Expected struct {
	Result          *string `json:"result"`
	CommitTruth     string  `json:"commit_truth"`
	PipelineReached *bool   `json:"pipeline_reached,omitempty"`
	WireDisposition *string `json:"wire_disposition,omitempty"`
	RecoveryOutcome *string `json:"recovery_outcome,omitempty"`
	RPC             cp2RPC  `json:"rpc_projection"`
}

// cp2Fixture is one catalog entry: a typed literal, never an alias to an alias.
type cp2Fixture struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// cp2Input is one typed stimulus pointer; the json tags mirror the schema.
type cp2Input struct {
	Pointer               string `json:"pointer"`
	Type                  string `json:"type"`
	ValueOrAlias          any    `json:"value_or_alias"`
	Provenance            string `json:"provenance"`
	ProductionSetupSink   string `json:"production_setup_sink"`
	ConsumptionProofOwner string `json:"consumption_proof_owner"`
}

type cp2Case struct {
	CaseID     string      `json:"case_id"`
	ScheduleID *string     `json:"schedule_id"`
	Input      []cp2Input  `json:"input,omitempty"`
	Expected   cp2Expected `json:"expected"`
}

type cp2Row struct {
	RowID string    `json:"row_id"`
	Kind  string    `json:"kind"`
	Cases []cp2Case `json:"cases,omitempty"`
}

type cp2Artifact struct {
	Artifact              string                `json:"artifact"`
	SchemaVersion         int                   `json:"schema_version"`
	Schema                string                `json:"schema"`
	Meta                  cpMap                 `json:"_meta"`
	Authority             cpMap                 `json:"authority"`
	ResultTaxonomy        []string              `json:"result_taxonomy"`
	CommitTruthValues     []string              `json:"commit_truth_values"`
	RPCProjectionClasses  []string              `json:"rpc_projection_classes"`
	WireDispositionValues []string              `json:"wire_disposition_values"`
	RecoveryOutcomeValues []string              `json:"recovery_outcome_values"`
	RowRegistry           map[string]string     `json:"row_registry"`
	Fixtures              map[string]cp2Fixture `json:"fixtures"`
	Rows                  []cp2Row              `json:"rows"`
}

// cp2RowRegistry is the frozen C01-R2 identity map (row_id -> kind): the 62
// identities inherited from the v1 corpus plus the 17 rows the closure epoch
// authorizes. Migration status is DERIVED, never stored: a row is migrated
// exactly when its id appears in `rows`.
func cp2RowRegistry() map[string]string {
	registry := make(map[string]string, cp2RegistrySize)
	for _, row := range canonicalPipelineRows() {
		registry[row.ID] = row.Kind
	}
	maps.Copy(registry, cp2NewRows)
	return registry
}

// cp2CommitTruthFor is the exact result -> commit truth relation of spec 6.4.1
// (rubin-spec@c14b0100 RUBIN_MEMPOOL_POLICY.md L436-L446). It is total on the
// closed taxonomy: an unmapped result is a corpus defect, never a default.
func cp2CommitTruthFor(result string) (string, bool) {
	if !canonicalPipelineResultRE.MatchString(result) {
		return "", false // the relation is defined only on the closed taxonomy
	}
	switch result {
	case "TERMINAL_PERSISTENCE(new)":
		return "NEW", true
	case "TERMINAL_PERSISTENCE(neither_or_unreadable)":
		return "UNKNOWN", true
	}
	head, _, _ := strings.Cut(result, "(")
	switch head {
	case "ACCEPTED":
		return "NEW", true
	case "STORED_NONCANONICAL", "KNOWN_BLOCK_NOOP", "LOCAL_STORE_ERROR":
		return "NOT_APPLICABLE", true
	case "MISSING_PARENT", "ORPHAN_RETAINED", "ORPHAN_ALREADY_RETAINED", "CONSENSUS_INVALID",
		"LOCAL_BUSY", "LOCAL_RESOURCE_UNAVAILABLE", "STALE_LOCAL_PLAN", "LOCAL_CANCELLED", //nolint:misspell // LOCAL_CANCELLED is the normative specification token spelling
		"LOCAL_PERSISTENCE_ERROR", "TERMINAL_STORE_INTEGRITY", "TERMINAL_LOCAL_INVARIANT",
		"TERMINAL_PERSISTENCE": // TERMINAL_PERSISTENCE(old); the other two arms are handled above
		return "OLD", true
	}
	return "", false
}

// cp2ValidateRPC is the typed RPC structural/domain validator: every field is a
// closed token domain, and error_class is a taxonomy token or RPC_UNAVAILABLE.
func cp2ValidateRPC(where string, r cp2RPC) error {
	for _, c := range []struct {
		field, value string
		allowed      []string
	}{
		{"class", r.Class, cp2RPCClasses},
		{"mined", r.Mined, cp2MinedValues},
		{"success_identity", r.SuccessIdentity, cp2SuccessIdentityValues},
		{"phase", r.Phase, cp2PhaseValues},
	} {
		if !slices.Contains(c.allowed, c.value) {
			return fmt.Errorf("case %s: rpc_projection.%s %q is outside its closed domain", where, c.field, c.value)
		}
	}
	if err := cp2ValidateRPCNullable(where, r); err != nil {
		return err
	}
	return cp2ValidateRPCClass(where, r)
}

// cp2ValidateRPCClass pins the derived class to its exact field tuple.
func cp2ValidateRPCClass(where string, r cp2RPC) error {
	want, pinned := cp2ClassTuple[r.Class]
	if !pinned { // NOT_REACHED: the one open class, bounded rather than pinned
		reached := r.HTTP != nil || r.Mined != "not_applicable" || r.SuccessIdentity != "not_applicable"
		if reached || !slices.Contains([]string{"not_reached", "continuation_only_bootstrap", "startup"}, r.Phase) || (r.CommitState != nil && *r.CommitState == "unknown") {
			return fmt.Errorf("case %s: rpc_projection class %s exceeds its bounds", where, r.Class)
		}
		return nil
	}
	http, commit, errClass := "", "", "no"
	if r.HTTP != nil {
		http = strconv.Itoa(*r.HTTP)
	}
	if r.CommitState != nil {
		commit = *r.CommitState
	}
	if r.ErrorClass != nil {
		errClass = "yes"
	}
	if got := [6]string{r.Phase, http, commit, r.Mined, r.SuccessIdentity, errClass}; got != want {
		return fmt.Errorf("case %s: rpc_projection class %s requires %v, got %v", where, r.Class, want, got)
	}
	return nil
}

// cp2ValidateRPCNullable covers the three fields a case may report as JSON null.
func cp2ValidateRPCNullable(where string, r cp2RPC) error {
	if r.CommitState != nil && !slices.Contains(cp2CommitStateValues, *r.CommitState) {
		return fmt.Errorf("case %s: rpc_projection.commit_state %q is outside its closed domain", where, *r.CommitState)
	}
	if r.HTTP != nil && !slices.Contains(cp2HTTPValues, *r.HTTP) {
		return fmt.Errorf("case %s: rpc_projection.http %d is outside its closed domain", where, *r.HTTP)
	}
	if r.ErrorClass != nil && *r.ErrorClass != cp2RPCUnavailable && !canonicalPipelineResultRE.MatchString(*r.ErrorClass) {
		return fmt.Errorf("case %s: rpc_projection.error_class %q is neither a taxonomy token nor %s", where, *r.ErrorClass, cp2RPCUnavailable)
	}
	return nil
}

// cp2ValidateExpected pins the commit-truth domain, the result -> commit truth
// relation and the RPC domain of one case.
func cp2ValidateExpected(where string, e cp2Expected) error {
	if !slices.Contains(canonicalPipelineCommitTruth, e.CommitTruth) {
		return fmt.Errorf("case %s: commit truth %q is unknown", where, e.CommitTruth)
	}
	for _, d := range []struct {
		name    string
		value   *string
		allowed []string
	}{{"wire_disposition", e.WireDisposition, cp2WireDispositionValues}, {"recovery_outcome", e.RecoveryOutcome, cp2RecoveryOutcomeValues}} {
		if d.value != nil && !slices.Contains(d.allowed, *d.value) {
			return fmt.Errorf("case %s: %s %q is outside its closed domain", where, d.name, *d.value)
		}
	}
	if err := cp2ValidateResultTruth(where, e); err != nil {
		return err
	}
	return cp2ValidateRPC(where, e.RPC)
}

// cp2ValidateResultTruth is the exact spec 6.4.1 relation check. A null result
// is a case disposed before a consensus classification (DD-001 wire layer,
// DD-002 startup/recovery) and carries pipeline_reached instead; a classified
// case may not carry it.
func cp2ValidateResultTruth(where string, e cp2Expected) error {
	if e.Result == nil {
		return cp2ValidateNullResult(where, e)
	}
	if e.PipelineReached != nil || e.WireDisposition != nil || e.RecoveryOutcome != nil {
		return fmt.Errorf("case %s: pipeline_reached, wire_disposition and recovery_outcome are set only when result is null", where)
	}
	truth, ok := cp2CommitTruthFor(*e.Result)
	if !ok {
		return fmt.Errorf("case %s: result %q is outside the closed taxonomy", where, *e.Result)
	}
	if truth != e.CommitTruth {
		return fmt.Errorf("case %s: result %q requires commit truth %s, got %q", where, *e.Result, truth, e.CommitTruth)
	}
	return nil
}

// cp2ValidateNullResult covers a case disposed before a consensus
// classification: a wire-layer disposal leaves the old image, and a
// startup/recovery case attempts no canonical transition at all.
func cp2ValidateNullResult(where string, e cp2Expected) error {
	if e.PipelineReached == nil || *e.PipelineReached {
		return fmt.Errorf("case %s: a null result requires pipeline_reached false", where)
	}
	if (e.WireDisposition != nil) == (e.RecoveryOutcome != nil) {
		return fmt.Errorf("case %s: a null result requires exactly one of wire_disposition, recovery_outcome", where)
	}
	if !slices.Contains([]string{"NOT_REACHED", "STARTUP_UNAVAILABLE_503"}, e.RPC.Class) {
		return fmt.Errorf("case %s: a null result requires an unreached or startup RPC class, got %s", where, e.RPC.Class)
	}
	return cp2ValidateNullTruth(where, e)
}

// cp2ValidateNullTruth binds the disposition of an unclassified case to its
// commit truth: the wire layer leaves the old image, startup attempts nothing.
func cp2ValidateNullTruth(where string, e cp2Expected) error {
	if e.WireDisposition != nil && e.CommitTruth != "OLD" {
		return fmt.Errorf("case %s: wire_disposition requires commit truth OLD, got %q", where, e.CommitTruth)
	}
	if e.RecoveryOutcome != nil && e.CommitTruth != "NOT_APPLICABLE" {
		return fmt.Errorf("case %s: recovery_outcome requires commit truth NOT_APPLICABLE, got %q", where, e.CommitTruth)
	}
	return nil
}

// cp2ValidateInputs closes the stimulus vocabulary the schema also pins and
// rejects two pointers of one case naming the same input.
func cp2ValidateInputs(where string, inputs []cp2Input) error {
	if len(inputs) == 0 {
		return fmt.Errorf("case %s: carries no input stimulus", where)
	}
	seen := make(map[string]bool, len(inputs))
	for _, in := range inputs {
		if !slices.Contains(cp2InputTypes, in.Type) || !slices.Contains(cp2Provenances, in.Provenance) {
			return fmt.Errorf("case %s: input %s has unknown type %q or provenance %q", where, in.Pointer, in.Type, in.Provenance)
		}
		if err := cp2InputOK(in); err != nil {
			return fmt.Errorf("case %s: %w", where, err)
		}
		if seen[in.Pointer] {
			return fmt.Errorf("case %s: duplicate input pointer %s", where, in.Pointer)
		}
		seen[in.Pointer] = true
	}
	return nil
}

func cp2ValidateCases(rowID string, cases []cp2Case) error {
	seen := make(map[string]bool, len(cases))
	for _, c := range cases {
		if !cp2UpperTokenRE.MatchString(c.CaseID) {
			return fmt.Errorf("row %s: case id %q is not a machine token", rowID, c.CaseID)
		}
		if seen[c.CaseID] {
			return fmt.Errorf("row %s: duplicate case id %q", rowID, c.CaseID)
		}
		seen[c.CaseID] = true
		if c.ScheduleID != nil && !cp2UpperTokenRE.MatchString(*c.ScheduleID) {
			return fmt.Errorf("case %s/%s: schedule_id %q is not an alias", rowID, c.CaseID, *c.ScheduleID)
		}
		if err := cp2ValidateInputs(rowID+"/"+c.CaseID, c.Input); err != nil {
			return err
		}
		if err := cp2ValidateExpected(rowID+"/"+c.CaseID, c.Expected); err != nil {
			return err
		}
	}
	return nil
}

// cp2ValidateRows gates the fields the Go structs carry: registry identity, the
// row-kind exclusions, row and case ids, the input vocabulary and pointers, the
// schedule alias, and the result/truth/RPC relations; cp2ValidateAliases and
// cp2ValidateFixtures cover the catalog. The schema-only fields
// (release_requirements, obligation_ids, sources, counters, effects, images,
// summary) are gated by validating the committed artifact against the committed
// schema, which stays the complete gate until RUB-1208 lands their values.
func cp2ValidateRows(rows []cp2Row, registry map[string]string) error {
	if len(registry) != cp2RegistrySize {
		return fmt.Errorf("row registry: %d identities, want the frozen %d", len(registry), cp2RegistrySize)
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if kind, ok := registry[row.RowID]; !ok || kind != row.Kind {
			return fmt.Errorf("row %s: (row_id, kind=%q) is not a frozen registry pair", row.RowID, row.Kind)
		}
		if seen[row.RowID] {
			return fmt.Errorf("row %s: duplicate row id", row.RowID)
		}
		seen[row.RowID] = true
		if (row.Kind == "observation") != (len(row.Cases) > 0) {
			return fmt.Errorf("row %s: kind %q with %d cases contradicts the kind exclusions", row.RowID, row.Kind, len(row.Cases))
		}
		if err := cp2ValidateCases(row.RowID, row.Cases); err != nil {
			return err
		}
	}
	return nil
}

// cp2Meta is the revision identity block: generator provenance, the byte-frozen
// R1 parent pins, the governing spec OID and the bound closure epoch.
func cp2Meta() cpMap {
	return cpMap{
		"generated_by":           "clients/go/cmd/gen-conformance-fixtures",
		"warning":                "MACHINE-GENERATED FILE. Do not edit manually.",
		"schema_version":         cp2SchemaVer,
		"corpus_revision":        cp2CorpusRev,
		"parent_r1_source_oid":   cp2ParentSourceOID,
		"parent_r1_merge_oid":    cp2ParentMergeOID,
		"parent_artifact_sha256": cp2ParentArtifactSHA,
		"parent_schema_sha256":   cp2ParentSchemaSHA,
		"governing_spec_oid":     cp2GoverningSpecOID,
		"rub1208_payload_sha256": cp2R1208PayloadSHA256,
		"closure_epoch": cpMap{
			"closure_manifest_version":        cp2ClosureManifestVersion,
			"manifest_root_sha256":            cp2ManifestRootSHA256,
			"obligation_set_hash":             cp2ObligationSetHash,
			"row_case_design_hash":            cp2RowCaseDesignHash,
			"stage_owner_relation_hash":       cp2StageOwnerRelationHash,
			"mutation_assignment_hash":        cp2MutationAssignmentHash,
			"image_manifest_hash":             cp2ImageManifestHash,
			"summary_manifest_hash":           cp2SummaryManifestHash,
			"relation_snapshot_hash":          cp2RelationSnapshotHash,
			"input_schema_design_hash":        cp2InputSchemaDesignHash,
			"expected_projection_design_hash": cp2ExpectedProjectionDesignHash,
			"status":                          cp2ClosureStatus,
		},
	}
}

// cp2Authority mirrors the v1 provenance block: every expected value is authored
// architecture authority, never measured from a node production path.
func cp2Authority() cpMap {
	return cpMap{
		"issue":                "RUB-1208",
		"architecture_parent":  "RUB-882 as superseded by RUB-1180; row and case design closed by RUB-1206",
		"normative_spec_ref":   "2tbmz9y2xt-lang/rubin-spec@" + cp2GoverningSpecOID,
		"baseline_ref":         "2tbmz9y2xt-lang/rubin-protocol@f972c0262c9762ce92e4c51263cd35b43d47df34",
		"expected_row_origin":  "authored architecture authority; no Go or Rust node production path is called to compute an expected value",
		"executors":            "none while status is building: no C02/C02A/C03/C04 consumer may bind this revision",
		"status":               "BUILDING C01-R2 authority — RUB-1208 migrates 8 registered publication/summary/DA-cleanup rows and 24 cases; remaining rows land in RUB-1209..RUB-1212 and RUB-1204 completes the revision",
		"consume_freeze_point": "POST-RUB-911 target: the frozen P2P effect order carries no canonical-DA consume step",
	}
}

// cp2AliasesOf returns the alias-shaped strings one stimulus pointer carries.
// A token tag carries a machine token, never a catalog alias (the schema maps
// `token`/`array<token>` to machineToken, not to an *OrAlias form), so an
// uppercase value there resolves to nothing.
func cp2AliasesOf(in cp2Input) []string {
	if in.Type == "token" || in.Type == "array<token>" {
		return nil
	}
	var out []string
	switch v := cp2JSONImage(in.ValueOrAlias).(type) {
	case []any:
		for _, e := range v {
			out = cp2AppendAlias(out, e)
		}
	default:
		out = cp2AppendAlias(out, v)
	}
	return out
}

func cp2AppendAlias(out []string, v any) []string {
	if s, ok := v.(string); ok && cp2UpperTokenRE.MatchString(s) {
		return append(out, s)
	}
	return out
}

// cp2ValidateAliases resolves every alias a stimulus pointer names against the
// top-level fixtures catalog. JSON Schema pins an alias's grammar but cannot
// express its EXISTENCE, so this is the only gate that catches a dangling one.
// The catalog is empty until RUB-1208 populates it, so an alias-carrying row is
// rejected until then — the intended fail-closed order.
// ponytail: input side only; the expected struct carries no effects or summary
// yet, so RUB-1208 extends this walk when it lands those alias positions.
func cp2ValidateAliases(rows []cp2Row, fixtures map[string]cp2Fixture) error {
	for _, row := range rows {
		for _, c := range row.Cases {
			for _, in := range c.Input {
				if err := cp2ResolveAliases(row.RowID+"/"+c.CaseID, in, fixtures); err != nil {
					return err
				}
			}
			if c.ScheduleID != nil {
				sched := cp2Input{Pointer: "/schedule_id", Type: "object", ValueOrAlias: *c.ScheduleID}
				if err := cp2ResolveAliases(row.RowID+"/"+c.CaseID, sched, fixtures); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// cp2ResolveAliases requires every alias one pointer names to exist in the
// catalog AND to carry the fixture type the pointer tag declares; an `alias`
// tag accepts any catalog type, since the tag names no literal form itself.
func cp2ResolveAliases(where string, in cp2Input, fixtures map[string]cp2Fixture) error {
	want := strings.TrimSuffix(strings.TrimPrefix(in.Type, "array<"), ">")
	for _, alias := range cp2AliasesOf(in) {
		fixture, ok := fixtures[alias]
		if !ok {
			return fmt.Errorf("case %s: input %s names alias %q, absent from the fixtures catalog", where, in.Pointer, alias)
		}
		if want != "alias" && fixture.Type != want {
			return fmt.Errorf("case %s: input %s alias %q is a %s fixture, want %s", where, in.Pointer, alias, fixture.Type, want)
		}
	}
	return nil
}

type cp2R1208Payload struct {
	ClosureBindings map[string]string     `json:"closure_bindings"`
	Fixtures        map[string]cp2Fixture `json:"fixtures"`
	ImageManifest   cpMap                 `json:"image_manifest"`
	ResolvedValues  map[string]cp2Fixture `json:"resolved_values"`
	Rows            []json.RawMessage     `json:"rows"`
	SummaryManifest cpMap                 `json:"summary_manifest"`
}

var cp2R1208Rows = map[string]int{
	"C01-DACLEAN-001": 12, "C01-DIRECT-001": 1, "C01-DISCONNECT-001": 1, "C01-EQUALWORK-001": 1,
	"C01-GENESIS-001": 1, "C01-REORG-001": 1, "C01-SIDE-001": 1, "C01-SUMMARY-001": 6,
}

func cp2DecodeR1208Payload(encoded, wantSHA string) (cp2R1208Payload, error) {
	var payload cp2R1208Payload
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return payload, fmt.Errorf("payload base64: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return payload, fmt.Errorf("payload gzip: %w", err)
	}
	raw, readErr := io.ReadAll(zr)
	closeErr := zr.Close()
	if readErr != nil {
		return payload, fmt.Errorf("payload read: %w", readErr)
	}
	if closeErr != nil {
		return payload, fmt.Errorf("payload close: %w", closeErr)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != wantSHA {
		return payload, fmt.Errorf("payload sha256=%s want %s", got, wantSHA)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return payload, fmt.Errorf("payload json: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return payload, errors.New("payload has trailing JSON")
	}
	return payload, nil
}

func cp2CanonicalSHA(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	raw := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func cp2ValidateResolved(values map[string]cp2Fixture) error {
	for name, value := range values {
		if !cp2TokenRE.MatchString(name) {
			return fmt.Errorf("resolved_values key %q is not a machine token", name)
		}
		if !slices.Contains([]string{"bytes32_hex", "object", "u64"}, value.Type) || !cp2FixtureValueOK(value) {
			return fmt.Errorf("resolved_values[%s] is not a valid %s literal", name, value.Type)
		}
	}
	return nil
}

func cp2ResolvedType(values map[string]cp2Fixture, alias, want string) error {
	value, ok := values[alias]
	if !ok {
		return fmt.Errorf("resolved alias %q is absent", alias)
	}
	if value.Type != want {
		return fmt.Errorf("resolved alias %q type=%s want %s", alias, value.Type, want)
	}
	return nil
}

func cp2ValidateR1208Expected(where string, expected map[string]any, fixtures map[string]cp2Fixture, resolved map[string]cp2Fixture) error {
	truth, _ := expected["commit_truth"].(string)
	images, ok := expected["state_image"].(map[string]any)
	if !ok || len(images) != 4 {
		return fmt.Errorf("%s/state_image must carry exactly four images", where)
	}
	directTypes := map[string]map[string]string{
		"CHAIN_IMAGE_V1":            {"tip_hash": "bytes32_hex", "height": "u64", "utxo_count": "u64"},
		"STANDARD_MEMPOOL_IMAGE_V1": {"current_mempool_min_fee_rate": "u64", "last_admission_seq": "u64", "used_bytes": "u64", "tx_count": "u64", "record_count": "u64"},
		"RETAINED_DA_IMAGE_V1":      {"set_count": "u64", "orphan_bytes": "u64", "pinned_payload_bytes": "u64"},
		"OWNER_IMAGE_V1":            {"claim_count": "u64", "stable_tip": "object"},
	}
	for image, fields := range directTypes {
		p, ok := images[image].(map[string]any)
		if !ok {
			return fmt.Errorf("%s/state_image/%s missing", where, image)
		}
		relation, _ := p["relation"].(string)
		if truth == "UNKNOWN" {
			if relation != "withheld" {
				return fmt.Errorf("%s/%s relation=%s want withheld", where, image, relation)
			}
		} else if relation == "withheld" || !slices.Contains([]string{"new", "old", "unchanged"}, relation) {
			return fmt.Errorf("%s/%s relation=%s invalid for %s", where, image, relation, truth)
		}
		digest, ok := p["digest_alias"].(string)
		if !ok {
			return fmt.Errorf("%s/%s digest_alias missing", where, image)
		}
		if err := cp2ResolvedType(resolved, digest, "bytes32_hex"); err != nil {
			return fmt.Errorf("%s/%s: %w", where, image, err)
		}
		direct, ok := p["direct_fields"].(map[string]any)
		if !ok || len(direct) != len(fields) {
			return fmt.Errorf("%s/%s direct_fields shape", where, image)
		}
		for field, typ := range fields {
			alias, ok := direct[field].(string)
			if !ok {
				return fmt.Errorf("%s/%s/%s alias missing", where, image, field)
			}
			if err := cp2ResolvedType(resolved, alias, typ); err != nil {
				return fmt.Errorf("%s/%s/%s: %w", where, image, field, err)
			}
		}
	}
	summary := expected["canonical_applied_blocks"]
	if truth != "NEW" {
		if summary != nil {
			return fmt.Errorf("%s summary must be null for %s", where, truth)
		}
		return nil
	}
	rows, ok := summary.([]any)
	if !ok {
		return fmt.Errorf("%s summary must be array for NEW", where)
	}
	lastHeight := uint64(0)
	haveHeight := false
	for i, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%s summary[%d] is not object", where, i)
		}
		blockID, _ := row["block_id"].(string)
		blockHash, _ := row["block_hash"].(string)
		bf, ok := fixtures[blockID]
		if !ok || bf.Type != "object" {
			return fmt.Errorf("%s summary[%d] block_id %q unresolved", where, i, blockID)
		}
		if err := cp2ResolvedFixtureAlias(fixtures, blockHash, "bytes32_hex"); err != nil {
			return fmt.Errorf("%s summary[%d]: %w", where, i, err)
		}
		obj, _ := cp2JSONImage(bf.Value).(map[string]any)
		h, ok := cp2UintOf(obj["height"])
		if !ok {
			return fmt.Errorf("%s summary[%d] block height invalid", where, i)
		}
		if haveHeight && h <= lastHeight {
			return fmt.Errorf("%s summary heights not strictly canonical", where)
		}
		lastHeight, haveHeight = h, true
		ids, ok := row["complete_da_ids"].([]any)
		if !ok {
			return fmt.Errorf("%s summary[%d] complete_da_ids invalid", where, i)
		}
		prev := ""
		for j, rawID := range ids {
			a, ok := rawID.(string)
			if !ok {
				return fmt.Errorf("%s summary[%d] da id invalid", where, i)
			}
			if err := cp2ResolvedFixtureAlias(fixtures, a, "bytes32_hex"); err != nil {
				return err
			}
			v := fixtures[a].Value.(string)
			if j > 0 && v < prev {
				return fmt.Errorf("%s summary[%d] da ids not raw-byte ascending", where, i)
			}
			prev = v
		}
	}
	return nil
}

func cp2ResolvedFixtureAlias(fixtures map[string]cp2Fixture, alias, want string) error {
	f, ok := fixtures[alias]
	if !ok {
		return fmt.Errorf("fixture alias %q is absent", alias)
	}
	if f.Type != want {
		return fmt.Errorf("fixture alias %q type=%s want %s", alias, f.Type, want)
	}
	return nil
}

func cp2ValidateR1208Payload(payload cp2R1208Payload) error {
	wantBindings := map[string]string{
		"closure_manifest_version": cp2ClosureManifestVersion, "manifest_root_sha256": cp2ManifestRootSHA256,
		"row_case_design_hash": cp2RowCaseDesignHash, "input_schema_design_hash": cp2InputSchemaDesignHash,
		"expected_projection_design_hash": cp2ExpectedProjectionDesignHash, "image_manifest_hash": cp2ImageManifestHash,
		"summary_manifest_hash": cp2SummaryManifestHash, "mutation_assignment_hash": cp2MutationAssignmentHash,
	}
	if !maps.Equal(payload.ClosureBindings, wantBindings) {
		return errors.New("RUB-1208 closure bindings differ from frozen v8 pins")
	}
	if got, err := cp2CanonicalSHA(payload.ImageManifest); err != nil || got != cp2ImageManifestHash {
		return fmt.Errorf("image manifest hash=%s err=%v", got, err)
	}
	if got, err := cp2CanonicalSHA(payload.SummaryManifest); err != nil || got != cp2SummaryManifestHash {
		return fmt.Errorf("summary manifest hash=%s err=%v", got, err)
	}
	if err := cp2ValidateFixtures(payload.Fixtures); err != nil {
		return err
	}
	if err := cp2ValidateResolved(payload.ResolvedValues); err != nil {
		return err
	}
	if len(payload.Rows) != len(cp2R1208Rows) {
		return fmt.Errorf("RUB-1208 rows=%d want %d", len(payload.Rows), len(cp2R1208Rows))
	}
	typed := make([]cp2Row, 0, len(payload.Rows))
	seen := map[string]bool{}
	for _, raw := range payload.Rows {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var row cp2Row
		if err := dec.Decode(&row); err != nil {
			return err
		}
		wantCases, ok := cp2R1208Rows[row.RowID]
		if !ok || seen[row.RowID] || len(row.Cases) != wantCases {
			return fmt.Errorf("RUB-1208 row %s cases=%d unauthorized", row.RowID, len(row.Cases))
		}
		seen[row.RowID] = true
		typed = append(typed, row)
		var generic map[string]any
		dec = json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&generic); err != nil {
			return err
		}
		cases, _ := generic["cases"].([]any)
		for _, cr := range cases {
			c := cr.(map[string]any)
			id, _ := c["case_id"].(string)
			exp, _ := c["expected"].(map[string]any)
			if err := cp2ValidateR1208Expected(row.RowID+"/"+id, exp, payload.Fixtures, payload.ResolvedValues); err != nil {
				return err
			}
		}
	}
	if err := cp2ValidateRows(typed, cp2RowRegistry()); err != nil {
		return err
	}
	return cp2ValidateAliases(typed, payload.Fixtures)
}

func mustWriteCompactJSON(path string, value any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		fatalf("marshal %s: %v", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func mustWriteCanonicalPipelineV2Corpus(path string) {
	payload, err := cp2DecodeR1208Payload(cp2R1208PayloadGzipBase64, cp2R1208PayloadSHA256)
	if err != nil {
		fatalf("canonical pipeline v2: %v", err)
	}
	if err := cp2ValidateR1208Payload(payload); err != nil {
		fatalf("canonical pipeline v2: %v", err)
	}
	rows := make([]any, 0, len(payload.Rows))
	for _, raw := range payload.Rows {
		var row any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&row); err != nil {
			fatalf("canonical pipeline v2 row: %v", err)
		}
		rows = append(rows, row)
	}
	artifact := cpMap{
		"artifact": cp2ArtifactName, "schema_version": cp2SchemaVer, "schema": cp2SchemaRel, "_meta": cp2Meta(), "authority": cp2Authority(),
		"result_taxonomy": canonicalPipelineTaxonomy, "commit_truth_values": canonicalPipelineCommitTruth, "rpc_projection_classes": cp2RPCClasses,
		"wire_disposition_values": cp2WireDispositionValues, "recovery_outcome_values": cp2RecoveryOutcomeValues, "row_registry": cp2RowRegistry(),
		"fixtures": payload.Fixtures, "image_manifest": payload.ImageManifest, "resolved_values": payload.ResolvedValues, "rows": rows, "summary_manifest": payload.SummaryManifest,
	}
	mustWriteCompactJSON(path, artifact)
}
