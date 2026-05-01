package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestMustJSONUint32RejectsNonIntegralAndOverflow(t *testing.T) {
	if _, err := parseJSONUint32("bad", math.MaxUint32+1); err == nil {
		t.Fatalf("parseJSONUint32 should reject overflow")
	}
	if _, err := parseJSONUint32("bad", 1.5); err == nil {
		t.Fatalf("parseJSONUint32 should reject non-integral values")
	}
	got, err := parseJSONUint32("ok", 7.0)
	if err != nil {
		t.Fatalf("parseJSONUint32(valid): %v", err)
	}
	if got != 7 {
		t.Fatalf("got %d, want 7", got)
	}
}

func TestGenConformanceFixturesGenerator_WritesToTempRepo(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	tmp := t.TempDir()
	repoRoot := tmp

	// Minimal directory layout expected by repoRootFromGoModule().
	clientsGoDir := filepath.Join(repoRoot, "clients/go")
	fixturesDir := filepath.Join(repoRoot, "conformance/fixtures")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("mkdir fixtures: %v", err)
	}
	if err := os.MkdirAll(clientsGoDir, 0o755); err != nil {
		t.Fatalf("mkdir clients/go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientsGoDir, "go.mod"), []byte("module temp\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	mkTxid := func(fill byte) string {
		b := make([]byte, 32)
		for i := range b {
			b[i] = fill
		}
		return hex.EncodeToString(b)
	}
	newVector := func(id string, utxoCount int, extra map[string]any) map[string]any {
		utxos := make([]any, 0, utxoCount)
		for i := 0; i < utxoCount; i++ {
			utxos = append(utxos, map[string]any{
				"txid":          mkTxid(byte(len(id) + i + 1)),
				"vout":          float64(i),
				"value":         float64(0),
				"covenant_type": float64(0),
				"covenant_data": "",
			})
		}
		v := map[string]any{
			"id":     id,
			"utxos":  utxos,
			"tx_hex": "",
		}
		for k, val := range extra {
			v[k] = val
		}
		return v
	}

	writeFixture := func(name string, vectors []map[string]any) {
		t.Helper()
		path := filepath.Join(fixturesDir, name)
		f := fixtureFile{Gate: name[:len(name)-len(".json")], Vectors: vectors}
		raw, err := json.MarshalIndent(&f, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	writeFixture("CV-MULTISIG.json", []map[string]any{
		newVector("CV-M-01", 1, nil),
	})

	writeFixture("CV-UTXO-BASIC.json", []map[string]any{
		newVector("CV-U-05", 1, nil),
		newVector("CV-U-06", 1, nil),
		newVector("CV-U-16", 1, nil),
		newVector("CV-U-09", 1, nil),
		newVector("CV-U-10", 2, nil),
		newVector("CV-U-11", 2, nil),
		newVector("CV-U-12", 2, nil),
		newVector("CV-U-13", 2, nil),
		newVector("CV-U-19", 1, nil), // burn-to-fee (output_count=0)
		newVector("CV-U-EXT-05", 1, map[string]any{
			"core_ext_profiles": []any{
				map[string]any{
					"ext_id":                 float64(1),
					"activation_height":      float64(0),
					"allowed_suite_ids":      []any{float64(3)},
					"binding":                "",
					"binding_descriptor_hex": "",
					"ext_payload_schema_hex": "",
				},
			},
		}),
	})

	writeFixture("CV-EXT.json", []map[string]any{
		newVector("CV-EXT-ENF-04", 1, map[string]any{
			"core_ext_profiles": []any{
				map[string]any{
					"ext_id":                 float64(4096),
					"activation_height":      float64(50),
					"allowed_suite_ids":      []any{float64(1), float64(3)},
					"binding":                "",
					"binding_descriptor_hex": "",
					"ext_payload_schema_hex": "",
				},
			},
		}),
	})

	writeFixture("CV-VAULT.json", []map[string]any{
		newVector("VAULT-CREATE-01", 1, nil),
		newVector("VAULT-CREATE-02", 1, nil),
		newVector("VAULT-SPEND-02", 3, nil),
		newVector("VAULT-SPEND-04", 2, nil),
	})

	// devnet operator-evidence artifact skeleton (#1312). Lives under
	// conformance/fixtures/devnet/, intentionally outside the auto-
	// discovered CV-*.json conformance namespace because the tx is
	// signed under the canonical devnet chain_id (and would fail the
	// zero-chain conformance replay the runner/matrix/formal tools
	// enforce on top-level CV-*.json fixtures).
	devnetDir := filepath.Join(fixturesDir, "devnet")
	if err := os.MkdirAll(devnetDir, 0o755); err != nil {
		t.Fatalf("mkdir devnet: %v", err)
	}
	{
		raw, err := json.MarshalIndent(&fixtureFile{
			Gate:    "devnet-vault-create-01",
			Vectors: []map[string]any{newVector("DEVNET-VAULT-CREATE-01", 1, nil)},
		}, "", "  ")
		if err != nil {
			t.Fatalf("marshal devnet skeleton: %v", err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(devnetDir, "devnet-vault-create-01.json"), raw, 0o600); err != nil {
			t.Fatalf("write devnet skeleton: %v", err)
		}
	}
	// devnet-htlc-claim-01 skeleton (#1241 prerequisite). Same
	// non-conformance namespace rationale as devnet-vault-create-01.
	{
		raw, err := json.MarshalIndent(&fixtureFile{
			Gate:    "devnet-htlc-claim-01",
			Vectors: []map[string]any{newVector("DEVNET-HTLC-CLAIM-01", 1, nil)},
		}, "", "  ")
		if err != nil {
			t.Fatalf("marshal devnet htlc skeleton: %v", err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(devnetDir, "devnet-htlc-claim-01.json"), raw, 0o600); err != nil {
			t.Fatalf("write devnet htlc skeleton: %v", err)
		}
	}
	// devnet-multisig-spend-01 skeleton (#1242 prerequisite). Same
	// non-conformance namespace rationale as the other devnet/*
	// fixtures. The skeleton's utxos[0].covenant_type is overridden
	// to COV_TYPE_MULTISIG (260) so the temp-repo seed mirrors the
	// shape of the committed devnet-multisig-spend-01 fixture; if a
	// future generator change starts depending on covenant_type, the
	// skeleton matches what the committed artifact already encodes.
	{
		multisigVec := newVector("DEVNET-MULTISIG-SPEND-01", 1, nil)
		if utxos, ok := multisigVec["utxos"].([]any); ok && len(utxos) > 0 {
			if u, ok := utxos[0].(map[string]any); ok {
				u["covenant_type"] = float64(260) // COV_TYPE_MULTISIG
			}
		}
		raw, err := json.MarshalIndent(&fixtureFile{
			Gate:    "devnet-multisig-spend-01",
			Vectors: []map[string]any{multisigVec},
		}, "", "  ")
		if err != nil {
			t.Fatalf("marshal devnet multisig skeleton: %v", err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(devnetDir, "devnet-multisig-spend-01.json"), raw, 0o600); err != nil {
			t.Fatalf("write devnet multisig skeleton: %v", err)
		}
	}

	writeFixture("CV-HTLC.json", []map[string]any{
		newVector("CV-HTLC-13", 1, nil),
	})

	writeFixture("CV-SUBSIDY.json", []map[string]any{
		newVector("CV-SUB-01", 1, map[string]any{"expected_prev_hash": mkTxid(0x00)}),
		newVector("CV-SUB-02", 1, map[string]any{"expected_prev_hash": mkTxid(0x00)}),
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(clientsGoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	// Cover main.go (calls runGeneratorCLI).
	main()

	// Sanity: generator should have written tx_hex / block_hex fields into our temp fixtures.
	mustContainField := func(file string, field string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(fixturesDir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", file, err)
		}
		vectors, ok := got["vectors"].([]any)
		if !ok || len(vectors) == 0 {
			t.Fatalf("%s: missing vectors", file)
		}
		seenNonEmpty := false
		for _, item := range vectors {
			m, _ := item.(map[string]any)
			if s, _ := m[field].(string); s != "" {
				seenNonEmpty = true
				break
			}
		}
		if !seenNonEmpty {
			t.Fatalf("%s: expected at least one non-empty %s", file, field)
		}
	}

	mustContainField("CV-UTXO-BASIC.json", "tx_hex")
	mustContainField("CV-VAULT.json", "tx_hex")
	mustContainField("CV-HTLC.json", "tx_hex")
	mustContainField("CV-SUBSIDY.json", "block_hex")
	mustContainField(filepath.Join("devnet", "devnet-vault-create-01.json"), "tx_hex")
	mustContainField(filepath.Join("devnet", "devnet-vault-create-01.json"), "chain_id_hex")
	mustContainField(filepath.Join("devnet", "devnet-htlc-claim-01.json"), "tx_hex")
	mustContainField(filepath.Join("devnet", "devnet-htlc-claim-01.json"), "chain_id_hex")
	mustContainField(filepath.Join("devnet", "devnet-multisig-spend-01.json"), "tx_hex")
	mustContainField(filepath.Join("devnet", "devnet-multisig-spend-01.json"), "chain_id_hex")
}

// TestDevnetVaultCreateArtifactSignedUnderDevnetChainID validates the
// committed canonical devnet operator-evidence artifact end-to-end
// through the public consensus.ApplyNonCoinbaseTxBasic verification
// path. This is the hostile-matrix proof that the artifact's signature
// domain is exactly the canonical devnet chain_id (issue #1312,
// blocker for #1240); a parse-only test would not exercise signature
// verification and could not reject a zero-chain-signed tx
// accidentally tagged as devnet.
//
// Proof assertion: ApplyNonCoinbaseTxBasic returns nil when called
// with chainID == node.DevnetGenesisChainID() AND returns a non-nil
// error when called with chainID == [32]byte{} (zero) — the latter
// rejection proves the signature is bound to the devnet domain and
// not a zero-chain tx coincidentally routed.
func TestDevnetVaultCreateArtifactSignedUnderDevnetChainID(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	// Locate the committed fixture relative to this test file (which
	// lives at clients/go/cmd/gen-conformance-fixtures/runtime_test.go).
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	fixturePath := filepath.Join(wd, "..", "..", "..", "..", "conformance", "fixtures", "devnet", "devnet-vault-create-01.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Gate    string           `json:"gate"`
		Vectors []map[string]any `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if doc.Gate != "devnet-vault-create-01" {
		t.Fatalf("gate=%q want devnet-vault-create-01", doc.Gate)
	}
	if len(doc.Vectors) != 1 {
		t.Fatalf("vectors=%d want 1", len(doc.Vectors))
	}
	v := doc.Vectors[0]
	if id, _ := v["id"].(string); id != "DEVNET-VAULT-CREATE-01" {
		t.Fatalf("vector id=%q want DEVNET-VAULT-CREATE-01", id)
	}

	// Vector chain_id_hex must match the canonical devnet chain_id from
	// node.DevnetGenesisChainID() so an operator/orchestrator reading
	// the artifact can verify the metadata without re-deriving it.
	devnetChainID := node.DevnetGenesisChainID()
	wantChainIDHex := hex.EncodeToString(devnetChainID[:])
	// Validated readers: every numeric fixture field MUST go through
	// parseJSONUint32 so missing keys, non-numeric values, fractional
	// values, and out-of-range values fail closed via t.Fatalf instead
	// of silently truncating to zero. String/bool fields use comma-ok
	// assertions with explicit type errors. The fixture stores small
	// values (height=200, value=100, etc.) so a uint32 ceiling is more
	// than sufficient; uint64 destination fields take an explicit
	// uint32→uint64 widening which is lossless.
	mustU32 := func(label string, raw any) uint32 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		return n
	}
	mustU16 := func(label string, raw any) uint16 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		if n > 0xFFFF {
			t.Fatalf("%s: value %d exceeds uint16", label, n)
		}
		return uint16(n)
	}
	mustString := func(label string, raw any) string {
		t.Helper()
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("%s: expected string, got %T", label, raw)
		}
		return s
	}
	mustBool := func(label string, raw any) bool {
		t.Helper()
		b, ok := raw.(bool)
		if !ok {
			t.Fatalf("%s: expected bool, got %T", label, raw)
		}
		return b
	}

	gotChainIDHex := mustString("chain_id_hex", v["chain_id_hex"])
	if gotChainIDHex != wantChainIDHex {
		t.Fatalf("chain_id_hex=%q want %q (canonical devnet)", gotChainIDHex, wantChainIDHex)
	}

	// Reconstruct the utxoSet from the fixture so ApplyNonCoinbaseTxBasic
	// has the input it needs to verify the signature against.
	utxosRaw, ok := v["utxos"].([]any)
	if !ok {
		t.Fatalf("utxos: expected array, got %T", v["utxos"])
	}
	if len(utxosRaw) != 1 {
		t.Fatalf("utxos=%d want 1", len(utxosRaw))
	}
	u, ok := utxosRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("utxos[0]: expected object, got %T", utxosRaw[0])
	}
	prevTxidHex := mustString("utxos[0].txid", u["txid"])
	prevTxidBytes, err := hex.DecodeString(prevTxidHex)
	if err != nil || len(prevTxidBytes) != 32 {
		t.Fatalf("utxo txid=%q invalid: %v", prevTxidHex, err)
	}
	var prevTxid [32]byte
	copy(prevTxid[:], prevTxidBytes)
	covenantDataHex := mustString("utxos[0].covenant_data", u["covenant_data"])
	covenantData, err := hex.DecodeString(covenantDataHex)
	if err != nil {
		t.Fatalf("utxo covenant_data hex: %v", err)
	}
	utxoSet := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prevTxid, Vout: mustU32("utxos[0].vout", u["vout"])}: {
			Value:             uint64(mustU32("utxos[0].value", u["value"])),
			CovenantType:      mustU16("utxos[0].covenant_type", u["covenant_type"]),
			CovenantData:      covenantData,
			CreationHeight:    uint64(mustU32("utxos[0].creation_height", u["creation_height"])),
			CreatedByCoinbase: mustBool("utxos[0].created_by_coinbase", u["created_by_coinbase"]),
		},
	}

	// Parse the committed tx_hex.
	txHex := mustString("tx_hex", v["tx_hex"])
	if txHex == "" {
		t.Fatalf("tx_hex is empty — regenerate the fixture via `cd clients/go && go run ./cmd/gen-conformance-fixtures`")
	}
	rawTx, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("tx_hex decode: %v", err)
	}
	_, txid, _, consumed, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(rawTx) {
		t.Fatalf("ParseTx consumed=%d want %d", consumed, len(rawTx))
	}
	parsedTx, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (re): %v", err)
	}

	height := uint64(mustU32("height", v["height"]))
	blockTimestamp := uint64(mustU32("block_timestamp", v["block_timestamp"]))

	// Positive: signature MUST verify under the canonical devnet chain_id.
	if _, err := consensus.ApplyNonCoinbaseTxBasic(parsedTx, txid, utxoSet, height, blockTimestamp, devnetChainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasic(devnet chain_id): %v — artifact is not signed under canonical devnet domain", err)
	}

	// Re-parse the tx bytes to drop any cached state from the positive
	// call, then call ApplyNonCoinbaseTxBasic with zero chain_id.
	// Proof assertion: the second ApplyNonCoinbaseTxBasic call returns
	// a non-nil error; a nil error would mean the tx_hex validates
	// under both devnet and zero chain_id, which contradicts the
	// devnet-domain-bound contract this artifact must satisfy.
	parsedTx2, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (negative): %v", err)
	}
	zeroChainID := [32]byte{}
	if _, err := consensus.ApplyNonCoinbaseTxBasic(parsedTx2, txid, utxoSet, height, blockTimestamp, zeroChainID); err == nil {
		t.Fatalf("ApplyNonCoinbaseTxBasic(zero chain_id) unexpectedly accepted — artifact signature must NOT verify under zero chain_id, otherwise it is not exclusively devnet-domain-bound")
	}
}

// TestDevnetHTLCClaimArtifactSignedUnderDevnetChainID validates the
// committed canonical devnet operator-evidence CORE_HTLC claim
// artifact end-to-end through the public
// consensus.ApplyNonCoinbaseTxBasicWithMTP verification path.
// Mirrors TestDevnetVaultCreateArtifactSignedUnderDevnetChainID with
// the same validated-reader pattern (parseJSONUint32 + comma-ok
// t.Fatalf) so missing/non-numeric/out-of-range fixture metadata
// fails closed; the only structural difference is the HTLC vector
// also pins block_mtp because TIMESTAMP-mode HTLC unlock checks MTP
// in addition to block_timestamp.
//
// Proof assertion: ApplyNonCoinbaseTxBasicWithMTP returns nil under
// chainID == node.DevnetGenesisChainID() AND non-nil under
// chainID == [32]byte{} zero. Issue #1241 prerequisite.
func TestDevnetHTLCClaimArtifactSignedUnderDevnetChainID(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	fixturePath := filepath.Join(wd, "..", "..", "..", "..", "conformance", "fixtures", "devnet", "devnet-htlc-claim-01.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Gate    string           `json:"gate"`
		Vectors []map[string]any `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if doc.Gate != "devnet-htlc-claim-01" {
		t.Fatalf("gate=%q want devnet-htlc-claim-01", doc.Gate)
	}
	if len(doc.Vectors) != 1 {
		t.Fatalf("vectors=%d want 1", len(doc.Vectors))
	}
	v := doc.Vectors[0]
	if id, _ := v["id"].(string); id != "DEVNET-HTLC-CLAIM-01" {
		t.Fatalf("vector id=%q want DEVNET-HTLC-CLAIM-01", id)
	}

	mustU32 := func(label string, raw any) uint32 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		return n
	}
	mustU16 := func(label string, raw any) uint16 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		if n > 0xFFFF {
			t.Fatalf("%s: value %d exceeds uint16", label, n)
		}
		return uint16(n)
	}
	mustString := func(label string, raw any) string {
		t.Helper()
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("%s: expected string, got %T", label, raw)
		}
		return s
	}
	mustBool := func(label string, raw any) bool {
		t.Helper()
		b, ok := raw.(bool)
		if !ok {
			t.Fatalf("%s: expected bool, got %T", label, raw)
		}
		return b
	}

	devnetChainID := node.DevnetGenesisChainID()
	wantChainIDHex := hex.EncodeToString(devnetChainID[:])
	gotChainIDHex := mustString("chain_id_hex", v["chain_id_hex"])
	if gotChainIDHex != wantChainIDHex {
		t.Fatalf("chain_id_hex=%q want %q (canonical devnet)", gotChainIDHex, wantChainIDHex)
	}

	utxosRaw, ok := v["utxos"].([]any)
	if !ok {
		t.Fatalf("utxos: expected array, got %T", v["utxos"])
	}
	if len(utxosRaw) != 1 {
		t.Fatalf("utxos=%d want 1", len(utxosRaw))
	}
	u, ok := utxosRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("utxos[0]: expected object, got %T", utxosRaw[0])
	}
	prevTxidHex := mustString("utxos[0].txid", u["txid"])
	prevTxidBytes, err := hex.DecodeString(prevTxidHex)
	if err != nil || len(prevTxidBytes) != 32 {
		t.Fatalf("utxo txid=%q invalid: %v", prevTxidHex, err)
	}
	var prevTxid [32]byte
	copy(prevTxid[:], prevTxidBytes)
	covenantDataHex := mustString("utxos[0].covenant_data", u["covenant_data"])
	covenantData, err := hex.DecodeString(covenantDataHex)
	if err != nil {
		t.Fatalf("utxo covenant_data hex: %v", err)
	}
	utxoSet := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prevTxid, Vout: mustU32("utxos[0].vout", u["vout"])}: {
			Value:             uint64(mustU32("utxos[0].value", u["value"])),
			CovenantType:      mustU16("utxos[0].covenant_type", u["covenant_type"]),
			CovenantData:      covenantData,
			CreationHeight:    uint64(mustU32("utxos[0].creation_height", u["creation_height"])),
			CreatedByCoinbase: mustBool("utxos[0].created_by_coinbase", u["created_by_coinbase"]),
		},
	}

	txHex := mustString("tx_hex", v["tx_hex"])
	if txHex == "" {
		t.Fatalf("tx_hex is empty — regenerate via `cd clients/go && go run ./cmd/gen-conformance-fixtures`")
	}
	rawTx, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("tx_hex decode: %v", err)
	}
	_, txid, _, consumed, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(rawTx) {
		t.Fatalf("ParseTx consumed=%d want %d", consumed, len(rawTx))
	}
	parsedTx, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (re): %v", err)
	}

	// HTLC TIMESTAMP-mode unlock checks block_mtp >= lockValue (the
	// helper sets lockValue=2500), so the test goes through the
	// WithMTP variant rather than the default that aliases blockMTP =
	// blockTimestamp.
	height := uint64(mustU32("height", v["height"]))
	blockTimestamp := uint64(mustU32("block_timestamp", v["block_timestamp"]))
	blockMTP := uint64(mustU32("block_mtp", v["block_mtp"]))

	// Positive: signature MUST verify under canonical devnet chain_id.
	if _, err := consensus.ApplyNonCoinbaseTxBasicWithMTP(parsedTx, txid, utxoSet, height, blockTimestamp, blockMTP, devnetChainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicWithMTP(devnet chain_id): %v — artifact is not signed under canonical devnet domain", err)
	}

	// Re-parse the tx bytes (drops cached state from the positive
	// call) before invoking ApplyNonCoinbaseTxBasicWithMTP with zero
	// chain_id.
	// Proof assertion: ApplyNonCoinbaseTxBasicWithMTP returns a
	// non-nil error under chainID == [32]byte{}; a nil error would
	// mean the tx_hex validates under both devnet and zero chain_id,
	// contradicting the devnet-domain-bound contract this artifact
	// must satisfy.
	parsedTx2, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (negative): %v", err)
	}
	zeroChainID := [32]byte{}
	if _, err := consensus.ApplyNonCoinbaseTxBasicWithMTP(parsedTx2, txid, utxoSet, height, blockTimestamp, blockMTP, zeroChainID); err == nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicWithMTP(zero chain_id) unexpectedly accepted — artifact signature must NOT verify under zero chain_id, otherwise it is not exclusively devnet-domain-bound")
	}
}

// TestDevnetMultisigSpendArtifactSignedUnderDevnetChainID validates
// the committed canonical devnet operator-evidence CORE_MULTISIG
// 1-of-1 spend artifact end-to-end through the public
// consensus.ApplyNonCoinbaseTxBasic verification path. Mirrors the
// CORE_VAULT and CORE_HTLC equivalents with the same validated-reader
// pattern (parseJSONUint32 + comma-ok t.Fatalf) so missing /
// non-numeric / out-of-range fixture metadata fails closed.
//
// Proof assertion: ApplyNonCoinbaseTxBasic returns nil under
// chainID == node.DevnetGenesisChainID() AND non-nil under
// chainID == [32]byte{} zero. Issue #1242 prerequisite.
func TestDevnetMultisigSpendArtifactSignedUnderDevnetChainID(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	fixturePath := filepath.Join(wd, "..", "..", "..", "..", "conformance", "fixtures", "devnet", "devnet-multisig-spend-01.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc struct {
		Gate    string           `json:"gate"`
		Vectors []map[string]any `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if doc.Gate != "devnet-multisig-spend-01" {
		t.Fatalf("gate=%q want devnet-multisig-spend-01", doc.Gate)
	}
	if len(doc.Vectors) != 1 {
		t.Fatalf("vectors=%d want 1", len(doc.Vectors))
	}
	v := doc.Vectors[0]
	if id, _ := v["id"].(string); id != "DEVNET-MULTISIG-SPEND-01" {
		t.Fatalf("vector id=%q want DEVNET-MULTISIG-SPEND-01", id)
	}

	mustU32 := func(label string, raw any) uint32 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		return n
	}
	mustU16 := func(label string, raw any) uint16 {
		t.Helper()
		n, perr := parseJSONUint32(label, raw)
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		if n > 0xFFFF {
			t.Fatalf("%s: value %d exceeds uint16", label, n)
		}
		return uint16(n)
	}
	mustString := func(label string, raw any) string {
		t.Helper()
		s, ok := raw.(string)
		if !ok {
			t.Fatalf("%s: expected string, got %T", label, raw)
		}
		return s
	}
	mustBool := func(label string, raw any) bool {
		t.Helper()
		b, ok := raw.(bool)
		if !ok {
			t.Fatalf("%s: expected bool, got %T", label, raw)
		}
		return b
	}

	devnetChainID := node.DevnetGenesisChainID()
	wantChainIDHex := hex.EncodeToString(devnetChainID[:])
	gotChainIDHex := mustString("chain_id_hex", v["chain_id_hex"])
	if gotChainIDHex != wantChainIDHex {
		t.Fatalf("chain_id_hex=%q want %q (canonical devnet)", gotChainIDHex, wantChainIDHex)
	}

	utxosRaw, ok := v["utxos"].([]any)
	if !ok {
		t.Fatalf("utxos: expected array, got %T", v["utxos"])
	}
	if len(utxosRaw) != 1 {
		t.Fatalf("utxos=%d want 1", len(utxosRaw))
	}
	u, ok := utxosRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("utxos[0]: expected object, got %T", utxosRaw[0])
	}
	prevTxidHex := mustString("utxos[0].txid", u["txid"])
	prevTxidBytes, err := hex.DecodeString(prevTxidHex)
	if err != nil || len(prevTxidBytes) != 32 {
		t.Fatalf("utxo txid=%q invalid: %v", prevTxidHex, err)
	}
	var prevTxid [32]byte
	copy(prevTxid[:], prevTxidBytes)
	covenantDataHex := mustString("utxos[0].covenant_data", u["covenant_data"])
	covenantData, err := hex.DecodeString(covenantDataHex)
	if err != nil {
		t.Fatalf("utxo covenant_data hex: %v", err)
	}
	utxoSet := map[consensus.Outpoint]consensus.UtxoEntry{
		{Txid: prevTxid, Vout: mustU32("utxos[0].vout", u["vout"])}: {
			Value:             uint64(mustU32("utxos[0].value", u["value"])),
			CovenantType:      mustU16("utxos[0].covenant_type", u["covenant_type"]),
			CovenantData:      covenantData,
			CreationHeight:    uint64(mustU32("utxos[0].creation_height", u["creation_height"])),
			CreatedByCoinbase: mustBool("utxos[0].created_by_coinbase", u["created_by_coinbase"]),
		},
	}

	txHex := mustString("tx_hex", v["tx_hex"])
	if txHex == "" {
		t.Fatalf("tx_hex is empty — regenerate via `cd clients/go && go run ./cmd/gen-conformance-fixtures`")
	}
	rawTx, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("tx_hex decode: %v", err)
	}
	_, txid, _, consumed, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx: %v", err)
	}
	if consumed != len(rawTx) {
		t.Fatalf("ParseTx consumed=%d want %d", consumed, len(rawTx))
	}
	parsedTx, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (re): %v", err)
	}

	height := uint64(mustU32("height", v["height"]))
	blockTimestamp := uint64(mustU32("block_timestamp", v["block_timestamp"]))

	// Positive: signature MUST verify under canonical devnet chain_id.
	if _, err := consensus.ApplyNonCoinbaseTxBasic(parsedTx, txid, utxoSet, height, blockTimestamp, devnetChainID); err != nil {
		t.Fatalf("ApplyNonCoinbaseTxBasic(devnet chain_id): %v — artifact is not signed under canonical devnet domain", err)
	}

	// Re-parse the tx bytes (drops cached state from the positive
	// call) before invoking ApplyNonCoinbaseTxBasic with zero chain_id.
	// Proof assertion: ApplyNonCoinbaseTxBasic returns a non-nil
	// error under chainID == [32]byte{}; a nil error would mean the
	// tx_hex validates under both devnet and zero chain_id,
	// contradicting the devnet-domain-bound contract this artifact
	// must satisfy.
	parsedTx2, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (negative): %v", err)
	}
	zeroChainID := [32]byte{}
	if _, err := consensus.ApplyNonCoinbaseTxBasic(parsedTx2, txid, utxoSet, height, blockTimestamp, zeroChainID); err == nil {
		t.Fatalf("ApplyNonCoinbaseTxBasic(zero chain_id) unexpectedly accepted — artifact signature must NOT verify under zero chain_id, otherwise it is not exclusively devnet-domain-bound")
	}
}

// TestGenerator_DeterministicOutputDir proves the core determinism
// contract for #1366: two consecutive runGeneratorCLIWithArgs
// invocations with --output-dir pointing at distinct temp directories
// produce byte-identical fixture output for every generator-owned
// file. Reads source fixtures from the real worktree
// conformance/fixtures/** at the repo's current HEAD and writes
// candidates only into the temp directories.
//
// Proof assertion: walking the two temp dirs file-by-file, every
// regular file pair has equal bytes. If OpenSSL ML-DSA hedged signing
// leaked into the conformance fixture path, signatures would differ
// per run and the byte-equality assertion would fail.
func TestGenerator_DeterministicOutputDir(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	tmpA := t.TempDir()
	tmpB := t.TempDir()

	runGeneratorCLIWithArgs([]string{"-output-dir", tmpA})
	runGeneratorCLIWithArgs([]string{"-output-dir", tmpB})

	// Walk tmpA and verify every file matches the byte content of the
	// corresponding file in tmpB. Also verify every file in tmpB has a
	// counterpart in tmpA (no missing-on-A, missing-on-B drift).
	pathsA := collectGeneratorOutput(t, tmpA)
	pathsB := collectGeneratorOutput(t, tmpB)
	if len(pathsA) == 0 {
		t.Fatalf("tmpA produced no files")
	}
	if len(pathsA) != len(pathsB) {
		t.Fatalf("file count mismatch: tmpA=%d tmpB=%d", len(pathsA), len(pathsB))
	}
	for rel, bytesA := range pathsA {
		bytesB, ok := pathsB[rel]
		if !ok {
			t.Fatalf("%s present in tmpA but missing from tmpB", rel)
		}
		if !bytes.Equal(bytesA, bytesB) {
			t.Fatalf("%s bytes differ between two generator runs (deterministic-mode contract violated)", rel)
		}
	}
}

// TestGenerator_OutputDirContainmentNoCommittedWrite proves that
// --output-dir mode never mutates conformance/fixtures/** in the
// committed worktree. The contract for #1358 (drift gate) depends on
// this: the gate compares candidate bytes to committed bytes, so the
// candidate path must be physically isolated.
//
// Proof assertion: capture full file bytes for a representative set
// of committed generator-owned fixtures, run the generator with
// --output-dir, re-read bytes and compare with bytes.Equal — none
// changed. Bytes-based comparison is robust against filesystems with
// coarse mtime resolution where a write may not advance ModTime;
// the earlier mtime-based assertion would silently pass on such
// runners.
func TestGenerator_OutputDirContainmentNoCommittedWrite(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	tmp := t.TempDir()

	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	committedSamples := []string{
		"CV-UTXO-BASIC.json",
		"CV-MULTISIG.json",
		"CV-EXT.json",
		"CV-VAULT.json",
		"CV-HTLC.json",
		"CV-SUBSIDY.json",
		filepath.Join("devnet", "devnet-vault-create-01.json"),
		filepath.Join("devnet", "devnet-htlc-claim-01.json"),
		filepath.Join("devnet", "devnet-multisig-spend-01.json"),
	}
	beforeContents := make(map[string][]byte, len(committedSamples))
	for _, rel := range committedSamples {
		full := filepath.Join(committedFixturesRoot, rel)
		// #nosec G304 -- path is repo-rooted, joined from a static
		// allowlist of committed fixture sample names.
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			t.Fatalf("read %s before generator: %v", rel, readErr)
		}
		beforeContents[rel] = data
	}

	runGeneratorCLIWithArgs([]string{"-output-dir", tmp})

	for _, rel := range committedSamples {
		full := filepath.Join(committedFixturesRoot, rel)
		// #nosec G304 -- same allowlist; second read covers the
		// post-generator containment assertion.
		afterData, readErr := os.ReadFile(full)
		if readErr != nil {
			t.Fatalf("read %s after generator: %v", rel, readErr)
		}
		if !bytes.Equal(afterData, beforeContents[rel]) {
			t.Fatalf("--output-dir mode mutated committed fixture %s (file contents changed) — containment broken", rel)
		}
	}
	// Sanity: candidate fixtures DID land under the temp output dir.
	if got := collectGeneratorOutput(t, tmp); len(got) == 0 {
		t.Fatalf("generator produced no candidate output under --output-dir=%s", tmp)
	}
}

// TestGenerator_CwdIndependence proves that --output-dir produces
// byte-identical results regardless of which directory inside the
// clients/go module the generator is invoked from. The
// cwd-independence claim is bounded by the existing
// repoRootFromGoModule walk-up: cwd MUST be somewhere under
// clients/go so the helper can find clients/go/go.mod by walking up.
//
// Proof assertion: running the generator from one directory in
// clients/go and then again from another directory within that same
// module (for example, clients/go/consensus) produces equal candidate
// bytes for the same absolute --output-dir family. Embedded DER keys
// load from the binary regardless of cwd; deterministic ML-DSA sign
// yields stable signatures; remap of the absolute --output-dir is
// cwd-free.
func TestGenerator_CwdIndependence(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	tmpA := t.TempDir()
	tmpB := t.TempDir()

	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWd)
	})

	// Run #1: from the existing test cwd (clients/go/cmd/gen-conformance-fixtures).
	runGeneratorCLIWithArgs([]string{"-output-dir", tmpA})

	// Run #2: from a sibling directory inside the same Go module
	// (clients/go). repoRootFromGoModule walks up looking for go.mod;
	// any cwd inside clients/go satisfies the walk regardless of how
	// nested it is. We chdir to the consensus package directory which
	// is a real, stable, sibling-to-cmd subdirectory.
	clientsGoModuleRoot := filepath.Join(originalWd, "..", "..") // clients/go
	siblingCwd := filepath.Join(clientsGoModuleRoot, "consensus")
	if _, err := os.Stat(siblingCwd); err != nil {
		t.Fatalf("sibling cwd %q stat: %v", siblingCwd, err)
	}
	if err := os.Chdir(siblingCwd); err != nil {
		t.Fatalf("chdir to %q: %v", siblingCwd, err)
	}
	runGeneratorCLIWithArgs([]string{"-output-dir", tmpB})

	pathsA := collectGeneratorOutput(t, tmpA)
	pathsB := collectGeneratorOutput(t, tmpB)
	if len(pathsA) == 0 {
		t.Fatalf("tmpA produced no files")
	}
	if len(pathsA) != len(pathsB) {
		t.Fatalf("file count mismatch across cwd: tmpA=%d tmpB=%d", len(pathsA), len(pathsB))
	}
	for rel, bytesA := range pathsA {
		bytesB, ok := pathsB[rel]
		if !ok {
			t.Fatalf("%s present in tmpA but missing from tmpB (run from unrelated cwd)", rel)
		}
		if !bytes.Equal(bytesA, bytesB) {
			t.Fatalf("%s bytes differ across cwd (cwd-independence contract violated)", rel)
		}
	}
}

// TestGenerator_ResolveWriteRootRejectsRelative exercises the
// reject branch for relative --output-dir; the testable variant
// returns an error so the assertion does not require subprocess
// wrapping around fatalf.
func TestGenerator_ResolveWriteRootRejectsRelative(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	if _, err := resolveWriteRoot("relative/path", committedFixturesRoot); err == nil {
		t.Fatalf("resolveWriteRoot accepted relative path")
	} else if !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("resolveWriteRoot relative err=%q, want substring %q", err.Error(), "must be absolute")
	}
}

// TestGenerator_ResolveWriteRootRejectsCommittedRootAlias exercises
// the reject branch for --output-dir that equals the committed root.
func TestGenerator_ResolveWriteRootRejectsCommittedRootAlias(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	if _, err := resolveWriteRoot(committedFixturesRoot, committedFixturesRoot); err == nil {
		t.Fatalf("resolveWriteRoot accepted committed root alias")
	} else if !strings.Contains(err.Error(), "must not equal the committed fixtures root") &&
		!strings.Contains(err.Error(), "aliases the committed fixtures root") {
		t.Fatalf("resolveWriteRoot alias err=%q, want substring naming committed fixtures root", err.Error())
	}
}

// TestGenerator_ResolveWriteRootRejectsInsideCommittedRoot exercises
// the reject branch for --output-dir that is inside the committed
// root.
func TestGenerator_ResolveWriteRootRejectsInsideCommittedRoot(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	insidePath := filepath.Join(committedFixturesRoot, "candidate-inside")
	if _, err := resolveWriteRoot(insidePath, committedFixturesRoot); err == nil {
		t.Fatalf("resolveWriteRoot accepted path inside committed root")
	} else if !strings.Contains(err.Error(), "is inside committed fixtures root") {
		t.Fatalf("resolveWriteRoot inside err=%q, want substring %q", err.Error(), "is inside committed fixtures root")
	}
}

// TestGenerator_ResolveWriteRootRejectsSymlinkedAncestor exercises
// the reject branch for --output-dir whose parent chain contains a
// symlink pointing into conformance/fixtures/**, even when the leaf
// component does not exist on disk yet.
//
// Proof assertion: a temp directory contains a symlink "link"
// pointing at the real committed fixtures root. resolveWriteRoot
// called with /tmp/<tmp>/link/newdir (a not-yet-created leaf under
// the symlink) walks up to the existing "link" ancestor, resolves
// it via filepath.EvalSymlinks to the committed fixtures root, and
// re-attaches "newdir" so the containment rule sees the real target
// and rejects.
func TestGenerator_ResolveWriteRootRejectsSymlinkedAncestor(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	tmp := t.TempDir()
	linkPath := filepath.Join(tmp, "link")
	if err := os.Symlink(committedFixturesRoot, linkPath); err != nil {
		// Skip on platforms where symlink creation is not supported
		// or requires elevated privileges (notably Windows without
		// Developer Mode, which surfaces "A required privilege is
		// not held by the client" / "operation not supported"). The
		// generator logic this test guards is platform-independent;
		// the symlink scenario is only exercisable where the OS
		// allows the test harness to create one.
		msg := err.Error()
		if strings.Contains(msg, "operation not supported") ||
			strings.Contains(msg, "permission denied") ||
			strings.Contains(msg, "A required privilege") ||
			strings.Contains(msg, "not implemented") ||
			strings.Contains(msg, "not permitted") {
			t.Skipf("os.Symlink unsupported in this environment: %v", err)
		}
		t.Fatalf("symlink: %v", err)
	}
	candidate := filepath.Join(linkPath, "newdir")
	if _, err := resolveWriteRoot(candidate, committedFixturesRoot); err == nil {
		t.Fatalf("resolveWriteRoot accepted symlinked-ancestor path %q (resolves into committed root)", candidate)
	} else if !strings.Contains(err.Error(), "is inside committed fixtures root") {
		t.Fatalf("resolveWriteRoot symlink-ancestor err=%q, want substring %q", err.Error(), "is inside committed fixtures root")
	}
}

// TestGenerator_MustResolveWriteRootPositivePaths exercises the
// accept paths for mustResolveWriteRoot — the absolute-cleaned
// pass-through and the empty-string fall-back to the committed root.
//
// The reject paths (relative --output-dir, alias of committed root,
// symlink-resolved alias of committed root) all go through fatalf
// which calls os.Exit and cannot be exercised from the same process
// without subprocess wrapping. Those paths are documented in the
// mustResolveWriteRoot docstring in runtime.go and exercised via
// manual operator smoke; the documented contract is also enforced by
// TestGenerator_OutputDirContainmentNoCommittedWrite, which verifies
// committed fixtures are not mutated when --output-dir is supplied.
func TestGenerator_MustResolveWriteRootPositivePaths(t *testing.T) {
	tmp := t.TempDir()
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	got := mustResolveWriteRoot(tmp, committedFixturesRoot)
	if got != filepath.Clean(tmp) {
		t.Fatalf("mustResolveWriteRoot(%q)=%q, want %q", tmp, got, filepath.Clean(tmp))
	}
	// Empty string falls back to committed root (default mutating mode).
	if got := mustResolveWriteRoot("", committedFixturesRoot); got != committedFixturesRoot {
		t.Fatalf("mustResolveWriteRoot(\"\")=%q, want %q (default mode)", got, committedFixturesRoot)
	}
}

// collectGeneratorOutput walks root and returns a map keyed by the
// path RELATIVE TO root, with file bytes as values. Used by
// determinism / cwd-independence assertions to compare two output
// trees byte-for-byte.
func collectGeneratorOutput(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := make(map[string][]byte)
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// #nosec G304 -- path comes from filepath.Walk under test-owned root.
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = raw
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", root, walkErr)
	}
	return out
}

// TestCoreExtAllowedSuiteID_Contract exercises the error-returning
// helper across the full happy / negative case matrix without
// subprocess-wrapping the CLI fatalf path. It pins the contract that
// the helper rejects every shape that is not "exactly one bound
// profile with exactly one allowed suite that fits in a byte and is
// not SENTINEL". The CLI-boundary fatalf wrapper
// (mustCoreExtAllowedSuiteID) is exercised separately by the
// generator-output integration test below.
func TestCoreExtAllowedSuiteID_Contract(t *testing.T) {
	t.Parallel()
	mkVector := func(profiles any) map[string]any {
		return map[string]any{
			"id":                "synthetic",
			"core_ext_profiles": profiles,
		}
	}
	cases := []struct {
		name        string
		input       map[string]any
		wantSuite   byte
		wantErrSubs string // substring expected in error; empty = no error
	}{
		{
			name:      "happy single bound profile, single allowed suite",
			input:     mkVector([]any{map[string]any{"allowed_suite_ids": []any{float64(3)}}}),
			wantSuite: 0x03,
		},
		{
			name:        "zero bound profiles",
			input:       mkVector([]any{}),
			wantErrSubs: "exactly one bound profile",
		},
		{
			name: "two bound profiles",
			input: mkVector([]any{
				map[string]any{"allowed_suite_ids": []any{float64(3)}},
				map[string]any{"allowed_suite_ids": []any{float64(4)}},
			}),
			wantErrSubs: "exactly one bound profile",
		},
		{
			name:        "missing allowed_suite_ids",
			input:       mkVector([]any{map[string]any{}}),
			wantErrSubs: "non-empty JSON array",
		},
		{
			name:        "empty allowed_suite_ids",
			input:       mkVector([]any{map[string]any{"allowed_suite_ids": []any{}}}),
			wantErrSubs: "non-empty JSON array",
		},
		{
			name:        "multi-element allowed_suite_ids",
			input:       mkVector([]any{map[string]any{"allowed_suite_ids": []any{float64(3), float64(4)}}}),
			wantErrSubs: "exactly one suite",
		},
		{
			name:        "out-of-byte allowed_suite_ids[0]",
			input:       mkVector([]any{map[string]any{"allowed_suite_ids": []any{float64(256)}}}),
			wantErrSubs: "single suite_id byte",
		},
		{
			name:        "sentinel allowed_suite_ids[0]",
			input:       mkVector([]any{map[string]any{"allowed_suite_ids": []any{float64(0)}}}),
			wantErrSubs: "SENTINEL",
		},
		{
			name:        "non-integral allowed_suite_ids[0]",
			input:       mkVector([]any{map[string]any{"allowed_suite_ids": []any{1.5}}}),
			wantErrSubs: "uint32-compatible JSON number",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coreExtAllowedSuiteID("synthetic", tc.input)
			if tc.wantErrSubs == "" {
				if err != nil {
					t.Fatalf("happy path err=%v, want nil", err)
				}
				if got != tc.wantSuite {
					t.Fatalf("happy path got=0x%02x, want 0x%02x", got, tc.wantSuite)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (suite=0x%02x)", tc.wantErrSubs, got)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubs) {
				t.Fatalf("err=%q, want substring %q", err.Error(), tc.wantErrSubs)
			}
		})
	}
}

// TestGenerator_CoreExtRealBindingWitnessSuiteFromVectorContract
// is the focused regression test for rubin-protocol#1382. It proves
// that `updateCoreExtRealBindingVector` emits a witness suite_id
// that matches the vector's `core_ext_profiles[0].allowed_suite_ids`
// contract instead of a hardcoded ML-DSA-87 default. Concretely,
// CV-U-EXT-05 in the committed CV-UTXO-BASIC.json pins
// `allowed_suite_ids: [3]`, so the regenerated tx_hex MUST encode a
// witness with suite_id byte == 0x03; the prior generator
// hardcoded 0x01, which the runtime rejects with
// TX_ERR_SIG_ALG_INVALID once deterministic regen brings the bytes
// back to current generator output.
//
// The test runs the generator under --output-dir against a temp
// directory so the committed fixture tree under
// conformance/fixtures/** is NEVER touched, satisfying issue
// #1382's "no fixture content regeneration in this PR" boundary.
func TestGenerator_CoreExtRealBindingWitnessSuiteFromVectorContract(t *testing.T) {
	skipIfMLDSA87DERUnavailable(t)
	tmp := t.TempDir()

	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	committedFixturesRoot := filepath.Join(repoRoot, "conformance", "fixtures")
	committedSamples := []string{"CV-UTXO-BASIC.json"}
	beforeContents := make(map[string][]byte, len(committedSamples))
	for _, rel := range committedSamples {
		full := filepath.Join(committedFixturesRoot, rel)
		// #nosec G304 -- repo-rooted, static allowlist.
		data, readErr := os.ReadFile(full)
		if readErr != nil {
			t.Fatalf("read %s before generator: %v", rel, readErr)
		}
		beforeContents[rel] = data
	}

	runGeneratorCLIWithArgs([]string{"-output-dir", tmp})

	// Containment: committed CV-UTXO-BASIC.json must remain
	// byte-identical (no fixture regen in this PR).
	for _, rel := range committedSamples {
		full := filepath.Join(committedFixturesRoot, rel)
		// #nosec G304 -- same allowlist.
		afterData, readErr := os.ReadFile(full)
		if readErr != nil {
			t.Fatalf("read %s after generator: %v", rel, readErr)
		}
		if !bytes.Equal(afterData, beforeContents[rel]) {
			t.Fatalf("--output-dir mode mutated committed %s", rel)
		}
	}

	// Read the candidate CV-UTXO-BASIC.json from the temp output
	// and assert CV-U-EXT-05's witness suite_id matches the
	// vector's allowed_suite_ids contract (0x03). Decoding the
	// witness from tx_hex avoids a brittle hex-byte scan: parse the
	// candidate JSON, locate CV-U-EXT-05, decode the tx, read the
	// first witness item's SuiteID field.
	candidatePath := filepath.Join(tmp, "CV-UTXO-BASIC.json")
	// #nosec G304 -- candidate path under t.TempDir().
	candidateBytes, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatalf("read candidate %s: %v", candidatePath, err)
	}
	var candidate fixtureFile
	if err := json.Unmarshal(candidateBytes, &candidate); err != nil {
		t.Fatalf("unmarshal candidate %s: %v", candidatePath, err)
	}
	v := findVector(&candidate, "CV-U-EXT-05")
	wantSuite := mustCoreExtAllowedSuiteID("CV-U-EXT-05", v)
	if wantSuite != 0x03 {
		t.Fatalf("CV-U-EXT-05 vector contract changed: allowed_suite_ids[0]=%d, want 3 (test premise)", wantSuite)
	}
	txHex, ok := v["tx_hex"].(string)
	if !ok {
		t.Fatalf("CV-U-EXT-05 candidate missing tx_hex")
	}
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatalf("CV-U-EXT-05 candidate tx_hex decode: %v", err)
	}
	tx, _, _, _, err := consensus.ParseTx(txBytes)
	if err != nil {
		t.Fatalf("CV-U-EXT-05 candidate consensus.ParseTx: %v", err)
	}
	if len(tx.Witness) != 1 {
		t.Fatalf("CV-U-EXT-05 candidate must have exactly one witness item, got %d", len(tx.Witness))
	}
	if got := tx.Witness[0].SuiteID; got != wantSuite {
		t.Fatalf(
			"CV-U-EXT-05 candidate witness suite_id mismatch: got 0x%02x, want 0x%02x (vector pins allowed_suite_ids=[%d])",
			got, wantSuite, wantSuite,
		)
	}
}

// skipIfMLDSA87DERUnavailable probes whether the runtime OpenSSL
// build can decode the embedded ML-DSA-87 PKCS#8 DER format used by
// the conformance fixture generator. On builds where the ML-DSA
// provider is missing or the OID decoder is not registered (observed
// on OpenSSL 3.0.x), `consensus.NewMLDSA87KeypairFromDER` returns an
// error containing `unsupported` / `DECODER`; this helper turns that
// failure mode into a `t.Skipf` so the test suite stays clean across
// supported toolchains. Mirrors the package-wide `mustMLDSA87Keypair`
// skip convention used by `clients/go/consensus` capability-dependent
// tests.
func skipIfMLDSA87DERUnavailable(t *testing.T) {
	t.Helper()
	der, err := embeddedTestKeysFS.ReadFile(filepath.ToSlash(filepath.Join("testdata", "keys", "owner.der")))
	if err != nil {
		t.Fatalf("embedded testdata/keys/owner.der missing: %v", err)
	}
	kp, err := consensus.NewMLDSA87KeypairFromDER(der)
	if err == nil {
		kp.Close()
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "unsupported") || strings.Contains(msg, "DECODER") {
		t.Skipf("ML-DSA-87 DER decoder unavailable in this OpenSSL build (OpenSSL ≥3.5 with ML-DSA provider required): %v", err)
	}
	t.Fatalf("NewMLDSA87KeypairFromDER (probe) unexpected error: %v", err)
}
