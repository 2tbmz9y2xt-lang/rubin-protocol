package main

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
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

	// Re-parse to drop cached state, then assert zero chain_id rejects.
	// Proof assertion: rejection under [32]byte{} zero chain_id; a nil
	// error here would mean the tx_hex validates under both devnet
	// and zero chain_id, contradicting the devnet-domain-bound
	// contract this artifact must satisfy.
	parsedTx2, _, _, _, err := consensus.ParseTx(rawTx)
	if err != nil {
		t.Fatalf("ParseTx (negative): %v", err)
	}
	zeroChainID := [32]byte{}
	if _, err := consensus.ApplyNonCoinbaseTxBasicWithMTP(parsedTx2, txid, utxoSet, height, blockTimestamp, blockMTP, zeroChainID); err == nil {
		t.Fatalf("ApplyNonCoinbaseTxBasicWithMTP(zero chain_id) unexpectedly accepted — artifact signature must NOT verify under zero chain_id, otherwise it is not exclusively devnet-domain-bound")
	}
}
