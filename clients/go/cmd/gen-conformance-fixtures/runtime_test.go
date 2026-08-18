package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

func TestDecodeFixtureRejectsTrailingContentAndKeepsExactIntegers(t *testing.T) {
	valid := []byte(`{"gate":"CV-X","vectors":[{"fee":18446744073709551615}]}`)
	f, err := decodeFixture(valid)
	if err != nil {
		t.Fatalf("decodeFixture(valid): %v", err)
	}
	// UseNumber, not float64: the u64-max literal must survive verbatim.
	if got := f.Vectors[0]["fee"]; got != json.Number("18446744073709551615") {
		t.Fatalf("fee decoded as %#v, want exact json.Number", got)
	}
	// A single Decode stops after the first value, so every one of these was
	// accepted before the trailing-content check and then silently dropped on
	// the way back out.
	trailing := []struct {
		name string
		body string
	}{
		{"second object", `{"gate":"CV-X","vectors":[]} {"gate":"CV-Y","vectors":[]}`},
		{"stray brace", `{"gate":"CV-X","vectors":[]} }`},
		{"stray number", `{"gate":"CV-X","vectors":[]} 1`},
		{"garbage", `{"gate":"CV-X","vectors":[]} not-json`},
	}
	for _, tc := range trailing {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeFixture([]byte(tc.body)); err == nil {
				t.Fatalf("decodeFixture accepted trailing content: %s", tc.body)
			}
		})
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
		newVector("CV-SUB-SUPPLY-U128-01", 1, map[string]any{
			"op": "stale", "height": float64(1), "already_generated": "stale",
			"expect_ok": false, "expect_err": "STALE", "expected_target": "stale", "stale_extra": true,
		}),
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

	subsidyRaw, err := os.ReadFile(filepath.Join(fixturesDir, "CV-SUBSIDY.json"))
	if err != nil {
		t.Fatalf("read CV-SUBSIDY.json: %v", err)
	}
	subsidyFixture, err := decodeFixture(subsidyRaw)
	if err != nil {
		t.Fatalf("decode CV-SUBSIDY.json: %v", err)
	}
	vectorByID := make(map[string]map[string]any, len(subsidyFixture.Vectors))
	for _, vector := range subsidyFixture.Vectors {
		id, ok := vector["id"].(string)
		if !ok || id == "" {
			t.Fatalf("generated subsidy vector has empty or non-string id: %#v", vector["id"])
		}
		if _, exists := vectorByID[id]; exists {
			t.Fatalf("duplicate generated subsidy vector id %q", id)
		}
		if strings.HasPrefix(id, "CV-SUB-SUPPLY-U128-") && id != "CV-SUB-SUPPLY-U128-01" &&
			id != "CV-SUB-SUPPLY-U128-02" && id != "CV-SUB-SUPPLY-U128-03" {
			t.Fatalf("unexpected generated supply vector id %q", id)
		}
		vectorByID[id] = vector
	}
	for _, id := range []string{"CV-SUB-01", "CV-SUB-02"} {
		if got := vectorByID[id]["already_generated"]; got != json.Number("0") {
			t.Fatalf("%s already_generated=%#v, want exact numeric token 0", id, got)
		}
	}
	assertSupplyFields := func(id string, want map[string]any) {
		t.Helper()
		vector, ok := vectorByID[id]
		if !ok {
			t.Fatalf("missing generated vector %s", id)
		}
		for field, expected := range want {
			if got := vector[field]; got != expected {
				t.Fatalf("%s.%s=%#v, want %#v", id, field, got, expected)
			}
		}
		if blockHex, _ := vector["block_hex"].(string); blockHex == "" {
			t.Fatalf("%s missing generated block_hex", id)
		}
	}
	assertSupplyFields("CV-SUB-SUPPLY-U128-01", map[string]any{
		"op":                          "connect_block_basic",
		"height":                      json.Number("5771107"),
		"expected_target":             nil,
		"already_generated":           "18446744073699181041",
		"expect_ok":                   true,
		"expect_already_generated":    "18446744073699181041",
		"expect_already_generated_n1": "18446744073718206916",
	})
	for _, field := range []string{"expect_err", "stale_extra"} {
		if _, exists := vectorByID["CV-SUB-SUPPLY-U128-01"][field]; exists {
			t.Fatalf("authoritative supply vector retained stale field %q", field)
		}
	}
	assertSupplyFields("CV-SUB-SUPPLY-U128-02", map[string]any{
		"already_generated":           json.Number("18446744073709551615"),
		"expect_already_generated":    "18446744073709551615",
		"expect_already_generated_n1": "18446744073728577490",
	})
	assertSupplyFields("CV-SUB-SUPPLY-U128-03", map[string]any{
		"already_generated": "340282366920938463463374607431768211455",
		"expect_err":        "BLOCK_ERR_PARSE",
	})
	if !bytes.Contains(subsidyRaw, []byte(`"already_generated": 18446744073709551615`)) {
		t.Fatal("legacy u64-max already_generated token was quoted or rounded")
	}
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
		"CV-VAULT.json",
		"CV-HTLC.json",
		"CV-SUBSIDY.json",
		filepath.Join("devnet", "devnet-vault-create-01.json"),
		filepath.Join("devnet", "devnet-htlc-claim-01.json"),
		filepath.Join("devnet", "devnet-multisig-spend-01.json"),
		filepath.Join("protocol", "canonical_pipeline_v1.json"),
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

// TestCanonicalPipelineCoverageReceiptIsCompleteAndClosed is the RUB-922
// coverage receipt assertion: every enumerated class (the closed taxonomy plus
// every named observable, accepted, rejected and hostile bullet of the
// contract) maps to at least one row, and every row stays inside the closed
// taxonomy and class set. A generator that silently dropped
// ORPHAN_ALREADY_RETAINED or TERMINAL_LOCAL_INVARIANT would pass the drift and
// policy gates; it fails here.
func TestCanonicalPipelineCoverageReceiptIsCompleteAndClosed(t *testing.T) {
	rows := canonicalPipelineRows()
	if len(rows) != 62 {
		t.Fatalf("canonical pipeline corpus has %d rows, want the frozen 62 (bump deliberately with a corpus revision)", len(rows))
	}
	// canonicalPipelineCoverage exits on a class with zero rows and otherwise
	// returns exactly one entry per enumerated class, so this count guard fires
	// only on a duplicate entry in canonicalPipelineClasses itself.
	if receipt := canonicalPipelineCoverage(rows); len(receipt) != len(canonicalPipelineClasses) {
		t.Fatalf("coverage receipt has %d classes, want %d", len(receipt), len(canonicalPipelineClasses))
	}
	mustValidateCanonicalPipelineRows(rows)
}

// TestCanonicalPipelinePendingOwnerRowsAreFrozen pins the exact `pending_owner`
// map (the observation rows among them are the RUB-926 exclusions). Adding an
// exclusion silently would hide a real Go/Rust divergence behind a pending owner.
func TestCanonicalPipelinePendingOwnerRowsAreFrozen(t *testing.T) {
	want := map[string]string{
		"C01-RELAY-STORED-001":           pendingOwnerRUB1195,
		"C01-RELAY-ACCEPTED-001":         pendingOwnerRUB1195,
		"C01-RES-IDENTITIES-PENDING-001": pendingOwnerRUB893,
		"C01-WIRE-OVERFLOW-001":          pendingOwnerRUB893,
		"C01-BUSY-001":                   pendingOwnerRUB910,
		"C01-BUDGET-RACE-001":            pendingOwnerRUB893,
		"C01-INVENTORY-RECLAIMED-001":    pendingOwnerRUB910,
		"C01-ORPH-DUP-001":               pendingOwnerRUB910,
		"C01-ORPH-OVERSIZE-001":          pendingOwnerRUB910,
		"C01-ORPH-SOURCE51-001":          pendingOwnerRUB910,
	}
	got := make(map[string]string)
	for _, row := range canonicalPipelineRows() {
		if row.PendingOwner != "" {
			got[row.ID] = row.PendingOwner
		}
	}
	if !maps.Equal(got, want) {
		t.Fatalf("pending-owner rows = %v, want %v", got, want)
	}
}

func TestCanonicalPipelineObservationDetailNeverCarriesEffectKeys(t *testing.T) {
	rows := canonicalPipelineRows()
	effectKeys := make(map[string]bool)
	for _, row := range rows {
		for k := range row.Effects {
			effectKeys[k] = true
		}
	}
	for _, row := range rows {
		for _, k := range slices.Sorted(maps.Keys(row.Detail)) {
			if row.Kind == "observation" && effectKeys[k] {
				t.Errorf("%s: detail carries compared effect key %q", row.ID, k)
			}
		}
	}
}

// TestCanonicalPipelineCorpusIsByteDeterministic proves the corpus writer is
// reproducible: two writes into different directories are byte-identical and
// never carry the authoring-only covers field.
func TestCanonicalPipelineCorpusIsByteDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "canonical_pipeline_v1.json")
	second := filepath.Join(t.TempDir(), "canonical_pipeline_v1.json")
	mustWriteCanonicalPipelineCorpus(first)
	mustWriteCanonicalPipelineCorpus(second)
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("canonical pipeline corpus is not byte-deterministic across runs")
	}
	if bytes.Contains(a, []byte(`"covers"`)) {
		t.Fatal("emitted corpus leaked the authoring-only covers field")
	}
}

func TestCanonicalPipelineResultPatternIsClosed(t *testing.T) {
	want := map[string]bool{"ACCEPTED(extra)": false, "KNOWN_BLOCK_NOOP(OTHER)": false, "TERMINAL_PERSISTENCE": false, "LOCAL_RESOURCE_UNAVAILABLE(bogus)": false, "CONSENSUS_INVALID()": false, "bogus": false, "ACCEPTED\n": false, "ACCEPTED": true, "KNOWN_BLOCK_NOOP(CANONICAL)": true}
	for s, ok := range want {
		if got := canonicalPipelineResultRE.MatchString(s); got != ok {
			t.Errorf("MatchString(%q) = %v, want %v", s, got, ok)
		}
	}
}

// TestCanonicalPipelineValidatorFailsClosed re-execs the test binary so every
// generator fatalf path (each calls os.Exit) is observable as a child exit code
// carrying its own message, mirroring cmd/formal-trace.TestMainExitCodeIs2OnError.
// The cases below cover all eight canonical-pipeline fatalf branches; bad_prefix
// and duplicate_id share one message and are both exercised.
func TestCanonicalPipelineValidatorFailsClosed(t *testing.T) {
	if c := os.Getenv("CP_NEGATIVE_CASE"); c != "" {
		rows := canonicalPipelineRows()
		if c == "zero_class" {
			const drop = "accepted:lazy_memoized_provider" // sole row: C01-PROVIDER-001
			canonicalPipelineCoverage(slices.DeleteFunc(rows, func(r cpRow) bool { return slices.Contains(r.Covers, drop) }))
			return
		}
		obs := slices.IndexFunc(rows, func(r cpRow) bool { return r.Kind == "observation" }) // rows[0] is authority: never Result- or CommitTruth-checked
		switch c {
		case "duplicate_id":
			rows = append(rows, rows[0])
		case "bad_prefix":
			rows[0].ID = "X01-BAD"
		case "no_covers":
			rows[0].Covers = nil
		case "unknown_class":
			rows[0].Covers = []string{"bogus:class"}
		case "duplicate_cover":
			rows[0].Covers = append(rows[0].Covers, rows[0].Covers[0])
		case "unknown_kind":
			rows[0].Kind = "conjecture"
		case "bad_result":
			rows[obs].Result = "ACCEPTED(extra)"
		case "unknown_truth":
			rows[obs].CommitTruth = "MAYBE"
		}
		mustValidateCanonicalPipelineRows(rows)
		return
	}
	for _, c := range []struct{ name, want string }{
		{"zero_class", "maps to zero rows"},
		{"duplicate_id", "must start with C01- and be unique"},
		{"bad_prefix", "must start with C01- and be unique"},
		{"no_covers", "covers no enumerated class"},
		{"unknown_class", "covers unknown class"},
		{"duplicate_cover", "twice"},
		{"unknown_kind", "has unknown kind"},
		{"bad_result", "outside the closed taxonomy"},
		{"unknown_truth", "commit truth"},
	} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=TestCanonicalPipelineValidatorFailsClosed") //nolint:gosec // re-exec of the test binary with fixed args
		cmd.Env = append(os.Environ(), "CP_NEGATIVE_CASE="+c.name)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			t.Fatalf("case %s: expected non-zero exit, stderr=%s", c.name, stderr.String())
		} else if got := stderr.String(); !strings.Contains(got, "fatal: canonical pipeline: ") || !strings.Contains(got, c.want) {
			t.Fatalf("case %s: stderr = %q, want a canonical-pipeline fatal containing %q", c.name, got, c.want)
		}
	}
}

// TestCanonicalPipelineV2ParentPairIsByteFrozen makes the RUB-1207 "the R1 pair
// is a byte-frozen read-only parent" clause executable: the pins the v2 _meta
// publishes are recomputed from the committed files, so any byte change to
// either parent fails here rather than silently re-parenting the revision.
func TestCanonicalPipelineV2ParentPairIsByteFrozen(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	for _, c := range []struct{ rel, want string }{
		{"conformance/fixtures/protocol/canonical_pipeline_v1.json", cp2ParentArtifactSHA},
		{"conformance/schemas/cv-canonical-pipeline-v1.json", cp2ParentSchemaSHA},
	} {
		raw, readErr := os.ReadFile(filepath.Join(repoRoot, c.rel))
		if readErr != nil {
			t.Fatalf("read %s: %v", c.rel, readErr)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != c.want {
			t.Fatalf("%s sha256 = %s, want the frozen parent pin %s", c.rel, got, c.want)
		}
	}
}

// TestCanonicalPipelineV2RegistryIsFrozen pins the C01-R2 identity map: the 62
// inherited (row_id, kind) pairs must equal the byte-frozen v1 corpus exactly
// and the 17 R2 rows must equal the closure-authorized constant list. A rename,
// removal, kind change or unauthorized addition on either side fails here, as
// does a collision that would silently shrink the merged map.
func TestCanonicalPipelineV2RegistryIsFrozen(t *testing.T) {
	registry := cp2RowRegistry()
	want := make(map[string]string, cp2RegistrySize)
	for _, row := range canonicalPipelineRows() {
		want[row.ID] = row.Kind
	}
	if len(want) != cp2RegistrySize-len(cp2NewRows) {
		t.Fatalf("inherited corpus has %d identities, want 62", len(want))
	}
	maps.Copy(want, cp2NewRows)
	if !maps.Equal(registry, want) {
		t.Fatal("row registry is not the inherited v1 identities plus the closure-authorized R2 rows")
	}
}

// TestCanonicalPipelineV2CommitTruthRelationIsExact checks the spec 6.4.1
// relation against the 62 merged R1 rows themselves, not against a restatement
// of the table: every observation row's (result, commit_truth) pair must be the
// one cp2CommitTruthFor derives, and the relation must be total on the closed
// taxonomy.
func TestCanonicalPipelineV2CommitTruthRelationIsExact(t *testing.T) {
	for _, row := range canonicalPipelineRows() {
		if row.Kind != "observation" {
			continue
		}
		truth, ok := cp2CommitTruthFor(row.Result)
		if !ok {
			t.Errorf("%s: result %q is unmapped by the 6.4.1 relation", row.ID, row.Result)
		} else if truth != row.CommitTruth {
			t.Errorf("%s: relation maps %q to %s, but the merged R1 row states %s", row.ID, row.Result, truth, row.CommitTruth)
		}
	}
	if _, ok := cp2CommitTruthFor("ACCEPTED(extra)"); ok {
		t.Error("a malformed result must not resolve to a commit truth")
	}
}

func cp2Ptr[T any](v T) *T { return &v }

// cp2ValidCase is the known-valid control every RUB-1207 negative mutates in
// exactly one dimension.
func cp2ValidCase() cp2Case {
	return cp2Case{CaseID: "MAIN", Expected: cp2Expected{
		Result: cp2Ptr("ACCEPTED"), CommitTruth: "NEW",
		RPC: cp2RPC{
			Class: "MINED_200_COMMITTED", HTTP: cp2Ptr(200), CommitState: cp2Ptr("committed"),
			Mined: "true", SuccessIdentity: "present", Phase: "result_selecting_mined_candidate",
		},
	}}
}

// TestCanonicalPipelineV2ValidatorFailsClosed drives the RUB-1207 mutation set:
// row-id substitution, kind change, a wrong result/truth relation, malformed RPC
// shape and a machine token carrying whitespace. Each case changes exactly one
// dimension of the control and asserts the specific reason.
func TestCanonicalPipelineV2ValidatorFailsClosed(t *testing.T) {
	registry := cp2RowRegistry()
	if err := cp2ValidateRows([]cp2Row{{RowID: "C01-DIRECT-001", Kind: "observation", Cases: []cp2Case{cp2ValidCase()}}}, registry); err != nil {
		t.Fatalf("control row must validate: %v", err)
	}
	dup := cp2Row{RowID: "C01-DIRECT-001", Kind: "observation", Cases: []cp2Case{cp2ValidCase()}}
	if err := cp2ValidateRows([]cp2Row{dup, dup}, registry); err == nil || !strings.Contains(err.Error(), "duplicate row id") {
		t.Errorf("two rows sharing an id: error = %v, want a duplicate row id rejection", err)
	}
	mutate := map[string]func(*cp2Row){
		"row id substitution":  func(r *cp2Row) { r.RowID = "C01-DIRECT-002" },
		"kind change":          func(r *cp2Row) { r.Kind = "authority" },
		"wrong result truth":   func(r *cp2Row) { r.Cases[0].Expected.CommitTruth = "OLD" },
		"result off taxonomy":  func(r *cp2Row) { r.Cases[0].Expected.Result = cp2Ptr("ACCEPTED(extra)") },
		"unknown commit truth": func(r *cp2Row) { r.Cases[0].Expected.CommitTruth = "MAYBE" },
		"rpc class":            func(r *cp2Row) { r.Cases[0].Expected.RPC.Class = "MINED_201_COMMITTED" },
		"rpc mined":            func(r *cp2Row) { r.Cases[0].Expected.RPC.Mined = "yes" },
		"rpc http":             func(r *cp2Row) { r.Cases[0].Expected.RPC.HTTP = cp2Ptr(418) },
		"rpc commit state":     func(r *cp2Row) { r.Cases[0].Expected.RPC.CommitState = cp2Ptr("maybe_committed") },
		"rpc error class":      func(r *cp2Row) { r.Cases[0].Expected.RPC.ErrorClass = cp2Ptr("LOCAL BUSY") },
		"token whitespace":     func(r *cp2Row) { r.Cases[0].CaseID = "MAIN CASE" },
		"class tuple":          func(r *cp2Row) { r.Cases[0].Expected.RPC.HTTP = cp2Ptr(503) },
		"wire truth": func(r *cp2Row) {
			r.Cases[0].Expected.Result, r.Cases[0].Expected.PipelineReached, r.Cases[0].Expected.WireDisposition = nil, cp2Ptr(false), cp2Ptr("CHECKSUM_REJECT")
		},
		"duplicate pointer": func(r *cp2Row) {
			p := cp2Input{Pointer: "/input/b", Type: "token", Provenance: "witness_fixture"}
			r.Cases[0].Input = []cp2Input{p, p}
		},
		"duplicate case id":    func(r *cp2Row) { r.Cases = append(r.Cases, r.Cases[0]) },
		"missing reached flag": func(r *cp2Row) { r.Cases[0].Expected.Result = nil },
		"surplus reached flag": func(r *cp2Row) { r.Cases[0].Expected.PipelineReached = cp2Ptr(false) },
	}
	want := map[string]string{
		"row id substitution": "is not a frozen registry pair", "kind change": "is not a frozen registry pair",
		"wrong result truth": "requires commit truth NEW", "result off taxonomy": "outside the closed taxonomy",
		"unknown commit truth": "commit truth \"MAYBE\" is unknown", "rpc class": "rpc_projection.class",
		"rpc mined": "rpc_projection.mined", "rpc http": "rpc_projection.http",
		"rpc commit state": "rpc_projection.commit_state", "rpc error class": "neither a taxonomy token",
		"token whitespace": "is not a machine token", "class tuple": "requires [result_selecting_mined_candidate 200",
		"wire truth": "wire_disposition requires commit truth OLD", "duplicate pointer": "duplicate input pointer /input/b", "duplicate case id": "duplicate case id",
		"missing reached flag": "null result requires pipeline_reached",
		"surplus reached flag": "only when result is null",
	}
	for name, apply := range mutate {
		row := cp2Row{RowID: "C01-DIRECT-001", Kind: "observation", Cases: []cp2Case{cp2ValidCase()}}
		apply(&row)
		err := cp2ValidateRows([]cp2Row{row}, registry)
		if err == nil {
			t.Errorf("%s: expected a fail-closed rejection", name)
		} else if !strings.Contains(err.Error(), want[name]) {
			t.Errorf("%s: error = %q, want it to name %q", name, err, want[name])
		}
	}
}

// TestCanonicalPipelineV2AliasesResolveInFixtures pins the one rule JSON Schema
// cannot express: an alias must exist in the catalog. Until RUB-1208 populates
// `fixtures`, an alias-carrying row is rejected — the intended fail-closed order.
func TestCanonicalPipelineV2AliasesResolveInFixtures(t *testing.T) {
	c := cp2ValidCase()
	c.Input = []cp2Input{{
		Pointer: "/input/stimulus_block", Type: "alias", ValueOrAlias: "B1",
		Provenance: "normative_boundary", ProductionSetupSink: "node.Miner.MineOne", ConsumptionProofOwner: "RUB-923",
	}}
	rows := []cp2Row{{RowID: "C01-DIRECT-001", Kind: "observation", Cases: []cp2Case{c}}}
	block := map[string]cp2Fixture{"B1": {Type: "object", Value: cpMap{"height": 1}}}
	err := cp2ValidateAliases(rows, map[string]cp2Fixture{})
	if err == nil || !strings.Contains(err.Error(), `alias "B1"`) {
		t.Fatalf("empty catalog: error = %v, want a rejection naming alias B1", err)
	}
	if err := cp2ValidateAliases(rows, block); err != nil {
		t.Fatalf("catalog carrying B1 must validate: %v", err)
	}
	// A pointer tagged u64 may not resolve to an object fixture.
	rows[0].Cases[0].Input[0].Type = "u64"
	if err := cp2ValidateAliases(rows, block); err == nil || !strings.Contains(err.Error(), "is a object fixture, want u64") {
		t.Fatalf("type mismatch: error = %v, want the fixture type named", err)
	}
	// A token tag carries a machine token, never a catalog alias.
	rows[0].Cases[0].Input[0].Type, rows[0].Cases[0].Input[0].ValueOrAlias = "token", "ABSENT"
	if err := cp2ValidateAliases(rows, map[string]cp2Fixture{}); err != nil {
		t.Fatalf("token input must not demand a fixture: %v", err)
	}
}

// TestCanonicalPipelineV2GoSchemaParity pins every closed list the generator
// keeps against the committed schema: one vocabulary, two copies, no drift.
func TestCanonicalPipelineV2GoSchemaParity(t *testing.T) {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(repoRoot, cp2SchemaRel))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	list := func(path ...string) []string {
		node := any(schema)
		for _, key := range path {
			node = node.(map[string]any)[key]
		}
		out := []string{}
		for _, v := range node.([]any) {
			if v != nil { // http carries an explicit null the Go list does not
				out = append(out, fmt.Sprint(v))
			}
		}
		return out
	}
	rpc := []string{"$defs", "rpcProjection", "properties"}
	httpValues := []string{}
	for _, v := range cp2HTTPValues {
		httpValues = append(httpValues, strconv.Itoa(v))
	}
	for name, pair := range map[string][2][]string{
		"class":            {cp2RPCClasses, list(append(rpc, "class", "enum")...)},
		"mined":            {cp2MinedValues, list(append(rpc, "mined", "enum")...)},
		"success_identity": {cp2SuccessIdentityValues, list(append(rpc, "success_identity", "enum")...)},
		"commit_state":     {cp2CommitStateValues, list(append(rpc, "commit_state", "enum")...)},
		"phase":            {cp2PhaseValues, list(append(rpc, "phase", "enum")...)},
		"http":             {httpValues, list(append(rpc, "http", "enum")...)},
		"inputType":        {cp2InputTypes, list("$defs", "inputType", "enum")},
		"provenance":       {cp2Provenances, list("$defs", "inputPointer", "properties", "provenance", "enum")},
		"wire_disposition": {cp2WireDispositionValues, list("properties", "wire_disposition_values", "const")},
		"recovery_outcome": {cp2RecoveryOutcomeValues, list("properties", "recovery_outcome_values", "const")},
	} {
		if got, want := slices.Sorted(slices.Values(pair[0])), slices.Sorted(slices.Values(pair[1])); !slices.Equal(got, want) {
			t.Errorf("%s: generator %v, schema %v", name, got, want)
		}
	}
	registry := map[string]string{}
	for id, kind := range schema["properties"].(map[string]any)["row_registry"].(map[string]any)["const"].(map[string]any) {
		registry[id] = fmt.Sprint(kind)
	}
	if !maps.Equal(registry, cp2RowRegistry()) {
		t.Error("row_registry const and the generator registry disagree")
	}
}

// TestCanonicalPipelineV2CorpusIsByteDeterministic proves the dormant revision
// is reproducible and carries neither retired v1 field.
func TestCanonicalPipelineV2CorpusIsByteDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "canonical_pipeline_v2.json")
	second := filepath.Join(t.TempDir(), "canonical_pipeline_v2.json")
	mustWriteCanonicalPipelineV2Corpus(first)
	mustWriteCanonicalPipelineV2Corpus(second)
	a, err := os.ReadFile(first)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	b, err := os.ReadFile(second)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("canonical pipeline v2 corpus is not byte-deterministic across runs")
	}
	for _, retired := range []string{`"pending_owner"`, `"detail"`, `"scenario"`} {
		if bytes.Contains(a, []byte(retired)) {
			t.Errorf("emitted v2 corpus carries the retired v1 field %s", retired)
		}
	}
	var artifact map[string]any
	if err := json.Unmarshal(a, &artifact); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	epoch, _ := artifact["_meta"].(map[string]any)["closure_epoch"].(map[string]any)
	if epoch["manifest_root_sha256"] != cp2ManifestRootSHA256 || epoch["status"] != cp2ClosureStatus {
		t.Fatalf("closure epoch = %v, want the bound RUB-1206 manifest identity in status %q", epoch, cp2ClosureStatus)
	}
}
