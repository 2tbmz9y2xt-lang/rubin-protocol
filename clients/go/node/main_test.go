package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rubin.dev/node/consensus"
)

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "clients")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("failed to locate repo root from wd=%q", wd)
	return ""
}

func withRepoRoot(t *testing.T, fn func(root string)) {
	t.Helper()
	root := findRepoRoot(t)
	old, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	fn(root)
}

func writeTempJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ctx.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write temp json: %v", err)
	}
	return path
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		_ = r.Close()
		done <- string(b)
	}()

	fn()

	_ = w.Close()
	return <-done
}

func TestExtractFencedHex_Inline(t *testing.T) {
	doc := "x\n`genesis_header_bytes`: `deadbeef`\n"
	got, err := extractFencedHex(doc, "genesis_header_bytes")
	if err != nil {
		t.Fatalf("extractFencedHex: %v", err)
	}
	if got != "deadbeef" {
		t.Fatalf("got=%q want=%q", got, "deadbeef")
	}
}

func TestExtractFencedHex_LegacyFence(t *testing.T) {
	doc := "genesis_tx_bytes\n```\n aabb \n```\n"
	got, err := extractFencedHex(doc, "genesis_tx_bytes")
	if err != nil {
		t.Fatalf("extractFencedHex: %v", err)
	}
	if strings.TrimSpace(got) != "aabb" {
		t.Fatalf("got=%q want=%q", got, "aabb")
	}
}

func TestResolveProfilePath_Basic(t *testing.T) {
	withRepoRoot(t, func(_ string) {
		got, err := resolveProfilePath(defaultChainProfile)
		if err != nil {
			t.Fatalf("resolveProfilePath: %v", err)
		}
		if !strings.Contains(got, string(filepath.Separator)+"spec"+string(filepath.Separator)) {
			t.Fatalf("expected resolved path inside spec/, got=%q", got)
		}
	})
}

func TestResolveProfilePath_RejectAbs(t *testing.T) {
	_, err := resolveProfilePath("/tmp/x")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestResolveProfilePath_RejectEscape(t *testing.T) {
	_, err := resolveProfilePath("../spec/x")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseTxIDHex(t *testing.T) {
	var txid [32]byte
	txid[0] = 1
	txid[31] = 2
	s := hex.EncodeToString(txid[:])
	got, err := parseTxIDHex(s)
	if err != nil {
		t.Fatalf("parseTxIDHex: %v", err)
	}
	if got != txid {
		t.Fatalf("mismatch")
	}
}

func TestParseBlockHeaderBytesStrict(t *testing.T) {
	_, err := parseBlockHeaderBytesStrict(make([]byte, 10))
	if err == nil {
		t.Fatalf("expected length error")
	}
	_, err = parseBlockHeaderBytesStrict(make([]byte, 116))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeriveChainID_DevnetProfile(t *testing.T) {
	withRepoRoot(t, func(_ string) {
		p, cleanup, err := loadCryptoProvider()
		if err != nil {
			t.Fatalf("loadCryptoProvider: %v", err)
		}
		defer cleanup()
		chainID, err := deriveChainID(p, defaultChainProfile)
		if err != nil {
			t.Fatalf("deriveChainID: %v", err)
		}
		if chainID == ([32]byte{}) {
			t.Fatalf("expected non-zero chainID")
		}
	})
}

func TestCmdTxIDWeightParse_HappyPath(t *testing.T) {
	// Minimal coinbase-like tx (valid parse/txid/weight; not meant to be applied).
	tx := &consensus.Tx{
		Version: 1,
		TxNonce: 0,
		Inputs: []consensus.TxInput{{
			PrevTxid:  [32]byte{},
			PrevVout:  consensus.TX_COINBASE_PREVOUT_VOUT,
			ScriptSig: nil,
			Sequence:  consensus.TX_COINBASE_PREVOUT_VOUT,
		}},
		Outputs: []consensus.TxOutput{{
			Value:        0,
			CovenantType: consensus.CORE_P2PK,
			CovenantData: make([]byte, 33),
		}},
		Locktime: 0,
		Witness:  consensus.WitnessSection{Witnesses: nil},
	}
	txHex := hex.EncodeToString(consensus.TxBytes(tx))

	_ = captureStdout(t, func() {
		if err := cmdTxID(txHex); err != nil {
			t.Fatalf("cmdTxID: %v", err)
		}
	})
	if w, err := cmdWeight(txHex); err != nil || w == 0 {
		t.Fatalf("cmdWeight: w=%d err=%v", w, err)
	}
	_ = captureStdout(t, func() {
		if err := cmdParse(txHex, 0); err != nil {
			t.Fatalf("cmdParse: %v", err)
		}
	})

	// Force witness overflow branch in cmdParse by using a tx with a non-empty witness section.
	tx2 := &consensus.Tx{
		Version:  1,
		TxNonce:  0,
		Inputs:   []consensus.TxInput{{PrevTxid: [32]byte{}, PrevVout: consensus.TX_COINBASE_PREVOUT_VOUT, Sequence: consensus.TX_COINBASE_PREVOUT_VOUT}},
		Outputs:  []consensus.TxOutput{{Value: 0, CovenantType: consensus.CORE_P2PK, CovenantData: make([]byte, 33)}},
		Locktime: 0,
		Witness: consensus.WitnessSection{Witnesses: []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
		}},
	}
	tx2Hex := hex.EncodeToString(consensus.TxBytes(tx2))
	_ = captureStdout(t, func() {
		if err := cmdParse(tx2Hex, 1); err == nil || err.Error() != consensus.TX_ERR_WITNESS_OVERFLOW {
			t.Fatalf("expected witness overflow, got: %v", err)
		}
	})
}

func TestCmdCompactSizeAndMapParseError(t *testing.T) {
	_ = captureStdout(t, func() {
		if err := cmdCompactSize("01"); err != nil {
			t.Fatalf("cmdCompactSize: %v", err)
		}
	})
	got := mapParseError(fmt.Errorf("parse: x"))
	if got == nil || got.Error() != "TX_ERR_PARSE" {
		t.Fatalf("mapParseError mismatch: %v", got)
	}
	got = mapParseError(fmt.Errorf("compactsize: x"))
	if got == nil || got.Error() != "TX_ERR_PARSE" {
		t.Fatalf("mapParseError mismatch: %v", got)
	}
	got = mapParseError(fmt.Errorf("other"))
	if got.Error() != "other" {
		t.Fatalf("expected passthrough, got: %v", got)
	}
}

func TestCmdCoinbaseSubsidy_EpochTransition(t *testing.T) {
	// Height at/after duration must return zero.
	sub, epoch := cmdCoinbaseSubsidy(0)
	if sub == 0 || epoch != 0 {
		t.Fatalf("expected subsidy>0 epoch=0 at height=0, got sub=%d epoch=%d", sub, epoch)
	}
	sub, epoch = cmdCoinbaseSubsidy(^uint64(0))
	if epoch != 1 {
		t.Fatalf("expected epoch=1 for huge height, got %d", epoch)
	}
}

func TestCmdApplyUTXO_MissingTxHex(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"chain_height":    0,
		"chain_timestamp": 0,
		"utxo_set":        []any{},
	})
	if err := cmdApplyUTXO(ctxPath); err == nil || !strings.Contains(err.Error(), "tx_hex") {
		t.Fatalf("expected missing tx_hex error, got: %v", err)
	}
}

func TestCmdApplyBlock_MissingBlockHex(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"block_height": 0,
		"utxo_set":     []any{},
	})
	if err := cmdApplyBlock(ctxPath); err == nil || !strings.Contains(err.Error(), "block_hex") {
		t.Fatalf("expected missing block_hex error, got: %v", err)
	}
}

func TestCmdChainstate_MissingBlocksHex(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{})
	_, err := cmdChainstate(ctxPath)
	if err == nil || !strings.Contains(err.Error(), "blocks_hex") {
		t.Fatalf("expected missing blocks_hex error, got: %v", err)
	}
}

func TestCmdChainstate_ChainIDAndProfileConflict(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"chain_id_hex": "00" + strings.Repeat("11", 31),
		"profile":      defaultChainProfile,
		"blocks_hex":   []string{"00"},
	})
	_, err := cmdChainstate(ctxPath)
	if err == nil || !strings.Contains(err.Error(), "use exactly one of chain_id_hex or profile") {
		t.Fatalf("expected conflict error, got: %v", err)
	}
}

func TestCmdChainstate_StartHeightNeedsAncestors(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"chain_id_hex": "00" + strings.Repeat("11", 31),
		"start_height": 1,
		"blocks_hex":   []string{"00"},
	})
	_, err := cmdChainstate(ctxPath)
	if err == nil || !strings.Contains(err.Error(), "ancestor_headers_hex") {
		t.Fatalf("expected missing ancestor_headers_hex error, got: %v", err)
	}
}

func TestCmdReorg_ForkChoice(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"fork_a_work":  10,
		"fork_b_work":  9,
		"tip_hash_a":   "aa",
		"tip_hash_b":   "bb",
		"unused_field": 1,
	})
	out, err := cmdReorg(ctxPath)
	if err != nil {
		t.Fatalf("cmdReorg: %v", err)
	}
	if out != "SELECT_FORK_A" {
		t.Fatalf("out=%q want=%q", out, "SELECT_FORK_A")
	}
}

func TestCmdReorg_OldTipChoice(t *testing.T) {
	ctxPath := writeTempJSON(t, map[string]any{
		"old_tip":       map[string]any{"cumulative_work": 10},
		"candidate_tip": map[string]any{"cumulative_work": 11},
		"stale_tip":     map[string]any{"cumulative_work": 0},
	})
	out, err := cmdReorg(ctxPath)
	if err != nil {
		t.Fatalf("cmdReorg: %v", err)
	}
	if out != "SELECT_CANDIDATE_ROLLBACK_STALE" {
		t.Fatalf("out=%q", out)
	}
}

func TestParseReorgInt_Types(t *testing.T) {
	if _, err := parseReorgInt(1.1, "x"); err == nil {
		t.Fatalf("expected non-integer float error")
	}
	if n, err := parseReorgInt(" 0x10 ", "x"); err != nil || n != 16 {
		t.Fatalf("expected parse ok, got n=%d err=%v", n, err)
	}
	if _, err := parseReorgInt(true, "x"); err == nil {
		t.Fatalf("expected type error")
	}
}
