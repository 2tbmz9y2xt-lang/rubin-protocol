package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

var requiredTelemetryKeys = []string{
	"shortid_collision_count",
	"shortid_collision_blocks",
	"shortid_collision_peers",
	"da_mempool_fill_pct",
	"orphan_pool_fill_pct",
	"miss_rate_bytes_L1",
	"miss_rate_bytes_DA",
	"partial_set_count",
	"partial_set_age_p95",
	"recovery_success_rate",
	"prefetch_latency_ms",
	"peer_quality_score",
}

func mustHex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

func mustHexBytes(b []byte) string {
	return hex.EncodeToString(b)
}

func buildAnchorOnlyCoinbaseLikeTxBytes(t *testing.T, height uint32, witnessCommitment [32]byte) []byte {
	t.Helper()

	// Canonical coinbase wire format (matches consensus.ParseTx expectations):
	// version:u32le, tx_kind:u8=0, tx_nonce:u64=0,
	// input_count:CompactSize=1,
	//   prev_txid:32*0, prev_vout:u32=0xffffffff, script_sig_len:0, sequence:0xffffffff
	// output_count:CompactSize=1,
	//   value:u64=0, covenant_type:u16le=ANCHOR, covenant_data_len:32, covenant_data=witnessCommitment
	// locktime:u32=height, witness_count:0, da_payload_len:0
	var tmp [8]byte
	out := make([]byte, 0, 200)

	binary.LittleEndian.PutUint32(tmp[:4], 1)
	out = append(out, tmp[:4]...)
	out = append(out, 0x00) // tx_kind
	binary.LittleEndian.PutUint64(tmp[:], 0)
	out = append(out, tmp[:]...)

	out = append(out, consensus.EncodeCompactSize(1)...) // input_count
	out = append(out, make([]byte, 32)...)               // prev_txid
	binary.LittleEndian.PutUint32(tmp[:4], ^uint32(0))
	out = append(out, tmp[:4]...)                        // prev_vout
	out = append(out, consensus.EncodeCompactSize(0)...) // script_sig_len
	binary.LittleEndian.PutUint32(tmp[:4], ^uint32(0))
	out = append(out, tmp[:4]...) // sequence

	out = append(out, consensus.EncodeCompactSize(1)...) // output_count
	binary.LittleEndian.PutUint64(tmp[:], 0)
	out = append(out, tmp[:]...) // value
	binary.LittleEndian.PutUint16(tmp[:2], consensus.COV_TYPE_ANCHOR)
	out = append(out, tmp[:2]...)                         // covenant_type
	out = append(out, consensus.EncodeCompactSize(32)...) // covenant_data_len
	out = append(out, witnessCommitment[:]...)

	binary.LittleEndian.PutUint32(tmp[:4], height)
	out = append(out, tmp[:4]...)                        // locktime
	out = append(out, consensus.EncodeCompactSize(0)...) // witness_count
	out = append(out, consensus.EncodeCompactSize(0)...) // da_payload_len

	_, _, _, consumed, err := consensus.ParseTx(out)
	if err != nil {
		t.Fatalf("coinbase-like tx must parse: %v", err)
	}
	if consumed != len(out) {
		t.Fatalf("coinbase-like tx must be canonical: consumed=%d len=%d", consumed, len(out))
	}
	return out
}

func mineGenesisBlockBytes(t *testing.T) (blockBytes []byte, headerBytes []byte) {
	t.Helper()

	dir := t.TempDir()
	chainStatePath := node.ChainStatePath(dir)

	chainState := node.NewChainState()
	blockStore, err := node.OpenBlockStore(node.BlockStorePath(dir))
	if err != nil {
		t.Fatalf("open blockstore: %v", err)
	}
	syncEngine, err := node.NewSyncEngine(
		chainState,
		blockStore,
		node.DefaultSyncConfig(nil, [32]byte{}, chainStatePath),
	)
	if err != nil {
		t.Fatalf("new sync engine: %v", err)
	}

	cfg := node.DefaultMinerConfig()
	cfg.TimestampSource = func() uint64 { return 1_777_000_000 }
	miner, err := node.NewMiner(chainState, blockStore, syncEngine, cfg)
	if err != nil {
		t.Fatalf("new miner: %v", err)
	}

	mb, err := miner.MineOne(context.Background(), nil)
	if err != nil {
		t.Fatalf("mine one: %v", err)
	}

	blockBytes, err = blockStore.GetBlockByHash(mb.Hash)
	if err != nil {
		t.Fatalf("get block: %v", err)
	}
	headerBytes, err = blockStore.GetHeaderByHash(mb.Hash)
	if err != nil {
		t.Fatalf("get header: %v", err)
	}
	return blockBytes, headerBytes
}

func runRawJSON(t *testing.T, raw []byte, entry func()) Response {
	t.Helper()

	rIn, wIn, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdin: %v", err)
	}

	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	oldIn := os.Stdin
	oldOut := os.Stdout
	os.Stdin = rIn
	os.Stdout = wOut
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
		_ = rIn.Close()
		_ = rOut.Close()
		_ = wOut.Close()
	}()

	outCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(rOut)
		outCh <- b
	}()

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := wIn.Write(raw)
		if closeErr := wIn.Close(); err == nil {
			err = closeErr
		}
		writeErrCh <- err
	}()

	entry()
	_ = wOut.Close()

	var outBytes []byte
	select {
	case outBytes = <-outCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for CLI output")
	}

	select {
	case err := <-writeErrCh:
		if err != nil {
			t.Fatalf("write stdin: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for stdin writer")
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(outBytes), &resp); err != nil {
		t.Fatalf("unmarshal resp: %v; raw=%q", err, string(outBytes))
	}
	return resp
}

func runRequest(t *testing.T, req Request) Response {
	t.Helper()

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return runRawJSON(t, raw, runFromStdin)
}

func mustRunOk(t *testing.T, req Request) Response {
	t.Helper()
	resp := runRequest(t, req)
	if !resp.Ok {
		t.Fatalf("expected ok, got: %+v", resp)
	}
	return resp
}

func mustRunErr(t *testing.T, req Request, wantErr string) Response {
	t.Helper()
	resp := runRequest(t, req)
	if resp.Ok || resp.Err != wantErr {
		t.Fatalf("expected err=%q, got: %+v", wantErr, resp)
	}
	return resp
}

func mustRunErrAny(t *testing.T, req Request) Response {
	t.Helper()
	resp := runRequest(t, req)
	if resp.Ok || resp.Err == "" {
		t.Fatalf("expected error, got: %+v", resp)
	}
	return resp
}

type runtimeSharedExecCorpus struct {
	ContractVersion int                     `json:"contract_version"`
	FixtureKind     string                  `json:"fixture_kind"`
	Description     string                  `json:"description"`
	Cases           []runtimeSharedExecCase `json:"cases"`
}

type runtimeSharedExecCase struct {
	ID                   string   `json:"id"`
	ProgramHex           string   `json:"program_hex"`
	WitnessHex           string   `json:"witness_hex"`
	EvalSteps            *uint64  `json:"eval_steps"`
	FrameBitWidths       []uint64 `json:"frame_bit_widths"`
	JetAccepted          *bool    `json:"jet_accepted"`
	JetCost              *uint64  `json:"jet_cost"`
	ExpectedAccepted     bool     `json:"expected_accepted"`
	ExpectedError        string   `json:"expected_error"`
	ExpectedFinalCounter uint64   `json:"expected_final_counter"`
}

func repoFixturePath(t *testing.T, elems ...string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(append([]string{dir}, elems...)...)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("fixture not found from %s: %s", dir, filepath.Join(elems...))
		}
		dir = parent
	}
}

type runtimeKeyOpsFixture struct {
	blockBytes  []byte
	headerBytes []byte
	chainIDHex  string
	txHex       string
	targetHex   string
}

func newRuntimeKeyOpsFixture(t *testing.T) runtimeKeyOpsFixture {
	t.Helper()

	blockBytes, headerBytes := mineGenesisBlockBytes(t)

	var chainID [32]byte
	chainIDHex := mustHex32(chainID)

	var commitment [32]byte
	txBytes := buildAnchorOnlyCoinbaseLikeTxBytes(t, 0, commitment)
	txHex := mustHexBytes(txBytes)

	targetHex := mustHex32(consensus.POW_LIMIT)

	return runtimeKeyOpsFixture{
		blockBytes:  blockBytes,
		headerBytes: headerBytes,
		chainIDHex:  chainIDHex,
		txHex:       txHex,
		targetHex:   targetHex,
	}
}

// TestRejectRetiredCoreExtProfiles mirrors the Rust consensus CLI's
// reject_core_ext_profiles_from_json tests: the retired 0x0102 CORE_EXT request
// fields are rejected (not silently ignored), keeping Go/Rust CLI parity.
func TestRejectRetiredCoreExtProfiles(t *testing.T) {
	mk := func(items ...string) []json.RawMessage {
		out := make([]json.RawMessage, 0, len(items))
		for _, it := range items {
			out = append(out, json.RawMessage(it))
		}
		return out
	}
	cases := []struct {
		name     string
		profiles []json.RawMessage
		anchor   string
		wantErr  string
	}{
		{"absent", nil, "", ""},
		{"empty array", []json.RawMessage{}, "", ""},
		{"non-empty profiles", mk(`{"ext_id":1}`), "", "core_ext_profiles unsupported by Go runtime"},
		{"anchor set", nil, "deadbeef", "core_ext_profile_set_anchor_hex unsupported by Go runtime"},
		{"anchor takes precedence", mk(`{"ext_id":1}`), "deadbeef", "core_ext_profile_set_anchor_hex unsupported by Go runtime"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := rejectRetiredCoreExtProfiles(tc.profiles, tc.anchor)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("expected error %q, got: %v", tc.wantErr, err)
			}
		})
	}
	// A non-array core_ext_profiles is a schema/decode error (Rust parity:
	// "bad request"), not the op-level "unsupported" error.
	t.Run("malformed non-array is a decode error", func(t *testing.T) {
		var env requestEnvelope
		if err := json.Unmarshal([]byte(`{"core_ext_profiles":"oops"}`), &env); err == nil {
			t.Fatal("expected decode error for non-array core_ext_profiles")
		}
	})
}

func TestRubinConsensusCLI_RunFromStdin_CoversKeyOps(t *testing.T) {
	fixture := newRuntimeKeyOpsFixture(t)

	t.Run("bad_request", testRuntimeKeyOpBadRequest)
	t.Run("parse_tx_ok_and_error", func(t *testing.T) {
		testRuntimeKeyOpParseTx(t, fixture)
	})
	t.Run("fork_work_and_choice", func(t *testing.T) {
		testRuntimeKeyOpForkWorkAndChoice(t)
	})
	t.Run("merkle_roots", func(t *testing.T) {
		testRuntimeKeyOpMerkleRoots(t)
	})
	t.Run("sighash_and_weight", func(t *testing.T) {
		testRuntimeKeyOpSighashAndWeight(t, fixture)
	})
	t.Run("simplicity_exec_vector", func(t *testing.T) {
		testRuntimeKeyOpSimplicityExecVector(t)
	})
	t.Run("block_hash_and_pow_check", func(t *testing.T) {
		testRuntimeKeyOpBlockHashAndPowCheck(t, fixture)
	})
	t.Run("retarget_v1_both_forms", func(t *testing.T) {
		testRuntimeKeyOpRetargetV1BothForms(t, fixture)
	})
	t.Run("block_validation_and_connect", func(t *testing.T) {
		testRuntimeKeyOpBlockValidationAndConnect(t, fixture)
	})
	t.Run("compact_and_policy_ops", func(t *testing.T) {
		testRuntimeKeyOpCompactAndPolicyOps(t)
	})
	t.Run("descriptor_nonce_timestamp_and_orders", func(t *testing.T) {
		testRuntimeKeyOpDescriptorNonceTimestampAndOrders(t)
	})
	t.Run("htlc_and_vault_policy_ops", func(t *testing.T) {
		testRuntimeKeyOpHTLCAndVaultPolicyOps(t)
	})
}

func testRuntimeKeyOpBadRequest(t *testing.T) {
	t.Helper()
	resp := runRawJSON(t, []byte("{"), runFromStdin)
	if resp.Ok || resp.Err == "" {
		t.Fatalf("expected error")
	}
}

func testRuntimeKeyOpParseTx(t *testing.T, fixture runtimeKeyOpsFixture) {
	t.Helper()
	ok := mustRunOk(t, Request{Op: "parse_tx", TxHex: fixture.txHex})
	if ok.TxidHex == "" || ok.WtxidHex == "" || ok.Consumed == 0 {
		t.Fatalf("unexpected ok resp: %+v", ok)
	}
	_ = mustRunErrAny(t, Request{Op: "parse_tx", TxHex: "00"})
}

func testRuntimeKeyOpForkWorkAndChoice(t *testing.T) {
	t.Helper()
	r := mustRunOk(t, Request{Op: "fork_work", Target: "0x01"})
	if r.WorkHex == "" {
		t.Fatalf("unexpected resp: %+v", r)
	}
	sel := mustRunOk(t, Request{
		Op: "fork_choice_select",
		Chains: []ForkChoiceChain{
			{ID: "a", Targets: []string{"0x02"}, TipHash: "0x02"},
			{ID: "b", Targets: []string{"0x02"}, TipHash: "0x01"},
		},
	})
	if sel.Winner != "b" || sel.Chainwork == "" {
		t.Fatalf("unexpected resp: %+v", sel)
	}
}

func testRuntimeKeyOpMerkleRoots(t *testing.T) {
	t.Helper()
	var a, b [32]byte
	a[31] = 1
	b[31] = 2
	r1 := mustRunOk(t, Request{Op: "merkle_root", Txids: []string{mustHex32(a), mustHex32(b)}})
	if r1.MerkleHex == "" {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	r2 := mustRunOk(t, Request{Op: "witness_merkle_root", Wtxids: []string{mustHex32(a), mustHex32(b)}})
	if r2.WitnessMerkleHex == "" {
		t.Fatalf("unexpected resp: %+v", r2)
	}
}

func testRuntimeKeyOpSighashAndWeight(t *testing.T, fixture runtimeKeyOpsFixture) {
	t.Helper()
	r1 := mustRunOk(t, Request{
		Op:         "sighash_v1",
		TxHex:      fixture.txHex,
		InputIndex: 0,
		InputValue: 0,
		ChainIDHex: fixture.chainIDHex,
	})
	if len(r1.DigestHex) != 64 {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	_ = mustRunOk(t, Request{Op: "tx_weight_and_stats", TxHex: fixture.txHex})
}

func testRuntimeKeyOpSimplicityExecVector(t *testing.T) {
	t.Helper()
	accepted := mustRunOk(t, Request{Op: "simplicity_exec_vector", ProgramHex: "24"})
	if accepted.Accepted == nil || !*accepted.Accepted || accepted.FinalCounter == nil || *accepted.FinalCounter != 1 {
		t.Fatalf("unexpected accepted response: %+v", accepted)
	}

	rejected := runRequest(t, Request{
		Op:         "simplicity_exec_vector",
		ProgramHex: "60",
		JetCost:    ptrUint64(3),
	})
	if rejected.Ok || rejected.Err != "TX_ERR_SIMPLICITY_REJECTED" ||
		rejected.Accepted == nil || *rejected.Accepted ||
		rejected.FinalCounter == nil || *rejected.FinalCounter != 3 {
		t.Fatalf("unexpected rejected response: %+v", rejected)
	}

	budget := runRequest(t, Request{
		Op:          "simplicity_exec_vector",
		ProgramHex:  "60",
		JetAccepted: ptrBool(true),
		JetCost:     ptrUint64(400_001),
	})
	if budget.Ok || budget.Err != "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED" ||
		budget.Accepted == nil || !*budget.Accepted ||
		budget.FinalCounter == nil || *budget.FinalCounter != 400_000 {
		t.Fatalf("unexpected budget response: %+v", budget)
	}

	syntheticAccepted := mustRunOk(t, Request{
		Op:             "simplicity_exec_vector",
		EvalSteps:      ptrUint64(1),
		FrameBitWidths: []uint64{simplicity.MaxFrameBytes * 8},
	})
	if syntheticAccepted.Accepted == nil || !*syntheticAccepted.Accepted ||
		syntheticAccepted.FinalCounter == nil || *syntheticAccepted.FinalCounter != 1 {
		t.Fatalf("unexpected synthetic accepted response: %+v", syntheticAccepted)
	}

	syntheticBudget := runRequest(t, Request{
		Op:             "simplicity_exec_vector",
		EvalSteps:      ptrUint64(1),
		FrameBitWidths: []uint64{simplicity.MaxFrameBytes*8 + 1},
	})
	if syntheticBudget.Ok || syntheticBudget.Err != "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED" ||
		syntheticBudget.Accepted == nil || *syntheticBudget.Accepted ||
		syntheticBudget.FinalCounter == nil || *syntheticBudget.FinalCounter != 0 {
		t.Fatalf("unexpected synthetic budget response: %+v", syntheticBudget)
	}
}

func TestRubinConsensusCLI_SimplicityExecVectorSharedCorpus(t *testing.T) {
	raw, err := os.ReadFile(repoFixturePath(t, "conformance", "fixtures", "protocol", "simplicity_exec_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared exec corpus: %v", err)
	}
	var corpus runtimeSharedExecCorpus
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared exec corpus: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_exec_corpus_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared exec corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			resp := runRequest(t, Request{
				Op:             "simplicity_exec_vector",
				ProgramHex:     tc.ProgramHex,
				WitnessHex:     tc.WitnessHex,
				EvalSteps:      tc.EvalSteps,
				FrameBitWidths: tc.FrameBitWidths,
				JetAccepted:    tc.JetAccepted,
				JetCost:        tc.JetCost,
			})
			if tc.ExpectedError != "" {
				if resp.Ok || resp.Err != tc.ExpectedError {
					t.Fatalf("expected err=%q, got: %+v", tc.ExpectedError, resp)
				}
			} else if !resp.Ok {
				t.Fatalf("expected ok, got: %+v", resp)
			}
			if resp.Accepted == nil || *resp.Accepted != tc.ExpectedAccepted ||
				resp.FinalCounter == nil || *resp.FinalCounter != tc.ExpectedFinalCounter {
				t.Fatalf("outcome=%+v want accepted=%v final_counter=%d", resp, tc.ExpectedAccepted, tc.ExpectedFinalCounter)
			}
		})
	}
}

func testRuntimeKeyOpBlockHashAndPowCheck(t *testing.T, fixture runtimeKeyOpsFixture) {
	t.Helper()
	headerHex := mustHexBytes(fixture.headerBytes)
	r1 := mustRunOk(t, Request{Op: "block_hash", HeaderHex: headerHex})
	if len(r1.BlockHash) != 64 {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	_ = mustRunOk(t, Request{Op: "pow_check", HeaderHex: headerHex, TargetHex: fixture.targetHex})
}

func testRuntimeKeyOpRetargetV1BothForms(t *testing.T, fixture runtimeKeyOpsFixture) {
	t.Helper()
	r1 := runRequest(t, Request{Op: "retarget_v1", TargetOldHex: fixture.targetHex, TimestampFirst: 100, TimestampLast: 200})
	if !r1.Ok || len(r1.TargetNew) != 64 {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	r2 := runRequest(t, Request{Op: "retarget_v1", TargetOldHex: fixture.targetHex, WindowTimestamps: []uint64{1}})
	if r2.Ok || r2.Err != string(consensus.TX_ERR_PARSE) {
		t.Fatalf("expected TX_ERR_PARSE: %+v", r2)
	}
}

func testRuntimeKeyOpBlockValidationAndConnect(t *testing.T, fixture runtimeKeyOpsFixture) {
	t.Helper()
	blockHex := mustHexBytes(fixture.blockBytes)
	r1 := runRequest(t, Request{Op: "block_basic_check", BlockHex: blockHex, Height: 0})
	if !r1.Ok || len(r1.BlockHash) != 64 {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	r2 := runRequest(t, Request{Op: "block_basic_check_with_fees", BlockHex: blockHex, Height: 0, AlreadyGenerated: 0, SumFees: 0})
	if !r2.Ok || len(r2.BlockHash) != 64 {
		t.Fatalf("unexpected resp: %+v", r2)
	}
	r3 := runRequest(t, Request{Op: "connect_block_basic", BlockHex: blockHex, Height: 0, AlreadyGenerated: 0, SumFees: 0, ChainIDHex: ""})
	if !r3.Ok {
		t.Fatalf("unexpected resp: %+v", r3)
	}
}

func testRuntimeKeyOpCompactAndPolicyOps(t *testing.T) {
	t.Helper()
	var wtxid [32]byte
	wtxid[0] = 1
	_ = runRequest(t, Request{Op: "compact_shortid", WtxidHex: mustHex32(wtxid), Nonce1: 1, Nonce2: 2})
	_ = runRequest(t, Request{Op: "compact_collision_fallback", MissingIndices: []int{2, 1}, GetblocktxnOK: ptrBool(true)})
	_ = runRequest(t, Request{Op: "compact_witness_roundtrip", PubkeyLength: 3, SigLength: 5})
	_ = runRequest(t, Request{Op: "compact_batch_verify", BatchSize: 4, InvalidIndices: nil})
	_ = runRequest(t, Request{Op: "compact_prefill_roundtrip", TxCount: 5, PrefilledIndices: []int{0}, MempoolIndices: []int{1, 2}, BlocktxnIndices: []int{3, 4}})
	_ = runRequest(t, Request{
		Op:                "compact_state_machine",
		ChunkCount:        2,
		InitialChunks:     []int{0},
		InitialCommitSeen: ptrBool(false),
		Events:            []any{map[string]any{"type": "commit"}, map[string]any{"type": "chunk", "index": 1}, map[string]any{"type": "checkblock"}, map[string]any{"type": "tick", "blocks": 1}},
	})
	_ = runRequest(t, Request{Op: "compact_orphan_limits", CurrentPeerBytes: 1, CurrentDaIDBytes: 2, CurrentGlobalBytes: 3, IncomingChunkBytes: 4})
	_ = runRequest(t, Request{Op: "compact_orphan_storm", GlobalLimit: 100, CurrentGlobalBytes: 95, IncomingChunkBytes: 10, IncomingHasCommit: ptrBool(false), StormTriggerPct: 90, RecoverySuccessRate: 90, ObservationMinutes: 10})
	_ = runRequest(t, Request{Op: "compact_chunk_count_cap", ChunkCount: 1, MaxDAChunkCount: 2})
	_ = runRequest(t, Request{Op: "compact_sendcmpct_modes", InIBD: ptrBool(true)})
	_ = runRequest(t, Request{Op: "compact_peer_quality", Events: []any{"getblocktxn_required"}, ElapsedBlocks: 0})
	_ = runRequest(t, Request{Op: "compact_prefetch_caps", PeerStreamsBPS: []int{5_000_000, 10}, PerPeerBPS: 4_000_000, GlobalBPS: 4_000_001})
	assertRuntimeKeyOpCompactTelemetry(t)
	_ = runRequest(t, Request{Op: "compact_grace_period", ElapsedBlocks: 0, Events: []any{"prefetch_completed"}})
	_ = runRequest(t, Request{Op: "compact_eviction_tiebreak", Entries: []map[string]any{{"da_id": "b", "fee": 100, "wire_bytes": 10, "received_time": 2}, {"da_id": "a", "fee": 50, "wire_bytes": 10, "received_time": 1}}})
	_ = runRequest(t, Request{Op: "compact_a_to_b_retention", ChunkCount: 3, InitialChunks: []int{0}, CommitArrives: ptrBool(true)})
	_ = runRequest(t, Request{Op: "compact_duplicate_commit", Commits: []map[string]any{{"da_id": "x", "peer": "p1"}, {"da_id": "x", "peer": "p2"}}})
	_ = runRequest(t, Request{Op: "compact_total_fee", CommitFee: 1, ChunkFees: []int{2, 3}})
	_ = runRequest(t, Request{Op: "compact_pinned_accounting", CapBytes: 10, CurrentPinnedBytes: 9, IncomingPayload: 2})
	_ = runRequest(t, Request{Op: "compact_storm_commit_bearing", OrphanPoolFillPct: 95, StormTriggerPct: 90, ContainsCommit: ptrBool(true)})
}

func assertRuntimeKeyOpCompactTelemetry(t *testing.T) {
	t.Helper()
	rRate := runRequest(t, Request{Op: "compact_telemetry_rate", CompletedSets: 1, TotalSets: 2})
	if !rRate.Ok {
		t.Fatalf("unexpected resp: %+v", rRate)
	}
	rFields := runRequest(t, Request{Op: "compact_telemetry_fields", Telemetry: map[string]any{}})
	if rFields.Ok || rFields.Err == "" {
		t.Fatalf("expected missing telemetry fields error: %+v", rFields)
	}
}

func testRuntimeKeyOpDescriptorNonceTimestampAndOrders(t *testing.T) {
	t.Helper()
	r1 := runRequest(t, Request{Op: "output_descriptor_bytes", CovenantType: consensus.COV_TYPE_ANCHOR, CovenantDataHex: mustHexBytes(bytes.Repeat([]byte{0x11}, 32))})
	if !r1.Ok || r1.DescriptorHex == "" {
		t.Fatalf("unexpected resp: %+v", r1)
	}
	r2 := runRequest(t, Request{Op: "output_descriptor_hash", CovenantType: consensus.COV_TYPE_ANCHOR, CovenantDataHex: mustHexBytes(bytes.Repeat([]byte{0x11}, 32))})
	if !r2.Ok || len(r2.DigestHex) != 64 {
		t.Fatalf("unexpected resp: %+v", r2)
	}
	dup := runRequest(t, Request{Op: "nonce_replay_intrablock", Nonces: []uint64{1, 2, 1}})
	if dup.Ok || dup.Err == "" || len(dup.Duplicates) == 0 {
		t.Fatalf("expected replay error: %+v", dup)
	}
	assertRuntimeKeyOpOrdering(t)
}

func assertRuntimeKeyOpOrdering(t *testing.T) {
	t.Helper()
	ts := runRequest(t, Request{Op: "timestamp_bounds", MTP: 100, Timestamp: 101})
	if !ts.Ok {
		t.Fatalf("unexpected resp: %+v", ts)
	}
	order := runRequest(t, Request{Op: "determinism_order", Keys: []any{"0x02", "0x01", "a"}})
	if !order.Ok || len(order.SortedKeys) == 0 {
		t.Fatalf("unexpected resp: %+v", order)
	}
	v := runRequest(t, Request{Op: "validation_order", Checks: []Check{{Name: "a", Fails: false}, {Name: "b", Fails: true, Err: "E"}}})
	if v.Ok || v.Err != "E" || v.FirstErr != "E" || len(v.Evaluated) != 2 {
		t.Fatalf("unexpected resp: %+v", v)
	}
}

func testRuntimeKeyOpHTLCAndVaultPolicyOps(t *testing.T) {
	t.Helper()
	r1 := runRequest(t, Request{Op: "htlc_ordering_policy", Path: "refund", LocktimeOK: ptrBool(false)})
	if r1.Ok || r1.Err == "" {
		t.Fatalf("expected refund locktime error: %+v", r1)
	}
	r2 := runRequest(t, Request{Op: "htlc_ordering_policy", Path: "claim", VerifyOK: ptrBool(false)})
	if r2.Ok || r2.Err != string(consensus.TX_ERR_SIG_INVALID) || !r2.VerifyCalled {
		t.Fatalf("unexpected resp: %+v", r2)
	}
	r3 := runRequest(t, Request{Op: "vault_policy_rules", OwnerLockID: "o", VaultInputCount: 1, NonVaultLockIDs: []string{"o"}, SumOut: 10, SumInVault: 10, Slots: 1, KeyCount: 1, Whitelist: []string{"aa"}})
	if !r3.Ok {
		t.Fatalf("unexpected resp: %+v", r3)
	}
}

func ptrBool(v bool) *bool { return &v }

func ptrUint64(v uint64) *uint64 { return &v }

func TestRubinConsensusCLI_RunFromStdin_CoversErrorPaths(t *testing.T) {
	blockBytes, _ := mineGenesisBlockBytes(t)
	txHex := mustHexBytes(buildAnchorOnlyCoinbaseLikeTxBytes(t, 0, [32]byte{}))

	type errCase struct {
		name    string
		wantErr string
		req     Request
	}
	for _, tc := range []errCase{
		{name: "parse_tx_bad_hex", req: Request{Op: "parse_tx", TxHex: "zz"}, wantErr: "bad hex"},
		{name: "fork_work_bad_target", req: Request{Op: "fork_work", Target: ""}, wantErr: "bad target"},
		{name: "fork_choice_bad_chains", req: Request{Op: "fork_choice_select"}, wantErr: "bad chains"},
		{name: "merkle_root_bad_txid", req: Request{Op: "merkle_root", Txids: []string{"00"}}, wantErr: "bad txid"},
		{name: "witness_merkle_root_bad_wtxid", req: Request{Op: "witness_merkle_root", Wtxids: []string{"00"}}, wantErr: "bad wtxid"},
		{name: "sighash_bad_chain_id", req: Request{Op: "sighash_v1", TxHex: txHex, ChainIDHex: "00"}, wantErr: "bad chain_id"},
		{name: "simplicity_exec_vector_missing_program", req: Request{Op: "simplicity_exec_vector"}, wantErr: "bad program_hex"},
		{name: "simplicity_exec_vector_empty_prefixed_program", req: Request{Op: "simplicity_exec_vector", ProgramHex: "0x"}, wantErr: "bad program_hex"},
		{name: "simplicity_exec_vector_bad_witness", req: Request{Op: "simplicity_exec_vector", ProgramHex: "24", WitnessHex: "zz"}, wantErr: "bad witness_hex"},
		{name: "simplicity_exec_vector_oversized_program", req: Request{Op: "simplicity_exec_vector", ProgramHex: strings.Repeat("00", simplicity.MaxProgramBytes+1)}, wantErr: "TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE"},
		{name: "simplicity_exec_vector_oversized_witness", req: Request{Op: "simplicity_exec_vector", ProgramHex: "24", WitnessHex: strings.Repeat("00", simplicity.MaxProgramBytes+1)}, wantErr: "bad witness_hex"},
		{name: "simplicity_exec_vector_bad_covenant_cmr", req: Request{Op: "simplicity_exec_vector", ProgramHex: "24", CovenantCMRHex: "00"}, wantErr: "bad covenant_cmr_hex"},
		{name: "simplicity_exec_vector_missing_jet_cost", req: Request{Op: "simplicity_exec_vector", ProgramHex: "60"}, wantErr: "bad jet_cost"},
		{name: "simplicity_exec_vector_decode_error", req: Request{Op: "simplicity_exec_vector", ProgramHex: "25"}, wantErr: "TX_ERR_SIMPLICITY_DECODE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustRunErr(t, tc.req, tc.wantErr)
		})
	}

	t.Run("block_basic_bad_expected_prev", func(t *testing.T) {
		r := runRequest(t, Request{
			Op:           "block_basic_check",
			BlockHex:     mustHexBytes(blockBytes),
			Height:       0,
			ExpectedPrev: "zz",
		})
		if r.Ok || r.Err != "bad expected_prev_hash" {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("connect_block_bad_utxo_map", func(t *testing.T) {
		r := runRequest(t, Request{
			Op:       "connect_block_basic",
			BlockHex: mustHexBytes(blockBytes),
			Height:   0,
			Utxos:    []UtxoJSON{{Txid: "00", CovenantDataHex: "zz"}},
		})
		if r.Ok || r.Err == "" {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("compact_collision_full_block_fallback", func(t *testing.T) {
		r := mustRunOk(t, Request{
			Op:             "compact_collision_fallback",
			MissingIndices: []int{1},
			GetblocktxnOK:  ptrBool(false),
		})
		if !r.RequestFullBlock {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("compact_witness_roundtrip_invalid_lengths", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_witness_roundtrip", PubkeyLength: -1, SigLength: 1}, "invalid pubkey_length")
		mustRunErr(
			t,
			Request{Op: "compact_witness_roundtrip", PubkeyLength: consensus.MAX_WITNESS_BYTES_PER_TX, SigLength: 1},
			"invalid witness lengths",
		)
	})

	t.Run("compact_witness_roundtrip_near_limit_valid", func(t *testing.T) {
		resp := mustRunOk(t, Request{Op: "compact_witness_roundtrip", PubkeyLength: 99990, SigLength: 0})
		if !resp.RoundtripOK || resp.WireBytes != 99997 {
			t.Fatalf("unexpected resp: %+v", resp)
		}
	})

	t.Run("compact_batch_verify_index_oob", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_batch_verify", BatchSize: 2, InvalidIndices: []int{2}}, "invalid index out of range")
	})

	t.Run("compact_state_machine_unknown_event", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_state_machine", ChunkCount: 2, Events: []any{map[string]any{"type": "nope"}}},
			"unknown state-machine event type",
		)
	})

	t.Run("compact_state_machine_invalid_numeric_fields", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_state_machine", ChunkCount: 2, Events: []any{map[string]any{"type": "chunk", "index": 1.5}}},
			"invalid index",
		)
		mustRunErr(
			t,
			Request{Op: "compact_state_machine", ChunkCount: 2, Events: []any{map[string]any{"type": "tick", "blocks": 1.5}}},
			"invalid blocks",
		)
		mustRunErr(
			t,
			Request{Op: "compact_state_machine", ChunkCount: 2, Events: []any{map[string]any{"type": "tick", "blocks": math.Exp2(63)}}},
			"invalid blocks",
		)
	})

	t.Run("compact_chunk_count_cap_over", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_chunk_count_cap", ChunkCount: 3, MaxDAChunkCount: 2}, string(consensus.TX_ERR_PARSE))
	})

	t.Run("compact_sendcmpct_modes_phases_branch", func(t *testing.T) {
		r := mustRunOk(t, Request{
			Op: "compact_sendcmpct_modes",
			Phases: []map[string]any{
				{"in_ibd": true},
				{"warmup_done": true, "miss_rate_pct": 0.1, "miss_rate_blocks": 0},
			},
		})
		if len(r.InvalidOut) != 2 {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("compact_sendcmpct_modes_invalid_miss_rate_blocks", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_sendcmpct_modes", Phases: []map[string]any{{"warmup_done": true, "miss_rate_blocks": 1.5}}},
			"invalid miss_rate_blocks",
		)
	})

	t.Run("compact_peer_quality_unknown_event", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_peer_quality", Events: []any{"unknown"}}, "unknown peer-quality event")
	})

	t.Run("compact_prefetch_caps_default_streams_branch", func(t *testing.T) {
		_ = mustRunOk(t, Request{
			Op:             "compact_prefetch_caps",
			PeerStreamsBPS: nil,
			ActiveSets:     2,
			PeerStreamBPS:  1,
		})
	})

	t.Run("compact_telemetry_rate_invalid", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_telemetry_rate", CompletedSets: 2, TotalSets: 1}, "invalid completed/total values")
	})

	t.Run("compact_telemetry_fields_ok", func(t *testing.T) {
		telemetry := map[string]any{}
		for _, k := range requiredTelemetryKeys {
			telemetry[k] = 1
		}
		r := mustRunOk(t, Request{Op: "compact_telemetry_fields", Telemetry: telemetry})
		if len(r.MissingFields) != 0 {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("compact_grace_period_unknown_event", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_grace_period", Events: []any{"nope"}}, "unknown grace event")
	})

	t.Run("compact_eviction_tiebreak_invalid_entry", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_eviction_tiebreak", Entries: []map[string]any{{"da_id": "", "wire_bytes": 0}}},
			"invalid da_id/wire_bytes",
		)
	})

	t.Run("compact_eviction_tiebreak_invalid_numeric_entry", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_eviction_tiebreak", Entries: []map[string]any{{"da_id": "x", "fee": 1.5, "wire_bytes": 1, "received_time": 0}}},
			"invalid fee",
		)
	})

	t.Run("compact_a_to_b_retention_invalid_chunk_count", func(t *testing.T) {
		mustRunErr(t, Request{Op: "compact_a_to_b_retention", ChunkCount: 0}, "chunk_count must be > 0")
	})

	t.Run("compact_duplicate_commit_invalid_entry", func(t *testing.T) {
		mustRunErr(
			t,
			Request{Op: "compact_duplicate_commit", Commits: []map[string]any{{"da_id": "", "peer": ""}}},
			"invalid duplicate-commit entry",
		)
	})

	t.Run("output_descriptor_bytes_bad_hex", func(t *testing.T) {
		mustRunErr(t, Request{Op: "output_descriptor_bytes", CovenantType: 1, CovenantDataHex: "zz"}, "bad covenant_data_hex")
	})

	t.Run("nonce_replay_ok", func(t *testing.T) {
		r := mustRunOk(t, Request{Op: "nonce_replay_intrablock", Nonces: []uint64{1, 2, 3}})
		if len(r.Duplicates) != 0 {
			t.Fatalf("unexpected resp: %+v", r)
		}
	})

	t.Run("timestamp_bounds_old_and_future", func(t *testing.T) {
		mustRunErr(t, Request{Op: "timestamp_bounds", MTP: 100, Timestamp: 100}, string(consensus.BLOCK_ERR_TIMESTAMP_OLD))
		mustRunErr(t, Request{Op: "timestamp_bounds", MTP: 100, Timestamp: 100 + 7200 + 1}, string(consensus.BLOCK_ERR_TIMESTAMP_FUTURE))
	})

	t.Run("determinism_order_bad_key", func(t *testing.T) {
		mustRunErr(t, Request{Op: "determinism_order", Keys: []any{"0xzz"}}, "bad key")
	})

	t.Run("validation_order_bad_checks", func(t *testing.T) {
		mustRunErr(t, Request{Op: "validation_order"}, "bad checks")
	})

	t.Run("htlc_structural_fail", func(t *testing.T) {
		mustRunErr(t, Request{Op: "htlc_ordering_policy", StructuralOK: ptrBool(false)}, string(consensus.TX_ERR_PARSE))
	})

	t.Run("vault_fee_sponsor_forbidden", func(t *testing.T) {
		mustRunErr(t, Request{
			Op:              "vault_policy_rules",
			OwnerLockID:     "o",
			VaultInputCount: 1,
			NonVaultLockIDs: []string{"o", "x"},
			SumOut:          10,
			SumInVault:      10,
			Slots:           1,
			KeyCount:        1,
			Whitelist:       []string{"aa"},
		}, string(consensus.TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN))
	})

	t.Run("unknown_op", func(t *testing.T) {
		mustRunErr(t, Request{Op: "nope"}, "unknown op")
	})
}

func TestMainCallsRunFromStdin(t *testing.T) {
	raw, err := json.Marshal(Request{Op: "compact_total_fee", CommitFee: 1, ChunkFees: []int{2}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp := runRawJSON(t, raw, main)
	if !resp.Ok || resp.TotalFee != 3 {
		t.Fatalf("unexpected resp: %+v", resp)
	}
}

func TestRubinConsensusCLI_RuntimeHelpers(t *testing.T) {
	t.Run("parseHexU256To32", testRuntimeHelperParseHexU256To32)
	t.Run("parseExactHex32_and_optionals", testRuntimeHelperParseExactHex32AndOptionals)
	t.Run("parseBlockValidationInputs", testRuntimeHelperParseBlockValidationInputs)
	t.Run("buildUtxoMap_errors", testRuntimeHelperBuildUtxoMapErrors)
	t.Run("parseKeyBytes", testRuntimeHelperParseKeyBytes)
	t.Run("default_and_cast_helpers", testRuntimeHelperDefaultAndCastHelpers)
	t.Run("writeConsensusErr_non_txerror", testRuntimeHelperWriteConsensusErrNonTxError)
	t.Run("compactsize_helpers", testRuntimeHelperCompactSize)
	t.Run("slice_and_int_helpers", testRuntimeHelperSliceAndIntHelpers)
}

func testRuntimeHelperParseHexU256To32(t *testing.T) {
	t.Helper()
	if _, err := parseHexU256To32(""); err == nil {
		t.Fatalf("expected error")
	}
	v, err := parseHexU256To32("0x1")
	if err != nil || v[31] != 0x01 {
		t.Fatalf("unexpected: v=%x err=%v", v, err)
	}
	if _, err := parseHexU256To32("0x" + strings.Repeat("11", 33)); err == nil {
		t.Fatalf("expected overflow error")
	}
}

func testRuntimeHelperParseExactHex32AndOptionals(t *testing.T) {
	t.Helper()
	okHex := hex.EncodeToString(make([]byte, 32))
	assertParseExactHex32Cases(t, okHex)
	assertParseOptionalHex32Cases(t, okHex)
	assertParseOptionalChainIDHexCases(t, okHex)
}

func assertParseExactHex32Cases(t *testing.T, okHex string) {
	t.Helper()
	if _, err := parseExactHex32("00"); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := parseExactHex32("zz"); err == nil {
		t.Fatalf("expected error")
	}
	v, err := parseExactHex32(okHex)
	if err != nil || v != ([32]byte{}) {
		t.Fatalf("unexpected: v=%x err=%v", v, err)
	}
}

func assertParseOptionalHex32Cases(t *testing.T, okHex string) {
	t.Helper()
	if opt, err := parseOptionalHex32("", "bad"); err != nil || opt != nil {
		t.Fatalf("unexpected: opt=%v err=%v", opt, err)
	}
	if opt, err := parseOptionalHex32("zz", "bad expected"); err == nil || opt != nil {
		t.Fatalf("expected error")
	}
	if opt, err := parseOptionalHex32(okHex, "bad expected"); err != nil || opt == nil || *opt != ([32]byte{}) {
		t.Fatalf("unexpected optional success: opt=%v err=%v", opt, err)
	}
}

func assertParseOptionalChainIDHexCases(t *testing.T, okHex string) {
	t.Helper()
	chainID, err := parseOptionalChainIDHex("")
	if err != nil || chainID != ([32]byte{}) {
		t.Fatalf("unexpected: %x err=%v", chainID, err)
	}
	if _, err := parseOptionalChainIDHex("00"); err == nil {
		t.Fatalf("expected bad chain_id error")
	}
	if chainID, err := parseOptionalChainIDHex(okHex); err != nil || chainID != ([32]byte{}) {
		t.Fatalf("unexpected chain_id success: %x err=%v", chainID, err)
	}
}

func testRuntimeHelperParseBlockValidationInputs(t *testing.T) {
	t.Helper()
	blockBytes, _ := mineGenesisBlockBytes(t)
	req := Request{
		BlockHex:       hex.EncodeToString(blockBytes),
		ExpectedPrev:   hex.EncodeToString(make([]byte, 32)),
		ExpectedTarget: hex.EncodeToString(make([]byte, 32)),
	}
	raw, expectedPrev, expectedTarget, err := parseBlockValidationInputs(req)
	if err != nil || len(raw) == 0 || expectedPrev == nil || expectedTarget == nil {
		t.Fatalf("unexpected success parse: len=%d prev=%v target=%v err=%v", len(raw), expectedPrev, expectedTarget, err)
	}
	if _, _, _, err := parseBlockValidationInputs(Request{BlockHex: "zz"}); err == nil {
		t.Fatalf("expected bad block error")
	}
	if _, _, _, err := parseBlockValidationInputs(Request{BlockHex: hex.EncodeToString(blockBytes), ExpectedTarget: "zz"}); err == nil {
		t.Fatalf("expected bad expected_target error")
	}
}

func testRuntimeHelperBuildUtxoMapErrors(t *testing.T) {
	t.Helper()
	if _, err := buildUtxoMap([]UtxoJSON{{Txid: "00", CovenantDataHex: ""}}); err == nil {
		t.Fatalf("expected bad utxo txid")
	}
	if _, err := buildUtxoMap([]UtxoJSON{{Txid: hex.EncodeToString(make([]byte, 32)), CovenantDataHex: "zz"}}); err == nil {
		t.Fatalf("expected bad utxo covenant_data")
	}
}

func testRuntimeHelperParseKeyBytes(t *testing.T) {
	t.Helper()
	if b, err := parseKeyBytes("0x1"); err != nil || len(b) != 1 || b[0] != 0x01 {
		t.Fatalf("unexpected: %x err=%v", b, err)
	}
	if _, err := parseKeyBytes("0xzz"); err == nil {
		t.Fatalf("expected error")
	}
	if b, err := parseKeyBytes("abc"); err != nil || string(b) != "abc" {
		t.Fatalf("unexpected ascii parse: %x err=%v", b, err)
	}
	if b, err := parseKeyBytes(42); err != nil || string(b) != "42" {
		t.Fatalf("unexpected generic parse: %x err=%v", b, err)
	}
}

func testRuntimeHelperDefaultAndCastHelpers(t *testing.T) {
	t.Helper()
	assertDefaultHelpers(t)
	assertCastHelpers(t)
}

func assertDefaultHelpers(t *testing.T) {
	t.Helper()
	if !boolOrDefault(nil, true) || boolOrDefault(ptrBool(false), true) {
		t.Fatalf("boolOrDefault mismatch")
	}
	var u8 uint8 = 7
	if uint8OrDefault(nil, 3) != 3 || uint8OrDefault(&u8, 3) != 7 {
		t.Fatalf("uint8OrDefault mismatch")
	}
	var u64 uint64 = 11
	if uint64OrDefault(nil, 5) != 5 || uint64OrDefault(&u64, 5) != 11 {
		t.Fatalf("uint64OrDefault mismatch")
	}
}

func assertCastHelpers(t *testing.T) {
	t.Helper()
	if toInt(float64(3), 9) != 3 || toInt(int64(4), 9) != 4 || toInt(uint64(5), 9) != 5 || toInt("x", 9) != 9 {
		t.Fatalf("toInt mismatch")
	}
	if toInt(float64(3.5), 9) != 9 || toInt(uint64(platformMaxInt)+1, 9) != 9 {
		t.Fatalf("toInt bounds mismatch")
	}
	if toString("ok", "bad") != "ok" || toString(123, "bad") != "bad" {
		t.Fatalf("toString mismatch")
	}
	if !toBool(true, false) || toBool("x", false) {
		t.Fatalf("toBool mismatch")
	}
}

func testRuntimeHelperWriteConsensusErrNonTxError(t *testing.T) {
	t.Helper()
	var out bytes.Buffer
	writeConsensusErr(&out, io.EOF)
	var resp Response
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ok || resp.Err != io.EOF.Error() {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func testRuntimeHelperCompactSize(t *testing.T) {
	t.Helper()
	for _, n := range []uint64{0, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0x1_0000_0000} {
		enc := consensus.EncodeCompactSize(n)
		dec, consumed, err := consensus.DecodeCompactSize(enc)
		if err != nil || dec != n || consumed != len(enc) {
			t.Fatalf("n=%d enc=%x dec=%d consumed=%d err=%v", n, enc, dec, consumed, err)
		}
	}
	assertCompactSizeRejectsShortInputs(t)
}

func assertCompactSizeRejectsShortInputs(t *testing.T) {
	t.Helper()
	if _, _, err := consensus.DecodeCompactSize(nil); err == nil {
		t.Fatalf("expected error")
	}
	if _, _, err := consensus.DecodeCompactSize([]byte{0xfd, 0x01}); err == nil {
		t.Fatalf("expected short error")
	}
	if _, _, err := consensus.DecodeCompactSize([]byte{0xfe, 0x01, 0x02, 0x03}); err == nil {
		t.Fatalf("expected short error")
	}
	if _, _, err := consensus.DecodeCompactSize([]byte{0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}); err == nil {
		t.Fatalf("expected short error")
	}
}

func testRuntimeHelperSliceAndIntHelpers(t *testing.T) {
	t.Helper()
	if slicesEqualInt([]int{1}, []int{1, 2}) {
		t.Fatalf("expected false")
	}
	if slicesEqualInt([]int{1, 2}, []int{1, 3}) {
		t.Fatalf("expected false")
	}
	if !slicesEqualInt([]int{1, 2}, []int{1, 2}) {
		t.Fatalf("expected true")
	}
	assertUniqueSortedInt(t)
	if minInt(1, 2) != 1 || minInt(2, 1) != 1 {
		t.Fatalf("minInt wrong")
	}
	if maxInt(1, 2) != 2 || maxInt(2, 1) != 2 {
		t.Fatalf("maxInt wrong")
	}
}

func assertUniqueSortedInt(t *testing.T) {
	t.Helper()
	u := uniqueSortedInt([]int{3, 1, 3, 2})
	if !slicesEqualInt(u, []int{1, 2, 3}) {
		t.Fatalf("unexpected unique: %v", u)
	}
	if unique := uniqueSortedInt(nil); len(unique) != 0 {
		t.Fatalf("expected empty")
	}
}

func TestRubinConsensusCLI_FeatureBitsStateOp(t *testing.T) {
	act := uint64(consensus.SIGNAL_WINDOW)
	resp := mustRunOk(t, Request{
		Op:                 "featurebits_state",
		Name:               "X",
		Bit:                0,
		StartHeight:        0,
		TimeoutHeight:      consensus.SIGNAL_WINDOW * 10,
		ActivationHeight:   &act,
		Height:             consensus.SIGNAL_WINDOW,
		WindowSignalCounts: []uint32{consensus.SIGNAL_THRESHOLD},
	})
	assertLockedInFeatureBitsResponse(t, resp, act)

	t.Run("bit_out_of_range", testFeatureBitsBitOutOfRange)
	t.Run("started_has_no_estimated_activation", testFeatureBitsStartedHasNoEstimatedActivation)
}

func assertLockedInFeatureBitsResponse(t *testing.T, resp Response, activationHeight uint64) {
	t.Helper()
	if resp.State != "LOCKED_IN" {
		t.Fatalf("expected LOCKED_IN, got %q", resp.State)
	}
	if resp.BoundaryHeight == nil || *resp.BoundaryHeight != consensus.SIGNAL_WINDOW {
		t.Fatalf("expected boundary W, got %v", resp.BoundaryHeight)
	}
	if resp.PrevWindowSignal == nil || *resp.PrevWindowSignal != consensus.SIGNAL_THRESHOLD {
		t.Fatalf("unexpected prev_window_signal_count: %v", resp.PrevWindowSignal)
	}
	if resp.SignalWindow != consensus.SIGNAL_WINDOW {
		t.Fatalf("unexpected signal_window: %d", resp.SignalWindow)
	}
	if resp.SignalThreshold != consensus.SIGNAL_THRESHOLD {
		t.Fatalf("unexpected signal_threshold: %d", resp.SignalThreshold)
	}
	if resp.EstimatedActivate == nil || *resp.EstimatedActivate != 2*consensus.SIGNAL_WINDOW {
		t.Fatalf("unexpected estimated_activation_height: %v", resp.EstimatedActivate)
	}
	if resp.ActivationHeight == nil || *resp.ActivationHeight != activationHeight {
		t.Fatalf("unexpected activation_height: %v", resp.ActivationHeight)
	}
	if resp.ConsensusActive == nil || !*resp.ConsensusActive {
		t.Fatalf("unexpected consensus_active: %v", resp.ConsensusActive)
	}
}

func testFeatureBitsBitOutOfRange(t *testing.T) {
	t.Helper()
	_ = mustRunErr(t, Request{
		Op:                 "featurebits_state",
		Name:               "X",
		Bit:                32,
		StartHeight:        0,
		TimeoutHeight:      1,
		Height:             0,
		WindowSignalCounts: nil,
	}, string(consensus.BLOCK_ERR_PARSE))
}

func testFeatureBitsStartedHasNoEstimatedActivation(t *testing.T) {
	t.Helper()
	act := uint64(1)
	resp := mustRunOk(t, Request{
		Op:                 "featurebits_state",
		Name:               "X",
		Bit:                0,
		StartHeight:        0,
		TimeoutHeight:      consensus.SIGNAL_WINDOW * 10,
		ActivationHeight:   &act,
		Height:             0,
		WindowSignalCounts: nil,
	})
	if resp.State != "STARTED" {
		t.Fatalf("expected STARTED, got %q", resp.State)
	}
	if resp.EstimatedActivate != nil {
		t.Fatalf("expected nil estimated_activation_height, got %v", resp.EstimatedActivate)
	}
	if resp.ConsensusActive == nil || *resp.ConsensusActive {
		t.Fatalf("unexpected consensus_active: %v", resp.ConsensusActive)
	}
}
