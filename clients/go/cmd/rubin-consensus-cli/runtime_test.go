package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
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
	if _, err := wIn.Write(raw); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = wIn.Close()

	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}

	oldIn := os.Stdin
	oldOut := os.Stdout
	os.Stdin = rIn
	os.Stdout = wOut

	outCh := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(rOut)
		outCh <- b
	}()

	entry()
	_ = wOut.Close()

	var outBytes []byte
	select {
	case outBytes = <-outCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for CLI output")
	}

	os.Stdin = oldIn
	os.Stdout = oldOut
	_ = rIn.Close()
	_ = rOut.Close()

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

func TestRubinConsensusCLI_RunFromStdin_CoversKeyOps(t *testing.T) {
	blockBytes, headerBytes := mineGenesisBlockBytes(t)

	var chainID [32]byte
	chainIDHex := mustHex32(chainID)

	var commitment [32]byte
	txBytes := buildAnchorOnlyCoinbaseLikeTxBytes(t, 0, commitment)
	txHex := mustHexBytes(txBytes)

	targetHex := mustHex32(consensus.POW_LIMIT)

	t.Run("bad_request", func(t *testing.T) {
		resp := runRawJSON(t, []byte("{"), runFromStdin)
		if resp.Ok || resp.Err == "" {
			t.Fatalf("expected error")
		}
	})

	t.Run("parse_tx_ok_and_error", func(t *testing.T) {
		ok := mustRunOk(t, Request{Op: "parse_tx", TxHex: txHex})
		if ok.TxidHex == "" || ok.WtxidHex == "" || ok.Consumed == 0 {
			t.Fatalf("unexpected ok resp: %+v", ok)
		}

		_ = mustRunErrAny(t, Request{Op: "parse_tx", TxHex: "00"})
	})

	t.Run("fork_work_and_choice", func(t *testing.T) {
		r := mustRunOk(t, Request{Op: "fork_work", Target: "0x01"})
		if r.WorkHex == "" {
			t.Fatalf("unexpected resp: %+v", r)
		}

		sel := mustRunOk(t, Request{
			Op: "fork_choice_select",
			Chains: []ForkChoiceChain{
				{ID: "a", Targets: []string{"0x02"}, TipHash: "0x02"},
				{ID: "b", Targets: []string{"0x02"}, TipHash: "0x01"}, // tie-break by smaller tip hash
			},
		})
		if sel.Winner != "b" || sel.Chainwork == "" {
			t.Fatalf("unexpected resp: %+v", sel)
		}
	})

	// merkle_root / witness_merkle_root
	t.Run("merkle_roots", func(t *testing.T) {
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
	})

	// sighash_v1 / tx_weight_and_stats
	t.Run("sighash_and_weight", func(t *testing.T) {
		r1 := mustRunOk(t, Request{
			Op:         "sighash_v1",
			TxHex:      txHex,
			InputIndex: 0,
			InputValue: 0,
			ChainIDHex: chainIDHex,
		})
		if len(r1.DigestHex) != 64 {
			t.Fatalf("unexpected resp: %+v", r1)
		}

		_ = mustRunOk(t, Request{Op: "tx_weight_and_stats", TxHex: txHex})
	})

	// header hash / pow check
	t.Run("block_hash_and_pow_check", func(t *testing.T) {
		r1 := mustRunOk(t, Request{Op: "block_hash", HeaderHex: mustHexBytes(headerBytes)})
		if len(r1.BlockHash) != 64 {
			t.Fatalf("unexpected resp: %+v", r1)
		}
		_ = mustRunOk(t, Request{
			Op:        "pow_check",
			HeaderHex: mustHexBytes(headerBytes),
			TargetHex: targetHex,
		})
	})

	t.Run("retarget_v1_both_forms", func(t *testing.T) {
		r1 := runRequest(t, Request{
			Op:             "retarget_v1",
			TargetOldHex:   targetHex,
			TimestampFirst: 100,
			TimestampLast:  200,
		})
		if !r1.Ok || len(r1.TargetNew) != 64 {
			t.Fatalf("unexpected resp: %+v", r1)
		}
		r2 := runRequest(t, Request{
			Op:               "retarget_v1",
			TargetOldHex:     targetHex,
			WindowTimestamps: []uint64{1}, // wrong count -> fast error path, but covers the clamped branch
		})
		if r2.Ok || r2.Err != string(consensus.TX_ERR_PARSE) {
			t.Fatalf("expected TX_ERR_PARSE: %+v", r2)
		}
	})

	// block basic / fees / connect
	t.Run("block_validation_and_connect", func(t *testing.T) {
		blockHex := mustHexBytes(blockBytes)

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
	})

	// compact blocks / telemetry / policy helpers (pure ops)
	t.Run("compact_and_policy_ops", func(t *testing.T) {
		var wtxid [32]byte
		wtxid[0] = 1
		_ = runRequest(t, Request{Op: "compact_shortid", WtxidHex: mustHex32(wtxid), Nonce1: 1, Nonce2: 2})
		_ = runRequest(t, Request{Op: "compact_collision_fallback", MissingIndices: []int{2, 1}, GetblocktxnOK: ptrBool(true)})
		_ = runRequest(t, Request{Op: "compact_witness_roundtrip", PubkeyLength: 3, SigLength: 5})
		_ = runRequest(t, Request{Op: "compact_batch_verify", BatchSize: 4, InvalidIndices: nil})
		_ = runRequest(t, Request{
			Op:               "compact_prefill_roundtrip",
			TxCount:          5,
			PrefilledIndices: []int{0},
			MempoolIndices:   []int{1, 2},
			BlocktxnIndices:  []int{3, 4},
		})
		_ = runRequest(t, Request{
			Op:                "compact_state_machine",
			ChunkCount:        2,
			InitialChunks:     []int{0},
			InitialCommitSeen: ptrBool(false),
			Events: []any{
				map[string]any{"type": "commit"},
				map[string]any{"type": "chunk", "index": 1},
				map[string]any{"type": "checkblock"},
				map[string]any{"type": "tick", "blocks": 1},
			},
		})
		_ = runRequest(t, Request{Op: "compact_orphan_limits", CurrentPeerBytes: 1, CurrentDaIDBytes: 2, CurrentGlobalBytes: 3, IncomingChunkBytes: 4})
		_ = runRequest(t, Request{
			Op:                  "compact_orphan_storm",
			GlobalLimit:         100,
			CurrentGlobalBytes:  95,
			IncomingChunkBytes:  10,
			IncomingHasCommit:   ptrBool(false),
			StormTriggerPct:     90,
			RecoverySuccessRate: 90,
			ObservationMinutes:  10,
		})
		_ = runRequest(t, Request{Op: "compact_chunk_count_cap", ChunkCount: 1, MaxDAChunkCount: 2})
		_ = runRequest(t, Request{Op: "compact_sendcmpct_modes", InIBD: ptrBool(true)})
		_ = runRequest(t, Request{Op: "compact_peer_quality", Events: []any{"getblocktxn_required"}, ElapsedBlocks: 0})
		_ = runRequest(t, Request{Op: "compact_prefetch_caps", PeerStreamsBPS: []int{5_000_000, 10}, PerPeerBPS: 4_000_000, GlobalBPS: 4_000_001})

		rRate := runRequest(t, Request{Op: "compact_telemetry_rate", CompletedSets: 1, TotalSets: 2})
		if !rRate.Ok {
			t.Fatalf("unexpected resp: %+v", rRate)
		}

		rFields := runRequest(t, Request{Op: "compact_telemetry_fields", Telemetry: map[string]any{}})
		if rFields.Ok || rFields.Err == "" {
			t.Fatalf("expected missing telemetry fields error: %+v", rFields)
		}

		_ = runRequest(t, Request{Op: "compact_grace_period", ElapsedBlocks: 0, Events: []any{"prefetch_completed"}})
		_ = runRequest(t, Request{
			Op:      "compact_eviction_tiebreak",
			Entries: []map[string]any{{"da_id": "b", "fee": 100, "wire_bytes": 10, "received_time": 2}, {"da_id": "a", "fee": 50, "wire_bytes": 10, "received_time": 1}},
		})
		_ = runRequest(t, Request{Op: "compact_a_to_b_retention", ChunkCount: 3, InitialChunks: []int{0}, CommitArrives: ptrBool(true)})
		_ = runRequest(t, Request{
			Op:      "compact_duplicate_commit",
			Commits: []map[string]any{{"da_id": "x", "peer": "p1"}, {"da_id": "x", "peer": "p2"}},
		})
		_ = runRequest(t, Request{Op: "compact_total_fee", CommitFee: 1, ChunkFees: []int{2, 3}})
		_ = runRequest(t, Request{Op: "compact_pinned_accounting", CapBytes: 10, CurrentPinnedBytes: 9, IncomingPayload: 2})
		_ = runRequest(t, Request{Op: "compact_storm_commit_bearing", OrphanPoolFillPct: 95, StormTriggerPct: 90, ContainsCommit: ptrBool(true)})
	})

	t.Run("descriptor_nonce_timestamp_and_orders", func(t *testing.T) {
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
	})

	t.Run("htlc_and_vault_policy_ops", func(t *testing.T) {
		r1 := runRequest(t, Request{Op: "htlc_ordering_policy", Path: "refund", LocktimeOK: ptrBool(false)})
		if r1.Ok || r1.Err == "" {
			t.Fatalf("expected refund locktime error: %+v", r1)
		}

		r2 := runRequest(t, Request{Op: "htlc_ordering_policy", Path: "claim", VerifyOK: ptrBool(false)})
		if r2.Ok || r2.Err != string(consensus.TX_ERR_SIG_INVALID) || !r2.VerifyCalled {
			t.Fatalf("unexpected resp: %+v", r2)
		}

		r3 := runRequest(t, Request{
			Op:              "vault_policy_rules",
			OwnerLockID:     "o",
			VaultInputCount: 1,
			NonVaultLockIDs: []string{"o"},
			SumOut:          10,
			SumInVault:      10,
			Slots:           1,
			KeyCount:        1,
			Whitelist:       []string{"aa"},
		})
		if !r3.Ok {
			t.Fatalf("unexpected resp: %+v", r3)
		}
	})
}

func ptrBool(v bool) *bool { return &v }

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
	t.Run("parseHexU256To32", func(t *testing.T) {
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
	})

	t.Run("parseExactHex32_and_optionals", func(t *testing.T) {
		if _, err := parseExactHex32("00"); err == nil {
			t.Fatalf("expected error")
		}
		if _, err := parseExactHex32("zz"); err == nil {
			t.Fatalf("expected error")
		}
		okHex := hex.EncodeToString(make([]byte, 32))
		v, err := parseExactHex32(okHex)
		if err != nil || v != ([32]byte{}) {
			t.Fatalf("unexpected: v=%x err=%v", v, err)
		}
		if opt, err := parseOptionalHex32("", "bad"); err != nil || opt != nil {
			t.Fatalf("unexpected: opt=%v err=%v", opt, err)
		}
		if opt, err := parseOptionalHex32("zz", "bad expected"); err == nil || opt != nil {
			t.Fatalf("expected error")
		}
		if opt, err := parseOptionalHex32(okHex, "bad expected"); err != nil || opt == nil || *opt != ([32]byte{}) {
			t.Fatalf("unexpected optional success: opt=%v err=%v", opt, err)
		}
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
	})

	t.Run("parseBlockValidationInputs", func(t *testing.T) {
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
	})

	t.Run("buildUtxoMap_errors", func(t *testing.T) {
		if _, err := buildUtxoMap([]UtxoJSON{{Txid: "00", CovenantDataHex: ""}}); err == nil {
			t.Fatalf("expected bad utxo txid")
		}
		if _, err := buildUtxoMap([]UtxoJSON{{Txid: hex.EncodeToString(make([]byte, 32)), CovenantDataHex: "zz"}}); err == nil {
			t.Fatalf("expected bad utxo covenant_data")
		}
	})

	t.Run("parseKeyBytes", func(t *testing.T) {
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
	})

	t.Run("default_and_cast_helpers", func(t *testing.T) {
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

		if toInt(float64(3), 9) != 3 || toInt(int64(4), 9) != 4 || toInt(uint64(5), 9) != 5 || toInt("x", 9) != 9 {
			t.Fatalf("toInt mismatch")
		}
		if toString("ok", "bad") != "ok" || toString(123, "bad") != "bad" {
			t.Fatalf("toString mismatch")
		}
		if !toBool(true, false) || toBool("x", false) {
			t.Fatalf("toBool mismatch")
		}
	})

	t.Run("writeConsensusErr_non_txerror", func(t *testing.T) {
		var out bytes.Buffer
		writeConsensusErr(&out, io.EOF)
		var resp Response
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if resp.Ok || resp.Err != io.EOF.Error() {
			t.Fatalf("unexpected response: %+v", resp)
		}
	})

	t.Run("compactsize_helpers", func(t *testing.T) {
		cases := []uint64{0, 1, 0xfc, 0xfd, 0xffff, 0x1_0000, 0x1_0000_0000}
		for _, n := range cases {
			enc := consensus.EncodeCompactSize(n)
			dec, consumed, err := consensus.DecodeCompactSize(enc)
			if err != nil || dec != n || consumed != len(enc) {
				t.Fatalf("n=%d enc=%x dec=%d consumed=%d err=%v", n, enc, dec, consumed, err)
			}
		}
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
	})

	t.Run("slice_and_int_helpers", func(t *testing.T) {
		if slicesEqualInt([]int{1}, []int{1, 2}) {
			t.Fatalf("expected false")
		}
		if !slicesEqualInt([]int{1, 2}, []int{1, 2}) {
			t.Fatalf("expected true")
		}
		u := uniqueSortedInt([]int{3, 1, 3, 2})
		if !slicesEqualInt(u, []int{1, 2, 3}) {
			t.Fatalf("unexpected unique: %v", u)
		}
		if unique := uniqueSortedInt(nil); len(unique) != 0 {
			t.Fatalf("expected empty")
		}
		if minInt(1, 2) != 1 || minInt(2, 1) != 1 {
			t.Fatalf("minInt wrong")
		}
		if maxInt(1, 2) != 2 || maxInt(2, 1) != 2 {
			t.Fatalf("maxInt wrong")
		}
	})
}
