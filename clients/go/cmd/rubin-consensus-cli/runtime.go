package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type Request struct {
	Op              string   `json:"op"`
	TxHex           string   `json:"tx_hex,omitempty"`
	BlockHex        string   `json:"block_hex,omitempty"`
	Txids           []string `json:"txids,omitempty"`
	Wtxids          []string `json:"wtxids,omitempty"`
	WtxidHex        string   `json:"wtxid,omitempty"`
	CovenantType    uint16   `json:"covenant_type,omitempty"`
	CovenantDataHex string   `json:"covenant_data_hex,omitempty"`
	Nonce1          uint64   `json:"nonce1,omitempty"`
	Nonce2          uint64   `json:"nonce2,omitempty"`
	InputIndex      uint32   `json:"input_index,omitempty"`
	InputValue      uint64   `json:"input_value,omitempty"`
	ChainIDHex      string   `json:"chain_id,omitempty"`

	HeaderHex        string   `json:"header_hex,omitempty"`
	TargetHex        string   `json:"target_hex,omitempty"`
	Target           string   `json:"target,omitempty"`
	TargetOldHex     string   `json:"target_old,omitempty"`
	TimestampFirst   uint64   `json:"timestamp_first,omitempty"`
	TimestampLast    uint64   `json:"timestamp_last,omitempty"`
	WindowTimestamps []uint64 `json:"window_timestamps,omitempty"`
	ExpectedPrev     string   `json:"expected_prev_hash,omitempty"`
	ExpectedTarget   string   `json:"expected_target,omitempty"`
	PrevTimestamps   []uint64 `json:"prev_timestamps,omitempty"`
	AlreadyGenerated uint64   `json:"already_generated,omitempty"`
	SumFees          uint64   `json:"sum_fees,omitempty"`

	Utxos          []UtxoJSON `json:"utxos,omitempty"`
	Height         uint64     `json:"height,omitempty"`
	BlockTimestamp uint64     `json:"block_timestamp,omitempty"`
	BlockMTP       *uint64    `json:"block_mtp,omitempty"`

	Chains []ForkChoiceChain `json:"chains,omitempty"`

	Nonces         []uint64 `json:"nonces,omitempty"`
	MTP            uint64   `json:"mtp,omitempty"`
	Timestamp      uint64   `json:"timestamp,omitempty"`
	MaxFutureDrift *uint64  `json:"max_future_drift,omitempty"`
	Keys           []any    `json:"keys,omitempty"`
	Checks         []Check  `json:"checks,omitempty"`

	Path                string  `json:"path,omitempty"`
	StructuralOK        *bool   `json:"structural_ok,omitempty"`
	LocktimeOK          *bool   `json:"locktime_ok,omitempty"`
	SuiteID             *uint8  `json:"suite_id,omitempty"`
	SLHActivationHeight *uint64 `json:"slh_activation_height,omitempty"`
	KeyBindingOK        *bool   `json:"key_binding_ok,omitempty"`
	PreimageOK          *bool   `json:"preimage_ok,omitempty"`
	VerifyOK            *bool   `json:"verify_ok,omitempty"`

	OwnerLockID          string   `json:"owner_lock_id,omitempty"`
	VaultInputCount      int      `json:"vault_input_count,omitempty"`
	NonVaultLockIDs      []string `json:"non_vault_lock_ids,omitempty"`
	HasOwnerAuth         *bool    `json:"has_owner_auth,omitempty"`
	SumOut               uint64   `json:"sum_out,omitempty"`
	SumInVault           uint64   `json:"sum_in_vault,omitempty"`
	Slots                int      `json:"slots,omitempty"`
	KeyCount             int      `json:"key_count,omitempty"`
	SigThresholdOK       *bool    `json:"sig_threshold_ok,omitempty"`
	SentinelSuiteID      uint8    `json:"sentinel_suite_id,omitempty"`
	SentinelPubkeyLen    int      `json:"sentinel_pubkey_len,omitempty"`
	SentinelSigLen       int      `json:"sentinel_sig_len,omitempty"`
	SentinelVerifyCalled *bool    `json:"sentinel_verify_called,omitempty"`
	Whitelist            []string `json:"whitelist,omitempty"`
	ValidationOrder      []string `json:"validation_order,omitempty"`

	MissingIndices      []int            `json:"missing_indices,omitempty"`
	GetblocktxnOK       *bool            `json:"getblocktxn_ok,omitempty"`
	PubkeyLength        int              `json:"pubkey_length,omitempty"`
	SigLength           int              `json:"sig_length,omitempty"`
	BatchSize           int              `json:"batch_size,omitempty"`
	InvalidIndices      []int            `json:"invalid_indices,omitempty"`
	TxCount             int              `json:"tx_count,omitempty"`
	PrefilledIndices    []int            `json:"prefilled_indices,omitempty"`
	MempoolIndices      []int            `json:"mempool_indices,omitempty"`
	BlocktxnIndices     []int            `json:"blocktxn_indices,omitempty"`
	ChunkCount          int              `json:"chunk_count,omitempty"`
	TTLBlocks           int              `json:"ttl_blocks,omitempty"`
	InitialChunks       []int            `json:"initial_chunks,omitempty"`
	InitialCommitSeen   *bool            `json:"initial_commit_seen,omitempty"`
	CommitArrives       *bool            `json:"commit_arrives,omitempty"`
	Events              []any            `json:"events,omitempty"`
	PerPeerLimit        int              `json:"per_peer_limit,omitempty"`
	PerDaIDLimit        int              `json:"per_da_id_limit,omitempty"`
	GlobalLimit         int              `json:"global_limit,omitempty"`
	CurrentPeerBytes    int              `json:"current_peer_bytes,omitempty"`
	CurrentDaIDBytes    int              `json:"current_da_id_bytes,omitempty"`
	CurrentGlobalBytes  int              `json:"current_global_bytes,omitempty"`
	IncomingChunkBytes  int              `json:"incoming_chunk_bytes,omitempty"`
	IncomingHasCommit   *bool            `json:"incoming_has_commit,omitempty"`
	StormTriggerPct     float64          `json:"storm_trigger_pct,omitempty"`
	RecoverySuccessRate float64          `json:"recovery_success_rate,omitempty"`
	ObservationMinutes  int              `json:"observation_minutes,omitempty"`
	MaxDAChunkCount     int              `json:"max_da_chunk_count,omitempty"`
	Phases              []map[string]any `json:"phases,omitempty"`
	InIBD               *bool            `json:"in_ibd,omitempty"`
	WarmupDone          *bool            `json:"warmup_done,omitempty"`
	MissRatePct         float64          `json:"miss_rate_pct,omitempty"`
	MissRateBlocks      int              `json:"miss_rate_blocks,omitempty"`
	StartScore          int              `json:"start_score,omitempty"`
	GracePeriodActive   *bool            `json:"grace_period_active,omitempty"`
	ElapsedBlocks       int              `json:"elapsed_blocks,omitempty"`
	PerPeerBPS          int              `json:"per_peer_bps,omitempty"`
	GlobalBPS           int              `json:"global_bps,omitempty"`
	PeerStreamsBPS      []int            `json:"peer_streams_bps,omitempty"`
	PeerStreamBPS       int              `json:"peer_stream_bps,omitempty"`
	ActiveSets          int              `json:"active_sets,omitempty"`
	CompletedSets       int              `json:"completed_sets,omitempty"`
	TotalSets           int              `json:"total_sets,omitempty"`
	Telemetry           map[string]any   `json:"telemetry,omitempty"`
	GracePeriodBlocks   int              `json:"grace_period_blocks,omitempty"`
	Entries             []map[string]any `json:"entries,omitempty"`
	DaID                string           `json:"da_id,omitempty"`
	Commits             []map[string]any `json:"commits,omitempty"`
	CommitFee           int              `json:"commit_fee,omitempty"`
	ChunkFees           []int            `json:"chunk_fees,omitempty"`
	CurrentPinnedBytes  int              `json:"current_pinned_payload_bytes,omitempty"`
	IncomingPayload     int              `json:"incoming_payload_bytes,omitempty"`
	IncomingOverhead    int              `json:"incoming_commit_overhead_bytes,omitempty"`
	CapBytes            int              `json:"cap_bytes,omitempty"`
	ContainsCommit      *bool            `json:"contains_commit,omitempty"`
	ContainsKnownChunk  *bool            `json:"contains_chunk_for_known_commit,omitempty"`
	ContainsBlockCommit *bool            `json:"contains_block_with_commit,omitempty"`
	OrphanPoolFillPct   float64          `json:"orphan_pool_fill_pct,omitempty"`
}

type UtxoJSON struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantDataHex   string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

type ForkChoiceChain struct {
	ID      string   `json:"id"`
	Targets []string `json:"targets"`
	TipHash string   `json:"tip_hash"`
}

type Check struct {
	Name  string `json:"name"`
	Fails bool   `json:"fails"`
	Err   string `json:"err"`
}

type Response struct {
	Ok                 bool   `json:"ok"`
	Err                string `json:"err,omitempty"`
	TxidHex            string `json:"txid,omitempty"`
	WtxidHex           string `json:"wtxid,omitempty"`
	MerkleHex          string `json:"merkle_root,omitempty"`
	WitnessMerkleHex   string `json:"witness_merkle_root,omitempty"`
	DigestHex          string `json:"digest,omitempty"`
	BlockHash          string `json:"block_hash,omitempty"`
	TargetNew          string `json:"target_new,omitempty"`
	ShortID            string `json:"short_id,omitempty"`
	DescriptorHex      string `json:"descriptor_hex,omitempty"`
	Consumed           int    `json:"consumed,omitempty"`
	Fee                uint64 `json:"fee,omitempty"`
	SumFees            uint64 `json:"sum_fees,omitempty"`
	UtxoCount          uint64 `json:"utxo_count,omitempty"`
	AlreadyGenerated   uint64 `json:"already_generated,omitempty"`
	AlreadyGeneratedN1 uint64 `json:"already_generated_n1,omitempty"`
	Weight             uint64 `json:"weight"`
	DaBytes            uint64 `json:"da_bytes"`
	AnchorBytes        uint64 `json:"anchor_bytes"`

	WorkHex            string   `json:"work,omitempty"`
	Winner             string   `json:"winner,omitempty"`
	Chainwork          string   `json:"chainwork,omitempty"`
	Duplicates         []uint64 `json:"duplicates,omitempty"`
	SortedKeys         []string `json:"sorted_keys,omitempty"`
	FirstErr           string   `json:"first_err,omitempty"`
	Evaluated          []string `json:"evaluated,omitempty"`
	VerifyCalled       bool     `json:"verify_called,omitempty"`
	RequestGetblocktxn bool     `json:"request_getblocktxn,omitempty"`
	RequestFullBlock   bool     `json:"request_full_block,omitempty"`
	PenalizePeer       bool     `json:"penalize_peer,omitempty"`
	RoundtripOK        bool     `json:"roundtrip_ok,omitempty"`
	WireBytes          int      `json:"wire_bytes,omitempty"`
	BatchOK            bool     `json:"batch_ok,omitempty"`
	Fallback           bool     `json:"fallback,omitempty"`
	InvalidOut         []int    `json:"invalid_indices,omitempty"`
	MissingOut         []int    `json:"missing_indices,omitempty"`
	Reconstructed      bool     `json:"reconstructed,omitempty"`
	State              string   `json:"state,omitempty"`
	Evicted            bool     `json:"evicted,omitempty"`
	Pinned             bool     `json:"pinned,omitempty"`
	TTL                int      `json:"ttl,omitempty"`
	TTLResetCount      int      `json:"ttl_reset_count,omitempty"`
	CheckblockResults  []bool   `json:"checkblock_results,omitempty"`
	Admit              bool     `json:"admit,omitempty"`
	FillPct            float64  `json:"fill_pct,omitempty"`
	StormMode          bool     `json:"storm_mode,omitempty"`
	Rollback           bool     `json:"rollback,omitempty"`
	Mode               int      `json:"mode,omitempty"`
	Score              int      `json:"score,omitempty"`
	PeerExceeded       bool     `json:"peer_exceeded,omitempty"`
	GlobalExceeded     bool     `json:"global_exceeded,omitempty"`
	QualityPenalty     bool     `json:"quality_penalty,omitempty"`
	Disconnect         bool     `json:"disconnect,omitempty"`
	Rate               float64  `json:"rate,omitempty"`
	MissingFields      []string `json:"missing_fields,omitempty"`
	EvictOrder         []string `json:"evict_order,omitempty"`
	RetainedChunks     []int    `json:"retained_chunks,omitempty"`
	PrefetchTargets    []int    `json:"prefetch_targets,omitempty"`
	DiscardedChunks    []int    `json:"discarded_chunks,omitempty"`
	RetainedPeer       string   `json:"retained_peer,omitempty"`
	DuplicatesDropped  int      `json:"duplicates_dropped,omitempty"`
	PenalizedPeers     []string `json:"penalized_peers,omitempty"`
	Replaced           bool     `json:"replaced,omitempty"`
	TotalFee           int      `json:"total_fee,omitempty"`
	CountedBytes       int      `json:"counted_bytes,omitempty"`
	IgnoredOverhead    int      `json:"ignored_overhead_bytes,omitempty"`
	CommitBearing      bool     `json:"commit_bearing,omitempty"`
	Prioritize         bool     `json:"prioritize,omitempty"`
}

func writeResp(w io.Writer, resp Response) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(resp)
}

func writeConsensusErr(w io.Writer, err error) {
	if te, ok := err.(*consensus.TxError); ok {
		writeResp(w, Response{Ok: false, Err: string(te.Code)})
		return
	}
	writeResp(w, Response{Ok: false, Err: err.Error()})
}

func parseHexU256To32(s string) ([32]byte, error) {
	var out [32]byte
	stripped := strings.TrimSpace(strings.ToLower(s))
	stripped = strings.TrimPrefix(stripped, "0x")
	if stripped == "" {
		return out, fmt.Errorf("empty")
	}
	if len(stripped)%2 == 1 {
		stripped = "0" + stripped
	}
	b, err := hex.DecodeString(stripped)
	if err != nil {
		return out, err
	}
	if len(b) > 32 {
		return out, fmt.Errorf("overflow")
	}
	copy(out[32-len(b):], b)
	return out, nil
}

func parseExactHex32(hexValue string) ([32]byte, error) {
	var out [32]byte
	stripped := strings.TrimSpace(hexValue)
	stripped = strings.TrimPrefix(strings.TrimPrefix(stripped, "0x"), "0X")
	b, err := hex.DecodeString(stripped)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func parseOptionalHex32(hexValue string, badErr string) (*[32]byte, error) {
	if strings.TrimSpace(hexValue) == "" {
		return nil, nil
	}
	value, err := parseExactHex32(hexValue)
	if err != nil {
		return nil, fmt.Errorf("%s", badErr)
	}
	return &value, nil
}

func parseOptionalChainIDHex(chainIDHex string) ([32]byte, error) {
	var chainID [32]byte
	if strings.TrimSpace(chainIDHex) == "" {
		return chainID, nil
	}
	parsed, err := parseExactHex32(chainIDHex)
	if err != nil {
		return chainID, fmt.Errorf("bad chain_id")
	}
	return parsed, nil
}

func parseHex32List(items []string, badErr string) ([][32]byte, error) {
	parsed := make([][32]byte, 0, len(items))
	for _, item := range items {
		value, err := parseExactHex32(item)
		if err != nil {
			return nil, fmt.Errorf("%s", badErr)
		}
		parsed = append(parsed, value)
	}
	return parsed, nil
}

func parseBlockValidationInputs(req Request) ([]byte, *[32]byte, *[32]byte, error) {
	blockBytes, err := hex.DecodeString(req.BlockHex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bad block")
	}
	expectedPrev, err := parseOptionalHex32(req.ExpectedPrev, "bad expected_prev_hash")
	if err != nil {
		return nil, nil, nil, err
	}
	expectedTarget, err := parseOptionalHex32(req.ExpectedTarget, "bad expected_target")
	if err != nil {
		return nil, nil, nil, err
	}
	return blockBytes, expectedPrev, expectedTarget, nil
}

func buildUtxoMap(items []UtxoJSON) (map[consensus.Outpoint]consensus.UtxoEntry, error) {
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(items))
	for _, item := range items {
		parsedTxid, err := parseExactHex32(item.Txid)
		if err != nil {
			return nil, fmt.Errorf("bad utxo txid")
		}
		covenantData, err := hex.DecodeString(item.CovenantDataHex)
		if err != nil {
			return nil, fmt.Errorf("bad utxo covenant_data")
		}

		outpoint := consensus.Outpoint{Txid: parsedTxid, Vout: item.Vout}
		utxos[outpoint] = consensus.UtxoEntry{
			Value:             item.Value,
			CovenantType:      item.CovenantType,
			CovenantData:      covenantData,
			CreationHeight:    item.CreationHeight,
			CreatedByCoinbase: item.CreatedByCoinbase,
		}
	}
	return utxos, nil
}

func boolOrDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func uint8OrDefault(v *uint8, def uint8) uint8 {
	if v == nil {
		return def
	}
	return *v
}

func uint64OrDefault(v *uint64, def uint64) uint64 {
	if v == nil {
		return def
	}
	return *v
}

func parseKeyBytes(item any) ([]byte, error) {
	if s, ok := item.(string); ok {
		stripped := strings.TrimSpace(strings.ToLower(s))
		if strings.HasPrefix(stripped, "0x") {
			stripped = strings.TrimPrefix(stripped, "0x")
			if len(stripped)%2 == 1 {
				stripped = "0" + stripped
			}
			b, err := hex.DecodeString(stripped)
			if err != nil {
				return nil, err
			}
			return b, nil
		}
		return []byte(s), nil
	}
	return []byte(fmt.Sprintf("%v", item)), nil
}

func asSortedInts(values []int) []int {
	out := append([]int(nil), values...)
	sort.Ints(out)
	return out
}

func toInt(v any, def int) int {
	switch value := v.(type) {
	case float64:
		return int(value)
	case int:
		return value
	case int64:
		return int(value)
	case uint64:
		return int(value)
	default:
		return def
	}
}

func toString(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func toBool(v any, def bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return def
}

func runFromStdin() {
	var req Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		writeResp(os.Stdout, Response{Ok: false, Err: fmt.Sprintf("bad request: %v", err)})
		return
	}

	switch req.Op {
	case "parse_tx":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		_, txid, wtxid, n, err := consensus.ParseTx(txBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{
			Ok:       true,
			TxidHex:  hex.EncodeToString(txid[:]),
			WtxidHex: hex.EncodeToString(wtxid[:]),
			Consumed: n,
		})
		return

	case "fork_work":
		t, err := parseHexU256To32(req.Target)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad target"})
			return
		}
		work, err := consensus.WorkFromTarget(t)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, WorkHex: "0x" + work.Text(16)})
		return

	case "fork_choice_select":
		if len(req.Chains) == 0 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad chains"})
			return
		}
		var bestID string
		var bestWork *big.Int
		var bestTip []byte

		for _, c := range req.Chains {
			if c.ID == "" || len(c.Targets) == 0 {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad chain"})
				return
			}
			tip, err := parseHexU256To32(c.TipHash)
			if err != nil {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad tip_hash"})
				return
			}
			tipb := tip[:]

			total := new(big.Int)
			for _, ts := range c.Targets {
				tb, err := parseHexU256To32(ts)
				if err != nil {
					writeResp(os.Stdout, Response{Ok: false, Err: "bad target"})
					return
				}
				w, err := consensus.WorkFromTarget(tb)
				if err != nil {
					writeConsensusErr(os.Stdout, err)
					return
				}
				total.Add(total, w)
			}

			if bestWork == nil ||
				total.Cmp(bestWork) > 0 ||
				(total.Cmp(bestWork) == 0 && (bestTip == nil || bytes.Compare(tipb, bestTip) < 0)) {
				bestID = c.ID
				bestWork = total
				bestTip = append(bestTip[:0], tipb...)
			}
		}

		writeResp(os.Stdout, Response{
			Ok:        true,
			Winner:    bestID,
			Chainwork: "0x" + bestWork.Text(16),
		})
		return

	case "merkle_root":
		txids, err := parseHex32List(req.Txids, "bad txid")
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		root, err := consensus.MerkleRootTxids(txids)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, MerkleHex: hex.EncodeToString(root[:])})
		return

	case "witness_merkle_root":
		wtxids, err := parseHex32List(req.Wtxids, "bad wtxid")
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		root, err := consensus.WitnessMerkleRootWtxids(wtxids)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, WitnessMerkleHex: hex.EncodeToString(root[:])})
		return

	case "sighash_v1":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, _, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}

		chainIDBytes, err := hex.DecodeString(req.ChainIDHex)
		if err != nil || len(chainIDBytes) != 32 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad chain_id"})
			return
		}
		var chainID [32]byte
		copy(chainID[:], chainIDBytes)

		d, err := consensus.SighashV1Digest(tx, req.InputIndex, req.InputValue, chainID)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, DigestHex: hex.EncodeToString(d[:])})
		return

	case "tx_weight_and_stats":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, _, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		w, da, anchor, err := consensus.TxWeightAndStats(tx)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, Weight: w, DaBytes: da, AnchorBytes: anchor})
		return

	case "block_hash":
		headerBytes, err := hex.DecodeString(req.HeaderHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad header"})
			return
		}
		h, err := consensus.BlockHash(headerBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, BlockHash: hex.EncodeToString(h[:])})
		return

	case "pow_check":
		headerBytes, err := hex.DecodeString(req.HeaderHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad header"})
			return
		}
		targetBytes, err := hex.DecodeString(req.TargetHex)
		if err != nil || len(targetBytes) != 32 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad target"})
			return
		}
		var target [32]byte
		copy(target[:], targetBytes)
		if err := consensus.PowCheck(headerBytes, target); err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true})
		return

	case "retarget_v1":
		oldBytes, err := hex.DecodeString(req.TargetOldHex)
		if err != nil || len(oldBytes) != 32 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad target_old"})
			return
		}
		var old [32]byte
		copy(old[:], oldBytes)
		var newT [32]byte
		var retErr error
		if len(req.WindowTimestamps) > 0 {
			newT, retErr = consensus.RetargetV1Clamped(old, req.WindowTimestamps)
		} else {
			newT, retErr = consensus.RetargetV1(old, req.TimestampFirst, req.TimestampLast)
		}
		if retErr != nil {
			writeConsensusErr(os.Stdout, retErr)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, TargetNew: hex.EncodeToString(newT[:])})
		return

	case "block_basic_check":
		blockBytes, expectedPrev, expectedTarget, err := parseBlockValidationInputs(req)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		s, err := consensus.ValidateBlockBasicWithContextAtHeight(
			blockBytes,
			expectedPrev,
			expectedTarget,
			req.Height,
			req.PrevTimestamps,
		)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, BlockHash: hex.EncodeToString(s.BlockHash[:])})
		return

	case "block_basic_check_with_fees":
		blockBytes, expectedPrev, expectedTarget, err := parseBlockValidationInputs(req)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		s, err := consensus.ValidateBlockBasicWithContextAndFeesAtHeight(
			blockBytes,
			expectedPrev,
			expectedTarget,
			req.Height,
			req.PrevTimestamps,
			req.AlreadyGenerated,
			req.SumFees,
		)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, BlockHash: hex.EncodeToString(s.BlockHash[:])})
		return

	case "connect_block_basic":
		blockBytes, expectedPrev, expectedTarget, err := parseBlockValidationInputs(req)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		utxos, err := buildUtxoMap(req.Utxos)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		st := consensus.InMemoryChainState{
			Utxos:            utxos,
			AlreadyGenerated: req.AlreadyGenerated,
		}

		chainID, err := parseOptionalChainIDHex(req.ChainIDHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		s, err := consensus.ConnectBlockBasicInMemoryAtHeight(
			blockBytes,
			expectedPrev,
			expectedTarget,
			req.Height,
			req.PrevTimestamps,
			&st,
			chainID,
		)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{
			Ok:                 true,
			SumFees:            s.SumFees,
			UtxoCount:          s.UtxoCount,
			AlreadyGenerated:   s.AlreadyGenerated,
			AlreadyGeneratedN1: s.AlreadyGeneratedN1,
		})
		return

	case "covenant_genesis_check":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, _, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		if err := consensus.ValidateTxCovenantsGenesis(tx, req.Height); err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true})
		return

	case "utxo_apply_basic":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, txid, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}

		utxos, err := buildUtxoMap(req.Utxos)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		blockMTP := req.BlockTimestamp
		if req.BlockMTP != nil {
			blockMTP = *req.BlockMTP
		}

		chainID, err := parseOptionalChainIDHex(req.ChainIDHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		s, err := consensus.ApplyNonCoinbaseTxBasicWithMTP(tx, txid, utxos, req.Height, req.BlockTimestamp, blockMTP, chainID)
		if err != nil {
			writeConsensusErr(os.Stdout, err)
			return
		}
		writeResp(os.Stdout, Response{Ok: true, Fee: s.Fee, UtxoCount: s.UtxoCount})
		return

	case "compact_shortid":
		wtxidBytes, err := hex.DecodeString(req.WtxidHex)
		if err != nil || len(wtxidBytes) != 32 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad wtxid"})
			return
		}
		var wtxid [32]byte
		copy(wtxid[:], wtxidBytes)

		shortID := consensus.CompactShortID(wtxid, req.Nonce1, req.Nonce2)
		writeResp(os.Stdout, Response{Ok: true, ShortID: hex.EncodeToString(shortID[:])})
		return

	case "compact_collision_fallback":
		missing := asSortedInts(req.MissingIndices)
		getblocktxnOK := boolOrDefault(req.GetblocktxnOK, true)
		requestGetBlockTxn := len(missing) > 0
		requestFullBlock := requestGetBlockTxn && !getblocktxnOK
		writeResp(os.Stdout, Response{
			Ok:                 true,
			RequestGetblocktxn: requestGetBlockTxn,
			RequestFullBlock:   requestFullBlock,
			PenalizePeer:       false,
		})
		return

	case "compact_witness_roundtrip":
		suiteID := uint8OrDefault(req.SuiteID, 0x01)
		pubLen := req.PubkeyLength
		sigLen := req.SigLength
		wire := make([]byte, 0, 1+9+pubLen+9+sigLen)
		wire = append(wire, suiteID)
		wire = append(wire, encodeCompactSize(uint64(pubLen))...)
		wire = append(wire, bytes.Repeat([]byte{0x11}, pubLen)...)
		wire = append(wire, encodeCompactSize(uint64(sigLen))...)
		wire = append(wire, bytes.Repeat([]byte{0x22}, sigLen)...)
		off := 0
		if len(wire) < 1 {
			writeResp(os.Stdout, Response{Ok: false, Err: "wire underflow"})
			return
		}
		suite2 := wire[off]
		off += 1
		pub2, n, err := decodeCompactSize(wire[off:])
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "wire decode failed"})
			return
		}
		off += n
		if off+int(pub2) > len(wire) {
			writeResp(os.Stdout, Response{Ok: false, Err: "wire bounds"})
			return
		}
		off += int(pub2)
		sig2, n, err := decodeCompactSize(wire[off:])
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "wire decode failed"})
			return
		}
		off += n
		if off+int(sig2) > len(wire) {
			writeResp(os.Stdout, Response{Ok: false, Err: "wire bounds"})
			return
		}
		off += int(sig2)
		roundtripOK := suite2 == suiteID && int(pub2) == pubLen && int(sig2) == sigLen && off == len(wire)
		writeResp(os.Stdout, Response{
			Ok:          true,
			RoundtripOK: roundtripOK,
			WireBytes:   len(wire),
		})
		return

	case "compact_batch_verify":
		batchSize := req.BatchSize
		if batchSize == 0 {
			batchSize = 64
		}
		invalid := asSortedInts(req.InvalidIndices)
		for _, idx := range invalid {
			if idx < 0 || idx >= batchSize {
				writeResp(os.Stdout, Response{Ok: false, Err: "invalid index out of range"})
				return
			}
		}
		batchOK := len(invalid) == 0
		writeResp(os.Stdout, Response{
			Ok:         true,
			BatchOK:    batchOK,
			Fallback:   !batchOK,
			InvalidOut: invalid,
		})
		return

	case "compact_prefill_roundtrip":
		txCount := req.TxCount
		prefilled := make(map[int]struct{}, len(req.PrefilledIndices))
		for _, idx := range asSortedInts(req.PrefilledIndices) {
			prefilled[idx] = struct{}{}
		}
		mempool := make(map[int]struct{}, len(req.MempoolIndices))
		for _, idx := range asSortedInts(req.MempoolIndices) {
			mempool[idx] = struct{}{}
		}
		blockTxn := asSortedInts(req.BlocktxnIndices)
		shortIDIndices := make([]int, 0)
		for i := 0; i < txCount; i++ {
			if _, ok := prefilled[i]; !ok {
				shortIDIndices = append(shortIDIndices, i)
			}
		}
		missing := make([]int, 0)
		for _, idx := range shortIDIndices {
			if _, ok := mempool[idx]; !ok {
				missing = append(missing, idx)
			}
		}
		requestGetBlockTxn := len(missing) > 0
		reconstructed := !requestGetBlockTxn || slicesEqualInt(blockTxn, missing)
		requestFullBlock := requestGetBlockTxn && !reconstructed
		writeResp(os.Stdout, Response{
			Ok:               true,
			MissingOut:       missing,
			Reconstructed:    reconstructed,
			RequestFullBlock: requestFullBlock,
		})
		return

	case "compact_state_machine":
		chunkCount := req.ChunkCount
		ttlCfg := req.TTLBlocks
		if ttlCfg == 0 {
			ttlCfg = 3
		}
		chunks := make(map[int]struct{}, len(req.InitialChunks))
		for _, idx := range asSortedInts(req.InitialChunks) {
			chunks[idx] = struct{}{}
		}
		commitSeen := boolOrDefault(req.InitialCommitSeen, false)
		state := "A"
		if commitSeen && len(chunks) == chunkCount {
			state = "C"
		} else if commitSeen {
			state = "B"
		}
		pinned := state == "C"
		ttl := ttlCfg
		if state == "C" {
			ttl = 0
		}
		ttlResetCount := 0
		evicted := false
		checkblockResults := make([]bool, 0)
		for _, raw := range req.Events {
			eventMap, ok := raw.(map[string]any)
			if !ok {
				writeResp(os.Stdout, Response{Ok: false, Err: "state-machine event must be object"})
				return
			}
			typ := toString(eventMap["type"], "")
			switch typ {
			case "chunk":
				idx := toInt(eventMap["index"], -1)
				if idx >= 0 && idx < chunkCount && state != "EVICTED" {
					chunks[idx] = struct{}{}
				}
				if commitSeen && len(chunks) == chunkCount {
					state = "C"
					pinned = true
				}
			case "commit":
				if state != "EVICTED" {
					if state == "A" {
						ttl = ttlCfg
						ttlResetCount++
					}
					commitSeen = true
					if len(chunks) == chunkCount {
						state = "C"
						pinned = true
					} else {
						state = "B"
						pinned = false
					}
				}
			case "tick":
				if state == "A" || state == "B" {
					ttl -= toInt(eventMap["blocks"], 1)
					if ttl <= 0 {
						state = "EVICTED"
						evicted = true
						commitSeen = false
						chunks = map[int]struct{}{}
						pinned = false
						ttl = 0
					}
				}
			case "checkblock":
				checkblockResults = append(checkblockResults, commitSeen && len(chunks) == chunkCount)
			default:
				writeResp(os.Stdout, Response{Ok: false, Err: "unknown state-machine event type"})
				return
			}
		}
		writeResp(os.Stdout, Response{
			Ok:                true,
			State:             state,
			Evicted:           evicted,
			Pinned:            pinned,
			TTL:               ttl,
			TTLResetCount:     ttlResetCount,
			CheckblockResults: checkblockResults,
		})
		return

	case "compact_orphan_limits":
		perPeerLimit := req.PerPeerLimit
		if perPeerLimit == 0 {
			perPeerLimit = 4 * 1024 * 1024
		}
		perDaIDLimit := req.PerDaIDLimit
		if perDaIDLimit == 0 {
			perDaIDLimit = 8 * 1024 * 1024
		}
		globalLimit := req.GlobalLimit
		if globalLimit == 0 {
			globalLimit = 64 * 1024 * 1024
		}
		admit := req.CurrentPeerBytes+req.IncomingChunkBytes <= perPeerLimit &&
			req.CurrentDaIDBytes+req.IncomingChunkBytes <= perDaIDLimit &&
			req.CurrentGlobalBytes+req.IncomingChunkBytes <= globalLimit
		writeResp(os.Stdout, Response{Ok: true, Admit: admit})
		return

	case "compact_orphan_storm":
		globalLimit := req.GlobalLimit
		if globalLimit == 0 {
			globalLimit = 64 * 1024 * 1024
		}
		incomingHasCommit := boolOrDefault(req.IncomingHasCommit, false)
		stormTriggerPct := req.StormTriggerPct
		if stormTriggerPct == 0 {
			stormTriggerPct = 90.0
		}
		fillPct := 0.0
		if globalLimit > 0 {
			fillPct = 100.0 * float64(req.CurrentGlobalBytes) / float64(globalLimit)
		}
		stormMode := fillPct > stormTriggerPct
		rollback := req.RecoverySuccessRate < 95.0 && req.ObservationMinutes >= 10
		admit := req.CurrentGlobalBytes+req.IncomingChunkBytes <= globalLimit
		if stormMode && !incomingHasCommit {
			admit = false
		}
		writeResp(os.Stdout, Response{
			Ok:        true,
			FillPct:   fillPct,
			StormMode: stormMode,
			Admit:     admit,
			Rollback:  rollback,
		})
		return

	case "compact_chunk_count_cap":
		maxCount := req.MaxDAChunkCount
		if maxCount == 0 {
			maxCount = 32_000_000 / 524_288
		}
		ok := req.ChunkCount >= 0 && req.ChunkCount <= maxCount
		if !ok {
			writeResp(os.Stdout, Response{Ok: false, Err: string(consensus.TX_ERR_PARSE)})
			return
		}
		writeResp(os.Stdout, Response{Ok: true})
		return

	case "compact_sendcmpct_modes":
		computeMode := func(payload map[string]any) int {
			inIBD := toBool(payload["in_ibd"], false)
			warmupDone := toBool(payload["warmup_done"], false)
			missRatePct, _ := payload["miss_rate_pct"].(float64)
			missRateBlocks := toInt(payload["miss_rate_blocks"], 0)
			if inIBD {
				return 0
			}
			if missRatePct > 10.0 && missRateBlocks >= 5 {
				return 0
			}
			if warmupDone && missRatePct <= 0.5 {
				return 2
			}
			if warmupDone {
				return 1
			}
			return 0
		}
		if len(req.Phases) > 0 {
			modes := make([]int, 0, len(req.Phases))
			for _, phase := range req.Phases {
				modes = append(modes, computeMode(phase))
			}
			writeResp(os.Stdout, Response{Ok: true, InvalidOut: modes})
			return
		}
		payload := map[string]any{
			"in_ibd":           boolOrDefault(req.InIBD, false),
			"warmup_done":      boolOrDefault(req.WarmupDone, false),
			"miss_rate_pct":    req.MissRatePct,
			"miss_rate_blocks": req.MissRateBlocks,
		}
		writeResp(os.Stdout, Response{Ok: true, Mode: computeMode(payload)})
		return

	case "compact_peer_quality":
		score := req.StartScore
		if score == 0 {
			score = 50
		}
		grace := boolOrDefault(req.GracePeriodActive, false)
		deltas := map[string]int{
			"reconstruct_no_getblocktxn": 2,
			"getblocktxn_first_try":      1,
			"prefetch_completed":         1,
			"incomplete_set":             -5,
			"getblocktxn_required":       -3,
			"full_block_required":        -10,
			"prefetch_cap_exceeded":      -2,
		}
		for _, raw := range req.Events {
			ev := toString(raw, "")
			delta, ok := deltas[ev]
			if !ok {
				writeResp(os.Stdout, Response{Ok: false, Err: "unknown peer-quality event"})
				return
			}
			if grace && delta < 0 {
				delta = int(delta / 2)
			}
			score = maxInt(0, minInt(100, score+delta))
		}
		for i := 0; i < req.ElapsedBlocks/144; i++ {
			if score > 50 {
				score--
			} else if score < 50 {
				score++
			}
		}
		mode := 0
		if score >= 75 {
			mode = 2
		} else if score >= 40 {
			mode = 1
		}
		writeResp(os.Stdout, Response{Ok: true, Score: score, Mode: mode})
		return

	case "compact_prefetch_caps":
		perPeerBPS := req.PerPeerBPS
		if perPeerBPS == 0 {
			perPeerBPS = 4_000_000
		}
		globalBPS := req.GlobalBPS
		if globalBPS == 0 {
			globalBPS = 32_000_000
		}
		streams := append([]int(nil), req.PeerStreamsBPS...)
		if len(streams) == 0 {
			active := req.ActiveSets
			if active <= 0 {
				active = 1
			}
			for i := 0; i < active; i++ {
				streams = append(streams, req.PeerStreamBPS)
			}
		}
		peerExceeded := false
		total := 0
		for _, bps := range streams {
			total += bps
			if bps > perPeerBPS {
				peerExceeded = true
			}
		}
		globalExceeded := total > globalBPS
		qualityPenalty := peerExceeded || globalExceeded
		writeResp(os.Stdout, Response{
			Ok:             true,
			PeerExceeded:   peerExceeded,
			GlobalExceeded: globalExceeded,
			QualityPenalty: qualityPenalty,
			Disconnect:     false,
		})
		return

	case "compact_telemetry_rate":
		completed := req.CompletedSets
		total := req.TotalSets
		if completed < 0 || total < 0 || completed > total {
			writeResp(os.Stdout, Response{Ok: false, Err: "invalid completed/total values"})
			return
		}
		rate := 1.0
		if total > 0 {
			rate = float64(completed) / float64(total)
		}
		writeResp(os.Stdout, Response{Ok: true, Rate: rate})
		return

	case "compact_telemetry_fields":
		required := []string{
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
		missing := make([]string, 0)
		for _, field := range required {
			if _, ok := req.Telemetry[field]; !ok {
				missing = append(missing, field)
			}
		}
		sort.Strings(missing)
		ok := len(missing) == 0
		if !ok {
			writeResp(os.Stdout, Response{Ok: false, Err: "missing telemetry fields", MissingFields: missing})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, MissingFields: missing})
		return

	case "compact_grace_period":
		gracePeriodBlocks := req.GracePeriodBlocks
		if gracePeriodBlocks == 0 {
			gracePeriodBlocks = 1440
		}
		graceActive := req.ElapsedBlocks < gracePeriodBlocks
		score := req.StartScore
		if score == 0 {
			score = 50
		}
		deltas := map[string]int{
			"reconstruct_no_getblocktxn": 2,
			"getblocktxn_first_try":      1,
			"prefetch_completed":         1,
			"incomplete_set":             -5,
			"getblocktxn_required":       -3,
			"full_block_required":        -10,
			"prefetch_cap_exceeded":      -2,
		}
		for _, raw := range req.Events {
			ev := toString(raw, "")
			delta, ok := deltas[ev]
			if !ok {
				writeResp(os.Stdout, Response{Ok: false, Err: "unknown grace event"})
				return
			}
			if graceActive && delta < 0 {
				delta = int(delta / 2)
			}
			score = maxInt(0, minInt(100, score+delta))
		}
		disconnect := score < 5 && !graceActive
		writeResp(os.Stdout, Response{
			Ok:         true,
			StormMode:  graceActive,
			Score:      score,
			Disconnect: disconnect,
		})
		return

	case "compact_eviction_tiebreak":
		type normalized struct {
			DaID         string
			FeePerByte   float64
			ReceivedTime int
		}
		normalizedEntries := make([]normalized, 0, len(req.Entries))
		for _, entry := range req.Entries {
			daID := toString(entry["da_id"], "")
			fee := toInt(entry["fee"], 0)
			wireBytes := toInt(entry["wire_bytes"], 0)
			receivedTime := toInt(entry["received_time"], 0)
			if daID == "" || wireBytes <= 0 {
				writeResp(os.Stdout, Response{Ok: false, Err: "invalid da_id/wire_bytes"})
				return
			}
			normalizedEntries = append(normalizedEntries, normalized{
				DaID: daID, FeePerByte: float64(fee) / float64(wireBytes), ReceivedTime: receivedTime,
			})
		}
		sort.Slice(normalizedEntries, func(i, j int) bool {
			if normalizedEntries[i].FeePerByte != normalizedEntries[j].FeePerByte {
				return normalizedEntries[i].FeePerByte < normalizedEntries[j].FeePerByte
			}
			if normalizedEntries[i].ReceivedTime != normalizedEntries[j].ReceivedTime {
				return normalizedEntries[i].ReceivedTime < normalizedEntries[j].ReceivedTime
			}
			return normalizedEntries[i].DaID < normalizedEntries[j].DaID
		})
		order := make([]string, 0, len(normalizedEntries))
		for _, entry := range normalizedEntries {
			order = append(order, entry.DaID)
		}
		writeResp(os.Stdout, Response{Ok: true, EvictOrder: order})
		return

	case "compact_a_to_b_retention":
		chunkCount := req.ChunkCount
		if chunkCount <= 0 {
			writeResp(os.Stdout, Response{Ok: false, Err: "chunk_count must be > 0"})
			return
		}
		retainedChunks := uniqueSortedInt(req.InitialChunks)
		retainedSet := make(map[int]struct{}, len(retainedChunks))
		for _, idx := range retainedChunks {
			retainedSet[idx] = struct{}{}
		}
		missingChunks := make([]int, 0)
		for i := 0; i < chunkCount; i++ {
			if _, ok := retainedSet[i]; !ok {
				missingChunks = append(missingChunks, i)
			}
		}
		state := "A"
		commitArrives := boolOrDefault(req.CommitArrives, true)
		if commitArrives {
			if len(missingChunks) == 0 {
				state = "C"
			} else {
				state = "B"
			}
		}
		prefetchTargets := []int{}
		if state == "B" {
			prefetchTargets = missingChunks
		}
		writeResp(os.Stdout, Response{
			Ok:              true,
			State:           state,
			RetainedChunks:  retainedChunks,
			MissingOut:      missingChunks,
			PrefetchTargets: prefetchTargets,
			DiscardedChunks: []int{},
		})
		return

	case "compact_duplicate_commit":
		targetDAID := req.DaID
		if targetDAID == "" {
			targetDAID = ""
		}
		firstSeenPeer := ""
		duplicatesDropped := 0
		penalizedPeers := make([]string, 0)
		for _, commit := range req.Commits {
			daID := toString(commit["da_id"], "")
			peer := toString(commit["peer"], "")
			if daID == "" || peer == "" {
				writeResp(os.Stdout, Response{Ok: false, Err: "invalid duplicate-commit entry"})
				return
			}
			if targetDAID == "" {
				targetDAID = daID
			}
			if daID != targetDAID {
				continue
			}
			if firstSeenPeer == "" {
				firstSeenPeer = peer
			} else {
				duplicatesDropped++
				penalizedPeers = append(penalizedPeers, peer)
			}
		}
		sort.Strings(penalizedPeers)
		writeResp(os.Stdout, Response{
			Ok:                true,
			RetainedPeer:      firstSeenPeer,
			DuplicatesDropped: duplicatesDropped,
			PenalizedPeers:    penalizedPeers,
			Replaced:          false,
		})
		return

	case "compact_total_fee":
		totalFee := req.CommitFee
		for _, fee := range req.ChunkFees {
			totalFee += fee
		}
		writeResp(os.Stdout, Response{Ok: true, TotalFee: totalFee})
		return

	case "compact_pinned_accounting":
		capBytes := req.CapBytes
		if capBytes == 0 {
			capBytes = 96_000_000
		}
		countedBytes := req.CurrentPinnedBytes + req.IncomingPayload
		admit := countedBytes <= capBytes
		writeResp(os.Stdout, Response{
			Ok:              true,
			CountedBytes:    countedBytes,
			Admit:           admit,
			IgnoredOverhead: req.IncomingOverhead,
		})
		return

	case "compact_storm_commit_bearing":
		containsCommit := boolOrDefault(req.ContainsCommit, false)
		containsKnownChunk := boolOrDefault(req.ContainsKnownChunk, false)
		containsBlockCommit := boolOrDefault(req.ContainsBlockCommit, false)
		triggerPct := req.StormTriggerPct
		if triggerPct == 0 {
			triggerPct = 90.0
		}
		commitBearing := containsCommit || containsKnownChunk || containsBlockCommit
		stormMode := req.OrphanPoolFillPct > triggerPct
		prioritize := !stormMode || commitBearing
		admit := true
		if stormMode && !commitBearing {
			admit = false
		}
		writeResp(os.Stdout, Response{
			Ok:            true,
			StormMode:     stormMode,
			CommitBearing: commitBearing,
			Prioritize:    prioritize,
			Admit:         admit,
		})
		return

	case "output_descriptor_bytes":
		desc, err := outputDescriptorBytes(req.CovenantType, req.CovenantDataHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad covenant_data_hex"})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, DescriptorHex: hex.EncodeToString(desc)})
		return

	case "output_descriptor_hash":
		desc, err := outputDescriptorBytes(req.CovenantType, req.CovenantDataHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad covenant_data_hex"})
			return
		}
		h := sha3.Sum256(desc)
		writeResp(os.Stdout, Response{Ok: true, DigestHex: hex.EncodeToString(h[:])})
		return

	case "nonce_replay_intrablock":
		seen := make(map[uint64]struct{}, len(req.Nonces))
		duplicates := make([]uint64, 0)
		for _, nonce := range req.Nonces {
			if _, ok := seen[nonce]; ok {
				duplicates = append(duplicates, nonce)
				continue
			}
			seen[nonce] = struct{}{}
		}
		if len(duplicates) > 0 {
			writeResp(os.Stdout, Response{Ok: false, Err: string(consensus.TX_ERR_NONCE_REPLAY), Duplicates: duplicates})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, Duplicates: duplicates})
		return

	case "timestamp_bounds":
		maxFutureDrift := uint64(7200)
		if req.MaxFutureDrift != nil {
			maxFutureDrift = *req.MaxFutureDrift
		}
		upperBound := uint64(math.MaxUint64)
		if req.MTP <= math.MaxUint64-maxFutureDrift {
			upperBound = req.MTP + maxFutureDrift
		}
		if req.Timestamp <= req.MTP {
			writeResp(os.Stdout, Response{Ok: false, Err: string(consensus.BLOCK_ERR_TIMESTAMP_OLD)})
			return
		}
		if req.Timestamp > upperBound {
			writeResp(os.Stdout, Response{Ok: false, Err: string(consensus.BLOCK_ERR_TIMESTAMP_FUTURE)})
			return
		}
		writeResp(os.Stdout, Response{Ok: true})
		return

	case "determinism_order":
		type keyWithBytes struct {
			Value string
			Bytes []byte
		}
		items := make([]keyWithBytes, 0, len(req.Keys))
		for _, key := range req.Keys {
			keyBytes, err := parseKeyBytes(key)
			if err != nil {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad key"})
				return
			}
			items = append(items, keyWithBytes{
				Value: fmt.Sprintf("%v", key),
				Bytes: keyBytes,
			})
		}
		sort.Slice(items, func(i, j int) bool {
			cmp := bytes.Compare(items[i].Bytes, items[j].Bytes)
			if cmp == 0 {
				return items[i].Value < items[j].Value
			}
			return cmp < 0
		})
		sortedKeys := make([]string, 0, len(items))
		for _, item := range items {
			sortedKeys = append(sortedKeys, item.Value)
		}
		writeResp(os.Stdout, Response{Ok: true, SortedKeys: sortedKeys})
		return

	case "validation_order":
		if len(req.Checks) == 0 {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad checks"})
			return
		}
		evaluated := make([]string, 0, len(req.Checks))
		firstErr := ""
		for _, check := range req.Checks {
			evaluated = append(evaluated, check.Name)
			if check.Fails {
				firstErr = check.Err
				break
			}
		}
		if firstErr != "" {
			writeResp(os.Stdout, Response{
				Ok:        false,
				Err:       firstErr,
				FirstErr:  firstErr,
				Evaluated: evaluated,
			})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, Evaluated: evaluated})
		return

	case "htlc_ordering_policy":
		path := strings.ToLower(strings.TrimSpace(req.Path))
		if path == "" {
			path = "claim"
		}
		structuralOK := boolOrDefault(req.StructuralOK, true)
		locktimeOK := boolOrDefault(req.LocktimeOK, true)
		suiteID := uint8OrDefault(req.SuiteID, 1)
		activationHeight := uint64OrDefault(req.SLHActivationHeight, 1_000_000)
		keyBindingOK := boolOrDefault(req.KeyBindingOK, true)
		preimageOK := boolOrDefault(req.PreimageOK, true)
		verifyOK := boolOrDefault(req.VerifyOK, true)

		verifyCalled := false
		errCode := ""
		switch {
		case !structuralOK:
			errCode = string(consensus.TX_ERR_PARSE)
		case path == "refund" && !locktimeOK:
			errCode = string(consensus.TX_ERR_TIMELOCK_NOT_MET)
		case suiteID != consensus.SUITE_ID_ML_DSA_87 && suiteID != consensus.SUITE_ID_SLH_DSA_SHAKE_256F:
			errCode = string(consensus.TX_ERR_SIG_ALG_INVALID)
		case suiteID == consensus.SUITE_ID_SLH_DSA_SHAKE_256F && req.Height < activationHeight:
			errCode = string(consensus.TX_ERR_SIG_ALG_INVALID)
		case !keyBindingOK:
			errCode = string(consensus.TX_ERR_SIG_INVALID)
		case path == "claim" && !preimageOK:
			errCode = string(consensus.TX_ERR_SIG_INVALID)
		default:
			verifyCalled = true
			if !verifyOK {
				errCode = string(consensus.TX_ERR_SIG_INVALID)
			}
		}

		if errCode != "" {
			writeResp(os.Stdout, Response{Ok: false, Err: errCode, VerifyCalled: verifyCalled})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, VerifyCalled: verifyCalled})
		return

	case "vault_policy_rules":
		ownerLockID := req.OwnerLockID
		if strings.TrimSpace(ownerLockID) == "" {
			ownerLockID = "owner"
		}
		hasOwnerAuth := boolOrDefault(req.HasOwnerAuth, false)
		if req.HasOwnerAuth == nil {
			for _, lockID := range req.NonVaultLockIDs {
				if lockID == ownerLockID {
					hasOwnerAuth = true
					break
				}
			}
		}
		sigThresholdOK := boolOrDefault(req.SigThresholdOK, true)
		sentinelVerifyCalled := boolOrDefault(req.SentinelVerifyCalled, false)
		sentinelOK := req.SentinelSuiteID == 0 &&
			req.SentinelPubkeyLen == 0 &&
			req.SentinelSigLen == 0 &&
			!sentinelVerifyCalled

		whitelistSorted := append([]string(nil), req.Whitelist...)
		sort.Strings(whitelistSorted)
		whitelistUnique := true
		for i := 1; i < len(whitelistSorted); i++ {
			if whitelistSorted[i] == whitelistSorted[i-1] {
				whitelistUnique = false
				break
			}
		}
		whitelistOK := len(req.Whitelist) == len(whitelistSorted) && whitelistUnique
		if whitelistOK {
			for i := range req.Whitelist {
				if req.Whitelist[i] != whitelistSorted[i] {
					whitelistOK = false
					break
				}
			}
		}

		checks := map[string]struct {
			OK   bool
			Code string
		}{
			"multi_vault": {
				OK:   req.VaultInputCount <= 1,
				Code: string(consensus.TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN),
			},
			"owner_auth": {
				OK:   hasOwnerAuth,
				Code: string(consensus.TX_ERR_VAULT_OWNER_AUTH_REQUIRED),
			},
			"fee_sponsor": {
				OK: func() bool {
					for _, lockID := range req.NonVaultLockIDs {
						if lockID != ownerLockID {
							return false
						}
					}
					return true
				}(),
				Code: string(consensus.TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN),
			},
			"witness_slots": {
				OK:   req.Slots == req.KeyCount,
				Code: string(consensus.TX_ERR_PARSE),
			},
			"sentinel": {
				OK:   sentinelOK,
				Code: string(consensus.TX_ERR_PARSE),
			},
			"sig_threshold": {
				OK:   sigThresholdOK,
				Code: string(consensus.TX_ERR_SIG_INVALID),
			},
			"whitelist": {
				OK:   whitelistOK,
				Code: string(consensus.TX_ERR_VAULT_WHITELIST_NOT_CANONICAL),
			},
			"value": {
				OK:   req.SumOut >= req.SumInVault,
				Code: string(consensus.TX_ERR_VALUE_CONSERVATION),
			},
		}

		validationOrder := req.ValidationOrder
		if len(validationOrder) == 0 {
			validationOrder = []string{
				"multi_vault",
				"owner_auth",
				"fee_sponsor",
				"witness_slots",
				"sentinel",
				"sig_threshold",
				"whitelist",
				"value",
			}
		}

		for _, rule := range validationOrder {
			check, ok := checks[rule]
			if !ok {
				writeResp(os.Stdout, Response{Ok: false, Err: "unknown validation rule"})
				return
			}
			if !check.OK {
				writeResp(os.Stdout, Response{Ok: false, Err: check.Code})
				return
			}
		}
		writeResp(os.Stdout, Response{Ok: true})
		return

	default:
		writeResp(os.Stdout, Response{Ok: false, Err: "unknown op"})
		return
	}
}

func outputDescriptorBytes(covType uint16, covDataHex string) ([]byte, error) {
	covData, err := hex.DecodeString(covDataHex)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+9+len(covData))
	var ct [2]byte
	binary.LittleEndian.PutUint16(ct[:], covType)
	out = append(out, ct[:]...)
	out = append(out, encodeCompactSize(uint64(len(covData)))...)
	out = append(out, covData...)
	return out, nil
}

func encodeCompactSize(n uint64) []byte {
	switch {
	case n < 0xfd:
		return []byte{byte(n)}
	case n <= 0xffff:
		out := make([]byte, 3)
		out[0] = 0xfd
		binary.LittleEndian.PutUint16(out[1:], uint16(n))
		return out
	case n <= 0xffffffff:
		out := make([]byte, 5)
		out[0] = 0xfe
		binary.LittleEndian.PutUint32(out[1:], uint32(n))
		return out
	default:
		out := make([]byte, 9)
		out[0] = 0xff
		binary.LittleEndian.PutUint64(out[1:], n)
		return out
	}
}

func decodeCompactSize(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, fmt.Errorf("empty")
	}
	pfx := buf[0]
	if pfx < 0xfd {
		return uint64(pfx), 1, nil
	}
	if pfx == 0xfd {
		if len(buf) < 3 {
			return 0, 0, fmt.Errorf("short")
		}
		return uint64(binary.LittleEndian.Uint16(buf[1:3])), 3, nil
	}
	if pfx == 0xfe {
		if len(buf) < 5 {
			return 0, 0, fmt.Errorf("short")
		}
		return uint64(binary.LittleEndian.Uint32(buf[1:5])), 5, nil
	}
	if len(buf) < 9 {
		return 0, 0, fmt.Errorf("short")
	}
	return binary.LittleEndian.Uint64(buf[1:9]), 9, nil
}

func slicesEqualInt(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uniqueSortedInt(v []int) []int {
	if len(v) == 0 {
		return []int{}
	}
	out := asSortedInts(v)
	w := 1
	for i := 1; i < len(out); i++ {
		if out[i] != out[i-1] {
			out[w] = out[i]
			w++
		}
	}
	return out[:w]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
