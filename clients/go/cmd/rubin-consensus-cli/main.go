package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type Request struct {
	Op         string   `json:"op"`
	TxHex      string   `json:"tx_hex,omitempty"`
	BlockHex   string   `json:"block_hex,omitempty"`
	Txids      []string `json:"txids,omitempty"`
	WtxidHex   string   `json:"wtxid,omitempty"`
	Nonce1     uint64   `json:"nonce1,omitempty"`
	Nonce2     uint64   `json:"nonce2,omitempty"`
	InputIndex uint32   `json:"input_index,omitempty"`
	InputValue uint64   `json:"input_value,omitempty"`
	ChainIDHex string   `json:"chain_id,omitempty"`

	HeaderHex      string `json:"header_hex,omitempty"`
	TargetHex      string `json:"target_hex,omitempty"`
	TargetOldHex   string `json:"target_old,omitempty"`
	TimestampFirst uint64 `json:"timestamp_first,omitempty"`
	TimestampLast  uint64 `json:"timestamp_last,omitempty"`
	ExpectedPrev   string `json:"expected_prev_hash,omitempty"`
	ExpectedTarget string `json:"expected_target,omitempty"`

	Utxos          []UtxoJSON `json:"utxos,omitempty"`
	Height         uint64     `json:"height,omitempty"`
	BlockTimestamp uint64     `json:"block_timestamp,omitempty"`
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

type Response struct {
	Ok        bool   `json:"ok"`
	Err       string `json:"err,omitempty"`
	TxidHex   string `json:"txid,omitempty"`
	WtxidHex  string `json:"wtxid,omitempty"`
	MerkleHex string `json:"merkle_root,omitempty"`
	DigestHex string `json:"digest,omitempty"`
	BlockHash string `json:"block_hash,omitempty"`
	TargetNew string `json:"target_new,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	Consumed  int    `json:"consumed,omitempty"`
	Fee       uint64 `json:"fee,omitempty"`
	UtxoCount uint64 `json:"utxo_count,omitempty"`
}

func writeResp(w io.Writer, resp Response) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(resp)
}

func main() {
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
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		writeResp(os.Stdout, Response{
			Ok:       true,
			TxidHex:  hex.EncodeToString(txid[:]),
			WtxidHex: hex.EncodeToString(wtxid[:]),
			Consumed: n,
		})
		return

	case "merkle_root":
		txids := make([][32]byte, 0, len(req.Txids))
		for _, h := range req.Txids {
			b, err := hex.DecodeString(h)
			if err != nil || len(b) != 32 {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad txid"})
				return
			}
			var a [32]byte
			copy(a[:], b)
			txids = append(txids, a)
		}
		root, err := consensus.MerkleRootTxids(txids)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, MerkleHex: hex.EncodeToString(root[:])})
		return

	case "sighash_v1":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, _, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
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
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, DigestHex: hex.EncodeToString(d[:])})
		return

	case "block_hash":
		headerBytes, err := hex.DecodeString(req.HeaderHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad header"})
			return
		}
		h, err := consensus.BlockHash(headerBytes)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
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
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
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
		newT, err := consensus.RetargetV1(old, req.TimestampFirst, req.TimestampLast)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, TargetNew: hex.EncodeToString(newT[:])})
		return

	case "block_basic_check":
		blockBytes, err := hex.DecodeString(req.BlockHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad block"})
			return
		}

		var expectedPrev *[32]byte
		if req.ExpectedPrev != "" {
			b, err := hex.DecodeString(req.ExpectedPrev)
			if err != nil || len(b) != 32 {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad expected_prev_hash"})
				return
			}
			var h [32]byte
			copy(h[:], b)
			expectedPrev = &h
		}

		var expectedTarget *[32]byte
		if req.ExpectedTarget != "" {
			b, err := hex.DecodeString(req.ExpectedTarget)
			if err != nil || len(b) != 32 {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad expected_target"})
				return
			}
			var h [32]byte
			copy(h[:], b)
			expectedTarget = &h
		}

		s, err := consensus.ValidateBlockBasic(blockBytes, expectedPrev, expectedTarget)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		writeResp(os.Stdout, Response{Ok: true, BlockHash: hex.EncodeToString(s.BlockHash[:])})
		return

	case "covenant_genesis_check":
		txBytes, err := hex.DecodeString(req.TxHex)
		if err != nil {
			writeResp(os.Stdout, Response{Ok: false, Err: "bad hex"})
			return
		}
		tx, _, _, _, err := consensus.ParseTx(txBytes)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}
		if err := consensus.ValidateTxCovenantsGenesis(tx); err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
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
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
			return
		}

		utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(req.Utxos))
		for _, u := range req.Utxos {
			txidBytes, err := hex.DecodeString(u.Txid)
			if err != nil || len(txidBytes) != 32 {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad utxo txid"})
				return
			}
			covData, err := hex.DecodeString(u.CovenantDataHex)
			if err != nil {
				writeResp(os.Stdout, Response{Ok: false, Err: "bad utxo covenant_data"})
				return
			}

			var opTxid [32]byte
			copy(opTxid[:], txidBytes)
			op := consensus.Outpoint{Txid: opTxid, Vout: u.Vout}
			utxos[op] = consensus.UtxoEntry{
				Value:             u.Value,
				CovenantType:      u.CovenantType,
				CovenantData:      covData,
				CreationHeight:    u.CreationHeight,
				CreatedByCoinbase: u.CreatedByCoinbase,
			}
		}

		s, err := consensus.ApplyNonCoinbaseTxBasic(tx, txid, utxos, req.Height, req.BlockTimestamp)
		if err != nil {
			if te, ok := err.(*consensus.TxError); ok {
				writeResp(os.Stdout, Response{Ok: false, Err: string(te.Code)})
				return
			}
			writeResp(os.Stdout, Response{Ok: false, Err: err.Error()})
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

	default:
		writeResp(os.Stdout, Response{Ok: false, Err: "unknown op"})
		return
	}
}
