package main

import (
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type Request struct {
	Op              string   `json:"op"`
	TxHex           string   `json:"tx_hex,omitempty"`
	BlockHex        string   `json:"block_hex,omitempty"`
	Txids           []string `json:"txids,omitempty"`
	WtxidHex        string   `json:"wtxid,omitempty"`
	CovenantType    uint16   `json:"covenant_type,omitempty"`
	CovenantDataHex string   `json:"covenant_data_hex,omitempty"`
	Nonce1          uint64   `json:"nonce1,omitempty"`
	Nonce2          uint64   `json:"nonce2,omitempty"`
	InputIndex      uint32   `json:"input_index,omitempty"`
	InputValue      uint64   `json:"input_value,omitempty"`
	ChainIDHex      string   `json:"chain_id,omitempty"`

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
	Ok            bool   `json:"ok"`
	Err           string `json:"err,omitempty"`
	TxidHex       string `json:"txid,omitempty"`
	WtxidHex      string `json:"wtxid,omitempty"`
	MerkleHex     string `json:"merkle_root,omitempty"`
	DigestHex     string `json:"digest,omitempty"`
	BlockHash     string `json:"block_hash,omitempty"`
	TargetNew     string `json:"target_new,omitempty"`
	ShortID       string `json:"short_id,omitempty"`
	DescriptorHex string `json:"descriptor_hex,omitempty"`
	Consumed      int    `json:"consumed,omitempty"`
	Fee           uint64 `json:"fee,omitempty"`
	UtxoCount     uint64 `json:"utxo_count,omitempty"`
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

		s, err := consensus.ValidateBlockBasicAtHeight(blockBytes, expectedPrev, expectedTarget, req.Height)
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
