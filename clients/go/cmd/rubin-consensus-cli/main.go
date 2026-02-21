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
	Txids      []string `json:"txids,omitempty"`
	InputIndex uint32   `json:"input_index,omitempty"`
	InputValue uint64   `json:"input_value,omitempty"`
	ChainIDHex string   `json:"chain_id,omitempty"`
}

type Response struct {
	Ok        bool   `json:"ok"`
	Err       string `json:"err,omitempty"`
	TxidHex   string `json:"txid,omitempty"`
	WtxidHex  string `json:"wtxid,omitempty"`
	MerkleHex string `json:"merkle_root,omitempty"`
	DigestHex string `json:"digest,omitempty"`
	Consumed  int    `json:"consumed,omitempty"`
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
		_, txid, wtxid, n, err := consensus.ParseTxV2(txBytes)
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
		tx, _, _, _, err := consensus.ParseTxV2(txBytes)
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

	default:
		writeResp(os.Stdout, Response{Ok: false, Err: "unknown op"})
		return
	}
}
