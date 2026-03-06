package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type spendableCoinbase struct {
	outpoint consensus.Outpoint
	entry    consensus.UtxoEntry
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rubin-txgen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	datadir := fs.String("datadir", node.DefaultDataDir(), "node data directory")
	fromKeyHex := fs.String("from-key", "", "hex-encoded ML-DSA private key DER")
	toKeyHex := fs.String("to-key", "", "destination P2PK key_id hex or canonical covenant_data hex")
	amount := fs.Uint64("amount", 0, "transfer amount")
	fee := fs.Uint64("fee", 0, "transaction fee")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*fromKeyHex) == "" {
		_, _ = fmt.Fprintln(stderr, "missing required --from-key")
		return 2
	}
	if strings.TrimSpace(*toKeyHex) == "" {
		_, _ = fmt.Fprintln(stderr, "missing required --to-key")
		return 2
	}
	if *amount == 0 {
		_, _ = fmt.Fprintln(stderr, "missing or zero --amount")
		return 2
	}

	fromDER, err := decodeHexFlag(*fromKeyHex)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid from-key: %v\n", err)
		return 2
	}
	fromKey, err := consensus.NewMLDSA87KeypairFromDER(fromDER)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid from-key: %v\n", err)
		return 2
	}
	defer fromKey.Close()

	toAddress, err := node.ParseMineAddress(*toKeyHex)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid to-key: %v\n", err)
		return 2
	}

	st, err := node.LoadChainState(node.ChainStatePath(*datadir))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "chainstate load failed: %v\n", err)
		return 2
	}
	nextHeight, err := nextSpendHeight(st)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "chainstate invalid: %v\n", err)
		return 2
	}

	required, err := addAmountAndFee(*amount, *fee)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "amount+fee invalid: %v\n", err)
		return 2
	}
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	selected, total, err := selectSpendableCoinbases(st, fromAddress, nextHeight, required)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "coinbase selection failed: %v\n", err)
		return 2
	}

	tx := buildTransferTx(selected, total, *amount, *fee, fromAddress, toAddress)
	if err := consensus.SignTransaction(tx, st.Utxos, node.DevnetGenesisChainID(), fromKey); err != nil {
		_, _ = fmt.Fprintf(stderr, "sign failed: %v\n", err)
		return 2
	}
	txBytes, err := consensus.MarshalTx(tx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "marshal failed: %v\n", err)
		return 2
	}
	if _, err := consensus.CheckTransaction(txBytes, st.Utxos, nextHeight, 0, node.DevnetGenesisChainID()); err != nil {
		_, _ = fmt.Fprintf(stderr, "generated tx invalid: %v\n", err)
		return 2
	}

	_, _ = fmt.Fprintf(stdout, "%x\n", txBytes)
	return 0
}

func decodeHexFlag(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.TrimPrefix(trimmed, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if trimmed == "" {
		return nil, errors.New("empty hex")
	}
	if len(trimmed)%2 != 0 {
		return nil, errors.New("odd-length hex")
	}
	return hex.DecodeString(trimmed)
}

func nextSpendHeight(st *node.ChainState) (uint64, error) {
	if st == nil {
		return 0, errors.New("nil chainstate")
	}
	if !st.HasTip {
		return 0, nil
	}
	if st.Height == math.MaxUint64 {
		return 0, errors.New("height overflow")
	}
	return st.Height + 1, nil
}

func addAmountAndFee(amount uint64, fee uint64) (uint64, error) {
	if amount > math.MaxUint64-fee {
		return 0, errors.New("u64 overflow")
	}
	return amount + fee, nil
}

func selectSpendableCoinbases(
	st *node.ChainState,
	fromAddress []byte,
	nextHeight uint64,
	required uint64,
) ([]spendableCoinbase, uint64, error) {
	candidates := make([]spendableCoinbase, 0, len(st.Utxos))
	for op, entry := range st.Utxos {
		if !entry.CreatedByCoinbase {
			continue
		}
		if entry.CovenantType != consensus.COV_TYPE_P2PK {
			continue
		}
		if !bytes.Equal(entry.CovenantData, fromAddress) {
			continue
		}
		if entry.CreationHeight > math.MaxUint64-consensus.COINBASE_MATURITY {
			return nil, 0, errors.New("coinbase maturity overflow")
		}
		if nextHeight < entry.CreationHeight+consensus.COINBASE_MATURITY {
			continue
		}
		candidates = append(candidates, spendableCoinbase{outpoint: op, entry: entry})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].entry.CreationHeight != candidates[j].entry.CreationHeight {
			return candidates[i].entry.CreationHeight < candidates[j].entry.CreationHeight
		}
		if cmp := bytes.Compare(candidates[i].outpoint.Txid[:], candidates[j].outpoint.Txid[:]); cmp != 0 {
			return cmp < 0
		}
		return candidates[i].outpoint.Vout < candidates[j].outpoint.Vout
	})

	selected := make([]spendableCoinbase, 0, len(candidates))
	var total uint64
	for _, candidate := range candidates {
		if total > math.MaxUint64-candidate.entry.Value {
			return nil, 0, errors.New("selected input total overflow")
		}
		selected = append(selected, candidate)
		total += candidate.entry.Value
		if total >= required {
			return selected, total, nil
		}
	}
	return nil, 0, errors.New("insufficient mature coinbase balance")
}

func buildTransferTx(
	selected []spendableCoinbase,
	totalIn uint64,
	amount uint64,
	fee uint64,
	changeAddress []byte,
	toAddress []byte,
) *consensus.Tx {
	inputs := make([]consensus.TxInput, 0, len(selected))
	for _, candidate := range selected {
		inputs = append(inputs, consensus.TxInput{
			PrevTxid: candidate.outpoint.Txid,
			PrevVout: candidate.outpoint.Vout,
			Sequence: 0,
		})
	}
	outputs := []consensus.TxOutput{{
		Value:        amount,
		CovenantType: consensus.COV_TYPE_P2PK,
		CovenantData: append([]byte(nil), toAddress...),
	}}
	change := totalIn - amount - fee
	if change > 0 {
		outputs = append(outputs, consensus.TxOutput{
			Value:        change,
			CovenantType: consensus.COV_TYPE_P2PK,
			CovenantData: append([]byte(nil), changeAddress...),
		})
	}

	return &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  deterministicNonce(selected, toAddress, amount, fee),
		Inputs:   inputs,
		Outputs:  outputs,
		Locktime: 0,
	}
}

func deterministicNonce(selected []spendableCoinbase, toAddress []byte, amount uint64, fee uint64) uint64 {
	h := sha3.New256()
	for _, candidate := range selected {
		_, _ = h.Write(candidate.outpoint.Txid[:])
		var vout [4]byte
		binary.LittleEndian.PutUint32(vout[:], candidate.outpoint.Vout)
		_, _ = h.Write(vout[:])
	}
	_, _ = h.Write(toAddress)
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], amount)
	binary.LittleEndian.PutUint64(buf[8:16], fee)
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	nonce := binary.LittleEndian.Uint64(sum[:8])
	if nonce == 0 {
		return 1
	}
	return nonce
}
