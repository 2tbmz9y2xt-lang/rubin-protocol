package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

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
	submitTo := fs.String("submit-to", "", "submit signed tx to devnet RPC host:port")
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
	if strings.TrimSpace(*datadir) == "" {
		_, _ = fmt.Fprintln(stderr, "missing required --datadir")
		return 2
	}
	dataDir := node.NormalizeDataDir(*datadir)

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

	st, err := node.LoadChainState(node.ChainStatePath(dataDir))
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
	if strings.TrimSpace(*submitTo) != "" {
		if err := submitTx(*submitTo, txBytes); err != nil {
			_, _ = fmt.Fprintf(stderr, "submit failed: %v\n", err)
			return 2
		}
	}
	return 0
}

type submitTxHTTPPayload struct {
	TxHex string `json:"tx_hex"`
}

func submitTx(target string, txBytes []byte) error {
	client := &http.Client{Timeout: 5 * time.Second}
	return submitTxWithClient(target, txBytes, client)
}

func submitTxWithClient(target string, txBytes []byte, client *http.Client) error {
	endpoint, err := normalizeSubmitTarget(target)
	if err != nil {
		return err
	}
	body, err := json.Marshal(submitTxHTTPPayload{TxHex: hex.EncodeToString(txBytes)})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// #nosec G107,G704 -- devnet-only submit targets are validated to localhost/loopback in normalizeSubmitTarget.
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		if err := discardResponseBody(resp.Body); err != nil {
			return err
		}
		return nil
	}
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
}

func discardResponseBody(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func normalizeSubmitTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("empty submit target")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", errors.New("submit target missing host")
	}
	if err := validateLocalSubmitHost(parsed.Hostname()); err != nil {
		return "", err
	}
	parsed.User = nil
	parsed.Path = "/submit_tx"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func validateLocalSubmitHost(host string) error {
	hostname := strings.TrimSpace(host)
	if hostname == "" {
		return errors.New("submit target missing host")
	}
	if strings.EqualFold(hostname, "localhost") {
		return nil
	}
	ip := net.ParseIP(hostname)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("submit target host %q must be localhost or loopback", hostname)
	}
	return nil
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
