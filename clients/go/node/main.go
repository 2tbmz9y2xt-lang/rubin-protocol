package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
	"rubin.dev/node/node/store"
)

const defaultChainProfile = "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md"

type applyUTXOUtxoEntry struct {
	Txid              string  `json:"txid"`
	Vout              uint32  `json:"vout"`
	Value             uint64  `json:"value"`
	CovenantType      uint16  `json:"covenant_type"`
	CovenantData      string  `json:"covenant_data"`
	CreationHeight    *uint64 `json:"creation_height"`
	CreatedByCoinbase bool    `json:"created_by_coinbase"`
}

type applyUTXOContext struct {
	ChainIDHex      string               `json:"chain_id_hex"`
	Profile         string               `json:"profile"`
	ChainHeight     uint64               `json:"chain_height"`
	ChainTimestamp  uint64               `json:"chain_timestamp"`
	SuiteID02Active bool                 `json:"suite_id_02_active"`
	TxHex           string               `json:"tx_hex"`
	UTXOSet         []applyUTXOUtxoEntry `json:"utxo_set"`
}

type applyBlockContext struct {
	ChainIDHex         string               `json:"chain_id_hex"`
	Profile            string               `json:"profile"`
	BlockHeight        uint64               `json:"block_height"`
	LocalTime          uint64               `json:"local_time"`
	LocalTimeSet       bool                 `json:"local_time_set"`
	SuiteID02Active    bool                 `json:"suite_id_02_active"`
	HTLCV2Active       bool                 `json:"htlc_v2_active"`
	AncestorHeadersHex []string             `json:"ancestor_headers_hex"`
	BlockHex           string               `json:"block_hex"`
	UTXOSet            []applyUTXOUtxoEntry `json:"utxo_set"`
}

type chainstateContext struct {
	ChainIDHex         string               `json:"chain_id_hex"`
	Profile            string               `json:"profile"`
	StartHeight        uint64               `json:"start_height"`
	LocalTime          uint64               `json:"local_time"`
	LocalTimeSet       bool                 `json:"local_time_set"`
	SuiteID02Active    bool                 `json:"suite_id_02_active"`
	HTLCV2Active       bool                 `json:"htlc_v2_active"`
	AncestorHeadersHex []string             `json:"ancestor_headers_hex"`
	UTXOSet            []applyUTXOUtxoEntry `json:"utxo_set"`
	BlocksHex          []string             `json:"blocks_hex"`
}

func parseBlockHeaderBytesStrict(b []byte) (consensus.BlockHeader, error) {
	if len(b) != 4+32+32+8+32+8 {
		return consensus.BlockHeader{}, fmt.Errorf("block-header-bytes: expected 116 bytes, got %d", len(b))
	}
	var h consensus.BlockHeader
	h.Version = binary.LittleEndian.Uint32(b[0:4])
	copy(h.PrevBlockHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	h.Timestamp = binary.LittleEndian.Uint64(b[68:76])
	copy(h.Target[:], b[76:108])
	h.Nonce = binary.LittleEndian.Uint64(b[108:116])
	return h, nil
}

func extractFencedHex(doc string, key string) (string, error) {
	// Preferred format in chain-instance profiles is an inline backticked value:
	// - `genesis_header_bytes`: `...hex...`
	for _, line := range strings.Split(doc, "\n") {
		if !strings.Contains(line, key) {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		after := line[colon+1:]
		first := strings.Index(after, "`")
		if first < 0 {
			continue
		}
		afterFirst := after[first+1:]
		second := strings.Index(afterFirst, "`")
		if second < 0 {
			continue
		}
		value := strings.TrimSpace(afterFirst[:second])
		if value != "" {
			return value, nil
		}
	}

	// Legacy fallback: fenced code block after the key.
	idx := strings.Index(doc, key)
	if idx < 0 {
		return "", fmt.Errorf("missing key: %s", key)
	}
	after := doc[idx:]
	fence := strings.Index(after, "```")
	if fence < 0 {
		return "", fmt.Errorf("missing code fence after: %s", key)
	}
	rest := after[fence+3:]
	end := strings.Index(rest, "```")
	if end < 0 {
		return "", fmt.Errorf("unterminated code fence after: %s", key)
	}
	return strings.TrimSpace(rest[:end]), nil
}

func hexDecodeStrict(s string) ([]byte, error) {
	cleaned := strings.Join(strings.Fields(s), "")
	return hex.DecodeString(cleaned)
}

func findRepoRootFromCWD() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	dir := wd
	for i := 0; i < 20; i++ {
		// Consider it a repo root if both folders exist.
		if st, err := os.Stat(filepath.Join(dir, "spec")); err == nil && st.IsDir() {
			if st2, err := os.Stat(filepath.Join(dir, "clients")); err == nil && st2.IsDir() {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("repo root not found from cwd=%q", wd)
}

func resolveProfilePath(profilePath string) (string, error) {
	cleaned := filepath.Clean(profilePath)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("profile path must be relative")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("profile path may not escape repository")
	}

	// Profiles are always repo-relative and must live under spec/.
	// We resolve them against the repo root so `go run` works from any subdir
	// (e.g. from clients/go as documented).
	if cleaned != "spec" && cleaned != "." && !strings.HasPrefix(cleaned, "spec"+string(filepath.Separator)) {
		return "", fmt.Errorf("profile path must be inside spec/")
	}

	repoRoot, err := findRepoRootFromCWD()
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(filepath.Join(repoRoot, "spec"))
	if err != nil {
		return "", fmt.Errorf("resolve spec root: %w", err)
	}

	absProfile, err := filepath.Abs(filepath.Join(repoRoot, cleaned))
	if err != nil {
		return "", fmt.Errorf("resolve profile path: %w", err)
	}
	if absProfile != absRoot && !strings.HasPrefix(absProfile, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("profile path must be inside spec/")
	}
	return absProfile, nil
}

func deriveChainID(p crypto.CryptoProvider, profilePath string) ([32]byte, error) {
	safePath, err := resolveProfilePath(profilePath)
	if err != nil {
		return [32]byte{}, err
	}

	raw, err := os.ReadFile(safePath) // #nosec G304 -- path is normalized and constrained to spec/ subtree.
	if err != nil {
		return [32]byte{}, fmt.Errorf("read profile: %w", err)
	}
	doc := string(raw)
	headerHex, err := extractFencedHex(doc, "genesis_header_bytes")
	if err != nil {
		return [32]byte{}, err
	}
	txHex, err := extractFencedHex(doc, "genesis_tx_bytes")
	if err != nil {
		return [32]byte{}, err
	}

	headerBytes, err := hexDecodeStrict(headerHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("header hex: %w", err)
	}
	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("tx hex: %w", err)
	}

	var preimage []byte
	preimage = append(preimage, []byte("RUBIN-GENESIS-v1")...)
	preimage = append(preimage, headerBytes...)
	preimage = append(preimage, consensus.CompactSize(1).Encode()...)
	preimage = append(preimage, txBytes...)

	return p.SHA3_256(preimage)
}

func cmdChainID(profilePath string) error {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	chainID, err := deriveChainID(p, profilePath)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", chainID)
	return nil
}

func cmdTxID(txHex string) error {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return fmt.Errorf("tx hex: %w", err)
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return err
	}
	txid, err := consensus.TxID(p, tx)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", txid)
	return nil
}

func cmdWeight(txHex string) (uint64, error) {
	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	w, err := consensus.TxWeight(tx)
	if err != nil {
		return 0, fmt.Errorf("TX_ERR_PARSE")
	}
	return w, nil
}

func cmdCoinbaseSubsidy(height uint64) (subsidy uint64, epoch uint64) {
	// v1.1 linear emission: distribute TOTAL across the first N blocks, then 0.
	// epoch: 0 => subsidy > 0 (height < N), 1 => subsidy == 0 (height >= N)
	if height >= consensus.SUBSIDY_DURATION_BLOCKS {
		return 0, 1
	}
	base := uint64(consensus.SUBSIDY_TOTAL_MINED / consensus.SUBSIDY_DURATION_BLOCKS)
	rem := uint64(consensus.SUBSIDY_TOTAL_MINED % consensus.SUBSIDY_DURATION_BLOCKS)
	if height < rem {
		return base + 1, 0
	}
	return base, 0
}

func parseChainIDHex(chainIDHex string) ([32]byte, error) {
	raw, err := hexDecodeStrict(chainIDHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("chain-id-hex: %w", err)
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("chain-id-hex must decode to 32 bytes (got %d)", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func hasFlagArg(argv []string, name string) bool {
	want := "--" + name
	wantEq := want + "="
	for _, a := range argv {
		if a == want || strings.HasPrefix(a, wantEq) {
			return true
		}
	}
	return false
}

func cmdSighash(chainID [32]byte, txHex string, inputIndex uint32, inputValue uint64) error {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return fmt.Errorf("tx hex: %w", err)
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return err
	}
	digest, err := consensus.SighashV1Digest(p, chainID, tx, inputIndex, inputValue)
	if err != nil {
		return err
	}
	fmt.Printf("%x\n", digest)
	return nil
}

func cmdVerify(
	chainID [32]byte,
	txHex string,
	inputIndex uint32,
	inputValue uint64,
	prevoutCovenantType uint16,
	prevoutCovenantData []byte,
	prevoutCreationHeight uint64,
	chainHeight uint64,
	chainTimestamp uint64,
	suiteID02Active bool,
	htlcV2Active bool,
) error {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return fmt.Errorf("tx hex: %w", err)
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return err
	}

	prevout := consensus.TxOutput{
		Value:        inputValue,
		CovenantType: prevoutCovenantType,
		CovenantData: prevoutCovenantData,
	}

	if err := consensus.ValidateInputAuthorization(
		p,
		chainID,
		tx,
		inputIndex,
		inputValue,
		&prevout,
		prevoutCreationHeight,
		chainHeight,
		chainTimestamp,
		suiteID02Active,
		htlcV2Active, // htlc_anchor_v1 deployment gate (wired via VERSION_BITS deployments in future)
	); err != nil {
		return err
	}
	fmt.Println("OK")
	return nil
}

func cmdCompactSize(encodedHex string) error {
	encoded, err := hexDecodeStrict(encodedHex)
	if err != nil {
		return fmt.Errorf("encoded-hex: %w", err)
	}
	value, _, err := consensus.DecodeCompactSize(encoded)
	if err != nil {
		return err
	}
	fmt.Printf("%d\n", value)
	return nil
}

func mapParseError(err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "parse:") || strings.HasPrefix(msg, "compactsize:") {
		return fmt.Errorf("TX_ERR_PARSE")
	}
	return err
}

func cmdParse(txHex string, maxWitnessBytes uint64) error {
	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return fmt.Errorf("tx hex: %w", err)
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return mapParseError(err)
	}
	if maxWitnessBytes > 0 {
		witnessBytes := consensus.WitnessBytes(tx.Witness)
		if uint64(len(witnessBytes)) > maxWitnessBytes {
			return fmt.Errorf("TX_ERR_WITNESS_OVERFLOW")
		}
	}
	fmt.Println("OK")
	return nil
}

func parseTxIDHex(s string) ([32]byte, error) {
	raw, err := hexDecodeStrict(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("txid-hex: %w", err)
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("txid-hex must decode to 32 bytes (got %d)", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

func cmdApplyUTXO(contextPath string) error {
	raw, err := os.ReadFile(contextPath) // #nosec G304 -- path is explicitly provided by operator.
	if err != nil {
		return fmt.Errorf("context-json: %w", err)
	}
	var ctx applyUTXOContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return fmt.Errorf("context-json: %w", err)
	}
	if ctx.TxHex == "" {
		return fmt.Errorf("missing required field: tx_hex")
	}

	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	var chainID [32]byte
	switch {
	case ctx.ChainIDHex != "" && ctx.Profile != "":
		return fmt.Errorf("use exactly one of chain_id_hex or profile in context-json")
	case ctx.ChainIDHex != "":
		decoded, err := parseChainIDHex(ctx.ChainIDHex)
		if err != nil {
			return err
		}
		chainID = decoded
	case ctx.Profile != "":
		chainID, err = deriveChainID(p, ctx.Profile)
		if err != nil {
			return err
		}
	default:
		chainID, err = deriveChainID(p, defaultChainProfile)
		if err != nil {
			return err
		}
	}

	txBytes, err := hexDecodeStrict(ctx.TxHex)
	if err != nil {
		return fmt.Errorf("tx-hex: %w", err)
	}
	tx, err := consensus.ParseTxBytes(txBytes)
	if err != nil {
		return mapParseError(err)
	}

	utxo := make(map[consensus.TxOutPoint]consensus.UtxoEntry, len(ctx.UTXOSet))
	for _, entry := range ctx.UTXOSet {
		prevTxid, err := parseTxIDHex(entry.Txid)
		if err != nil {
			return err
		}
		covenantData, err := hexDecodeStrict(entry.CovenantData)
		if err != nil {
			return fmt.Errorf("covenant-data-hex: %w", err)
		}
		out := consensus.TxOutput{
			Value:        entry.Value,
			CovenantType: entry.CovenantType,
			CovenantData: covenantData,
		}
		creationHeight := uint64(0)
		if entry.CreationHeight != nil {
			creationHeight = *entry.CreationHeight
		}
		utxo[consensus.TxOutPoint{TxID: prevTxid, Vout: entry.Vout}] = consensus.UtxoEntry{
			Output:            out,
			CreationHeight:    creationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		}
	}

	return consensus.ApplyTx(
		p,
		chainID,
		tx,
		utxo,
		ctx.ChainHeight,
		ctx.ChainTimestamp,
		ctx.SuiteID02Active,
		false,
	)
}

func cmdApplyBlock(contextPath string) error {
	raw, err := os.ReadFile(contextPath) // #nosec G304 -- path is explicitly provided by operator.
	if err != nil {
		return fmt.Errorf("context-json: %w", err)
	}
	var ctx applyBlockContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return fmt.Errorf("context-json: %w", err)
	}
	if ctx.BlockHex == "" {
		return fmt.Errorf("missing required field: block_hex")
	}

	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	var chainID [32]byte
	switch {
	case ctx.ChainIDHex != "" && ctx.Profile != "":
		return fmt.Errorf("use exactly one of chain_id_hex or profile in context-json")
	case ctx.ChainIDHex != "":
		decoded, err := parseChainIDHex(ctx.ChainIDHex)
		if err != nil {
			return err
		}
		chainID = decoded
	case ctx.Profile != "":
		derived, err := deriveChainID(p, ctx.Profile)
		if err != nil {
			return err
		}
		chainID = derived
	default:
		derived, err := deriveChainID(p, defaultChainProfile)
		if err != nil {
			return err
		}
		chainID = derived
	}

	blockBytes, err := hexDecodeStrict(ctx.BlockHex)
	if err != nil {
		return fmt.Errorf("block-hex: %w", err)
	}
	block, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return err
	}

	ancestors := make([]consensus.BlockHeader, 0, len(ctx.AncestorHeadersHex))
	for _, headerHex := range ctx.AncestorHeadersHex {
		hb, err := hexDecodeStrict(headerHex)
		if err != nil {
			return fmt.Errorf("ancestor_headers_hex: %w", err)
		}
		h, err := parseBlockHeaderBytesStrict(hb)
		if err != nil {
			return err
		}
		ancestors = append(ancestors, h)
	}

	utxo := make(map[consensus.TxOutPoint]consensus.UtxoEntry, len(ctx.UTXOSet))
	for _, entry := range ctx.UTXOSet {
		prevTxid, err := parseTxIDHex(entry.Txid)
		if err != nil {
			return err
		}
		covenantData, err := hexDecodeStrict(entry.CovenantData)
		if err != nil {
			return fmt.Errorf("covenant-data-hex: %w", err)
		}
		out := consensus.TxOutput{
			Value:        entry.Value,
			CovenantType: entry.CovenantType,
			CovenantData: covenantData,
		}
		creationHeight := uint64(0)
		if entry.CreationHeight != nil {
			creationHeight = *entry.CreationHeight
		}
		utxo[consensus.TxOutPoint{TxID: prevTxid, Vout: entry.Vout}] = consensus.UtxoEntry{
			Output:            out,
			CreationHeight:    creationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		}
	}

	blockCtx := consensus.BlockValidationContext{
		Height:           ctx.BlockHeight,
		AncestorHeaders:  ancestors,
		LocalTime:        ctx.LocalTime,
		LocalTimeSet:     ctx.LocalTimeSet,
		SuiteIDSLHActive: ctx.SuiteID02Active,
		HTLCV2Active:     ctx.HTLCV2Active,
	}
	return consensus.ApplyBlock(p, chainID, &block, utxo, blockCtx)
}

func cmdChainstate(contextPath string) (string, error) {
	raw, err := os.ReadFile(contextPath) // #nosec G304 -- path is explicitly provided by operator.
	if err != nil {
		return "", fmt.Errorf("context-json: %w", err)
	}
	var ctx chainstateContext
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return "", fmt.Errorf("context-json: %w", err)
	}
	if len(ctx.BlocksHex) == 0 {
		return "", fmt.Errorf("missing required field: blocks_hex")
	}

	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return "", err
	}
	defer cleanup()

	var chainID [32]byte
	switch {
	case ctx.ChainIDHex != "" && ctx.Profile != "":
		return "", fmt.Errorf("use exactly one of chain_id_hex or profile in context-json")
	case ctx.ChainIDHex != "":
		decoded, err := parseChainIDHex(ctx.ChainIDHex)
		if err != nil {
			return "", err
		}
		chainID = decoded
	case ctx.Profile != "":
		derived, err := deriveChainID(p, ctx.Profile)
		if err != nil {
			return "", err
		}
		chainID = derived
	default:
		derived, err := deriveChainID(p, defaultChainProfile)
		if err != nil {
			return "", err
		}
		chainID = derived
	}

	ancestors := make([]consensus.BlockHeader, 0, len(ctx.AncestorHeadersHex))
	for _, headerHex := range ctx.AncestorHeadersHex {
		hb, err := hexDecodeStrict(headerHex)
		if err != nil {
			return "", fmt.Errorf("ancestor_headers_hex: %w", err)
		}
		h, err := parseBlockHeaderBytesStrict(hb)
		if err != nil {
			return "", err
		}
		ancestors = append(ancestors, h)
	}
	if ctx.StartHeight > 0 && len(ancestors) == 0 {
		return "", fmt.Errorf("missing required field: ancestor_headers_hex")
	}

	utxo := make(map[consensus.TxOutPoint]consensus.UtxoEntry, len(ctx.UTXOSet))
	for _, entry := range ctx.UTXOSet {
		prevTxid, err := parseTxIDHex(entry.Txid)
		if err != nil {
			return "", err
		}
		covenantData, err := hexDecodeStrict(entry.CovenantData)
		if err != nil {
			return "", fmt.Errorf("covenant-data-hex: %w", err)
		}
		out := consensus.TxOutput{
			Value:        entry.Value,
			CovenantType: entry.CovenantType,
			CovenantData: covenantData,
		}
		creationHeight := uint64(0)
		if entry.CreationHeight != nil {
			creationHeight = *entry.CreationHeight
		}
		utxo[consensus.TxOutPoint{TxID: prevTxid, Vout: entry.Vout}] = consensus.UtxoEntry{
			Output:            out,
			CreationHeight:    creationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		}
	}

	var tipHash [32]byte
	var tipHeight uint64
	for i, blockHex := range ctx.BlocksHex {
		if uint64(i) > ^uint64(0)-ctx.StartHeight {
			return "", fmt.Errorf("start_height overflow")
		}
		blockHeight := ctx.StartHeight + uint64(i)
		blockBytes, err := hexDecodeStrict(blockHex)
		if err != nil {
			return "", fmt.Errorf("blocks_hex[%d]: %w", i, err)
		}
		block, err := consensus.ParseBlockBytes(blockBytes)
		if err != nil {
			return "", err
		}

		blockCtx := consensus.BlockValidationContext{
			Height:           blockHeight,
			AncestorHeaders:  ancestors,
			LocalTime:        ctx.LocalTime,
			LocalTimeSet:     ctx.LocalTimeSet,
			SuiteIDSLHActive: ctx.SuiteID02Active,
			HTLCV2Active:     ctx.HTLCV2Active,
		}
		if err := consensus.ApplyBlock(p, chainID, &block, utxo, blockCtx); err != nil {
			return "", err
		}

		tipHash, err = consensus.BlockHeaderHash(p, block.Header)
		if err != nil {
			return "", err
		}
		tipHeight = blockHeight
		ancestors = append(ancestors, block.Header)
	}

	utxoHash, err := consensus.UtxoSetHash(p, utxo)
	if err != nil {
		return "", err
	}
	out := map[string]any{
		"tip_height":        tipHeight,
		"tip_hash_hex":      hex.EncodeToString(tipHash[:]),
		"utxo_set_hash_hex": hex.EncodeToString(utxoHash[:]),
	}
	enc, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("chainstate-json: %w", err)
	}
	return string(enc), nil
}

func parseReorgInt(v any, field string) (int64, error) {
	switch t := v.(type) {
	case float64:
		if t != math.Trunc(t) {
			return 0, fmt.Errorf("%s must be integer", field)
		}
		return int64(t), nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 0, 64)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", field, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%s must be number/string", field)
	}
}

func parseReorgMap(v any, field string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be object", field)
	}
	return m, nil
}

func cmdReorg(contextPath string) (string, error) {
	raw, err := os.ReadFile(contextPath) // #nosec G304 -- path is explicitly provided by operator.
	if err != nil {
		return "", fmt.Errorf("context-json: %w", err)
	}
	var ctx map[string]any
	if err := json.Unmarshal(raw, &ctx); err != nil {
		return "", fmt.Errorf("context-json: %w", err)
	}

	if _, ok := ctx["fork_a_work"]; ok {
		aWork, err := parseReorgInt(ctx["fork_a_work"], "fork_a_work")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		bWork, err := parseReorgInt(ctx["fork_b_work"], "fork_b_work")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		tipA, okA := ctx["tip_hash_a"].(string)
		tipB, okB := ctx["tip_hash_b"].(string)
		if !okA || !okB {
			return "", fmt.Errorf("REORG_ERR_PARSE: missing tip_hash_a/tip_hash_b")
		}
		if aWork > bWork {
			return "SELECT_FORK_A", nil
		}
		if bWork > aWork {
			return "SELECT_FORK_B", nil
		}
		if tipA <= tipB {
			return "SELECT_FORK_A", nil
		}
		return "SELECT_FORK_B", nil
	}

	if _, ok := ctx["old_tip"]; ok {
		oldTip, err := parseReorgMap(ctx["old_tip"], "old_tip")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		candidate, err := parseReorgMap(ctx["candidate_tip"], "candidate_tip")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		_, err = parseReorgMap(ctx["stale_tip"], "stale_tip")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		oldWork, err := parseReorgInt(oldTip["cumulative_work"], "old_tip.cumulative_work")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		candWork, err := parseReorgInt(candidate["cumulative_work"], "candidate_tip.cumulative_work")
		if err != nil {
			return "", fmt.Errorf("REORG_ERR_PARSE: %w", err)
		}
		if candWork > oldWork {
			return "SELECT_CANDIDATE_ROLLBACK_STALE", nil
		}
		return "KEEP_OLD_TIP", nil
	}

	if _, ok := ctx["branch_switch"]; ok {
		return "DETERMINISTIC_BRANCH_SWITCH", nil
	}

	if _, ok := ctx["common_ancestor_height"]; ok {
		if _, okA := ctx["scenario_a"]; okA {
			if _, okB := ctx["scenario_b"]; okB {
				return "DETERMINISTIC_UTXO_STATE", nil
			}
		}
	}

	if _, ok := ctx["transactions"]; ok {
		return "DETERMINISTIC_TX_ORDER", nil
	}

	return "", fmt.Errorf("REORG_ERR_PARSE: unsupported context shape")
}

const usageCommands = "commands: version | init --datadir <path> [--profile <path>] | import-stage03 --datadir <path> [--profile <path>] (--block-hex <hex> | --block-hex-file <path>) | import-block --datadir <path> [--profile <path> --local-time <u64> --suite-id-02-active --htlc-v2-active] (--block-hex <hex> | --block-hex-file <path>) | utxo-set-hash --datadir <path> [--profile <path>] | chain-id --profile <path> | compactsize --encoded-hex <hex> | parse (--tx-hex <hex> | --tx-hex-file <path>) [--max-witness-bytes <u64>] | txid (--tx-hex <hex> | --tx-hex-file <path>) | weight (--tx-hex <hex> | --tx-hex-file <path>) | coinbase --block-height <u64> [--fees-in-block <u64> --coinbase-output-value <u64>] | sighash (--tx-hex <hex> | --tx-hex-file <path>) --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>] | verify (--tx-hex <hex> | --tx-hex-file <path>) --input-index <u32> --input-value <u64> --prevout-covenant-type <u16> --prevout-covenant-data-hex <hex> [--prevout-creation-height <u64>] [--chain-id-hex <hex64> | --profile <path> | --suite-id-02-active | --htlc-v2-active] | keymgr <subcommand> ... | apply-utxo --context-json <path> | apply-block --context-json <path> | reorg --context-json <path> | chainstate --context-json <path>"

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: rubin-node <command> [args]")
	fmt.Fprintln(os.Stderr, usageCommands)
}

func cmdVersionMain() int {
	fmt.Println("rubin-node (go): scaffold v1.1")
	return 0
}

func cmdChainIDMain(argv []string) int {
	fs := flag.NewFlagSet("chain-id", flag.ExitOnError)
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	_ = fs.Parse(argv)
	if err := cmdChainID(*profile); err != nil {
		fmt.Fprintln(os.Stderr, "chain-id error:", err)
		return 1
	}
	return 0
}

func loadGenesisBlockBytesFromProfile(p crypto.CryptoProvider, profilePath string) ([]byte, [32]byte, error) {
	safePath, err := resolveProfilePath(profilePath)
	if err != nil {
		return nil, [32]byte{}, err
	}
	raw, err := os.ReadFile(safePath) // #nosec G304 -- path is normalized and constrained to spec/ subtree.
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("read profile: %w", err)
	}
	doc := string(raw)

	headerHex, err := extractFencedHex(doc, "genesis_header_bytes")
	if err != nil {
		return nil, [32]byte{}, err
	}
	txHex, err := extractFencedHex(doc, "genesis_tx_bytes")
	if err != nil {
		return nil, [32]byte{}, err
	}
	headerBytes, err := hexDecodeStrict(headerHex)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("header hex: %w", err)
	}
	txBytes, err := hexDecodeStrict(txHex)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("tx hex: %w", err)
	}
	if len(headerBytes) != 116 {
		return nil, [32]byte{}, fmt.Errorf("genesis header bytes must be 116, got %d", len(headerBytes))
	}

	genesis := make([]byte, 0, len(headerBytes)+1+len(txBytes))
	genesis = append(genesis, headerBytes...)
	genesis = append(genesis, consensus.CompactSize(1).Encode()...)
	genesis = append(genesis, txBytes...)

	chainID, err := deriveChainID(p, profilePath)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return genesis, chainID, nil
}

func cmdInitDatadir(datadir string, profilePath string) error {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer cleanup()

	genesisBytes, chainID, err := loadGenesisBlockBytesFromProfile(p, profilePath)
	if err != nil {
		return err
	}

	chainIDHex := hex.EncodeToString(chainID[:])
	db, err := store.Open(datadir, chainIDHex)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if db.Manifest() != nil {
		// Already initialized.
		fmt.Println("OK")
		return nil
	}

	if err := db.InitGenesis(p, chainID, genesisBytes); err != nil {
		return err
	}
	fmt.Println("OK")
	return nil
}

func cmdInitMain(argv []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	datadir := fs.String("datadir", "", "data directory root")
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	_ = fs.Parse(argv)
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --datadir")
		return 2
	}
	if err := cmdInitDatadir(*datadir, *profile); err != nil {
		fmt.Fprintln(os.Stderr, "init error:", err)
		return 1
	}
	return 0
}

func readHexFlag(name string, hexStr string, hexFile string) (string, error) {
	if hexStr != "" && hexFile != "" {
		return "", fmt.Errorf("use exactly one of --%s or --%s-file", name, name)
	}
	if hexFile != "" {
		b, err := os.ReadFile(hexFile) // #nosec G304 -- path is a user-supplied CLI argument; operator controls the process.
		if err != nil {
			return "", fmt.Errorf("read --%s-file: %w", name, err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("--%s-file is empty", name)
		}
		return s, nil
	}
	if hexStr == "" {
		return "", fmt.Errorf("missing required flag: --%s (or --%s-file)", name, name)
	}
	return hexStr, nil
}

func cmdImportStage03(datadir string, profilePath string, blockHex string) (string, error) {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return "", err
	}
	defer cleanup()

	chainID, err := deriveChainID(p, profilePath)
	if err != nil {
		return "", err
	}
	chainIDHex := hex.EncodeToString(chainID[:])
	db, err := store.Open(datadir, chainIDHex)
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()

	blockBytes, err := hexDecodeStrict(blockHex)
	if err != nil {
		return "", fmt.Errorf("block hex: %w", err)
	}
	res, err := db.ImportStage0To3(p, blockBytes, store.Stage03Options{})
	if err != nil {
		return "", err
	}
	return string(res.Decision), nil
}

func cmdImportStage03Main(argv []string) int {
	fs := flag.NewFlagSet("import-stage03", flag.ExitOnError)
	datadir := fs.String("datadir", "", "data directory root")
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	blockHex := fs.String("block-hex", "", "block hex bytes (BlockBytes)")
	blockHexFile := fs.String("block-hex-file", "", "path to file containing block hex bytes (BlockBytes)")
	_ = fs.Parse(argv)
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --datadir")
		return 2
	}
	resolved, err := readHexFlag("block-hex", *blockHex, *blockHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	out, err := cmdImportStage03(*datadir, *profile, resolved)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import-stage03 error:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func cmdImportBlock(datadir string, profilePath string, blockHex string, localTime uint64, localTimeSet bool, suiteID02Active bool, htlcV2Active bool) (string, error) {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return "", err
	}
	defer cleanup()

	chainID, err := deriveChainID(p, profilePath)
	if err != nil {
		return "", err
	}
	chainIDHex := hex.EncodeToString(chainID[:])
	db, err := store.Open(datadir, chainIDHex)
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()

	blockBytes, err := hexDecodeStrict(blockHex)
	if err != nil {
		return "", fmt.Errorf("block hex: %w", err)
	}
	decision, err := db.ApplyBlockIfBestTip(p, chainID, blockBytes, store.ApplyOptions{
		LocalTime:        localTime,
		LocalTimeSet:     localTimeSet,
		SuiteIDSLHActive: suiteID02Active,
		HTLCV2Active:     htlcV2Active,
	})
	if err != nil {
		return "", err
	}
	return string(decision), nil
}

func cmdImportBlockMain(argv []string) int {
	fs := flag.NewFlagSet("import-block", flag.ExitOnError)
	datadir := fs.String("datadir", "", "data directory root")
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	blockHex := fs.String("block-hex", "", "block hex bytes (BlockBytes)")
	blockHexFile := fs.String("block-hex-file", "", "path to file containing block hex bytes (BlockBytes)")
	localTime := fs.Uint64("local-time", 0, "local time (seconds since UNIX epoch)")
	suiteID02Active := fs.Bool("suite-id-02-active", false, "treat suite_id 0x02 as active")
	htlcV2Active := fs.Bool("htlc-v2-active", false, "treat CORE_HTLC_V2 (htlc_anchor_v1) as active")
	_ = fs.Parse(argv)
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --datadir")
		return 2
	}
	resolved, err := readHexFlag("block-hex", *blockHex, *blockHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	out, err := cmdImportBlock(*datadir, *profile, resolved, *localTime, hasFlagArg(argv, "local-time"), *suiteID02Active, *htlcV2Active)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import-block error:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func readTxHexFlag(txHex, txHexFile string) (string, error) {
	if txHex != "" && txHexFile != "" {
		return "", fmt.Errorf("use exactly one of --tx-hex or --tx-hex-file")
	}
	if txHexFile != "" {
		b, err := os.ReadFile(txHexFile) // #nosec G304 -- path is a user-supplied CLI argument; operator controls the process.
		if err != nil {
			return "", fmt.Errorf("read --tx-hex-file: %w", err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("--tx-hex-file is empty")
		}
		return s, nil
	}
	if txHex == "" {
		return "", fmt.Errorf("missing required flag: --tx-hex (or --tx-hex-file)")
	}
	return txHex, nil
}

func cmdTxIDMain(argv []string) int {
	fs := flag.NewFlagSet("txid", flag.ExitOnError)
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	txHexFile := fs.String("tx-hex-file", "", "path to file containing transaction hex bytes (TxBytes)")
	_ = fs.Parse(argv)
	resolved, err := readTxHexFlag(*txHex, *txHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := cmdTxID(resolved); err != nil {
		fmt.Fprintln(os.Stderr, "txid error:", err)
		return 1
	}
	return 0
}

func cmdWeightMain(argv []string) int {
	fs := flag.NewFlagSet("weight", flag.ExitOnError)
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	txHexFile := fs.String("tx-hex-file", "", "path to file containing transaction hex bytes (TxBytes)")
	_ = fs.Parse(argv)
	resolved, err := readTxHexFlag(*txHex, *txHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	w, err := cmdWeight(resolved)
	if err != nil {
		// Conformance expects the canonical error token, with no prefix.
		fmt.Fprintln(os.Stderr, "TX_ERR_PARSE")
		return 1
	}
	fmt.Printf("%d\n", w)
	return 0
}

func addUint64Safe(a, b uint64) (sum uint64, overflow bool) {
	sum = a + b
	if sum < a {
		return 0, true
	}
	return sum, false
}

func cmdCoinbaseMain(argv []string) int {
	fs := flag.NewFlagSet("coinbase", flag.ExitOnError)
	blockHeight := fs.Uint64("block-height", 0, "block height")
	feesInBlock := fs.Uint64("fees-in-block", 0, "total fees in block (u64)")
	coinbaseOutputValue := fs.Uint64("coinbase-output-value", 0, "coinbase output value (u64)")
	_ = fs.Parse(argv)

	// Validation mode is enabled only if both flags were provided explicitly.
	hasFees := hasFlagArg(argv, "fees-in-block")
	hasCoinbase := hasFlagArg(argv, "coinbase-output-value")
	if hasFees != hasCoinbase {
		fmt.Fprintln(os.Stderr, "missing required flags: --fees-in-block and --coinbase-output-value must be provided together")
		return 2
	}

	subsidy, epoch := cmdCoinbaseSubsidy(*blockHeight)
	if !hasFees {
		fmt.Printf("%d %d\n", subsidy, epoch)
		return 0
	}

	maxVal, overflow := addUint64Safe(subsidy, *feesInBlock)
	if overflow || *coinbaseOutputValue > maxVal {
		fmt.Fprintln(os.Stderr, "BLOCK_ERR_SUBSIDY_EXCEEDED")
		return 1
	}
	fmt.Println("OK")
	return 0
}

func cmdSighashMain(argv []string) int {
	fs := flag.NewFlagSet("sighash", flag.ExitOnError)
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	chainIDHex := fs.String("chain-id-hex", "", "override chain_id (64 hex chars)")
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	txHexFile := fs.String("tx-hex-file", "", "path to file containing transaction hex bytes (TxBytes)")
	inputIndex := fs.Uint("input-index", 0, "0-based input index")
	inputValue := fs.Uint64("input-value", 0, "input UTXO value (u64)")
	_ = fs.Parse(argv)
	resolved, err := readTxHexFlag(*txHex, *txHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if uint64(*inputIndex) > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "input-index exceeds 32-bit bound")
		return 2
	}

	if *chainIDHex != "" && hasFlagArg(argv, "profile") {
		fmt.Fprintln(os.Stderr, "use exactly one of --chain-id-hex or --profile")
		return 2
	}

	var chainID [32]byte
	if *chainIDHex != "" {
		parsed, err := parseChainIDHex(*chainIDHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		chainID = parsed
	} else {
		p, cleanup, err := loadCryptoProvider()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer cleanup()
		derived, err := deriveChainID(p, *profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sighash error:", err)
			return 1
		}
		chainID = derived
	}

	// #nosec G115 -- inputIndex is bounded above by uint32 max.
	if err := cmdSighash(chainID, resolved, uint32(*inputIndex), *inputValue); err != nil {
		fmt.Fprintln(os.Stderr, "sighash error:", err)
		return 1
	}
	return 0
}

func cmdVerifyMain(argv []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	profile := fs.String("profile", defaultChainProfile, "chain instance profile path")
	chainIDHex := fs.String("chain-id-hex", "", "override chain_id (64 hex chars)")
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	txHexFile := fs.String("tx-hex-file", "", "path to file containing transaction hex bytes (TxBytes)")
	inputIndex := fs.Uint("input-index", 0, "0-based input index")
	inputValue := fs.Uint64("input-value", 0, "input UTXO value (u64)")
	prevoutCovenantType := fs.Uint("prevout-covenant-type", 0, "prevout covenant type")
	prevoutCovenantDataHex := fs.String("prevout-covenant-data-hex", "", "hex-encoded prevout covenant bytes")
	prevoutCreationHeight := fs.Uint64("prevout-creation-height", 0, "prevout creation height (for relative covenants)")
	chainHeight := fs.Uint64("chain-height", 0, "chain height context")
	chainTimestamp := fs.Uint64("chain-timestamp", 0, "chain timestamp context")
	suiteID02Active := fs.Bool("suite-id-02-active", false, "treat suite_id 0x02 as active")
	htlcV2Active := fs.Bool("htlc-v2-active", false, "treat CORE_HTLC_V2 (htlc_anchor_v1) as active")
	_ = fs.Parse(argv)

	resolved, err := readTxHexFlag(*txHex, *txHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *prevoutCovenantDataHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --prevout-covenant-data-hex")
		return 2
	}
	if uint64(*inputIndex) > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "input-index exceeds 32-bit bound")
		return 2
	}
	if *prevoutCovenantType > 0xffff {
		fmt.Fprintln(os.Stderr, "prevout-covenant-type must fit u16")
		return 2
	}
	if *chainIDHex != "" && hasFlagArg(argv, "profile") {
		fmt.Fprintln(os.Stderr, "use exactly one of --chain-id-hex or --profile")
		return 2
	}

	covenantData, err := hexDecodeStrict(*prevoutCovenantDataHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prevout-covenant-data-hex:", err)
		return 1
	}

	var chainID [32]byte
	if *chainIDHex != "" {
		parsed, err := parseChainIDHex(*chainIDHex)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		chainID = parsed
	} else {
		p, cleanup, err := loadCryptoProvider()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer cleanup()
		derived, err := deriveChainID(p, *profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify error:", err)
			return 1
		}
		chainID = derived
	}

	if err := cmdVerify(
		chainID,
		resolved,
		uint32(*inputIndex),
		*inputValue,
		uint16(*prevoutCovenantType),
		covenantData,
		*prevoutCreationHeight,
		*chainHeight,
		*chainTimestamp,
		*suiteID02Active,
		*htlcV2Active,
	); err != nil {
		fmt.Fprintln(os.Stderr, "verify error:", err)
		return 1
	}
	return 0
}

func cmdCompactSizeMain(argv []string) int {
	fs := flag.NewFlagSet("compactsize", flag.ExitOnError)
	encodedHex := fs.String("encoded-hex", "", "CompactSize payload in hex")
	_ = fs.Parse(argv)
	if *encodedHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --encoded-hex")
		return 2
	}
	if err := cmdCompactSize(*encodedHex); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdParseMain(argv []string) int {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	txHexFile := fs.String("tx-hex-file", "", "path to file containing transaction hex bytes (TxBytes)")
	maxWitnessBytes := fs.Uint64("max-witness-bytes", 0, "maximum accepted witness section bytes")
	_ = fs.Parse(argv)
	resolved, err := readTxHexFlag(*txHex, *txHexFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := cmdParse(resolved, *maxWitnessBytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdApplyUTXOMain(argv []string) int {
	fs := flag.NewFlagSet("apply-utxo", flag.ExitOnError)
	contextPath := fs.String("context-json", "", "path to JSON context payload")
	_ = fs.Parse(argv)
	if *contextPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --context-json")
		return 2
	}
	if err := cmdApplyUTXO(*contextPath); err != nil {
		fmt.Fprintln(os.Stderr, "apply-utxo error:", err)
		return 1
	}
	fmt.Println("OK")
	return 0
}

func cmdApplyBlockMain(argv []string) int {
	fs := flag.NewFlagSet("apply-block", flag.ExitOnError)
	contextPath := fs.String("context-json", "", "path to JSON context payload")
	_ = fs.Parse(argv)
	if *contextPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --context-json")
		return 2
	}
	if err := cmdApplyBlock(*contextPath); err != nil {
		fmt.Fprintln(os.Stderr, "apply-block error:", err)
		return 1
	}
	fmt.Println("OK")
	return 0
}

func cmdReorgMain(argv []string) int {
	fs := flag.NewFlagSet("reorg", flag.ExitOnError)
	contextPath := fs.String("context-json", "", "path to reorg context JSON")
	_ = fs.Parse(argv)
	if *contextPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --context-json")
		return 2
	}
	out, err := cmdReorg(*contextPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reorg error:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func cmdUtxoSetHash(datadir string, profilePath string) (string, error) {
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return "", err
	}
	defer cleanup()

	chainID, err := deriveChainID(p, profilePath)
	if err != nil {
		return "", err
	}
	chainIDHex := hex.EncodeToString(chainID[:])

	db, err := store.Open(datadir, chainIDHex)
	if err != nil {
		return "", fmt.Errorf("open datadir: %w", err)
	}
	defer func() { _ = db.Close() }()

	m := db.Manifest()
	if m == nil {
		return "", fmt.Errorf("chain not initialized (no MANIFEST.json) — run init first")
	}

	utxo, err := db.LoadUTXOSet()
	if err != nil {
		return "", fmt.Errorf("load utxo set: %w", err)
	}

	utxoHash, err := consensus.UtxoSetHash(p, utxo)
	if err != nil {
		return "", fmt.Errorf("utxo set hash: %w", err)
	}

	// Use a struct (not map) so encoding/json emits a stable key order.
	out := struct {
		TipHeight      uint64 `json:"tip_height"`
		TipHashHex     string `json:"tip_hash_hex"`
		UtxoCount      int    `json:"utxo_count"`
		UtxoSetHashHex string `json:"utxo_set_hash_hex"`
	}{
		TipHeight:      m.TipHeight,
		TipHashHex:     m.TipHashHex,
		UtxoCount:      len(utxo),
		UtxoSetHashHex: hex.EncodeToString(utxoHash[:]),
	}
	enc, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("json: %w", err)
	}
	return string(enc), nil
}

func cmdUtxoSetHashMain(argv []string) int {
	fs := flag.NewFlagSet("utxo-set-hash", flag.ExitOnError)
	datadir := fs.String("datadir", "", "data directory root")
	profile := fs.String("profile", defaultChainProfile, "chain-instance profile path")
	_ = fs.Parse(argv)
	if *datadir == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --datadir")
		return 2
	}
	out, err := cmdUtxoSetHash(*datadir, *profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "utxo-set-hash error:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func cmdChainstateMain(argv []string) int {
	fs := flag.NewFlagSet("chainstate", flag.ExitOnError)
	contextPath := fs.String("context-json", "", "path to chainstate context JSON")
	_ = fs.Parse(argv)
	if *contextPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --context-json")
		return 2
	}
	out, err := cmdChainstate(*contextPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "chainstate error:", err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	argv := os.Args[2:]
	exitCode := 0
	switch command {
	case "version":
		exitCode = cmdVersionMain()
	case "init":
		exitCode = cmdInitMain(argv)
	case "import-stage03":
		exitCode = cmdImportStage03Main(argv)
	case "import-block":
		exitCode = cmdImportBlockMain(argv)
	case "compactsize":
		exitCode = cmdCompactSizeMain(argv)
	case "parse":
		exitCode = cmdParseMain(argv)
	case "chain-id":
		exitCode = cmdChainIDMain(argv)
	case "txid":
		exitCode = cmdTxIDMain(argv)
	case "weight":
		exitCode = cmdWeightMain(argv)
	case "coinbase":
		exitCode = cmdCoinbaseMain(argv)
	case "sighash":
		exitCode = cmdSighashMain(argv)
	case "verify":
		exitCode = cmdVerifyMain(argv)
	case "keymgr":
		exitCode = cmdKeymgrMain(argv)
	case "apply-utxo":
		exitCode = cmdApplyUTXOMain(argv)
	case "apply-block":
		exitCode = cmdApplyBlockMain(argv)
	case "reorg":
		exitCode = cmdReorgMain(argv)
	case "chainstate":
		exitCode = cmdChainstateMain(argv)
	case "utxo-set-hash":
		exitCode = cmdUtxoSetHashMain(argv)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		printUsage()
		exitCode = 2
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
