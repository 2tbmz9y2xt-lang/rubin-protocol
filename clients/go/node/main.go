package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

func extractFencedHex(doc string, key string) (string, error) {
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

func resolveProfilePath(profilePath string) (string, error) {
	cleaned := filepath.Clean(profilePath)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("profile path must be relative")
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("profile path may not escape repository")
	}

	root := filepath.Clean("spec")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve profile root: %w", err)
	}
	absProfile, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("resolve profile path: %w", err)
	}
	if absProfile != absRoot && !strings.HasPrefix(absProfile, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("profile path must be inside %s", root)
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

	return p.SHA3_256(preimage), nil
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
	txid := consensus.TxID(p, tx)
	fmt.Printf("%x\n", txid)
	return nil
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
	chainHeight uint64,
	chainTimestamp uint64,
	suiteID02Active bool,
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
			chainHeight,
		chainTimestamp,
		suiteID02Active,
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

const usageCommands = "commands: version | chain-id --profile <path> | compactsize --encoded-hex <hex> | parse --tx-hex <hex> [--max-witness-bytes <u64>] | txid --tx-hex <hex> | sighash --tx-hex <hex> --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>] | verify --tx-hex <hex> --input-index <u32> --input-value <u64> --prevout-covenant-type <u16> --prevout-covenant-data-hex <hex> [--chain-id-hex <hex64> | --profile <path>]"

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
	profile := fs.String("profile", "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md", "chain instance profile path")
	_ = fs.Parse(argv)
	if err := cmdChainID(*profile); err != nil {
		fmt.Fprintln(os.Stderr, "chain-id error:", err)
		return 1
	}
	return 0
}

func cmdTxIDMain(argv []string) int {
	fs := flag.NewFlagSet("txid", flag.ExitOnError)
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	_ = fs.Parse(argv)
	if *txHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
		return 2
	}
	if err := cmdTxID(*txHex); err != nil {
		fmt.Fprintln(os.Stderr, "txid error:", err)
		return 1
	}
	return 0
}

func cmdSighashMain(argv []string) int {
	fs := flag.NewFlagSet("sighash", flag.ExitOnError)
	profile := fs.String("profile", "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md", "chain instance profile path")
	chainIDHex := fs.String("chain-id-hex", "", "override chain_id (64 hex chars)")
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	inputIndex := fs.Uint("input-index", 0, "0-based input index")
	inputValue := fs.Uint64("input-value", 0, "input UTXO value (u64)")
	_ = fs.Parse(argv)
	if *txHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
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
	if err := cmdSighash(chainID, *txHex, uint32(*inputIndex), *inputValue); err != nil {
		fmt.Fprintln(os.Stderr, "sighash error:", err)
		return 1
	}
	return 0
}

func cmdVerifyMain(argv []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	profile := fs.String("profile", "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md", "chain instance profile path")
	chainIDHex := fs.String("chain-id-hex", "", "override chain_id (64 hex chars)")
	txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
	inputIndex := fs.Uint("input-index", 0, "0-based input index")
	inputValue := fs.Uint64("input-value", 0, "input UTXO value (u64)")
	prevoutCovenantType := fs.Uint("prevout-covenant-type", 0, "prevout covenant type")
	prevoutCovenantDataHex := fs.String("prevout-covenant-data-hex", "", "hex-encoded prevout covenant bytes")
	chainHeight := fs.Uint64("chain-height", 0, "chain height context")
	chainTimestamp := fs.Uint64("chain-timestamp", 0, "chain timestamp context")
	suiteID02Active := fs.Bool("suite-id-02-active", false, "treat suite_id 0x02 as active")
	_ = fs.Parse(argv)

	if *txHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
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
		*txHex,
		uint32(*inputIndex),
		*inputValue,
		uint16(*prevoutCovenantType),
		covenantData,
		*chainHeight,
		*chainTimestamp,
		*suiteID02Active,
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
	maxWitnessBytes := fs.Uint64("max-witness-bytes", 0, "maximum accepted witness section bytes")
	_ = fs.Parse(argv)
	if *txHex == "" {
		fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
		return 2
	}
	if err := cmdParse(*txHex, *maxWitnessBytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
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
	case "compactsize":
		exitCode = cmdCompactSizeMain(argv)
	case "parse":
		exitCode = cmdParseMain(argv)
	case "chain-id":
		exitCode = cmdChainIDMain(argv)
	case "txid":
		exitCode = cmdTxIDMain(argv)
	case "sighash":
		exitCode = cmdSighashMain(argv)
	case "verify":
		exitCode = cmdVerifyMain(argv)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		printUsage()
		exitCode = 2
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
