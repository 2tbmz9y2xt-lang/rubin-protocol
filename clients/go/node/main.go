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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rubin-node <command> [args]")
		fmt.Fprintln(os.Stderr, "commands: version | chain-id --profile <path> | txid --tx-hex <hex> | sighash --tx-hex <hex> --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>]")
		os.Exit(2)
	}

	command := os.Args[1]
	switch command {
	case "version":
		fmt.Println("rubin-node (go): scaffold v1.1")
	case "chain-id":
		fs := flag.NewFlagSet("chain-id", flag.ExitOnError)
		profile := fs.String("profile", "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md", "chain instance profile path")
		_ = fs.Parse(os.Args[2:])
		if err := cmdChainID(*profile); err != nil {
			fmt.Fprintln(os.Stderr, "chain-id error:", err)
			os.Exit(1)
		}
	case "txid":
		fs := flag.NewFlagSet("txid", flag.ExitOnError)
		txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
		_ = fs.Parse(os.Args[2:])
		if *txHex == "" {
			fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
			os.Exit(2)
		}
		if err := cmdTxID(*txHex); err != nil {
			fmt.Fprintln(os.Stderr, "txid error:", err)
			os.Exit(1)
		}
	case "sighash":
		fs := flag.NewFlagSet("sighash", flag.ExitOnError)
		profile := fs.String("profile", "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md", "chain instance profile path")
		chainIDHex := fs.String("chain-id-hex", "", "override chain_id (64 hex chars)")
		txHex := fs.String("tx-hex", "", "transaction hex bytes (TxBytes)")
		inputIndex := fs.Uint("input-index", 0, "0-based input index")
		inputValue := fs.Uint64("input-value", 0, "input UTXO value (u64)")
		_ = fs.Parse(os.Args[2:])
		if *txHex == "" {
			fmt.Fprintln(os.Stderr, "missing required flag: --tx-hex")
			os.Exit(2)
		}
		if uint64(*inputIndex) > uint64(^uint32(0)) {
			fmt.Fprintln(os.Stderr, "input-index exceeds 32-bit bound")
			os.Exit(2)
		}

		if *chainIDHex != "" && hasFlagArg(os.Args[2:], "profile") {
			fmt.Fprintln(os.Stderr, "use exactly one of --chain-id-hex or --profile")
			os.Exit(2)
		}

		var chainID [32]byte
		if *chainIDHex != "" {
			parsed, err := parseChainIDHex(*chainIDHex)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			chainID = parsed
		} else {
			p, cleanup, err := loadCryptoProvider()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer cleanup()
			derived, err := deriveChainID(p, *profile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "sighash error:", err)
				os.Exit(1)
			}
			chainID = derived
		}

		if err := cmdSighash(chainID, *txHex, uint32(*inputIndex) /* #nosec G115 -- inputIndex is bounded above by uint32 max */, *inputValue); err != nil {
			fmt.Fprintln(os.Stderr, "sighash error:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		fmt.Fprintln(os.Stderr, "commands: version | chain-id --profile <path> | txid --tx-hex <hex> | sighash --tx-hex <hex> --input-index <u32> --input-value <u64> [--chain-id-hex <hex64> | --profile <path>]")
		os.Exit(2)
	}
}
