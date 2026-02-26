package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type traceHeader struct {
	Type                  string `json:"type"`
	SchemaVersion         int    `json:"schema_version"`
	GeneratedAtUTC        string `json:"generated_at_utc"`
	RepoCommit            string `json:"repo_commit"`
	GoVersion             string `json:"go_version"`
	FixturesDigestSHA3256 string `json:"fixtures_digest_sha3_256"`
}

type traceEntry struct {
	Type     string         `json:"type"`
	Gate     string         `json:"gate"`
	VectorID string         `json:"vector_id"`
	Op       string         `json:"op"`
	Ok       bool           `json:"ok"`
	Err      string         `json:"err"`
	Inputs   map[string]any `json:"inputs"`
	Outputs  map[string]any `json:"outputs"`
}

type parseFixture struct {
	Gate    string        `json:"gate"`
	Vectors []parseVector `json:"vectors"`
}
type parseVector struct {
	ID       string `json:"id"`
	Op       string `json:"op"`
	TxHex    string `json:"tx_hex"`
	ExpectOk bool   `json:"expect_ok"`
}

type sighashFixture struct {
	Gate    string          `json:"gate"`
	Vectors []sighashVector `json:"vectors"`
}
type sighashVector struct {
	ID         string `json:"id"`
	Op         string `json:"op"`
	TxHex      string `json:"tx_hex"`
	ChainIDHex string `json:"chain_id"`
	InputIndex uint32 `json:"input_index"`
	InputValue uint64 `json:"input_value"`
	ExpectOk   bool   `json:"expect_ok"`
}

type powFixture struct {
	Gate    string      `json:"gate"`
	Vectors []powVector `json:"vectors"`
}
type powVector struct {
	ID             string `json:"id"`
	Op             string `json:"op"`
	ExpectOk       bool   `json:"expect_ok"`
	ExpectErr      string `json:"expect_err"`
	TargetOldHex   string `json:"target_old"`
	TimestampFirst uint64 `json:"timestamp_first"`
	TimestampLast  uint64 `json:"timestamp_last"`
	HeaderHex      string `json:"header_hex"`
	TargetHex      string `json:"target_hex"`
}

type utxoBasicFixture struct {
	Gate    string            `json:"gate"`
	Vectors []utxoBasicVector `json:"vectors"`
}
type utxoBasicVector struct {
	ID             string     `json:"id"`
	Op             string     `json:"op"`
	TxHex          string     `json:"tx_hex"`
	Utxos          []utxoJSON `json:"utxos"`
	Height         uint64     `json:"height"`
	BlockTimestamp uint64     `json:"block_timestamp"`
	BlockMTP       *uint64    `json:"block_mtp"`
	ExpectOk       bool       `json:"expect_ok"`
	ExpectErr      string     `json:"expect_err"`
}

type utxoJSON struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantDataHex   string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

type blockBasicFixture struct {
	Gate    string             `json:"gate"`
	Vectors []blockBasicVector `json:"vectors"`
}
type blockBasicVector struct {
	ID             string `json:"id"`
	Op             string `json:"op"`
	BlockHex       string `json:"block_hex"`
	ExpectedPrev   string `json:"expected_prev_hash"`
	ExpectedTarget string `json:"expected_target"`
	ExpectOk       bool   `json:"expect_ok"`
	ExpectErr      string `json:"expect_err"`
}

func mustGitCommit() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "UNKNOWN"
	}
	return strings.TrimSpace(string(out))
}

func mustGoVersion() string {
	out, err := exec.Command("go", "version").Output()
	if err != nil {
		return "UNKNOWN"
	}
	return strings.TrimSpace(string(out))
}

func sha3hex(b []byte) string {
	h := sha3.Sum256(b)
	return hex.EncodeToString(h[:])
}

func digestFixtures(dir string) (string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "CV-*.json"))
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	sum := sha3.New256()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		_, _ = sum.Write([]byte(filepath.Base(p)))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write(b)
		_, _ = sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func txErrString(err error) string {
	if err == nil {
		return ""
	}
	if te, ok := err.(*consensus.TxError); ok {
		return string(te.Code)
	}
	return err.Error()
}

func parseHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func main() {
	var fixturesDir string
	var outPath string
	flag.StringVar(&fixturesDir, "fixtures-dir", "conformance/fixtures", "path to conformance fixtures dir")
	flag.StringVar(&outPath, "out", "rubin-formal/traces/go_trace_v1.jsonl", "output JSONL path")
	flag.Parse()

	fixturesDigest, err := digestFixtures(fixturesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fixtures digest: %v\n", err)
		os.Exit(2)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(2)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create out: %v\n", err)
		os.Exit(2)
	}
	defer f.Close()

	hdr := traceHeader{
		Type:                  "header",
		SchemaVersion:         1,
		GeneratedAtUTC:        time.Now().UTC().Format(time.RFC3339Nano),
		RepoCommit:            mustGitCommit(),
		GoVersion:             mustGoVersion(),
		FixturesDigestSHA3256: fixturesDigest,
	}
	if err := writeJSON(f, hdr); err != nil {
		fmt.Fprintf(os.Stderr, "write header: %v\n", err)
		os.Exit(2)
	}

	paths, err := filepath.Glob(filepath.Join(fixturesDir, "CV-*.json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob: %v\n", err)
		os.Exit(2)
	}
	sort.Strings(paths)

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", p, err)
			os.Exit(2)
		}

		var gateProbe struct {
			Gate string `json:"gate"`
		}
		if err := json.Unmarshal(b, &gateProbe); err != nil {
			fmt.Fprintf(os.Stderr, "parse gate %s: %v\n", p, err)
			os.Exit(2)
		}

		switch gateProbe.Gate {
		case "CV-PARSE":
			var fx parseFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal %s: %v\n", p, err)
				os.Exit(2)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				_, txid, wtxid, n, err := consensus.ParseTx(txBytes)
				e := traceEntry{
					Type:     "entry",
					Gate:     fx.Gate,
					VectorID: v.ID,
					Op:       v.Op,
					Ok:       err == nil,
					Err:      txErrString(err),
					Inputs: map[string]any{
						"tx_hex": v.TxHex,
					},
					Outputs: map[string]any{
						"consumed": n,
						"txid":     hex.EncodeToString(txid[:]),
						"wtxid":    hex.EncodeToString(wtxid[:]),
					},
				}
				if err := writeJSON(f, e); err != nil {
					fmt.Fprintf(os.Stderr, "write: %v\n", err)
					os.Exit(2)
				}
			}

		case "CV-SIGHASH":
			var fx sighashFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal %s: %v\n", p, err)
				os.Exit(2)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				tx, _, _, _, perr := consensus.ParseTx(txBytes)
				var digest [32]byte
				var err error
				if perr != nil {
					err = perr
				} else {
					var chainID [32]byte
					cb, e := hex.DecodeString(v.ChainIDHex)
					if e != nil || len(cb) != 32 {
						err = fmt.Errorf("bad chain_id")
					} else {
						copy(chainID[:], cb)
						digest, err = consensus.SighashV1Digest(tx, v.InputIndex, v.InputValue, chainID)
					}
				}
				e := traceEntry{
					Type:     "entry",
					Gate:     fx.Gate,
					VectorID: v.ID,
					Op:       v.Op,
					Ok:       err == nil,
					Err:      txErrString(err),
					Inputs: map[string]any{
						"tx_hex":      v.TxHex,
						"chain_id":    v.ChainIDHex,
						"input_index": v.InputIndex,
						"input_value": v.InputValue,
					},
					Outputs: map[string]any{
						"digest": hex.EncodeToString(digest[:]),
					},
				}
				_ = writeJSON(f, e)
			}

		case "CV-POW":
			var fx powFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal %s: %v\n", p, err)
				os.Exit(2)
			}
			for _, v := range fx.Vectors {
				var outErr error
				outputs := map[string]any{}
				inputs := map[string]any{
					"op": v.Op,
				}
				switch v.Op {
				case "retarget_v1":
					inputs["target_old"] = v.TargetOldHex
					inputs["timestamp_first"] = v.TimestampFirst
					inputs["timestamp_last"] = v.TimestampLast
					tOld, err := parseHex32(v.TargetOldHex)
					if err != nil {
						outErr = err
					} else {
						tNew, err := consensus.RetargetV1(tOld, v.TimestampFirst, v.TimestampLast)
						outErr = err
						outputs["target_new"] = hex.EncodeToString(tNew[:])
					}
				case "block_hash":
					inputs["header_hex"] = v.HeaderHex
					hb, _ := hex.DecodeString(v.HeaderHex)
					bh, err := consensus.BlockHash(hb)
					outErr = err
					outputs["block_hash"] = hex.EncodeToString(bh[:])
				case "pow_check":
					inputs["header_hex"] = v.HeaderHex
					inputs["target_hex"] = v.TargetHex
					hb, _ := hex.DecodeString(v.HeaderHex)
					t, err := parseHex32(v.TargetHex)
					if err != nil {
						outErr = err
					} else {
						outErr = consensus.PowCheck(hb, t)
					}
				default:
					outErr = fmt.Errorf("unsupported op")
				}
				e := traceEntry{
					Type:     "entry",
					Gate:     fx.Gate,
					VectorID: v.ID,
					Op:       v.Op,
					Ok:       outErr == nil,
					Err:      txErrString(outErr),
					Inputs:   inputs,
					Outputs:  outputs,
				}
				_ = writeJSON(f, e)
			}

		case "CV-UTXO-BASIC":
			var fx utxoBasicFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal %s: %v\n", p, err)
				os.Exit(2)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				tx, txid, _, _, perr := consensus.ParseTx(txBytes)
				var sum *consensus.UtxoApplySummary
				var err error
				if perr != nil {
					err = perr
				} else {
					utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(v.Utxos))
					for _, u := range v.Utxos {
						txidb, e := parseHex32(u.Txid)
						if e != nil {
							err = e
							break
						}
						cd, e := hex.DecodeString(u.CovenantDataHex)
						if e != nil {
							err = e
							break
						}
						utxos[consensus.Outpoint{Txid: txidb, Vout: u.Vout}] = consensus.UtxoEntry{
							Value:             u.Value,
							CovenantType:      u.CovenantType,
							CovenantData:      cd,
							CreationHeight:    u.CreationHeight,
							CreatedByCoinbase: u.CreatedByCoinbase,
						}
					}
					if err == nil {
						mtp := v.BlockTimestamp
						if v.BlockMTP != nil {
							mtp = *v.BlockMTP
						}
						var chainID [32]byte
						_, sum, err = consensus.ApplyNonCoinbaseTxBasicUpdateWithMTP(tx, txid, utxos, v.Height, v.BlockTimestamp, mtp, chainID)
					}
				}
				outputs := map[string]any{}
				if sum != nil {
					outputs["fee"] = sum.Fee
					outputs["utxo_count"] = sum.UtxoCount
				}
				e := traceEntry{
					Type:     "entry",
					Gate:     fx.Gate,
					VectorID: v.ID,
					Op:       v.Op,
					Ok:       err == nil,
					Err:      txErrString(err),
					Inputs: map[string]any{
						"tx_hex":          v.TxHex,
						"height":          v.Height,
						"block_timestamp": v.BlockTimestamp,
					},
					Outputs: outputs,
				}
				_ = writeJSON(f, e)
			}

		case "CV-BLOCK-BASIC":
			var fx blockBasicFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				fmt.Fprintf(os.Stderr, "unmarshal %s: %v\n", p, err)
				os.Exit(2)
			}
			for _, v := range fx.Vectors {
				blockBytes, _ := hex.DecodeString(v.BlockHex)
				prev, perr := parseHex32(v.ExpectedPrev)
				tgt, terr := parseHex32(v.ExpectedTarget)
				var err error
				var sum *consensus.BlockBasicSummary
				if perr != nil || terr != nil {
					err = fmt.Errorf("bad expected prev/target")
				} else {
					sum, err = consensus.ValidateBlockBasicWithContextAtHeight(blockBytes, &prev, &tgt, 0, nil)
				}
				outputs := map[string]any{}
				if sum != nil {
					outputs["block_hash"] = hex.EncodeToString(sum.BlockHash[:])
					outputs["sum_weight"] = sum.SumWeight
					outputs["sum_da"] = sum.SumDa
				}
				e := traceEntry{
					Type:     "entry",
					Gate:     fx.Gate,
					VectorID: v.ID,
					Op:       v.Op,
					Ok:       err == nil,
					Err:      txErrString(err),
					Inputs: map[string]any{
						"block_hex_digest_sha3_256": sha3hex(blockBytes),
						"expected_prev_hash":        v.ExpectedPrev,
						"expected_target":           v.ExpectedTarget,
					},
					Outputs: outputs,
				}
				_ = writeJSON(f, e)
			}

		default:
			// non-critical gate for refinement trace: skip silently (for now)
			continue
		}
	}

	// deterministic footer: verify file is non-empty beyond header
	outBytes, _ := os.ReadFile(outPath)
	if bytes.Count(outBytes, []byte("\n")) < 2 {
		fmt.Fprintf(os.Stderr, "no entries written\n")
		os.Exit(2)
	}
}
