package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
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

type windowPatternJSON struct {
	Mode       string `json:"mode"`
	WindowSize int    `json:"window_size"`
	Start      uint64 `json:"start"`
	Step       uint64 `json:"step"`
	LastJump   uint64 `json:"last_jump"`
}

type powVector struct {
	ID             string             `json:"id"`
	Op             string             `json:"op"`
	ExpectOk       bool               `json:"expect_ok"`
	ExpectErr      string             `json:"expect_err"`
	TargetOldHex   string             `json:"target_old"`
	TimestampFirst uint64             `json:"timestamp_first"`
	TimestampLast  uint64             `json:"timestamp_last"`
	WindowPattern  *windowPatternJSON `json:"window_pattern"`
	HeaderHex      string             `json:"header_hex"`
	TargetHex      string             `json:"target_hex"`
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

var writeJSONFn = writeJSON

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

func listFixtureNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "CV-") && strings.HasSuffix(name, ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func readFixtureFile(dir, name string) ([]byte, error) {
	return fs.ReadFile(os.DirFS(dir), name)
}

func digestFixtures(dir string) (string, error) {
	names, err := listFixtureNames(dir)
	if err != nil {
		return "", err
	}
	sum := sha3.New256()
	for _, name := range names {
		b, err := readFixtureFile(dir, name)
		if err != nil {
			return "", err
		}
		_, _ = sum.Write([]byte(name))
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

func parseHex32Ptr(fieldName string, value string) (*[32]byte, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := parseHex32(value)
	if err != nil {
		return nil, fmt.Errorf("bad %s", fieldName)
	}
	return &parsed, nil
}

func writeTraceEntry(buf *bytes.Buffer, gate string, vectorID string, op string, runErr error, inputs map[string]any, outputs map[string]any) error {
	entry := traceEntry{
		Type:     "entry",
		Gate:     gate,
		VectorID: vectorID,
		Op:       op,
		Ok:       runErr == nil,
		Err:      txErrString(runErr),
		Inputs:   inputs,
		Outputs:  outputs,
	}
	if err := writeJSONFn(buf, entry); err != nil {
		return fmt.Errorf("write entry: %w", err)
	}
	return nil
}

func run(fixturesDir, outPath string) error {
	fixturesDigest, err := digestFixtures(fixturesDir)
	if err != nil {
		return fmt.Errorf("fixtures digest: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	var traceBuf bytes.Buffer

	hdr := traceHeader{
		Type:                  "header",
		SchemaVersion:         1,
		GeneratedAtUTC:        time.Now().UTC().Format(time.RFC3339Nano),
		RepoCommit:            mustGitCommit(),
		GoVersion:             mustGoVersion(),
		FixturesDigestSHA3256: fixturesDigest,
	}
	if err := writeJSONFn(&traceBuf, hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	names, err := listFixtureNames(fixturesDir)
	if err != nil {
		return fmt.Errorf("list fixtures: %w", err)
	}

	for _, name := range names {
		b, err := readFixtureFile(fixturesDir, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", filepath.Join(fixturesDir, name), err)
		}

		var gateProbe struct {
			Gate string `json:"gate"`
		}
		if err := json.Unmarshal(b, &gateProbe); err != nil {
			return fmt.Errorf("parse gate %s: %w", filepath.Join(fixturesDir, name), err)
		}

		switch gateProbe.Gate {
		case "CV-PARSE":
			var fx parseFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				return fmt.Errorf("unmarshal %s: %w", filepath.Join(fixturesDir, name), err)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				_, txid, wtxid, consumed, runErr := consensus.ParseTx(txBytes)
				if err := writeTraceEntry(
					&traceBuf,
					fx.Gate,
					v.ID,
					v.Op,
					runErr,
					map[string]any{"tx_hex": v.TxHex},
					map[string]any{
						"consumed": consumed,
						"txid":     hex.EncodeToString(txid[:]),
						"wtxid":    hex.EncodeToString(wtxid[:]),
					},
				); err != nil {
					return err
				}
			}

		case "CV-SIGHASH":
			var fx sighashFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				return fmt.Errorf("unmarshal %s: %w", filepath.Join(fixturesDir, name), err)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				tx, _, _, _, perr := consensus.ParseTx(txBytes)
				var digest [32]byte
				var runErr error
				if perr != nil {
					runErr = perr
				} else {
					var chainID [32]byte
					chainIDBytes, decodeErr := hex.DecodeString(v.ChainIDHex)
					if decodeErr != nil || len(chainIDBytes) != 32 {
						runErr = fmt.Errorf("bad chain_id")
					} else {
						copy(chainID[:], chainIDBytes)
						digest, runErr = consensus.SighashV1Digest(tx, v.InputIndex, v.InputValue, chainID)
					}
				}
				if err := writeTraceEntry(
					&traceBuf,
					fx.Gate,
					v.ID,
					v.Op,
					runErr,
					map[string]any{
						"tx_hex":      v.TxHex,
						"chain_id":    v.ChainIDHex,
						"input_index": v.InputIndex,
						"input_value": v.InputValue,
					},
					map[string]any{
						"digest": hex.EncodeToString(digest[:]),
					},
				); err != nil {
					return err
				}
			}

		case "CV-POW":
			var fx powFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				return fmt.Errorf("unmarshal %s: %w", filepath.Join(fixturesDir, name), err)
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
						var tNew [32]byte
						var err error
						if v.WindowPattern != nil {
							inputs["window_pattern_mode"] = v.WindowPattern.Mode
							inputs["window_pattern_window_size"] = v.WindowPattern.WindowSize
							inputs["window_pattern_start"] = v.WindowPattern.Start
							inputs["window_pattern_step"] = v.WindowPattern.Step
							inputs["window_pattern_last_jump"] = v.WindowPattern.LastJump

							if v.WindowPattern.Mode != "step_with_last_jump" || v.WindowPattern.WindowSize < 2 {
								err = fmt.Errorf("bad window_pattern")
							} else {
								ts := make([]uint64, v.WindowPattern.WindowSize)
								ts[0] = v.WindowPattern.Start
								for i := 1; i < v.WindowPattern.WindowSize; i++ {
									ts[i] = ts[i-1] + v.WindowPattern.Step
								}
								if v.WindowPattern.LastJump > 0 && v.WindowPattern.WindowSize >= 2 {
									ts[v.WindowPattern.WindowSize-1] = ts[v.WindowPattern.WindowSize-2] + v.WindowPattern.LastJump
								}
								tNew, err = consensus.RetargetV1Clamped(tOld, ts)
							}
						} else {
							tNew, err = consensus.RetargetV1(tOld, v.TimestampFirst, v.TimestampLast)
						}
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
				if err := writeTraceEntry(&traceBuf, fx.Gate, v.ID, v.Op, outErr, inputs, outputs); err != nil {
					return err
				}
			}

		case "CV-UTXO-BASIC":
			var fx utxoBasicFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				return fmt.Errorf("unmarshal %s: %w", filepath.Join(fixturesDir, name), err)
			}
			for _, v := range fx.Vectors {
				txBytes, _ := hex.DecodeString(v.TxHex)
				tx, txid, _, _, perr := consensus.ParseTx(txBytes)
				var sum *consensus.UtxoApplySummary
				var runErr error
				if perr != nil {
					runErr = perr
				} else {
					utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(v.Utxos))
					for _, u := range v.Utxos {
						txidb, e := parseHex32(u.Txid)
						if e != nil {
							runErr = e
							break
						}
						cd, e := hex.DecodeString(u.CovenantDataHex)
						if e != nil {
							runErr = e
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
					if runErr == nil {
						mtp := v.BlockTimestamp
						if v.BlockMTP != nil {
							mtp = *v.BlockMTP
						}
						var chainID [32]byte
						_, sum, runErr = consensus.ApplyNonCoinbaseTxBasicUpdateWithMTP(tx, txid, utxos, v.Height, v.BlockTimestamp, mtp, chainID)
					}
				}
				outputs := map[string]any{}
				if sum != nil {
					outputs["fee"] = sum.Fee
					outputs["utxo_count"] = sum.UtxoCount
				}
				if err := writeTraceEntry(
					&traceBuf,
					fx.Gate,
					v.ID,
					v.Op,
					runErr,
					map[string]any{
						"tx_hex":          v.TxHex,
						"height":          v.Height,
						"block_timestamp": v.BlockTimestamp,
					},
					outputs,
				); err != nil {
					return err
				}
			}

		case "CV-BLOCK-BASIC":
			var fx blockBasicFixture
			if err := json.Unmarshal(b, &fx); err != nil {
				return fmt.Errorf("unmarshal %s: %w", filepath.Join(fixturesDir, name), err)
			}
			for _, v := range fx.Vectors {
				blockBytes, _ := hex.DecodeString(v.BlockHex)
				var runErr error
				var sum *consensus.BlockBasicSummary
				prevPtr, prevErr := parseHex32Ptr("expected_prev_hash", v.ExpectedPrev)
				if prevErr != nil {
					runErr = prevErr
				}
				tgtPtr, tgtErr := parseHex32Ptr("expected_target", v.ExpectedTarget)
				if runErr == nil && tgtErr != nil {
					runErr = tgtErr
				}
				if runErr == nil {
					sum, runErr = consensus.ValidateBlockBasicWithContextAtHeight(blockBytes, prevPtr, tgtPtr, 0, nil)
				}
				outputs := map[string]any{}
				if sum != nil {
					outputs["block_hash"] = hex.EncodeToString(sum.BlockHash[:])
					outputs["sum_weight"] = sum.SumWeight
					outputs["sum_da"] = sum.SumDa
				}
				if err := writeTraceEntry(
					&traceBuf,
					fx.Gate,
					v.ID,
					v.Op,
					runErr,
					map[string]any{
						"block_hex_digest_sha3_256": sha3hex(blockBytes),
						"expected_prev_hash":        v.ExpectedPrev,
						"expected_target":           v.ExpectedTarget,
					},
					outputs,
				); err != nil {
					return err
				}
			}

		default:
			// non-critical gate for refinement trace: skip silently (for now)
			continue
		}
	}

	if bytes.Count(traceBuf.Bytes(), []byte("\n")) < 2 {
		return fmt.Errorf("no entries written")
	}
	if err := os.WriteFile(outPath, traceBuf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write out: %w", err)
	}
	return nil
}

func main() {
	var fixturesDir string
	var outPath string
	flag.StringVar(&fixturesDir, "fixtures-dir", "conformance/fixtures", "path to conformance fixtures dir")
	flag.StringVar(&outPath, "out", "rubin-formal/traces/go_trace_v1.jsonl", "output JSONL path")
	flag.Parse()

	if err := run(fixturesDir, outPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
