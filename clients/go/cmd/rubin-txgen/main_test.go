package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestTxGenCreateValidTx(t *testing.T) {
	fromKey := mustTxGenKeypair(t)
	toKey := mustTxGenKeypair(t)
	fromDER, err := fromKey.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}

	dir := t.TempDir()
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	st := node.NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x44
	var prevTxid [32]byte
	prevTxid[0] = 0x99
	st.Utxos[consensus.Outpoint{Txid: prevTxid, Vout: 0}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      fromAddress,
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}
	if err := st.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", dir,
		"--from-key", hex.EncodeToString(fromDER),
		"--to-key", hex.EncodeToString(toAddress),
		"--amount", "90",
		"--fee", "1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit=%d stderr=%q", code, stderr.String())
	}

	txBytes, err := hex.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	checked, err := consensus.CheckTransaction(txBytes, st.Utxos, 101, 0, node.DevnetGenesisChainID())
	if err != nil {
		t.Fatalf("CheckTransaction: %v", err)
	}
	if checked.Fee != 1 {
		t.Fatalf("fee=%d, want 1", checked.Fee)
	}
	if checked.SerializedSize != len(txBytes) {
		t.Fatalf("serialized_size=%d len=%d", checked.SerializedSize, len(txBytes))
	}
	if len(checked.Tx.Outputs) != 2 {
		t.Fatalf("outputs=%d, want 2", len(checked.Tx.Outputs))
	}
	if checked.Tx.Outputs[0].Value != 90 {
		t.Fatalf("output[0]=%d, want 90", checked.Tx.Outputs[0].Value)
	}
	if checked.Tx.Outputs[1].Value != 9 {
		t.Fatalf("change=%d, want 9", checked.Tx.Outputs[1].Value)
	}
}

func symlinkTraversalDataDir(t *testing.T) (raw string, cleaned string, escaped string) {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	raw = filepath.Join(link, "..", "chain")
	cleaned = node.NormalizeDataDir(raw)
	escaped = filepath.Join(outside, "chain")
	if cleaned == escaped {
		t.Fatalf("invalid fixture: cleaned path equals symlink-resolved escape path %q", cleaned)
	}
	return raw, cleaned, escaped
}

func TestRunNormalizesDataDirBeforeChainStateLoad(t *testing.T) {
	fromKey := mustTxGenKeypair(t)
	toKey := mustTxGenKeypair(t)
	fromDER, err := fromKey.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}
	rawDataDir, normalizedDataDir, escapedDataDir := symlinkTraversalDataDir(t)
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	st := node.NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x44
	var prevTxid [32]byte
	prevTxid[0] = 0x99
	st.Utxos[consensus.Outpoint{Txid: prevTxid, Vout: 0}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      fromAddress,
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}
	if err := st.Save(node.ChainStatePath(normalizedDataDir)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", rawDataDir,
		"--from-key", hex.EncodeToString(fromDER),
		"--to-key", hex.EncodeToString(toAddress),
		"--amount", "90",
		"--fee", "1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(node.ChainStatePath(escapedDataDir)); !os.IsNotExist(err) {
		t.Fatalf("raw symlink traversal path was used; stat err=%v path=%s", err, node.ChainStatePath(escapedDataDir))
	}
}

func TestRunRejectsMissingRequiredFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing from-key exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "missing required --from-key") {
		t.Fatalf("stderr=%q", stderr.String())
	}

	stderr.Reset()
	if code := run([]string{"--from-key", "00"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing to-key exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "missing required --to-key") {
		t.Fatalf("stderr=%q", stderr.String())
	}

	stderr.Reset()
	if code := run([]string{"--from-key", "00", "--to-key", "00"}, &stdout, &stderr); code != 2 {
		t.Fatalf("zero amount exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "missing or zero --amount") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunRejectsBlankDataDir(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", " \t ",
		"--from-key", "00",
		"--to-key", "00",
		"--amount", "1",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("blank datadir exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "missing required --datadir") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func mustTxGenKeypair(t *testing.T) *consensus.MLDSA87Keypair {
	t.Helper()
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
			t.Skipf("ML-DSA backend unavailable: %v", err)
		}
		t.Fatalf("NewMLDSA87Keypair: %v", err)
	}
	t.Cleanup(func() { kp.Close() })
	return kp
}

func TestNormalizeSubmitTargetAddsSubmitPath(t *testing.T) {
	got, err := normalizeSubmitTarget("127.0.0.1:19112")
	if err != nil {
		t.Fatalf("normalizeSubmitTarget: %v", err)
	}
	if got != "http://127.0.0.1:19112/submit_tx" {
		t.Fatalf("target=%q, want %q", got, "http://127.0.0.1:19112/submit_tx")
	}
}

func TestNormalizeSubmitTargetRejectsUnsupportedScheme(t *testing.T) {
	_, err := normalizeSubmitTarget("ftp://127.0.0.1:19112")
	if err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestNormalizeSubmitTargetRejectsMissingHost(t *testing.T) {
	_, err := normalizeSubmitTarget("http:///submit_tx")
	if err == nil {
		t.Fatal("expected missing host error")
	}
}

func TestNormalizeSubmitTargetRejectsNonLoopbackHost(t *testing.T) {
	_, err := normalizeSubmitTarget("http://example.com:19112")
	if err == nil {
		t.Fatal("expected non-loopback host error")
	}
}

func TestNormalizeSubmitTargetAcceptsIPv6Loopback(t *testing.T) {
	got, err := normalizeSubmitTarget("http://[::1]:19112")
	if err != nil {
		t.Fatalf("normalizeSubmitTarget: %v", err)
	}
	if got != "http://[::1]:19112/submit_tx" {
		t.Fatalf("target=%q", got)
	}
}

func TestDecodeHexFlagRejectsOddLength(t *testing.T) {
	if _, err := decodeHexFlag("abc"); err == nil {
		t.Fatal("expected odd-length error")
	}
}

func TestNextSpendHeightVariants(t *testing.T) {
	if _, err := nextSpendHeight(nil); err == nil {
		t.Fatal("expected nil chainstate error")
	}
	st := node.NewChainState()
	height, err := nextSpendHeight(st)
	if err != nil || height != 0 {
		t.Fatalf("got height=%d err=%v, want 0 nil", height, err)
	}
	st.HasTip = true
	st.Height = math.MaxUint64
	if _, err := nextSpendHeight(st); err == nil {
		t.Fatal("expected height overflow")
	}
}

func TestAddAmountAndFeeRejectsOverflow(t *testing.T) {
	if _, err := addAmountAndFee(math.MaxUint64, 1); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestSelectSpendableCoinbasesRejectsInsufficientBalance(t *testing.T) {
	st := node.NewChainState()
	var txid [32]byte
	txid[0] = 1
	st.Utxos[consensus.Outpoint{Txid: txid, Vout: 0}] = consensus.UtxoEntry{
		Value:             10,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      []byte{0x01},
		CreationHeight:    0,
		CreatedByCoinbase: true,
	}
	_, _, err := selectSpendableCoinbases(st, []byte{0x01}, consensus.COINBASE_MATURITY, 20)
	if err == nil {
		t.Fatal("expected insufficient balance error")
	}
}

func TestSelectSpendableCoinbasesChoosesMatureSortedInputs(t *testing.T) {
	st := node.NewChainState()
	var txidA [32]byte
	var txidB [32]byte
	txidA[0] = 0x02
	txidB[0] = 0x01
	st.Utxos[consensus.Outpoint{Txid: txidA, Vout: 0}] = consensus.UtxoEntry{
		Value:             7,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      []byte{0x01},
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}
	st.Utxos[consensus.Outpoint{Txid: txidB, Vout: 0}] = consensus.UtxoEntry{
		Value:             8,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      []byte{0x01},
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}
	selected, total, err := selectSpendableCoinbases(st, []byte{0x01}, consensus.COINBASE_MATURITY+1, 10)
	if err != nil {
		t.Fatalf("selectSpendableCoinbases: %v", err)
	}
	if total != 15 {
		t.Fatalf("total=%d, want 15", total)
	}
	if len(selected) != 2 {
		t.Fatalf("len=%d, want 2", len(selected))
	}
	if selected[0].outpoint.Txid != txidB {
		t.Fatalf("expected lexicographically smaller txid first")
	}
}

func TestSubmitTxReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/submit_tx" {
			t.Fatalf("path=%q, want /submit_tx", r.URL.Path)
		}
		http.Error(w, "rejected", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	err := submitTx(srv.URL, []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected submit error")
	}
	if !strings.Contains(err.Error(), "status=422") {
		t.Fatalf("error=%q, want status=422", err.Error())
	}
}

func TestSubmitTxSucceedsOn200(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%q, want POST", r.Method)
		}
		if r.URL.Path != "/submit_tx" {
			t.Fatalf("path=%q, want /submit_tx", r.URL.Path)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		gotBody = string(raw)
		fmt.Fprintln(w, `{"accepted":true}`)
	}))
	defer srv.Close()

	if err := submitTx(srv.URL, []byte{0x0a, 0x0b}); err != nil {
		t.Fatalf("submitTx: %v", err)
	}
	if !strings.Contains(gotBody, `"tx_hex":"0a0b"`) {
		t.Fatalf("body=%q, want tx_hex payload", gotBody)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("body read failed") }
func (errReadCloser) Close() error             { return nil }

func TestSubmitTxReturnsErrorWhenResponseDrainFails(t *testing.T) {
	client := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/submit_tx" {
				t.Fatalf("path=%q, want /submit_tx", r.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       errReadCloser{},
				Header:     make(http.Header),
			}, nil
		}),
	}

	err := submitTxWithClient("http://127.0.0.1:19112", []byte{0x0a, 0x0b}, client)
	if err == nil {
		t.Fatal("expected body drain error")
	}
	if !strings.Contains(err.Error(), "body read failed") {
		t.Fatalf("error=%q", err.Error())
	}
}

func TestSubmitTxReturnsTransportError(t *testing.T) {
	client := &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("transport failed")
		}),
	}

	err := submitTxWithClient("http://127.0.0.1:19112", []byte{0x0a, 0x0b}, client)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("error=%q", err.Error())
	}
}

func TestRunSubmitToReturnsErrorOnReject(t *testing.T) {
	fromKey := mustTxGenKeypair(t)
	toKey := mustTxGenKeypair(t)
	fromDER, err := fromKey.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}

	dir := t.TempDir()
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	st := node.NewChainState()
	st.HasTip = true
	st.Height = 100
	var prevTxid [32]byte
	prevTxid[0] = 0x24
	st.Utxos[consensus.Outpoint{Txid: prevTxid, Vout: 0}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      fromAddress,
		CreationHeight:    0,
		CreatedByCoinbase: true,
	}
	if err := st.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rejected", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", dir,
		"--from-key", hex.EncodeToString(fromDER),
		"--to-key", hex.EncodeToString(toAddress),
		"--amount", "90",
		"--fee", "1",
		"--submit-to", srv.URL,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "submit failed: status=422") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunSubmitToReturnsErrorOnInvalidTarget(t *testing.T) {
	fromKey := mustTxGenKeypair(t)
	toKey := mustTxGenKeypair(t)
	fromDER, err := fromKey.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}

	dir := t.TempDir()
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	st := node.NewChainState()
	st.HasTip = true
	st.Height = 100
	var prevTxid [32]byte
	prevTxid[0] = 0x25
	st.Utxos[consensus.Outpoint{Txid: prevTxid, Vout: 0}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      fromAddress,
		CreationHeight:    0,
		CreatedByCoinbase: true,
	}
	if err := st.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", dir,
		"--from-key", hex.EncodeToString(fromDER),
		"--to-key", hex.EncodeToString(toAddress),
		"--amount", "90",
		"--fee", "1",
		"--submit-to", "https://example.com:19112/debug",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `submit failed: submit target host "example.com" must be localhost or loopback`) {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if strings.TrimSpace(stdout.String()) == "" {
		t.Fatal("expected generated tx hex on stdout before submit failure")
	}
}

func TestRunSubmitToPostsGeneratedTxAndPreservesStdout(t *testing.T) {
	fromKey := mustTxGenKeypair(t)
	toKey := mustTxGenKeypair(t)
	fromDER, err := fromKey.PrivateKeyDER()
	if err != nil {
		t.Fatalf("PrivateKeyDER: %v", err)
	}

	dir := t.TempDir()
	fromAddress := consensus.P2PKCovenantDataForPubkey(fromKey.PubkeyBytes())
	toAddress := consensus.P2PKCovenantDataForPubkey(toKey.PubkeyBytes())

	st := node.NewChainState()
	st.HasTip = true
	st.Height = 100
	st.TipHash[0] = 0x55
	var prevTxid [32]byte
	prevTxid[0] = 0x42
	st.Utxos[consensus.Outpoint{Txid: prevTxid, Vout: 0}] = consensus.UtxoEntry{
		Value:             100,
		CovenantType:      consensus.COV_TYPE_P2PK,
		CovenantData:      fromAddress,
		CreationHeight:    0,
		CreatedByCoinbase: true,
	}
	if err := st.Save(node.ChainStatePath(dir)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		gotBody = string(raw)
		fmt.Fprintln(w, `{"accepted":true}`)
	}))
	defer srv.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--datadir", dir,
		"--from-key", hex.EncodeToString(fromDER),
		"--to-key", hex.EncodeToString(toAddress),
		"--amount", "90",
		"--fee", "1",
		"--submit-to", srv.URL,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exit=%d stderr=%q", code, stderr.String())
	}
	generatedHex := strings.TrimSpace(stdout.String())
	if generatedHex == "" {
		t.Fatal("expected tx hex on stdout")
	}
	if !strings.Contains(gotBody, generatedHex) {
		t.Fatalf("submit body missing generated tx hex")
	}
}
