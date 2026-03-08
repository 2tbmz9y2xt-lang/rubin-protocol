package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
