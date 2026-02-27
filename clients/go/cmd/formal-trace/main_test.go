package main

import (
	"crypto/sha3"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestListFixtureNamesSortedAndFiltered(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// Should include:
	mustWrite("CV-B.json", `{"gate":"CV-PARSE"}`)
	mustWrite("CV-A.json", `{"gate":"CV-PARSE"}`)
	// Should ignore:
	mustWrite("not-a-fixture.json", `{}`)
	if err := os.Mkdir(filepath.Join(dir, "CV-DIR.json"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	names, err := listFixtureNames(dir)
	if err != nil {
		t.Fatalf("listFixtureNames: %v", err)
	}
	if len(names) != 2 || names[0] != "CV-A.json" || names[1] != "CV-B.json" {
		t.Fatalf("unexpected names: %#v", names)
	}
}

func TestListFixtureNamesError(t *testing.T) {
	if _, err := listFixtureNames(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestReadFixtureFileDirFS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CV-X.json")
	want := []byte(`{"gate":"CV-PARSE"}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readFixtureFile(dir, "CV-X.json")
	if err != nil {
		t.Fatalf("readFixtureFile: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read mismatch: got=%q want=%q", string(got), string(want))
	}
}

func TestDigestFixturesDeterministicAndSensitive(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("CV-A.json", `{"gate":"CV-PARSE","vectors":[{"id":"A"}]}`)
	write("CV-B.json", `{"gate":"CV-SIGHASH","vectors":[{"id":"B"}]}`)

	d1, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	d2, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("digest not deterministic: d1=%s d2=%s", d1, d2)
	}

	// Mutate one file content: digest MUST change.
	write("CV-B.json", `{"gate":"CV-SIGHASH","vectors":[{"id":"B2"}]}`)
	d3, err := digestFixtures(dir)
	if err != nil {
		t.Fatalf("digestFixtures: %v", err)
	}
	if d3 == d1 {
		t.Fatalf("digest did not change after content change: d1=%s d3=%s", d1, d3)
	}

	// Sanity: digest is a SHA3-256 hex string.
	if len(d1) != sha3.New256().Size()*2 {
		t.Fatalf("unexpected digest length: %d", len(d1))
	}
}

func TestDigestFixturesPropagatesListError(t *testing.T) {
	if _, err := digestFixtures(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestDigestFixturesReturnsReadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "CV-A.json")
	if err := os.WriteFile(path, []byte(`{"gate":"CV-PARSE"}`), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := digestFixtures(dir); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunWritesTraceFileMultipleGates(t *testing.T) {
	fixturesDir := t.TempDir()
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "trace.jsonl")

	const validSighashTxHex = "0100000000000000000000000001111111111111111111111111111111111111111111111111111111111111111102000000000300000000040000000000"
	const validUtxoTxHex = "0100000000010000000000000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000000000000000010100000000000000000021010000000000000000000000000000000000000000000000000000000000000000000000000000"

	fixtures := map[string]string{
		"CV-PARSE.json": `{"gate":"CV-PARSE","vectors":[{"id":"P1","op":"parse","tx_hex":"00","expect_ok":false}]}`,
		"CV-SIGHASH.json": `{"gate":"CV-SIGHASH","vectors":[` +
			`{"id":"S1","op":"sighash_v1","tx_hex":"00","chain_id":"` + "00" + `","input_index":0,"input_value":0,"expect_ok":false},` +
			`{"id":"S2","op":"sighash_v1","tx_hex":"` + validSighashTxHex + `","chain_id":"` + "00" + `","input_index":0,"input_value":0,"expect_ok":false},` +
			`{"id":"S3","op":"sighash_v1","tx_hex":"` + validSighashTxHex + `","chain_id":"` + "0000000000000000000000000000000000000000000000000000000000000000" + `","input_index":0,"input_value":0,"expect_ok":false}` +
			`]}`,
		"CV-POW.json": `{"gate":"CV-POW","vectors":[` +
			`{"id":"W1","op":"retarget_v1","expect_ok":false,"target_old":"00","timestamp_first":0,"timestamp_last":0},` +
			`{"id":"W2","op":"retarget_v1","expect_ok":false,"target_old":"0000000000000000000000000000000000000000000000000000000000001234","timestamp_first":0,"timestamp_last":0,` +
			`"window_pattern":{"mode":"step_with_last_jump","window_size":2,"start":0,"step":120,"last_jump":240}},` +
			`{"id":"W3","op":"pow_check","expect_ok":false,"header_hex":"00","target_hex":"00"}` +
			`]}`,
		"CV-UTXO-BASIC.json": `{"gate":"CV-UTXO-BASIC","vectors":[` +
			`{"id":"U1","op":"utxo_apply_basic","tx_hex":"00","utxos":[],"height":1,"block_timestamp":1,"expect_ok":false,"expect_err":"TX_ERR_PARSE"},` +
			`{"id":"U2","op":"utxo_apply_basic","tx_hex":"` + validUtxoTxHex + `","utxos":[{"txid":"00","vout":0,"value":1,"covenant_type":1,"covenant_data":"00","creation_height":0,"created_by_coinbase":false}],` +
			`"height":1,"block_timestamp":1,"expect_ok":false,"expect_err":"TX_ERR_PARSE"}` +
			`]}`,
		"CV-BLOCK-BASIC.json": `{"gate":"CV-BLOCK-BASIC","vectors":[` +
			`{"id":"B1","op":"block_basic_check","block_hex":"00","expected_prev_hash":"00","expected_target":"","expect_ok":false,"expect_err":"BLOCK_ERR_PARSE"},` +
			`{"id":"B2","op":"block_basic_check","block_hex":"00","expected_prev_hash":"","expected_target":"00","expect_ok":false,"expect_err":"BLOCK_ERR_PARSE"},` +
			`{"id":"B3","op":"block_basic_check","block_hex":"00","expected_prev_hash":"` + "1111111111111111111111111111111111111111111111111111111111111111" + `","expected_target":"","expect_ok":false,"expect_err":"BLOCK_ERR_PARSE"}` +
			`]}`,
	}
	for name, content := range fixtures {
		if err := os.WriteFile(filepath.Join(fixturesDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
	}

	if err := run(fixturesDir, outPath); err != nil {
		t.Fatalf("run: %v", err)
	}

	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	// Must contain at least header + 1 entry line.
	lines := 0
	for _, c := range b {
		if c == '\n' {
			lines++
		}
	}
	if lines < 2 {
		t.Fatalf("expected >=2 lines, got %d", lines)
	}
}

func TestRunReturnsWriteHeaderError(t *testing.T) {
	prev := writeJSONFn
	writeJSONFn = func(io.Writer, any) error { return errors.New("nope") }
	t.Cleanup(func() { writeJSONFn = prev })

	fixturesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixturesDir, "CV-PARSE.json"), []byte(`{"gate":"CV-PARSE","vectors":[{"id":"P1","op":"parse","tx_hex":"00","expect_ok":false}]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "trace.jsonl")

	if err := run(fixturesDir, outPath); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunReturnsWriteOutError(t *testing.T) {
	fixturesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixturesDir, "CV-PARSE.json"), []byte(`{"gate":"CV-PARSE","vectors":[{"id":"P1","op":"parse","tx_hex":"00","expect_ok":false}]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// outPath points at a directory: os.WriteFile MUST fail.
	outDir := filepath.Join(t.TempDir(), "outdir")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := run(fixturesDir, outDir); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunReturnsParseGateError(t *testing.T) {
	fixturesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixturesDir, "CV-BAD.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := run(fixturesDir, outPath); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunReturnsNoEntriesWritten(t *testing.T) {
	fixturesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(fixturesDir, "CV-X.json"), []byte(`{"gate":"CV-NONCRITICAL","vectors":[]}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "trace.jsonl")
	if err := run(fixturesDir, outPath); err == nil {
		t.Fatalf("expected error")
	}
}

func TestMainExitCodeIs2OnError(t *testing.T) {
	if os.Getenv("FORMAL_TRACE_CHILD") == "1" {
		fixturesDir := filepath.Join(t.TempDir(), "missing")
		outPath := filepath.Join(t.TempDir(), "trace.jsonl")

		prevArgs := os.Args
		prevFS := flag.CommandLine
		t.Cleanup(func() {
			os.Args = prevArgs
			flag.CommandLine = prevFS
		})

		flag.CommandLine = flag.NewFlagSet("formal-trace-child", flag.ContinueOnError)
		os.Args = []string{"formal-trace", "--fixtures-dir", fixturesDir, "--out", outPath}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainExitCodeIs2OnError")
	cmd.Env = append(os.Environ(), "FORMAL_TRACE_CHILD=1")
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-zero exit")
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("unexpected error type: %T: %v", err, err)
	}
	if ee.ExitCode() != 2 {
		t.Fatalf("exit code=%d, want 2", ee.ExitCode())
	}
}
