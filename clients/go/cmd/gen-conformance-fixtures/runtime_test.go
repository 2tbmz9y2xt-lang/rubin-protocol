package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenConformanceFixturesGenerator_WritesToTempRepo(t *testing.T) {
	tmp := t.TempDir()
	repoRoot := tmp

	// Minimal directory layout expected by repoRootFromGoModule().
	clientsGoDir := filepath.Join(repoRoot, "clients/go")
	fixturesDir := filepath.Join(repoRoot, "conformance/fixtures")
	if err := os.MkdirAll(fixturesDir, 0o755); err != nil {
		t.Fatalf("mkdir fixtures: %v", err)
	}
	if err := os.MkdirAll(clientsGoDir, 0o755); err != nil {
		t.Fatalf("mkdir clients/go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(clientsGoDir, "go.mod"), []byte("module temp\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	mkTxid := func(fill byte) string {
		b := make([]byte, 32)
		for i := range b {
			b[i] = fill
		}
		return hex.EncodeToString(b)
	}
	newVector := func(id string, utxoCount int, extra map[string]any) map[string]any {
		utxos := make([]any, 0, utxoCount)
		for i := 0; i < utxoCount; i++ {
			utxos = append(utxos, map[string]any{
				"txid":          mkTxid(byte(len(id) + i + 1)),
				"vout":          float64(i),
				"value":         float64(0),
				"covenant_type": float64(0),
				"covenant_data": "",
			})
		}
		v := map[string]any{
			"id":     id,
			"utxos":  utxos,
			"tx_hex": "",
		}
		for k, val := range extra {
			v[k] = val
		}
		return v
	}

	writeFixture := func(name string, vectors []map[string]any) {
		t.Helper()
		path := filepath.Join(fixturesDir, name)
		f := fixtureFile{Gate: name[:len(name)-len(".json")], Vectors: vectors}
		raw, err := json.MarshalIndent(&f, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	writeFixture("CV-UTXO-BASIC.json", []map[string]any{
		newVector("CV-U-05", 1, nil),
		newVector("CV-U-06", 1, nil),
		newVector("CV-U-16", 1, nil),
		newVector("CV-U-09", 1, nil),
		newVector("CV-U-10", 2, nil),
		newVector("CV-U-11", 2, nil),
		newVector("CV-U-12", 2, nil),
		newVector("CV-U-13", 2, nil),
	})

	writeFixture("CV-VAULT.json", []map[string]any{
		newVector("VAULT-CREATE-01", 1, nil),
		newVector("VAULT-CREATE-02", 1, nil),
		newVector("VAULT-SPEND-02", 3, nil),
		newVector("VAULT-SPEND-04", 2, nil),
	})

	writeFixture("CV-HTLC.json", []map[string]any{
		newVector("CV-HTLC-13", 1, nil),
	})

	writeFixture("CV-SUBSIDY.json", []map[string]any{
		newVector("CV-SUB-01", 1, map[string]any{"expected_prev_hash": mkTxid(0x00)}),
		newVector("CV-SUB-02", 1, map[string]any{"expected_prev_hash": mkTxid(0x00)}),
	})

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(clientsGoDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	// Cover main.go (calls runGeneratorCLI).
	main()

	// Sanity: generator should have written tx_hex / block_hex fields into our temp fixtures.
	mustContainField := func(file string, field string) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(fixturesDir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", file, err)
		}
		vectors, ok := got["vectors"].([]any)
		if !ok || len(vectors) == 0 {
			t.Fatalf("%s: missing vectors", file)
		}
		seenNonEmpty := false
		for _, item := range vectors {
			m, _ := item.(map[string]any)
			if s, _ := m[field].(string); s != "" {
				seenNonEmpty = true
				break
			}
		}
		if !seenNonEmpty {
			t.Fatalf("%s: expected at least one non-empty %s", file, field)
		}
	}

	mustContainField("CV-UTXO-BASIC.json", "tx_hex")
	mustContainField("CV-VAULT.json", "tx_hex")
	mustContainField("CV-HTLC.json", "tx_hex")
	mustContainField("CV-SUBSIDY.json", "block_hex")
}
