package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeymgrVerifyPubkey(t *testing.T) {
	td := t.TempDir()
	ksPath := filepath.Join(td, "k.json")

	// Minimal keystore, no wrapped key needed for verify-pubkey.
	if err := os.WriteFile(ksPath, []byte(`{
  "version": "RBKSv1",
  "suite_id": 1,
  "pubkey_hex": "11",
  "key_id_hex": "",
  "wrap_alg": "AES-256-KW",
  "wrapped_sk_hex": "00"
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// verify-pubkey should compute key_id and not crash even if wrapped_sk_hex is junk.
	out, err := cmdKeymgrVerifyPubkey([]string{"--in", ksPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 64 {
		t.Fatalf("expected 32-byte key_id hex, got %q", out)
	}
}
