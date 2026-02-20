package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"rubin.dev/node/crypto"
)

// Q-127: key lifecycle tooling (non-consensus).
//
// This implements a dev keystore format backed by AES-256-KW:
// - strict mode: requires wolfcrypt shim keywrap symbols
// - non-strict mode: allows software AES-KW fallback for dev/test environments

type keyWrapProvider interface {
	HasKeyManagement() bool
	KeyWrap(kek, keyIn []byte) ([]byte, error)
	KeyUnwrap(kek, wrapped []byte) ([]byte, error)
}

type KeyStoreV1 struct {
	Version      string `json:"version"` // "RBKSv1"
	SuiteID      uint8  `json:"suite_id"`
	PubkeyHex    string `json:"pubkey_hex"`
	KeyIDHex     string `json:"key_id_hex"`
	WrapAlg      string `json:"wrap_alg"` // "AES-256-KW"
	WrappedSKHex string `json:"wrapped_sk_hex"`
}

func wolfcryptStrict() bool {
	v := os.Getenv("RUBIN_WOLFCRYPT_STRICT")
	return v == "1" || strings.EqualFold(v, "true")
}

func mustLen(b []byte, n int, name string) error {
	if len(b) != n {
		return fmt.Errorf("%s must be %d bytes (got %d)", name, n, len(b))
	}
	return nil
}

func loadKeyWrapper(strict bool) (keyWrapProvider, func(), error) {
	// In strict mode: require shim keywrap symbols.
	// In non-strict mode: allow software AES-KW fallback for dev/test.
	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return nil, func() {}, err
	}
	if km, ok := p.(keyWrapProvider); ok && km.HasKeyManagement() {
		return km, cleanup, nil
	}
	cleanup()
	if strict {
		return nil, func() {}, fmt.Errorf("keymgr requires wolfcrypt shim keywrap symbols in strict mode")
	}
	return nil, func() {}, nil
}

func keywrap(strict bool, kek, keyIn []byte, km keyWrapProvider) ([]byte, error) {
	if km != nil {
		return km.KeyWrap(kek, keyIn)
	}
	return crypto.AESKeyWrapRFC3394(kek, keyIn)
}

func keyunwrap(strict bool, kek, wrapped []byte, km keyWrapProvider) ([]byte, error) {
	if km != nil {
		return km.KeyUnwrap(kek, wrapped)
	}
	if strict {
		return nil, fmt.Errorf("keyunwrap requires shim in strict mode")
	}
	return crypto.AESKeyUnwrapRFC3394(kek, wrapped)
}

func cmdKeymgrExportWrapped(argv []string) error {
	fs := flag.NewFlagSet("keymgr export-wrapped", flag.ExitOnError)
	out := fs.String("out", "", "output keystore json path")
	suiteID := fs.Uint("suite-id", 0, "suite_id (0x01 ML-DSA-87; 0x02 SLH-DSA reserved)")
	pubkeyHex := fs.String("pubkey-hex", "", "pubkey bytes (hex)")
	skHex := fs.String("sk-hex", "", "secret key bytes (hex) to wrap (dev only; do not use for FIPS claims)")
	kekHex := fs.String("kek-hex", "", "AES-256 KEK (32 bytes hex)")
	_ = fs.Parse(argv)
	if *out == "" || *pubkeyHex == "" || *skHex == "" || *kekHex == "" {
		return fmt.Errorf("missing required flags: --out --pubkey-hex --sk-hex --kek-hex")
	}

	strict := wolfcryptStrict()
	km, cleanup, err := loadKeyWrapper(strict)
	if err != nil {
		return err
	}
	defer cleanup()

	pub, err := hexDecodeStrict(*pubkeyHex)
	if err != nil {
		return fmt.Errorf("pubkey-hex: %w", err)
	}
	kek, err := hexDecodeStrict(*kekHex)
	if err != nil {
		return fmt.Errorf("kek-hex: %w", err)
	}
	if err := mustLen(kek, 32, "kek"); err != nil {
		return err
	}
	sk, err := hexDecodeStrict(*skHex)
	if err != nil {
		return fmt.Errorf("sk-hex: %w", err)
	}
	if len(sk) == 0 || len(sk)%8 != 0 {
		return fmt.Errorf("sk must be non-zero multiple of 8 bytes (AES-KW requirement)")
	}

	// key_id = SHA3-256(pubkey)
	p, pc, err := loadCryptoProvider()
	if err != nil {
		return err
	}
	defer pc()
	keyID, err := p.SHA3_256(pub)
	if err != nil {
		return err
	}

	wrapped, err := keywrap(strict, kek, sk, km)
	if err != nil {
		return err
	}

	ks := KeyStoreV1{
		Version:      "RBKSv1",
		SuiteID:      uint8(*suiteID),
		PubkeyHex:    hex.EncodeToString(pub),
		KeyIDHex:     hex.EncodeToString(keyID[:]),
		WrapAlg:      "AES-256-KW",
		WrappedSKHex: hex.EncodeToString(wrapped),
	}
	b, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(*out, b, 0o600)
}

func readKeystore(path string) (*KeyStoreV1, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-provided
	if err != nil {
		return nil, err
	}
	var ks KeyStoreV1
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, err
	}
	if ks.Version != "RBKSv1" {
		return nil, fmt.Errorf("unsupported keystore version: %q", ks.Version)
	}
	if strings.ToUpper(ks.WrapAlg) != "AES-256-KW" {
		return nil, fmt.Errorf("unsupported wrap_alg: %q", ks.WrapAlg)
	}
	return &ks, nil
}

func cmdKeymgrImportWrapped(argv []string) error {
	fs := flag.NewFlagSet("keymgr import-wrapped", flag.ExitOnError)
	in := fs.String("in", "", "input keystore json path")
	out := fs.String("out", "", "output keystore json path")
	oldKekHex := fs.String("old-kek-hex", "", "old AES-256 KEK (32 bytes hex)")
	newKekHex := fs.String("new-kek-hex", "", "new AES-256 KEK (32 bytes hex)")
	_ = fs.Parse(argv)
	if *in == "" || *out == "" || *oldKekHex == "" || *newKekHex == "" {
		return fmt.Errorf("missing required flags: --in --out --old-kek-hex --new-kek-hex")
	}

	strict := wolfcryptStrict()
	km, cleanup, err := loadKeyWrapper(strict)
	if err != nil {
		return err
	}
	defer cleanup()

	ks, err := readKeystore(*in)
	if err != nil {
		return err
	}

	oldKek, err := hexDecodeStrict(*oldKekHex)
	if err != nil {
		return fmt.Errorf("old-kek-hex: %w", err)
	}
	if err := mustLen(oldKek, 32, "old-kek"); err != nil {
		return err
	}
	newKek, err := hexDecodeStrict(*newKekHex)
	if err != nil {
		return fmt.Errorf("new-kek-hex: %w", err)
	}
	if err := mustLen(newKek, 32, "new-kek"); err != nil {
		return err
	}
	wrapped, err := hexDecodeStrict(ks.WrappedSKHex)
	if err != nil {
		return fmt.Errorf("wrapped_sk_hex: %w", err)
	}

	plain, err := keyunwrap(strict, oldKek, wrapped, km)
	if err != nil {
		return err
	}
	newWrapped, err := keywrap(strict, newKek, plain, km)
	if err != nil {
		return err
	}
	ks.WrappedSKHex = hex.EncodeToString(newWrapped)

	b, err := json.Marshal(ks)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(*out, b, 0o600)
}

func cmdKeymgrVerifyPubkey(argv []string) (string, error) {
	fs := flag.NewFlagSet("keymgr verify-pubkey", flag.ExitOnError)
	in := fs.String("in", "", "input keystore json path")
	expectedKeyIDHex := fs.String("expected-key-id-hex", "", "optional expected key_id hex")
	_ = fs.Parse(argv)
	if *in == "" {
		return "", fmt.Errorf("missing required flag: --in")
	}

	ks, err := readKeystore(*in)
	if err != nil {
		return "", err
	}
	pub, err := hexDecodeStrict(ks.PubkeyHex)
	if err != nil {
		return "", fmt.Errorf("pubkey_hex: %w", err)
	}

	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		return "", err
	}
	defer cleanup()
	keyID, err := p.SHA3_256(pub)
	if err != nil {
		return "", err
	}
	gotHex := hex.EncodeToString(keyID[:])
	if ks.KeyIDHex != "" && !strings.EqualFold(ks.KeyIDHex, gotHex) {
		return "", fmt.Errorf("keystore key_id mismatch: embedded=%s computed=%s", ks.KeyIDHex, gotHex)
	}
	if *expectedKeyIDHex != "" {
		exp := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(*expectedKeyIDHex), "0x"))
		if exp != gotHex {
			return "", fmt.Errorf("expected key_id mismatch: expected=%s computed=%s", exp, gotHex)
		}
	}
	return gotHex, nil
}

func cmdKeymgrMain(argv []string) int {
	if len(argv) < 1 {
		fmt.Fprintln(os.Stderr, "usage: rubin-node keymgr <subcommand> [flags]")
		return 2
	}
	sub := argv[0]
	subargv := argv[1:]

	switch sub {
	case "export-wrapped":
		if err := cmdKeymgrExportWrapped(subargv); err != nil {
			fmt.Fprintln(os.Stderr, "keymgr export-wrapped error:", err)
			return 1
		}
		fmt.Println("OK")
		return 0
	case "import-wrapped":
		if err := cmdKeymgrImportWrapped(subargv); err != nil {
			fmt.Fprintln(os.Stderr, "keymgr import-wrapped error:", err)
			return 1
		}
		fmt.Println("OK")
		return 0
	case "verify-pubkey":
		out, err := cmdKeymgrVerifyPubkey(subargv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keymgr verify-pubkey error:", err)
			return 1
		}
		fmt.Println(out)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown keymgr subcommand")
		return 2
	}
}
