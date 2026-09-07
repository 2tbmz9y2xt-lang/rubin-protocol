//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
)

// requireReverseRawBytes compares the stored bytes at key with want through the raw update image comparison, because
// Reader.Get keeps its SchemaV1 width checks and cannot observe a value outside them.
func requireReverseRawBytes(t *testing.T, store *Store, dbi DBI, key, want []byte, marker string) {
	t.Helper()
	mustEnvironment(t, store.View(func(reader *Reader) error {
		expected, imageErr := updateOwnedImage(want)
		if imageErr != nil {
			return imageErr
		}
		equal, compareErr := updateNativeEqual(reader.txn, reader.dbis[dbi.Rank], key, expected)
		runtime.KeepAlive(want)
		if compareErr != nil || !equal {
			return fmt.Errorf("%s: %v/%v", marker, equal, compareErr)
		}
		return nil
	}))
}

func TestUpdateReverseRefRawTransport(t *testing.T) {
	dbis := readDBIsLiteral()
	for _, row := range []struct {
		name  string
		value []byte
	}{
		{"present empty", []byte{}},
		{"width valid, schema invalid", append(make([]byte, 19), 0xff)},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, decodeErr := DecodeUTXOValue(row.value); decodeErr == nil {
				t.Fatalf("reverse ref raw literal decodes as a UTXOValue: %s", row.name)
			}
			path, cfg := filepath.Join(t.TempDir(), "db"), environmentConfig()
			store, err := Create(path, cfg)
			mustEnvironment(t, err)
			target, source := reverseKeys(t, 1, 8)
			mustEnvironment(t, fixtureSeedPrefixRawRow(store, dbis[5], source, row.value))
			requireUpdateCommit(t, store, "reverse ref NEW tuple", reverseRefRow(target, source))
			for _, reopened := range []bool{false, true} {
				if reopened {
					mustEnvironment(t, store.Close())
					store, err = Open(path, cfg)
					mustEnvironment(t, err)
				}
				requireReverseRawBytes(t, store, dbis[1], target, row.value, "reverse ref raw transport")
				requireReverseRawBytes(t, store, dbis[5], source, row.value, "reverse ref retained raw source")
			}
			mustEnvironment(t, store.Close())
		})
	}
}
