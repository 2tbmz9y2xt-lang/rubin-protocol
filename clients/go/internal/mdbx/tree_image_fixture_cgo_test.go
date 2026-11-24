//go:build rubin_mdbx_fixture && cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"testing"
)

func TestTreeImageLifecycleV1(t *testing.T) {
	// OpenTreeV1 checks the meta 03 identity before it reads meta key 0x02.
	t.Run("OpenTreeV1 refuses meta 03 identity mismatch before one-byte key 0x02 decode", func(t *testing.T) {
		store, path, identity := treeNativeStore(t)
		treeNativeSeed(t, store, 0, []byte{2}, []byte{0})
		treeNativeSeed(t, store, 0, []byte{3}, bytes.Repeat([]byte{8}, 32))
		mustEnvironment(t, store.Close())
		for range 2 {
			got, err := OpenTreeV1(path, environmentConfig(), identity)
			if got != nil {
				t.Fatal("tree open published a Store")
			}
			treeNativeIntegrity(t, err, operationOpen, nil)
		}
	})
}
