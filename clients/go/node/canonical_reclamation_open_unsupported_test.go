//go:build !darwin && !linux

package node

import (
	"errors"
	"testing"
)

func TestNoncanonicalRebuildUnsupportedHost(t *testing.T) {
	image, err := (&BlockStore{}).rebuildNoncanonicalAccounting(0)
	if image != nil || !errors.Is(err, errNoncanonicalReconstructionUnsupported) {
		t.Fatalf("image=%v err=%v", image, err)
	}
}
