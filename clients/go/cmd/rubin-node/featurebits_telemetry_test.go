package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type fakeHeaderStore struct {
	bit          uint8
	windowCounts map[uint64]uint32
}

func (f *fakeHeaderStore) CanonicalHash(height uint64) ([32]byte, bool, error) {
	var h [32]byte
	binary.LittleEndian.PutUint64(h[:8], height)
	return h, true, nil
}

func (f *fakeHeaderStore) GetHeaderByHash(hash [32]byte) ([]byte, error) {
	height := binary.LittleEndian.Uint64(hash[:8])
	windowIndex := height / consensus.SIGNAL_WINDOW
	pos := height % consensus.SIGNAL_WINDOW

	var version uint32
	if uint32(pos) < f.windowCounts[windowIndex] {
		version = 1 << f.bit
	}

	headerBytes := make([]byte, consensus.BLOCK_HEADER_BYTES)
	binary.LittleEndian.PutUint32(headerBytes[:4], version)
	return headerBytes, nil
}

type missingAtHeightStore struct {
	missHeight uint64
}

func (m *missingAtHeightStore) CanonicalHash(height uint64) ([32]byte, bool, error) {
	var h [32]byte
	if height == m.missHeight {
		return h, false, nil
	}
	binary.LittleEndian.PutUint64(h[:8], height)
	return h, true, nil
}

func (m *missingAtHeightStore) GetHeaderByHash(_ [32]byte) ([]byte, error) {
	headerBytes := make([]byte, consensus.BLOCK_HEADER_BYTES)
	binary.LittleEndian.PutUint32(headerBytes[:4], 0)
	return headerBytes, nil
}

func TestCountSignalsInWindow(t *testing.T) {
	t.Run("counts_signals_for_bit", func(t *testing.T) {
		bs := &fakeHeaderStore{
			bit: 0,
			windowCounts: map[uint64]uint32{
				0: 3,
			},
		}
		got, err := countSignalsInWindow(bs, 0, 0)
		if err != nil {
			t.Fatalf("countSignalsInWindow: %v", err)
		}
		if got != 3 {
			t.Fatalf("expected 3, got %d", got)
		}
	})

	t.Run("missing_canonical_hash_errors", func(t *testing.T) {
		bs := &missingAtHeightStore{missHeight: 0}
		_, err := countSignalsInWindow(bs, 0, 0)
		if err == nil || !strings.Contains(err.Error(), "missing canonical hash") {
			t.Fatalf("expected missing canonical hash error, got: %v", err)
		}
	})
}

func TestPrintFeatureBitsTelemetry(t *testing.T) {
	dir := t.TempDir()
	deploymentsPath := filepath.Join(dir, "deployments.json")
	raw, err := json.Marshal([]featureBitDeploymentJSON{
		{
			Name:          "X",
			Bit:           0,
			StartHeight:   0,
			TimeoutHeight: consensus.SIGNAL_WINDOW * 10,
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(deploymentsPath, raw, 0o600); err != nil {
		t.Fatalf("write deployments: %v", err)
	}

	bs := &fakeHeaderStore{
		bit: 0,
		windowCounts: map[uint64]uint32{
			0: consensus.SIGNAL_THRESHOLD,
		},
	}

	var out bytes.Buffer
	if err := printFeatureBitsTelemetry(&out, bs, consensus.SIGNAL_WINDOW, deploymentsPath); err != nil {
		t.Fatalf("printFeatureBitsTelemetry: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "featurebits: name=X") ||
		!strings.Contains(s, "state=LOCKED_IN") ||
		!strings.Contains(s, "prev_window_signal_count=1815") {
		t.Fatalf("unexpected output: %q", s)
	}
}

