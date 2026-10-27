package consensus

import (
	"bytes"
	"math"
	"reflect"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestRetainedChargeV1(t *testing.T) {
	t.Run("PureLimits", func(t *testing.T) {
		for _, pair := range [][2]uint64{{0, 0}, {805306367, 1}, {805306368, 805306367}, {1073741824, 9}, {math.MaxUint64, 0}, {0, math.MaxUint64}} {
			value := NewLimitsV1(pair[0], pair[1])
			copy := value
			value = LimitsV1{}
			if copy.R() != pair[0] || copy.LRet() != pair[1] || value.R() != 0 || value.LRet() != 0 {
				t.Fatalf("configuration copy: %+v -> %+v", pair, copy)
			}
		}
		value := DefaultLimitsV1()
		if value.R() != 805306368 || value.LRet() != 18446744073709551615 {
			t.Fatalf("default limits: %+v", value)
		}
		kind := reflect.TypeOf(value)
		for i := range kind.NumField() {
			if kind.Field(i).IsExported() || kind.Field(i).Type.Kind() != reflect.Uint64 {
				t.Fatal("configuration is not an immutable scalar value")
			}
		}
	})
	t.Run("D1-D6-tariffs", retainedChargeLiterals)
	t.Run("D6-codec-forwarding", func(t *testing.T) {
		for _, raw := range [][]byte{nil, make([]byte, 19), make([]byte, 65561), append(make([]byte, 19), 2), append(make([]byte, 10), 253, 0)} {
			before := bytes.Clone(raw)
			_, want := mdbx.DecodeUTXOValue(raw)
			got, err := RetainedStateEntryChargeV1(raw)
			if got != 0 || want == nil || any(err) != any(want) || !bytes.Equal(raw, before) {
				t.Fatalf("sole decoder cause/input: %d/%v/%v", got, err, want)
			}
		}
	})
}

func retainedChargeLiterals(t *testing.T) {
	t.Helper()
	for _, row := range []struct{ count, charge uint64 }{{0, 32}, {1, 100}, {2, 270}, {108510259257115009, 18446744073709551460}} {
		got, err := RetainedTreeChargeV1(row.count)
		if err != nil || got != row.charge {
			t.Fatalf("complete tree N=%d: %d/%v want%d", row.count, got, err, row.charge)
		}
	}
	for _, count := range []uint64{108510259257115010, math.MaxUint64} {
		if got, err := RetainedTreeChargeV1(count); got != 0 || err == nil {
			t.Fatalf("tree overflow N=%d: %d/%v", count, got, err)
		}
	}
	for _, row := range []struct {
		kind   mdbx.TreeNodeKindV1
		charge uint64
	}{{0, 0}, {1, 68}, {2, 102}, {3, 0}, {255, 0}} {
		got, err := RetainedNodeChargeV1(row.kind)
		if got != row.charge || (err != nil) != (row.charge == 0) {
			t.Fatalf("node kind%d: %d/%v", row.kind, got, err)
		}
	}
	for _, row := range []struct {
		bytes           int
		native, logical uint64
	}{{0, 20, 56}, {1, 21, 57}, {33, 53, 89}, {65536, 65560, 65596}} {
		raw, err := (mdbx.UTXOValue{CovenantData: make([]byte, row.bytes)}).Encode()
		if err != nil || uint64(len(raw)) != row.native {
			t.Fatalf("native suffix width: %d/%v", len(raw), err)
		}
		before := bytes.Clone(raw)
		got, err := RetainedStateEntryChargeV1(raw)
		if err != nil || got != row.logical || !bytes.Equal(raw, before) {
			t.Fatalf("logical suffix width: %d/%v want%d", got, err, row.logical)
		}
	}
	if RetainedHeaderChargeV1 != 148 || RetainedIndexChargeV1 != 112 || RetainedRootChargeV1 != 32 {
		t.Fatal("hash-global/index/root tariffs differ")
	}
	// D1 is solely an explicit arithmetic-domain fixture; these short bodies are not stored images.
	state, _ := RetainedStateEntryChargeV1(make([]byte, 20))
	tree, _ := RetainedTreeChargeV1(1)
	empty, _ := RetainedTreeChargeV1(0)
	if got := state + tree + empty + 2*RetainedIndexChargeV1 + 2*RetainedHeaderChargeV1 + 120 + 121 + 56; got != 1005 {
		t.Fatalf("D1 arithmetic pre: %d want1005", got)
	}
}
