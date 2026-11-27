package treebody

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"
	"unsafe"
)

func fixtureBlock(width int, count byte, parent [32]byte) []byte {
	raw := make([]byte, width+1)
	raw[0], raw[width-1] = 1, 0x6d
	copy(raw[4:36], parent[:])
	raw[width] = count
	return raw
}

func fixtureInput(core []byte, prev [32]byte) []byte {
	core = append(core, prev[:]...)
	return append(core, 9, 0, 0, 0, 1, 0x7f, 0xff, 0xff, 0xff, 0xff)
}

func fixtureFrame(value byte, kind uint16) []byte {
	frame := binary.LittleEndian.AppendUint64(nil, uint64(value))
	return append(binary.LittleEndian.AppendUint16(frame, kind), 2, 0x6b, value)
}

func fixtureTail(kind byte) []byte {
	tail := []byte{0, 0, 0, 0}
	switch kind {
	case 1:
		tail = append(tail, make([]byte, 32)...)
		tail = append(tail, 1, 0)
		tail = append(tail, make([]byte, 137)...)
		return append(tail, 1, 0x6a)
	case 2:
		tail = append(tail, make([]byte, 32)...)
		tail = append(tail, 0, 0)
		return append(tail, make([]byte, 32)...)
	}
	return tail
}

type outputSpan struct{ start, end int }

func fixtureCore(kind byte, prev [32]byte) ([]byte, outputSpan) {
	core := append([]byte{1, 0, 0, 0, kind}, make([]byte, 8)...)
	if kind == 1 {
		core = fixtureInput(append(core, 2), [32]byte{31: 0x25})
	} else {
		core = append(core, 1)
	}
	core = append(fixtureInput(core, prev), 3)
	start := len(core)
	core = append(core, fixtureFrame(7, 0x0002)...)
	core = append(core, fixtureFrame(8, 0x0103)...)
	core = append(core, fixtureFrame(9, 0)...)
	end := len(core)
	return append(core, fixtureTail(kind)...), outputSpan{start, end}
}

func fixtureTransaction(kind byte, prev [32]byte) ([]byte, [32]byte, outputSpan) {
	core, span := fixtureCore(kind, prev)
	id := sha3.Sum256(core)
	tx := append(core, 1, 0x7f, 1, 0x2a, 2, 0xcb, 0x40)
	if kind == 0 {
		return append(tx, 0), id, span
	}
	return append(tx, 1, 0x4a), id, span
}

func fixtureTranscript() ([]byte, Census, []Event, []outputSpan) {
	parent := [32]byte{4, 5, 31: 6}
	raw := fixtureBlock(148, 3, parent)
	var want []Event
	var outputs []outputSpan
	for kind := uint8(0); kind < 3; kind++ {
		prev := [32]byte{31: 7 + kind}
		tx, id, outputsInTx := fixtureTransaction(kind, prev)
		start := len(raw) + outputsInTx.start
		outputs = append(outputs, outputSpan{start, len(raw) + outputsInTx.end})
		if kind == 1 {
			want = append(want, Event{Kind: 1, Outpoint: Outpoint{Txid: [32]byte{31: 0x25}, Vout: 9}, TxIndex: 1})
			want = append(want, Event{Kind: 1, Outpoint: Outpoint{Txid: prev, Vout: 9}, TxIndex: 1, InputIndex: 1})
		}
		if kind == 2 {
			want = append(want, Event{Kind: 1, Outpoint: Outpoint{Txid: prev, Vout: 9}, TxIndex: 2})
		}
		const frameSize = 13
		want = append(want, Event{Kind: 2, Outpoint: Outpoint{Txid: id, Vout: 2}, TxIndex: uint32(kind), FrameOffset: uint64(start + 2*frameSize), FrameLength: frameSize})
		raw = append(raw, tx...)
	}
	return raw, Census{Parent: parent, TxCount: 3, EventCount: 6}, want, outputs
}

func TestScan(t *testing.T) {
	raw, wantCensus, wantEvents, outputs := fixtureTranscript()
	for _, stored := range []bool{false, true} {
		for _, emit := range []bool{false, true} {
			t.Run(fmt.Sprintf("stored=%t/emit=%t", stored, emit), func(t *testing.T) {
				checkTranscript(t, raw, wantCensus, wantEvents, outputs, stored, emit)
			})
		}
	}
}

func checkTranscript(t *testing.T, raw []byte, wantCensus Census, wantEvents []Event, outputs []outputSpan, stored, emit bool) {
	t.Helper()
	var gotEvents []Event
	var callback func(Event) error
	if emit {
		callback = func(e Event) error {
			gotEvents = append(gotEvents, e)
			return nil
		}
	}
	reads := make([]uint8, len(raw))
	source := Source{Raw: raw}
	if stored {
		source = recordedSource(t, raw, reads)
	}
	got, err := Scan(source, 148, 4, callback)
	if err != nil || got != wantCensus {
		t.Fatalf("scan census = %+v/%v, want %+v", got, err, wantCensus)
	}
	if emit && !slices.Equal(gotEvents, wantEvents) {
		t.Fatalf("events = %+v, want %+v", gotEvents, wantEvents)
	}
	if stored {
		checkReads(t, reads, outputs, emit)
	}
}

func recordedSource(t *testing.T, raw []byte, reads []uint8) Source {
	t.Helper()
	window := make([]byte, 64)
	return Source{Length: uint64(len(raw)), Window: window, ReadAt: func(dst []byte, off uint64) (int, error) {
		if len(dst) == 0 || len(dst) > len(window) || &dst[0] != &window[0] ||
			off > uint64(len(raw)) || uint64(len(dst)) > uint64(len(raw))-off {
			t.Fatalf("row read %d+%d with window %d and row %d", off, len(dst), len(window), len(raw))
		}
		end := off + uint64(len(dst))
		for i := off; i < end; i++ {
			reads[i]++
		}
		return copy(dst, raw[off:end]), nil
	}}
}

func checkReads(t *testing.T, reads []uint8, outputs []outputSpan, emit bool) {
	t.Helper()
	want := make([]uint8, len(reads))
	for i := range want {
		want[i] = 1
	}
	if emit {
		for _, span := range outputs {
			for i := span.start; i < span.end; i++ {
				want[i] = 2
			}
		}
	}
	if !slices.Equal(reads, want) {
		t.Fatalf("row byte reads = %v, want %v", reads, want)
	}
}

func TestScanFailures(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		raw, _, _, spans := fixtureTranscript()
		raw = raw[:len(raw)-1]
		want := fmt.Errorf("selected row: %w", errors.New("read failed"))
		firstOutput := uint64(spans[0].start)
		visits := 0
		source := Source{Window: make([]byte, 64), Length: uint64(len(raw)), ReadAt: func(dst []byte, off uint64) (int, error) {
			n := copy(dst, raw[off:off+uint64(len(dst))])
			if off == firstOutput {
				visits++
				if visits == 2 {
					return n, want
				}
			}
			return n, nil
		}}
		census, err := Scan(source, 148, 4, func(Event) error { return nil })
		if any(err) != any(want) || census.Malformed {
			t.Fatalf("first row error on %d output reads = %v (framing=%t), want original %v", visits, err, census.Malformed, want)
		}
	})
	t.Run("emit_before_bad_witness", func(t *testing.T) {
		first, _, _ := fixtureTransaction(0, [32]byte{})
		raw := append(fixtureBlock(116, 2, [32]byte{}), first...)
		prev := [32]byte{31: 8}
		second, _ := fixtureCore(0, prev)
		raw = append(raw, second...)
		raw = append(raw, 253)
		want := fmt.Errorf("spend callback: %w", errors.New("emit failed"))
		var gotSpend Event
		census, err := Scan(Source{Raw: raw}, 116, 1, func(e Event) error {
			if e.Kind == 1 {
				gotSpend = e
				return want
			}
			return nil
		})
		if any(err) != any(want) || census.Malformed {
			t.Fatalf("first emit error = %v (framing=%t), want original %v", err, census.Malformed, want)
		}
		if expected := (Event{Kind: 1, Outpoint: Outpoint{Txid: prev, Vout: 9}, TxIndex: 1}); gotSpend != expected {
			t.Fatalf("emitted spend = %+v, want %+v", gotSpend, expected)
		}
	})
}

func TestScanFraming(t *testing.T) {
	raw := fixtureBlock(116, 1, [32]byte{1})
	tx, _, _ := fixtureTransaction(0, [32]byte{})
	raw = append(raw, tx...)
	if census, err := Scan(Source{Raw: raw}, 116, 0, nil); err != nil || census != (Census{Parent: [32]byte{1}, TxCount: 1, EventCount: 1}) {
		t.Fatalf("height-zero census = %+v/%v", census, err)
	}
	wrongKind := slices.Clone(raw)
	wrongKind[121] = 3
	for _, bad := range [][]byte{raw[:len(raw)-1], append(slices.Clone(raw), 0), raw[:116], wrongKind} {
		if census, err := Scan(Source{Raw: bad}, 116, 0, nil); err != nil || !census.Malformed {
			t.Fatalf("invalid %x: census = %+v/%v", bad, census, err)
		}
	}
}

func TestCompactSize(t *testing.T) {
	for _, tc := range []struct {
		n   uint64
		raw []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{252, []byte{252}},
		{253, []byte{253, 253, 0}},
		{65535, []byte{253, 255, 255}},
		{65536, []byte{254, 0, 0, 1, 0}},
		{math.MaxUint32, []byte{254, 255, 255, 255, 255}},
		{4294967296, []byte{255, 0, 0, 0, 0, 1, 0, 0, 0}},
		{math.MaxUint64, []byte{255, 255, 255, 255, 255, 255, 255, 255, 255}},
	} {
		c := cursor{raw: tc.raw, length: uint64(len(tc.raw))}
		if got := c.compactV1(math.MaxUint64); got != tc.n || c.err != nil || c.off != uint64(len(tc.raw)) {
			t.Fatalf("CompactSize %x = %d/%d/%v, want %d", tc.raw, got, c.off, c.err, tc.n)
		}
	}
	for _, raw := range [][]byte{{}, {253}, {253, 252, 0}, {254, 255, 255, 0, 0}, {255, 255, 255, 255, 255, 0, 0, 0, 0}, {255, 0}, {254, 0, 0, 1}} {
		c := cursor{raw: raw, length: uint64(len(raw))}
		c.compactV1(math.MaxUint64)
		checkFraming(t, c.err)
	}
	c := cursor{raw: []byte{2}, length: 1}
	c.compactV1(1)
	checkFraming(t, c.err)
	for _, offset := range []uint64{1, math.MaxUint64} {
		c := cursor{raw: []byte{0}, length: 1, off: offset}
		c.skipV1(math.MaxUint64)
		checkFraming(t, c.err)
	}
}

func checkFraming(t *testing.T, err error) {
	t.Helper()
	if any(err) != any(errFraming) {
		t.Fatalf("framing error = %v", err)
	}
}

func TestLayout(t *testing.T) {
	fixed := 2*unsafe.Sizeof(cursor{}) + 2*unsafe.Sizeof(sha3.SHA3{})
	if fixed > 1024 {
		t.Fatalf("fixed cursor layout = %d > 1024", fixed)
	}
}
