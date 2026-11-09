package policycontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// builder writes an image field by field, independently of encode.
type builder struct{ bytes.Buffer }

func (b *builder) u8(v uint8) *builder   { b.WriteByte(v); return b }
func (b *builder) u16(v uint16) *builder { _ = binary.Write(b, binary.BigEndian, v); return b }
func (b *builder) u64(v uint64) *builder { _ = binary.Write(b, binary.BigEndian, v); return b }
func (b *builder) raw(v []byte) *builder { b.Write(v); return b }
func (b *builder) v16(v string) *builder { return b.u16(uint16(len(v))).raw([]byte(v)) }

func fill32(v byte) (out [32]byte) {
	for i := range out {
		out[i] = v
	}
	return
}

func independentOpID(id Identity, successor uint64) [32]byte {
	var pre []byte
	pre = append(pre, "rubin/policycontrol/operation/v1"...)
	pre = append(pre, id.InstallationID[:]...)
	pre = append(pre, id.ChainID[:]...)
	pre = append(pre, id.GenesisHash[:]...)
	pre = append(pre, byte(id.Profile))
	pre = binary.BigEndian.AppendUint64(pre, successor)
	return sha256.Sum256(pre)
}

func codecIdentity() Identity {
	return Identity{InstallationID: fill32(0xA1), ChainID: fill32(0xB2), GenesisHash: fill32(0xC3), Profile: ProfileV1}
}

func header(b *builder, id Identity, seq uint64) *builder {
	return b.raw([]byte("RBNPCTL\x01")).raw(id.InstallationID[:]).raw(id.ChainID[:]).raw(id.GenesisHash[:]).u8(1).u64(seq)
}

// richImage is a hand-built image at sequence 41: H1 batch receipt with cursors 0..128, latched control with an INTENT incident and two rows.
func richImage() ([]byte, *state) {
	id := codecIdentity()
	op := independentOpID(id, 41)
	b := header(&builder{}, id, 41)
	b.u8(1).u64(40).u64(41).raw(op[:]).u8(3).u64(10).v16("intent_10").u8(6).u64(7).u8(1).u64(0).u64(128)
	b.u64(41).u8(1).u8(1)
	b.u8(1).u64(4294967295).raw(bytes.Repeat([]byte{0xEE}, 32)).v16("err").v16("src").v16("trig").u8(1).u8(2)
	b.u8(1).v16("old").v16("dst").u8(1).u8(1).v16("own")
	b.u64(2)
	b.u8(1).v16("k1").u64(41).v16("p1")
	b.u8(3).v16("").u64(7).v16("")
	st := &state{
		id: id, seq: 41,
		receipt: &Receipt{Predecessor: 40, Successor: 41, Operation: op, Owner: Owner{Kind: OwnerH1, Epoch: 10, Intent: []byte("intent_10")}, Class: ClassReconciliationBatch, Ordinal: 7, Cursors: &Cursors{Before: 0, After: 128}},
		ctl: control{sequence: 41, initialSync: true, hasAttempt: true, incident: &Incident{
			Diagnosis: Diagnosis{Height: 4294967295, Hash: fill32(0xEE), Error: []byte("err"), Source: []byte("src"), Trigger: []byte("trig")},
			Attempted: true, State: StateIntent,
			Admission: &Admission{Old: []byte("old"), Destination: []byte("dst"), Source: SourceGenesisReplay, Profile: ProfileV1, Ownership: []byte("own")},
		}},
		rows: map[string]Row{
			"\x01k1": {Kind: KindOriginalRejection, Key: []byte("k1"), Sequence: 41, Payload: []byte("p1")},
			"\x03":   {Kind: KindContext, Sequence: 7},
		},
	}
	return b.Bytes(), st
}

func initialImage() ([]byte, *state) {
	id := codecIdentity()
	b := header(&builder{}, id, 0).u8(0).u64(0).u8(0).u8(0).u8(0).u64(0)
	return b.Bytes(), &state{id: id, rows: map[string]Row{}}
}

// H3: independently derived valid images decode exactly and re-encode exactly.
func TestDecodeIndependentImagesExactly(t *testing.T) {
	for name, mk := range map[string]func() ([]byte, *state){"initial": initialImage, "rich": richImage} {
		img, want := mk()
		got, err := decode(img)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: decoded %+v, want %+v", name, got, want)
		}
		if enc := encode(want); !bytes.Equal(enc, img) {
			t.Fatalf("%s: encode differs from the independent image", name)
		}
	}
}

func mustIntegrity(t *testing.T, name string, img []byte) {
	t.Helper()
	if st, err := decode(img); st != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("%s: decode state=%v err=%v, want ErrIntegrity", name, st != nil, err)
	}
}

// H3: truncation, trailing bytes and noncanonical structure refuse.
func TestDecodeRejectsStructuralCorpus(t *testing.T) {
	img, _ := richImage()
	for n := 0; n < len(img); n++ {
		mustIntegrity(t, "truncated", img[:n])
	}
	mustIntegrity(t, "trailing", append(bytes.Clone(img), 0))
	rowsAt := len(img) - (1 + 2 + 2 + 8 + 2 + 2) - (1 + 2 + 8 + 2) - 8
	if binary.BigEndian.Uint64(img[rowsAt:]) != 2 {
		t.Fatal("row offset helper drifted")
	}
	row1 := img[rowsAt+8 : rowsAt+8+17]
	row2 := img[rowsAt+8+17:]
	head := bytes.Clone(img[:rowsAt])
	rows := func(count uint64, parts ...[]byte) []byte {
		out := binary.BigEndian.AppendUint64(bytes.Clone(head), count)
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	if _, err := decode(rows(2, row1, row2)); err != nil {
		t.Fatalf("reassembled image: %v", err)
	}
	mustIntegrity(t, "unordered rows", rows(2, row2, row1))
	mustIntegrity(t, "duplicate key", rows(2, row1, row1))
	mustIntegrity(t, "count above rows", rows(3, row1, row2))
	mustIntegrity(t, "count below rows", rows(1, row1, row2))
	mustIntegrity(t, "count over ceiling", rows(maxRows+1, row1, row2))
	if _, err := decode(rows(maxRows+1, make([]byte, (maxRows+1)*minRowBytes))); err == nil || !strings.Contains(err.Error(), "row count") {
		t.Fatalf("count over ceiling with enough bytes not refused by the count ceiling: %v", err)
	}
	overKey := append([]byte{1, 0, MaxKeyBytes + 1}, make([]byte, MaxKeyBytes+1+8+2)...)
	mustIntegrity(t, "over-ceiling key", rows(1, overKey))
	// The coder ceiling refuses before allocation, not later validation.
	if _, err := decode(rows(1, overKey)); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("over-ceiling key not refused by the coder ceiling: %v", err)
	}
	overPayload := binary.BigEndian.AppendUint16([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, MaxPayloadBytes+1)
	mustIntegrity(t, "over-ceiling payload", rows(1, append(overPayload, make([]byte, MaxPayloadBytes+1)...)))
	const receiptAt, receiptLen = 8 + 96 + 1 + 8, 1 + 8 + 8 + 32 + 1 + 8 + 11 + 1 + 8 + 1 + 16
	flags := map[string]int{"receipt tag": receiptAt, "cursor tag": receiptAt + receiptLen - 17, "initial sync": receiptAt + receiptLen + 8}
	for name, off := range flags {
		if img[off] != 1 {
			t.Fatalf("%s offset drifted: %d", name, img[off])
		}
		bad := bytes.Clone(img)
		bad[off] = 2
		mustIntegrity(t, name+" = 2", bad)
	}
	mustIntegrity(t, "bad magic", append([]byte("RBNPCTL\x02"), img[8:]...))
}

// H3: every field domain is checked after a structurally valid parse.
func TestDecodeRejectsDomainCorpus(t *testing.T) {
	cases := map[string]func(st *state){
		"zero installation":          func(st *state) { st.id.InstallationID = [32]byte{} },
		"unknown profile":            func(st *state) { st.id.Profile = 2 },
		"unknown owner kind":         func(st *state) { st.receipt.Owner.Kind = 7 },
		"owner kind zero":            func(st *state) { st.receipt.Owner.Kind = 0 },
		"unknown class":              func(st *state) { st.receipt.Class = 8 },
		"operation identity of n":    func(st *state) { st.receipt.Operation = independentOpID(st.id, 40) },
		"wrong predecessor":          func(st *state) { st.receipt.Predecessor = 39 },
		"wrong successor":            func(st *state) { st.receipt.Successor = 42 },
		"batch without cursors":      func(st *state) { st.receipt.Cursors = nil },
		"cursors without batch":      func(st *state) { st.receipt.Class = ClassControl },
		"compound nonzero ordinal":   func(st *state) { st.receipt.Class = ClassCompoundControl },
		"owned epoch zero":           func(st *state) { st.receipt.Owner.Epoch = 0 },
		"owned epoch above n+1":      func(st *state) { st.receipt.Owner.Epoch = 42 },
		"owned empty intent":         func(st *state) { st.receipt.Owner.Intent = nil },
		"ownerless epoch not n+1":    func(st *state) { st.receipt.Owner = Owner{Kind: OwnerlessControl, Epoch: 0} },
		"ownerless with intent":      func(st *state) { st.receipt.Owner = Owner{Kind: OwnerlessControl, Epoch: 41, Intent: []byte("x")} },
		"missing receipt":            func(st *state) { st.receipt = nil },
		"control seq above P":        func(st *state) { st.ctl.sequence = 42 },
		"control seq zero changed":   func(st *state) { st.ctl.sequence = 0 },
		"height above u32max":        func(st *state) { st.ctl.incident.Diagnosis.Height = MaxIncidentHeight + 1 },
		"empty error provenance":     func(st *state) { st.ctl.incident.Diagnosis.Error = nil },
		"unknown incident state":     func(st *state) { st.ctl.incident.State = 4 },
		"INTENT without admission":   func(st *state) { st.ctl.incident.Admission = nil },
		"INTENT not attempted":       func(st *state) { st.ctl.incident.Attempted = false },
		"INTENT without has_attempt": func(st *state) { st.ctl.hasAttempt = false },
		"attempted OBSERVED without has_attempt": func(st *state) {
			st.ctl.incident = &Incident{Diagnosis: st.ctl.incident.Diagnosis, Attempted: true, State: StateObserved}
			st.ctl.hasAttempt = false
		},
		"OBSERVED with destination": func(st *state) { st.ctl.incident.State = StateObserved },
		"destination equals OLD":    func(st *state) { st.ctl.incident.Admission.Destination = []byte("old") },
		"non GENESIS_REPLAY source": func(st *state) { st.ctl.incident.Admission.Source = 2 },
		"admission profile":         func(st *state) { st.ctl.incident.Admission.Profile = 2 },
		"empty ownership":           func(st *state) { st.ctl.incident.Admission.Ownership = nil },
		"unknown row kind":          func(st *state) { st.rows["\x09"] = Row{Kind: 9, Sequence: 1} },
		"row seq above P":           func(st *state) { st.rows["\x05r"] = Row{Kind: KindReservation, Key: []byte("r"), Sequence: 42} },
		"row seq zero":              func(st *state) { st.rows["\x05r"] = Row{Kind: KindReservation, Key: []byte("r")} },
		"second working row": func(st *state) {
			st.rows["\x08a"] = Row{Kind: KindWorkingReservation, Key: []byte("a"), Sequence: 1}
			st.rows["\x08b"] = Row{Kind: KindWorkingReservation, Key: []byte("b"), Sequence: 1}
		},
	}
	for name, mutate := range cases {
		_, st := richImage()
		mutate(st)
		mustIntegrity(t, name, encode(st))
	}
	for name, mutate := range map[string]func(st *state){
		"seq 0 with receipt":   func(st *state) { _, r := richImage(); st.receipt = r.receipt },
		"seq 0 latched":        func(st *state) { st.ctl.initialSync = true },
		"seq 0 with rows":      func(st *state) { st.rows["\x05"] = Row{Kind: KindReservation, Sequence: 1} },
		"seq 0 control seq":    func(st *state) { st.ctl.sequence = 1 },
		"seq 0 with incident":  func(st *state) { _, r := richImage(); st.ctl.incident = r.ctl.incident },
		"seq 0 with attempted": func(st *state) { st.ctl.hasAttempt = true },
	} {
		_, st := initialImage()
		mutate(st)
		mustIntegrity(t, name, encode(st))
	}
}

// H3: a single-byte mutation either refuses or decodes to another exact legal value whose canonical encoding is the mutated image; a mutated identity byte is then caught by the expected-binding check.
func TestDecodeSingleByteMutationCorpus(t *testing.T) {
	img, want := richImage()
	for i := range img {
		for _, x := range []byte{0x01, 0x80, 0xFF} {
			bad := bytes.Clone(img)
			bad[i] ^= x
			st, err := decode(bad)
			if err != nil {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("byte %d^%#x: %v", i, x, err)
				}
				continue
			}
			if reflect.DeepEqual(st, want) || !bytes.Equal(encode(st), bad) || validateState(st) != nil {
				t.Fatalf("byte %d^%#x decoded to a non-distinct or non-canonical value", i, x)
			}
			if i >= 8 && i < 8+96 && st.id == want.id {
				t.Fatalf("byte %d^%#x changed identity bytes without changing identity", i, x)
			}
		}
	}
}

// The encoder refuses an over-ceiling field before any narrowing, independently of callers' validation.
func TestEncodeRefusesOverCeilingField(t *testing.T) {
	for name, mutate := range map[string]func(st *state){
		"intent": func(st *state) { st.receipt.Owner.Intent = make([]byte, MaxIntentBytes+1) },
		"field":  func(st *state) { st.ctl.incident.Diagnosis.Error = make([]byte, 1<<16) },
		"payload": func(st *state) {
			st.rows["\x01k1"] = Row{Kind: KindOriginalRejection, Key: []byte("k1"), Sequence: 41, Payload: make([]byte, MaxPayloadBytes+1)}
		},
	} {
		_, st := richImage()
		mutate(st)
		if img := encode(st); img != nil {
			t.Fatalf("%s: encode did not refuse an over-ceiling field", name)
		}
	}
}

// cross refuses an unencodable state before any file-system effect.
func TestCrossRefusesUnencodableState(t *testing.T) {
	dir, s := seedStore(t, ownerlessState(testIdentity(1), 40))
	before := fileBytes(t, dir)
	_, st := richImage()
	st.receipt.Owner.Intent = make([]byte, MaxIntentBytes+1)
	if c := s.cross(st); c.committed || c.image != nil || !errors.Is(c.err, ErrRefused) || !bytes.Equal(fileBytes(t, dir), before) {
		t.Fatalf("crossing %+v", c)
	}
}
