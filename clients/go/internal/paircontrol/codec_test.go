package paircontrol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// exactShapeError excludes every errors.Is adapter, leaving only sentinel identity.
func exactShapeError(err error) bool {
	switch err.(type) {
	case interface{ Is(error) bool }, interface{ Unwrap() error }, interface{ Unwrap() []error }:
		return false
	}
	return errors.Is(err, errShapeV1)
}

func identity() IdentityV1 {
	return IdentityV1{Identity: policycontrol.Identity{
		InstallationID: [32]byte{0x11}, ChainID: [32]byte{0x22},
		GenesisHash: [32]byte{0x33}, Profile: 1,
	}, DatabaseRoot: "/db"}
}

func originalPair() PairBindingV1 {
	return PairBindingV1{
		Database:          DatabaseLocationV1{Form: 1, Location: "/old", DatabaseID: [32]byte{0x55}},
		CurrentGeneration: 17, LagGeneration: 19, AuthoritySequence: 23,
	}
}

func reference() ReferenceV1 {
	return ReferenceV1{OwnerID: [32]byte{0x66}, Opaque: []byte("source")}
}

func replacement() IntentV1 {
	old, ref := originalPair(), reference()
	return IntentV1{
		ID: [32]byte{0x44}, Origin: 1, Source: 1, LAG: 1,
		Destination: DatabaseLocationV1{Form: 2, Location: "D17", DatabaseID: [32]byte{0x77}},
		Old:         &old, SourceRef: ref, ComparandRef: &ReferenceV1{OwnerID: [32]byte{0x88}, Opaque: []byte("compare")},
	}
}

func selected() RecordV1 {
	p := originalPair()
	return RecordV1{Identity: identity(), Sequence: 17, Selector: 2, Selected: &p}
}

// fixtureBytes is independent test-side serialization of the frozen byte table.
// No production encoder, tag constant, shape helper or expected Result is used.
func fixtureBytes(v RecordV1) []byte {
	b := []byte{0x52, 0x42, 0x4e, 0x4f, 0x55, 0x54, 1, 0}
	b = append(b, v.Identity.InstallationID[:]...)
	b = append(b, v.Identity.ChainID[:]...)
	b = append(b, v.Identity.GenesisHash[:]...)
	b = append(b, byte(v.Identity.Profile))
	b = fieldBytes(b, []byte(v.Identity.DatabaseRoot))
	b = binary.BigEndian.AppendUint64(b, v.Sequence)
	b = append(b, v.Selector)
	if v.Selected != nil {
		b = pairBytes(b, *v.Selected)
	}
	if v.Retired != nil {
		b = pairBytes(b, v.Retired.Old)
		b = append(b, v.Retired.Reason)
		b = refBytes(b, v.Retired.Result)
	}
	if v.Intent == nil {
		return append(b, 0)
	}
	i := v.Intent
	b = append(b, 1)
	b = append(b, i.ID[:]...)
	b = append(b, i.Origin, i.Source, i.LAG)
	b = append(b, leafBytes(i.Destination)...)
	if i.Old == nil {
		b = append(b, 0)
	} else {
		b = pairBytes(append(b, 1), *i.Old)
	}
	b = refBytes(b, i.SourceRef)
	for _, r := range []*ReferenceV1{i.ComparandRef, i.AssuranceRef, i.LAGSourceRef} {
		if r == nil {
			b = append(b, 0)
			continue
		}
		b = refBytes(append(b, 1), *r)
	}
	if i.H1Binding == nil {
		return append(b, 0)
	}
	h := i.H1Binding
	b = binary.BigEndian.AppendUint64(append(b, 1), h.Diagnosis.Height)
	b = append(b, h.Diagnosis.Hash[:]...)
	b = binary.BigEndian.AppendUint64(b, h.OwnerEpoch)
	b = append(b, h.OwnerIntent[:]...)
	b = binary.BigEndian.AppendUint64(b, h.ObservedPSequence)
	for _, f := range [][]byte{h.Diagnosis.Error, h.Diagnosis.Source, h.Diagnosis.Trigger, h.Admission.Old, h.Admission.Destination} {
		b = fieldBytes(b, f)
	}
	b = append(b, byte(h.Admission.Source), byte(h.Admission.Profile))
	return fieldBytes(b, h.Admission.Ownership)
}

func fieldBytes(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

func leafBytes(v DatabaseLocationV1) []byte {
	b := fieldBytes([]byte{v.Form}, []byte(v.Location))
	return append(b, v.DatabaseID[:]...)
}

func pairBytes(b []byte, v PairBindingV1) []byte {
	b = append(b, leafBytes(v.Database)...)
	for _, n := range []uint64{v.CurrentGeneration, v.LagGeneration, v.AuthoritySequence} {
		b = binary.BigEndian.AppendUint64(b, n)
	}
	return b
}

func refBytes(b []byte, v ReferenceV1) []byte {
	return fieldBytes(append(b, v.OwnerID[:]...), v.Opaque)
}

func TestLiteralFixtureAnchor(t *testing.T) {
	// Independently hand-pinned complete first-install image, including every zero.
	const image = "52424e4f555401001100000000000000000000000000000000000000000000000000000000000000220000000000000000000000000000000000000000000000000000000000000033000000000000000000000000000000000000000000000000000000000000000100032f646200000000000000000100"
	want, err := hex.DecodeString(image)
	require(t, err)
	b, err := encodeV1(RecordV1{Identity: identity(), Selector: 1})
	require(t, err)
	if !bytes.Equal(b, want) {
		t.Fatalf("complete literal first-install image: %x", b)
	}
}

func h1Value() IntentV1 {
	i := replacement()
	i.Origin = 3
	owner := binary.BigEndian.AppendUint64(nil, 2)
	owner = append(owner, i.ID[:]...)
	i.H1Binding = &H1BindingV1{
		OwnerEpoch: 2, OwnerIntent: i.ID, ObservedPSequence: 2,
		Diagnosis: policycontrol.Diagnosis{Height: 17, Hash: [32]byte{0x99}, Error: []byte("integrity"), Source: []byte("current"), Trigger: []byte("startup")},
		Admission: policycontrol.Admission{Old: leafBytes(i.Old.Database), Destination: leafBytes(i.Destination), Source: 1, Profile: 1, Ownership: owner},
	}
	return i
}

func operatorValue(origin, source, lag uint8) IntentV1 {
	i := replacement()
	i.Origin, i.Source, i.LAG = origin, source, lag
	if source == 2 {
		r := reference()
		i.AssuranceRef = &r
	}
	if lag == 2 {
		r := reference()
		i.LAGSourceRef = &r
	}
	return i
}

// assertRecord checks both boundaries against the independent grammar, including refusal preservation.
func assertRecord(t *testing.T, v RecordV1, valid bool) {
	t.Helper()
	original := v
	var nested IntentV1
	if v.Intent != nil {
		nested = *v.Intent
	}
	before, err := json.Marshal(v)
	require(t, err)
	want := fixtureBytes(v)
	input := append([]byte(nil), want...)
	got, encErr := encodeV1(v)
	decoded, decErr := decodeV1(input)
	after, err := json.Marshal(v)
	require(t, err)
	if !bytes.Equal(before, after) || !bytes.Equal(input, want) {
		t.Fatal("codec mutated supplied value or input image")
	}
	if v.Selected != original.Selected || v.Retired != original.Retired || v.Intent != original.Intent {
		t.Fatal("codec replaced a supplied outer pointer")
	}
	if v.Intent != nil && (v.Intent.Old != nested.Old || v.Intent.ComparandRef != nested.ComparandRef || v.Intent.AssuranceRef != nested.AssuranceRef || v.Intent.LAGSourceRef != nested.LAGSourceRef || v.Intent.H1Binding != nested.H1Binding) {
		t.Fatal("codec replaced a supplied nested pointer")
	}
	if !valid {
		if !exactShapeError(encErr) || !exactShapeError(decErr) {
			t.Fatalf("exact unwrapped refusal: encode %v decode %v", encErr, decErr)
		}
		return
	}
	require(t, encErr)
	require(t, decErr)
	if !bytes.Equal(got, want) || !reflect.DeepEqual(decoded, v) {
		t.Fatal("independent complete image or decoded value differs")
	}
	clear(input)
	again, err := encodeV1(decoded)
	require(t, err)
	if !bytes.Equal(again, want) {
		t.Fatal("independent image did not re-encode exactly")
	}
}

func refuseImage(t *testing.T, b []byte) {
	t.Helper()
	before := append([]byte(nil), b...)
	if _, err := decodeV1(b); !exactShapeError(err) {
		t.Fatalf("exact malformed-image refusal: %v", err)
	}
	if !bytes.Equal(before, b) {
		t.Fatal("refused image input mutated")
	}
}

func TestCompleteRecordLiteralDomains(t *testing.T) {
	values := []RecordV1{{Identity: identity(), Selector: 1}, selected()}
	for reason := uint8(1); reason <= 3; reason++ {
		values = append(values, RecordV1{Identity: identity(), Selector: 3, Retired: &RetirementV1{originalPair(), reason, reference()}})
	}
	intents := []IntentV1{h1Value()}
	for _, origin := range []uint8{1, 2} {
		for _, mode := range [][2]uint8{{1, 1}, {1, 2}, {2, 3}} {
			intents = append(intents, operatorValue(origin, mode[0], mode[1]))
		}
	}
	for _, i := range intents {
		v := selected()
		v.Intent = &i
		values = append(values, v)
		for reason := uint8(1); reason <= 3; reason++ {
			if reason == 1 && i.Origin != 1 || reason == 2 && i.Origin != 3 {
				continue
			}
			v.Selector, v.Selected = 3, nil
			v.Retired = &RetirementV1{originalPair(), reason, reference()}
			values = append(values, v)
		}
	}
	if len(values) != 23 {
		t.Fatalf("finite record corpus: %d", len(values))
	}
	for n, v := range values {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			assertRecord(t, v, true)
			b := fixtureBytes(v)
			for at := 0; at < len(b); at++ {
				refuseImage(t, b[:at])
			}
			refuseImage(t, append(b, 0))
		})
	}
}

func TestLocationLiteralCorpus(t *testing.T) {
	for _, form := range []uint8{1, 2} {
		for _, n := range []int{0, 1, 17, 255, 256, 767, 768, 769} {
			s := strings.Repeat("x", n)
			if form == 1 && n > 0 {
				s = "/" + s[1:]
			}
			v := DatabaseLocationV1{form, s, [32]byte{17}}
			valid := n > 0 && (form == 1 && n <= 768 || form == 2 && n <= 255)
			checkLeaf(t, v, valid)
		}
	}
	for _, v := range []DatabaseLocationV1{
		{0, "/old", [32]byte{1}},
		{3, "/old", [32]byte{1}},
		{0, "", [32]byte{}},
		{1, "/old", [32]byte{}},
		{1, "old", [32]byte{1}},
		{2, "D17", [32]byte{}},
		{1, "/a/../b", [32]byte{1}},
		{1, "/a//b", [32]byte{1}},
		{1, "/a\x00b", [32]byte{1}},
		{2, ".", [32]byte{1}},
		{2, "..", [32]byte{1}},
		{2, "a/b", [32]byte{1}},
		{2, "a\\b", [32]byte{1}},
		{2, "a\x00b", [32]byte{1}},
	} {
		checkLeaf(t, v, false)
	}
}

func checkLeaf(t *testing.T, v DatabaseLocationV1, valid bool) {
	t.Helper()
	want := leafBytes(v)
	input := append([]byte(nil), want...)
	got, err := EncodeDatabaseLocationV1(v)
	decoded, decErr := DecodeDatabaseLocationV1(input)
	if !bytes.Equal(input, want) {
		t.Fatal("leaf input mutated")
	}
	if !valid {
		if !exactShapeError(err) || !exactShapeError(decErr) {
			t.Fatalf("exact leaf refusal: %v / %v", err, decErr)
		}
		return
	}
	require(t, err)
	require(t, decErr)
	if !bytes.Equal(got, want) || decoded != v {
		t.Fatalf("leaf literal/value differs: %x", got)
	}
	for at := 0; at < len(want); at++ {
		input := append([]byte(nil), want[:at]...)
		if _, err := DecodeDatabaseLocationV1(input); !exactShapeError(err) {
			t.Fatalf("leaf truncation %d accepted", at)
		}
		if !bytes.Equal(input, want[:at]) {
			t.Fatal("truncated leaf input mutated")
		}
	}
	if _, err := DecodeDatabaseLocationV1(append(want, 0)); !exactShapeError(err) {
		t.Fatal("leaf trailing byte accepted")
	}
	input[3] ^= 1
	got[3] ^= 1
	again, err := EncodeDatabaseLocationV1(decoded)
	require(t, err)
	if decoded != v || !bytes.Equal(again, want) {
		t.Fatal("leaf result aliases supplied or returned bytes")
	}
}

func TestH1OwnershipLiteral(t *testing.T) {
	for _, epoch := range []uint64{1, 2, 17, 0x0102030405060708, ^uint64(0)} {
		id := [32]byte{0x44, 17}
		want := binary.BigEndian.AppendUint64(nil, epoch)
		want = append(want, id[:]...)
		got, err := EncodeH1OwnershipV1(epoch, id)
		require(t, err)
		if len(got) != 40 || !bytes.Equal(got, want) {
			t.Fatalf("ownership exact40/endian/order: %x", got)
		}
		got[0] ^= 1
		again, err := EncodeH1OwnershipV1(epoch, id)
		require(t, err)
		if !bytes.Equal(again, want) || id != [32]byte{0x44, 17} {
			t.Fatal("ownership backing retained or input changed")
		}
	}
	for _, v := range []struct {
		epoch uint64
		id    [32]byte
	}{{0, [32]byte{1}}, {1, [32]byte{}}} {
		if _, err := EncodeH1OwnershipV1(v.epoch, v.id); !exactShapeError(err) {
			t.Fatal("zero ownership component accepted")
		}
	}
	if errShapeV1.Error() != "paircontrol: invalid closed value" {
		t.Fatal("shape diagnostic changed")
	}
}

func TestClosedShapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*RecordV1)
	}{
		{"zero_installation", func(v *RecordV1) { v.Identity.InstallationID = [32]byte{} }},
		{"zero_chain", func(v *RecordV1) { v.Identity.ChainID = [32]byte{} }},
		{"zero_genesis", func(v *RecordV1) { v.Identity.GenesisHash = [32]byte{} }},
		{"profile_zero", func(v *RecordV1) { v.Identity.Profile = 0 }},
		{"profile_two", func(v *RecordV1) { v.Identity.Profile = 2 }},
		{"selector_zero", func(v *RecordV1) { v.Selector = 0 }},
		{"selector_four", func(v *RecordV1) { v.Selector = 4 }},
		{"selector_zero_bad_payload", func(v *RecordV1) { v.Selector, v.Selected = 0, nil }},
		{"none_selected", func(v *RecordV1) { v.Selector, v.Intent = 1, nil }},
		{"none_retired", func(v *RecordV1) {
			v.Selector, v.Selected, v.Intent = 1, nil, nil
			v.Retired = &RetirementV1{originalPair(), 3, reference()}
		}},
		{"none_intent", func(v *RecordV1) { v.Selector, v.Selected = 1, nil }},
		{"selected_missing", func(v *RecordV1) { v.Selected = nil }},
		{"selected_retired", func(v *RecordV1) { v.Retired = &RetirementV1{originalPair(), 3, reference()} }},
		{"retired_missing", func(v *RecordV1) { v.Selector, v.Selected = 3, nil }},
		{"retired_selected", func(v *RecordV1) {
			v.Selector = 3
			v.Retired = &RetirementV1{originalPair(), 3, reference()}
		}},
		{"zero_intent", func(v *RecordV1) { v.Intent.ID = [32]byte{} }},
		{"origin_zero", func(v *RecordV1) { v.Intent.Origin = 0 }},
		{"origin_four", func(v *RecordV1) { v.Intent.Origin = 4 }},
		{"origin_zero_bad_payload", func(v *RecordV1) { v.Intent.Origin, v.Intent.Old = 0, nil }},
		{"source_zero", func(v *RecordV1) { v.Intent.Source = 0 }},
		{"source_three", func(v *RecordV1) { v.Intent.Source = 3 }},
		{"source_zero_bad_payload", func(v *RecordV1) { v.Intent.Source, v.Intent.Old = 0, nil }},
		{"lag_zero", func(v *RecordV1) { v.Intent.LAG = 0 }},
		{"lag_four", func(v *RecordV1) { v.Intent.LAG = 4 }},
		{"lag_zero_bad_payload", func(v *RecordV1) { v.Intent.LAG, v.Intent.Old = 0, nil }},
		{"missing_old", func(v *RecordV1) { v.Intent.Old = nil }},
		{"wrong_old", func(v *RecordV1) { v.Intent.Old.AuthoritySequence++ }},
		{"retired_wrong_old", func(v *RecordV1) {
			v.Selector, v.Selected = 3, nil
			v.Retired = &RetirementV1{originalPair(), 3, reference()}
			v.Intent.Old.AuthoritySequence++
		}},
		{"reason_zero_bad_payload", func(v *RecordV1) {
			v.Selector, v.Selected, v.Intent = 3, nil, nil
			v.Retired = &RetirementV1{Old: originalPair()}
		}},
		{"absolute_destination", func(v *RecordV1) { v.Intent.Destination.Form, v.Intent.Destination.Location = 1, "/D17" }},
		{"same_destination_id", func(v *RecordV1) { v.Intent.Destination.DatabaseID = originalPair().Database.DatabaseID }},
		{"missing_comparand", func(v *RecordV1) { v.Intent.ComparandRef = nil }},
		{"operator_h1", func(v *RecordV1) { v.Intent.H1Binding = h1Value().H1Binding }},
		{"rebuild_lagref", func(v *RecordV1) {
			r := reference()
			v.Intent.LAGSourceRef = &r
		}},
		{"reuse_missing_lagref", func(v *RecordV1) { v.Intent.LAG = 2 }},
		{"genesis_assurance", func(v *RecordV1) {
			r := reference()
			v.Intent.AssuranceRef = &r
		}},
		{"genesis_lag3", func(v *RecordV1) { v.Intent.LAG = 3 }},
		{"image_missing_assurance", func(v *RecordV1) { v.Intent.Source, v.Intent.LAG = 2, 3 }},
		{"image_lag1", func(v *RecordV1) {
			r := reference()
			v.Intent.Source, v.Intent.AssuranceRef = 2, &r
		}},
		{"image_lag2", func(v *RecordV1) { *v.Intent = operatorValue(1, 2, 2) }},
		{"image_lagref", func(v *RecordV1) {
			*v.Intent = operatorValue(1, 2, 3)
			r := reference()
			v.Intent.LAGSourceRef = &r
		}},
		{"h1_missing", func(v *RecordV1) { v.Intent.Origin = 3 }},
		{"h1_image", func(v *RecordV1) {
			*v.Intent = h1Value()
			v.Intent.Source = 2
		}},
		{"h1_lag2", func(v *RecordV1) {
			*v.Intent = h1Value()
			v.Intent.LAG = 2
		}},
		{"h1_lag3", func(v *RecordV1) {
			*v.Intent = h1Value()
			v.Intent.LAG = 3
		}},
		{"h1_assurance", func(v *RecordV1) {
			*v.Intent = h1Value()
			r := reference()
			v.Intent.AssuranceRef = &r
		}},
		{"h1_lagref", func(v *RecordV1) {
			*v.Intent = h1Value()
			r := reference()
			v.Intent.LAGSourceRef = &r
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, i := selected(), replacement()
			v.Intent = &i
			test.change(&v)
			assertRecord(t, v, false)
		})
	}
}

func TestPairAndRetirementDomains(t *testing.T) {
	for _, position := range []string{"selected", "retired", "old"} {
		for _, kind := range []string{"id", "current", "lag", "equal", "authority_zero", "maxima"} {
			v, i := selected(), replacement()
			var p *PairBindingV1
			switch position {
			case "selected":
				p = v.Selected
			case "retired":
				v.Selector, v.Selected = 3, nil
				v.Retired = &RetirementV1{originalPair(), 3, reference()}
				p = &v.Retired.Old
			case "old":
				v.Intent = &i
				p = i.Old
			}
			switch kind {
			case "id":
				p.Database.DatabaseID = [32]byte{}
			case "current":
				p.CurrentGeneration = 0
			case "lag":
				p.LagGeneration = 0
			case "equal":
				p.LagGeneration = p.CurrentGeneration
			case "authority_zero":
				p.AuthoritySequence = 0
			case "maxima":
				p.CurrentGeneration, p.LagGeneration, p.AuthoritySequence = ^uint64(0), ^uint64(0)-1, ^uint64(0)
			}
			if position == "old" {
				*v.Selected = *p
			}
			t.Run(position+"/"+kind, func(t *testing.T) { assertRecord(t, v, kind == "authority_zero" || kind == "maxima") })
		}
	}
	for _, reason := range []uint8{0, 1, 2, 3, 4} {
		for _, origin := range []uint8{0, 1, 2, 3} {
			v := RecordV1{Identity: identity(), Selector: 3, Retired: &RetirementV1{originalPair(), reason, reference()}}
			if origin != 0 {
				i := replacement()
				i.Origin = origin
				if origin == 3 {
					i = h1Value()
				}
				v.Intent = &i
			}
			valid := reason >= 1 && reason <= 3 && (origin == 0 || reason == 3 || reason == 1 && origin == 1 || reason == 2 && origin == 3)
			t.Run(fmt.Sprintf("reason%d/origin%d", reason, origin), func(t *testing.T) { assertRecord(t, v, valid) })
		}
	}
}

func variableRecord(position string) (RecordV1, *[]byte) {
	v, i := selected(), h1Value()
	v.Intent = &i
	h := i.H1Binding
	switch position {
	case "source":
		return v, &i.SourceRef.Opaque
	case "comparand":
		return v, &i.ComparandRef.Opaque
	case "assurance":
		i = operatorValue(1, 2, 3)
		return v, &i.AssuranceRef.Opaque
	case "lag_source":
		i = operatorValue(2, 1, 2)
		return v, &i.LAGSourceRef.Opaque
	case "result":
		v.Intent, v.Selected, v.Selector = nil, nil, 3
		v.Retired = &RetirementV1{originalPair(), 3, reference()}
		return v, &v.Retired.Result.Opaque
	case "error":
		return v, &h.Diagnosis.Error
	case "diagnosis_source":
		return v, &h.Diagnosis.Source
	case "trigger":
		return v, &h.Diagnosis.Trigger
	case "admission_old":
		return v, &h.Admission.Old
	case "admission_destination":
		return v, &h.Admission.Destination
	default:
		return v, &h.Admission.Ownership
	}
}

func TestVariableBoundsAndCopies(t *testing.T) {
	for _, position := range []string{"source", "comparand", "assurance", "lag_source", "result", "error", "diagnosis_source", "trigger", "admission_old", "admission_destination", "ownership"} {
		t.Run(position, func(t *testing.T) {
			v, backing := variableRecord(position)
			want := fixtureBytes(v)
			b, err := encodeV1(v)
			require(t, err)
			decoded, err := decodeV1(b)
			require(t, err)
			at := bytes.LastIndex(b, *backing)
			if at < 0 {
				t.Fatal("position absent from independent image")
			}
			(*backing)[0] ^= 1
			if !bytes.Equal(b, want) {
				t.Fatal("encoded bytes alias caller position")
			}
			b[at] ^= 1
			again, err := encodeV1(decoded)
			require(t, err)
			if !bytes.Equal(again, want) {
				t.Fatal("decoded position aliases input")
			}
			other, err := decodeV1(want)
			require(t, err)
			mutatePosition(&decoded, position)
			again, err = encodeV1(other)
			require(t, err)
			if !bytes.Equal(again, want) {
				t.Fatal("decoded position aliases another result")
			}
			for _, n := range []int{0, 1, 17, 1023, 1024, 1025} {
				v, field := variableRecord(position)
				*field = bytes.Repeat([]byte{17}, n)
				valid := n > 0 && n <= 1024
				if strings.HasPrefix(position, "admission") || position == "ownership" {
					valid = false
				}
				assertRecord(t, v, valid)
			}
		})
	}
}

func mutatePosition(v *RecordV1, position string) {
	i := v.Intent
	switch position {
	case "source":
		i.SourceRef.Opaque[0] ^= 1
	case "comparand":
		i.ComparandRef.Opaque[0] ^= 1
	case "assurance":
		i.AssuranceRef.Opaque[0] ^= 1
	case "lag_source":
		i.LAGSourceRef.Opaque[0] ^= 1
	case "result":
		v.Retired.Result.Opaque[0] ^= 1
	case "error":
		i.H1Binding.Diagnosis.Error[0] ^= 1
	case "diagnosis_source":
		i.H1Binding.Diagnosis.Source[0] ^= 1
	case "trigger":
		i.H1Binding.Diagnosis.Trigger[0] ^= 1
	case "admission_old":
		i.H1Binding.Admission.Old[0] ^= 1
	case "admission_destination":
		i.H1Binding.Admission.Destination[0] ^= 1
	case "ownership":
		i.H1Binding.Admission.Ownership[0] ^= 1
	}
}

func TestEveryReferenceOwner(t *testing.T) {
	for _, position := range []string{"source", "comparand", "assurance", "lag_source", "result"} {
		v, _ := variableRecord(position)
		switch position {
		case "source":
			v.Intent.SourceRef.OwnerID = [32]byte{}
		case "comparand":
			v.Intent.ComparandRef.OwnerID = [32]byte{}
		case "assurance":
			v.Intent.AssuranceRef.OwnerID = [32]byte{}
		case "lag_source":
			v.Intent.LAGSourceRef.OwnerID = [32]byte{}
		case "result":
			v.Retired.Result.OwnerID = [32]byte{}
		}
		t.Run(position, func(t *testing.T) { assertRecord(t, v, false) })
	}
}

func TestIdentityRootAndH1Domains(t *testing.T) {
	for _, n := range []int{0, 1, 17, 255, 256, 767, 768, 769} {
		v := selected()
		v.Identity.DatabaseRoot = strings.Repeat("x", n)
		if n > 0 {
			v.Identity.DatabaseRoot = "/" + v.Identity.DatabaseRoot[1:]
		}
		assertRecord(t, v, n > 0 && n <= 768)
	}
	for _, root := range []string{"relative", "/a/../b", "/a//b", "/a\x00b"} {
		v := selected()
		v.Identity.DatabaseRoot = root
		assertRecord(t, v, false)
	}
	for _, test := range []struct {
		name   string
		valid  bool
		change func(*H1BindingV1)
	}{
		{"height_zero", true, func(h *H1BindingV1) { h.Diagnosis.Height = 0 }},
		{"height_max", true, func(h *H1BindingV1) { h.Diagnosis.Height = 4294967295 }},
		{"height_over", false, func(h *H1BindingV1) { h.Diagnosis.Height = 4294967296 }},
		{"hash_zero", true, func(h *H1BindingV1) { h.Diagnosis.Hash = [32]byte{} }},
		{"epoch_zero", false, func(h *H1BindingV1) {
			h.OwnerEpoch = 0
			h.Admission.Ownership[7] = 0
		}},
		{"intent_zero", false, func(h *H1BindingV1) {
			h.OwnerIntent = [32]byte{}
			clear(h.Admission.Ownership[8:])
		}},
		{"ownership_short", false, func(h *H1BindingV1) { h.Admission.Ownership = h.Admission.Ownership[:39] }},
		{"ownership_long", false, func(h *H1BindingV1) { h.Admission.Ownership = append(h.Admission.Ownership, 0) }},
		{"ownership_epoch_mismatch", false, func(h *H1BindingV1) { h.Admission.Ownership[7] ^= 1 }},
		{"ownership_intent_mismatch", false, func(h *H1BindingV1) { h.Admission.Ownership[8] ^= 1 }},
		{"old_mismatch", false, func(h *H1BindingV1) { h.Admission.Old[3] ^= 1 }},
		{"destination_mismatch", false, func(h *H1BindingV1) { h.Admission.Destination[3] ^= 1 }},
		{"source_zero", false, func(h *H1BindingV1) { h.Admission.Source = 0 }},
		{"source_two", false, func(h *H1BindingV1) { h.Admission.Source = 2 }},
		{"profile_zero", false, func(h *H1BindingV1) { h.Admission.Profile = 0 }},
		{"profile_two", false, func(h *H1BindingV1) { h.Admission.Profile = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			v, i := selected(), h1Value()
			v.Intent = &i
			test.change(i.H1Binding)
			assertRecord(t, v, test.valid)
		})
	}
}

func TestWireDiscriminatorsAndPresence(t *testing.T) {
	v, i := selected(), replacement()
	v.Intent = &i
	base := fixtureBytes(v)
	// Frozen fixture offsets: header118, selected pair63, ID32, leaf38, refs40/41.
	for _, at := range []int{118, 182, 215, 216, 217, 218, 256, 360, 402, 403, 404} {
		for _, tag := range []byte{0, 1, 2, 3, 4, 255} {
			b := append([]byte(nil), base...)
			b[at] = tag
			if tag == base[at] {
				continue
			}
			if at == 215 && tag == 2 {
				i.Origin = 2
				assertRecord(t, v, true)
				i.Origin = 1
				continue
			}
			refuseImage(t, b)
		}
	}
	for at := 0; at < 8; at++ {
		b := append([]byte(nil), base...)
		b[at] ^= 1
		refuseImage(t, b)
	}
	refuseImage(t, make([]byte, 16385))
	if _, err := DecodeDatabaseLocationV1(make([]byte, 804)); !exactShapeError(err) {
		t.Fatal("oversized leaf accepted")
	}
}

func TestCanonicalLeafPositions(t *testing.T) {
	for _, position := range []string{"selected", "retired", "old", "destination"} {
		for _, n := range []int{0, 1, 17, 255, 256, 767, 768, 769} {
			v, i := selected(), replacement()
			var leaf *DatabaseLocationV1
			switch position {
			case "selected":
				leaf = &v.Selected.Database
			case "retired":
				v.Selector, v.Selected = 3, nil
				v.Retired = &RetirementV1{originalPair(), 3, reference()}
				leaf = &v.Retired.Old.Database
			case "old":
				v.Intent = &i
				leaf = &i.Old.Database
			case "destination":
				v.Intent = &i
				leaf = &i.Destination
			}
			leaf.Location = strings.Repeat("x", n)
			if leaf.Form == 1 && n > 0 {
				leaf.Location = "/" + leaf.Location[1:]
			}
			leaf.DatabaseID = [32]byte{0x98, 17}
			if position == "old" {
				*v.Selected = *i.Old
			}
			valid := n > 0 && (position == "destination" && n <= 255 || position != "destination" && n <= 768)
			t.Run(fmt.Sprintf("%s/%d", position, n), func(t *testing.T) { assertRecord(t, v, valid) })
		}
	}
	for _, position := range []string{"selected", "retired", "old"} {
		v, i := selected(), replacement()
		leaf := DatabaseLocationV1{Form: 2, Location: "root-relative-D17", DatabaseID: [32]byte{0x98, 17}}
		switch position {
		case "selected":
			v.Selected.Database = leaf
		case "retired":
			v.Selector, v.Selected = 3, nil
			v.Retired = &RetirementV1{originalPair(), 3, reference()}
			v.Retired.Old.Database = leaf
		case "old":
			v.Intent = &i
			i.Old.Database = leaf
			*v.Selected = *i.Old
		}
		t.Run(position+"/form2", func(t *testing.T) { assertRecord(t, v, true) })
	}
	for _, n := range []int{1, 17, 255, 256, 767, 768} {
		v, i := selected(), h1Value()
		v.Intent = &i
		i.Old.Database.Location = "/" + strings.Repeat("x", n-1)
		*v.Selected = *i.Old
		i.H1Binding.Admission.Old = leafBytes(i.Old.Database)
		i.Destination.Location = strings.Repeat("d", 255)
		i.H1Binding.Admission.Destination = leafBytes(i.Destination)
		assertRecord(t, v, true)
	}
}

func TestNestedPointersAndLegalIdentity(t *testing.T) {
	t.Run("distinct_numeric_fields", func(t *testing.T) {
		v, i := selected(), h1Value()
		v.Intent = &i
		v.Sequence = 41
		i.H1Binding.Diagnosis.Height = 29
		i.H1Binding.OwnerEpoch, i.H1Binding.ObservedPSequence = 31, 37
		binary.BigEndian.PutUint64(i.H1Binding.Admission.Ownership, 31)
		assertRecord(t, v, true)
	})
	v, i := selected(), h1Value()
	v.Intent = &i
	v.Identity.InstallationID, v.Identity.ChainID, v.Identity.GenesisHash = [32]byte{7}, [32]byte{8}, [32]byte{9}
	v.Sequence, i.H1Binding.ObservedPSequence = ^uint64(0), ^uint64(0)
	i.H1Binding.OwnerEpoch = ^uint64(0)
	binary.BigEndian.PutUint64(i.H1Binding.Admission.Ownership, ^uint64(0))
	assertRecord(t, v, true)
	want := fixtureBytes(v)
	a, err := decodeV1(want)
	require(t, err)
	b, err := decodeV1(want)
	require(t, err)
	a.Selected.AuthoritySequence++
	a.Intent.Old.AuthoritySequence++
	a.Intent.Destination.DatabaseID[0] ^= 1
	a.Intent.H1Binding.OwnerIntent[0] ^= 1
	again, err := encodeV1(b)
	require(t, err)
	if !bytes.Equal(again, want) {
		t.Fatal("nested decoded pointers alias another result")
	}
}

func TestDecodeTotalBoundBeforeAllocation(t *testing.T) {
	v, i := selected(), h1Value()
	v.Intent = &i
	b := fixtureBytes(v)
	b = append(b, make([]byte, 16385-len(b))...)
	before := append([]byte(nil), b...)
	allocations := testing.AllocsPerRun(1, func() {
		if _, err := decodeV1(b); !exactShapeError(err) {
			t.Fatal("oversized complete-prefix image accepted")
		}
	})
	if allocations != 0 {
		t.Fatalf("oversized input allocated before total bound: %g", allocations)
	}
	if !bytes.Equal(b, before) {
		t.Fatal("oversized image input mutated")
	}
}

func TestAdmissionFieldBoundsBeforeAllocation(t *testing.T) {
	for _, position := range []string{"admission_old", "admission_destination", "ownership"} {
		zero, field := variableRecord(position)
		*field = nil
		short := fixtureBytes(zero)
		over, field := variableRecord(position)
		n := 804
		if position == "ownership" {
			n = 41
		}
		*field = bytes.Repeat([]byte{17}, n)
		long := fixtureBytes(over)
		measure := func(b []byte) float64 {
			return testing.AllocsPerRun(1, func() {
				if _, err := decodeV1(b); !exactShapeError(err) {
					t.Fatal("invalid bounded field accepted")
				}
			})
		}
		if a, b := measure(short), measure(long); a != b {
			t.Fatalf("%s overbound payload allocated: zero %g overbound %g", position, a, b)
		}
	}
}

func TestSourcePayloadMatrix(t *testing.T) {
	for _, origin := range []uint8{1, 2, 3} {
		for _, source := range []uint8{1, 2} {
			for _, lag := range []uint8{1, 2, 3} {
				for _, assurance := range []bool{false, true} {
					for _, lagref := range []bool{false, true} {
						v, i := selected(), replacement()
						if origin == 3 {
							i = h1Value()
						}
						i.Origin, i.Source, i.LAG = origin, source, lag
						if assurance {
							r := reference()
							i.AssuranceRef = &r
						}
						if lagref {
							r := reference()
							i.LAGSourceRef = &r
						}
						v.Intent = &i
						valid := source == 1 && !assurance && (lag == 1 && !lagref || lag == 2 && lagref) || source == 2 && lag == 3 && assurance && !lagref
						if origin == 3 {
							valid = source == 1 && lag == 1 && !assurance && !lagref
						}
						t.Run(fmt.Sprintf("%d/%d/%d/%t/%t", origin, source, lag, assurance, lagref), func(t *testing.T) { assertRecord(t, v, valid) })
					}
				}
			}
		}
	}
}

func TestSharedInputBackingDetachesEachPosition(t *testing.T) {
	v, i := selected(), h1Value()
	v.Intent = &i
	shared := []byte("shared")
	i.SourceRef.Opaque, i.ComparandRef.Opaque = shared, shared
	h := i.H1Binding
	h.Diagnosis.Error, h.Diagnosis.Source, h.Diagnosis.Trigger = shared, shared, shared
	want := fixtureBytes(v)
	decoded, err := decodeV1(want)
	require(t, err)
	decoded.Intent.SourceRef.Opaque[0] ^= 1
	decoded.Intent.H1Binding.Diagnosis.Error[0] ^= 1
	if !bytes.Equal(decoded.Intent.ComparandRef.Opaque, shared) || !bytes.Equal(decoded.Intent.H1Binding.Diagnosis.Source, shared) || !bytes.Equal(decoded.Intent.H1Binding.Diagnosis.Trigger, shared) {
		t.Fatal("decoded sibling variable positions share backing")
	}
	if !bytes.Equal(want, fixtureBytes(v)) {
		t.Fatal("decoded position aliases original image or caller")
	}
}
