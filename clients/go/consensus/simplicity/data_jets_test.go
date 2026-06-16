package simplicity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestU64DataJets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		got      U64JetResult
		want     uint64
		accepted bool
	}{
		{"add", EvaluateU64CheckedAddJet(2, 3), 5, true},
		{"add-overflow", EvaluateU64CheckedAddJet(^uint64(0), 1), 0, false},
		{"sub", EvaluateU64CheckedSubJet(5, 3), 2, true},
		{"sub-underflow", EvaluateU64CheckedSubJet(3, 5), 0, false},
		{"mul", EvaluateU64CheckedMulJet(7, 6), 42, true},
		{"mul-overflow", EvaluateU64CheckedMulJet(1<<63, 2), 0, false},
	} {
		if tc.got.Accepted != tc.accepted || tc.got.Value != tc.want || tc.got.Cost != 1 {
			t.Fatalf("%s = %+v, want accepted=%v value=%d cost=1", tc.name, tc.got, tc.accepted, tc.want)
		}
	}

	assertOrdering(t, "u64-lt", EvaluateU64CmpJet(1, 2), OrderingLT, 1)
	assertOrdering(t, "u64-eq", EvaluateU64CmpJet(2, 2), OrderingEQ, 1)
	assertOrdering(t, "u64-gt", EvaluateU64CmpJet(3, 2), OrderingGT, 1)
}

func TestU128DataJets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		got      U128JetResult
		want     Uint128
		accepted bool
	}{
		{"add-carry", EvaluateU128CheckedAddJet(Uint128{Lo: ^uint64(0)}, Uint128{Lo: 1}), Uint128{Hi: 1}, true},
		{"add-overflow", EvaluateU128CheckedAddJet(Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}, Uint128{Lo: 1}), Uint128{}, false},
		{"sub-borrow", EvaluateU128CheckedSubJet(Uint128{Hi: 1}, Uint128{Lo: 1}), Uint128{Lo: ^uint64(0)}, true},
		{"sub-underflow", EvaluateU128CheckedSubJet(Uint128{}, Uint128{Lo: 1}), Uint128{}, false},
	} {
		if tc.got.Accepted != tc.accepted || tc.got.Value != tc.want || tc.got.Cost != 1 {
			t.Fatalf("%s = %+v, want accepted=%v value=%+v cost=1", tc.name, tc.got, tc.accepted, tc.want)
		}
	}

	assertOrdering(t, "u128-hi-lt", EvaluateU128CmpJet(Uint128{Hi: 1}, Uint128{Hi: 2}), OrderingLT, 1)
	assertOrdering(t, "u128-eq", EvaluateU128CmpJet(Uint128{Hi: 2, Lo: 3}, Uint128{Hi: 2, Lo: 3}), OrderingEQ, 1)
	assertOrdering(t, "u128-lo-gt", EvaluateU128CmpJet(Uint128{Hi: 2, Lo: 4}, Uint128{Hi: 2, Lo: 3}), OrderingGT, 1)
}

func TestBytesDataJets(t *testing.T) {
	if got := EvaluateBytesEqJet(nil, []byte{}); !got.Value || got.Cost != 1 {
		t.Fatalf("bytes_eq empty = %+v, want true cost=1", got)
	}
	if got := EvaluateBytesEqJet(bytes.Repeat([]byte{0x11}, 33), bytes.Repeat([]byte{0x11}, 32)); got.Value || got.Cost != 3 {
		t.Fatalf("bytes_eq 33/32 = %+v, want false cost=3", got)
	}

	assertOrdering(t, "bytes-unsigned", EvaluateBytesCmpJet([]byte{0xff}, []byte{0x01}), OrderingGT, 2)
	assertOrdering(t, "bytes-prefix-shorter", EvaluateBytesCmpJet([]byte("ab"), []byte("abc")), OrderingLT, 2)
	assertOrdering(t, "bytes-prefix-longer", EvaluateBytesCmpJet([]byte("abc"), []byte("ab")), OrderingGT, 2)
	assertOrdering(t, "bytes-eq", EvaluateBytesCmpJet([]byte("abc"), []byte("abc")), OrderingEQ, 2)

	src := []byte("abcdef")
	if got := EvaluateBytesSliceJet(src, 2, 3); !got.Accepted || string(got.Bytes) != "cde" || got.Cost != 2 {
		t.Fatalf("bytes_slice = %+v, want accepted cde cost=2", got)
	} else {
		src[2] = 'X'
		if string(got.Bytes) != "cde" {
			t.Fatalf("bytes_slice returned aliased bytes %q", got.Bytes)
		}
	}
	if got := EvaluateBytesSliceJet(src, uint64(len(src)), 0); !got.Accepted || len(got.Bytes) != 0 || got.Cost != 1 {
		t.Fatalf("bytes_slice empty = %+v, want accepted empty cost=1", got)
	}
	if got := EvaluateBytesSliceJet(src, 5, 2); got.Accepted || got.Cost != 2 {
		t.Fatalf("bytes_slice out of range = %+v, want rejected cost=2", got)
	}
	if got := EvaluateBytesSliceJet(src, ^uint64(0), 1); got.Accepted || got.Cost != 2 {
		t.Fatalf("bytes_slice overflow = %+v, want rejected cost=2", got)
	}
	maxLength := ^uint64(0)
	expectedMaxCost := dataJetFlatCost + maxLength/bytesJetChunkLen
	if maxLength%bytesJetChunkLen != 0 {
		expectedMaxCost++
	}
	if got := EvaluateBytesSliceJet(nil, 0, maxLength); got.Accepted || got.Cost != expectedMaxCost {
		t.Fatalf("bytes_slice max len = %+v, want rejected cost=%d", got, expectedMaxCost)
	}
}

type sharedDataJetCorpus struct {
	ContractVersion int                 `json:"contract_version"`
	FixtureKind     string              `json:"fixture_kind"`
	Description     string              `json:"description"`
	Cases           []sharedDataJetCase `json:"cases"`
}

type sharedDataJetCase struct {
	ID               string  `json:"id"`
	Jet              string  `json:"jet"`
	AU64             *uint64 `json:"a_u64"`
	BU64             *uint64 `json:"b_u64"`
	AU128Hi          *uint64 `json:"a_u128_hi"`
	AU128Lo          *uint64 `json:"a_u128_lo"`
	BU128Hi          *uint64 `json:"b_u128_hi"`
	BU128Lo          *uint64 `json:"b_u128_lo"`
	BytesAHex        *string `json:"bytes_a_hex"`
	BytesBHex        *string `json:"bytes_b_hex"`
	SourceHex        *string `json:"source_hex"`
	Start            *uint64 `json:"start"`
	Length           *uint64 `json:"length"`
	ExpectedAccepted *bool   `json:"expected_accepted"`
	ExpectedU64      *uint64 `json:"expected_u64"`
	ExpectedU128Hi   *uint64 `json:"expected_u128_hi"`
	ExpectedU128Lo   *uint64 `json:"expected_u128_lo"`
	ExpectedOrdering *int8   `json:"expected_ordering"`
	ExpectedBool     *bool   `json:"expected_bool"`
	ExpectedBytesHex *string `json:"expected_bytes_hex"`
	ExpectedCost     *uint64 `json:"expected_cost"`
}

func TestSharedDataJetsCorpus(t *testing.T) {
	var corpus sharedDataJetCorpus
	raw, err := os.ReadFile(repoPath(t, "conformance", "fixtures", "protocol", "simplicity_data_jets_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared data jets corpus: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared data jets corpus: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("shared data jets corpus has trailing data: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_data_jets_corpus_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared data jets corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			if err := tc.validateOutcomeFields(); err != nil {
				t.Fatal(err)
			}
			switch tc.Jet {
			case "u64_checked_add":
				assertU64Jet(t, tc.ID, EvaluateU64CheckedAddJet(*tc.AU64, *tc.BU64), tc)
			case "u64_checked_sub":
				assertU64Jet(t, tc.ID, EvaluateU64CheckedSubJet(*tc.AU64, *tc.BU64), tc)
			case "u64_checked_mul":
				assertU64Jet(t, tc.ID, EvaluateU64CheckedMulJet(*tc.AU64, *tc.BU64), tc)
			case "u64_cmp":
				assertOrdering(t, tc.ID, EvaluateU64CmpJet(*tc.AU64, *tc.BU64), Ordering(*tc.ExpectedOrdering), *tc.ExpectedCost)
			case "u128_checked_add":
				a128 := Uint128{Hi: *tc.AU128Hi, Lo: *tc.AU128Lo}
				b128 := Uint128{Hi: *tc.BU128Hi, Lo: *tc.BU128Lo}
				assertU128Jet(t, tc.ID, EvaluateU128CheckedAddJet(a128, b128), tc)
			case "u128_checked_sub":
				a128 := Uint128{Hi: *tc.AU128Hi, Lo: *tc.AU128Lo}
				b128 := Uint128{Hi: *tc.BU128Hi, Lo: *tc.BU128Lo}
				assertU128Jet(t, tc.ID, EvaluateU128CheckedSubJet(a128, b128), tc)
			case "u128_cmp":
				a128 := Uint128{Hi: *tc.AU128Hi, Lo: *tc.AU128Lo}
				b128 := Uint128{Hi: *tc.BU128Hi, Lo: *tc.BU128Lo}
				assertOrdering(t, tc.ID, EvaluateU128CmpJet(a128, b128), Ordering(*tc.ExpectedOrdering), *tc.ExpectedCost)
			case "bytes_eq":
				got := EvaluateBytesEqJet(hx(*tc.BytesAHex), hx(*tc.BytesBHex))
				if got.Value != *tc.ExpectedBool || got.Cost != *tc.ExpectedCost {
					t.Fatalf("%s = %+v, want value=%v cost=%d", tc.ID, got, *tc.ExpectedBool, *tc.ExpectedCost)
				}
			case "bytes_cmp":
				assertOrdering(t, tc.ID, EvaluateBytesCmpJet(hx(*tc.BytesAHex), hx(*tc.BytesBHex)), Ordering(*tc.ExpectedOrdering), *tc.ExpectedCost)
			case "bytes_slice":
				got := EvaluateBytesSliceJet(hx(*tc.SourceHex), *tc.Start, *tc.Length)
				if got.Accepted != *tc.ExpectedAccepted || !bytes.Equal(got.Bytes, hx(*tc.ExpectedBytesHex)) || got.Cost != *tc.ExpectedCost {
					t.Fatalf("%s = %+v, want accepted=%v bytes=%s cost=%d", tc.ID, got, *tc.ExpectedAccepted, *tc.ExpectedBytesHex, *tc.ExpectedCost)
				}
			default:
				t.Fatalf("unknown data jet %q", tc.Jet)
			}
		})
	}
}

func TestSharedDataJetsCorpusRequiresOutcomeFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"missing u64 accepted", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-ACCEPTED","jet":"u64_checked_add","a_u64":0,"b_u64":0,"expected_u64":0,"expected_cost":1}]}`, "missing expected_accepted"},
		{"missing u64 input", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-A-U64","jet":"u64_checked_add","b_u64":3,"expected_accepted":true,"expected_u64":3,"expected_cost":1}]}`, "missing a_u64"},
		{"missing u64 value", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-U64","jet":"u64_checked_add","a_u64":0,"b_u64":0,"expected_accepted":false,"expected_cost":1}]}`, "missing expected_u64"},
		{"missing ordering", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-ORDERING","jet":"bytes_cmp","bytes_a_hex":"","bytes_b_hex":"","expected_cost":2}]}`, "missing expected_ordering"},
		{"invalid ordering", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-BAD-ORDERING","jet":"u64_cmp","a_u64":0,"b_u64":0,"expected_ordering":2,"expected_cost":1}]}`, "invalid expected_ordering 2"},
		{"missing bool", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BOOL","jet":"bytes_eq","bytes_a_hex":"","bytes_b_hex":"","expected_cost":1}]}`, "missing expected_bool"},
		{"missing bytes input", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BYTES-A","jet":"bytes_eq","bytes_b_hex":"","expected_bool":true,"expected_cost":1}]}`, "missing bytes_a_hex"},
		{"missing bytes", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-BYTES","jet":"bytes_slice","source_hex":"","start":0,"length":0,"expected_accepted":false,"expected_cost":2}]}`, "missing expected_bytes_hex"},
		{"missing u128 input", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-A-U128-HI","jet":"u128_checked_sub","a_u128_lo":0,"b_u128_hi":0,"b_u128_lo":1,"expected_accepted":false,"expected_u128_hi":0,"expected_u128_lo":0,"expected_cost":1}]}`, "missing a_u128_hi"},
		{"missing slice input", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-START","jet":"bytes_slice","source_hex":"616263","length":0,"expected_accepted":true,"expected_bytes_hex":"","expected_cost":1}]}`, "missing start"},
		{"missing cost", `{"contract_version":1,"fixture_kind":"simplicity_data_jets_corpus_v1","description":"x","cases":[{"id":"VEC-SDJ-MISSING-COST","jet":"u64_cmp","a_u64":0,"b_u64":0,"expected_ordering":0}]}`, "missing expected_cost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var corpus sharedDataJetCorpus
			decoder := json.NewDecoder(strings.NewReader(tc.raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&corpus); err != nil {
				t.Fatalf("decode malformed corpus: %v", err)
			}
			if len(corpus.Cases) != 1 {
				t.Fatalf("case count = %d, want 1", len(corpus.Cases))
			}
			err := corpus.Cases[0].validateOutcomeFields()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateOutcomeFields() = %v, want %q", err, tc.want)
			}
		})
	}
}

type requiredDataJetField struct {
	name string
	ok   bool
}

func requiredDataJet(name string, ok bool) requiredDataJetField {
	return requiredDataJetField{name: name, ok: ok}
}

func (tc sharedDataJetCase) validateOutcomeFields() error {
	required := []requiredDataJetField{requiredDataJet("expected_cost", tc.ExpectedCost != nil)}
	switch tc.Jet {
	case "u64_checked_add", "u64_checked_sub", "u64_checked_mul":
		required = append(required, tc.u64Inputs()...)
		required = append(required, requiredDataJet("expected_accepted", tc.ExpectedAccepted != nil), requiredDataJet("expected_u64", tc.ExpectedU64 != nil))
	case "u64_cmp":
		required = append(required, tc.u64Inputs()...)
		required = append(required, requiredDataJet("expected_ordering", tc.ExpectedOrdering != nil))
	case "u128_checked_add", "u128_checked_sub":
		required = append(required, tc.u128Inputs()...)
		required = append(required, requiredDataJet("expected_accepted", tc.ExpectedAccepted != nil), requiredDataJet("expected_u128_hi", tc.ExpectedU128Hi != nil), requiredDataJet("expected_u128_lo", tc.ExpectedU128Lo != nil))
	case "u128_cmp":
		required = append(required, tc.u128Inputs()...)
		required = append(required, requiredDataJet("expected_ordering", tc.ExpectedOrdering != nil))
	case "bytes_eq":
		required = append(required, tc.bytesPairInputs()...)
		required = append(required, requiredDataJet("expected_bool", tc.ExpectedBool != nil))
	case "bytes_cmp":
		required = append(required, tc.bytesPairInputs()...)
		required = append(required, requiredDataJet("expected_ordering", tc.ExpectedOrdering != nil))
	case "bytes_slice":
		required = append(required, tc.sliceInputs()...)
		required = append(required, requiredDataJet("expected_accepted", tc.ExpectedAccepted != nil), requiredDataJet("expected_bytes_hex", tc.ExpectedBytesHex != nil))
	default:
		return fmt.Errorf("%s: unknown data jet %q", tc.ID, tc.Jet)
	}
	for _, field := range required {
		if !field.ok {
			return tc.missingField(field.name)
		}
	}
	if tc.ExpectedOrdering != nil && (*tc.ExpectedOrdering < -1 || *tc.ExpectedOrdering > 1) {
		return fmt.Errorf("%s: invalid expected_ordering %d for %s", tc.ID, *tc.ExpectedOrdering, tc.Jet)
	}
	return nil
}

func (tc sharedDataJetCase) u64Inputs() []requiredDataJetField {
	return []requiredDataJetField{
		requiredDataJet("a_u64", tc.AU64 != nil),
		requiredDataJet("b_u64", tc.BU64 != nil),
	}
}

func (tc sharedDataJetCase) u128Inputs() []requiredDataJetField {
	return []requiredDataJetField{
		requiredDataJet("a_u128_hi", tc.AU128Hi != nil),
		requiredDataJet("a_u128_lo", tc.AU128Lo != nil),
		requiredDataJet("b_u128_hi", tc.BU128Hi != nil),
		requiredDataJet("b_u128_lo", tc.BU128Lo != nil),
	}
}

func (tc sharedDataJetCase) bytesPairInputs() []requiredDataJetField {
	return []requiredDataJetField{
		requiredDataJet("bytes_a_hex", tc.BytesAHex != nil),
		requiredDataJet("bytes_b_hex", tc.BytesBHex != nil),
	}
}

func (tc sharedDataJetCase) sliceInputs() []requiredDataJetField {
	return []requiredDataJetField{
		requiredDataJet("source_hex", tc.SourceHex != nil),
		requiredDataJet("start", tc.Start != nil),
		requiredDataJet("length", tc.Length != nil),
	}
}

func (tc sharedDataJetCase) missingField(name string) error {
	return fmt.Errorf("%s: missing %s for %s", tc.ID, name, tc.Jet)
}

func assertU64Jet(t *testing.T, name string, got U64JetResult, want sharedDataJetCase) {
	t.Helper()
	if got.Accepted != *want.ExpectedAccepted || got.Value != *want.ExpectedU64 || got.Cost != *want.ExpectedCost {
		t.Fatalf("%s = %+v, want accepted=%v value=%d cost=%d", name, got, *want.ExpectedAccepted, *want.ExpectedU64, *want.ExpectedCost)
	}
}

func assertU128Jet(t *testing.T, name string, got U128JetResult, want sharedDataJetCase) {
	t.Helper()
	expected := Uint128{Hi: *want.ExpectedU128Hi, Lo: *want.ExpectedU128Lo}
	if got.Accepted != *want.ExpectedAccepted || got.Value != expected || got.Cost != *want.ExpectedCost {
		t.Fatalf("%s = %+v, want accepted=%v value=%+v cost=%d", name, got, *want.ExpectedAccepted, expected, *want.ExpectedCost)
	}
}

func assertOrdering(t *testing.T, name string, got OrderingJetResult, want Ordering, cost uint64) {
	t.Helper()
	if got.Ordering != want || got.Cost != cost {
		t.Fatalf("%s = %+v, want ordering=%d cost=%d", name, got, want, cost)
	}
}
