package simplicity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var errSink error

func TestDescriptorHashAccessCostBoundaries(t *testing.T) {
	got, err := DescriptorHashAccessCost(3)
	if err != nil || got != DescriptorHashBaseCost+3*DescriptorHashByteCost {
		t.Fatalf("DescriptorHashAccessCost(3)=%d err=%v", got, err)
	}

	maxLen := (MaxExecCost - DescriptorHashBaseCost) / DescriptorHashByteCost
	got, err = DescriptorHashAccessCost(maxLen)
	if err != nil || got != MaxExecCost {
		t.Fatalf("DescriptorHashAccessCost(maxLen)=%d err=%v want %d", got, err, MaxExecCost)
	}

	got, err = DescriptorHashAccessCost(maxLen + 1)
	assertErrorCode(t, err, ErrBudgetExceeded)
	if got != MaxExecCost {
		t.Fatalf("over-budget cost=%d want %d", got, MaxExecCost)
	}

	got, err = DescriptorHashAccessCost(^uint64(0))
	assertErrorCode(t, err, ErrBudgetExceeded)
	if got != MaxExecCost {
		t.Fatalf("overflow cost=%d want %d", got, MaxExecCost)
	}
}

func TestDecodeVectors(t *testing.T) {
	tests := []struct {
		id        string
		program   []byte
		witness   []byte
		alternate []byte
		version   uint32
		covenant  string
		wantCMR   string
		wantError ErrorCode
	}{
		{id: "VEC-PE-001", program: hx("24"), version: 1, wantCMR: "c40a10263f7436b4160acbef1c36fba4be4d95df181a968afeab5eac247adff7"},
		{id: "VEC-PE-002", program: hx("c1220f0100"), version: 1, wantCMR: "afeae8c18903b9e0aae2c125f31f7b8e09de916e461f221936b633d587c1b434"},
		{id: "VEC-PE-003", program: hx("8900"), version: 1, wantCMR: "d296a48e538af38908242ab30244036fdb66e9056d5f812a5b328fae2b6a2726"},
		{id: "VEC-PE-004", program: hx("c1d21014"), witness: hx("00"), alternate: hx("80"), version: 1, covenant: "d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83", wantCMR: "d3ae07ae97378595ef49c6677fd92a1761f8fe7fd8dde86197efb49a49448b83"},
		{id: "VEC-PE-005", program: hx("60"), version: 1, wantCMR: "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637"},
		{id: "VEC-PE-006", program: hx("70"), version: 1, wantCMR: "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941"},
		{id: "VEC-PE-007", program: hx("24"), version: 2, wantError: ErrDecode},
		{id: "VEC-PE-008", program: hx("25"), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-009", program: append([]byte{0x24}, make([]byte, MaxProgramBytes)...), version: 1, wantError: ErrProgramTooLarge},
		{id: "VEC-PE-010", program: hx("24"), version: 1, covenant: "0000000000000000000000000000000000000000000000000000000000000000", wantError: ErrCMRMismatch},
		{id: "VEC-PE-011", program: append([]byte{0x28}, make([]byte, 64)...), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-012", program: hx("8958"), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-013", program: hx("7c0680"), version: 1, wantError: ErrJetDisallowed},
		{id: "VEC-PE-014", program: hx("c1d21014"), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-015", program: hx("c1d21014"), witness: hx("01"), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-016", program: hx("c1d21014"), witness: hx("0000"), version: 1, wantError: ErrDecode},
		{id: "VEC-PE-017", program: hx("2400"), version: 1, wantError: ErrDecode},
		{id: "RUB598-PE-UNKNOWN-CONTEXT-INTRINSIC", program: hx("e86000"), version: 1, wantError: ErrDecode},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got, err := Decode(tt.program, tt.witness, DecodeOptions{
				SemanticsVersion:   tt.version,
				CovenantProgramCMR: optionalCMR(tt.covenant),
			})
			if tt.wantError != "" {
				assertErrorCode(t, err, tt.wantError)
				return
			}
			if err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}
			wantCMR := hex32(tt.wantCMR)
			if got.CMR != wantCMR {
				t.Fatalf("cmr=%x want %s", got.CMR, tt.wantCMR)
			}
			if tt.alternate != nil {
				got, err = Decode(tt.program, tt.alternate, DecodeOptions{SemanticsVersion: tt.version})
				if err != nil || got.CMR != wantCMR {
					t.Fatalf("alternate witness cmr=%x err=%v want %x", got.CMR, err, wantCMR)
				}
			}
		})
	}
}

func TestSharedEncodingCorpus(t *testing.T) {
	var corpus struct {
		ContractVersion int    `json:"contract_version"`
		FixtureKind     string `json:"fixture_kind"`
		Description     string `json:"description"`
		Cases           []struct {
			ID               string `json:"id"`
			ProgramHex       string `json:"program_hex"`
			WitnessHex       string `json:"witness_hex"`
			SemanticsVersion uint32 `json:"semantics_version"`
			CovenantCMRHex   string `json:"covenant_cmr_hex"`
			ExpectedCMRHex   string `json:"expected_cmr_hex"`
			ExpectedError    string `json:"expected_error"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile(repoPath(t, "conformance", "fixtures", "protocol", "simplicity_program_encoding_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared corpus: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared corpus: %v", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		t.Fatal("parse shared corpus: trailing data")
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("parse shared corpus: trailing data: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_program_encoding_cmr_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			got, err := Decode(hx(tc.ProgramHex), hx(tc.WitnessHex), DecodeOptions{
				SemanticsVersion:   tc.SemanticsVersion,
				CovenantProgramCMR: optionalCMR(tc.CovenantCMRHex),
			})
			if tc.ExpectedError != "" {
				assertErrorCode(t, err, ErrorCode(tc.ExpectedError))
				return
			}
			if err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}
			if got.CMR != hex32(tc.ExpectedCMRHex) {
				t.Fatalf("cmr=%x want %s", got.CMR, tc.ExpectedCMRHex)
			}
		})
	}
}

type sharedExecCorpus struct {
	ContractVersion int              `json:"contract_version"`
	FixtureKind     string           `json:"fixture_kind"`
	Description     string           `json:"description"`
	Cases           []sharedExecCase `json:"cases"`
}

type sharedExecCase struct {
	ID                   string   `json:"id"`
	ProgramHex           string   `json:"program_hex"`
	WitnessHex           string   `json:"witness_hex"`
	EvalSteps            uint64   `json:"eval_steps"`
	FrameBitWidths       []uint64 `json:"frame_bit_widths"`
	JetAccepted          bool     `json:"jet_accepted"`
	JetCost              uint64   `json:"jet_cost"`
	ExpectedAccepted     bool     `json:"expected_accepted"`
	ExpectedError        string   `json:"expected_error"`
	ExpectedFinalCounter uint64   `json:"expected_final_counter"`
}

type sharedJetsRegistryCorpus struct {
	ContractVersion         int                      `json:"contract_version"`
	FixtureKind             string                   `json:"fixture_kind"`
	Description             string                   `json:"description"`
	ExpectedRegistryHashHex string                   `json:"expected_registry_hash_hex"`
	Cases                   []sharedJetsRegistryCase `json:"cases"`
}

type sharedJetsRegistryCase struct {
	ID              string `json:"id"`
	JetID           uint16 `json:"jet_id"`
	SubOp           uint8  `json:"sub_op"`
	Name            string `json:"name"`
	Signature       string `json:"signature"`
	ProgramHex      string `json:"program_hex"`
	ExpectedPresent bool   `json:"expected_present"`
	ExpectedError   string `json:"expected_error"`
}

func TestSharedExecCorpus(t *testing.T) {
	var corpus sharedExecCorpus
	raw, err := os.ReadFile(repoPath(t, "conformance", "fixtures", "protocol", "simplicity_exec_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared exec corpus: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared exec corpus: %v", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		t.Fatal("parse shared exec corpus: trailing data")
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("parse shared exec corpus: trailing data: %v", err)
	}
	if err := requireSharedExecOutcomeFields(corpus.Cases, raw); err != nil {
		t.Fatalf("validate shared exec corpus schema: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_exec_corpus_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared exec corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			got, err := evaluateSharedExecCase(t, tc)
			if tc.ExpectedError != "" {
				assertErrorCode(t, err, ErrorCode(tc.ExpectedError))
			} else if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Accepted != tc.ExpectedAccepted || got.Cost != tc.ExpectedFinalCounter {
				t.Fatalf("evaluation=%+v want accepted=%v final_counter=%d", got, tc.ExpectedAccepted, tc.ExpectedFinalCounter)
			}
		})
	}
}

func TestSharedJetsRegistryCorpus(t *testing.T) {
	var corpus sharedJetsRegistryCorpus
	raw, err := os.ReadFile(repoPath(t, "conformance", "fixtures", "protocol", "simplicity_jets_registry_corpus_v1.json"))
	if err != nil {
		t.Fatalf("read shared jets registry corpus: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("parse shared jets registry corpus: %v", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err == nil {
		t.Fatal("parse shared jets registry corpus: trailing data")
	} else if !errors.Is(err, io.EOF) {
		t.Fatalf("parse shared jets registry corpus: trailing data: %v", err)
	}
	if corpus.ContractVersion != 1 || corpus.FixtureKind != "simplicity_jets_registry_corpus_v1" || len(corpus.Cases) == 0 {
		t.Fatalf("bad shared jets registry corpus header: version=%d kind=%q cases=%d", corpus.ContractVersion, corpus.FixtureKind, len(corpus.Cases))
	}
	if got := JetsRegistryHash(); got != hex32(corpus.ExpectedRegistryHashHex) {
		t.Fatalf("jets_registry_hash=%x want %s", got, corpus.ExpectedRegistryHashHex)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			got, ok := registryRow(tc.JetID, tc.SubOp)
			if ok != tc.ExpectedPresent {
				t.Fatalf("present=%v want %v", ok, tc.ExpectedPresent)
			}
			if tc.ExpectedPresent {
				if got.jet.Name != tc.Name || got.signature != tc.Signature {
					t.Fatalf("row=%#04x/%#02x name=%q signature=%q", tc.JetID, tc.SubOp, got.jet.Name, got.signature)
				}
				return
			}
			if tc.ProgramHex != "" {
				_, err := Decode(hx(tc.ProgramHex), nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
				assertErrorCode(t, err, ErrorCode(tc.ExpectedError))
			}
		})
	}
}

// Self-consistency guard only: the expected hash below is derived from contextIntrinsicRows itself
// (same pattern as TestCostModelHashMatchesSpecArtifact/TestJetsRegistryHashMatchesSpecArtifact
// already on main), so it catches an ACCIDENTAL EDIT after this file was written, not an incorrect
// initial transcription from the RUB-597 artifact — see context_abi_generated.go's header.
func TestContextIntrinsicRowsMatchRUB597Snapshot(t *testing.T) {
	if len(contextIntrinsicRows) != 35 {
		t.Fatalf("context ABI row count=%d want 35", len(contextIntrinsicRows))
	}
	hash := sha256.New()
	for _, row := range contextIntrinsicRows {
		program, err := Decode(hx(row.SelectorHex), nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
		if err != nil {
			t.Fatalf("Decode context ABI row %#04x: %v", row.ID, err)
		}
		if program.CMR != row.CMR {
			t.Fatalf("row %#04x cmr=%x want %x", row.ID, program.CMR, row.CMR)
		}
		if len(program.intrinsics) != 1 || program.intrinsics[0].ID != row.ID {
			t.Fatalf("row %#04x decoded intrinsics=%+v", row.ID, program.intrinsics)
		}
		fmt.Fprintf(hash, "%04x|%s|%s|%s|%x|%d|%d|%t|%t\n", row.ID, row.Name, row.Signature, row.SelectorHex, row.CMR, row.Kind, row.OutputBitWidth, row.Either, row.Indexed)
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != "8a7543f57ac73443a793a66f281e78072eedcf1bf12ed27710aefb0624865638" {
		t.Fatalf("context ABI RUB-597 snapshot hash=%s", got)
	}
}

type evalTestHost struct {
	meter
	charges, reads   int
	lastCharge       uint64
	failCharge       bool
	intrinsicCostErr error
	intrinsicResult  IntrinsicResult
	readErr          error
	lastIndex        uint16
}

func (h *evalTestHost) Charge(cost uint64) error {
	h.charges++
	h.lastCharge = cost
	if h.failCharge {
		return &Error{Code: ErrBudgetExceeded}
	}
	return h.charge(cost)
}
func (h *evalTestHost) Cost() uint64 { return h.cost }
func (h *evalTestHost) IntrinsicCost(ContextIntrinsic) (uint64, error) {
	return 1, h.intrinsicCostErr
}

func (h *evalTestHost) ReadIntrinsic(intrinsic ContextIntrinsic) (IntrinsicResult, error) {
	h.reads++
	h.lastIndex = intrinsic.Index
	return h.intrinsicResult, h.readErr
}

func TestAdversarialHostDoesNotMutateOnBudgetError(t *testing.T) {
	if (IntrinsicResult{Value: ContextValue{Kind: ContextValueU8, Uint: 0x100}}).validFor(ContextIntrinsic{Kind: ContextValueU8}) {
		t.Fatal("u8 intrinsic accepted out-of-range host value")
	}
	bytesIntrinsic := ContextIntrinsic{Kind: ContextValueBytes}
	if !(IntrinsicResult{Value: ContextValue{Kind: ContextValueBytes, Bytes: make([]byte, maxContextStateBytes)}}).validFor(bytesIntrinsic) {
		t.Fatal("bytes intrinsic rejected at-cap host value")
	}
	if (IntrinsicResult{Value: ContextValue{Kind: ContextValueBytes, Bytes: make([]byte, maxContextStateBytes+1)}}).validFor(bytesIntrinsic) {
		t.Fatal("bytes intrinsic accepted over-cap host value")
	}
	desc, err := Decode(hx("e82200"), nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
	if err != nil {
		t.Fatalf("Decode descriptor intrinsic: %v", err)
	}
	host := &evalTestHost{meter: meter{cost: MaxExecCost - 1}, failCharge: true}
	got, err := Program{decoded: true, evalSteps: 1}.Evaluate(EvalOptions{Host: host})
	if !hasErrorCode(err, ErrBudgetExceeded) || got.Cost != MaxExecCost-1 || host.Cost() != MaxExecCost-1 || host.charges != 1 || host.lastCharge != 1 || host.reads != 0 {
		t.Fatalf("adversarial host step charge result=%+v host=%+v err=%v", got, host, err)
	}
	host = &evalTestHost{meter: meter{cost: 7}}
	got, err = Program{decoded: true, evalSteps: MaxExecCost/StepCost + 1}.Evaluate(EvalOptions{Host: host})
	if !hasErrorCode(err, ErrBudgetExceeded) || got.Cost != MaxExecCost || host.Cost() != MaxExecCost || host.charges != 1 || host.lastCharge != MaxExecCost-7 || host.reads != 0 {
		t.Fatalf("over-cap host precharge result=%+v host=%+v err=%v", got, host, err)
	}
	host = &evalTestHost{meter: meter{cost: MaxExecCost}, failCharge: true}
	got, err = desc.Evaluate(EvalOptions{Host: host})
	if !hasErrorCode(err, ErrBudgetExceeded) || got.Cost != MaxExecCost || host.charges != 0 || host.reads != 0 {
		t.Fatalf("exhausted intrinsic result=%+v host=%+v err=%v", got, host, err)
	}
}

func TestSharedExecCorpusRequiresOutcomeFields(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		cases []sharedExecCase
		want  string
	}{
		{name: "missing accepted", raw: `{"cases":[{"expected_final_counter":0}]}`, cases: []sharedExecCase{{ID: "VEC-SE-MISSING-ACCEPTED"}}, want: "shared exec corpus case VEC-SE-MISSING-ACCEPTED missing expected_accepted"},
		{name: "missing final counter", raw: `{"cases":[{"expected_accepted":false}]}`, cases: []sharedExecCase{{ID: "VEC-SE-MISSING-COUNTER"}}, want: "shared exec corpus case VEC-SE-MISSING-COUNTER missing expected_final_counter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireSharedExecOutcomeFields(tt.cases, []byte(tt.raw))
			if err == nil || err.Error() != tt.want {
				t.Fatalf("error=%v want %q", err, tt.want)
			}
		})
	}
}

func requireSharedExecOutcomeFields(cases []sharedExecCase, raw []byte) error {
	var rawCorpus struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(raw, &rawCorpus); err != nil {
		return err
	}
	if len(rawCorpus.Cases) != len(cases) {
		return fmt.Errorf("shared exec corpus raw cases=%d decoded cases=%d", len(rawCorpus.Cases), len(cases))
	}
	for i, fields := range rawCorpus.Cases {
		id := cases[i].ID
		if id == "" {
			id = fmt.Sprintf("index %d", i)
		}
		if _, ok := fields["expected_accepted"]; !ok {
			return fmt.Errorf("shared exec corpus case %s missing expected_accepted", id)
		}
		if _, ok := fields["expected_final_counter"]; !ok {
			return fmt.Errorf("shared exec corpus case %s missing expected_final_counter", id)
		}
	}
	return nil
}

func TestProgramSizeBoundary(t *testing.T) {
	atCap := make([]byte, MaxProgramBytes)
	atCap[0] = 0x24
	_, err := Decode(atCap, nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
	assertErrorCode(t, err, ErrDecode)

	tooLarge := append([]byte{0x24}, make([]byte, MaxProgramBytes)...)
	_, err = Decode(tooLarge, nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
	assertErrorCode(t, err, ErrProgramTooLarge)
}

func TestDecodeRejectsOversizedWitnessBeforeCopy(t *testing.T) {
	program := hx("24")
	witness := bytes.Repeat([]byte{0x01}, MaxProgramBytes*4)
	allocs := testing.AllocsPerRun(100, func() {
		_, errSink = Decode(program, witness, DecodeOptions{SemanticsVersion: SemanticsVersion})
	})
	if allocs > 1 {
		t.Fatalf("Decode allocated %.0f times on oversized witness reject", allocs)
	}
	assertErrorCode(t, errSink, ErrDecode)
}

func TestJetRows(t *testing.T) {
	keys := [][2]uint16{{0x0001, 0}, {0x0002, 0}, {0x0010, 0}, {0x0010, 1}, {0x0010, 2}, {0x0010, 3}, {0x0011, 0}, {0x0011, 1}, {0x0011, 3}, {0x0020, 0}, {0x0020, 1}, {0x0021, 0}}
	for _, key := range keys {
		if _, ok := LookupJet(key[0], uint8(key[1])); !ok {
			t.Fatalf("missing jet row (%#04x,%#02x)", key[0], key[1])
		}
	}
	sha3Row, ok := LookupJet(0x0001, 0x00)
	if !ok {
		t.Fatal("missing sha3_256 row")
	}
	if sha3Row.Name != "sha3_256" || sha3Row.SelectorBitLen != 2 || !bytes.Equal(sha3Row.SelectorPadded, hx("00")) {
		t.Fatalf("bad sha3 row: %+v", sha3Row)
	}
	if _, ok := LookupJet(0x0011, 0x02); ok {
		t.Fatal("unexpected u128_checked_mul row")
	}
	sha3Row.SelectorPadded[0] = 0xff
	again, _ := LookupJet(0x0001, 0x00)
	if !bytes.Equal(again.SelectorPadded, hx("00")) {
		t.Fatal("LookupJet returned mutable internal selector storage")
	}
	if _, err := requireJet(0x0011, 0x02); err == nil {
		t.Fatal("requireJet accepted unassigned u128_checked_mul")
	} else {
		assertErrorCode(t, err, ErrJetDisallowed)
	}
}

func TestDecodeJetMetadataIsImmutable(t *testing.T) {
	tests := []struct {
		program []byte
		name    string
		cmr     string
	}{
		{program: hx("60"), name: "sha3_256", cmr: "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637"},
		{program: hx("70"), name: "mldsa87_verify", cmr: "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941"},
	}
	for _, tt := range tests {
		first, err := Decode(tt.program, nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
		if err != nil || first.Jet == nil {
			t.Fatalf("Decode(%x) jet=%v err=%v", tt.program, first.Jet, err)
		}
		first.Jet.Name = "corrupted"
		first.Jet.CMR = [32]byte{}
		first.Jet.SelectorPadded[0] = 0xff

		again, err := Decode(tt.program, nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
		if err != nil || again.Jet == nil {
			t.Fatalf("second Decode(%x) jet=%v err=%v", tt.program, again.Jet, err)
		}
		if again.Jet.Name != tt.name || again.Jet.CMR != hex32(tt.cmr) || again.Jet.SelectorPadded[0] == 0xff {
			t.Fatalf("Decode returned mutable jet metadata: %+v", again.Jet)
		}
	}
}

func TestEvaluateChargesDecodedProgramSteps(t *testing.T) {
	tests := []struct {
		name    string
		program []byte
		witness []byte
		cost    uint64
	}{
		{name: "unit", program: hx("24"), cost: 1},
		{name: "comp unit unit", program: hx("8900"), cost: 2},
		{name: "drop wrapper", program: hx("c1220f0100"), cost: 4},
		{name: "witness case", program: hx("c1d21014"), witness: hx("00"), cost: 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			program, err := Decode(tt.program, tt.witness, DecodeOptions{SemanticsVersion: SemanticsVersion})
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			got, err := program.Evaluate(EvalOptions{})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if !got.Accepted || got.Cost != tt.cost*StepCost {
				t.Fatalf("evaluation=%+v want accepted cost=%d", got, tt.cost*StepCost)
			}
		})
	}
}

func TestCostModelHashMatchesSpecArtifact(t *testing.T) {
	preimage := costModelBytes()
	wantPreimage := "" +
		"525542494e2d53494d504c49434954592d434f53542d76310200000001000000000000000100000000000000010000000000000040000000000000000100000000000000000001000000000000001000000000000c" +
		"0100000140000000000000000200000050c3000000000000100000000100000000000000100001000100000000000000100002000100000000000000100003000100000000000000110000000100000000000000110001000100000000000000110003000100000000000000200000020000000000000000200001020000000000000000210000020000000000000000"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("cost preimage=%s want %s", got, wantPreimage)
	}
	if got := CostModelHash(); got != hex32("accb55570168bd7b1fedadff2135c99e32508680ff7a315cf4f33f97744aabc9") {
		t.Fatalf("cost_model_hash=%x", got)
	}
}

func TestJetsRegistryHashMatchesSpecArtifact(t *testing.T) {
	preimage := jetsRegistryBytes(jetRegistryRows)
	wantPreimage := "" +
		"525542494e2d53494d504c49434954592d4a4554532d7631020000000c010000" +
		"08736861335f323536106279746573202d3e20627974657333320200000e6d6c" +
		"64736138375f76657269667933287075626b65793a62797465732c207369673a" +
		"62797465732c2064696765737433323a6279746573333229202d3e20626f6f6c" +
		"1000000f7536345f636865636b65645f6164641f287536342c2075363429202d" +
		"3e204569746865723c756e69742c207536343e1000010f7536345f636865636b" +
		"65645f7375621f287536342c2075363429202d3e204569746865723c756e6974" +
		"2c207536343e1000020f7536345f636865636b65645f6d756c1f287536342c20" +
		"75363429202d3e204569746865723c756e69742c207536343e10000307753634" +
		"5f636d7016287536342c2075363429202d3e206f72646572696e671100001075" +
		"3132385f636865636b65645f6164642228753132382c207531323829202d3e20" +
		"4569746865723c756e69742c20753132383e11000110753132385f636865636b" +
		"65645f7375622228753132382c207531323829202d3e204569746865723c756e" +
		"69742c20753132383e11000308753132385f636d701828753132382c20753132" +
		"3829202d3e206f72646572696e672000000862797465735f6571162862797465" +
		"732c20627974657329202d3e20626f6f6c2000010962797465735f636d701a28" +
		"62797465732c20627974657329202d3e206f72646572696e672100000b627974" +
		"65735f736c69636536287372633a62797465732c2073746172743a7536342c20" +
		"6c656e3a75363429202d3e204569746865723c756e69742c2062797465733e"
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("jets registry preimage=%s want %s", got, wantPreimage)
	}
	if got := JetsRegistryHash(); got != hex32("5aee78aae6b610a3eb3c05bd1487523e318418e0419de48e4fe9555b37f1c059") {
		t.Fatalf("jets_registry_hash=%x", got)
	}
}

// Regression guard, NOT an artifact recompute — see ProgramEncodingHash's doc comment for why.
func TestProgramEncodingHashPinsPublishedSpecValue(t *testing.T) {
	if got := ProgramEncodingHash(); got != hex32("27e5ad521efdf9d185c1c92a3a1a4aacc9276c2a5b1b8518ce25c8c973a38adc") {
		t.Fatalf("program_encoding_hash=%x", got)
	}
}

// Regression guard, NOT an artifact recompute — see ContextSchemaHash's doc comment for why (no
// in-repo Rust/preimage anchor yet; deferred to RUB-606 under the Rust freeze).
func TestContextSchemaHashPinsPublishedSpecValue(t *testing.T) {
	if got := ContextSchemaHash(); got != hex32("e832db3008c355262420c63168c1c9787a69aac31d15a50a640f0301d8410150") {
		t.Fatalf("context_schema_hash=%x", got)
	}
}

func TestJetRegistryRuntimeMetadataMatchesSpecArtifact(t *testing.T) {
	want := map[jetKey]struct {
		selectorBitLen int
		selectorPadded string
		cmr            string
	}{
		{id: 0x0001, subOp: 0x00}: {selectorBitLen: 2, selectorPadded: "00", cmr: "3999889bdf18d07c6c38b7aacb89f6c2bdd3c6a5c3c93ce79d1902a567b1e637"},
		{id: 0x0002, subOp: 0x00}: {selectorBitLen: 4, selectorPadded: "80", cmr: "f5f90bf76aea628b4f2d75267cb5c13b49cd444b0690c3411fa01856342d4941"},
		{id: 0x0010, subOp: 0x00}: {selectorBitLen: 12, selectorPadded: "e000", cmr: "4911cf2b5d37ccc5407c0d4e0686f0c6871c0b18c33ebc2dd28ec905cbec90ee"},
		{id: 0x0010, subOp: 0x01}: {selectorBitLen: 14, selectorPadded: "e010", cmr: "9c2b594d0673d2f416e0bb216f15d35a55a75c2237d030493ec3ae72652f2146"},
		{id: 0x0010, subOp: 0x02}: {selectorBitLen: 14, selectorPadded: "e014", cmr: "cf668e8e6a8bd1e9bcceebef182e063d1facd1665664170b6ae163456e739fa7"},
		{id: 0x0010, subOp: 0x03}: {selectorBitLen: 17, selectorPadded: "e01800", cmr: "50a228b34771cac098612f13ccf74949a8a0d8856b29440502fe8b45dd699c07"},
		{id: 0x0011, subOp: 0x00}: {selectorBitLen: 12, selectorPadded: "e020", cmr: "9d4674805162aca15086e994aa03fb6d2093665316449f9cc97e5288daf14dd9"},
		{id: 0x0011, subOp: 0x01}: {selectorBitLen: 14, selectorPadded: "e030", cmr: "0d8bc8c7815edb3c220fd212f4c7b6986f50e8a427d6200b74f83a85c1792f75"},
		{id: 0x0011, subOp: 0x03}: {selectorBitLen: 17, selectorPadded: "e03800", cmr: "c90a66af21fc7ced71a9141082a47dbb0db878c25f432af25f382ccb055f4add"},
		{id: 0x0020, subOp: 0x00}: {selectorBitLen: 13, selectorPadded: "e200", cmr: "33f82e38417283760f1d9deba367aeaa0feb4c703b69aa37dc8c2aefe7c32d4a"},
		{id: 0x0020, subOp: 0x01}: {selectorBitLen: 15, selectorPadded: "e208", cmr: "bd237f53ad86be9b3c8bd3dcb2a36642782c07885d5afc44903b5dc6d017960a"},
		{id: 0x0021, subOp: 0x00}: {selectorBitLen: 13, selectorPadded: "e210", cmr: "9c28e72f9da964de2c90d92c5c772211537ed2e07d20f6790c988284a87c0ce2"},
	}
	if len(want) != len(jetRegistryRows) {
		t.Fatalf("metadata rows=%d want registry rows=%d", len(want), len(jetRegistryRows))
	}
	for _, row := range jetRegistryRows {
		key := jetKey{id: row.jet.ID, subOp: row.jet.SubOp}
		w, ok := want[key]
		if !ok {
			t.Fatalf("unexpected jet row %#04x/%#02x", key.id, key.subOp)
		}
		if row.jet.SelectorBitLen != w.selectorBitLen || !bytes.Equal(row.jet.SelectorPadded, hx(w.selectorPadded)) || row.jet.CMR != hex32(w.cmr) {
			t.Fatalf("metadata %#04x/%#02x got selector=%d/%x cmr=%x", key.id, key.subOp, row.jet.SelectorBitLen, row.jet.SelectorPadded, row.jet.CMR)
		}
	}
}

func TestJetsRegistryRowsRejectDuplicatesAndOrderDrift(t *testing.T) {
	duplicate := append([]jetRegistryRow(nil), jetRegistryRows...)
	duplicate[1] = duplicate[0]
	if err := validateJetLookupRows(duplicate); err == nil {
		t.Fatal("duplicate jet registry key was accepted")
	}

	orderDrift := append([]jetRegistryRow(nil), jetRegistryRows...)
	orderDrift[0], orderDrift[1] = orderDrift[1], orderDrift[0]
	if err := validateJetLookupRows(orderDrift); err == nil {
		t.Fatal("out-of-order jet registry rows were accepted")
	}
}

func TestCostModelRowsMatchJetTable(t *testing.T) {
	if len(costModelRows) != len(jetRows) || len(costModelRows) >= 253 {
		t.Fatalf("cost rows=%d jet rows=%d", len(costModelRows), len(jetRows))
	}
	var prev jetKey
	for i, row := range costModelRows {
		if _, ok := jetRows[row.jet]; !ok {
			t.Fatalf("cost row %d missing jet %#04x/%#02x", i, row.jet.id, row.jet.subOp)
		}
		if i > 0 && (prev.id > row.jet.id || (prev.id == row.jet.id && prev.subOp >= row.jet.subOp)) {
			t.Fatalf("cost rows not sorted at %d", i)
		}
		if row.formula > costOnePlusCeilLen32 || (row.formula == costOnePlusCeilLen32 && row.param != 0) {
			t.Fatalf("bad cost formula at %d", i)
		}
		prev = row.jet
	}
}

func TestCostModelRowCountRejectsMultiByteCompactSize(t *testing.T) {
	defer func() {
		if got := recover(); got == nil {
			t.Fatal("cost model row count requiring multi-byte CompactSize did not panic")
		}
	}()

	_ = costModelRowCountByte(make([]costModelRow, 253))
}

func TestEvaluateJetRequiresCostHook(t *testing.T) {
	program := decodeSHA3Jet(t)
	_, err := program.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrJetDisallowed)
}

func TestEvaluateRejectsUndecodedProgram(t *testing.T) {
	program := Program{Jet: &Jet{Name: "sha3_256"}}
	_, err := evaluateSHA3JetWithResult(t, program, EvalResult{Accepted: true, Cost: 1})
	assertErrorCode(t, err, ErrDecode)
}

func TestEvaluateUsesDecodedJetIdentity(t *testing.T) {
	program := decodeSHA3Jet(t)
	program.Jet = &Jet{Name: "forged"}
	got, err := evaluateSHA3JetWithResult(t, program, EvalResult{Accepted: true, Cost: 1})
	if err != nil {
		t.Fatalf("Evaluate jet: %v", err)
	}
	if !got.Accepted || got.Cost != 1 {
		t.Fatalf("evaluation=%+v want accepted cost=1", got)
	}
}

func TestEvaluateJetCostHookCapBoundary(t *testing.T) {
	program := decodeSHA3Jet(t)
	tests := []struct {
		name     string
		jetCost  uint64
		wantCost uint64
	}{
		{name: "under cap", jetCost: MaxExecCost - 1, wantCost: MaxExecCost - 1},
		{name: "equal cap", jetCost: MaxExecCost, wantCost: MaxExecCost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateSHA3JetWithResult(t, program, EvalResult{Accepted: true, Cost: tt.jetCost})
			if err != nil {
				t.Fatalf("Evaluate jet: %v", err)
			}
			if !got.Accepted || got.Cost != tt.wantCost {
				t.Fatalf("evaluation=%+v want accepted cost=%d", got, tt.wantCost)
			}
		})
	}
	calls := 0
	_, err := program.Evaluate(EvalOptions{Host: &evalTestHost{meter: meter{cost: MaxExecCost}}, JetRegistry: func(Jet) bool { return true }, JetCost: func(Jet) (uint64, error) { return 1, nil }, JetEvaluator: func(Jet) (EvalResult, error) {
		calls++
		return EvalResult{Accepted: true}, nil
	}})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if calls != 0 {
		t.Fatalf("JetEvaluator calls=%d want 0 after budget reject", calls)
	}
	_, err = program.Evaluate(EvalOptions{Host: &evalTestHost{meter: meter{cost: MaxExecCost}}, JetRegistry: func(Jet) bool { return false }, JetEvaluator: func(Jet) (EvalResult, error) {
		t.Fatal("JetEvaluator called after registry reject")
		return EvalResult{}, nil
	}})
	assertErrorCode(t, err, ErrJetDisallowed)

	got, err := evaluateSHA3JetWithResult(t, program, EvalResult{Accepted: true, Cost: MaxExecCost + 1})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if !got.Accepted || got.Cost != MaxExecCost {
		t.Fatalf("evaluation=%+v want accepted saturated cost=%d", got, MaxExecCost)
	}
}

func TestEvaluateJetWithHostFullPath(t *testing.T) {
	program := decodeSHA3Jet(t)
	host := &evalTestHost{}
	got, err := program.Evaluate(EvalOptions{
		Host:        host,
		JetRegistry: func(Jet) bool { return true },
		JetCost:     func(Jet) (uint64, error) { return 5, nil },
		JetEvaluator: func(j Jet) (EvalResult, error) {
			return EvalResult{Accepted: true, Cost: 3}, nil
		},
	})
	if err != nil || !got.Accepted || got.Cost != 5 || host.Cost() != 5 {
		t.Fatalf("full host jet path result=%+v host.cost=%d err=%v", got, host.Cost(), err)
	}

	_, err = program.Evaluate(EvalOptions{
		Host:         &evalTestHost{},
		JetEvaluator: func(Jet) (EvalResult, error) { t.Fatal("evaluator called with no registry"); return EvalResult{}, nil },
	})
	assertErrorCode(t, err, ErrJetDisallowed)

	_, err = program.Evaluate(EvalOptions{
		Host:         &evalTestHost{},
		JetRegistry:  func(Jet) bool { return true },
		JetEvaluator: func(Jet) (EvalResult, error) { t.Fatal("evaluator called with no JetCost"); return EvalResult{}, nil },
	})
	assertErrorCode(t, err, ErrJetDisallowed)

	_, err = program.Evaluate(EvalOptions{
		Host:        &evalTestHost{},
		JetRegistry: func(Jet) bool { return true },
		JetCost:     func(Jet) (uint64, error) { return 0, &Error{Code: ErrBudgetExceeded} },
		JetEvaluator: func(Jet) (EvalResult, error) {
			t.Fatal("evaluator called after JetCost error")
			return EvalResult{}, nil
		},
	})
	assertErrorCode(t, err, ErrBudgetExceeded)

	got, err = program.Evaluate(EvalOptions{
		Host:        &evalTestHost{},
		JetRegistry: func(Jet) bool { return true },
		JetCost:     func(Jet) (uint64, error) { return 1, nil },
		JetEvaluator: func(Jet) (EvalResult, error) {
			return EvalResult{Accepted: false}, nil
		},
	})
	assertErrorCode(t, err, ErrRejected)
	if got.Accepted {
		t.Fatalf("host jet rejection result=%+v want Accepted=false", got)
	}
}

func TestCheckRunnableDisallowedJetPriority(t *testing.T) {
	_, err := Program{decoded: true, disallowedJet: true, evalSteps: 1}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrJetDisallowed)
}

func TestEvaluateIntrinsicsRequiresHost(t *testing.T) {
	ctx := ContextIntrinsic{ID: 0x0100, Kind: ContextValueBytes32}
	_, err := Program{decoded: true, intrinsics: []ContextIntrinsic{ctx}}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrDecode)
}

func TestEvaluateIntrinsicsWithLeadingSteps(t *testing.T) {
	ctx := ContextIntrinsic{ID: 0x0100, Kind: ContextValueBytes32}
	failHost := &evalTestHost{meter: meter{cost: MaxExecCost - 1}, failCharge: true}
	_, err := Program{decoded: true, evalSteps: 1, intrinsics: []ContextIntrinsic{ctx}}.Evaluate(EvalOptions{Host: failHost})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if failHost.reads != 0 {
		t.Fatalf("read count=%d want 0 before failed step charge", failHost.reads)
	}
}

func TestEvaluateOneIntrinsicBranches(t *testing.T) {
	valid := ContextIntrinsic{ID: 0x0122, Kind: ContextValueBytes32, Indexed: true}

	host := &evalTestHost{intrinsicResult: IntrinsicResult{Value: ContextValue{Kind: ContextValueBytes32}}}
	got, err := Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{Host: host, ContextIndex: 9})
	if err != nil || !got.Accepted || host.lastIndex != 9 {
		t.Fatalf("indexed success result=%+v host=%+v err=%v", got, host, err)
	}

	costErrHost := &evalTestHost{intrinsicCostErr: &Error{Code: ErrBudgetExceeded}}
	_, err = Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{Host: costErrHost})
	assertErrorCode(t, err, ErrBudgetExceeded)

	chargeErrHost := &evalTestHost{failCharge: true}
	_, err = Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{Host: chargeErrHost})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if chargeErrHost.reads != 0 {
		t.Fatalf("read count=%d want 0 before failed intrinsic charge", chargeErrHost.reads)
	}

	readErrHost := &evalTestHost{readErr: &Error{Code: ErrDecode}}
	_, err = Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{Host: readErrHost})
	assertErrorCode(t, err, ErrDecode)

	rejectHost := &evalTestHost{} // zero-value IntrinsicResult has Kind ContextValueInvalid
	got, err = Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{Host: rejectHost})
	assertErrorCode(t, err, ErrRejected)
	if got.Accepted {
		t.Fatalf("kind-mismatch rejection result=%+v want Accepted=false", got)
	}

	evaluatorHost := &evalTestHost{intrinsicResult: IntrinsicResult{Value: ContextValue{Kind: ContextValueBytes32}}}
	called := false
	_, err = Program{decoded: true, intrinsics: []ContextIntrinsic{valid}}.Evaluate(EvalOptions{
		Host:             evaluatorHost,
		ContextEvaluator: func(ContextIntrinsic, IntrinsicResult) bool { called = true; return false },
	})
	assertErrorCode(t, err, ErrRejected)
	if !called {
		t.Fatal("ContextEvaluator never called for a validFor-passing result")
	}
}

func TestMustHexBytesPanicsOnInvalidHex(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustHexBytes did not panic on invalid hex")
		}
	}()
	mustHexBytes("not-hex")
}

func TestEvaluateMemoryBounds(t *testing.T) {
	for _, frames := range [][]uint64{{MaxFrameBytes * 8}, repeated(MaxFrameBytes*8, int(MaxLiveMemoryBytes/MaxFrameBytes))} {
		got, err := Program{decoded: true, evalSteps: 1, frameBitWidths: frames}.Evaluate(EvalOptions{})
		if err != nil || !got.Accepted || got.Cost != StepCost {
			t.Fatalf("evaluation=%+v err=%v want accepted cost=%d", got, err, StepCost)
		}
	}
	for _, frames := range [][]uint64{{MaxFrameBytes*8 + 1}, append(repeated(MaxFrameBytes*8, int(MaxLiveMemoryBytes/MaxFrameBytes)), 8)} {
		_, err := Program{decoded: true, evalSteps: 1, frameBitWidths: frames}.Evaluate(EvalOptions{})
		assertErrorCode(t, err, ErrBudgetExceeded)
	}

	calls := 0
	program := decodeSHA3Jet(t)
	program.frameBitWidths = []uint64{MaxFrameBytes*8 + 1}
	_, err := program.Evaluate(EvalOptions{
		JetEvaluator: func(Jet) (EvalResult, error) {
			calls++
			return EvalResult{Accepted: true, Cost: 1}, nil
		},
	})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if calls != 0 {
		t.Fatalf("JetEvaluator calls=%d want 0 before memory reject", calls)
	}
}

func TestDecodePopulatesMemorySchedule(t *testing.T) {
	for _, tt := range []struct{ program, witness string }{
		{"24", ""},
		{"c1d21014", "00"},
		{"60", ""},
		{"70", ""},
	} {
		program, err := Decode(hx(tt.program), hx(tt.witness), DecodeOptions{SemanticsVersion: SemanticsVersion})
		if err != nil {
			t.Fatalf("Decode(%s): %v", tt.program, err)
		}
		if len(program.frameBitWidths) == 0 {
			t.Fatalf("Decode(%s) returned no frame schedule", tt.program)
		}
		if err := checkMemoryBounds(program.frameBitWidths); err != nil {
			t.Fatalf("Decode(%s) frame schedule exceeds bounds: %v", tt.program, err)
		}
	}

	first := decodeSHA3Jet(t)
	first.frameBitWidths[0] = MaxFrameBytes*8 + 1

	if err := checkMemoryBounds(decodeSHA3Jet(t).frameBitWidths); err != nil {
		t.Fatalf("Decode returned mutable frame schedule: %v", err)
	}
}

func TestEvaluateMemoryErrorClassPriority(t *testing.T) {
	overFrame := []uint64{MaxFrameBytes*8 + 1}
	_, err := Program{frameBitWidths: overFrame}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrDecode)

	_, err = Program{decoded: true, frameBitWidths: overFrame}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrDecode)

	_, err = Program{decoded: true, hasJet: true, jetKey: jetKey{id: 0xffff}, frameBitWidths: overFrame}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrDecode)

	_, err = Program{decoded: true, evalSteps: 1, frameBitWidths: overFrame}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrBudgetExceeded)
}

func TestEvaluateJetRejectsFailedHookResult(t *testing.T) {
	program := decodeSHA3Jet(t)
	got, err := evaluateSHA3JetWithResult(t, program, EvalResult{Cost: 3})
	assertErrorCode(t, err, ErrRejected)
	if got.Accepted || got.Cost != 3 {
		t.Fatalf("evaluation=%+v want rejected cost=3", got)
	}
}

func TestEvaluateInternalFailClosedPaths(t *testing.T) {
	_, err := Program{decoded: true}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrDecode)

	_, err = Program{decoded: true, hasJet: true, jetKey: jetKey{id: 0xffff}}.Evaluate(EvalOptions{
		JetEvaluator: func(Jet) (EvalResult, error) { return EvalResult{Accepted: true}, nil },
	})
	assertErrorCode(t, err, ErrDecode)

	sentinel := errors.New("jet hook failed")
	_, err = decodeSHA3Jet(t).Evaluate(EvalOptions{
		JetEvaluator: func(Jet) (EvalResult, error) { return EvalResult{}, sentinel },
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v want sentinel", err)
	}

	got, err := Program{decoded: true, evalSteps: MaxExecCost/StepCost + 1}.Evaluate(EvalOptions{})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if !got.Accepted || got.Cost != MaxExecCost {
		t.Fatalf("over-cap evaluation=%+v want accepted cost=%d", got, MaxExecCost)
	}
}

func TestRubinJetCMRHelperExamples(t *testing.T) {
	zero := [32]byte{}
	if got := RubinJetCMR(zero, 1); got != hex32("f2a8d5366d7ca4a4960440c95e3c465ea3df2a5a14c0d58198c65d8aa1e796de") {
		t.Fatalf("zero helper cmr=%x", got)
	}
	var ones [32]byte
	copy(ones[:], "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11")
	got := RubinJetCMR(ones, 4_294_967_296)
	if got != hex32("2e4a23492db398e98317272348128f39da97983f5cbab825d5389c2c8b908e11") {
		t.Fatalf("ones helper cmr=%x", got)
	}
}

func evaluateSharedExecCase(t *testing.T, tc sharedExecCase) (EvalResult, error) {
	t.Helper()
	var program Program
	if tc.ProgramHex != "" {
		got, err := Decode(hx(tc.ProgramHex), hx(tc.WitnessHex), DecodeOptions{SemanticsVersion: SemanticsVersion})
		if err != nil {
			return EvalResult{}, err
		}
		program = got
	} else {
		program = Program{
			decoded:        true,
			evalSteps:      tc.EvalSteps,
			frameBitWidths: append([]uint64(nil), tc.FrameBitWidths...),
		}
	}
	opts := EvalOptions{}
	if program.hasJet {
		opts.JetEvaluator = func(Jet) (EvalResult, error) {
			return EvalResult{Accepted: tc.JetAccepted, Cost: tc.JetCost}, nil
		}
	}
	return program.Evaluate(opts)
}

func registryRow(id uint16, subOp uint8) (jetRegistryRow, bool) {
	for _, row := range jetRegistryRows {
		if row.jet.ID == id && row.jet.SubOp == subOp {
			return row, true
		}
	}
	return jetRegistryRow{}, false
}

func hx(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	segments := append([]string{filepath.Dir(currentFile), "..", "..", "..", ".."}, parts...)
	return filepath.Clean(filepath.Join(segments...))
}

func optionalCMR(s string) *[32]byte {
	if s == "" {
		return nil
	}
	out := hex32(s)
	return &out
}

func decodeSHA3Jet(t *testing.T) Program {
	t.Helper()
	program, err := Decode(hx("60"), nil, DecodeOptions{SemanticsVersion: SemanticsVersion})
	if err != nil {
		t.Fatalf("Decode sha3 jet: %v", err)
	}
	return program
}

func evaluateSHA3JetWithResult(t *testing.T, program Program, result EvalResult) (EvalResult, error) {
	t.Helper()
	calls := 0
	got, err := program.Evaluate(EvalOptions{
		JetEvaluator: func(j Jet) (EvalResult, error) {
			calls++
			if j.Name != "sha3_256" {
				t.Fatalf("jet=%s want sha3_256", j.Name)
			}
			return result, nil
		},
	})
	if calls != 1 && !hasErrorCode(err, ErrDecode) {
		t.Fatalf("JetEvaluator calls=%d want 1", calls)
	}
	return got, err
}

func repeated(value uint64, count int) []uint64 {
	out := make([]uint64, count)
	for i := range out {
		out[i] = value
	}
	return out
}

func assertErrorCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if !hasErrorCode(err, want) {
		t.Fatalf("error=%v want code %q", err, want)
	}
}

func hasErrorCode(err error, want ErrorCode) bool {
	var got *Error
	return errors.As(err, &got) && got.Code == want
}
