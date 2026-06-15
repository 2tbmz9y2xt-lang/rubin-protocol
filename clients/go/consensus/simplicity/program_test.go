package simplicity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var errSink error

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

	got, err := evaluateSHA3JetWithResult(t, program, EvalResult{Accepted: true, Cost: MaxExecCost + 1})
	assertErrorCode(t, err, ErrBudgetExceeded)
	if !got.Accepted || got.Cost != MaxExecCost {
		t.Fatalf("evaluation=%+v want accepted saturated cost=%d", got, MaxExecCost)
	}
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
