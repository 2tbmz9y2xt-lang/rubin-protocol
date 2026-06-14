package simplicity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	raw, err := os.ReadFile(repoPath("conformance", "fixtures", "protocol", "simplicity_program_encoding_corpus_v1.json"))
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
	} else if err.Error() != "EOF" {
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

func hx(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func repoPath(parts ...string) string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
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
