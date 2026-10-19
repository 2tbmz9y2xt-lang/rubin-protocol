package mdbx

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

type ordinaryEnvelopeCase struct {
	name  string
	input OrdinaryEnvelopeInputV1
	bound uint64
	want  error
}

func ordinaryEnvelopeInput(hOld, f, d, c uint32) OrdinaryEnvelopeInputV1 {
	return OrdinaryEnvelopeInputV1{KPair: 1, R: 805306368, LRet: 18446744073709551615,
		HOld: hOld, F: f, D: d, C: c}
}

// Literal thresholds come from the frozen contract, not evaluator expressions.
// These synthetic scalars do not certify a complete reachable ENTRY snapshot.
func ordinaryEnvelopeBounds() []ordinaryEnvelopeCase {
	e01 := ordinaryEnvelopeInput(100, 99, 1, 1)
	e04 := e01
	e04.R = 1073741824
	e06 := ordinaryEnvelopeInput(20159, 20159, 0, 2)
	e06ExtraK := e06
	e06ExtraK.KPair = 2
	e07 := e06
	e07.SCurrentOld, e07.SLagOld = 56, 56
	e10 := e06
	e10.SCurrentOld = 412316860472
	e12 := ordinaryEnvelopeInput(100, 99, 1, 2)
	e12.UndoOld = 56
	return []ordinaryEnvelopeCase{
		{name: "E01", input: e01, bound: 1154590253},
		{name: "E02", input: ordinaryEnvelopeInput(100, 100, 0, 2), bound: 1590408517},
		{name: "E03", input: ordinaryEnvelopeInput(101, 100, 1, 5), bound: 2897862973},
		{name: "E04_actual_R", input: e04, bound: 1423025709},
		{name: "E05_first_companion", input: ordinaryEnvelopeInput(15119, 15118, 1, 2), bound: 1941363153},
		{name: "E06_burst", input: e06, bound: 315295676075},
		{name: "H01_E06_extra_KPair", input: e06ExtraK, bound: 315295676076},
		{name: "E07_independent_roles", input: e07, bound: 315295676639},
		{name: "E08_no_new_lag", input: ordinaryEnvelopeInput(20160, 20160, 0, 2), bound: 1593219829},
		{name: "E09_two_bursts", input: ordinaryEnvelopeInput(20159, 20159, 0, 1440), bound: 1255791287361},
		{name: "E10_above_cap", input: e10, bound: 2391605580619},
		{name: "E11_u32_height", input: ordinaryEnvelopeInput(4294967293, 4294967293, 0, 2), bound: 963661349285},
		{name: "E12_original_undo", input: e12, bound: 1590408687},
		{name: "schedule_last_no_burst", input: ordinaryEnvelopeInput(15837, 15837, 0, 2), bound: 1592171173},
		{name: "schedule_next_720", input: ordinaryEnvelopeInput(15838, 15838, 0, 2), bound: 315294708283},
		{name: "falling_100_to_99", input: ordinaryEnvelopeInput(100, 98, 2, 1), bound: 1154590253},
		{name: "falling_1439_to_1438", input: ordinaryEnvelopeInput(1439, 1437, 2, 1), bound: 1154740221},
		{name: "cutoff_1440_equal", input: ordinaryEnvelopeInput(1440, 1439, 1, 1), bound: 1154740333},
	}
}

func ordinaryEnvelopeBoundaryBounds() []ordinaryEnvelopeCase {
	e08 := ordinaryEnvelopeInput(20160, 20160, 0, 2)
	rows := []ordinaryEnvelopeCase{}
	// SLagOld=0 is E08; every additional row distinguishes a floor or root edge.
	for _, edge := range []struct{ state, bound uint64 }{
		{55, 1593219884}, {56, 1593219953}, {111, 1593220008}, {112, 1593220179},
	} {
		input := e08
		input.SLagOld = edge.state
		rows = append(rows, ordinaryEnvelopeCase{name: fmt.Sprintf("lag_floor_%d", edge.state), input: input, bound: edge.bound})
	}
	e08.SCurrentOld, e08.SLagOld = 56, 56
	rows = append(rows, ordinaryEnvelopeCase{name: "equal_roles", input: e08, bound: 1593220235})
	e01 := ordinaryEnvelopeInput(100, 99, 1, 1)
	e01.KPair = 0
	return append(rows, ordinaryEnvelopeCase{name: "zero_KPair", input: e01, bound: 1154590252})
}

func ordinaryEnvelopeDomainCases() []ordinaryEnvelopeCase {
	e01 := ordinaryEnvelopeInput(100, 99, 1, 1)
	zeroC, wrongF, lagBeforeGenesis := e01, e01, e01
	zeroC.C, wrongF.F, lagBeforeGenesis.SLagOld = 0, 98, 1
	undoWithoutDisconnect := ordinaryEnvelopeInput(100, 100, 0, 2)
	undoWithoutDisconnect.UndoOld = 1
	lowR, zeroR, lowLimit := e01, e01, e01
	lowR.R, zeroR.R, lowLimit.LRet = 805306367, 0, 805306367
	return []ordinaryEnvelopeCase{
		{name: "R02_C_zero", input: zeroC, want: errOrdinaryEnvelopeInput},
		{name: "R02_wrong_F", input: wrongF, want: errOrdinaryEnvelopeInput},
		{name: "R02_both_suffixes_long", input: ordinaryEnvelopeInput(2000, 559, 1441, 1441), want: errOrdinaryEnvelopeInput},
		{name: "R02_new_suffix_long", input: ordinaryEnvelopeInput(100, 100, 0, 1441), want: errOrdinaryEnvelopeInput},
		{name: "R02_D_exceeds_height", input: ordinaryEnvelopeInput(100, 0, 101, 101), want: errOrdinaryEnvelopeInput},
		{name: "R02_cutoff_regression", input: ordinaryEnvelopeInput(1440, 1438, 2, 1), want: errOrdinaryEnvelopeInput},
		{name: "R02_height_overflow", input: ordinaryEnvelopeInput(4294967295, 4294967295, 0, 2), want: errOrdinaryEnvelopeInput},
		{name: "R02_direct", input: ordinaryEnvelopeInput(100, 100, 0, 1), want: errOrdinaryEnvelopeInput},
		{name: "R02_all_zero", input: OrdinaryEnvelopeInputV1{}, want: errOrdinaryEnvelopeInput},
		{name: "R03_undo_without_disconnect", input: undoWithoutDisconnect, want: errOrdinaryEnvelopeInput},
		{name: "R03_lag_before_genesis", input: lagBeforeGenesis, want: errOrdinaryEnvelopeInput},
		{name: "R04_low_R", input: lowR, want: errOrdinaryEnvelopeInput},
		{name: "R04_zero_R", input: zeroR, want: errOrdinaryEnvelopeInput},
		{name: "R04_low_limit", input: lowLimit, want: errOrdinaryEnvelopeInput},
	}
}

func ordinaryEnvelopeCapacityCases() []ordinaryEnvelopeCase {
	e01 := ordinaryEnvelopeInput(100, 99, 1, 1)
	exact := e01
	exact.KPair = 18446744072554961363
	exactMinus := exact
	exactMinus.LRet = 18446744073709551614
	exceeds := exact
	exceeds.KPair = 18446744072554961364
	minimum, maxR := e01, e01
	minimum.LRet, maxR.R = 805306368, 18446744073709551615
	treeAddition := ordinaryEnvelopeInput(20160, 20160, 0, 2)
	treeAddition.SLagOld = 6720000000000000000
	return []ordinaryEnvelopeCase{
		{name: "exact_u64", input: exact},
		{name: "exact_u64_minus_one", input: exactMinus, want: errOrdinaryEnvelopeCapacity},
		{name: "exceeds_u64", input: exceeds, want: errOrdinaryEnvelopeCapacity},
		{name: "R04_minimum_configuration", input: minimum, want: errOrdinaryEnvelopeCapacity},
		{name: "R04_maximum_configuration", input: maxR, want: errOrdinaryEnvelopeCapacity},
		{name: "R06_tree_addition", input: treeAddition, want: errOrdinaryEnvelopeCapacity},
	}
}

func ordinaryEnvelopeOverflowCases() []ordinaryEnvelopeCase {
	e01 := ordinaryEnvelopeInput(100, 99, 1, 1)
	k, sc, undo := e01, e01, e01
	k.KPair, sc.SCurrentOld, undo.UndoOld = 18446744073709551615, 18446744073709551615, 18446744073709551615
	sl := ordinaryEnvelopeInput(20160, 20160, 0, 2)
	sl.SLagOld = 18446744073709551615
	return []ordinaryEnvelopeCase{
		{name: "R05_KPair_overflow", input: k, want: errOrdinaryEnvelopeCapacity},
		{name: "R05_current_overflow", input: sc, want: errOrdinaryEnvelopeCapacity},
		{name: "R05_undo_overflow", input: undo, want: errOrdinaryEnvelopeCapacity},
		{name: "R05_lag_product_overflow", input: sl, want: errOrdinaryEnvelopeCapacity},
	}
}

func ordinaryEnvelopeAssert(t *testing.T, input OrdinaryEnvelopeInputV1, want error) {
	t.Helper()
	before := input
	got := EvaluateOrdinaryEnvelopeV1(input)
	if any(got) != any(want) {
		t.Fatalf("EvaluateOrdinaryEnvelopeV1(%+v) = %v, want direct %v", input, got, want)
	}
	if input != before {
		t.Fatalf("input changed: got %+v, want %+v", input, before)
	}
	if got == nil {
		return
	}
	text := "invalid ordinary envelope input"
	if any(want) == any(errOrdinaryEnvelopeCapacity) {
		text = "ordinary envelope capacity unavailable"
	}
	if got.Error() != text || errors.Unwrap(got) != nil {
		t.Fatalf("error = %q, unwrap = %v; want %q without cause", got.Error(), errors.Unwrap(got), text)
	}
}

func ordinaryEnvelopeClassifierCases(t *testing.T) {
	t.Helper()
	for _, row := range []struct {
		name string
		err  error
		want bool
	}{
		{"direct_capacity", errOrdinaryEnvelopeCapacity, true},
		{"nil", nil, false},
		{"direct_input", errOrdinaryEnvelopeInput, false},
		{"same_text", errors.New("ordinary envelope capacity unavailable"), false},
		{"wrapped", fmt.Errorf("wrapped: %w", errOrdinaryEnvelopeCapacity), false},
		{"joined", errors.Join(errOrdinaryEnvelopeCapacity), false},
		{"typed_nil", (*os.PathError)(nil), false},
	} {
		t.Run("H03_"+row.name, func(t *testing.T) {
			if got := IsOrdinaryEnvelopeCapacity(row.err); got != row.want {
				t.Fatalf("IsOrdinaryEnvelopeCapacity(%v) = %v, want %v", row.err, got, row.want)
			}
		})
	}
}

func ordinaryEnvelopeCopyIndependence(t *testing.T) {
	t.Helper()
	input := ordinaryEnvelopeInput(100, 99, 1, 1)
	input.LRet = 1154590253
	saved := input
	ordinaryEnvelopeAssert(t, input, nil)
	input.LRet = 1154590252
	ordinaryEnvelopeAssert(t, input, errOrdinaryEnvelopeCapacity)
	ordinaryEnvelopeAssert(t, saved, nil)
	input.C = 0
	ordinaryEnvelopeAssert(t, input, errOrdinaryEnvelopeInput)
	ordinaryEnvelopeAssert(t, saved, nil)
	ordinaryEnvelopeAssert(t, input, errOrdinaryEnvelopeInput)
}

func TestOrdinaryEnvelopeV1(t *testing.T) {
	for _, row := range append(ordinaryEnvelopeBounds(), ordinaryEnvelopeBoundaryBounds()...) {
		for _, threshold := range []struct {
			name  string
			limit uint64
			want  error
		}{
			{"U_minus_one", row.bound - 1, errOrdinaryEnvelopeCapacity},
			{"U", row.bound, nil},
			{"U_plus_one", row.bound + 1, nil},
		} {
			t.Run(row.name+"/"+threshold.name, func(t *testing.T) {
				input := row.input
				input.LRet = threshold.limit
				ordinaryEnvelopeAssert(t, input, threshold.want)
			})
		}
	}
	rows := append(ordinaryEnvelopeDomainCases(), ordinaryEnvelopeCapacityCases()...)
	rows = append(rows, ordinaryEnvelopeOverflowCases()...)
	for _, row := range ordinaryEnvelopeDomainCases() {
		input := row.input
		input.KPair = 18446744073709551615
		rows = append(rows, ordinaryEnvelopeCase{name: row.name + "_before_capacity", input: input, want: errOrdinaryEnvelopeInput})
	}
	for _, row := range ordinaryEnvelopeOverflowCases() {
		input := row.input
		input.C = 0
		rows = append(rows, ordinaryEnvelopeCase{name: row.name + "_C_zero_first", input: input, want: errOrdinaryEnvelopeInput})
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) { ordinaryEnvelopeAssert(t, row.input, row.want) })
	}
	ordinaryEnvelopeClassifierCases(t)
	t.Run("H02_copy_independence", ordinaryEnvelopeCopyIndependence)
}
