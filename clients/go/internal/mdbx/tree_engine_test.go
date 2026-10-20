package mdbx

import (
	"reflect"
	"testing"
)

// treeSameErrorV1 is pointer identity of two errors, so a wrapper or a copy never matches.
func treeSameErrorV1(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	return g.Type() == w.Type() && g.Kind() == reflect.Pointer && g.Pointer() == w.Pointer()
}

// A10, A13, H5: budget arithmetic, the ledger view and the exact constants (literals from CSM line 358, 671-672).
func TestTreeBudgetAndConstantsV1(t *testing.T) {
	const maxStateEntry = 65596
	b := treeBudgetV1{held: 10}
	if !b.drawV1(10) || b.drawV1(1) || b.used != 10 {
		t.Fatalf("held 10 draw: %+v", b)
	}
	b.returnV1(4)
	if !b.drawV1(4) || b.drawV1(1) {
		t.Fatalf("return then draw: %+v", b)
	}
	top := treeBudgetV1{held: 1<<64 - 1, used: 1<<64 - 2}
	if !top.drawV1(1) || top.drawV1(1) {
		t.Fatalf("u64 top: %+v", top)
	}
	wrap := treeBudgetV1{held: 5, used: 3}
	if wrap.drawV1(1<<64-1) || wrap.used != 3 {
		t.Fatalf("wraparound draw: %+v", wrap)
	}
	view := treeBudgetV1{held: 8}
	ledger := view.ledgerV1()
	if ledger.chargeV1(5) != nil || view.used != 5 {
		t.Fatalf("view charge: %+v", view)
	}
	if err := ledger.chargeV1(4); !treeSameErrorV1(err, errOperationReservationCapacity) || view.used != 5 {
		t.Fatalf("view refusal: %v %+v", err, view)
	}
	ledger.releaseV1(5)
	if ledger.chargeV1(8) != nil {
		t.Fatalf("view release: %+v", view)
	}
	over := treeBudgetV1{held: 10}
	over.drawV1(3)
	over.returnV1(4)
	if over.held != 0 || over.used != 0 || over.drawV1(1) || !treeSameErrorV1(over.ledgerV1().chargeV1(1), errOperationReservationCapacity) {
		t.Fatalf("over-return: %+v", over)
	}
	constants := [...]uint64{treeWindowBytesV1, treeFixedBytesV1, treeValueBytesV1, treeScratchBytesV1, treeNodeWorkBytesV1}
	if constants != [...]uint64{65536, 4096, maxStateEntry - 36, 2 * maxStateEntry, (288 + 1) * 512} {
		t.Fatalf("charge constants %v", constants)
	}
	encodings := [...]uint8{treeForwardV1, treeInverseV1, treeKindDirectApplyV1, treeKindConnectV1, treeKindReplayNextV1, treeKindFirstGenesisV1, treeKindRestoreOldV1, treeKindLagForwardV1, treeKindDisconnectV1, treeKindRollbackNewV1, treeKindLagReverseV1}
	if encodings != [...]uint8{1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9} || treeWriterV1 != 1 || treeReadbackV1 != 2 {
		t.Fatalf("encodings %v", encodings)
	}
	primitive := treePrimitiveV1{direction: treeForwardV1, kind: treeKindLagForwardV1}
	body, leaf := treeBodyV1{pair: true}, treeLeafV1{newPresent: true}
	var leaves treeLeavesV1
	if primitive.direction != 1 || !body.pair || !leaf.newPresent || leaves != nil {
		t.Fatal("declaration shapes")
	}
}

func BenchmarkTreeBudgetDrawV1(b *testing.B) {
	b.ReportAllocs()
	budget := treeBudgetV1{held: 1 << 40}
	for i := 0; i < b.N; i++ {
		if !budget.drawV1(64) {
			budget.used = 0
		}
	}
}
