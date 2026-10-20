package mdbx

import (
	"testing"
	"unsafe"
)

// A22, M48: the L1 control objects and treeStoredBodyV1's 32-byte block copy fit C = 4,096 (D14-2, D25).
func TestTreeDeltaControlBoundV1(t *testing.T) {
	if treeControlBytesV1 != 4096 {
		t.Fatalf("treeControlBytesV1 = %d", treeControlBytesV1)
	}
	var leaves treeLeafIterV1
	total := uint64(unsafe.Sizeof(treeRecorderV1{})) + uint64(unsafe.Sizeof(treeDeltaV1{})) + 2*uint64(unsafe.Sizeof(leaves)) + 32
	if total > 4096 {
		t.Fatalf("control objects %d bytes", total)
	}
	if size := unsafe.Sizeof(treeDescV1{}); size > 128 {
		t.Fatalf("descriptor %d bytes", size)
	}
}
