package mdbx

import (
	"reflect"
	"testing"
	"unsafe"
)

// A22, M48: the L1 control objects and treeStoredBodyV1's 32-byte block copy fit C = 4,096 (D14-2, D25).
func TestTreeDeltaControlBoundV1(t *testing.T) {
	if treeControlBytesV1 != 4096 {
		t.Fatalf("treeControlBytesV1 = %d", treeControlBytesV1)
	}
	var leaves treeLeafIterV1
	total := uint64(unsafe.Sizeof(treeRecorderV1{})) + uint64(unsafe.Sizeof(treeDeltaV1{})) + uint64(unsafe.Sizeof(treeKeysV1{})) + 2*uint64(unsafe.Sizeof(leaves)) + 32
	if total > 4096 {
		t.Fatalf("control objects %d bytes", total)
	}
	if size := uint64(unsafe.Sizeof(treeDescV1{})); size > 128 || size != treeDescSizeV1 {
		t.Fatalf("descriptor %d bytes, treeDescSizeV1 %d", size, treeDescSizeV1)
	}
}

// H10 (a), M-K-PTR: the key scratch K holds no field that can carry a Go pointer (D28, G10).
func TestTreeDeltaKeyScratchPointerFreeV1(t *testing.T) {
	var walk func(typ reflect.Type, path string)
	walk = func(typ reflect.Type, path string) {
		switch typ.Kind() {
		case reflect.Pointer, reflect.UnsafePointer, reflect.Slice, reflect.String, reflect.Map, reflect.Chan, reflect.Func, reflect.Interface:
			t.Errorf("key scratch field %s has kind %s", path, typ.Kind())
		case reflect.Array:
			walk(typ.Elem(), path+"[]")
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				walk(typ.Field(i).Type, path+"."+typ.Field(i).Name)
			}
		default:
		}
	}
	walk(reflect.TypeFor[treeKeysV1](), "treeKeysV1")
}
