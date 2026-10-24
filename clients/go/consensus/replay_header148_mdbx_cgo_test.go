//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
)

type replay148View struct {
	inv   HeaderCandidateInventory148V1
	calls int
	limit uint64
}

func (v *replay148View) Inventory148V1(limit uint64) HeaderCandidateInventory148V1 {
	v.calls++
	v.limit = limit
	return v.inv
}

func (v *replay148View) ProtectV1(uint64) (bool, func()) { return true, func() {} }
func (v *replay148View) VersionV1() uint64               { return v.inv.Version }
func (v *replay148View) Header148V1([32]byte, *[148]byte) bool {
	return false
}

// replay148NilView answers on a nil receiver, so a typed-nil provider is observable.
type replay148NilView struct{}

func (*replay148NilView) Inventory148V1(uint64) HeaderCandidateInventory148V1 {
	return HeaderCandidateInventory148V1{Status: HeaderCandidateCapacityRefusedV1, Version: 7}
}
func (*replay148NilView) ProtectV1(uint64) (bool, func()) { return true, func() {} }

func replay148Check(t *testing.T, name string, inv HeaderCandidateInventory148V1, limit uint64, want string) *replay148View {
	t.Helper()
	view := &replay148View{inv: inv}
	got, result := replayEntryInventory148(view, limit)
	if result != want || !reflect.DeepEqual(got, inv) || view.calls != 1 || view.limit != limit {
		t.Fatalf("%s: result %q want %q, inventory changed %v, calls %d, limit %d want %d", name, result, want, !reflect.DeepEqual(got, inv), view.calls, view.limit, limit)
	}
	return view
}

func TestReplayEntryInventory148Decisions(t *testing.T) {
	tips, headers := make([][32]byte, 2), make([][148]byte, 3)
	complete := HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Version: 3, Tips: tips, Headers: headers, Bytes: 508}
	replay148Check(t, "I1", complete, 508, "")
	replay148Check(t, "I2", HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1}, 0, "")
	replay148Check(t, "I3 incomplete", HeaderCandidateInventory148V1{Status: HeaderCandidateIncompleteV1}, 508, replayEntryRecovery)
	replay148Check(t, "I3 capacity", HeaderCandidateInventory148V1{Status: HeaderCandidateCapacityRefusedV1}, 508, selectedSideCapacity)
	replay148Check(t, "I4", complete, 507, selectedSideInvariant)
	at116 := complete
	at116.Bytes = 412
	replay148Check(t, "I5", at116, 508, selectedSideInvariant)
	for _, status := range []HeaderCandidateStatusV1{HeaderCandidateIncompleteV1, HeaderCandidateCapacityRefusedV1} {
		nonzero := complete
		nonzero.Status = status
		replay148Check(t, fmt.Sprintf("I6 nonzero status %d", status), nonzero, 508, selectedSideInvariant)
	}
	for _, status := range []HeaderCandidateStatusV1{0, 4} {
		replay148Check(t, fmt.Sprintf("I6 unknown status %d", status), HeaderCandidateInventory148V1{Status: status}, 508, selectedSideInvariant)
	}
}

// replay148NilCall turns a panic on the nil view into a value the I7 assertion checks.
func replay148NilCall() (got HeaderCandidateInventory148V1, result string, panicked any) {
	defer func() { panicked = recover() }()
	got, result = replayEntryInventory148(nil, 508)
	return got, result, nil
}

func TestReplayEntryInventory148NilViews(t *testing.T) {
	got, result, panicked := replay148NilCall()
	if panicked != nil || result != replayEntryRecovery || !reflect.DeepEqual(got, HeaderCandidateInventory148V1{}) {
		t.Fatalf("I7 nil view: %q %+v panic %v", result, got, panicked)
	}
	var typed *replay148NilView
	got, result = replayEntryInventory148(typed, 508)
	if result != selectedSideCapacity || got.Version != 7 {
		t.Fatalf("I7 typed nil: %q version %d", result, got.Version)
	}
}

func TestReplayEntryInventory148LargestCount(t *testing.T) {
	backing := make([][148]byte, 547_320)
	accepted := HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Headers: backing[:547_319], Bytes: 81_003_212}
	replay148Check(t, "I8 largest", accepted, 81_003_330, "")
	above := HeaderCandidateInventory148V1{Status: HeaderCandidateCompleteV1, Headers: backing, Bytes: 81_003_360}
	replay148Check(t, "I8 above", above, 81_003_330, selectedSideInvariant)
}

func TestReplayHeader148Limits(t *testing.T) {
	if replayEntryWalk148Bytes != 404_134 || replayEntryInventory148Limit != 81_003_330 || replayRecoveryMin148Bytes != 3_550_886 {
		t.Errorf("L1 walk %d limit %d M %d", replayEntryWalk148Bytes, replayEntryInventory148Limit, replayRecoveryMin148Bytes)
	}
	if replayInvLimit148(0) != 81_003_330 || replayInvLimit148(154_611_151) != 81_003_330 {
		t.Errorf("L1 lane limits %d %d", replayInvLimit148(0), replayInvLimit148(154_611_151))
	}
	if replayInvLimit(154_611_151) != 71_815_566 || replayRecoveryMinBytes != 3_550_822 {
		t.Errorf("L1 116 pins %d %d", replayInvLimit(154_611_151), replayRecoveryMinBytes)
	}
	if replayInvLimit148(3_550_886) != 0 || replayInvLimit148(3_550_886+276) != 148 {
		t.Errorf("L2 %d %d", replayInvLimit148(3_550_886), replayInvLimit148(3_550_886+276))
	}
}

func TestReplayHeaderBind148(t *testing.T) {
	want := Initial148Header{Version: 0x01020304, PrevBlockHash: [32]byte{0x11, 1}, MerkleRoot: [32]byte{0x22, 2}, Timestamp: 0x0506070809, Target: [32]byte{0x33, 3}, UtxoRoot: [32]byte{0x44, 4}, Nonce: 0x0a0b0c0d0e}
	raw := EncodeInitial148Header(want)
	hash := sha3_256(raw[:])
	if got, ok := replayHeaderBind148(raw[:], hash); !ok || got != want {
		t.Fatalf("H1: ok %v header %+v", ok, got)
	}
	changed := raw
	changed[108] ^= 0xff
	if _, ok := replayHeaderBind148(changed[:], hash); ok {
		t.Fatal("H2 changed utxo_root byte bound the original hash")
	}
	long := append(raw[:], 0)
	for _, short := range [][]byte{raw[:116], raw[:147], long} {
		if _, ok := replayHeaderBind148(short, sha3_256(short)); ok {
			t.Fatalf("H3 length %d bound", len(short))
		}
	}
	if prefixHash, err := BlockHash(raw[:116]); err != nil {
		t.Fatalf("H3 116 hash: %v", err)
	} else if _, ok := replayHeaderBind148(raw[:116], prefixHash); ok {
		t.Fatal("H3 116 prefix bound its 116 hash")
	}
	for _, empty := range [][]byte{nil, {}} {
		if _, ok := replayHeaderBind148(empty, hash); ok {
			t.Fatal("H4 empty bound")
		}
	}
}

func TestReplayHeader148Shape(t *testing.T) {
	var view ReplayHeaderCandidateView148V1 = &replay148View{}
	var _ HeaderCandidateView148V1 = view
	field, _ := reflect.TypeOf(HeaderCandidateInventory148V1{}).FieldByName("Headers")
	if field.Type.Elem() != reflect.TypeOf([148]byte{}) {
		t.Fatalf("V1 header element %v", field.Type.Elem())
	}
	iface := reflect.TypeOf((*ReplayHeaderCandidateView148V1)(nil)).Elem()
	var methods []string
	for i := range iface.NumMethod() {
		methods = append(methods, iface.Method(i).Name)
	}
	if !slices.Equal(methods, []string{"Header148V1", "Inventory148V1", "ProtectV1", "VersionV1"}) {
		t.Fatalf("V1 methods %v", methods)
	}
}
