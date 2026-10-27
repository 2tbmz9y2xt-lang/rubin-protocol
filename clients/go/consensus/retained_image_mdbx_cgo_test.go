//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

func TestRetainedImageMDBX(t *testing.T) {
	t.Run("D4-healthy1077", riHealthy)
	t.Run("D8-context-lifetime", riControls)
	t.Run("D8-D16-domain-before-roles", riDomain)
	t.Run("FailureCarrier", riCarriers)
	t.Run("D2-D5-D26-owner-union", riOptional)
	t.Run("D3-ARCHIVE16385", riArchive)
	t.Run("D12-acquisition-frames", riFrames)
	if unsafe.Sizeof(retainedPreImageV1{}) != 64 || unsafe.Sizeof(retainedReadV1{}) != 576 {
		t.Fatalf("source layouts result=%d context=%d", unsafe.Sizeof(retainedPreImageV1{}), unsafe.Sizeof(retainedReadV1{}))
	}
}

func riGenesis(t *testing.T) (*btWorld, []byte, [32]byte) {
	t.Helper()
	w := btNew(t)
	raw := initial148BlockGenesis(t)
	r := btRequest(raw, 0)
	r.Kind, r.Endpoint.CumulativeChainwork = 4, [40]byte{39: 1}
	result, _, _ := w.run(t, []blockTreeRequestV1{r}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil && len(raw) == 298 && ValidateInitial148BlockBodyCommitments(raw) == nil, "healthy actual genesis: %v", result.err)
	return w, raw, r.Block
}

// The outer grant funds copied scalar controls; the read grant spans every context use and clear.
func riContext(t *testing.T, w *btWorld, late *[32]byte, use func(*retainedReadV1) error) error {
	t.Helper()
	var result error
	err := w.owner.WithOperation(mdbx.TreeOperation, func(account *mdbx.OperationAccount) error {
		err := account.WithReservation(8192, func() error {
			return account.WithReservation(2313928, func() error {
				return w.s.View(func(reader *mdbx.Reader) error {
					var read retainedReadV1
					defer func() { read = retainedReadV1{} }()
					if err := prepareRetainedReadV1(&read, reader, account, late); err != nil {
						logicalMDBXAssert(t, reflect.ValueOf(read).IsZero(), "failed initializer changed its destination")
						return err
					}
					return use(&read)
				})
			})
		})
		result = err
		ran := 0
		if err := account.WithReservation(402653184, func() error { ran++; return nil }); err != nil || ran != 1 {
			t.Fatalf("account not restored: %d/%v", ran, err)
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "read account owner: %v", err)
	btReservationsReleased(t, w.owner)
	return result
}

func riRead(t *testing.T, w *btWorld, late *[32]byte) (retainedPreImageV1, error) {
	t.Helper()
	var result retainedPreImageV1
	err := riContext(t, w, late, func(read *retainedReadV1) error {
		var err error
		result, err = readDirectRetainedMDBXV1(read)
		return err
	})
	return result, err
}

func riAuthority(t *testing.T, w *btWorld, edit func(*mdbx.TreeAuthorityV1)) []byte {
	t.Helper()
	var encoded []byte
	err := w.s.View(func(reader *mdbx.Reader) error {
		a, present, err := reader.ReadTreeAuthorityV1()
		logicalMDBXAssert(t, err == nil && present, "read authority: %v", err)
		edit(&a)
		encoded, err = a.Encode()
		return err
	})
	logicalMDBXAssert(t, err == nil, "encode authority: %v", err)
	m := btMutation(0, []byte{2}, encoded)
	m.BeforePresent = true
	w.pair(t, m)
	return encoded
}

func riSide(t *testing.T, w *btWorld, raw []byte, g, h uint64) [32]byte {
	t.Helper()
	hash := sha3.Sum256(raw[:148])
	key, _ := mdbx.HeightKey(g, h)
	link := mdbx.ChainValue(hash, [32]byte(raw[4:36]), [40]byte{39: 1})
	w.pair(t, btMutation(4, hash[:], raw), btMutation(6, key, link))
	return hash
}

func riHealthy(t *testing.T) {
	w, genesis, hash := riGenesis(t)
	var expected mdbx.MutationBindingV1
	logicalMDBXAssert(t, w.s.View(func(reader *mdbx.Reader) error { var err error; expected, err = reader.MutationBindingV1(); return err }) == nil, "capture actual native provenance")
	if got, err := riRead(t, w, nil); err != nil || got.exactRet != 779 || got.binding != expected {
		t.Fatalf("genesis pre: %+v/%v want779", got, err)
	}
	child := bytes.Clone(genesis)
	child[140] ^= 1
	copy(child[4:36], hash[:])
	x := riSide(t, w, child, 3, 1)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
		a.Authority.Phase = 2
		a.Authority.Cleanup = &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 1, LastHeight: 1, NextHeight: 1}}}
	})
	got, err := riRead(t, w, &x)
	if err != nil || got.exactRet != 1077 || got.complete != ([2]retainedCompleteV1{}) {
		t.Fatalf("stored298 SIDE pre: %+v/%v want1077", got, err)
	}
	// The independently decoded actual source pins native53/logical89 and the canonical root.
	tx, _, _, consumed, err := ParseTx(genesis[149:])
	logicalMDBXAssert(t, err == nil && consumed == 149 && len(tx.Outputs[0].CovenantData) == 33, "genesis transaction shape: %v", err)
	entry := UtxoEntry{Value: tx.Outputs[0].Value, CovenantType: tx.Outputs[0].CovenantType, CovenantData: tx.Outputs[0].CovenantData, CreatedByCoinbase: true}
	entries := map[Outpoint]UtxoEntry{{Txid: initial148Array(t, initial148GenesisTxidHex), Vout: 0}: entry}
	logicalMDBXAssert(t, canonicalUTXORoot(entries) == initial148Array(t, initial148GenesisRootHex), "independent genesis root differs")
	err = riContext(t, w, nil, func(read *retainedReadV1) error {
		if err := readRetainedRolesV1(read); err != nil {
			return err
		}
		if read.roles != ([2]retainedRoleV1{{1, 89, 1, 1}, {2, 0, 0, 0}}) {
			t.Fatalf("exact independent role terms: %+v", read.roles)
		}
		_, err := readDirectRetainedMDBXV1(read)
		riLocal(t, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "role-only trusted consumer path: %v", err)
}

func riLocal(t *testing.T, err error) {
	t.Helper()
	var failure *logicalStateFailure
	if !errors.As(err, &failure) || failure == nil || failure.kind != logicalStateFailureLocalInvariant {
		t.Fatalf("local API classification: %T %v", err, err)
	}
}

func riResource(t *testing.T, err error, resource string) *RetainedProofFailureV1 {
	t.Helper()
	var failure *RetainedProofFailureV1
	if !errors.As(err, &failure) || failure == nil || failure.Resource != resource || !retainedCauseV1(failure.Cause) {
		t.Fatalf("resource result: %T %v want%s", err, err, resource)
	}
	if resource != "selected_damage" && failure.Damage != nil {
		t.Fatal("non-selected result contains damage")
	}
	return failure
}

func riControls(t *testing.T) {
	w := btNew(t)
	var closed *mdbx.OperationAccount
	logicalMDBXAssert(t, w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error { closed = a; return nil }) == nil, "capture expired account")
	var uninitialized retainedReadV1
	_, err := readDirectRetainedMDBXV1(nil)
	riLocal(t, err)
	_, err = readDirectRetainedMDBXV1(&uninitialized)
	riLocal(t, err)
	err = riContext(t, w, nil, func(read *retainedReadV1) error {
		riLocal(t, prepareRetainedReadV1(nil, read.reader, read.account, nil))
		nonzero := retainedReadV1{lateHeader: [32]byte{1}}
		lateHeader := nonzero.lateHeader
		riLocal(t, prepareRetainedReadV1(&nonzero, read.reader, read.account, nil))
		logicalMDBXAssert(t, nonzero.lateHeader == lateHeader, "unused nonzero destination header changed")
		nonzero.lateHeader = [32]byte{}
		logicalMDBXAssert(t, reflect.ValueOf(nonzero).IsZero(), "unused nonzero destination changed")
		before := *read
		authority, encodeErr := read.authority.Encode()
		logicalMDBXAssert(t, encodeErr == nil, "snapshot active authority: %v", encodeErr)
		riLocal(t, prepareRetainedReadV1(read, read.reader, read.account, nil))
		afterAuthority, encodeErr := read.authority.Encode()
		logicalMDBXAssert(t, encodeErr == nil && bytes.Equal(afterAuthority, authority), "active authority changed: %v", encodeErr)
		logicalMDBXAssert(t, len(read.authority.Progress.Payload) == len(before.authority.Progress.Payload) && cap(read.authority.Progress.Payload) == cap(before.authority.Progress.Payload) && reflect.ValueOf(read.authority.Progress.Payload).Pointer() == reflect.ValueOf(before.authority.Progress.Payload).Pointer(), "active authority source backing changed")
		a, b := read.authority.Authority, before.authority.Authority
		logicalMDBXAssert(t, a.Cleanup == b.Cleanup && a.Replay == b.Replay && a.Ordinary == b.Ordinary && a.PendingTargetProfile == b.PendingTargetProfile && a.ExcludedInvalidBranch == b.ExcludedInvalidBranch && a.SelectedSide == b.SelectedSide && a.DetachedSuffix == b.DetachedSuffix, "active authority pointers changed")
		if read.reader != before.reader || read.account != before.account || read.binding != before.binding || read.roles != before.roles || read.endpoints != before.endpoints || read.origin != before.origin || read.lateHeader != before.lateHeader || read.omitHeader != before.omitHeader || read.prepared != before.prepared {
			t.Fatal("active destination changed")
		}
		for _, bad := range []*mdbx.OperationAccount{nil, {}, closed} {
			var dst retainedReadV1
			want := bad.WithReservation(0, func() error { t.Fatal("bad account entered"); return nil })
			got := prepareRetainedReadV1(&dst, read.reader, bad, nil)
			if any(got) != any(want) || !reflect.ValueOf(dst).IsZero() {
				t.Fatalf("actual account error/zero output: %v/%v", got, want)
			}
		}
		var dst retainedReadV1
		wantBinding, wantErr := (*mdbx.Reader)(nil).MutationBindingV1()
		gotErr := prepareRetainedReadV1(&dst, nil, read.account, nil)
		if wantBinding != (mdbx.MutationBindingV1{}) || gotErr == nil || gotErr.Error() != wantErr.Error() || !reflect.ValueOf(dst).IsZero() {
			t.Fatalf("inactive binding: %v/%v", gotErr, wantErr)
		}
		first, err := readDirectRetainedMDBXV1(read)
		if err != nil || first.exactRet != 64 {
			t.Fatalf("empty paired image: %+v/%v", first, err)
		}
		second, err := readDirectRetainedMDBXV1(read)
		riLocal(t, err)
		if second != (retainedPreImageV1{}) {
			t.Fatal("reused context emitted partial evidence")
		}
		return nil
	})
	logicalMDBXAssert(t, err == nil, "control test source: %v", err)
	logicalMDBXAssert(t, w.s.Close() == nil, "close before fresh unverified Open")
	w.s, err = mdbx.OpenTreeV1(w.path, w.cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "fresh OpenTreeV1: %v", err)
	_, err = riRead(t, w, nil)
	var native *mdbx.EngineError
	logicalMDBXAssert(t, errors.As(err, &native) && native != nil && any(err) == any(native) && native.Operation == "get" && native.Class == "InvalidInput" && native.Code == 22 && native.Diagnostic == "canonical owner index is not verified" && native.Cause == nil, "unverified owner permission: %T %v", err, err)
}

func riDomain(t *testing.T) {
	for _, row := range []string{"NONE-recovery", "GC-recovery", "SIDE1440", "SIDE1441", "REPLAY-image", "ORDINARY-connect"} {
		t.Run(row, func(t *testing.T) {
			w := btNew(t)
			riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
				switch row {
				case "REPLAY-image":
					a.Authority.Phase, a.Authority.Lifecycle = 3, 2
					a.Authority.Replay = &mdbx.ReplayV1{TargetProfile: 1, TargetGenerationID: 3, Target: mdbx.RecoveryTargetV1{TipHeight: 1, TipHash: [32]byte{1}, CumulativeChainwork: [40]byte{39: 1}}}
					a.SourceKind, a.TargetLagGenerationID, a.Progress = 2, 4, mdbx.TreeProgressV1{Kind: 1, Payload: []byte{1}}
					return
				case "ORDINARY-connect":
					point := mdbx.AuthorityPointV1{Height: 1, BlockHash: [32]byte{2}}
					a.Authority.Phase, a.Authority.Lifecycle = 4, 2
					a.Authority.Ordinary = &mdbx.OrdinaryApplyV1{Stage: 2, Cursor: &point, Target: point, OldSuffix: []mdbx.AuthorityPointV1{{Height: 1, BlockHash: [32]byte{1}}}, NewSuffix: []mdbx.AuthorityPointV1{point}, CapturedSelectedSide: &mdbx.SelectedSideV1{GenerationID: 3, F: 0, TipHeight: 1, TipHash: point.BlockHash, RowCount: 1, LogicalBytes: 298, CumulativeChainwork: [40]byte{39: 1}}}
					return
				}
				if row == "SIDE1440" || row == "SIDE1441" {
					last := uint64(1439)
					if row == "SIDE1441" {
						last = 1440
					}
					a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, LastHeight: last}}}
					return
				}
				profile := mdbx.StorageProfileArchiveV1
				a.Authority.Lifecycle, a.Authority.PendingTargetProfile = 2, &profile
				if row == "GC-recovery" {
					a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}}
				}
			})
			called := 0
			err := riContext(t, w, nil, func(*retainedReadV1) error { called++; return nil })
			if row == "SIDE1440" {
				logicalMDBXAssert(t, err == nil && called == 1, "exact aggregate1440 refused before role consumer: %v", err)
				return
			}
			riLocal(t, err)
			logicalMDBXAssert(t, called == 0, "unsupported domain reached role/quantity consumer")
		})
	}
}

type riNilCause struct{}

func (*riNilCause) Error() string { panic("typed-nil cause invoked") }

type (
	riNilMap   map[string]int
	riNilSlice []byte
	riNilFunc  func()
	riNilChan  chan int
)

func (riNilMap) Error() string   { panic("nil map cause invoked") }
func (riNilSlice) Error() string { panic("nil slice cause invoked") }
func (riNilFunc) Error() string  { panic("nil func cause invoked") }
func (riNilChan) Error() string  { panic("nil chan cause invoked") }

func riCarriers(t *testing.T) {
	base := errors.New("actual source")
	wrapped := fmt.Errorf("outer: %w", base)
	for _, resource := range []string{"storage_capacity", "canonical_artifact_read", "branch_data", "selected_damage"} {
		artifacts := []string{""}
		if resource == "selected_damage" {
			artifacts = []string{"header", "body"}
		}
		for _, cause := range []error{base, wrapped, errors.Join(base, errors.New("secondary"))} {
			for _, artifact := range artifacts {
				f := &RetainedProofFailureV1{Resource: resource, Cause: cause}
				if resource == "selected_damage" {
					f.Damage = &SelectedRowDamageV1{Generation: 3, Height: 0xffffffff, Hash: [32]byte{9}, Artifact: artifact, Cause: cause}
				}
				if any(f.Unwrap()) != any(cause) || !errors.Is(f, base) || f.Error() != cause.Error() {
					t.Fatalf("exact wrapper not retained: %+v", f)
				}
			}
		}
	}
	var typedNil *riNilCause
	validDamage := &SelectedRowDamageV1{Generation: 3, Artifact: "header", Cause: base}
	for _, f := range []*RetainedProofFailureV1{
		nil,
		{Cause: base},
		{Resource: "unknown", Cause: base},
		{Resource: "storage_capacity"},
		{Resource: "branch_data", Cause: typedNil},
		{Resource: "canonical_artifact_read", Cause: base, Damage: validDamage},
		{Resource: "selected_damage", Cause: base},
		{Resource: "selected_damage", Cause: typedNil, Damage: validDamage},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Artifact: "header", Cause: base}},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Height: 1 << 32, Artifact: "header", Cause: base}},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "undo", Cause: base}},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "", Cause: base}},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "body"}},
		{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "body", Cause: typedNil}},
	} {
		message := "invalid retained proof failure"
		if f != nil && any(f.Cause) == any(base) && f.Resource == "selected_damage" {
			message = "invalid retained selected damage"
		}
		logicalMDBXAssert(t, f.Error() == message, "invalid carrier Error discriminator: %v", f)
		riLocal(t, f.Unwrap())
	}
	for _, cause := range []error{riNilMap(nil), riNilSlice(nil), riNilFunc(nil), riNilChan(nil)} {
		f := &RetainedProofFailureV1{Resource: "branch_data", Cause: cause}
		logicalMDBXAssert(t, f.Error() == "invalid retained proof failure", "nil concrete carrier cause invoked")
		riLocal(t, f.Unwrap())
		f = &RetainedProofFailureV1{Resource: "selected_damage", Cause: base, Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "body", Cause: cause}}
		logicalMDBXAssert(t, f.Error() == "invalid retained selected damage", "nil concrete selected cause invoked")
		riLocal(t, f.Unwrap())
	}
	for _, resource := range []string{"storage_capacity", "canonical_artifact_read", "branch_data"} {
		f := &RetainedProofFailureV1{Resource: resource, Cause: base, Damage: validDamage}
		riLocal(t, f.Unwrap())
	}
	combined := &RetainedProofFailureV1{Resource: "selected_damage", Damage: &SelectedRowDamageV1{Generation: 3, Artifact: "undo", Cause: base}}
	logicalMDBXAssert(t, combined.Error() == "invalid retained proof failure", "nil cause lost precedence to invalid selected payload")
}

func riOptional(t *testing.T) {
	for _, row := range []struct {
		kind         string
		header, body bool
		malformed    bool
		want         uint64
	}{
		{"SIDE", true, true, false, 362},
		{"SIDE", true, false, false, 64},
		{"detached", true, true, false, 510},
		{"detached", true, false, false, 212},
		{"detached", false, true, false, 362},
		{"detached", false, false, false, 64},
		{"SIDE", true, true, true, 0},
		{"detached", true, true, true, 0},
		{"selected", true, true, false, 510},
		{"selected", false, true, false, 0},
		{"selected", true, false, false, 0},
		{"selected", true, true, true, 0},
		{"selected+SIDE", true, true, false, 510},
		{"selected-header-bad", true, true, false, 0},
		{"detached-header-bad", true, true, false, 0},
	} {
		t.Run(fmt.Sprintf("%s/header%v/body%v/bad%v", row.kind, row.header, row.body, row.malformed), func(t *testing.T) {
			kind := row.kind
			if kind == "selected-header-bad" {
				kind = "selected"
			}
			if kind == "detached-header-bad" {
				kind = "detached"
			}
			w := btNew(t)
			raw := initial148BlockGenesis(t)
			hash := sha3.Sum256(raw[:148])
			var mutations []mdbx.Mutation
			if row.header {
				header := bytes.Clone(raw[:148])
				if row.kind != kind {
					header[140] ^= 1
				}
				mutations = append(mutations, btMutation(3, hash[:], header))
			}
			if row.body {
				body := raw
				if row.malformed {
					body = raw[:149]
				}
				mutations = append(mutations, btMutation(4, hash[:], body))
			}
			if kind != "detached" {
				key, _ := mdbx.HeightKey(3, 5)
				mutations = append(mutations, btMutation(6, key, mdbx.ChainValue(hash, [32]byte{}, [40]byte{39: 1})))
			}
			if kind == "selected+SIDE" {
				key, _ := mdbx.HeightKey(4, 0)
				mutations = append(mutations, btMutation(6, key, mdbx.ChainValue(hash, [32]byte{}, [40]byte{39: 1})))
			}
			if len(mutations) != 0 {
				w.pair(t, mutations...)
			}
			encoded := riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) {
				switch kind {
				case "selected", "selected+SIDE":
					a.Authority.SelectedSide = &mdbx.SelectedSideV1{GenerationID: 3, F: 4, TipHeight: 5, TipHash: hash, RowCount: 1, LogicalBytes: 298, CumulativeChainwork: [40]byte{39: 1}}
					if kind == "selected+SIDE" {
						a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 4}}}
					}
				case "detached":
					a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 1, GenerationID: 3}}}
					a.Authority.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: []mdbx.DetachedSuffixEntryV1{{Height: 5, Hash: hash, BlockBytesLen: 298}}, Cursor: mdbx.AuthorityPointV1{Height: 5, BlockHash: hash}, EntryCount: 1, LogicalBytes: 298}
				case "SIDE":
					a.Authority.Phase, a.Authority.Cleanup = 2, &mdbx.CleanupV1{Spans: []mdbx.CleanupSpanV1{{Kind: 4, GenerationID: 3, FirstHeight: 5, NextHeight: 5, LastHeight: 5}}}
				}
			})
			got, err := riRead(t, w, nil)
			if row.want != 0 {
				logicalMDBXAssert(t, err == nil && got.exactRet == row.want, "optional union %+v/%v want%d", got, err, row.want)
			} else {
				logicalMDBXAssert(t, got == (retainedPreImageV1{}), "partial optional quantity: %+v", got)
				resource := "storage_capacity"
				if kind == "selected" {
					resource = "selected_damage"
				}
				failure := riResource(t, err, resource)
				if resource == "selected_damage" {
					artifact := "body"
					if !row.header || row.kind != kind {
						artifact = "header"
					}
					d := failure.Damage
					logicalMDBXAssert(t, d.Generation == 3 && d.Height == 5 && d.Hash == hash && d.Artifact == artifact && any(d.Cause) == any(failure.Cause), "exact damage tuple: %+v", d)
				}
			}
			w.read(t, 0, []byte{2}, encoded)
		})
	}
}

func riArchive(t *testing.T) {
	const count = uint64(16385)
	w := riChain(t, count)
	riAuthority(t, w, func(a *mdbx.TreeAuthorityV1) { a.Authority.ActiveProfile, a.Authority.U = 2, count })
	got, err := riRead(t, w, nil)
	if err != nil || got.exactRet != 9143051 {
		t.Fatalf("16385-frame ARCHIVE scalar: %+v/%v want9143051", got, err)
	}
}

// Only bounded setup batches are retained; subject quantities have literal independent oracles.
func riChain(t *testing.T, count uint64) *btWorld {
	t.Helper()
	w, genesis, previous := riGenesis(t)
	rows := make([]mdbx.Mutation, 0, 512)
	for h := uint64(1); h < count; h++ {
		raw := bytes.Clone(genesis)
		copy(raw[4:36], previous[:])
		binary.LittleEndian.PutUint64(raw[140:148], h)
		hash := sha3.Sum256(raw[:148])
		key, _ := mdbx.HeightKey(1, h)
		owner, _ := mdbx.CanonicalOwnerKey(1, hash)
		var work [40]byte
		binary.BigEndian.PutUint64(work[32:], h+1)
		rows = append(rows, btMutation(2, key, mdbx.ChainValue(hash, previous, work)), btMutation(3, hash[:], raw[:148]), btMutation(4, hash[:], raw), btMutation(7, owner, mdbx.CanonicalOwnerValue(h)))
		if len(rows) == 512 {
			w.pair(t, rows...)
			rows = rows[:0]
		}
		previous = hash
	}
	if len(rows) != 0 {
		w.pair(t, rows...)
	}
	var binding mdbx.RootBindingV1
	err := w.s.View(func(reader *mdbx.Reader) error {
		var err error
		binding, _, err = reader.ReadTreeRootBindingV1(1)
		return err
	})
	logicalMDBXAssert(t, err == nil, "archive complete binding: %v", err)
	binding.Endpoint.Height, binding.Endpoint.BlockHash = count-1, previous
	binary.BigEndian.PutUint64(binding.Endpoint.CumulativeChainwork[32:], count)
	root, err := binding.Encode()
	logicalMDBXAssert(t, err == nil, "archive root encode: %v", err)
	m := btMutation(0, btMeta(0x11, 1), root)
	m.BeforePresent = true
	w.pair(t, m)
	return w
}

func riFrames(t *testing.T) {
	for _, share := range []uint64{136463309, 136463310} {
		t.Run(fmt.Sprintf("body-share%d", share), func(t *testing.T) {
			w, _, _ := riGenesis(t)
			var got retainedPreImageV1
			err := riContext(t, w, nil, func(read *retainedReadV1) error {
				return read.account.WithReservation(402653184-8192-2313928-share, func() error {
					var err error
					got, err = readDirectRetainedMDBXV1(read)
					return err
				})
			})
			if share == 136463309 {
				riResource(t, err, "storage_capacity")
				logicalMDBXAssert(t, got == (retainedPreImageV1{}), "denied body emitted scalar")
			} else {
				logicalMDBXAssert(t, err == nil && got.exactRet == 779, "exact body frame: %+v/%v", got, err)
			}
		})
	}
	for _, r := range []uint64{0, 805306367, 805306368, 1073741824, math.MaxUint64} {
		limits := NewLimitsV1(r, 0)
		owner, err := mdbx.NewOperationReservationOwner(limits.R())
		logicalMDBXAssert(t, err == nil, "any-u64 owner construction: %v", err)
		ran := 0
		err = owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
			return a.WithReservation(0, func() error { ran++; return nil })
		})
		wantCalls := 1
		if r < 805306368 {
			wantCalls = 0
		}
		logicalMDBXAssert(t, (err != nil) == (r < 805306368) && ran == wantCalls, "reservation first refusal r%d: %d/%v", r, ran, err)
	}
}
