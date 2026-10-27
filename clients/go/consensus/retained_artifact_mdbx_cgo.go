//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"math"
	"reflect"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// SelectedRowDamageV1 identifies the row for the separate selected-clear owner.
type SelectedRowDamageV1 struct {
	Generation, Height uint64
	Hash               [32]byte
	Artifact           string
	Cause              error
}

// RetainedProofFailureV1 preserves source evidence beside its resource result.
type RetainedProofFailureV1 struct {
	Resource string
	Damage   *SelectedRowDamageV1
	Cause    error
}

// retainedCauseV1 excludes nil concrete implementations without invoking them.
func retainedCauseV1(err error) bool {
	if err == nil {
		return false
	}
	v := reflect.ValueOf(err)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

func (f *RetainedProofFailureV1) failureV1() error {
	if f == nil || !retainedCauseV1(f.Cause) {
		return localLogicalStateFailure("invalid retained proof failure")
	}
	if f.Resource == "selected_damage" {
		return f.selectedV1()
	}
	known := f.Resource == "storage_capacity" || f.Resource == "canonical_artifact_read" || f.Resource == "branch_data"
	if !known || f.Damage != nil {
		return localLogicalStateFailure("invalid retained proof failure")
	}
	return f.Cause
}

func (f *RetainedProofFailureV1) selectedV1() error {
	d := f.Damage
	if d == nil || d.Generation == 0 || d.Height > math.MaxUint32 {
		return localLogicalStateFailure("invalid retained selected damage")
	}
	if d.Artifact != "header" && d.Artifact != "body" || !retainedCauseV1(d.Cause) {
		return localLogicalStateFailure("invalid retained selected damage")
	}
	return f.Cause
}

// Error safely normalizes malformed carriers through the existing API error.
func (f *RetainedProofFailureV1) Error() string { return f.failureV1().Error() }

// Unwrap retains the valid supplied wrapper and its exact nested cause.
func (f *RetainedProofFailureV1) Unwrap() error { return f.failureV1() }

func retainedFailureV1(resource string, cause error) error {
	if !retainedCauseV1(cause) {
		return localLogicalStateFailure("invalid retained proof cause")
	}
	return &RetainedProofFailureV1{Resource: resource, Cause: cause}
}

func retainedRequiredV1(cause error) error {
	return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: cause}
}

// retainedSourceV1 never invents a native cause or drops the first source wrapper.
func retainedSourceV1(err error, required bool) error {
	if err == nil {
		return nil
	}
	resource := "branch_data"
	if required {
		var native *mdbx.EngineError
		if errors.As(err, &native) && native != nil && native.Class == mdbx.EngineIntegrity {
			return retainedRequiredV1(err)
		}
		resource = "canonical_artifact_read"
	}
	return retainedFailureV1(resource, err)
}

type retainedArtifactV1 struct {
	hash, parent       [32]byte
	height, generation uint64
	bits, required     uint8
	selected           bool
}

// optionalAtV1 streams the admitted authority order without a copied selector list.
func (read *retainedReadV1) optionalAtV1(at uint64) (retainedArtifactV1, bool, error) {
	a := read.authority.Authority
	if s := a.SelectedSide; s != nil {
		if at < uint64(s.RowCount) {
			item, err := read.sideV1(s.GenerationID, selectedSideFirst(s)+at)
			item.bits, item.selected = 3, true
			return item, true, err
		}
		at -= uint64(s.RowCount)
	}
	if d := a.DetachedSuffix; d != nil {
		if at < uint64(d.EntryCount) {
			e := d.Entries[at]
			return retainedArtifactV1{hash: e.Hash, height: e.Height, bits: 3}, true, nil
		}
		at -= uint64(d.EntryCount)
	}
	return read.sideAtV1(at)
}

// sideAtV1 resolves only the remaining pending SIDE span after stronger descriptors.
func (read *retainedReadV1) sideAtV1(at uint64) (retainedArtifactV1, bool, error) {
	for _, s := range retainedSpansV1(read.authority.Authority) {
		if s.Kind == mdbx.CleanupSpanSideV1 && at <= s.LastHeight-s.NextHeight {
			item, err := read.sideV1(s.GenerationID, s.NextHeight+at)
			return item, true, err
		}
	}
	return retainedArtifactV1{}, false, nil
}

func (read *retainedReadV1) sideV1(g, h uint64) (retainedArtifactV1, error) {
	value, err := read.reader.ReadRequiredSideLink(g, h)
	if err != nil {
		return retainedArtifactV1{}, retainedSourceV1(err, false)
	}
	return retainedArtifactV1{hash: [32]byte(value[:32]), parent: [32]byte(value[32:64]), height: h, generation: g, bits: 2}, nil
}

// retainedSpansV1 borrows the decoded cleanup descriptors without copying backing.
func retainedSpansV1(a mdbx.StorageAuthorityV1) []mdbx.CleanupSpanV1 {
	if a.Cleanup == nil {
		return nil
	}
	return a.Cleanup.Spans
}

func retainedOwedV1(a mdbx.StorageAuthorityV1, height uint64, kind mdbx.CleanupSpanKindV1) bool {
	for _, s := range retainedSpansV1(a) {
		if s.Kind == kind && height >= s.NextHeight && height <= s.LastHeight {
			return true
		}
	}
	return false
}

// ownersV1 resolves one protected CURRENT point and only earlier optional owners.
func (read *retainedReadV1) ownersV1(hash [32]byte, before uint64) (retainedArtifactV1, error) {
	k, err := read.canonicalOwnerV1(hash)
	if err != nil {
		return k, err
	}
	for at := uint64(0); at < before; at++ {
		item, present, err := read.optionalAtV1(at)
		if err != nil || !present {
			return k, err
		}
		if item.hash == hash {
			k.bits |= item.bits
		}
	}
	return k, nil
}

// canonicalOwnerV1 applies each kind's actual keep window to a protected point.
func (read *retainedReadV1) canonicalOwnerV1(hash [32]byte) (retainedArtifactV1, error) {
	o, err := read.reader.CanonicalOwnerV1(read.roles[0].generation, hash)
	if err != nil {
		return retainedArtifactV1{}, retainedSourceV1(err, true)
	}
	k := retainedArtifactV1{hash: hash}
	if o.Owned {
		k.bits, k.required, k.height, k.parent = 1, 1, o.Height, [32]byte(o.Entry[32:64])
		k.generation = read.roles[0].generation
		a := read.authority.Authority
		if o.Height >= read.bodyFirstV1() || retainedOwedV1(a, o.Height, mdbx.CleanupSpanBlocksV1) {
			k.bits, k.required = k.bits|2, k.required|2
		}
		if o.Height >= a.U || retainedOwedV1(a, o.Height, mdbx.CleanupSpanUndoV1) {
			k.bits, k.required = k.bits|4, k.required|4
		}
	}
	return k, nil
}

// optionalV1 charges the first owner occurrence of each kind and hash.
func (w *retainedWalkV1) optionalV1() error {
	for at := uint64(0); ; at++ {
		item, present, err := w.read.optionalAtV1(at)
		if err != nil || !present {
			return err
		}
		higher, err := w.read.ownersV1(item.hash, at)
		if err != nil {
			return err
		}
		item.bits &^= higher.bits
		if err := w.artifactsV1(item); err != nil {
			return err
		}
	}
}

// retainedDamageV1 classifies positive evidence at its actual kind-specific owner.
func retainedDamageV1(item retainedArtifactV1, bit uint8, cause error) error {
	if item.required&bit != 0 {
		return retainedRequiredV1(cause)
	}
	if item.selected {
		artifact := "body"
		if bit == 1 {
			artifact = "header"
		}
		d := &SelectedRowDamageV1{Generation: item.generation, Height: item.height, Hash: item.hash, Artifact: artifact, Cause: cause}
		return &RetainedProofFailureV1{Resource: "selected_damage", Damage: d, Cause: cause}
	}
	return retainedFailureV1("storage_capacity", cause)
}

// headerV1 implements only the qualified zero-ownership late-header exclusion.
func (read *retainedReadV1) headerV1(hash [32]byte) ([]byte, bool, error) {
	if read.omitHeader && hash == read.lateHeader {
		return nil, false, nil
	}
	row, err := read.reader.GetInitial148OptionalSide(mdbx.TreeSchemaV1DBIs()[3], hash[:])
	return row.Value, row.Present, err
}

func retainedHeaderV1(header []byte, item retainedArtifactV1) bool {
	if len(header) != 148 || sha3.Sum256(header) != item.hash {
		return false
	}
	return item.generation == 0 || [32]byte(header[4:36]) == item.parent
}

// artifactsV1 releases each body before acquiring a family or the next artifact.
func (w *retainedWalkV1) artifactsV1(item retainedArtifactV1) error {
	if item.bits&1 != 0 {
		if err := w.headerChargeV1(item); err != nil {
			return err
		}
	}
	if item.bits&2 != 0 {
		if err := w.bodyV1(item); err != nil {
			return err
		}
	}
	if item.bits&4 != 0 {
		return w.undoV1(item)
	}
	return nil
}

// headerChargeV1 distinguishes allowed absence from a present damaged retained row.
func (w *retainedWalkV1) headerChargeV1(item retainedArtifactV1) error {
	header, present, err := w.read.headerV1(item.hash)
	if err != nil {
		return retainedSourceV1(err, item.required&1 != 0)
	}
	if present && !retainedHeaderV1(header, item) {
		return retainedDamageV1(item, 1, errors.New("retained header is malformed"))
	}
	if !present && item.selected {
		return retainedDamageV1(item, 1, errors.New("retained header is absent"))
	}
	if present {
		return w.addV1(RetainedHeaderChargeV1)
	}
	return nil
}

// retainedValueV1 uses bounded windows into one already funded complete value.
func retainedValueV1(size uint64, read func([]byte, uint64) (int, error)) ([]byte, error) {
	value := make([]byte, size)
	for at := 0; at < len(value); {
		end := min(at+65536, len(value))
		if _, err := read(value[at:end], uint64(at)); err != nil {
			return nil, err
		}
		at = end
	}
	return value, nil
}

// bodyV1 admits assembly, immutable OLD and streaming health before acquisition.
func (w *retainedWalkV1) bodyV1(item retainedArtifactV1) error {
	ran := false
	err := w.read.account.WithReservation(retainedBodyFrameV1, func() error {
		ran = true
		return w.read.reader.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: item.hash}, func(row mdbx.LargeImageRowV1) error {
			return w.bodyRowV1(item, row)
		})
	})
	if !ran {
		return retainedFailureV1("storage_capacity", err)
	}
	return retainedObservedV1(err, item.required&2 != 0)
}

// retainedObservedV1 leaves semantic carriers intact and classifies actual source errors.
func retainedObservedV1(err error, required bool) error {
	var own *RetainedProofFailureV1
	var logical *logicalStateFailure
	if err == nil || errors.As(err, &own) || errors.As(err, &logical) {
		return err
	}
	return retainedSourceV1(err, required)
}

func (w *retainedWalkV1) bodyRowV1(item retainedArtifactV1, row mdbx.LargeImageRowV1) error {
	if !row.Present() {
		if item.required&2 != 0 || item.selected {
			return retainedDamageV1(item, 2, errors.New("retained body is absent"))
		}
		return nil
	}
	if row.Length() < 148 || row.Length() > 68000157 {
		return retainedDamageV1(item, 2, errors.New("retained body width is invalid"))
	}
	raw, err := retainedValueV1(row.Length(), row.ReadAt)
	if err != nil {
		return retainedSourceV1(err, item.required&2 != 0)
	}
	return w.bodyHealthV1(item, raw)
}

func (w *retainedWalkV1) bodyHealthV1(item retainedArtifactV1, raw []byte) error {
	if !retainedHeaderV1(raw[:148], item) {
		return retainedDamageV1(item, 2, errors.New("retained body identity differs"))
	}
	if err := ValidateInitial148BlockBodyCommitments(raw); err != nil {
		return retainedDamageV1(item, 2, err)
	}
	return w.addV1(uint64(len(raw)))
}

type retainedUndoReadV1 struct {
	health cleanupUndoHealth
	charge uint64
	bad    bool
}

// undoV1 funds one family visit and its complete distinctness check together.
func (w *retainedWalkV1) undoV1(item retainedArtifactV1) error {
	u := retainedUndoReadV1{health: cleanupUndoHealth{height: item.height}}
	err := w.read.account.WithReservation(retainedUndoFrameV1, func() error {
		defer func() { u.health.outpoints = nil }()
		if err := w.read.reader.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageUndoFamilyV1, Hash: item.hash}, u.visitV1); err != nil {
			return err
		}
		return u.finishV1(item.required&4 != 0)
	})
	if mdbx.IsOperationReservationCapacity(err) {
		return retainedFailureV1("storage_capacity", err)
	}
	if err != nil {
		if u.bad {
			return retainedDamageV1(item, 4, err)
		}
		return retainedSourceV1(err, item.required&4 != 0)
	}
	return w.addV1(u.charge)
}

// visitV1 shares the sole manifest/provenance rule while charging each original.
func (u *retainedUndoReadV1) visitV1(row mdbx.LargeImageRowV1) error {
	if !row.Present() {
		return nil
	}
	u.bad = true
	if row.Length() > 65560 {
		return errors.New("retained undo width is invalid")
	}
	u.bad = false
	value, err := retainedValueV1(row.Length(), row.ReadAt)
	if err != nil {
		return err
	}
	u.bad = true
	key := row.Key()
	if err := mdbx.ValidateRow(mdbx.TreeSchemaV1DBIs()[5], key, value); err != nil {
		return err
	}
	if err := u.health.row(key, value); err != nil {
		return err
	}
	if len(key) != 33 {
		n, err := RetainedStateEntryChargeV1(value)
		if err != nil {
			return err
		}
		u.charge += n
	}
	u.bad = false
	return nil
}

func (u *retainedUndoReadV1) finishV1(required bool) error {
	u.bad = true
	points := u.health.outpoints
	if points == nil && !required {
		u.bad = false
		return nil
	}
	if points == nil || len(points) != cap(points) {
		return errors.New("retained undo family is absent or incomplete")
	}
	slices.SortFunc(points, func(a, b [36]byte) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(points); i++ {
		if points[i] == points[i-1] {
			return errors.New("retained undo outpoint is duplicated")
		}
	}
	u.bad = false
	return nil
}
