//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type (
	retainedRoleV1     struct{ generation, s, n, j uint64 }
	retainedCompleteV1 struct {
		generation uint64
		complete   bool
	}
	retainedOriginV1   struct{ database, chain, genesis [32]byte }
	retainedPreImageV1 struct {
		binding  mdbx.MutationBindingV1
		exactRet uint64
		complete [2]retainedCompleteV1
	}
	retainedReadV1 struct {
		reader               *mdbx.Reader
		account              *mdbx.OperationAccount
		authority            mdbx.TreeAuthorityV1
		binding              mdbx.MutationBindingV1
		roles                [2]retainedRoleV1
		endpoints            [2]mdbx.TreeEndpointV1
		origin               retainedOriginV1
		lateHeader           [32]byte
		omitHeader, prepared bool
	}
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

// failureV1 is used by both public carrier methods, including malformed inputs.
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

// selectedV1 checks the complete bounded discriminator payload.
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

// retainedFailureV1 admits only concrete source causes into produced carriers.
func retainedFailureV1(resource string, cause error) error {
	if !retainedCauseV1(cause) {
		return localLogicalStateFailure("invalid retained proof cause")
	}
	return &RetainedProofFailureV1{Resource: resource, Cause: cause}
}

// retainedRequiredV1 reuses the canonical integrity identity without adding effects.
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

// prepareRetainedReadV1 initializes only OLD authority under the caller's read frame.
func prepareRetainedReadV1(dst *retainedReadV1, old *mdbx.Reader, account *mdbx.OperationAccount, lateHeader *[32]byte) error {
	if dst == nil || !reflect.ValueOf(*dst).IsZero() {
		return localLogicalStateFailure("retained read context is not unused")
	}
	return account.WithReservation(0, func() error {
		return dst.initializeV1(old, account, lateHeader)
	})
}

// initializeV1 binds the actual source before publishing the prepared context.
func (read *retainedReadV1) initializeV1(old *mdbx.Reader, account *mdbx.OperationAccount, lateHeader *[32]byte) error {
	binding, err := old.MutationBindingV1()
	if err != nil {
		return err
	}
	authority, present, err := old.ReadTreeAuthorityV1()
	if err != nil {
		return retainedSourceV1(err, true)
	}
	if !present || !retainedAuthorityV1(authority) {
		return localLogicalStateFailure("invalid retained direct authority")
	}
	if err := old.RequireCanonicalOwnerVerificationV1(); err != nil {
		return err
	}
	*read = retainedReadV1{reader: old, account: account, authority: authority, binding: binding, prepared: true}
	if lateHeader != nil {
		read.lateHeader, read.omitHeader = *lateHeader, true
	}
	return nil
}

// retainedAuthorityV1 narrows the already decoded authority to the direct domain.
func retainedAuthorityV1(a mdbx.TreeAuthorityV1) bool {
	s := a.Authority
	stable := s.Lifecycle == mdbx.StorageLifecycleStableV1
	direct := s.Phase == mdbx.StoragePhaseNoneV1 || s.Phase == mdbx.StoragePhasePruneGCV1
	return stable && direct && cleanupDrainRetention(s, s.Cleanup)
}

// readRetainedRolesV1 captures each role once; a failed capture cannot be retried.
func readRetainedRolesV1(read *retainedReadV1) (err error) {
	if read == nil || !read.prepared || read.roles != ([2]retainedRoleV1{}) {
		return localLogicalStateFailure("invalid retained role context")
	}
	read.prepared = false
	for i, g := range [2]uint64{read.authority.Authority.ActiveGenerationID, read.authority.LagGenerationID} {
		if err := read.roleV1(i, g); err != nil {
			return err
		}
	}
	read.prepared = true
	return nil
}

// roleV1 reads the counter before that role's complete binding.
func (read *retainedReadV1) roleV1(i int, g uint64) error {
	key, _ := mdbx.MetaKey(0x10, g)
	value, present, err := read.reader.Get(mdbx.TreeSchemaV1DBIs()[0], key)
	if err != nil {
		return retainedSourceV1(err, true)
	}
	if !present {
		return retainedRequiredV1(errors.New("retained role counter is absent"))
	}
	s, n, err := mdbx.DecodeLogicalCounterValue(value)
	if err != nil {
		return retainedRequiredV1(err)
	}
	if !validLogicalStateResidualEnvelope(s, n) {
		return retainedRequiredV1(errors.New("retained role counter envelope is invalid"))
	}
	return read.bindingV1(i, g, s, n)
}

// bindingV1 captures identity scalars and releases decoded top/import backing.
func (read *retainedReadV1) bindingV1(i int, g, s, n uint64) error {
	root, present, err := read.reader.ReadTreeRootBindingV1(g)
	if err != nil {
		return retainedSourceV1(err, true)
	}
	if !present {
		return retainedRequiredV1(errors.New("retained role binding is absent"))
	}
	origin := retainedOriginV1{root.DatabaseID, root.ChainID, root.GenesisHash}
	if i == 1 && origin != read.origin {
		return retainedRequiredV1(errors.New("retained role origins differ"))
	}
	j := uint64(0)
	if root.Endpoint.Kind == mdbx.TreeEndpointAppliedV1 {
		j = root.Endpoint.Height + 1
	}
	read.roles[i], read.endpoints[i], read.origin = retainedRoleV1{g, s, n, j}, root.Endpoint, origin
	return nil
}

const (
	retainedPageFrameV1 uint64 = 663576
	retainedBodyFrameV1 uint64 = 136463310
	retainedUndoFrameV1 uint64 = 15328256
)

type retainedWalkV1 struct {
	read *retainedReadV1
	pre  retainedPreImageV1
}

// readDirectRetainedMDBXV1 publishes only a fully completed scalar image.
func readDirectRetainedMDBXV1(read *retainedReadV1) (retainedPreImageV1, error) {
	if err := readRetainedRolesV1(read); err != nil {
		return retainedPreImageV1{}, err
	}
	w := retainedWalkV1{read: read, pre: retainedPreImageV1{binding: read.binding}}
	for _, role := range read.roles {
		tree, err := RetainedTreeChargeV1(role.n)
		if err != nil {
			return retainedPreImageV1{}, retainedFailureV1("storage_capacity", err)
		}
		if err := w.addV1(role.s, tree, RetainedIndexChargeV1*role.j); err != nil {
			return retainedPreImageV1{}, err
		}
	}
	if err := w.visitV1(); err != nil {
		return retainedPreImageV1{}, err
	}
	return w.pre, nil
}

// addV1 preserves nonnegative checked arithmetic without publishing partial sums.
func (w *retainedWalkV1) addV1(values ...uint64) error {
	for _, n := range values {
		if n > math.MaxUint64-w.pre.exactRet {
			return retainedFailureV1("storage_capacity", errRetainedArithmetic)
		}
		w.pre.exactRet += n
	}
	return nil
}

// bodyFirstV1 keeps L_body independent of the service promise B.
func (read *retainedReadV1) bodyFirstV1() uint64 {
	if read.authority.Authority.ActiveProfile == mdbx.StorageProfileArchiveV1 || read.endpoints[1].Kind == mdbx.TreeEndpointPreGenesisV1 {
		return 0
	}
	return read.endpoints[1].Height + 1
}

// visitV1 preserves the normative first-source order.
func (w *retainedWalkV1) visitV1() error {
	if err := w.addV1(RetainedHeaderChargeV1 * w.read.roles[0].j); err != nil {
		return err
	}
	for _, undo := range [2]bool{false, true} {
		if err := w.canonicalV1(undo); err != nil {
			return err
		}
	}
	if err := w.optionalV1(); err != nil {
		return err
	}
	at := 0
	for _, span := range retainedSpansV1(w.read.authority.Authority) {
		if span.Kind == mdbx.CleanupSpanGenerationV1 {
			w.pre.complete[at] = retainedCompleteV1{span.GenerationID, true}
			if err := w.generationV1(at); err != nil {
				return err
			}
			at++
		}
	}
	return nil
}

// canonicalV1 visits the canonical keep before the disjoint remaining owed range.
func (w *retainedWalkV1) canonicalV1(undo bool) error {
	first, kind, bits := w.read.bodyFirstV1(), mdbx.CleanupSpanBlocksV1, uint8(2)
	if undo {
		first, kind, bits = w.read.authority.Authority.U, mdbx.CleanupSpanUndoV1, 4
	}
	if w.read.roles[0].j != 0 {
		if err := w.rangeV1(first, w.read.endpoints[0].Height, bits); err != nil {
			return err
		}
	}
	if first == 0 {
		return nil
	}
	for _, s := range retainedSpansV1(w.read.authority.Authority) {
		if s.Kind == kind {
			if err := w.rangeV1(s.NextHeight, min(s.LastHeight, first-1), bits); err != nil {
				return err
			}
		}
	}
	return nil
}

// rangeV1 streams a required range in ascending canonical height.
func (w *retainedWalkV1) rangeV1(first, last uint64, bits uint8) error {
	for h := first; h <= last; h++ {
		key, _ := mdbx.HeightKey(w.read.roles[0].generation, h)
		entry, present, err := w.read.reader.Get(mdbx.TreeSchemaV1DBIs()[2], key)
		if err != nil {
			return retainedSourceV1(err, true)
		}
		if !present {
			return retainedRequiredV1(errors.New("retained canonical entry is absent"))
		}
		item := retainedArtifactV1{hash: [32]byte(entry[:32]), parent: [32]byte(entry[32:64]), height: h, generation: w.read.roles[0].generation, bits: bits, required: bits}
		if err := w.artifactsV1(item); err != nil {
			return err
		}
	}
	return nil
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

// sideV1 preserves the exact source result of a required identity link.
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

// retainedOwedV1 includes only an undrained required duty of this artifact kind.
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

// retainedHeaderV1 binds the complete fixed header to its named hash and parent.
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

// bodyRowV1 distinguishes optional absence, owner damage and source failure.
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

// bodyHealthV1 validates the sole complete fixed148 body without retaining parsed data.
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

// finishV1 rejects missing/count-mismatched families and duplicate outpoints.
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

type retainedRawV1 struct {
	key        [46]byte
	value      [104]byte
	keyLength  int
	charge     uint64
	admissible bool
}

// pageV1 drops the public page before returning fixed evidence and one continuation.
func (read *retainedReadV1) pageV1(g uint64, class mdbx.ObsoleteClassV1, after []byte) (retainedRawV1, []byte, bool, error) {
	var raw retainedRawV1
	var next []byte
	exhausted, ran := false, false
	err := read.account.WithReservation(retainedPageFrameV1, func() error {
		ran = true
		page, err := read.reader.ObsoleteGenerationPageV1(g, class, after, 1)
		if err != nil {
			return retainedSourceV1(err, false)
		}
		next, exhausted = page.Next, page.Stop == mdbx.PrefixPageExhausted
		if len(page.Rows) == 0 {
			return nil
		}
		row, key := page.Rows[0], page.Rows[0].Key()
		raw.keyLength = len(key)
		copy(raw.key[:], key)
		return raw.observeV1(row, class, key)
	})
	if !ran {
		err = retainedFailureV1("storage_capacity", err)
	}
	return raw, next, exhausted, err
}

// observeV1 classifies raw kind before any value or subsequent-page observation.
func (raw *retainedRawV1) observeV1(row mdbx.ObsoleteRowV1, class mdbx.ObsoleteClassV1, key []byte) error {
	switch class {
	case mdbx.ObsoleteUTXOV1:
		return raw.stateV1(row)
	case mdbx.ObsoleteIndexV1, mdbx.ObsoleteDerivedV1:
		return raw.fixedV1(row, class)
	case mdbx.ObsoleteNodeV1:
		_, id, err := mdbx.DecodeTreeNodeKey(key)
		if err != nil {
			return retainedFailureV1("storage_capacity", err)
		}
		raw.charge, _ = RetainedNodeChargeV1(id.Kind)
	case mdbx.ObsoleteRootV1:
		raw.charge = RetainedRootChargeV1
	case mdbx.ObsoleteCounterV1:
		raw.charge = 0
	}
	return nil
}

// stateV1 funds both the complete native value and the sole decoder's copy.
func (raw *retainedRawV1) stateV1(row mdbx.ObsoleteRowV1) error {
	if raw.keyLength != 44 || row.Length() > 65560 {
		return retainedFailureV1("storage_capacity", errors.New("retained obsolete state is malformed"))
	}
	value, err := retainedValueV1(row.Length(), row.ReadAt)
	if err != nil {
		return retainedSourceV1(err, false)
	}
	raw.charge, err = RetainedStateEntryChargeV1(value)
	if err != nil {
		return retainedFailureV1("storage_capacity", err)
	}
	return nil
}

// fixedV1 extracts bounded forward or reverse evidence without active-owner promotion.
func (raw *retainedRawV1) fixedV1(row mdbx.ObsoleteRowV1, class mdbx.ObsoleteClassV1) error {
	keySize, valueSize := 40, 8
	if class == mdbx.ObsoleteIndexV1 {
		raw.charge, keySize, valueSize = RetainedIndexChargeV1, 16, 104
	}
	if raw.keyLength != keySize || row.Length() != uint64(valueSize) {
		return nil
	}
	if _, err := row.ReadAt(raw.value[:valueSize], 0); err != nil {
		return retainedSourceV1(err, false)
	}
	raw.admissible = binary.BigEndian.Uint64(raw.value[:8]) <= math.MaxUint32
	if class == mdbx.ObsoleteIndexV1 {
		raw.admissible = binary.BigEndian.Uint64(raw.key[8:16]) <= math.MaxUint32 && archiveSelectedSideWork(raw.value[64:104])
	}
	return nil
}

// exactV1 distinguishes an exact row, a conclusive successor and an unverifiable gap.
func (read *retainedReadV1) exactV1(g uint64, class mdbx.ObsoleteClassV1, key []byte) (retainedRawV1, bool, error) {
	raw, _, _, err := read.pageV1(g, class, cleanupDrainPredecessor(key))
	if err != nil || raw.keyLength == 0 {
		return raw, false, err
	}
	comparison := bytes.Compare(raw.key[:min(raw.keyLength, len(raw.key))], key)
	if comparison < 0 {
		return raw, false, retainedFailureV1("branch_data", errors.New("retained exact range is unverifiable"))
	}
	return raw, comparison == 0 && raw.keyLength == len(key), nil
}

// reverseV1 drops its public page before the subsequent own-forward probe.
func (read *retainedReadV1) reverseV1(g uint64, hash [32]byte) (uint64, bool, error) {
	key, _ := mdbx.CanonicalOwnerKey(g, hash)
	raw, present, err := read.exactV1(g, mdbx.ObsoleteDerivedV1, key)
	return binary.BigEndian.Uint64(raw.value[:8]), present && raw.admissible, err
}

// priorV1 requires the actual admissible hash and healthy-header parent.
func (read *retainedReadV1) priorV1(g, h uint64, item retainedArtifactV1) (bool, error) {
	if g == item.generation && h >= item.height {
		return false, nil
	}
	key, _ := mdbx.HeightKey(g, h)
	raw, present, err := read.exactV1(g, mdbx.ObsoleteIndexV1, key)
	valid := present && raw.admissible && [32]byte(raw.value[:32]) == item.hash && [32]byte(raw.value[32:64]) == item.parent
	return valid, err
}

// earlierV1 uses actual positive parent proof even when a completed fact is false.
func (w *retainedWalkV1) earlierV1(at int, item retainedArtifactV1) (bool, error) {
	for _, fact := range w.pre.complete[:at] {
		h, valid, err := w.read.reverseV1(fact.generation, item.hash)
		if err != nil {
			return false, err
		}
		if valid {
			found, err := w.read.priorV1(fact.generation, h, item)
			if err != nil || found {
				return found, err
			}
		}
		if !fact.complete {
			return false, retainedFailureV1("branch_data", errors.New("retained earlier membership is inconclusive"))
		}
	}
	return false, nil
}

// generationV1 visits each generation contiguously, with root presence last.
func (w *retainedWalkV1) generationV1(at int) error {
	for _, class := range [4]mdbx.ObsoleteClassV1{mdbx.ObsoleteUTXOV1, mdbx.ObsoleteIndexV1, mdbx.ObsoleteNodeV1, mdbx.ObsoleteRootV1} {
		var after []byte
		for {
			raw, next, exhausted, err := w.read.pageV1(w.pre.complete[at].generation, class, after)
			if err != nil {
				return err
			}
			after = next
			if err := w.addV1(raw.charge); err != nil {
				return err
			}
			if raw.admissible {
				if err := w.indexV1(at, raw); err != nil {
					return err
				}
			}
			if exhausted {
				break
			}
		}
	}
	return nil
}

// indexV1 separates needed-firstness from the later completeness-only observation.
func (w *retainedWalkV1) indexV1(at int, raw retainedRawV1) error {
	fact := &w.pre.complete[at]
	item := retainedArtifactV1{hash: [32]byte(raw.value[:32]), parent: [32]byte(raw.value[32:64]), height: binary.BigEndian.Uint64(raw.key[8:16]), generation: fact.generation, bits: 7}
	item, err := w.projectedV1(item)
	if err != nil {
		return err
	}
	h, valid, observed := uint64(0), false, false
	if item.bits != 0 {
		h, valid, observed, err = w.contributionV1(at, item)
		if err != nil {
			return err
		}
	}
	if !observed {
		h, valid, err = w.read.reverseV1(fact.generation, item.hash)
		if err != nil {
			return err
		}
	}
	fact.complete = fact.complete && valid && h == item.height
	return nil
}

// projectedV1 qualifies the existing OLD own-forward projection after stronger owners.
func (w *retainedWalkV1) projectedV1(item retainedArtifactV1) (retainedArtifactV1, error) {
	higher, err := w.read.ownersV1(item.hash, 1440)
	if err != nil {
		return item, err
	}
	item.bits &^= higher.bits
	if item.bits == 0 {
		return item, nil
	}
	header, present, err := w.read.headerV1(item.hash)
	if err != nil {
		return item, retainedSourceV1(err, higher.required&1 != 0)
	}
	if higher.required&1 != 0 && !retainedHeaderV1(header, higher) {
		return item, retainedRequiredV1(errors.New("retained canonical header is malformed"))
	}
	if !present {
		item.bits = 0
		return item, nil
	}
	if !retainedHeaderV1(header, item) {
		item.bits = 0
	}
	return item, nil
}

// contributionV1 uses oldP before the caller updates current reciprocity.
func (w *retainedWalkV1) contributionV1(at int, item retainedArtifactV1) (uint64, bool, bool, error) {
	prior, err := w.earlierV1(at, item)
	if err != nil || prior {
		return 0, false, false, err
	}
	fact := w.pre.complete[at]
	h, valid, err := w.read.reverseV1(fact.generation, item.hash)
	if valid {
		prior, err = w.read.priorV1(fact.generation, h, item)
	}
	if err != nil {
		return h, valid, true, err
	}
	if !prior && !fact.complete {
		return h, valid, true, retainedFailureV1("branch_data", errors.New("retained prefix membership is inconclusive"))
	}
	if !prior {
		err = w.artifactsV1(item)
	}
	return h, valid, true, err
}
