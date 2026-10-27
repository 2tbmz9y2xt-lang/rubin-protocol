//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"

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
