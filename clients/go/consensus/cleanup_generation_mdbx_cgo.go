//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// CleanupGenerationMDBX drains one finite page of the first GENERATION span.
// It is dormant; the full-lane grant encloses its sole Update and native cleanup.
func CleanupGenerationMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, firstClass mdbx.ObsoleteClassV1, maxRows uint32) SelectedSideDamageOutcome {
	out := selectedSideOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	if store == nil {
		out.Truth, out.Stage, out.Err = store.Update(nil)
		return out
	}
	if firstClass < 1 || firstClass > 4 || maxRows == 0 || maxRows > 1440 {
		out.Err = errors.New("invalid cleanup generation page request")
		return out
	}
	p := &cleanupGenerationPlan{noWork: errors.New("cleanup GENERATION has no selected work")}
	ran, called := false, false
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		out.Truth, out.Stage, out.Err = store.Update(func(r *mdbx.Reader) (mdbx.Batch, error) {
			called = true
			return p.batch(r, firstClass, maxRows)
		})
		return out.Err
	})
	if !ran {
		out.Err = err
		return out
	}
	if !called {
		return out
	}
	return p.project(out)
}

type cleanupGenerationPlan struct {
	noWork     error
	step       string
	positive   bool
	batchImage mdbx.Batch
	rawClass   mdbx.ObsoleteClassV1
}

func (p *cleanupGenerationPlan) project(out selectedSideOutcome) selectedSideOutcome {
	out.CanonicalTruth = "OLD"
	if p.positive {
		return selectedSideDamageProject(out, &selectedSideDamagePlan{healthy: p.noWork, step: p.step})
	}
	return archiveSelectedSideProject(out, p.step, p.noWork, nil)
}

// cleanupDrainAuthority qualifies promises even for a no-work routing branch.
func cleanupDrainAuthority(r *mdbx.Reader) (mdbx.StorageAuthorityV1, error) {
	a, err := r.ReadStorageAuthorityV1()
	if err != nil {
		return a, err
	}
	cleanup := a.Cleanup
	if a.Ordinary != nil {
		cleanup = a.Ordinary.CarriedCleanup
	}
	if cleanup != nil {
		for _, span := range cleanup.Spans {
			if !cleanupDrainPromise(a, span) {
				return a, &mdbx.EngineError{Class: mdbx.EngineIntegrity, Operation: "get", Code: -30793, Diagnostic: "invalid storage authority"}
			}
		}
	}
	if !cleanupDrainRetention(a, cleanup) {
		return a, selectedSideDefect("invalid cleanup retained aggregate")
	}
	return a, nil
}

func cleanupDrainRetention(a mdbx.StorageAuthorityV1, cleanup *mdbx.CleanupV1) bool {
	var rows uint64
	if a.SelectedSide != nil {
		rows += uint64(a.SelectedSide.RowCount)
	}
	if a.DetachedSuffix != nil {
		rows += uint64(a.DetachedSuffix.EntryCount)
	}
	if cleanup != nil {
		for _, span := range cleanup.Spans {
			if span.Kind == mdbx.CleanupSpanSideV1 {
				rows += span.LastHeight-span.NextHeight+1
			}
		}
	}
	return rows <= 1440
}

func cleanupDrainPromise(a mdbx.StorageAuthorityV1, span mdbx.CleanupSpanV1) bool {
	switch span.Kind {
	case mdbx.CleanupSpanBlocksV1:
		return span.LastHeight+1 == a.B
	case mdbx.CleanupSpanUndoV1:
		return span.LastHeight+1 == a.U
	default:
		return true
	}
}

func (p *cleanupGenerationPlan) batch(r *mdbx.Reader, first mdbx.ObsoleteClassV1, maxRows uint32) (mdbx.Batch, error) {
	a, err := cleanupDrainAuthority(r)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if a.Phase != mdbx.StoragePhasePruneGCV1 || a.DetachedSuffix != nil || a.Cleanup.Spans[0].Kind != mdbx.CleanupSpanGenerationV1 {
		return mdbx.Batch{}, p.noWork
	}
	return p.drain(r, a, first, maxRows)
}

func (p *cleanupGenerationPlan) drain(r *mdbx.Reader, a mdbx.StorageAuthorityV1, first mdbx.ObsoleteClassV1, maxRows uint32) (mdbx.Batch, error) {
	p.step = selectedSideBranch
	g := a.Cleanup.Spans[0].GenerationID
	page, class, err := p.selectPage(r, g, first, maxRows)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if len(page.Rows) != 0 {
		if err := p.dispose(r, a, page, class); err != nil {
			return mdbx.Batch{}, err
		}
	}
	if p.positive {
		p.step = ""
		return p.batchImage, nil
	}
	exhausted, err := p.exhausted(r, g)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if exhausted {
		a = cleanupGenerationAdvance(a)
	}
	encoded, err := selectedSideEncode(a)
	if err != nil {
		return mdbx.Batch{}, err
	}
	p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
	cleanupDrainSort(&p.batchImage)
	p.step = ""
	return p.batchImage, nil
}

func cleanupGenerationAdvance(a mdbx.StorageAuthorityV1) mdbx.StorageAuthorityV1 {
	a.Cleanup = &mdbx.CleanupV1{Spans: slices.Clone(a.Cleanup.Spans[1:])}
	if len(a.Cleanup.Spans) == 0 {
		a.Cleanup, a.Phase = nil, mdbx.StoragePhaseNoneV1
	}
	return a
}

func (p *cleanupGenerationPlan) selectPage(r *mdbx.Reader, g uint64, first mdbx.ObsoleteClassV1, maxRows uint32) (mdbx.ObsoletePageV1, mdbx.ObsoleteClassV1, error) {
	for offset := mdbx.ObsoleteClassV1(0); offset < 4; offset++ {
		class := (first-1+offset)%4 + 1
		bound := maxRows
		if class == mdbx.ObsoleteIndexV1 || class == mdbx.ObsoleteDerivedV1 {
			bound = 1
		}
		page, err := r.ObsoleteGenerationPageV1(g, class, nil, bound)
		if err != nil {
			return page, class, err
		}
		p.batchImage.ObsoleteConsulted = append(p.batchImage.ObsoleteConsulted, page.Witness)
		if len(page.Rows) != 0 {
			p.rawClass = class
			return page, class, nil
		}
	}
	return mdbx.ObsoletePageV1{}, first, nil
}

func (p *cleanupGenerationPlan) dispose(r *mdbx.Reader, a mdbx.StorageAuthorityV1, page mdbx.ObsoletePageV1, class mdbx.ObsoleteClassV1) error {
	switch class {
	case mdbx.ObsoleteIndexV1:
		return p.index(r, a, page.Rows[0])
	case mdbx.ObsoleteDerivedV1:
		return p.derived(r, a, page.Rows[0])
	default:
		var charged uint64
		for _, row := range page.Rows {
			// Raw values need no copy or decode. A maximum-width UTXO ends
			// this finite work page; even an over-bound malformed first row progresses.
			if charged != 0 && row.Length() > 65560-min(charged, 65560) {
				break
			}
			p.batchImage.ObsoleteDeletes = append(p.batchImage.ObsoleteDeletes, row)
			charged += min(row.Length(), 65560)
		}
		return nil
	}
}

// exactRow observes an opaque partner with a bounded raw page, without Get's
// semantic width requirements. A malformed/orphan partner creates no obligation.
func (p *cleanupGenerationPlan) exactRow(r *mdbx.Reader, g uint64, class mdbx.ObsoleteClassV1, key []byte) (mdbx.ObsoleteRowV1, error) {
	after := cleanupDrainPredecessor(key)
	for {
		page, err := r.ObsoleteGenerationPageV1(g, class, after, 1)
		if err != nil {
			return mdbx.ObsoleteRowV1{}, err
		}
		if len(page.Rows) == 0 || bytes.Compare(page.Rows[0].Key(), key) >= 0 || page.Stop == mdbx.PrefixPageExhausted {
			p.batchImage.ObsoleteConsulted = append(p.batchImage.ObsoleteConsulted, page.Witness)
			if len(page.Rows) == 1 && bytes.Equal(page.Rows[0].Key(), key) {
				return page.Rows[0], nil
			}
			return mdbx.ObsoleteRowV1{}, nil
		}
		// Intermediate predecessors are neither targets nor owner evidence.
		// Reader stores no page registry: only the continuation survives.
		after = page.Next
	}
}

func cleanupDrainPredecessor(key []byte) []byte {
	after := bytes.Clone(key)
	last := len(after) - 1
	if after[last] == 0 {
		after = after[:last]
	} else {
		after[last]--
	}
	return after
}

func (p *cleanupGenerationPlan) derived(r *mdbx.Reader, a mdbx.StorageAuthorityV1, row mdbx.ObsoleteRowV1) error {
	key := row.Key()
	if len(key) == 40 && row.Length() == 8 {
		var value [8]byte
		if _, err := row.ReadAt(value[:], 0); err != nil {
			return err
		}
		indexKey, _ := mdbx.HeightKey(a.Cleanup.Spans[0].GenerationID, binary.BigEndian.Uint64(value[:]))
		index, err := p.exactRow(r, a.Cleanup.Spans[0].GenerationID, mdbx.ObsoleteIndexV1, indexKey)
		if err != nil {
			return err
		}
		if index.Length() == 104 {
			var entry [104]byte
			if _, err := index.ReadAt(entry[:], 0); err != nil {
				return err
			}
			if bytes.Equal(entry[:32], key[8:]) {
				return p.index(r, a, index)
			}
		}
	}
	p.batchImage.ObsoleteDeletes = append(p.batchImage.ObsoleteDeletes, row)
	p.rawClass = mdbx.ObsoleteDerivedV1
	return nil
}

type cleanupGenerationOwners struct {
	canonical                    mdbx.CanonicalOwnerResultV1
	selected, bodyDefer, undoDefer bool
}

func (p *cleanupGenerationPlan) index(r *mdbx.Reader, a mdbx.StorageAuthorityV1, index mdbx.ObsoleteRowV1) error {
	key := index.Key()
	if len(key) != 16 || index.Length() != 104 {
		p.batchImage.ObsoleteDeletes = append(p.batchImage.ObsoleteDeletes, index)
		p.rawClass = mdbx.ObsoleteIndexV1
		return nil
	}
	var entry [104]byte
	if _, err := index.ReadAt(entry[:], 0); err != nil {
		return err
	}
	hash := [32]byte(entry[:32])
	return p.indexKnown(r, a, key, index, hash)
}

func (p *cleanupGenerationPlan) indexKnown(r *mdbx.Reader, a mdbx.StorageAuthorityV1, key []byte, index mdbx.ObsoleteRowV1, hash [32]byte) error {
	owners, err := p.owners(r, a, hash)
	if err != nil {
		return err
	}
	if owners.canonical.Owned {
		p.step = selectedSideCanonical
	}
	proof, err := r.ObsoleteUndoPageV1(index, nil, 1)
	if err != nil {
		return err
	}
	p.step = selectedSideBranch
	p.batchImage.ObsoleteConsulted = append(p.batchImage.ObsoleteConsulted, proof.Witness)
	if err := p.health(r, a, hash, owners); err != nil || p.positive {
		return err
	}
	if proof.Projection == mdbx.ObsoleteProjectionProvenV1 {
		if err := p.dependents(r, a, index, hash, owners); err != nil {
			return err
		}
	}
	return p.pair(r, a.Cleanup.Spans[0].GenerationID, key, hash)
}

func (p *cleanupGenerationPlan) owners(r *mdbx.Reader, a mdbx.StorageAuthorityV1, hash [32]byte) (cleanupGenerationOwners, error) {
	p.step = selectedSideCanonical
	owner, err := r.CanonicalOwnerV1(a.ActiveGenerationID, hash)
	if err != nil {
		return cleanupGenerationOwners{}, err
	}
	p.step = selectedSideBranch
	p.batchImage.Consulted = append(p.batchImage.Consulted, owner.Rows...)
	o := cleanupGenerationOwners{canonical: owner}
	o.selected, err = p.membership(r, a.SelectedSide, hash)
	if err != nil {
		return o, err
	}
	for _, span := range a.Cleanup.Spans[1:] {
		if span.Kind == mdbx.CleanupSpanSideV1 {
			deferBody, readErr := p.sideMembership(r, span.GenerationID, span.NextHeight, span.LastHeight, hash)
			if readErr != nil {
				return o, readErr
			}
			o.bodyDefer = o.bodyDefer || deferBody
		}
		o.promise(span)
	}
	return o, nil
}

func (p *cleanupGenerationPlan) membership(r *mdbx.Reader, side *mdbx.SelectedSideV1, hash [32]byte) (bool, error) {
	if side == nil {
		return false, nil
	}
	return p.sideMembership(r, side.GenerationID, selectedSideFirst(side), side.TipHeight, hash)
}

func (p *cleanupGenerationPlan) sideMembership(r *mdbx.Reader, g, first, last uint64, hash [32]byte) (bool, error) {
	keep := false
	for h := first; h <= last; h++ {
		link, err := r.ReadRequiredSideLink(g, h)
		if err != nil {
			return false, err
		}
		key, _ := mdbx.HeightKey(g, h)
		p.batchImage.Consulted = append(p.batchImage.Consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[6], Key: key})
		keep = keep || bytes.Equal(link[:32], hash[:])
	}
	return keep, nil
}

func (o *cleanupGenerationOwners) promise(span mdbx.CleanupSpanV1) {
	if !o.canonical.Owned || o.canonical.Height < span.NextHeight || o.canonical.Height > span.LastHeight {
		return
	}
	o.bodyDefer = o.bodyDefer || span.Kind == mdbx.CleanupSpanBlocksV1
	o.undoDefer = o.undoDefer || span.Kind == mdbx.CleanupSpanUndoV1
}

func (o cleanupGenerationOwners) keeps(a mdbx.StorageAuthorityV1) (header, bodyRequired, body, undo bool) {
	header = o.canonical.Owned || o.selected
	bodyRequired = o.canonical.Owned && o.canonical.Height >= a.B
	body = bodyRequired || o.selected
	undo = o.canonical.Owned && o.canonical.Height >= a.U
	return
}

func (p *cleanupGenerationPlan) health(r *mdbx.Reader, a mdbx.StorageAuthorityV1, hash [32]byte, o cleanupGenerationOwners) error {
	header, required, body, undo := o.keeps(a)
	if header {
		bad, err := p.headerHealth(r, hash, o.canonical.Entry)
		if err != nil {
			return err
		}
		if bad {
			return p.clear(r)
		}
	}
	if body {
		bad, err := p.bodyHealth(r, hash, required)
		if err != nil {
			return err
		}
		if bad {
			return p.clear(r)
		}
	}
	if undo {
		return p.undoHealth(r, hash, o.canonical.Height)
	}
	return nil
}

func (p *cleanupGenerationPlan) headerHealth(r *mdbx.Reader, hash [32]byte, canonicalEntry []byte) (bool, error) {
	required := len(canonicalEntry) != 0
	if required {
		p.step = selectedSideCanonical
	}
	row, err := r.GetOptionalSide(mdbx.SchemaV2DBIs()[3], hash[:])
	if err != nil {
		return false, err
	}
	p.step = selectedSideBranch
	bad := !row.Present || row.InvalidWidth || sha3.Sum256(row.Value) != hash
	if required && (bad || !bytes.Equal(row.Value[4:36], canonicalEntry[32:64])) {
		return false, selectedSideDefect("invalid cleanup canonical header")
	}
	p.batchImage.Consulted = append(p.batchImage.Consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[3], Key: bytes.Clone(hash[:])})
	return bad, nil
}

// This frame owns the body and parser. It returns before undo raw collection.
func (p *cleanupGenerationPlan) bodyHealth(r *mdbx.Reader, hash [32]byte, required bool) (bool, error) {
	if required {
		p.step = selectedSideCanonical
	}
	row, err := r.GetOptionalSide(mdbx.SchemaV2DBIs()[4], hash[:])
	if err != nil {
		return false, err
	}
	p.step = selectedSideBranch
	bad := !row.Present || row.InvalidWidth
	if !bad {
		bad = sha3.Sum256(row.Value[:116]) != hash || verifyStoredBlockCommitmentsStream(row.Value) != nil
	}
	if bad && required {
		return false, selectedSideDefect("invalid cleanup canonical body")
	}
	p.batchImage.LargeConsulted = append(p.batchImage.LargeConsulted, mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: hash})
	return bad, nil
}

func (p *cleanupGenerationPlan) clear(r *mdbx.Reader) error {
	plan, err := PlanSelectedSideClearMDBX(r)
	if err != nil {
		p.step = plan.ReadResource
		return err
	}
	plan.Batch.Consulted = append(plan.Batch.Consulted, p.batchImage.Consulted...)
	plan.Batch.LargeConsulted = append(plan.Batch.LargeConsulted, p.batchImage.LargeConsulted...)
	plan.Batch.ObsoleteConsulted = p.batchImage.ObsoleteConsulted
	cleanupDrainSort(&plan.Batch)
	p.batchImage, p.positive = plan.Batch, true
	return nil
}

func (p *cleanupGenerationPlan) undoHealth(r *mdbx.Reader, hash [32]byte, height uint64) error {
	p.step = selectedSideCanonical
	u := cleanupUndoHealth{height: height}
	err := r.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageUndoFamilyV1, Hash: hash}, u.visit)
	if err != nil {
		return err
	}
	p.step = selectedSideBranch
	if u.outpoints == nil || len(u.outpoints) != cap(u.outpoints) {
		return selectedSideDefect("invalid cleanup canonical undo")
	}
	slices.SortFunc(u.outpoints, func(a, b [36]byte) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(u.outpoints); i++ {
		if u.outpoints[i-1] == u.outpoints[i] {
			return selectedSideDefect("invalid cleanup canonical undo")
		}
	}
	return nil
}

// This health frame holds only spent outpoints and one bounded value window;
// it ends before any full raw-family handle allocation.
type cleanupUndoHealth struct {
	height    uint64
	txCount   uint32
	previous  [8]byte
	outpoints [][36]byte
}

func (u *cleanupUndoHealth) visit(row mdbx.LargeImageRowV1) error {
	key := row.Key()
	if row.Length() > 65560 {
		return selectedSideDefect("invalid cleanup canonical undo")
	}
	value := make([]byte, int(row.Length()))
	if _, err := row.ReadAt(value[:min(len(value), 65536)], 0); err != nil {
		return err
	}
	if len(value) > 65536 {
		if _, err := row.ReadAt(value[65536:], 65536); err != nil {
			return err
		}
	}
	if mdbx.ValidateRow(mdbx.SchemaV2DBIs()[5], key, value) != nil {
		return selectedSideDefect("invalid cleanup canonical undo")
	}
	return u.row(key, value)
}

func (u *cleanupUndoHealth) row(key, value []byte) error {
	if len(key) == 33 {
		return u.manifest(value)
	}
	tx := binary.BigEndian.Uint32(key[33:37])
	coordinate := [8]byte(key[33:41])
	if u.outpoints == nil || len(u.outpoints) == cap(u.outpoints) || tx == 0 || tx >= u.txCount || len(u.outpoints) != 0 && coordinate == u.previous {
		return selectedSideDefect("invalid cleanup canonical undo")
	}
	u.previous = coordinate
	u.outpoints = append(u.outpoints, [36]byte(key[41:77]))
	return nil
}

func (u *cleanupUndoHealth) manifest(value []byte) error {
	u.txCount = binary.BigEndian.Uint32(value[25:29])
	spent := binary.BigEndian.Uint32(value[29:33])
	if binary.BigEndian.Uint64(value[1:9]) != u.height || u.txCount == 0 || u.txCount > 1545454 || spent > 414634 {
		return selectedSideDefect("invalid cleanup canonical undo")
	}
	u.outpoints = make([][36]byte, 0, int(spent))
	return nil
}

func (p *cleanupGenerationPlan) dependents(r *mdbx.Reader, a mdbx.StorageAuthorityV1, index mdbx.ObsoleteRowV1, hash [32]byte, o cleanupGenerationOwners) error {
	headerKeep, _, bodyKeep, undoKeep := o.keeps(a)
	if !headerKeep {
		p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[3], Key: bytes.Clone(hash[:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	}
	if !bodyKeep && !o.bodyDefer {
		if err := p.bodyDelete(r, hash); err != nil {
			return err
		}
	}
	p.batchImage.LargeConsulted = append(p.batchImage.LargeConsulted, mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: hash})
	if o.undoDefer || undoKeep {
		p.batchImage.LargeConsulted = append(p.batchImage.LargeConsulted, mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageUndoFamilyV1, Hash: hash})
		return nil
	}
	return p.undoDeletes(r, index, o.canonical.Owned)
}

func (p *cleanupGenerationPlan) bodyDelete(r *mdbx.Reader, hash [32]byte) error {
	err := r.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: hash}, func(row mdbx.LargeImageRowV1) error {
		if row.Present() {
			p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[4], Key: bytes.Clone(hash[:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		}
		return nil
	})
	return err
}

func (p *cleanupGenerationPlan) undoDeletes(r *mdbx.Reader, index mdbx.ObsoleteRowV1, requiredProjection bool) error {
	// Exactly one full-family allocation, after body health has returned.
	p.batchImage.ObsoleteDeletes = make([]mdbx.ObsoleteRowV1, 0, 414635)
	var after []byte
	for {
		if requiredProjection {
			p.step = selectedSideCanonical
		}
		page, err := r.ObsoleteUndoPageV1(index, after, 1440)
		if err != nil {
			return err
		}
		p.step = selectedSideBranch
		if len(page.Rows) > cap(p.batchImage.ObsoleteDeletes)-len(p.batchImage.ObsoleteDeletes) {
			return &selectedSideFailure{result: selectedSideCapacity, cause: errors.New("cleanup undo family exceeds native row bound")}
		}
		p.batchImage.ObsoleteDeletes = append(p.batchImage.ObsoleteDeletes, page.Rows...)
		p.batchImage.ObsoleteConsulted = append(p.batchImage.ObsoleteConsulted, page.Witness)
		if page.Stop == mdbx.PrefixPageExhausted {
			return nil
		}
		after = page.Next
	}
}

func (p *cleanupGenerationPlan) pair(r *mdbx.Reader, g uint64, indexKey []byte, hash [32]byte) error {
	p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[2], Key: indexKey, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	key, _ := mdbx.CanonicalOwnerKey(g, hash)
	partner, err := p.exactRow(r, g, mdbx.ObsoleteDerivedV1, key)
	if err != nil {
		return err
	}
	if partner.Length() == 8 {
		var value [8]byte
		if _, err := partner.ReadAt(value[:], 0); err != nil {
			return err
		}
		if bytes.Equal(value[:], indexKey[8:]) {
			p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[7], Key: key, BeforePresent: true, AfterKind: mdbx.AfterAbsent})
		}
	}
	return nil
}

func (p *cleanupGenerationPlan) exhausted(r *mdbx.Reader, g uint64) (bool, error) {
	for class := mdbx.ObsoleteClassV1(1); class <= 4; class++ {
		page, err := r.ObsoleteGenerationPageV1(g, class, nil, 1440)
		if err != nil {
			return false, err
		}
		p.batchImage.ObsoleteConsulted = append(p.batchImage.ObsoleteConsulted, page.Witness)
		for _, row := range page.Rows {
			if !p.deleting(class, row.Key()) {
				return false, nil
			}
		}
		if page.Stop != mdbx.PrefixPageExhausted {
			return false, nil
		}
	}
	return true, nil
}

func (p *cleanupGenerationPlan) deleting(class mdbx.ObsoleteClassV1, key []byte) bool {
	rank := [...]uint8{0, 1, 2, 0, 7}[class]
	for _, target := range p.batchImage.Mutations {
		if target.DBI.Rank == rank && bytes.Equal(target.Key, key) {
			return true
		}
	}
	if p.rawClass != class {
		return false
	}
	_, found := slices.BinarySearchFunc(p.batchImage.ObsoleteDeletes, key, func(row mdbx.ObsoleteRowV1, key []byte) int { return bytes.Compare(row.Key(), key) })
	return found
}

func cleanupDrainSort(batch *mdbx.Batch) {
	slices.SortFunc(batch.Mutations, func(a, b mdbx.Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
	batch.Consulted = selectedSideReadback(batch.Consulted, batch.Mutations)
	slices.SortFunc(batch.LargeConsulted, func(a, b mdbx.LargeImageSelectorV1) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.Hash[:], b.Hash[:])
	})
	batch.LargeConsulted = slices.Compact(batch.LargeConsulted)
	batch.Consulted = slices.DeleteFunc(batch.Consulted, func(row mdbx.ConsultedRow) bool {
		return slices.ContainsFunc(batch.LargeConsulted, func(selector mdbx.LargeImageSelectorV1) bool {
			rank := uint8(4)
			if selector.Kind == mdbx.LargeImageUndoFamilyV1 {
				rank = 5
			}
			return row.DBI.Rank == rank && bytes.HasPrefix(row.Key, selector.Hash[:])
		})
	})
}
