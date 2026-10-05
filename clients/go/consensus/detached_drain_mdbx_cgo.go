//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"slices"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// DrainDetachedMDBX drains exactly the first committed detached cursor entry.
// It is dormant: its caller must have ended source copying and released pins.
// One full-lane grant encloses the sole Update, readback and native cleanup.
func DrainDetachedMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner) SelectedSideDamageOutcome {
	out := selectedSideOutcome{Truth: mdbx.CommitTruthOld, Stage: mdbx.UpdateStagePrewrite}
	if store == nil {
		out.Truth, out.Stage, out.Err = store.Update(nil)
		return out
	}
	p := &detachedDrainPlan{cleanupGenerationPlan: cleanupGenerationPlan{noWork: errors.New("detached drain has no selected work")}}
	ran, called := false, false
	update := func(r *mdbx.Reader) (mdbx.Batch, error) {
		called = true
		return p.batch(r)
	}
	err := reservations.WithReservation(mdbx.MaxOperationDataBytes, func() error {
		ran = true
		out.Truth, out.Stage, out.Err = store.Update(update)
		return out.Err
	})
	if !ran {
		if err.Error() != selectedSideCapacityText {
			out.Err = err
			return out
		}
		p.denied = err
		out.Truth, out.Stage, out.Err = store.Update(update)
	}
	if !called {
		return out
	}
	return p.project(out)
}

type detachedDrainPlan struct {
	cleanupGenerationPlan
	denied error
}

func (p *detachedDrainPlan) project(out selectedSideOutcome) selectedSideOutcome {
	switch out.Stage {
	case mdbx.UpdateStageCommitMayHaveCrossed:
		out = archiveSelectedSideCrossed(out)
		if out.Truth == mdbx.CommitTruthNew && out.Err == nil && p.positive {
			out.Result, out.CanonicalTruth = "LOCAL_STORE_ERROR(noncanonical)", "NOT_APPLICABLE"
		}
		return out
	case mdbx.UpdateStagePrewrite:
		return p.prewrite(out)
	case mdbx.UpdateStageInvalid, mdbx.UpdateStageWriteStartedDefinitelyPrecommit:
	}
	out.CanonicalTruth = "OLD"
	classification := &selectedSideDamagePlan{healthy: p.noWork, denied: p.denied, step: p.step}
	if out.Stage == mdbx.UpdateStageWriteStartedDefinitelyPrecommit {
		out.Result = selectedSidePrecommitResult(out.Err, classification)
		return out
	}
	out.Result = selectedSideResult(out.Err, classification)
	return out
}

func (p *detachedDrainPlan) prewrite(out selectedSideOutcome) selectedSideOutcome {
	out.CanonicalTruth = "OLD"
	classification := &selectedSideDamagePlan{healthy: p.noWork, denied: p.denied, step: p.step}
	return selectedSideDamageProject(out, classification)
}

func (p *detachedDrainPlan) batch(r *mdbx.Reader) (mdbx.Batch, error) {
	a, err := cleanupDrainAuthority(r)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if a.Phase != mdbx.StoragePhasePruneGCV1 || a.DetachedSuffix == nil {
		return mdbx.Batch{}, p.noWork
	}
	if p.denied != nil {
		p.step = selectedSideCapacity
		return mdbx.Batch{}, p.denied
	}
	return p.drain(r, a)
}

func (p *detachedDrainPlan) drain(r *mdbx.Reader, a mdbx.StorageAuthorityV1) (mdbx.Batch, error) {
	e := a.DetachedSuffix.Entries[0]
	o, err := p.owners(r, a, e.Hash)
	if err != nil {
		return mdbx.Batch{}, err
	}
	parent, err := p.parent(r, a)
	if err != nil {
		return mdbx.Batch{}, err
	}
	if err := p.remnants(r, a, e, parent, o); err != nil {
		return mdbx.Batch{}, err
	}
	next, err := detachedDrainAdvance(a)
	if err != nil {
		return mdbx.Batch{}, err
	}
	encoded, err := selectedSideEncode(next)
	if err != nil {
		return mdbx.Batch{}, err
	}
	p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[0], Key: []byte{2}, BeforePresent: true, AfterKind: mdbx.AfterLiteral, Literal: encoded})
	cleanupDrainSort(&p.batchImage)
	p.step = ""
	return p.batchImage, nil
}

func (p *detachedDrainPlan) parent(r *mdbx.Reader, a mdbx.StorageAuthorityV1) ([32]byte, error) {
	d := a.DetachedSuffix
	if d.Entries[0].Height == 0 {
		return [32]byte{}, nil
	}
	if len(d.Entries) > 1 {
		return d.Entries[1].Hash, nil
	}
	p.step = selectedSideCanonical
	key, _ := mdbx.HeightKey(a.ActiveGenerationID, d.Entries[0].Height-1)
	value, present, err := r.Get(mdbx.SchemaV2DBIs()[2], key)
	if err != nil {
		return [32]byte{}, err
	}
	if !present || !archiveSelectedSideWork(value[64:104]) {
		return [32]byte{}, selectedSideDefect("detached fork parent is absent or undecodable")
	}
	p.batchImage.Consulted = append(p.batchImage.Consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[2], Key: key})
	p.step = selectedSideBranch
	return [32]byte(value[:32]), nil
}

func (p *detachedDrainPlan) remnants(r *mdbx.Reader, a mdbx.StorageAuthorityV1, e mdbx.DetachedSuffixEntryV1, parent [32]byte, o cleanupGenerationOwners) error {
	headerKeep, required, bodyKeep, _ := o.keeps(a)
	present, err := p.header(r, e, parent, o)
	if err != nil {
		return err
	}
	if present && !headerKeep {
		p.batchImage.Mutations = append(p.batchImage.Mutations, mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[3], Key: bytes.Clone(e.Hash[:]), BeforePresent: true, AfterKind: mdbx.AfterAbsent})
	} else {
		p.batchImage.Consulted = append(p.batchImage.Consulted, mdbx.ConsultedRow{DBI: mdbx.SchemaV2DBIs()[3], Key: bytes.Clone(e.Hash[:])})
	}
	if err := p.body(r, e, required); err != nil {
		return err
	}
	if !bodyKeep && !o.bodyDefer {
		if err := p.bodyDelete(r, e.Hash); err != nil {
			return err
		}
	}
	p.batchImage.LargeConsulted = append(p.batchImage.LargeConsulted, mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: e.Hash})
	return nil
}

func (p *detachedDrainPlan) header(r *mdbx.Reader, e mdbx.DetachedSuffixEntryV1, parent [32]byte, o cleanupGenerationOwners) (bool, error) {
	p.step = selectedSideBranch
	if o.canonical.Owned {
		p.step = selectedSideCanonical
	}
	header, err := r.GetOptionalSide(mdbx.SchemaV2DBIs()[3], e.Hash[:])
	if err != nil {
		return false, err
	}
	bad := detachedHeaderInvalid(header.Value, e.Hash)
	if o.canonical.Owned && (bad || !bytes.Equal(header.Value[4:36], o.canonical.Entry[32:64])) {
		return false, selectedSideDefect("invalid cleanup canonical header")
	}
	p.positive = bad || detachedParentInvalid(e.Height, header.Value, parent) || o.selected.headerDamage(header.Value)
	return header.Present, nil
}

func detachedHeaderInvalid(value []byte, hash [32]byte) bool {
	return len(value) != 116 || sha3.Sum256(value) != hash
}

func detachedParentInvalid(height uint64, value []byte, parent [32]byte) bool {
	return height > 0 && !bytes.Equal(value[4:36], parent[:])
}

// The health body copy and streaming parser end before native image capture.
// After positive header damage only native presence is needed, never a body copy.
func (p *detachedDrainPlan) body(r *mdbx.Reader, e mdbx.DetachedSuffixEntryV1, required bool) error {
	p.step = selectedSideBranch
	if required {
		p.step = selectedSideCanonical
	}
	if p.positive {
		return r.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: e.Hash}, func(row mdbx.LargeImageRowV1) error {
			if required && !row.Present() {
				return selectedSideDefect("invalid cleanup canonical body")
			}
			return nil
		})
	}
	row, err := r.GetOptionalSide(mdbx.SchemaV2DBIs()[4], e.Hash[:])
	if err != nil {
		return err
	}
	bad := detachedBodyInvalid(row, e)
	if bad && required {
		return selectedSideDefect("invalid cleanup canonical body")
	}
	p.positive = bad
	p.step = selectedSideBranch
	return nil
}

func detachedBodyInvalid(row mdbx.OptionalSideValueV1, e mdbx.DetachedSuffixEntryV1) bool {
	if !row.Present || row.InvalidWidth || row.Length != e.BlockBytesLen {
		return true
	}
	return sha3.Sum256(row.Value[:116]) != e.Hash || verifyStoredBlockCommitmentsStream(row.Value) != nil
}

func detachedDrainAdvance(a mdbx.StorageAuthorityV1) (mdbx.StorageAuthorityV1, error) {
	d := a.DetachedSuffix
	e := d.Entries[0]
	if d.EntryCount == 0 || d.LogicalBytes < e.BlockBytesLen {
		return a, selectedSideIllegal()
	}
	a.DetachedSuffix = nil
	if len(d.Entries) > 1 {
		next := d.Entries[1]
		a.DetachedSuffix = &mdbx.DetachedSuffixV1{Entries: slices.Clone(d.Entries[1:]), Cursor: mdbx.AuthorityPointV1{Height: next.Height, BlockHash: next.Hash}, EntryCount: d.EntryCount - 1, LogicalBytes: d.LogicalBytes - e.BlockBytesLen}
	}
	return a, nil
}
