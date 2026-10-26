//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
)

type entryWalkV1 struct {
	s     *entryInventoryStateV1
	old   *Reader
	visit func(EntryInventoryRowV1) error
}

func (w *entryWalkV1) pointV1(row EntryInventoryRowV1, key []byte) (updateImage, error) {
	w.s.requestV1(row, 1, key)
	image, err := w.old.obsoletePoint(0, key, operationGet)
	if err != nil {
		return updateImage{}, w.s.stopV1(1, err)
	}
	if !image.present {
		return image, w.s.stopV1(2, nil)
	}
	return image, nil
}

// This helper's row/walker/native views return before authority decoding begins.
func (s *entryInventoryStateV1) firstAuthorityV1() error {
	w := entryWalkV1{s: s, old: s.reader}
	image, err := w.pointV1(EntryInventoryRowV1{Source: 25, Artifact: 1}, []byte{2})
	if err != nil {
		return err
	}
	borrow, _ := treeBorrowV1(image) // point shape already proved its native span
	s.oldBytes = borrow.value
	return nil
}

func entryDecodeControlV1(c *authorityDecodeControl) {
	c.ordinary.Cursor, c.ordinary.CapturedSelectedSide = &c.cursor, &c.selected
	c.ordinary.CarriedCleanup, c.ordinary.RecordedFailure = &c.cleanup, &c.failure
	c.failure.FailedBlockHash = &c.hash
}

func (s *entryInventoryStateV1) prepareV1() error {
	if err := s.firstAuthorityV1(); err != nil {
		return err
	}
	entryDecodeControlV1(&s.decode[0])
	var err error
	s.authority[0], err = decodeTreeAuthorityV1(s.oldBytes, &s.decode[0], &s.inspection[0])
	if err != nil {
		return s.stopV1(4, nil) // complete malformed OLD is physical, not input
	}
	if s.mutations[0].DBI.Rank != 0 || !bytes.Equal(s.mutations[0].Key, []byte{2}) {
		return entryInputV1()
	}
	s.nextBytes = s.mutations[0].Literal
	entryDecodeControlV1(&s.decode[1])
	s.authority[1], err = decodeTreeAuthorityV1(s.nextBytes, &s.decode[1], &s.inspection[1])
	if err != nil {
		return entryInputV1()
	}
	if err := s.transitionV1(); err != nil {
		return err
	}
	return s.targetsV1()
}

func (s *entryInventoryStateV1) transitionV1() error {
	a, n := s.authority[0], s.authority[1]
	o, next := a.Authority, n.Authority
	oldPhase := anyTrue(o.Phase == 1, o.Phase == 2)
	if !all(o.Lifecycle == 1, oldPhase, o.DetachedSuffix == nil, next.Phase == 4, next.Lifecycle == 2, next.Ordinary != nil, next.SelectedSide == nil, next.DetachedSuffix == nil) {
		return entryInputV1()
	}
	p := next.Ordinary
	d, c := s.inspection[1].old.len(), s.inspection[1].new.len()
	stage := anyTrue(p.Stage == OrdinaryStageConnectV1, p.Stage == OrdinaryStageDisconnectV1)
	if !all(p.Cursor == nil, p.RecordedFailure == nil, stage, (d > 0) == (p.Stage == OrdinaryStageDisconnectV1), c >= 1, d != 0 || c != 1) {
		return entryInputV1()
	}
	if !all(o.ActiveProfile == next.ActiveProfile, o.B == next.B, o.U == next.U, o.ActiveGenerationID == next.ActiveGenerationID, a.LagGenerationID == n.LagGenerationID, a.SourceKind == n.SourceKind, a.TargetLagGenerationID == n.TargetLagGenerationID) {
		return entryInputV1()
	}
	if !all(bytes.Equal(s.inspection[0].phase.encoded, s.inspection[1].carried.encoded), entryExclusionSameV1(o.ExcludedInvalidBranch, next.ExcludedInvalidBranch), s.allocationV1()) {
		return entryInputV1()
	}
	return nil
}

func (s *entryInventoryStateV1) allocationV1() bool {
	o, next := s.authority[0].Authority, s.authority[1].Authority
	captured := next.Ordinary.CapturedSelectedSide
	if s.inspection[1].new.len() == 1 && o.SelectedSide == nil {
		return o.NextGenerationID != ^uint64(0) && next.NextGenerationID == o.NextGenerationID+1 && captured.GenerationID == o.NextGenerationID
	}
	return o.NextGenerationID == next.NextGenerationID && o.SelectedSide != nil && *o.SelectedSide == *captured
}

func entryExclusionSameV1(a, b *InvalidBranchV1) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.FirstInvalidHeight == b.FirstInvalidHeight && a.FirstInvalidBlockHash == b.FirstInvalidBlockHash && bytes.Equal(a.ExactConsensusError, b.ExactConsensusError)
}

func (s *entryInventoryStateV1) targetsV1() error {
	if !s.mutations[0].BeforePresent {
		return entryInputV1()
	}
	link := false
	for _, m := range s.mutations[1:] {
		if !s.targetIdentityV1(m) {
			return entryInputV1()
		}
		link = link || m.DBI.Rank == 6
	}
	if s.inspection[1].new.len() == 1 && s.authority[0].Authority.SelectedSide == nil && !link {
		return entryInputV1()
	}
	return nil
}

func (s *entryInventoryStateV1) targetIdentityV1(m Mutation) bool {
	if m.BeforePresent || m.AfterKind != AfterLiteral {
		return false
	}
	n := s.inspection[1].new
	if m.DBI.Rank == 3 {
		return n.hasHash([32]byte(m.Key), n.len())
	}
	if n.len() != 1 || s.authority[0].Authority.SelectedSide != nil {
		return false
	}
	p := n.at(0)
	if m.DBI.Rank == 4 {
		return bytes.Equal(m.Key, p.BlockHash[:])
	}
	return s.targetLinkV1(m, p)
}

func (s *entryInventoryStateV1) targetLinkV1(m Mutation, p AuthorityPointV1) bool {
	return m.DBI.Rank == 6 && len(m.Literal) == 104 && bytes.Equal(m.Literal[:32], p.BlockHash[:]) && binary.BigEndian.Uint64(m.Key) == s.authority[1].Authority.Ordinary.CapturedSelectedSide.GenerationID && binary.BigEndian.Uint64(m.Key[8:]) == p.Height
}

func entryMetaV1(kind byte, generation uint64) [9]byte {
	var key [9]byte
	key[0] = kind
	binary.BigEndian.PutUint64(key[1:], generation)
	return key
}

func (w *entryWalkV1) controlsV1() error {
	s := w.s
	for role, g := range [2]uint64{s.authority[0].Authority.ActiveGenerationID, s.authority[0].LagGenerationID} {
		row := EntryInventoryRowV1{Source: uint8(1 + role*2), Artifact: 2, Role: uint8(role + 1), Generation: g}
		key := entryMetaV1(0x10, g)
		image, err := w.pointV1(row, key[:])
		if err != nil {
			return err
		}
		if image.length != 16 {
			return s.stopV1(4, nil)
		}
		if err := w.emitV1(row, key[:], image); err != nil {
			return err
		}
		if err := w.bindingV1(uint8(role), g); err != nil {
			return err
		}
	}
	return entryInputV1()
}

func (w *entryWalkV1) bindingV1(role uint8, generation uint64) error {
	s := w.s
	row := EntryInventoryRowV1{Source: 2 + role*2, Artifact: 11, Role: role + 1, Generation: generation}
	key := entryMetaV1(0x11, generation)
	image, err := w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	b, _ := treeBorrowV1(image)
	s.roots[role], err = decodeRootBindingV1(b.value, &s.rootControl[role])
	if err != nil || s.roots[role].DatabaseID != w.old.databaseID {
		return s.stopV1(4, nil)
	}
	if s.roots[role].Endpoint.Kind == 1 {
		row.IndexCount = s.roots[role].Endpoint.Height + 1
	}
	if err := w.emitV1(row, key[:], image); err != nil {
		return err
	}
	return w.assuranceV1(role, row)
}

func (w *entryWalkV1) assuranceV1(role uint8, row EntryInventoryRowV1) error {
	ref := w.s.roots[role].Assurance.Import
	if ref == nil {
		return nil
	}
	if !w.old.ownerVerified {
		return entryInputV1()
	}
	var key [33]byte
	key[0] = 0x12
	copy(key[1:], ref.EvidenceID[:])
	row.Source, row.Artifact, row.IndexCount = 26, 12, 0
	image, err := w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	// Startup qualified this jointly immutable capsule. Its opaque payload is
	// borrowed raw; this prefix neither clones nor semantically qualifies it.
	_, _ = treeBorrowV1(image)
	return nil
}

func (w *entryWalkV1) emitV1(row EntryInventoryRowV1, key []byte, image updateImage) error {
	s, r := w.s, w.old
	s.serial++
	a := &s.access
	a.reader, a.image, a.serial, a.active = r, image, s.serial, true
	a.key = a.key[:copy(a.key[:cap(a.key)], key)]
	row.Key, row.Present, row.Length = a.key, image.present, uint64(image.length)
	row.access, row.serial = a, s.serial
	s.row = row
	err := w.visitRowV1(row)
	if s.retired {
		return entryInputV1()
	}
	s.access.active = false
	if err != nil {
		return err
	}
	if s.failed {
		return errEntryStoppedV1
	}
	if !r.usable() {
		if r.failure != nil {
			return r.failure
		}
		return entryInputV1()
	}
	return err
}

func (w *entryWalkV1) visitRowV1(row EntryInventoryRowV1) error {
	mu := &w.old.getMu // retain only the immutable locator across user code
	mu.Unlock()
	defer mu.Lock()
	return w.visit(row)
}
