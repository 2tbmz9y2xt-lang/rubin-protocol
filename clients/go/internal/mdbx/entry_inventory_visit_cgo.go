//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
)

type entryWalkV1 struct {
	s         *entryInventoryStateV1
	old       *Reader
	candidate *Reader
	visit     func(EntryInventoryRowV1) error
	stream    *entryStreamV1
	other     *entryStreamV1
	cursor    *entryCursorV1
	context   *EntryInventoryRowV1
	plan      *treePlanV1
	equal     bool
}

type entryCursorV1 struct {
	positions [2]uint64
	hashes    [2][32]byte
}

func entryRankV1(artifact uint8) uint8 {
	ranks := [...]uint8{255, 0, 0, 1, 2, 7, 3, 4, 5, 6, 8, 0, 0}
	return ranks[artifact]
}

func (w *entryWalkV1) pointV1(row *EntryInventoryRowV1, key []byte) (updateImage, error) {
	w.s.requestV1(row, 1, key)
	image, err := w.old.obsoletePoint(entryRankV1(row.Artifact), key, w.operationV1())
	if err != nil {
		return updateImage{}, w.s.stopV1(1, err)
	}
	if err := w.pointCompareV1(row, key, &image); err != nil {
		return updateImage{}, err
	}
	return image, nil
}

func (w *entryWalkV1) rowV1(source, artifact, role uint8, generation uint64) *EntryInventoryRowV1 {
	w.s.row = EntryInventoryRowV1{Source: source, Artifact: artifact, Role: role, Generation: generation}
	return &w.s.row
}

func (w *entryWalkV1) requiredV1(row *EntryInventoryRowV1, key []byte) (updateImage, error) {
	image, err := w.pointV1(row, key)
	if err == nil && !image.present {
		err = w.s.stopV1(2, nil)
	}
	return image, err
}

// This helper's row/walker/native views return before authority decoding begins.
func (s *entryInventoryStateV1) firstAuthorityV1() error {
	w := entryWalkV1{s: s, old: s.reader}
	row := EntryInventoryRowV1{Source: 25, Artifact: 1}
	image, err := w.requiredV1(&row, []byte{2})
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
		row := w.rowV1(uint8(1+role*2), 2, uint8(role+1), g)
		key := entryMetaV1(0x10, g)
		image, err := w.requiredV1(row, key[:])
		if err != nil {
			return err
		}
		if image.length != 16 {
			return s.stopV1(4, nil)
		}
		if err := w.emitV1(row, key[:], &image); err != nil {
			return err
		}
		if err := w.bindingV1(uint8(role), g, row); err != nil {
			return err
		}
	}
	return nil
}

func (w *entryWalkV1) bindingV1(role uint8, generation uint64, row *EntryInventoryRowV1) error {
	s := w.s
	*row = EntryInventoryRowV1{Source: 2 + role*2, Artifact: 11, Role: role + 1, Generation: generation}
	key := entryMetaV1(0x11, generation)
	image, err := w.requiredV1(row, key[:])
	if err != nil {
		return err
	}
	b, _ := treeBorrowV1(image)
	root, err := decodeRootBindingV1(b.value, &s.rootControl)
	if err != nil || root.DatabaseID != w.old.databaseID {
		return s.stopV1(4, nil)
	}
	s.endpoints[role] = root.Endpoint
	if root.Endpoint.Kind == 1 {
		row.IndexCount = root.Endpoint.Height + 1
	}
	b.value = nil
	if err := w.emitV1(row, key[:], &image); err != nil {
		return err
	}
	err = w.assuranceV1(root.Assurance.Import, row)
	root.Top.Node, root.Assurance.Import = nil, nil
	s.rootControl = rootDecodeControl{}
	return err
}

func (w *entryWalkV1) assuranceV1(ref *TreeImportReferenceV1, row *EntryInventoryRowV1) error {
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
	image, err := w.requiredV1(row, key[:])
	if err != nil {
		return err
	}
	// Startup qualified this jointly immutable capsule. Its opaque payload is
	// borrowed raw; this prefix neither clones nor semantically qualifies it.
	_, _ = treeBorrowV1(image)
	return nil
}

// Move the caller's image into the registered access owner before unlocking.
func (w *entryWalkV1) emitV1(row *EntryInventoryRowV1, key []byte, image *updateImage) error {
	if w.visit == nil {
		*image = updateImage{}
		return nil
	}
	s, r := w.s, w.old
	s.serial++
	a := &s.access
	a.reader, a.image, a.serial, a.active = r, *image, s.serial, row.Source != 6
	a.key = a.key[:copy(a.key[:cap(a.key)], key)]
	row.Key, row.Present, row.Length = a.key, image.present, uint64(image.length)
	if row.Source == 6 {
		row.Key = nil
	}
	row.access, row.serial = a, s.serial
	s.row = *row
	*image = updateImage{}
	err := w.visitRowV1(row)
	if s.retired {
		return entryInputV1()
	}
	s.access.active, s.access.image = false, updateImage{}
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

func (w *entryWalkV1) visitRowV1(row *EntryInventoryRowV1) error {
	mu := &w.old.getMu // retain only the immutable locator across user code
	mu.Unlock()
	defer mu.Lock()
	return w.visit(*row)
}

func (w *entryWalkV1) literalV1(rank uint8, key []byte) (updateImage, bool, error) {
	if w.plan != nil {
		if i := canonicalTargetIndex(w.plan.pair, rank, key); i >= 0 {
			image, err := updateOwnedImage(w.plan.pair[i].literal)
			return image, true, err
		}
		return updateImage{}, false, nil
	}
	for _, m := range w.s.mutations {
		if m.DBI.Rank == rank && bytes.Equal(m.Key, key) {
			image, err := updateOwnedImage(m.Literal)
			return image, true, err
		}
	}
	return updateImage{}, false, nil
}

func (w *entryWalkV1) imageV1(row *EntryInventoryRowV1, key []byte) (updateImage, error) {
	image, err := w.pointV1(row, key)
	if err != nil {
		return image, err
	}
	projected, found, err := w.literalV1(entryRankV1(row.Artifact), key)
	if err != nil {
		return updateImage{}, err
	}
	if found {
		return w.targetImageV1(image, projected)
	}
	if !image.present {
		return image, w.s.stopV1(2, nil)
	}
	return image, nil
}

func (w *entryWalkV1) targetImageV1(old, projected updateImage) (updateImage, error) {
	if !old.present {
		return projected, nil
	}
	if !largeRowsEqual(largeNativeRow{image: old}, largeNativeRow{image: projected}) {
		return updateImage{}, w.s.stopV1(4, nil)
	}
	return updateImage{}, entryInputV1()
}

// After imageV1 succeeds, a matching target proves OLD was absent.
func (w *entryWalkV1) malformedImageV1(row *EntryInventoryRowV1, key []byte) error {
	_, literal, err := w.literalV1(entryRankV1(row.Artifact), key)
	if err != nil {
		return err
	}
	if literal {
		return entryInputV1()
	}
	return w.s.stopV1(4, nil)
}

func (w *entryWalkV1) runV1() error {
	w.stream.seek = make([]byte, w.s.maxKey)
	if err := w.controlsV1(); err != nil {
		return err
	}
	if err := w.pathsV1(); err != nil {
		return err
	}
	if err := w.oldUndoV1(); err != nil {
		return err
	}
	if err := w.headerGroupV1(); err != nil {
		return err
	}
	if err := w.canonicalV1(false); err != nil {
		return err
	}
	if err := w.canonicalV1(true); err != nil {
		return err
	}
	if err := w.capturedV1(); err != nil {
		return err
	}
	return w.obsoleteV1()
}

func (w *entryWalkV1) headerGroupV1() error {
	row := w.rowV1(6, 6, 1, w.s.authority[0].Authority.ActiveGenerationID)
	row.Count = w.s.endpoints[0].Height + 1
	image := updateImage{}
	return w.emitV1(row, nil, &image)
}

func entryHeightV1(generation, height uint64) [16]byte {
	var key [16]byte
	binary.BigEndian.PutUint64(key[:8], generation)
	binary.BigEndian.PutUint64(key[8:], height)
	return key
}

func (w *entryWalkV1) canonicalPointV1(height uint64) ([104]byte, error) {
	var value [104]byte
	g := w.s.authority[0].Authority.ActiveGenerationID
	row := w.rowV1(27, 4, 1, g)
	row.Height = height
	key := entryHeightV1(g, height)
	image, err := w.requiredV1(row, key[:])
	if err != nil {
		return value, err
	}
	if image.length != 104 {
		return value, w.s.stopV1(4, nil)
	}
	_, _ = largeImageCopy(value[:], image.bytes, 104, 0)
	if !validWork([40]byte(value[64:])) {
		return value, w.s.stopV1(4, nil)
	}
	return value, nil
}

func (s *entryInventoryStateV1) boundaryV1() (uint64, error) {
	tip, old := s.endpoints[0], s.inspection[1].old
	if tip.Kind != 1 {
		return 0, entryInputV1()
	}
	f := tip.Height
	if old.len() > 0 {
		if old.at(0) != (AuthorityPointV1{Height: tip.Height, BlockHash: tip.BlockHash}) {
			return 0, entryInputV1()
		}
		f = old.at(old.len()-1).Height - 1
	}
	if s.inspection[1].new.at(0).Height != f+1 {
		return 0, entryInputV1()
	}
	return f, nil
}

func (w *entryWalkV1) pathsV1() error {
	if !w.old.ownerVerified {
		return entryInputV1()
	}
	f, err := w.s.boundaryV1()
	if err != nil {
		return err
	}
	for i := 0; i < w.s.inspection[1].old.len(); i++ {
		if err := w.oldPathV1(i); err != nil {
			return err
		}
	}
	return w.commonPathV1(f)
}

// The common boundary binds the first N parent to actual CURRENT bytes.
func (w *entryWalkV1) commonPathV1(height uint64) error {
	entry, err := w.canonicalPointV1(height)
	if err != nil {
		return err
	}
	expected := w.s.endpoints[0].BlockHash
	if w.s.inspection[1].old.len() > 0 {
		expected = w.cursor.hashes[1]
	} else if [40]byte(entry[64:]) != w.s.endpoints[0].CumulativeChainwork {
		return entryInputV1()
	}
	if expected != [32]byte(entry[:32]) {
		return entryInputV1()
	}
	if err := w.canonicalHeaderV1(height, &entry); err != nil {
		return err
	}
	w.cursor.hashes[0] = expected
	return nil
}

func (w *entryWalkV1) oldPathV1(i int) error {
	old := w.s.inspection[1].old
	p := old.at(i)
	entry, err := w.canonicalPointV1(p.Height)
	if err != nil {
		return err
	}
	if [32]byte(entry[:32]) != p.BlockHash {
		return entryInputV1()
	}
	if i == 0 && [40]byte(entry[64:]) != w.s.endpoints[0].CumulativeChainwork {
		return entryInputV1()
	}
	if err := w.canonicalHeaderV1(p.Height, &entry); err != nil {
		return err
	}
	parent := [32]byte(entry[32:64])
	if i+1 < old.len() && parent != old.at(i+1).BlockHash {
		return entryInputV1()
	}
	w.cursor.hashes[1] = parent
	return nil
}

func (w *entryWalkV1) canonicalHeaderV1(height uint64, entry *[104]byte) error {
	row := w.rowV1(27, 6, 1, w.s.authority[0].Authority.ActiveGenerationID)
	row.Height, row.Hash = height, [32]byte(entry[:32])
	image, err := w.requiredV1(row, row.Hash[:])
	if err != nil {
		return err
	}
	return w.headerV1(row, image, [32]byte(entry[32:64]))
}

func (w *entryWalkV1) headerV1(row *EntryInventoryRowV1, image updateImage, parent [32]byte) error {
	if !entryLinkedV1(&image, &row.Hash, &parent) {
		if row.Source == 11 {
			return w.malformedImageV1(row, row.Hash[:])
		}
		return w.s.stopV1(4, nil)
	}
	return nil
}

func (w *entryWalkV1) oldUndoV1() error {
	old := w.s.inspection[1].old
	for i := 0; i < old.len(); i++ {
		p := old.at(i)
		row := w.rowV1(5, 8, 1, w.s.authority[0].Authority.ActiveGenerationID)
		row.Height, row.Hash = p.Height, p.BlockHash
		if err := w.undoV1(row); err != nil {
			return err
		}
	}
	return nil
}

func (w *entryWalkV1) bodyV1(row *EntryInventoryRowV1) error {
	image, err := w.imageV1(row, row.Hash[:])
	if err != nil {
		return err
	}
	borrow, _ := treeBorrowV1(image)
	if validateInitial148Value(row.Hash, borrow.value, true) != nil {
		return w.s.stopV1(4, nil)
	}
	borrow.value = nil
	return w.emitV1(row, row.Hash[:], &image)
}

func (w *entryWalkV1) bodyFirstV1() uint64 {
	if w.s.authority[0].Authority.ActiveProfile == 2 || w.s.endpoints[1].Kind == 0 {
		return 0
	}
	return w.s.endpoints[1].Height + 1
}

func (w *entryWalkV1) canonicalV1(undo bool) error {
	s := w.s
	first, source, artifact, kind := w.bodyFirstV1(), uint8(7), uint8(7), CleanupSpanBlocksV1
	if undo {
		first, source, artifact, kind = s.authority[0].Authority.U, 9, 8, CleanupSpanUndoV1
	}
	if err := w.heightRangeV1(first, s.endpoints[0].Height, source, artifact, undo); err != nil {
		return err
	}
	for i := 0; i < s.inspection[0].phase.len(); i++ {
		span := s.inspection[0].phase.at(i)
		if span.Kind != kind {
			continue
		}
		if err := w.heightRangeV1(span.NextHeight, span.LastHeight, source+1, artifact, undo); err != nil {
			return err
		}
	}
	return nil
}

func (w *entryWalkV1) heightRangeV1(first, last uint64, source, artifact uint8, undo bool) error {
	for height := first; height <= last; height++ {
		entry, err := w.canonicalPointV1(height)
		if err != nil {
			return err
		}
		row := w.rowV1(source, artifact, 1, w.s.authority[0].Authority.ActiveGenerationID)
		row.Height, row.Hash = height, [32]byte(entry[:32])
		if undo && w.s.inspection[1].old.hasHash(row.Hash, w.s.inspection[1].old.len()) {
			continue
		}
		if undo {
			err = w.undoV1(row)
		} else {
			err = w.bodyV1(row)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *entryWalkV1) capturedV1() error {
	n := w.s.inspection[1].new
	for i := 0; i < n.len(); i++ {
		if err := w.capturedMemberV1(i, w.cursor.hashes[0]); err != nil {
			return err
		}
		w.cursor.hashes[0] = n.at(i).BlockHash
	}
	return nil
}

func (w *entryWalkV1) capturedMemberV1(i int, parent [32]byte) error {
	p := w.s.inspection[1].new.at(i)
	side := w.s.authority[1].Authority.Ordinary.CapturedSelectedSide
	bodySource, linkSource := uint8(12), uint8(13)
	if p.Height < side.TipHeight-uint64(side.RowCount)+1 {
		bodySource, linkSource = 14, 15
	}
	row := w.rowV1(linkSource, 9, 0, side.GenerationID)
	row.Height, row.Hash = p.Height, p.BlockHash
	key := entryHeightV1(side.GenerationID, p.Height)
	if err := w.capturedLinkV1(row, key[:], parent); err != nil {
		return err
	}
	row.Source, row.Artifact = 11, 6
	if err := w.capturedHeaderV1(row, parent); err != nil {
		return err
	}
	row.Source, row.Artifact = bodySource, 7
	if err := w.bodyV1(row); err != nil {
		return err
	}
	row.Source, row.Artifact = linkSource, 9
	return w.emitV1(row, key[:], &w.stream.row.image)
}

func (w *entryWalkV1) capturedHeaderV1(row *EntryInventoryRowV1, parent [32]byte) error {
	image, err := w.imageV1(row, row.Hash[:])
	if err != nil {
		return err
	}
	if err := w.headerV1(row, image, parent); err != nil {
		return err
	}
	return w.emitV1(row, row.Hash[:], &image)
}

func (w *entryWalkV1) capturedLinkV1(row *EntryInventoryRowV1, key []byte, parent [32]byte) error {
	image, err := w.imageV1(row, key)
	if err != nil {
		return err
	}
	if image.length != 104 {
		return w.s.stopV1(4, nil)
	}
	b, _ := treeBorrowV1(image)
	work := [40]byte(b.value[64:])
	if !all([32]byte(b.value[:32]) == row.Hash, [32]byte(b.value[32:64]) == parent, validWork(work)) {
		return w.malformedImageV1(row, key)
	}
	side := w.s.authority[1].Authority.Ordinary.CapturedSelectedSide
	if row.Height == side.TipHeight && work != side.CumulativeChainwork {
		return entryInputV1()
	}
	w.stream.row.image = image
	return nil
}

type entryStreamV1 struct {
	reader *Reader
	domain obsoleteDomain
	seek   []byte
	row    largeNativeRow
	done   bool
}

func entrySuccessorV1(buffer, key []byte) []byte {
	n := copy(buffer[:cap(buffer)], key)
	if n < cap(buffer) {
		buffer = buffer[:n+1]
		buffer[n] = 0
		return buffer
	}
	buffer = buffer[:n]
	for i := n - 1; i >= 0; i-- {
		if buffer[i] != 255 {
			buffer[i]++
			return buffer[:i+1]
		}
	}
	return buffer[:0]
}

func (w *entryWalkV1) fetchV1(stream *entryStreamV1, row *EntryInventoryRowV1) error {
	if stream.done || len(stream.seek) == 0 {
		stream.done = true
		return nil
	}
	w.s.requestV1(row, 2, stream.seek)
	w.s.failure.Prefix = w.s.access.key[:copy(w.s.access.key[:cap(w.s.access.key)], stream.domain.prefix)]
	next, err := stream.reader.obsoleteFetch(stream.domain, stream.seek, w.operationV1())
	if err != nil {
		return w.s.stopV1(1, err)
	}
	stream.row, stream.done = next, next.done
	if !next.done {
		w.s.requestV1(row, 2, next.key) // a positive row owns its actual key
		w.s.failure.Prefix = w.s.access.key[:copy(w.s.access.key[:cap(w.s.access.key)], stream.domain.prefix)]
	}
	return nil
}

func (w *entryWalkV1) scanV1(row *EntryInventoryRowV1) error {
	stream := w.stream
	w.scanStartV1(stream, w.old, row)
	if w.other != nil {
		w.scanStartV1(w.other, w.candidate, row)
	}
	for {
		stream.row = largeNativeRow{}
		if err := w.fetchV1(stream, row); err != nil {
			return err
		}
		if err := w.scanCompareV1(row); err != nil {
			return err
		}
		if stream.done {
			stream.reader, stream.domain, stream.row = nil, obsoleteDomain{}, largeNativeRow{}
			return nil
		}
		w.s.requestV1(row, 2, stream.row.key)
		w.s.failure.Prefix = w.s.access.key[:copy(w.s.access.key[:cap(w.s.access.key)], stream.domain.prefix)]
		if err := w.scanRowV1(row); err != nil {
			return err
		}
	}
}

func (w *entryWalkV1) scanStartV1(stream *entryStreamV1, reader *Reader, row *EntryInventoryRowV1) {
	stream.reader, stream.done = reader, false
	prefix := row.Hash[:]
	if row.Source != 22 && row.Artifact != 8 {
		// Captured linkage has ended. This existing cursor slot is stable while
		// successor advancement mutates seek, including a full-M suffix of ff.
		binary.BigEndian.PutUint64(w.cursor.hashes[0][:8], row.Generation)
		prefix = w.cursor.hashes[0][:8]
	}
	stream.domain = obsoleteDomain{rank: entryRankV1(row.Artifact), prefix: prefix}
	stream.seek = stream.seek[:copy(stream.seek[:cap(stream.seek)], prefix)]
}

func (w *entryWalkV1) scanRowV1(row *EntryInventoryRowV1) error {
	stream := w.stream
	if row.Source == 17 && len(stream.row.key) == 16 {
		return w.indexRowV1(row)
	}
	if err := w.rawRowV1(row); err != nil {
		return err
	}
	if err := w.emitV1(row, stream.row.key, &stream.row.image); err != nil {
		return err
	}
	stream.seek = entrySuccessorV1(stream.seek, stream.row.key)
	w.advanceOtherV1()
	return nil
}

func (w *entryWalkV1) rawRowV1(row *EntryInventoryRowV1) error {
	switch row.Source {
	case 17:
		row.Projection = 1
	case 23:
		row.Node = TreeNodeIDV1{}
		g, id, err := DecodeTreeNodeKey(w.stream.row.key)
		if err != nil || g != row.Generation {
			return w.s.stopV1(4, nil)
		}
		row.Node = id
	}
	if row.Artifact == 8 {
		return w.rawShapeV1(w.stream.row.key, w.stream.row.image)
	}
	return nil
}

// Only a fixed resume identity and candidate exhaustion survive a child scan.
func (w *entryWalkV1) indexRowV1(row *EntryInventoryRowV1) error {
	var fixed [16]byte
	copy(fixed[:], w.stream.row.key)
	image := w.stream.row.image
	w.stream.row, w.stream.domain = largeNativeRow{}, obsoleteDomain{}
	done := false
	if w.other != nil {
		done = w.other.done
		w.other.row, w.other.domain = largeNativeRow{}, obsoleteDomain{}
	}
	if err := w.indexV1(row, fixed[:], &image); err != nil {
		return err
	}
	*row = EntryInventoryRowV1{Source: 17, Artifact: 4, Generation: binary.BigEndian.Uint64(fixed[:])}
	w.scanStartV1(w.stream, w.old, row)
	w.stream.seek = entrySuccessorV1(w.stream.seek, fixed[:])
	if w.other != nil {
		w.scanStartV1(w.other, w.candidate, row)
		w.other.done = done
	}
	w.advanceOtherV1()
	return nil
}

func (w *entryWalkV1) rawShapeV1(key []byte, image updateImage) error {
	borrow, _ := treeBorrowV1(image)
	if !validUndoKey(key) || !treeUndoValueOKV1(key, borrow.value) {
		return w.s.stopV1(4, nil)
	}
	if len(key) == 77 {
		w.cursor.positions[0]++
		if w.cursor.positions[0] > w.cursor.positions[1] {
			return w.s.stopV1(4, nil)
		}
	}
	return nil
}

func (w *entryWalkV1) undoV1(row *EntryInventoryRowV1) error {
	var key [33]byte
	copy(key[:32], row.Hash[:])
	var err error
	w.stream.row.image, err = w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	if !w.stream.row.image.present {
		return w.absentUndoV1(row, key[:])
	}
	borrow, _ := treeBorrowV1(w.stream.row.image)
	if len(borrow.value) != 33 || borrow.value[0] != 1 || binary.BigEndian.Uint64(borrow.value[1:]) != row.Height {
		return w.s.stopV1(4, nil)
	}
	w.cursor.positions[0], w.cursor.positions[1] = 0, uint64(binary.BigEndian.Uint32(borrow.value[29:]))
	borrow.value, w.stream.row.image = nil, updateImage{}
	if err := w.scanV1(row); err != nil {
		return err
	}
	if w.cursor.positions[0] != w.cursor.positions[1] {
		return w.s.stopV1(4, nil)
	}
	return nil
}

func (w *entryWalkV1) absentUndoV1(row *EntryInventoryRowV1, key []byte) error {
	if row.Source != 22 {
		return w.s.stopV1(2, nil)
	}
	w.cursor.positions = [2]uint64{}
	if err := w.emitV1(row, key, &w.stream.row.image); err != nil {
		return err
	}
	return w.scanV1(row)
}

func (w *entryWalkV1) obsoleteV1() error {
	spans := w.s.inspection[0].phase
	for i := 0; i < spans.len(); i++ {
		if spans.at(i).Kind != 1 {
			continue
		}
		if err := w.generationV1(spans.at(i).GenerationID); err != nil {
			return err
		}
	}
	return nil
}

func (w *entryWalkV1) generationV1(g uint64) error {
	row := w.rowV1(19, 2, 0, g)
	key := entryMetaV1(0x10, g)
	image, err := w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	if err := w.emitV1(row, key[:], &image); err != nil {
		return err
	}
	for i, source := range [4]uint8{16, 17, 18, 23} {
		row = w.rowV1(source, [4]uint8{3, 4, 5, 10}[i], 0, g)
		if err := w.scanV1(row); err != nil {
			return err
		}
	}
	row = w.rowV1(24, 11, 0, g)
	key[0] = 0x11
	image, err = w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	return w.emitV1(row, key[:], &image)
}

// Active keyed ownership retains its integrity priority and actual request context.
func (w *entryWalkV1) ownerV1(role int, primary *EntryInventoryRowV1) (uint64, bool, error) {
	g := w.s.authority[0].Authority.ActiveGenerationID
	if role == 1 {
		g = w.s.authority[0].LagGenerationID
	}
	row := w.context
	*row = EntryInventoryRowV1{Source: 28, Artifact: 5, Role: uint8(role + 1), Generation: g, Hash: primary.Hash}
	var key [40]byte
	binary.BigEndian.PutUint64(key[:8], g)
	copy(key[8:], primary.Hash[:])
	image, err := w.pointV1(row, key[:])
	if err != nil || !image.present {
		return 0, false, err
	}
	b, _ := treeBorrowV1(image)
	if len(b.value) != 8 || binary.BigEndian.Uint64(b.value) > 0xffffffff {
		return 0, false, w.ownerFailureV1()
	}
	row.Height, row.Artifact = binary.BigEndian.Uint64(b.value), 4
	forward := entryHeightV1(g, row.Height)
	image, err = w.pointV1(row, forward[:])
	if err != nil {
		return 0, false, err
	}
	if !entryForwardV1(&image, &primary.Hash) {
		return 0, false, w.ownerFailureV1()
	}
	return row.Height, true, nil
}

func (w *entryWalkV1) ownerFailureV1() error {
	return w.s.stopV1(4, nil)
}

func (w *entryWalkV1) keptV1(row *EntryInventoryRowV1) (bool, error) {
	for role := 0; role < 2; role++ {
		k, owned, err := w.ownerV1(role, row)
		if err != nil {
			return false, err
		}
		if owned && w.activeKeepV1(row.Artifact, role, k) {
			return true, nil
		}
	}
	if w.phaseKeepV1(row) {
		return true, nil
	}
	return w.priorV1(row)
}

func (w *entryWalkV1) phaseKeepV1(row *EntryInventoryRowV1) bool {
	points := w.s.inspection[1].new
	if row.Artifact == 8 {
		points = w.s.inspection[1].old
	}
	return points.hasHash(row.Hash, points.len())
}

func (w *entryWalkV1) activeKeepV1(artifact uint8, role int, height uint64) bool {
	if artifact == 6 {
		return true
	}
	first, kind := w.bodyFirstV1(), CleanupSpanBlocksV1
	if artifact == 8 {
		first, kind = w.s.authority[0].Authority.U, CleanupSpanUndoV1
	}
	if height >= first {
		return true
	}
	return w.owedV1(kind, role, height)
}

func (w *entryWalkV1) owedV1(kind CleanupSpanKindV1, role int, height uint64) bool {
	if role != 0 {
		return false
	}
	spans := w.s.inspection[0].phase
	for i := 0; i < spans.len(); i++ {
		s := spans.at(i)
		if s.Kind == kind && height >= s.NextHeight && height <= s.LastHeight {
			return true
		}
	}
	return false
}

// Prior slots already visited their complete own proof; orphan raw rows confer no ownership.
func (w *entryWalkV1) priorV1(primary *EntryInventoryRowV1) (bool, error) {
	spans := w.s.inspection[0].phase
	for i := 0; i < spans.len(); i++ {
		span := spans.at(i)
		if span.Kind != 1 || span.GenerationID >= primary.Generation {
			continue
		}
		owned, err := w.priorOwnerV1(primary, span.GenerationID)
		if owned || err != nil {
			return owned, err
		}
	}
	return false, nil
}

func (w *entryWalkV1) priorOwnerV1(primary *EntryInventoryRowV1, g uint64) (bool, error) {
	row := w.context
	*row = EntryInventoryRowV1{Source: 17, Artifact: 5, Generation: g, Hash: primary.Hash}
	var key [40]byte
	binary.BigEndian.PutUint64(key[:8], g)
	copy(key[8:], primary.Hash[:])
	image, err := w.pointV1(row, key[:])
	if err != nil || !image.present {
		return false, err
	}
	b, _ := treeBorrowV1(image)
	if len(b.value) != 8 || binary.BigEndian.Uint64(b.value) > 0xffffffff {
		return false, nil
	}
	row.Artifact, row.Height = 4, binary.BigEndian.Uint64(b.value)
	forward := entryHeightV1(g, row.Height)
	image, err = w.pointV1(row, forward[:])
	if err != nil {
		return false, err
	}
	if !entryForwardV1(&image, &primary.Hash) {
		return false, nil
	}
	b, _ = treeBorrowV1(image)
	parent := [32]byte(b.value[32:64])
	row.Source, row.Artifact = 20, 6
	image, err = w.projectedV1(row, primary.Hash[:])
	return entryLinkedV1(&image, &primary.Hash, &parent), err
}

// Projection alone admits absent OLD headers supplied by the immutable Pair.
func (w *entryWalkV1) projectedV1(row *EntryInventoryRowV1, key []byte) (updateImage, error) {
	image, err := w.pointV1(row, key)
	if err != nil {
		return image, err
	}
	projected, literal, err := w.literalV1(entryRankV1(row.Artifact), key)
	if literal {
		return projected, err
	}
	return image, err
}

func entryLinkedV1(image *updateImage, hash, parent *[32]byte) bool {
	b, _ := treeBorrowV1(*image)
	return validateInitial148Value(*hash, b.value, false) == nil && [32]byte(b.value[4:36]) == *parent
}

func entryForwardV1(image *updateImage, hash *[32]byte) bool {
	b, _ := treeBorrowV1(*image)
	return len(b.value) == 104 && [32]byte(b.value[:32]) == *hash && validWork([40]byte(b.value[64:]))
}

func (w *entryWalkV1) indexV1(row *EntryInventoryRowV1, key []byte, image *updateImage) error {
	row.Projection = 1
	b, _ := treeBorrowV1(*image)
	if !obsoleteIndexShape(key, *image) || !validWork([40]byte(b.value[64:])) {
		return w.emitV1(row, key, image)
	}
	row.Height, row.Hash = binary.BigEndian.Uint64(key[8:]), [32]byte(b.value[:32])
	parent := [32]byte(b.value[32:64])
	b.value = nil
	row.Source, row.Artifact, row.Projection = 20, 6, 0
	keep, err := w.keptV1(row)
	if err != nil {
		return err
	}
	header, err := w.projectedV1(row, row.Hash[:])
	if err != nil {
		return err
	}
	if !entryLinkedV1(&header, &row.Hash, &parent) {
		return w.invalidIndexV1(row, key, image, keep)
	}
	if err := w.reverseV1(row); err != nil {
		return err
	}
	w.stream.row.image, header = header, updateImage{}
	row.Source, row.Artifact, row.Projection = 17, 4, 3
	if err := w.emitV1(row, key, image); err != nil {
		return err
	}
	row.Source, row.Artifact, row.Projection = 20, 6, 0
	return w.projectedRowsV1(row, &w.stream.row.image, keep)
}

func (w *entryWalkV1) invalidIndexV1(row *EntryInventoryRowV1, key []byte, image *updateImage, keep bool) error {
	if keep {
		return w.s.stopV1(4, nil)
	}
	row.Source, row.Artifact, row.Projection = 17, 4, 1
	row.Height, row.Hash = 0, [32]byte{}
	return w.emitV1(row, key, image)
}

func (w *entryWalkV1) projectedRowsV1(row *EntryInventoryRowV1, header *updateImage, keep bool) error {
	if !keep {
		if err := w.emitV1(row, row.Hash[:], header); err != nil {
			return err
		}
	}
	*header = updateImage{}
	return w.dependentsV1(row)
}

func (w *entryWalkV1) reverseV1(primary *EntryInventoryRowV1) error {
	row := w.context
	*row = EntryInventoryRowV1{Source: 17, Artifact: 5, Generation: primary.Generation, Height: primary.Height, Hash: primary.Hash}
	var key [40]byte
	binary.BigEndian.PutUint64(key[:8], primary.Generation)
	copy(key[8:], primary.Hash[:])
	image, err := w.pointV1(row, key[:])
	if err != nil {
		return err
	}
	b, _ := treeBorrowV1(image)
	if !image.present || len(b.value) != 8 || binary.BigEndian.Uint64(b.value) != primary.Height {
		return w.s.stopV1(3, nil)
	}
	return nil
}

func (w *entryWalkV1) dependentsV1(row *EntryInventoryRowV1) error {
	for _, artifact := range [2]uint8{7, 8} {
		row.Source, row.Artifact = 14 + artifact, artifact
		keep, err := w.keptV1(row)
		if err != nil {
			return err
		}
		if keep {
			continue
		}
		if artifact == 8 {
			return w.undoV1(row)
		}
		image, err := w.pointV1(row, row.Hash[:])
		if err != nil {
			return err
		}
		if err := w.emitV1(row, row.Hash[:], &image); err != nil {
			return err
		}
	}
	return nil
}
