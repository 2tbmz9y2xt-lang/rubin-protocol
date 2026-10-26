//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
)

type entryWalkV1 struct {
	s      *entryInventoryStateV1
	old    *Reader
	visit  func(EntryInventoryRowV1) error
	stream *entryStreamV1
	cursor *entryCursorV1
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
	image, err := w.old.obsoletePoint(entryRankV1(row.Artifact), key, operationGet)
	if err != nil {
		return updateImage{}, w.s.stopV1(1, err)
	}
	return image, nil
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
		row := EntryInventoryRowV1{Source: uint8(1 + role*2), Artifact: 2, Role: uint8(role + 1), Generation: g}
		key := entryMetaV1(0x10, g)
		image, err := w.requiredV1(&row, key[:])
		if err != nil {
			return err
		}
		if image.length != 16 {
			return s.stopV1(4, nil)
		}
		if err := w.emitV1(&row, key[:], &image); err != nil {
			return err
		}
		if err := w.bindingV1(uint8(role), g, &row); err != nil {
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
	s.roots[role], err = decodeRootBindingV1(b.value, &s.rootControl[role])
	if err != nil || s.roots[role].DatabaseID != w.old.databaseID {
		return s.stopV1(4, nil)
	}
	if s.roots[role].Endpoint.Kind == 1 {
		row.IndexCount = s.roots[role].Endpoint.Height + 1
	}
	b.value = nil
	if err := w.emitV1(row, key[:], &image); err != nil {
		return err
	}
	return w.assuranceV1(role, row)
}

func (w *entryWalkV1) assuranceV1(role uint8, row *EntryInventoryRowV1) error {
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
	return w.finishV1()
}

func (w *entryWalkV1) finishV1() error {
	for _, spans := range [2]authoritySpans{w.s.inspection[0].phase, w.s.inspection[1].carried} {
		for i := 0; i < spans.len(); i++ {
			if spans.at(i).Kind == 1 {
				return entryInputV1()
			}
		}
	}
	w.s.completed = true // the sole full-domain completion, under getMu
	return nil
}

func (w *entryWalkV1) headerGroupV1() error {
	row := EntryInventoryRowV1{Source: 6, Artifact: 6, Role: 1, Generation: w.s.authority[0].Authority.ActiveGenerationID, Count: w.s.roots[0].Endpoint.Height + 1}
	image := updateImage{}
	return w.emitV1(&row, nil, &image)
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
	row := EntryInventoryRowV1{Source: 27, Artifact: 4, Role: 1, Generation: g, Height: height}
	key := entryHeightV1(g, height)
	image, err := w.requiredV1(&row, key[:])
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
	tip, old := s.roots[0].Endpoint, s.inspection[1].old
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
	expected := w.s.roots[0].Endpoint.BlockHash
	if w.s.inspection[1].old.len() > 0 {
		expected = w.cursor.hashes[1]
	} else if [40]byte(entry[64:]) != w.s.roots[0].Endpoint.CumulativeChainwork {
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
	if i == 0 && [40]byte(entry[64:]) != w.s.roots[0].Endpoint.CumulativeChainwork {
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
	row := EntryInventoryRowV1{Source: 27, Artifact: 6, Role: 1, Generation: w.s.authority[0].Authority.ActiveGenerationID, Height: height, Hash: [32]byte(entry[:32])}
	image, err := w.requiredV1(&row, row.Hash[:])
	if err != nil {
		return err
	}
	return w.headerV1(&row, image, [32]byte(entry[32:64]))
}

func (w *entryWalkV1) headerV1(row *EntryInventoryRowV1, image updateImage, parent [32]byte) error {
	borrow, _ := treeBorrowV1(image)
	if validateInitial148Value(row.Hash, borrow.value, false) != nil || [32]byte(borrow.value[4:36]) != parent {
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
		row := EntryInventoryRowV1{Source: 5, Artifact: 8, Role: 1, Generation: w.s.authority[0].Authority.ActiveGenerationID, Height: p.Height, Hash: p.BlockHash}
		if err := w.undoV1(&row); err != nil {
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
	if w.s.authority[0].Authority.ActiveProfile == 2 || w.s.roots[1].Endpoint.Kind == 0 {
		return 0
	}
	return w.s.roots[1].Endpoint.Height + 1
}

func (w *entryWalkV1) canonicalV1(undo bool) error {
	s := w.s
	first, source, artifact, kind := w.bodyFirstV1(), uint8(7), uint8(7), CleanupSpanBlocksV1
	if undo {
		first, source, artifact, kind = s.authority[0].Authority.U, 9, 8, CleanupSpanUndoV1
	}
	if err := w.heightRangeV1(first, s.roots[0].Endpoint.Height, source, artifact, undo); err != nil {
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
		row := EntryInventoryRowV1{Source: source, Artifact: artifact, Role: 1, Generation: w.s.authority[0].Authority.ActiveGenerationID, Height: height, Hash: [32]byte(entry[:32])}
		if undo && w.s.inspection[1].old.hasHash(row.Hash, w.s.inspection[1].old.len()) {
			continue
		}
		if undo {
			err = w.undoV1(&row)
		} else {
			err = w.bodyV1(&row)
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
	row := EntryInventoryRowV1{Source: linkSource, Artifact: 9, Generation: side.GenerationID, Height: p.Height, Hash: p.BlockHash}
	key := entryHeightV1(side.GenerationID, p.Height)
	if err := w.capturedLinkV1(&row, key[:], parent); err != nil {
		return err
	}
	row.Source, row.Artifact = 11, 6
	if err := w.capturedHeaderV1(&row, parent); err != nil {
		return err
	}
	row.Source, row.Artifact = bodySource, 7
	if err := w.bodyV1(&row); err != nil {
		return err
	}
	row.Source, row.Artifact = linkSource, 9
	return w.emitV1(&row, key[:], &w.stream.row.image)
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

func (w *entryWalkV1) fetchV1(row *EntryInventoryRowV1) error {
	stream := w.stream
	w.s.requestV1(row, 2, stream.seek)
	next, err := stream.reader.obsoleteFetch(stream.domain, stream.seek, operationGet)
	if err != nil {
		return w.s.stopV1(1, err)
	}
	stream.row, stream.done = next, next.done
	if !next.done {
		w.s.requestV1(row, 2, next.key) // a positive row owns its actual key
	}
	return nil
}

func (w *entryWalkV1) scanV1(row *EntryInventoryRowV1) error {
	stream := w.stream
	stream.reader, stream.domain, stream.done = w.old, obsoleteDomain{rank: 5, prefix: row.Hash[:]}, false
	stream.seek = stream.seek[:copy(stream.seek[:cap(stream.seek)], row.Hash[:])]
	for {
		stream.row = largeNativeRow{}
		if err := w.fetchV1(row); err != nil {
			return err
		}
		if stream.done {
			stream.reader, stream.domain, stream.row = nil, obsoleteDomain{}, largeNativeRow{}
			return nil
		}
		if err := w.rawShapeV1(stream.row.key, stream.row.image); err != nil {
			return err
		}
		if err := w.emitV1(row, stream.row.key, &stream.row.image); err != nil {
			return err
		}
		stream.seek = entrySuccessorV1(stream.seek, stream.row.key)
	}
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
	w.stream.row.image, err = w.requiredV1(row, key[:])
	if err != nil {
		return err
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
