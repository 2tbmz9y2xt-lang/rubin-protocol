//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"io"
	"sort"
)

// ObsoleteClassV1 selects a nonzero generation's dedicated physical namespace.
// These selectors do not establish the caller's cleanup authority or generation roles.
type ObsoleteClassV1 uint8

const (
	ObsoleteUTXOV1    ObsoleteClassV1 = 1
	ObsoleteIndexV1   ObsoleteClassV1 = 2
	ObsoleteCounterV1 ObsoleteClassV1 = 3
	ObsoleteDerivedV1 ObsoleteClassV1 = 4
)

// ObsoleteProjectionV1 reports only the fixed own-index/header proof.
type ObsoleteProjectionV1 uint8

const (
	ObsoleteProjectionNotApplicableV1 ObsoleteProjectionV1 = 1
	ObsoleteProjectionInvalidV1       ObsoleteProjectionV1 = 2
	ObsoleteProjectionProvenV1        ObsoleteProjectionV1 = 3
)

// ObsoleteRowV1 owns immutable key metadata with Reader-callback-scoped reads.
type ObsoleteRowV1 struct{ span *obsoleteSpan }

type obsoleteSpan struct {
	reader *Reader
	key    []byte
	image  updateImage
	rank   uint8
}

// ObsoletePageWitnessV1 is opaque same-OLD scope evidence, independent of Page rows.
type ObsoletePageWitnessV1 struct{ scope *obsoleteWitness }

type obsoleteWitness struct {
	reader *Reader
	domain obsoleteDomain
	points []obsoletePoint
}

type obsoletePoint struct {
	rank uint8
	key  []byte
}

type obsoleteDomain struct {
	rank        uint8
	prefix      []byte
	after, last []byte
	end, point  bool
}

func (domain obsoleteDomain) seek(maxKey uint64) []byte {
	if domain.after == nil {
		return domain.prefix
	}
	return largeImageAdvance(domain.after, maxKey)
}

// ObsoletePageV1 contains present rows and independently copied continuation keys.
// Every error returns its zero value. Successful exhaustion has nil Next.
type ObsoletePageV1 struct {
	Rows       []ObsoleteRowV1
	Next       []byte
	Stop       PrefixPageStop
	Projection ObsoleteProjectionV1
	Witness    ObsoletePageWitnessV1
}

func obsoleteInput(op engineOperation, diagnostic string) error {
	return adapterError(op, EngineInvalidInput, codeEINVAL, diagnostic, nil)
}

func obsoleteBounds() error {
	return obsoleteInput(operationPrefixPage, "invalid obsolete generation page bounds")
}

func obsoleteShape(op engineOperation) error {
	return adapterError(op, EngineLocalInvariant, codeProblem, "invalid native obsolete generation result", nil)
}

func obsoleteRank(class ObsoleteClassV1) uint8 {
	switch class {
	case ObsoleteUTXOV1:
		return 1
	case ObsoleteIndexV1:
		return 2
	case ObsoleteCounterV1:
		return 0
	case ObsoleteDerivedV1:
		return 7
	}
	return 255
}

func (row ObsoleteRowV1) Key() []byte {
	if row.span == nil {
		return nil
	}
	return bytes.Clone(row.span.key)
}

func (row ObsoleteRowV1) Length() uint64 {
	if row.span == nil {
		return 0
	}
	return uint64(row.span.image.length)
}

func (row ObsoleteRowV1) readInput(dst []byte) error {
	if !row.span.reader.usable() {
		return obsoleteInput(operationGet, "Reader is not active")
	}
	if len(dst) > 65_536 {
		return obsoleteInput(operationGet, "ReadAt buffer exceeds 65536 bytes")
	}
	return nil
}

func (row ObsoleteRowV1) ReadAt(dst []byte, offset uint64) (int, error) {
	if row.span == nil {
		return 0, obsoleteInput(operationGet, "invalid obsolete generation row")
	}
	r := row.span.reader
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if err := row.readInput(dst); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if offset >= row.Length() {
		return 0, io.EOF
	}
	image, err := r.obsoletePoint(row.span.rank, row.span.key, operationGet)
	if err != nil {
		return 0, r.largeFailure(err)
	}
	if !image.present || image.length != row.span.image.length {
		return 0, r.largeFailure(obsoleteShape(operationGet))
	}
	return largeImageCopy(dst, image.bytes, row.Length()-offset, offset)
}

func obsoletePageBounds(after, prefix []byte, maxKey uint64, maxRows uint32, point bool) bool {
	if maxRows == 0 || maxRows > 1440 {
		return false
	}
	if after == nil {
		return true
	}
	if point {
		return bytes.Equal(after, prefix)
	}
	return uint64(len(after)) <= maxKey && bytes.HasPrefix(after, prefix)
}

// ObsoleteGenerationPageV1 observes physical ownership only, including malformed rows.
func (r *Reader) ObsoleteGenerationPageV1(g uint64, class ObsoleteClassV1, after []byte, maxRows uint32) (ObsoletePageV1, error) {
	if !r.usable() {
		return ObsoletePageV1{}, obsoleteInput(operationPrefixPage, "Reader is not active")
	}
	rank := obsoleteRank(class)
	if g == 0 || rank == 255 {
		return ObsoletePageV1{}, obsoleteInput(operationPrefixPage, "invalid obsolete generation selector")
	}
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, g)
	point := class == ObsoleteCounterV1
	if point {
		prefix = append([]byte{0x10}, prefix...)
	}
	if !obsoletePageBounds(after, prefix, r.maxKey, maxRows, point) {
		return ObsoletePageV1{}, obsoleteBounds()
	}
	domain := obsoleteDomain{rank: rank, prefix: prefix, after: bytes.Clone(after), point: point}
	return r.obsoletePage(domain, maxRows, ObsoleteProjectionNotApplicableV1, nil)
}

func (r *Reader) obsoleteUndoInput(index ObsoleteRowV1, after []byte, maxRows uint32) error {
	if !r.usable() {
		return obsoleteInput(operationPrefixPage, "Reader is not active")
	}
	if index.span == nil || index.span.reader != r || index.span.rank != 2 {
		return obsoleteInput(operationPrefixPage, "invalid or foreign obsolete generation index")
	}
	if !obsoleteUndoBounds(after, r.maxKey, maxRows) {
		return obsoleteBounds()
	}
	return nil
}

func obsoleteUndoBounds(after []byte, maxKey uint64, maxRows uint32) bool {
	if maxRows == 0 || maxRows > 1440 {
		return false
	}
	if after == nil {
		return true
	}
	return len(after) >= 32 && uint64(len(after)) <= maxKey
}

// ObsoleteUndoPageV1 proves the index's own projection before dependent bounds or traversal.
// The proof reads no predecessor and confers no consumer disposal authority.
func (r *Reader) ObsoleteUndoPageV1(index ObsoleteRowV1, after []byte, maxRows uint32) (ObsoletePageV1, error) {
	if err := r.obsoleteUndoInput(index, after, maxRows); err != nil {
		return ObsoletePageV1{}, err
	}
	r.getMu.Lock()
	if !r.usable() {
		r.getMu.Unlock()
		return ObsoletePageV1{}, obsoleteInput(operationPrefixPage, "Reader is not active")
	}
	hash, points, proven, err := r.obsoleteProjection(index)
	if err != nil {
		err = r.largeFailure(err)
	}
	r.getMu.Unlock()
	if err != nil {
		return ObsoletePageV1{}, err
	}
	if !proven {
		if after != nil {
			return ObsoletePageV1{}, obsoleteBounds()
		}
		witness := &obsoleteWitness{reader: r, points: points}
		return ObsoletePageV1{Stop: PrefixPageExhausted, Projection: ObsoleteProjectionInvalidV1, Witness: ObsoletePageWitnessV1{scope: witness}}, nil
	}
	if !obsoletePageBounds(after, hash[:], r.maxKey, maxRows, false) {
		return ObsoletePageV1{}, obsoleteBounds()
	}
	return r.obsoletePage(obsoleteDomain{rank: 5, prefix: hash[:], after: bytes.Clone(after)}, maxRows, ObsoleteProjectionProvenV1, points)
}

func (r *Reader) obsoleteProjection(index ObsoleteRowV1) ([32]byte, []obsoletePoint, bool, error) {
	points := []obsoletePoint{{rank: 2, key: bytes.Clone(index.span.key)}}
	image, err := r.obsoletePoint(2, index.span.key, operationPrefixPage)
	if err != nil {
		return [32]byte{}, points, false, err
	}
	key := index.span.key
	if !obsoleteIndexShape(key, image) {
		return [32]byte{}, points, false, nil
	}
	entry := make([]byte, 104)
	_, _ = largeImageCopy(entry, image.bytes, 104, 0)
	if !validWork([40]byte(entry[64:])) {
		return [32]byte{}, points, false, nil
	}
	hash := [32]byte(entry[:32])
	points = append(points, obsoletePoint{rank: 3, key: bytes.Clone(hash[:])})
	header, err := r.obsoletePoint(3, hash[:], operationPrefixPage)
	if err != nil {
		return hash, points, false, err
	}
	if !header.present || header.length != 116 {
		return hash, points, false, nil
	}
	data := make([]byte, 116)
	_, _ = largeImageCopy(data, header.bytes, 116, 0)
	return hash, points, sha3.Sum256(data) == hash && bytes.Equal(data[4:36], entry[32:64]), nil
}

func obsoleteIndexShape(key []byte, image updateImage) bool {
	return len(key) == 16 && binary.BigEndian.Uint64(key[8:]) <= 0xffffffff && image.present && image.length == 104
}

func (r *Reader) obsoletePage(domain obsoleteDomain, maxRows uint32, projection ObsoleteProjectionV1, points []obsoletePoint) (ObsoletePageV1, error) {
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() {
		return ObsoletePageV1{}, obsoleteInput(operationPrefixPage, "Reader is not active")
	}
	page := ObsoletePageV1{Projection: projection}
	seek := domain.seek(r.maxKey)
	if domain.point {
		return r.obsoleteCounterPage(domain, projection)
	}
	return r.obsoleteScanPage(domain, maxRows, page, seek, points)
}

func (r *Reader) obsoleteScanPage(domain obsoleteDomain, maxRows uint32, page ObsoletePageV1, seek []byte, points []obsoletePoint) (ObsoletePageV1, error) {
	var copied uint64
	for {
		row, err := r.obsoleteFetch(domain, seek, operationPrefixPage)
		if err != nil {
			return ObsoletePageV1{}, r.largeFailure(err)
		}
		if row.done {
			page.Stop, domain.end = PrefixPageExhausted, true
			break
		}
		domain.last = bytes.Clone(row.key)
		page.Stop = obsoletePageStop(len(page.Rows), maxRows, copied, uint64(len(row.key)))
		if page.Stop != 0 {
			if len(page.Rows) == 0 {
				return ObsoletePageV1{}, adapterError(operationPrefixPage, EngineCapacity, codeTooLarge, "obsolete generation page exceeds bound", nil)
			}
			page.Next = page.Rows[len(page.Rows)-1].Key()
			break
		}
		page.Rows = append(page.Rows, ObsoleteRowV1{span: &obsoleteSpan{reader: r, rank: domain.rank, key: row.key, image: row.image}})
		copied += uint64(len(row.key))
		seek = largeImageAdvance(row.key, r.maxKey)
	}
	page.Witness.scope = &obsoleteWitness{reader: r, domain: domain, points: points}
	return page, nil
}

func obsoletePageStop(rows int, maxRows uint32, copied, next uint64) PrefixPageStop {
	if rows == int(maxRows) {
		return PrefixPageRowLimit
	}
	if next > 65_596-copied {
		return PrefixPageByteLimit
	}
	return 0
}

func (r *Reader) obsoleteCounterPage(domain obsoleteDomain, projection ObsoleteProjectionV1) (ObsoletePageV1, error) {
	image, err := r.obsoletePoint(0, domain.prefix, operationPrefixPage)
	if err != nil {
		return ObsoletePageV1{}, r.largeFailure(err)
	}
	page := ObsoletePageV1{Stop: PrefixPageExhausted, Projection: projection}
	if image.present && domain.after == nil {
		page.Rows = []ObsoleteRowV1{{span: &obsoleteSpan{reader: r, rank: 0, key: bytes.Clone(domain.prefix), image: image}}}
	}
	page.Witness.scope = &obsoleteWitness{reader: r, domain: domain}
	return page, nil
}

func obsoleteContains(domain obsoleteDomain, rank uint8, key []byte) bool {
	if domain.prefix == nil || domain.rank != rank {
		return false
	}
	if domain.point {
		return bytes.Equal(domain.prefix, key)
	}
	if !bytes.HasPrefix(key, domain.prefix) || bytes.Compare(key, domain.after) <= 0 {
		return false
	}
	return domain.end || bytes.Compare(key, domain.last) <= 0
}

func obsoleteWitnesses(batch Batch, reader *Reader) error {
	seen := make(map[*obsoleteWitness]struct{}, len(batch.ObsoleteConsulted))
	for _, token := range batch.ObsoleteConsulted {
		witness := token.scope
		if witness == nil || witness.reader != reader || !reader.updateOld {
			return updateInvalidBatch()
		}
		if _, duplicate := seen[witness]; duplicate {
			return updateInvalidBatch()
		}
		seen[witness] = struct{}{}
	}
	return nil
}

func obsoleteCovered(domains []obsoleteDomain, span *obsoleteSpan) bool {
	for _, domain := range domains {
		if obsoleteContains(domain, span.rank, span.key) {
			return true
		}
	}
	return false
}

func obsoleteCharge(budget *updateBudget, span *obsoleteSpan) bool {
	m := Mutation{DBI: schemaDBIs[span.rank], Key: span.key, BeforePresent: true, AfterKind: AfterAbsent}
	if !budget.addTotals(m) {
		return false
	}
	var ok bool
	switch {
	case span.rank == 1:
		budget.utxoDeletes, ok = updateAdd(budget.utxoDeletes, 1, maxUpdateInputs)
	case span.rank == 5 && (len(span.key) != 33 || span.key[32] != 0):
		budget.undoEntryDeletes, ok = updateAdd(budget.undoEntryDeletes, 1, maxUpdateInputs)
	default:
		budget.aux, ok = updateAdd(budget.aux, 1, maxUpdateAux)
	}
	return ok
}

// Legacy rows are already admitted, preserving their per-row first-error sequence.
func updateOwnedObsolete(batch Batch, reader *Reader, plan []ownedMutation) ([]ownedMutation, error) {
	if len(batch.ObsoleteDeletes) == 0 && len(batch.ObsoleteConsulted) == 0 {
		return plan, nil
	}
	if batch.Reverse {
		return nil, updateInvalidBatch()
	}
	if uint64(len(batch.ObsoleteDeletes))+uint64(len(batch.ObsoleteConsulted)) > maxUpdateMutations {
		return nil, updateBoundError()
	}
	if err := obsoleteWitnesses(batch, reader); err != nil {
		return nil, err
	}
	rows, err := obsoleteAdmitRows(batch, reader, plan)
	if err != nil {
		return nil, err
	}
	return obsoleteCompileRows(batch, rows, plan)
}

func obsoleteCompileRows(batch Batch, rows []ObsoleteRowV1, plan []ownedMutation) ([]ownedMutation, error) {
	budget := updateBudget{}
	for _, m := range batch.Mutations {
		_ = budget.addMutation(m)
	}
	for _, row := range rows {
		if !obsoleteCharge(&budget, row.span) {
			return nil, updateBoundError()
		}
	}
	for _, row := range rows {
		span := row.span
		plan = append(plan, ownedMutation{dbi: schemaDBIs[span.rank], key: bytes.Clone(span.key), beforePresent: true, after: AfterAbsent})
	}
	sort.Slice(plan, func(i, j int) bool {
		return updateKeyOrdered(plan[i].dbi.Rank, plan[i].key, plan[j].dbi.Rank, plan[j].key)
	})
	return plan, nil
}

func obsoleteAdmitRows(batch Batch, reader *Reader, plan []ownedMutation) ([]ObsoleteRowV1, error) {
	domains := make([]obsoleteDomain, 0, len(batch.ObsoleteConsulted))
	for _, token := range batch.ObsoleteConsulted {
		domains = append(domains, token.scope.domain)
	}
	domains = obsoleteCoalesce(domains)
	rows := append([]ObsoleteRowV1(nil), batch.ObsoleteDeletes...)
	for _, row := range rows {
		if !obsoleteRowCurrent(row, reader, domains) {
			return nil, updateInvalidBatch()
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		return updateKeyOrdered(rows[i].span.rank, rows[i].span.key, rows[j].span.rank, rows[j].span.key)
	})
	for i, row := range rows {
		span := row.span
		if canonicalTargetIndex(plan, span.rank, span.key) >= 0 {
			return nil, updateInvalidBatch()
		}
		if i != 0 && !updateKeyOrdered(rows[i-1].span.rank, rows[i-1].span.key, span.rank, span.key) {
			return nil, updateInvalidBatch()
		}
	}
	return rows, nil
}

func obsoleteRowCurrent(row ObsoleteRowV1, reader *Reader, domains []obsoleteDomain) bool {
	return row.span != nil && row.span.reader == reader && reader.updateOld && obsoleteCovered(domains, row.span)
}

func obsoleteDomainOrdered(a, b obsoleteDomain) bool {
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	if order := bytes.Compare(a.prefix, b.prefix); order != 0 {
		return order < 0
	}
	return bytes.Compare(a.after, b.after) < 0
}

func obsoleteCoalesce(domains []obsoleteDomain) []obsoleteDomain {
	sort.Slice(domains, func(i, j int) bool { return obsoleteDomainOrdered(domains[i], domains[j]) })
	merged := domains[:0]
	for _, domain := range domains {
		if len(merged) != 0 && obsoleteMergeable(merged[len(merged)-1], domain) {
			previous := &merged[len(merged)-1]
			previous.end = previous.end || domain.end
			if bytes.Compare(domain.last, previous.last) > 0 {
				previous.last = domain.last
			}
			continue
		}
		merged = append(merged, domain)
	}
	return merged
}

func obsoleteMergeable(a, b obsoleteDomain) bool {
	if a.rank != b.rank || a.point != b.point || !bytes.Equal(a.prefix, b.prefix) {
		return false
	}
	return a.point || a.end || bytes.Compare(b.after, a.last) <= 0
}

func obsoleteCoalescePoints(points []obsoletePoint, domains []obsoleteDomain) []obsoletePoint {
	sort.Slice(points, func(i, j int) bool {
		return updateKeyOrdered(points[i].rank, points[i].key, points[j].rank, points[j].key)
	})
	merged := points[:0]
	for _, point := range points {
		if len(merged) != 0 && !updateKeyOrdered(merged[len(merged)-1].rank, merged[len(merged)-1].key, point.rank, point.key) {
			continue
		}
		covered := false
		for _, domain := range domains {
			covered = covered || obsoleteContains(domain, point.rank, point.key)
		}
		if !covered {
			merged = append(merged, point)
		}
	}
	return merged
}

func obsoleteRetainControls(scope *largeImageScope) error {
	if uint64(len(scope.domains))+uint64(len(scope.points))+uint64(len(scope.selectors)) > maxUpdateMutations {
		return updateBoundError()
	}
	keys := obsoleteControlKeys(*scope)
	charge := uint64(len(scope.selectors)) * 32
	var ok bool
	for _, point := range keys {
		if charge, ok = updateAdd(charge, uint64(len(point.key)), maxUpdateKeyBytes); !ok {
			return updateBoundError()
		}
	}
	for i := range keys {
		keys[i].key = bytes.Clone(keys[i].key)
	}
	for i := range scope.domains {
		domain := &scope.domains[i]
		domain.prefix = obsoleteControlKey(keys, domain.rank, domain.prefix)
		domain.after = obsoleteControlKey(keys, domain.rank, domain.after)
		domain.last = obsoleteControlKey(keys, domain.rank, domain.last)
	}
	for i := range scope.points {
		scope.points[i].key = obsoleteControlKey(keys, scope.points[i].rank, scope.points[i].key)
	}
	return nil
}

func obsoleteControlKeys(scope largeImageScope) []obsoletePoint {
	keys := append([]obsoletePoint(nil), scope.points...)
	for _, domain := range scope.domains {
		keys = append(keys, obsoletePoint{rank: domain.rank, key: domain.prefix}, obsoletePoint{rank: domain.rank, key: domain.after}, obsoletePoint{rank: domain.rank, key: domain.last})
	}
	return obsoleteCoalescePoints(keys, nil)
}

func obsoleteControlKey(keys []obsoletePoint, rank uint8, key []byte) []byte {
	if key == nil {
		return nil
	}
	i := sort.Search(len(keys), func(i int) bool { return !updateKeyOrdered(keys[i].rank, keys[i].key, rank, key) })
	return keys[i].key
}

func updateObsoleteScope(batch Batch, scope largeImageScope) (largeImageScope, error) {
	if len(batch.ObsoleteConsulted) == 0 {
		return scope, nil
	}
	for _, token := range batch.ObsoleteConsulted {
		witness := token.scope
		if witness.domain.prefix != nil {
			scope.domains = append(scope.domains, witness.domain)
		}
		scope.points = append(scope.points, witness.points...)
	}
	// A complete admitted large undo family subsumes its raw intervals only.
	domains := scope.domains[:0]
	for _, domain := range scope.domains {
		row := ownedConsulted{dbi: schemaDBIs[domain.rank], key: domain.prefix}
		if domain.rank != 5 || !largeSelectorContains(scope.selectors, row) {
			domains = append(domains, domain)
		}
	}
	scope.domains = obsoleteCoalesce(domains)
	scope.points = obsoleteCoalescePoints(scope.points, scope.domains)
	if err := obsoleteRetainControls(&scope); err != nil {
		return largeImageScope{}, err
	}
	return scope, nil
}

// Ordinary Consulted has already folded its physical equality at each stage.
func obsoleteConsultedContains(consulted []ownedConsulted, rank uint8, key []byte) bool {
	i := sort.Search(len(consulted), func(i int) bool {
		return !updateKeyOrdered(consulted[i].dbi.Rank, consulted[i].key, rank, key)
	})
	return i < len(consulted) && consulted[i].dbi.Rank == rank && bytes.Equal(consulted[i].key, key)
}

func obsoletePointEqual(old, candidate *Reader, point obsoletePoint, plan []ownedMutation, consulted []ownedConsulted) (bool, error) {
	if canonicalTargetIndex(plan, point.rank, point.key) >= 0 || obsoleteConsultedContains(consulted, point.rank, point.key) {
		return true, nil
	}
	a, err := old.obsoletePoint(point.rank, point.key, operationUpdate)
	if err != nil {
		return false, err
	}
	b, err := candidate.obsoletePoint(point.rank, point.key, operationUpdate)
	if err != nil {
		return false, err
	}
	return largeRowsEqual(largeNativeRow{key: point.key, image: a}, largeNativeRow{key: point.key, image: b}), nil
}

func obsoleteDomainEqual(old, candidate *Reader, domain obsoleteDomain, plan []ownedMutation, consulted []ownedConsulted) (bool, error) {
	if domain.point {
		return obsoletePointEqual(old, candidate, obsoletePoint{rank: domain.rank, key: domain.prefix}, plan, consulted)
	}
	seek := domain.seek(old.maxKey)
	start := sort.Search(len(plan), func(i int) bool {
		return !updateKeyOrdered(plan[i].dbi.Rank, plan[i].key, domain.rank, seek)
	})
	left := largeResidualStream{reader: old, domain: &domain, seek: seek, plan: plan[start:]}
	right := largeResidualStream{reader: candidate, domain: &domain, seek: seek, plan: plan[start:]}
	equal := true
	for {
		a, err := left.next()
		if err != nil {
			return false, err
		}
		b, err := right.next()
		if err != nil {
			return false, err
		}
		if a.done && b.done {
			return equal, nil
		}
		equal = obsoleteRowsEqual(a, b, domain.rank, consulted) && equal
	}
}

func obsoleteRowsEqual(a, b largeNativeRow, rank uint8, consulted []ownedConsulted) bool {
	// Keep both streams complete: only a same-key value predicate is shared.
	if a.done != b.done || !bytes.Equal(a.key, b.key) {
		return false
	}
	if obsoleteConsultedContains(consulted, rank, a.key) {
		return true
	}
	return largeRowsEqual(a, b)
}
