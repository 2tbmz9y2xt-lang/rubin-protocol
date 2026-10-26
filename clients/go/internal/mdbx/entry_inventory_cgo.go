//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

// EntryInventoryV1 identifies one same-entry inventory preparation.
type EntryInventoryV1 struct{ scope *entryInventoryStateV1 }

// EntryInventoryRowV1 lends immutable metadata and bounded reads during its
// visitor call. Do not mutate the borrowed Key backing. Value copies retain
// the original private source regardless of changes to exported metadata.
type EntryInventoryRowV1 struct {
	Source     uint8
	Artifact   uint8
	Role       uint8
	Projection uint8
	Generation uint64
	Height     uint64
	Hash       [32]byte
	Count      uint64
	IndexCount uint64
	Node       TreeNodeIDV1
	Key        []byte
	Present    bool
	Length     uint64
	access     *entryRowAccessV1
	serial     uint64
}

// EntryInventoryFailureV1 owns the first actual request's inert provenance.
// SourceError is the original interface, including nil for positive failures.
type EntryInventoryFailureV1 struct {
	Source      uint8
	Artifact    uint8
	Role        uint8
	Access      uint8
	Observation uint8
	Generation  uint64
	Height      uint64
	Hash        [32]byte
	Key         []byte
	Prefix      []byte
	SourceError error
}

type entryRowAccessV1 struct {
	mu     *sync.Mutex // immutable locator, also after retirement
	reader *Reader
	key    []byte
	image  updateImage
	serial uint64
	active bool
}

// Fixed state owns retirement; the sole Visit walker owns its source cursor.
type entryInventoryStateV1 struct {
	entry       *treePublicEntryV1
	reader      *Reader
	account     *OperationAccount
	oldBytes    []byte
	nextBytes   []byte
	mutations   []Mutation
	consulted   []ConsultedRow
	decode      [2]authorityDecodeControl
	inspection  [2]authorityInspection
	authority   [2]TreeAuthorityV1
	rootControl rootDecodeControl
	endpoints   [2]TreeEndpointV1
	failure     *EntryInventoryFailureV1
	maxKey      uint64
	serial      uint64
	completed   bool
	retired     bool
	visiting    bool
	failed      bool
	row         EntryInventoryRowV1
	access      entryRowAccessV1
	stream      *entryStreamV1
}

var errEntryStoppedV1 = errors.New("ENTRY inventory stopped")

func entryInputV1() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "invalid ENTRY inventory", nil)
}

// PrepareEntryInventoryV1 consumes one preparation on the initial ORIGINAL OLD
// Reader. Ordinary Pair grammar precedes funding and physical source access.
// Preparation alone does not establish completed inventory or permit a write.
func (r *Reader) PrepareEntryInventoryV1(account *OperationAccount, target TreePairV1) (EntryInventoryV1, *EntryInventoryFailureV1, error) {
	if !r.usable() {
		return EntryInventoryV1{}, nil, entryInputV1()
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if !r.usable() || r.entry == nil {
		return EntryInventoryV1{}, nil, entryInputV1()
	}
	e := r.entry
	if !e.preparableV1(r, account) || target.EntryInventory != nil {
		return EntryInventoryV1{}, nil, entryInputV1()
	}
	if err := treeAdmitV1(TreeOperationV1{Pair: target}, account, r.databaseID); err != nil {
		return EntryInventoryV1{}, nil, err
	}
	if err := e.hold.grow(8192 + 6*r.maxKey); err != nil {
		return EntryInventoryV1{}, nil, err
	}
	s := &entryInventoryStateV1{entry: e, reader: r, account: account, maxKey: r.maxKey, mutations: target.Mutations, consulted: target.Consulted}
	e.inventory = s
	s.failure = &EntryInventoryFailureV1{Key: make([]byte, s.maxKey)}
	s.access.mu, s.access.key = &r.getMu, make([]byte, s.maxKey)
	return s.preparedV1(s.prepareV1())
}

func (e *treePublicEntryV1) preparableV1(r *Reader, account *OperationAccount) bool {
	if !e.initialReaderV1(r) || e.inventory != nil || e.hold == nil || account == nil {
		return false
	}
	return e.hold.account == account.shared && account.openV1() && account.shared.ceiling == TreeLaneMaxBytes
}

func (e *treePublicEntryV1) initialReaderV1(r *Reader) bool {
	return e.reader == r && r.updateOld && e.old == r.txn
}

func (s *entryInventoryStateV1) preparedV1(err error) (EntryInventoryV1, *EntryInventoryFailureV1, error) {
	failure, err := s.resultV1(s.failure, err)
	if err != nil || failure != nil {
		return EntryInventoryV1{}, failure, err
	}
	return EntryInventoryV1{scope: s}, nil, nil
}

// Preparation and Visit project the same first-failure frame. Visit supplies
// its saved inert pointer, which remains available after callback expiry.
func (s *entryInventoryStateV1) resultV1(failure *EntryInventoryFailureV1, err error) (*EntryInventoryFailureV1, error) {
	if !s.failed {
		return nil, err
	}
	if errors.Is(errEntryStoppedV1, err) {
		err = failure.SourceError
	}
	return failure, err
}

func (s *entryInventoryStateV1) failureResultV1() *EntryInventoryFailureV1 {
	if s.failed {
		return s.failure
	}
	return nil
}

// VisitEntryInventoryV1 observes the complete protected physical source domain.
// A physical stop can instead return a nonnil sidecar with a nil SourceError.
func (r *Reader) VisitEntryInventoryV1(token EntryInventoryV1, visit func(EntryInventoryRowV1) error) (*EntryInventoryFailureV1, error) {
	if !r.usable() || token.scope == nil {
		return nil, entryInputV1()
	}
	mu := &r.getMu
	mu.Lock()
	defer mu.Unlock()
	if !r.usable() || r.entry == nil || r.entry.inventory != token.scope {
		return nil, entryInputV1()
	}
	s := token.scope // identity precedes mutable foreign-state access
	if !s.visitableV1(r) {
		return s.failureResultV1(), entryInputV1()
	}
	s.visiting = true // consumed, including unsupported completion and unwind
	if visit == nil {
		return nil, entryInputV1()
	}
	defer s.clearSourcesV1()
	var cursor entryCursorV1
	var context EntryInventoryRowV1
	stream := &entryStreamV1{}
	s.stream = stream // register before any fallible source work
	w := entryWalkV1{s: s, old: r, visit: visit, stream: stream, cursor: &cursor, context: &context}
	failure := s.failure // survives callback expiry and mutable-borrow retirement
	err := w.runV1()
	s.clearSourcesV1()
	s.completed = all(err == nil, !s.failed, !s.retired)
	return s.resultV1(failure, err)
}

func (s *entryInventoryStateV1) visitableV1(r *Reader) bool {
	return s.reader == r && s.entry == r.entry && !s.completed && !s.visiting && !s.retired && !s.failed && s.account.openV1()
}

func (s *entryInventoryStateV1) requestV1(row *EntryInventoryRowV1, access uint8, key []byte) {
	if s.failed {
		return
	}
	f := s.failure
	f.Source, f.Artifact, f.Role = row.Source, row.Artifact, row.Role
	f.Generation, f.Height, f.Hash = row.Generation, row.Height, row.Hash
	f.Access, f.Observation, f.SourceError = access, 0, nil
	f.Key = f.Key[:copy(f.Key[:cap(f.Key)], key)]
	f.Prefix = nil
	if access == 2 {
		f.Prefix = f.Hash[:]
	}
}

func (s *entryInventoryStateV1) stopV1(observation uint8, err error) error {
	if !s.failed {
		s.failed = true
		s.failure.Observation, s.failure.SourceError = observation, err
		if err != nil {
			_ = s.reader.largeFailure(err)
		}
	}
	return errEntryStoppedV1
}

// ReadAt reads the private current source, not fields of the public Row copy.
func (row EntryInventoryRowV1) ReadAt(dst []byte, offset uint64) (int, error) {
	a := row.access
	if a == nil {
		return 0, largeImageInput("invalid ENTRY inventory row")
	}
	mu := a.mu
	mu.Lock()
	defer mu.Unlock()
	if err := a.inputV1(row.serial, len(dst)); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if offset >= uint64(a.image.length) {
		return 0, io.EOF
	}
	return a.readV1(dst, offset)
}

func (a *entryRowAccessV1) inputV1(serial uint64, length int) error {
	if !a.active || a.serial != serial || a.reader == nil {
		return largeImageInput("ENTRY inventory row is not active")
	}
	if !a.reader.usable() || a.reader.entry == nil {
		return largeImageInput("ENTRY inventory row is not active")
	}
	if length > 65536 {
		return largeImageInput("ReadAt buffer exceeds 65536 bytes")
	}
	return nil
}

func (a *entryRowAccessV1) readV1(dst []byte, offset uint64) (int, error) {
	r := a.reader
	s := r.entry.inventory
	if s.failed {
		return 0, largeImageInput("ENTRY inventory row is not active")
	}
	s.requestV1(&s.row, 3, a.key)
	w := entryWalkV1{s: s}
	image, literal, err := w.literalV1(entryRankV1(s.row.Artifact), a.key)
	if err == nil && !literal {
		image, err = r.obsoletePoint(entryRankV1(s.row.Artifact), a.key, operationGet)
	}
	if err == nil && (!image.present || image.length != a.image.length) {
		err = obsoleteShape(operationGet)
	}
	if err != nil {
		_ = s.stopV1(1, err)
		return 0, err
	}
	return largeImageCopy(dst, image.bytes, uint64(image.length)-offset, offset)
}

func (e *treePublicEntryV1) retireEntryV1() {
	e.reader.getMu.Lock()
	defer e.reader.getMu.Unlock()
	e.reader.entry = nil
	if e.inventory != nil {
		e.inventory.retireV1()
	}
}

// Expiry ends public capabilities while retaining the private complete recipe.
func (e *treePublicEntryV1) expireEntryV1() {
	e.reader.getMu.Lock()
	defer e.reader.getMu.Unlock()
	e.reader.entry = nil
	if e.inventory != nil {
		e.inventory.clearSourcesV1()
	}
}

func (s *entryInventoryStateV1) clearSourcesV1() {
	if !s.failed && s.access.key != nil {
		s.failure.Prefix = s.access.key[:0] // private request storage, never a lease
	}
	if s.stream != nil {
		*s.stream = entryStreamV1{}
		s.stream = nil
	}
	s.row = EntryInventoryRowV1{}
	s.access.reader, s.access.key, s.access.image = nil, nil, updateImage{}
	s.access.active = false
}

func (e *treePublicEntryV1) entryAdmitV1(op *TreeOperationV1, account *OperationAccount) error {
	s, token := e.inventory, op.Pair.EntryInventory
	if s == nil && token == nil {
		return nil
	}
	if s == nil || token == nil || token.scope != s {
		return entryInputV1()
	}
	valid := all(s.entry == e, s.reader == e.reader, s.account == account, s.reader.txn == e.old, s.completed, !s.failed, !s.retired, len(op.Primitives) == 0)
	if !valid || !s.targetSameV1(&op.Pair) {
		return entryInputV1()
	}
	return nil
}

func (s *entryInventoryStateV1) targetSameV1(pair *TreePairV1) bool {
	if len(pair.Mutations) != len(s.mutations) || len(pair.Consulted) != len(s.consulted) {
		return false
	}
	for i := range s.mutations {
		a, b := &s.mutations[i], &pair.Mutations[i]
		if !all(a.DBI == b.DBI, a.BeforePresent == b.BeforePresent, a.AfterKind == b.AfterKind, a.RefDBI == b.RefDBI, bytes.Equal(a.Key, b.Key), bytes.Equal(a.Literal, b.Literal), bytes.Equal(a.RefKey, b.RefKey)) {
			return false
		}
	}
	for i := range s.consulted {
		if s.consulted[i].DBI != pair.Consulted[i].DBI || !bytes.Equal(s.consulted[i].Key, pair.Consulted[i].Key) {
			return false
		}
	}
	return true
}

// Called under the immutable Reader getMu before ORIGINAL OLD is aborted.
func (s *entryInventoryStateV1) retireV1() {
	s.retired = true
	s.clearSourcesV1()
	s.entry, s.reader, s.account = nil, nil, nil
	s.oldBytes, s.nextBytes, s.mutations, s.consulted = nil, nil, nil, nil
	s.decode, s.inspection, s.authority = [2]authorityDecodeControl{}, [2]authorityInspection{}, [2]TreeAuthorityV1{}
	s.rootControl, s.endpoints = rootDecodeControl{}, [2]TreeEndpointV1{}
	if !s.failed {
		s.failure.Key, s.failure.Prefix = nil, nil
	}
	// The separate failure owns only bytes/error; suspended Visit may return it.
}
