//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"sync/atomic"
)

// ErrCandidateParentNotCurrent is a coherent CURRENT selection refusal.
var ErrCandidateParentNotCurrent = errors.New("candidate parent is not CURRENT")

// ErrCandidateSourceUnavailable reports a verified empty selection source.
var ErrCandidateSourceUnavailable = errors.New("candidate source unavailable")

// CandidateRootParentV1 names a positive-height derivation's committed parent.
type CandidateRootParentV1 struct {
	DatabaseID         [32]byte
	Generation, Height uint64
	Parent             TreeEndpointV1
}

// CandidateRootBodyV1 borrows an immutable complete body and its ordered events.
type CandidateRootBodyV1 struct {
	Raw         []byte
	HeaderBytes uint16
	BlockMeta   TreeBlockV1
	Events      func([]byte, *TreeDeltaSinkV1) error
}

// CandidateRootScopeV1 is a single synchronous root derivation on a borrowed Reader.
type CandidateRootScopeV1 struct {
	state *candidateRootScopeStateV1
}

type candidateRootScopeStateV1 struct {
	reader    *Reader
	account   *OperationAccount
	selection CandidateRootParentV1
	status    atomic.Uint32
}

const (
	candidateUnqualifiedV1 uint32 = iota
	candidateQualifyingV1
	candidateCurrentV1
	candidateDerivingV1
)

// WithCandidateRootV1 admits one parent selection and closes the account on exit.
func (o *OperationReservationOwner) WithCandidateRootV1(r *Reader, parent CandidateRootParentV1, use func(*CandidateRootScopeV1) error) error {
	if o == nil || o.shared == nil || use == nil {
		return errOperationReservationInput
	}
	if err := r.treeContext(); err != nil {
		return err
	}
	if !candidateRootParentValidV1(r, parent) {
		return treeDeltaInvalidV1()
	}
	return o.withAccountV1(TreeLaneMaxBytes, func(account *OperationAccount) error {
		state := &candidateRootScopeStateV1{reader: r, account: account, selection: parent}
		return use(&CandidateRootScopeV1{state: state})
	})
}

// candidateRootParentValidV1 checks the request against the factory database identity.
func candidateRootParentValidV1(r *Reader, p CandidateRootParentV1) bool {
	return all(p.DatabaseID != [32]byte{}, p.DatabaseID == r.databaseID, p.Generation != 0,
		p.Height != 0, p.Height <= math.MaxUint32, treeRootReadParentV1(p.Height, p.Parent))
}

// openV1 checks account and Reader lifetime before lending work.
func (s *CandidateRootScopeV1) openV1() bool {
	return s != nil && s.state != nil && s.state.account.openV1() && s.state.reader.usable()
}

// WithCandidateValidationV1 funds validation and lends its once-only retirement function.
func (s *CandidateRootScopeV1) WithCandidateValidationV1(initial, rawBytes uint64, use func(retire func() error) error) error {
	if !s.openV1() || rawBytes > 68_000_157 {
		return errOperationReservationInput
	}
	return s.state.account.WithPhaseReservationV1(initial, rawBytes+4096, use)
}

// WithCandidateCensusV1 funds the synchronous body census.
func (s *CandidateRootScopeV1) WithCandidateCensusV1(use func() error) error {
	if !s.openV1() {
		return errOperationReservationInput
	}
	return s.state.account.WithReservation(4824, use)
}

// WithCandidateFactsV1 funds the full consulted-state arrays and lends their retirement functions.
func (s *CandidateRootScopeV1) WithCandidateFactsV1(rawBytes uint64, events uint32, use func(retireLookup func() error, retireLengths func() error, retireKeys func() error) error) error {
	if !s.openV1() || use == nil {
		return errOperationReservationInput
	}
	e := uint64(events)
	if !candidateRootEventBoundV1(rawBytes, e) {
		return errOperationReservationCapacity
	}
	return s.state.account.withHold(func(h *operationHold) error {
		if err := h.grow(135192 + 48*e); err != nil {
			return err
		}
		return use(h.reductionV1(135192+8*e), h.reductionV1(4*e), h.reductionV1(36*e))
	})
}

// QualifyCurrentV1 verifies the selected generation and tip on the borrowed Reader.
func (s *CandidateRootScopeV1) QualifyCurrentV1() error {
	if !s.openV1() || !s.state.status.CompareAndSwap(candidateUnqualifiedV1, candidateQualifyingV1) {
		return treeDeltaInvalidV1()
	}
	state := s.state
	if err := state.reader.qualifyCandidateParentV1(state.selection); err != nil {
		return err
	}
	state.status.Store(candidateCurrentV1)
	return nil
}

// qualifyCandidateParentV1 records reached authority and tip failures on this Reader.
func (r *Reader) qualifyCandidateParentV1(p CandidateRootParentV1) error {
	r.getMu.Lock()
	defer r.getMu.Unlock()
	if err := r.treeContext(); err != nil {
		return err
	}
	generation, err := r.candidateActiveGenerationV1()
	if err != nil {
		return r.treeRecord(err)
	}
	if generation == 0 {
		return ErrCandidateSourceUnavailable
	}
	if generation != p.Generation {
		return ErrCandidateParentNotCurrent
	}
	endpoint, err := r.candidateTipV1(generation)
	if err != nil {
		return r.treeRecord(err)
	}
	if endpoint != p.Parent {
		return ErrCandidateParentNotCurrent
	}
	return nil
}

// candidateActiveGenerationV1 inspects borrowed authority or proves exact emptiness.
func (r *Reader) candidateActiveGenerationV1() (uint64, error) {
	image, err := r.largePoint(0, []byte{2})
	if err != nil {
		return 0, err
	}
	if !image.present {
		return 0, treeEmptyCensus(r.txn, r.dbis, r.treeConfig, r.databaseID, operationGet)
	}
	if uint64(image.length) > MaxMetadataBytes {
		return 0, treeIntegrity(operationGet, errSchema)
	}
	value, err := treeBorrowV1(image)
	if err != nil {
		return 0, err
	}
	var control authorityDecodeControl
	var inspection authorityInspection
	authority, err := decodeTreeAuthorityV1(value.value, &control, &inspection)
	if err != nil {
		return 0, treeIntegrity(operationGet, err)
	}
	return authority.Authority.ActiveGenerationID, nil
}

// candidateTipV1 captures the physical tip and its work under the Reader lock.
func (r *Reader) candidateTipV1(generation uint64) (TreeEndpointV1, error) {
	row, err := canonicalTipEndpoint(r.txn, r.dbis[2], generation, operationPrefixPage)
	if err != nil {
		return TreeEndpointV1{}, err
	}
	if row.key == nil {
		return TreeEndpointV1{}, integrityError(operationPrefixPage, "canonical tip absent", nil)
	}
	point, err := canonicalTipPoint(row)
	if err != nil {
		return TreeEndpointV1{}, err
	}
	image, err := treeBorrowV1(row.image)
	if err != nil {
		return TreeEndpointV1{}, err
	}
	return TreeEndpointV1{Kind: TreeEndpointAppliedV1, Height: point.Height, BlockHash: point.BlockHash, CumulativeChainwork: [40]byte(image.value[64:104])}, nil
}

// DeriveCandidateRootV1 returns the new digest and consumes the scope's one attempt.
func (s *CandidateRootScopeV1) DeriveCandidateRootV1(body CandidateRootBodyV1, inputs []TreeOutpointV1) ([32]byte, error) {
	if !s.openV1() || !s.state.status.CompareAndSwap(candidateCurrentV1, candidateDerivingV1) {
		return [32]byte{}, treeDeltaInvalidV1()
	}
	state := s.state
	if !candidateRootCoverageV1(state.selection, body, len(inputs)) {
		return [32]byte{}, treeDeltaInvalidV1()
	}
	if err := treeRootReadInputsV1(inputs); err != nil {
		return [32]byte{}, err
	}
	n := treeStepBytesV1 + treeValueBytesV1 + treeNodeWorkBytesV1 + treeDescSizeV1*uint64(body.BlockMeta.EventCount)
	var root [32]byte
	err := state.account.WithReservation(n, func() error {
		budget := treeBudgetV1{held: n}
		var err error
		root, err = state.reader.candidateRootReadV1(state.selection, body, inputs, budget.ledgerV1())
		return err
	})
	if err != nil {
		return [32]byte{}, err
	}
	return root, nil
}

// candidateRootCoverageV1 bounds the candidate's body and facts before D admission.
func candidateRootCoverageV1(p CandidateRootParentV1, body CandidateRootBodyV1, facts int) bool {
	n := uint64(len(body.Raw))
	if !all(body.HeaderBytes == 148, n >= 149, n <= 68_000_157, body.Events != nil) {
		return false
	}
	if !bytes.Equal(body.Raw[4:36], p.Parent.BlockHash[:]) {
		return false
	}
	txs, _, ok := readCompactSize(body.Raw[148:])
	e := uint64(body.BlockMeta.EventCount)
	return all(ok, txs != 0, txs == uint64(body.BlockMeta.TxCount), candidateRootEventBoundV1(n, e), uint64(facts) <= e)
}

// candidateRootEventBoundV1 checks the disjoint body-byte and allocation bounds.
func candidateRootEventBoundV1(n, e uint64) bool {
	if n < 149 || n > 68_000_157 {
		return false
	}
	base := min(17_000_000, n-149, (68_000_157-n)/3)
	return e <= base/11 && e <= uint64(math.MaxInt)/treeDescSizeV1
}

// candidateRootReadV1 resolves and walks the candidate's immutable event stream.
func (r *Reader) candidateRootReadV1(p CandidateRootParentV1, body CandidateRootBodyV1, inputs []TreeOutpointV1, ledger treeLedgerV1) ([32]byte, error) {
	if err := ledger.chargeV1(treeStepBytesV1); err != nil {
		return [32]byte{}, err
	}
	defer ledger.releaseV1(treeStepBytesV1)
	observation := TreeObservationV1{DatabaseID: r.databaseID, Generation: p.Generation, Height: p.Height, Position: TreeWriterV1}
	shape := treePrimitiveV1{direction: treeForwardV1, undo: treeUndoTransientV1, generation: p.Generation, height: p.Height}
	rec := newTreeRecorderV1(treeWriterV1, shape, treeBodyV1{bytes: body.Raw}, make([]byte, treeWindowBytesV1), ledger)
	rec.rootReadOnly, rec.coverage.BlockMeta, rec.observation = true, body.BlockMeta, &observation
	defer rec.releaseV1()
	delta, err := r.candidateRootEventsV1(rec, body)
	if err != nil {
		return [32]byte{}, err
	}
	old := &treeRootOldV1{reader: r, generation: p.Generation, parent: p.Parent, inputs: inputs, rec: rec, observation: &observation, remaining: 577*uint64(rec.eventCount) + 1}
	if err = delta.resolveV1(old); err != nil {
		return [32]byte{}, r.treeRootRecordV1(err)
	}
	w := treeWalkV1{generation: p.Generation, old: old, leaves: delta.leavesV1(), observation: &observation}
	root, err := treeCandidateDigestV1(&w, r.databaseID, ledger)
	return root, r.treeRootRecordV1(err)
}

// candidateRootEventsV1 seals the recorder after the source stops.
func (r *Reader) candidateRootEventsV1(rec *treeRecorderV1, body CandidateRootBodyV1) (*treeDeltaV1, error) {
	unwind, sourceErr := treeCallV1(func() error { return body.Events(body.Raw, &TreeDeltaSinkV1{recorder: rec}) })
	defer unwind.resumeV1()
	r.getMu.Lock()
	readErr := r.failure
	r.getMu.Unlock()
	err := treePrimaryV1(sourceErr, readErr, rec.failureV1())
	if err != nil || unwind.kind != 0 {
		return nil, err
	}
	return rec.finishRootEventsV1()
}

// TreeRootReadV1 binds one fresh noncommitting derivation to its selected parent.
// Primitive is forward, DirectApply, UndoTransient and covered by a complete
// current initial148 body. Inputs borrows immutable present-parent keys for this
// synchronous call, strictly ordered by raw Txid then unsigned Vout, without
// duplicates, values, caller-computed roots or node hashes. All keys assert a
// parent premise, including keys without an event group; nil and empty agree.
type TreeRootReadV1 struct {
	Primitive TreePrimitiveV1
	Parent    TreeEndpointV1
	Inputs    []TreeOutpointV1
}

// DeriveTreeRootV1 borrows this live tree Reader and account synchronously. It
// opens no transaction, emits no mutation and returns no digest on failure.
// Parent rows are point-only; at height zero the parent is definitionally empty.
// SPEND-first groups use Inputs presence without reading parent row values.
// Incompatible obtained parent identities refuse before later reads or digests.
func (r *Reader) DeriveTreeRootV1(account *OperationAccount, request TreeRootReadV1) (root [32]byte, err error) {
	if err := r.CheckTreeRootReadV1(account, request); err != nil {
		return root, err
	}
	n := treeStepBytesV1 + treeValueBytesV1 + treeNodeWorkBytesV1 + treeDescSizeV1*uint64(request.Primitive.Coverage.BlockMeta.EventCount)
	err = account.WithReservation(n, func() error {
		budget := treeBudgetV1{held: n}
		var deriveErr error
		root, deriveErr = r.treeRootReadV1(request, budget.ledgerV1())
		return deriveErr
	})
	if err != nil {
		return [32]byte{}, err
	}
	return root, nil
}

// CheckTreeRootReadV1 checks Reader, account and request admission without I/O,
// reservation, observation, or changing their state. Derive repeats this check
// with the final borrowed Inputs before reserving its work.
func (r *Reader) CheckTreeRootReadV1(account *OperationAccount, request TreeRootReadV1) error {
	if err := r.treeContext(); err != nil {
		return err
	}
	if !account.openV1() || account.shared.ceiling != TreeLaneMaxBytes {
		return treeDeltaInvalidV1()
	}
	p := request.Primitive
	if !treeRootReadPrimitiveV1(p) {
		return treeDeltaInvalidV1()
	}
	if !treeRootReadCoverageV1(p, r.databaseID) {
		return treeDeltaInvalidV1()
	}
	if !treeRootReadParentV1(p.Height, request.Parent) {
		return treeDeltaInvalidV1()
	}
	return treeRootReadFactsV1(request)
}

func treeRootReadFactsV1(request TreeRootReadV1) error {
	p := request.Primitive
	if uint64(p.Coverage.BlockMeta.EventCount) > uint64(math.MaxInt)/treeDescSizeV1 || len(request.Inputs) > int(p.Coverage.BlockMeta.EventCount) {
		return treeDeltaInvalidV1()
	}
	if p.Height == 0 && len(request.Inputs) != 0 {
		return treeDeltaInvalidV1()
	}
	return treeRootReadInputsV1(request.Inputs)
}

func treeRootReadPrimitiveV1(p TreePrimitiveV1) bool {
	return treePrimitiveShapeV1(p, 0) && treeEndpointAllowedV1(p) && p.Direction == TreeForwardV1 && p.Kind == TreeKindDirectApplyV1 && p.Undo == UndoTransientV1
}

func treeRootReadCoverageV1(p TreePrimitiveV1, database [32]byte) bool {
	if p.Coverage == nil {
		return false
	}
	c := p.Coverage
	return treeCoverageIdentityV1(c, p, database) && treeCoverageMetaV1(c) && c.HeaderBytes == 148 && c.BodyKind == 1 && len(c.CurrentBody) != 0
}

func treeRootReadParentV1(height uint64, parent TreeEndpointV1) bool {
	if !validTreeEndpoint(parent) {
		return false
	}
	if height == 0 {
		return parent.Kind == TreeEndpointPreGenesisV1
	}
	return parent.Kind == TreeEndpointAppliedV1 && parent.Height == height-1
}

func treeRootReadInputsV1(inputs []TreeOutpointV1) error {
	for i, input := range inputs {
		if i != 0 && treeRootOutpointCompareV1(inputs[i-1], input) >= 0 {
			return treeDeltaInvalidV1()
		}
	}
	return nil
}

func treeRootOutpointCompareV1(a, b TreeOutpointV1) int {
	if order := bytes.Compare(a.Txid[:], b.Txid[:]); order != 0 {
		return order
	}
	return cmp.Compare(a.Vout, b.Vout)
}

func (r *Reader) treeRootReadV1(request TreeRootReadV1, ledger treeLedgerV1) ([32]byte, error) {
	if err := ledger.chargeV1(treeStepBytesV1); err != nil {
		return [32]byte{}, err
	}
	defer ledger.releaseV1(treeStepBytesV1)
	p := request.Primitive
	observation := TreeObservationV1{DatabaseID: r.databaseID, Generation: p.Generation, Block: p.Block, Height: p.Height, Primitive: 0, Position: TreeWriterV1}
	rec := newTreeRecorderV1(treeWriterV1, treeAdmittedPrimitiveV1(&p), treeBodyV1{bytes: p.Coverage.CurrentBody, pair: true}, make([]byte, treeWindowBytesV1), ledger)
	rec.rootReadOnly, rec.coverage, rec.observation = true, *p.Coverage, &observation
	defer rec.releaseV1()
	unwind, sourceErr := treeCallV1(func() error { return p.Source.TreeDeltaV1(TreeWriterV1, r, &TreeDeltaSinkV1{recorder: rec}) })
	defer unwind.resumeV1()
	err := treePrimaryV1(sourceErr, r.failure, rec.failureV1())
	if err != nil || unwind.kind != 0 {
		return [32]byte{}, err
	}
	delta, err := rec.finishV1()
	if err != nil {
		return [32]byte{}, err
	}
	var old treeOldV1 = &treeRootOldV1{reader: r, generation: p.Generation, parent: request.Parent, inputs: request.Inputs, rec: rec, observation: &observation, remaining: 577*uint64(rec.eventCount) + 1}
	var seed *RootBindingV1
	if p.Height == 0 {
		old = treeEmptyOldV1{}
		seed = &RootBindingV1{DatabaseID: r.databaseID, CommitmentVersion: 1, Endpoint: request.Parent, RootDigest: treeEmptyDigestV1(), Top: TreeTopV1{Kind: TreeTopEmptyV1}, Assurance: TreeAssuranceV1{Kind: TreeAssuranceFullHistoryV1}}
	}
	if err = delta.resolveV1(old); err != nil {
		return [32]byte{}, r.treeRootRecordV1(err)
	}
	w := treeWalkV1{generation: p.Generation, old: old, leaves: delta.leavesV1(), observation: &observation}
	root, err := treeRunResultV1(w, p.Endpoint, r.databaseID, ledger, seed)
	return root, r.treeRootRecordV1(err)
}

func (r *Reader) treeRootRecordV1(err error) error {
	var engine *EngineError
	if !errors.As(err, &engine) || engine == nil || engine.Class == EngineInvalidInput {
		return err
	}
	r.getMu.Lock()
	defer r.getMu.Unlock()
	return r.treeRecord(err)
}

// treeRootOldV1 exposes neither range discovery nor counter/undo access. The
// selected transaction owns borrowed images until the enclosing Reader expires.
type treeRootOldV1 struct {
	reader      *Reader
	generation  uint64
	parent      TreeEndpointV1
	inputs      []TreeOutpointV1
	rec         *treeRecorderV1
	observation *TreeObservationV1
	remaining   uint64
}

func (o *treeRootOldV1) getV1(dbi DBI, key []byte) (treeImageV1, error) {
	if !o.pointV1(dbi, key) || o.remaining == 0 {
		return treeImageV1{}, treeDeltaInvalidV1()
	}
	o.reader.getMu.Lock()
	defer o.reader.getMu.Unlock()
	if err := o.reader.treeContext(); err != nil {
		return treeImageV1{}, err
	}
	o.remaining--
	if dbi.Rank == 1 {
		if spend, err := o.spendV1(key); spend {
			return treeImageV1{present: err == nil}, o.reader.treeRecord(err)
		}
	}
	image, err := treeReadPointV1(o.reader.txn, o.reader.dbis[dbi.Rank], key)
	if err == nil {
		err = o.checkV1(dbi, key, image)
	}
	return image, o.reader.treeRecord(err)
}

func (o *treeRootOldV1) pointV1(dbi DBI, key []byte) bool {
	if readerDBI(3, dbi) != nil || !readerKey(3, dbi.Rank, key) {
		return false
	}
	if dbi.Rank == 0 {
		return len(key) == 9 && key[0] == 0x11 && binary.BigEndian.Uint64(key[1:]) == o.generation
	}
	return (dbi.Rank == 1 || dbi.Rank == 8) && binary.BigEndian.Uint64(key[:8]) == o.generation
}

func (o *treeRootOldV1) checkV1(dbi DBI, key []byte, image treeImageV1) error {
	if dbi.Rank == 0 {
		return o.bindingV1(key, image)
	}
	if dbi.Rank == 8 {
		return o.nodeV1(key, image)
	}
	if dbi.Rank != 1 {
		return nil
	}
	if image.present && !treeUTXOValueOKV1(image.value) {
		return treeObserveV1(treeIntegrity(operationUpdate, errSchema), o.observation, 1, key, TreeObservationMalformedV1, image, true)
	}
	return o.originalV1(key, image)
}

func (o *treeRootOldV1) bindingV1(key []byte, image treeImageV1) error {
	if !image.present {
		return nil // The shared walker owns absent/malformed binding detection.
	}
	binding, err := DecodeRootBindingV1(image.value)
	if err == nil {
		if binding.Endpoint != o.parent || binding.DatabaseID != o.reader.databaseID {
			return treeObserveV1(treeIntegrity(operationUpdate, nil), o.observation, 0, key, TreeObservationIdentityMismatchV1, image, true)
		}
		return o.topV1(binding)
	}
	return nil
}

// topV1 checks a decoded, selected-parent binding before its walker consumption.
func (o *treeRootOldV1) topV1(binding RootBindingV1) error {
	if len(o.inputs) != 0 && binding.RootDigest == treeEmptyDigestV1() {
		return treeIntegrity(operationUpdate, nil)
	}
	if binding.Top.Kind == TreeTopEmptyV1 {
		if len(o.inputs) != 0 {
			return treeIntegrity(operationUpdate, nil)
		}
		return nil
	}
	return o.identityV1(treeRefOfID(*binding.Top.Node, binding.RootDigest), o.inputs)
}

// nodeV1 checks both identities only after the existing record decoder accepts.
func (o *treeRootOldV1) nodeV1(key []byte, image treeImageV1) error {
	_, id, err := DecodeTreeNodeKey(key)
	node := treeRefOfID(id, [32]byte{})
	decodedBranch := image.present && err == nil && treeRecordOKV1(node, image.value) && node.depth != 288
	if !decodedBranch {
		return nil // The walker owns absent, malformed, identity and digest errors.
	}
	for side := range 2 {
		offset := side * 70
		child, _ := decodeTreeSuffix(image.value[offset : offset+38])
		interval := treeNodeRefV1{key: node.key, depth: node.depth + 1}
		interval.key[node.depth/8] |= byte(side) << (7 - node.depth%8)
		if err := o.identityV1(treeRefOfID(child, [32]byte{}), o.intervalV1(interval)); err != nil {
			return err
		}
	}
	return nil
}

// identityV1 checks an obtained identity against C and both sorted P extrema.
func (o *treeRootOldV1) identityV1(node treeNodeRefV1, inputs []TreeOutpointV1) error {
	if node.depth == 288 && o.createdV1(treeRootOutpointV1(node.key)) {
		return treeIntegrity(operationUpdate, nil)
	}
	if len(inputs) == 0 {
		return nil
	}
	if !treeContainsV1(node, treeRootRoutingV1(inputs[0])) || !treeContainsV1(node, treeRootRoutingV1(inputs[len(inputs)-1])) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

// intervalV1 borrows exactly P's parent-prefix/side interval without scanning.
func (o *treeRootOldV1) intervalV1(node treeNodeRefV1) []TreeOutpointV1 {
	inputs := o.inputs
	lower, upper := treeRootOutpointV1(node.key), treeRootOutpointV1(treeUpperV1(node))
	first := sort.Search(len(inputs), func(i int) bool { return treeRootOutpointCompareV1(inputs[i], lower) >= 0 })
	last := sort.Search(len(inputs), func(i int) bool { return treeRootOutpointCompareV1(inputs[i], upper) > 0 })
	return inputs[first:last]
}

// spendV1 supplies only a captured present-key premise, before native row I/O.
func (o *treeRootOldV1) spendV1(key []byte) (bool, error) {
	op := treeRootOutpointV1([36]byte(key[8:44]))
	group := o.groupV1(op)
	if group == nil || group.kind != treeSpendV1 {
		return false, nil
	}
	if !o.inputV1(op) {
		return true, treeIntegrity(operationUpdate, nil)
	}
	return true, nil
}

// originalV1 preserves CREATE-first's captured-premise/absent-row refusal.
func (o *treeRootOldV1) originalV1(key []byte, image treeImageV1) error {
	if !image.present && o.inputV1(treeRootOutpointV1([36]byte(key[8:44]))) {
		return treeIntegrity(operationUpdate, nil)
	}
	return nil
}

// inputV1 searches all captured P keys, independently of event membership.
func (o *treeRootOldV1) inputV1(op TreeOutpointV1) bool {
	inputs := o.inputs
	i := sort.Search(len(inputs), func(i int) bool { return treeRootOutpointCompareV1(inputs[i], op) >= 0 })
	return i < len(inputs) && inputs[i] == op
}

// createdV1 includes every CREATE in a complete alternating group, minus P.
func (o *treeRootOldV1) createdV1(op TreeOutpointV1) bool {
	group := o.groupV1(op)
	if group == nil || o.inputV1(op) {
		return false
	}
	return group.kind == treeCreateV1 || group.last > group.group
}

// groupV1 finds the first complete descriptor for this identity and sequence.
func (o *treeRootOldV1) groupV1(op TreeOutpointV1) *treeDescV1 {
	want := treeDescV1{txid: op.Txid, vout: op.Vout}
	// finishV1 sorts by identity then sequence. Zero is the minimum sequence;
	// >= also keeps an exact sequence-zero match despite the comparator's +1.
	i := sort.Search(len(o.rec.descs), func(i int) bool { return treeCompareDescV1(o.rec.descs[i], want) >= 0 })
	if i < len(o.rec.descs) && treeSameKeyV1(&want, &o.rec.descs[i]) {
		return &o.rec.descs[i]
	}
	return nil
}

// treeRootOutpointV1 decodes raw Txid/u32be routing bytes without retaining them.
func treeRootOutpointV1(key [36]byte) TreeOutpointV1 {
	return TreeOutpointV1{Txid: [32]byte(key[:32]), Vout: binary.BigEndian.Uint32(key[32:])}
}

// treeRootRoutingV1 forms CSM routing bytes in fixed local storage.
func treeRootRoutingV1(op TreeOutpointV1) (key [36]byte) {
	copy(key[:32], op.Txid[:])
	binary.BigEndian.PutUint32(key[32:], op.Vout)
	return key
}

func (o *treeRootOldV1) nextV1(DBI, []byte) ([]byte, treeImageV1, bool, error) {
	return nil, treeImageV1{}, false, treeDeltaInvalidV1()
}

// The genesis resolver has no Reader, transaction or parent identity to query.
type treeEmptyOldV1 struct{}

func (treeEmptyOldV1) getV1(DBI, []byte) (treeImageV1, error) {
	return treeImageV1{}, nil
}

func (treeEmptyOldV1) nextV1(DBI, []byte) ([]byte, treeImageV1, bool, error) {
	return nil, treeImageV1{}, false, treeDeltaInvalidV1()
}
