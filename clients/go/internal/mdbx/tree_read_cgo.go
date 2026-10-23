//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

// TreeResolvedInputV1 borrows one exact original present R suffix. The caller
// retains its immutable backing under the same account through DeriveTreeRootV1.
type TreeResolvedInputV1 struct {
	Outpoint TreeOutpointV1
	Value    []byte
}

// TreeRootReadV1 binds one fresh noncommitting derivation to its selected parent.
// Primitive is forward, DirectApply, UndoTransient and covered by a complete
// current initial148 body. Inputs contain no caller-computed root or node hash.
type TreeRootReadV1 struct {
	Primitive TreePrimitiveV1
	Parent    TreeEndpointV1
	Inputs    []TreeResolvedInputV1
}

// DeriveTreeRootV1 borrows this live tree Reader and account synchronously. It
// opens no transaction, emits no mutation and returns no digest on failure.
// Parent rows are point-only; at height zero the parent is definitionally empty.
func (r *Reader) DeriveTreeRootV1(account *OperationAccount, request TreeRootReadV1) (root [32]byte, err error) {
	if err := r.treeRootReadInputV1(account, request); err != nil {
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

func (r *Reader) treeRootReadInputV1(account *OperationAccount, request TreeRootReadV1) error {
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

func treeRootReadInputsV1(inputs []TreeResolvedInputV1) error {
	for i, input := range inputs {
		if !treeUTXOValueOKV1(input.Value) {
			return treeDeltaInvalidV1()
		}
		for _, previous := range inputs[:i] {
			if previous.Outpoint == input.Outpoint {
				return treeDeltaInvalidV1()
			}
		}
	}
	return nil
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
	var old treeOldV1 = &treeRootOldV1{reader: r, request: request, rec: rec, observation: &observation, remaining: 577*uint64(rec.eventCount) + 1}
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
	request     TreeRootReadV1
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
		return len(key) == 9 && key[0] == 0x11 && binary.BigEndian.Uint64(key[1:]) == o.request.Primitive.Generation
	}
	return (dbi.Rank == 1 || dbi.Rank == 8) && binary.BigEndian.Uint64(key[:8]) == o.request.Primitive.Generation
}

func (o *treeRootOldV1) checkV1(dbi DBI, key []byte, image treeImageV1) error {
	if dbi.Rank == 0 {
		return o.bindingV1(key, image)
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
	if err == nil && (binding.Endpoint != o.request.Parent || binding.DatabaseID != o.reader.databaseID) {
		return treeObserveV1(treeIntegrity(operationUpdate, nil), o.observation, 0, key, TreeObservationIdentityMismatchV1, image, true)
	}
	return nil
}

func (o *treeRootOldV1) originalV1(key []byte, image treeImageV1) error {
	var op TreeOutpointV1
	copy(op.Txid[:], key[8:40])
	op.Vout = binary.BigEndian.Uint32(key[40:])
	for _, input := range o.request.Inputs {
		if input.Outpoint == op {
			if !image.present || !bytes.Equal(image.value, input.Value) {
				return treeIntegrity(operationUpdate, nil)
			}
			return nil
		}
	}
	want := treeDescV1{txid: op.Txid, vout: op.Vout}
	for i := range o.rec.descs {
		event := &o.rec.descs[i]
		if treeSameKeyV1(&want, event) && event.flags&treeDescOldV1 != 0 {
			return treeIntegrity(operationUpdate, nil)
		}
	}
	return nil
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
