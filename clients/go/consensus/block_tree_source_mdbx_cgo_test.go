//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"unsafe"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// The independent wire builder retains the core boundary and output frames at
// construction time. Expected identifiers never call the cursor or ParseTx.
type btTx struct {
	raw, core []byte
	id        [32]byte
	frames    [][]byte
}

func btCompact(n uint64) []byte {
	switch {
	case n < 253:
		return []byte{byte(n)}
	case n <= 65535:
		return binary.LittleEndian.AppendUint16([]byte{253}, uint16(n))
	case n <= math.MaxUint32:
		return binary.LittleEndian.AppendUint32([]byte{254}, uint32(n))
	default:
		return binary.LittleEndian.AppendUint64([]byte{255}, n)
	}
}

func btFrame(value uint64, kind uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint64(nil, value)
	b = binary.LittleEndian.AppendUint16(b, kind)
	b = append(b, btCompact(uint64(len(data)))...)
	return append(b, data...)
}

func btTransaction(nonce uint64, kind byte, inputs []Outpoint, frames [][]byte, signature, witness, payload []byte) btTx {
	b := binary.LittleEndian.AppendUint32(nil, 1)
	b = append(b, kind)
	b = binary.LittleEndian.AppendUint64(b, nonce)
	b = append(b, btCompact(uint64(len(inputs)))...)
	for _, input := range inputs {
		b = append(b, input.Txid[:]...)
		b = binary.LittleEndian.AppendUint32(b, input.Vout)
		b = append(b, 0) // empty scriptSig
		b = binary.LittleEndian.AppendUint32(b, 0xffffffff)
	}
	b = append(b, btCompact(uint64(len(frames)))...)
	for _, frame := range frames {
		b = append(b, frame...)
	}
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = append(b, btDaCore(kind, signature)...)
	tx := btTx{core: bytes.Clone(b), id: sha3.Sum256(b), frames: frames}
	b = append(b, witness...)
	b = append(b, btCompact(uint64(len(payload)))...)
	tx.raw = append(b, payload...)
	return tx
}

func btDaCore(kind byte, signature []byte) []byte {
	switch kind {
	case 1:
		b := bytes.Repeat([]byte{0x41}, 32)
		b = append(b, 1, 0)
		b = append(b, bytes.Repeat([]byte{0x42}, 32+8+32+32+32)...)
		b = append(b, 0x7f)
		b = append(b, btCompact(uint64(len(signature)))...)
		return append(b, signature...)
	case 2:
		b := bytes.Repeat([]byte{0x51}, 32)
		b = append(b, 1, 0)
		return append(b, bytes.Repeat([]byte{0x52}, 32)...)
	}
	return nil
}

func btBody(width int, salt byte, parent [32]byte, txs ...btTx) []byte {
	b := make([]byte, 0, width)
	b = append(b, make([]byte, width)...)
	b[0], b[width-1] = 1, salt
	copy(b[4:36], parent[:])
	b = append(b, btCompact(uint64(len(txs)))...)
	for _, tx := range txs {
		b = append(b, tx.raw...)
	}
	return b
}

func btRequest(raw []byte, height uint64) blockTreeRequestV1 {
	block := sha3.Sum256(raw[:148])
	return blockTreeRequestV1{
		DatabaseID: [32]byte{7}, Generation: 1, Block: block, Height: height,
		HeaderBytes: 148, BodyKind: 1, Raw: raw, Generated: &Uint128{}, Direction: 1, Kind: 2, Undo: 1,
		Endpoint: mdbx.TreeEndpointV1{Kind: 1, Height: height, BlockHash: block, CumulativeChainwork: [40]byte{39: 99}},
	}
}

type btResult struct {
	truth mdbx.CommitTruth
	stage mdbx.UpdateStage
	index int
	err   error
}

func (r btResult) want(t *testing.T, truth, stage uint8, index int) {
	t.Helper()
	if uint8(r.truth) != truth || uint8(r.stage) != stage || r.index != index {
		t.Fatalf("native result = (%d,%d,%d,%v), want (%d,%d,%d)", r.truth, r.stage, r.index, r.err, truth, stage, index)
	}
}

type btWorld struct {
	s     *mdbx.Store
	owner *mdbx.OperationReservationOwner
	path  string
	cfg   mdbx.ConfigV1
}

func btNew(t *testing.T) *btWorld {
	t.Helper()
	w := &btWorld{path: filepath.Join(t.TempDir(), "tree"), cfg: mdbx.ConfigV1{Lower: 1 << 20, Now: 2 << 20, Upper: 256 << 20, Growth: 1 << 20, Shrink: 2 << 20, PageSize: 4096, MaxReaders: 492}}
	var err error
	w.s, err = mdbx.CreateTreeV1(w.path, w.cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "CreateTreeV1: %v", err)
	w.owner, err = mdbx.NewOperationReservationOwner(805306368)
	logicalMDBXAssert(t, err == nil, "reservation owner: %v", err)
	t.Cleanup(func() { _ = w.s.Close() })
	root := mdbx.RootBindingV1{
		DatabaseID: [32]byte{7}, CommitmentVersion: 1,
		RootDigest: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")), Assurance: mdbx.TreeAssuranceV1{Kind: 1},
	}
	encoded, err := root.Encode()
	logicalMDBXAssert(t, err == nil, "empty binding: %v", err)
	authority, err := (mdbx.TreeAuthorityV1{Authority: mdbx.StorageAuthorityV1{Version: 1, ActiveProfile: 1, ActiveGenerationID: 1, NextGenerationID: 5, Phase: 1, Lifecycle: 1}, LagGenerationID: 2}).Encode()
	logicalMDBXAssert(t, err == nil, "authority: %v", err)
	w.pair(t, btMutation(0, []byte{2}, authority), btMutation(0, btMeta(0x10, 1), make([]byte, 16)), btMutation(0, btMeta(0x10, 2), make([]byte, 16)), btMutation(0, btMeta(0x11, 1), encoded), btMutation(0, btMeta(0x11, 2), encoded))
	return w
}

func btMeta(tag byte, generation uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte{tag}, generation)
}

func btMutation(rank int, key, value []byte) mdbx.Mutation {
	return mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[rank], Key: key, AfterKind: 2, Literal: value}
}

func btSort(rows []mdbx.Mutation) {
	slices.SortFunc(rows, func(a, b mdbx.Mutation) int {
		if a.DBI.Rank != b.DBI.Rank {
			return int(a.DBI.Rank) - int(b.DBI.Rank)
		}
		return bytes.Compare(a.Key, b.Key)
	})
}

func (w *btWorld) pair(t *testing.T, rows ...mdbx.Mutation) {
	t.Helper()
	btSort(rows)
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		truth, stage, index, err := w.s.UpdateTreeV1(a, func(*mdbx.Reader) (mdbx.TreeOperationV1, error) {
			return mdbx.TreeOperationV1{Pair: mdbx.TreePairV1{Mutations: rows}}, nil
		})
		logicalMDBXAssert(t, err == nil && truth == 2 && stage == 3 && index == -1, "seed Pair: %d/%d/%d/%v", truth, stage, index, err)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "seed account: %v", err)
}

// The real native operation owns all counts, undo, counters and tree effects.
// Observation wrappers below delegate the complete source unchanged.
type btObserved struct {
	t      *testing.T
	source *blockTreeSourceV1
	calls  [3]int
	reader *mdbx.Reader
	sink   *mdbx.TreeDeltaSinkV1
	before func(mdbx.TreePositionV1, *mdbx.Reader, *mdbx.TreeDeltaSinkV1) error
}

func (o *btObserved) TreeDeltaV1(p mdbx.TreePositionV1, r *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
	logicalMDBXAssert(o.t, len(sink.WindowV1()) == 65536, "native source window length %d", len(sink.WindowV1()))
	o.calls[p]++
	o.reader, o.sink = r, sink
	if o.before != nil {
		if err := o.before(p, r, sink); err != nil {
			return err
		}
	}
	return o.source.TreeDeltaV1(p, r, sink)
}

func (w *btWorld) run(t *testing.T, requests []blockTreeRequestV1, edit func([]blockTreeEffectV1, []*btObserved, *mdbx.TreeOperationV1)) (btResult, []blockTreeEffectV1, []*btObserved) {
	t.Helper()
	var result btResult
	var effects []blockTreeEffectV1
	var observed []*btObserved
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(2<<20, func() error {
			effects, observed = make([]blockTreeEffectV1, len(requests)), make([]*btObserved, len(requests))
			result.truth, result.stage, result.index, result.err = w.s.UpdateTreeV1(a, func(r *mdbx.Reader) (mdbx.TreeOperationV1, error) {
				var op mdbx.TreeOperationV1
				for i, request := range requests {
					request.Raw = bytes.Clone(request.Raw)
					if request.Raw != nil && request.HeaderBytes == 148 {
						_, present, readErr := r.Get(mdbx.TreeSchemaV1DBIs()[3], request.Block[:])
						if readErr != nil {
							return mdbx.TreeOperationV1{}, readErr
						}
						if !present {
							op.Pair.Mutations = append(op.Pair.Mutations, btMutation(3, bytes.Clone(request.Block[:]), bytes.Clone(request.Raw[:148])))
						}
					}
					source := new(blockTreeSourceV1)
					effect, prepareErr := prepareBlockTreeEffectV1(source, r, a, request)
					if prepareErr != nil {
						return mdbx.TreeOperationV1{}, prepareErr
					}
					effects[i] = effect
					observed[i] = &btObserved{t: t, source: source}
					op.Primitives = append(op.Primitives, effect.Primitive)
					op.Primitives[i].Source = observed[i]
					op.Pair.Mutations = append(op.Pair.Mutations, effect.Index[:]...)
					if effect.CurrentBody.AfterKind != 0 {
						op.Pair.Mutations = append(op.Pair.Mutations, effect.CurrentBody)
					}
				}
				btSort(op.Pair.Mutations)
				if edit != nil {
					edit(effects, observed, &op)
				}
				return op, nil
			})
			return nil
		})
	})
	logicalMDBXAssert(t, err == nil, "test account: %v", err)
	btReservationsReleased(t, w.owner)
	return result, effects, observed
}

func btReservationsReleased(t *testing.T, owner *mdbx.OperationReservationOwner) {
	t.Helper()
	entered := false
	// Both TreeOperation grants stay live together, covering 805306368 bytes.
	err := owner.WithOperation(mdbx.TreeOperation, func(first *mdbx.OperationAccount) error {
		return first.WithReservation(402653184, func() error {
			return owner.WithOperation(mdbx.TreeOperation, func(second *mdbx.OperationAccount) error {
				return second.WithReservation(402653184, func() error {
					entered = true
					return nil
				})
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "operation leaked a reservation: %v", err)
	logicalMDBXAssert(t, entered, "full aggregate reservation callback did not run")
}

func (w *btWorld) read(t *testing.T, rank int, key, want []byte) {
	t.Helper()
	err := w.s.View(func(r *mdbx.Reader) error {
		value, present, err := r.Get(mdbx.TreeSchemaV1DBIs()[rank], key)
		logicalMDBXAssert(t, err == nil && present == (want != nil) && bytes.Equal(value, want), "rank%d key%x = %x/%t/%v, want %x", rank, key, value, present, err, want)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "read: %v", err)
}

func (w *btWorld) reopen(t *testing.T) {
	t.Helper()
	previous := w.s.View(func(*mdbx.Reader) error { return nil })
	closeErr := w.s.Close()
	logicalMDBXAssert(t, reflect.ValueOf(closeErr).Equal(reflect.ValueOf(previous)), "close before reopen: %v, cached %v", closeErr, previous)
	var err error
	w.s, err = mdbx.OpenTreeV1(w.path, w.cfg, [32]byte{7})
	logicalMDBXAssert(t, err == nil, "OpenTreeV1: %v", err)
}

func btFailure(t *testing.T, err error, kind logicalStateFailureKind, message string) {
	t.Helper()
	var f *logicalStateFailure
	ok := errors.As(err, &f)
	logicalMDBXAssert(t, ok && f != nil && reflect.ValueOf(err).Equal(reflect.ValueOf(f)) && f.kind == kind && f.cause != nil && f.cause.Error() == message && f.Error() == message, "source error = %T %v, want %d/%q", err, err, kind, message)
}

func btPrepare(t *testing.T, w *btWorld, request blockTreeRequestV1) (*blockTreeSourceV1, blockTreeEffectV1, error) {
	t.Helper()
	var source blockTreeSourceV1
	var effect blockTreeEffectV1
	var result error
	err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
		return a.WithReservation(1<<20, func() error {
			request.Raw = bytes.Clone(request.Raw)
			return w.s.View(func(r *mdbx.Reader) error {
				effect, result = prepareBlockTreeEffectV1(&source, r, a, request)
				if result == nil && request.Raw != nil {
					logicalMDBXAssert(t, &source.Raw[0] == &request.Raw[0], "producer copied the charged borrowed body")
				}
				return nil
			})
		})
	})
	logicalMDBXAssert(t, err == nil, "prepare setup: %v", err)
	return &source, effect, result
}

func TestBlockTreeSourceV1(t *testing.T) {
	t.Run("shape", btShape)
	t.Run("compact", btCompactCases)
	t.Run("framing", btFraming)
	t.Run("syntax-limits", btSyntaxLimits)
	t.Run("compact-owners", btCompactOwners)
	t.Run("complete-span-truncation", btSpanTruncation)
	t.Run("count-charge", btCountCharge)
	t.Run("layout", btLayout)
	t.Run("captured-fields", btCaptured)
}

func btShape(t *testing.T) {
	valid := btRequest(btBody(148, 1, [32]byte{}, btTransaction(1, 0, nil, nil, nil, []byte{0}, nil)), 1)
	rows := []struct {
		name string
		edit func(*blockTreeRequestV1)
	}{
		{"generation0", func(r *blockTreeRequestV1) { r.Generation = 0 }},
		{"Generatednil", func(r *blockTreeRequestV1) { r.Generated = nil }},
		{"width0", func(r *blockTreeRequestV1) { r.HeaderBytes = 0 }},
		{"width117", func(r *blockTreeRequestV1) { r.HeaderBytes = 117 }},
		{"kind0", func(r *blockTreeRequestV1) { r.BodyKind = 0 }},
		{"kind3", func(r *blockTreeRequestV1) { r.BodyKind = 3 }},
		{"kind1nil", func(r *blockTreeRequestV1) { r.Raw = nil }},
		{"kind1empty", func(r *blockTreeRequestV1) { r.Raw = []byte{} }},
		{"kind2extra", func(r *blockTreeRequestV1) { r.BodyKind = 2 }},
		{"kind2empty", func(r *blockTreeRequestV1) { r.BodyKind = 2; r.Raw = []byte{} }},
		{"invalid-tag-payload", func(r *blockTreeRequestV1) { r.BodyKind = 255; r.Raw = nil }},
	}
	w := btNew(t)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			r := valid
			row.edit(&r)
			source, effect, err := btPrepare(t, w, r)
			btFailure(t, err, logicalStateFailureLocalInvariant, "invalid block tree source request")
			logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero() && reflect.ValueOf(*source).IsZero(), "failure published a source/effect")
		})
	}
	for _, row := range []string{"dst", "reader", "account"} {
		t.Run("nil-"+row, func(t *testing.T) {
			dst, reader, account := &blockTreeSourceV1{}, &mdbx.Reader{}, &mdbx.OperationAccount{}
			switch row {
			case "dst":
				dst = nil
			case "reader":
				reader = nil
			case "account":
				account = nil
			}
			effect, err := prepareBlockTreeEffectV1(dst, reader, account, valid)
			btFailure(t, err, logicalStateFailureLocalInvariant, "invalid block tree source request")
			logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero(), "nil required field published effect")
		})
	}
	for _, p := range []mdbx.TreePositionV1{0, 3, 255} {
		btFailure(t, (&blockTreeSourceV1{}).TreeDeltaV1(p, nil, nil), logicalStateFailureLocalInvariant, "invalid block tree source position")
	}
	for _, s := range []*blockTreeSourceV1{nil, {}} {
		btFailure(t, s.TreeDeltaV1(1, nil, nil), logicalStateFailureLocalInvariant, "invalid block tree source request")
	}
	zero := &mdbx.OperationAccount{}
	expected := zero.WithReservation(1, func() error { t.Fatal("zero account callback"); return nil })
	effect, err := prepareBlockTreeEffectV1(&blockTreeSourceV1{}, &mdbx.Reader{}, zero, valid)
	logicalMDBXAssert(t, reflect.ValueOf(err).Equal(reflect.ValueOf(expected)) && reflect.ValueOf(effect).IsZero(), "account refusal wrapped: %v", err)
}

func btCompactCases(t *testing.T) {
	for _, n := range []uint64{0, 1, 252, 253, 65535, 65536, math.MaxUint32, 4294967296, math.MaxUint64} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			raw := btCompact(n)
			c := blockTreeCursorV1{raw: raw, length: uint64(len(raw)), source: &blockTreeSourceV1{}}
			got := c.compactV1(math.MaxUint64)
			logicalMDBXAssert(t, got == n && c.err == nil && c.off == uint64(len(raw)), "CompactSize %x = %d/%d/%v", raw, got, c.off, c.err)
		})
	}
	for _, raw := range [][]byte{{}, {253}, {253, 252, 0}, {254, 255, 255, 0, 0}, {255, 255, 255, 255, 255, 0, 0, 0, 0}, {255, 0}, {254, 0, 0, 1}} {
		c := blockTreeCursorV1{raw: raw, length: uint64(len(raw)), source: &blockTreeSourceV1{}}
		c.compactV1(math.MaxUint64)
		btFailure(t, c.err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
	}
	c := blockTreeCursorV1{raw: []byte{2}, length: 1, source: &blockTreeSourceV1{}}
	c.compactV1(1)
	btFailure(t, c.err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
	for _, offset := range []uint64{1, math.MaxUint64} {
		c := blockTreeCursorV1{raw: []byte{0}, length: 1, off: offset, source: &blockTreeSourceV1{}}
		c.skipV1(math.MaxUint64)
		btFailure(t, c.err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
	}
}

func btFraming(t *testing.T) {
	w := btNew(t)
	frames := [][]byte{btFrame(7, 0, nil), btFrame(8, 2, nil), btFrame(9, 0x103, nil), btFrame(10, 0, bytes.Repeat([]byte{3}, 65536))}
	for _, width := range []int{116, 148} {
		for _, kind := range []byte{0, 1, 2} {
			t.Run(fmt.Sprintf("%d/kind%d", width, kind), func(t *testing.T) {
				payload := []byte(nil)
				if kind != 0 {
					payload = bytes.Repeat([]byte{0x55}, 1025)
				}
				tx := btTransaction(1, kind, []Outpoint{{Txid: [32]byte{8}}}, frames, bytes.Repeat([]byte{0x56}, 253), []byte{1, 0x7f, 1, 3, 2, 4, 5}, payload)
				second := btTransaction(2, 0, []Outpoint{{Txid: [32]byte{6}}, {Txid: [32]byte{7}}}, nil, nil, []byte{0}, nil)
				raw := btBody(width, 5, [32]byte{4}, tx, second)
				r := btRequest(btBody(148, 5, [32]byte{}, tx), 5)
				r.Raw, r.HeaderBytes = raw, uint16(width)
				r.Block = sha3.Sum256(raw[:width])
				r.Endpoint.BlockHash = r.Block
				source, effect, err := btPrepare(t, w, r)
				logicalMDBXAssert(t, err == nil && source.coverage.BlockMeta.TxCount == 2 && source.coverage.BlockMeta.EventCount == 4, "frame/count %d/%d: %+v %v", width, kind, source.coverage, err)
				logicalMDBXAssert(t, bytes.Equal(source.Raw, raw) && &effect.CurrentBody.Literal[0] == &source.Raw[0] && &source.coverage.CurrentBody[0] == &source.Raw[0], "body backing copied")
			})
		}
	}
	tx := btTransaction(1, 0, []Outpoint{{}}, [][]byte{btFrame(1, 0, nil)}, nil, []byte{0}, nil)
	valid := btBody(148, 7, [32]byte{}, tx)
	for end := range len(valid) {
		r := btRequest(valid, 1)
		r.Raw = valid[:end]
		_, _, err := btPrepare(t, w, r)
		if end == 0 {
			btFailure(t, err, logicalStateFailureLocalInvariant, "invalid block tree source request")
			continue
		}
		btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
	}
	for _, row := range []struct {
		name string
		raw  []byte
	}{
		{"trailing", append(bytes.Clone(valid), 0)},
		{"tx-count0", append(bytes.Clone(valid[:148]), 0)},
		{"tx-count-nonminimal", append(append(bytes.Clone(valid[:148]), 253, 1, 0), tx.raw...)},
		{"tx-kind3", btBody(148, 7, [32]byte{}, btTransaction(1, 3, nil, nil, nil, []byte{0}, nil))},
		{"version", append(bytes.Clone(valid[:149]), append([]byte{2}, valid[150:]...)...)},
		{"payload-kind0", btBody(148, 7, [32]byte{}, btTransaction(1, 0, nil, nil, nil, []byte{0}, []byte{1}))},
		{"payload-kind2-empty", btBody(148, 7, [32]byte{}, btTransaction(1, 2, nil, nil, nil, []byte{0}, nil))},
		{"script-overflow", append(append(bytes.Clone(valid[:199]), 33), valid[200:]...)},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := btRequest(valid, 1)
			r.Raw = row.raw
			source, effect, err := btPrepare(t, w, r)
			btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
			logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero() && reflect.ValueOf(*source).IsZero(), "malformed body published effect")
		})
	}
}

func btCountCharge(t *testing.T) {
	w := btNew(t)
	r := btRequest(btBody(148, 1, [32]byte{}, btTransaction(1, 0, nil, nil, nil, []byte{0}, nil)), 1)
	for _, remaining := range []uint64{4823, 4824} {
		err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
			return a.WithReservation(402653184-remaining, func() error {
				request := r
				request.Raw = bytes.Clone(r.Raw)
				return w.s.View(func(reader *mdbx.Reader) error {
					var source blockTreeSourceV1
					effect, prepareErr := prepareBlockTreeEffectV1(&source, reader, a, request)
					if remaining == 4823 {
						logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(prepareErr) && reflect.ValueOf(effect).IsZero() && reflect.ValueOf(source).IsZero(), "below preparation grant: %v", prepareErr)
					} else {
						logicalMDBXAssert(t, prepareErr == nil && effect.Primitive.Coverage.BlockMeta.TxCount == 1, "exact preparation grant: %v", prepareErr)
					}
					logicalMDBXAssert(t, a.WithReservation(remaining, func() error { return nil }) == nil, "preparation grant not released exactly")
					logicalMDBXAssert(t, mdbx.IsOperationReservationCapacity(a.WithReservation(remaining+1, func() error { return nil })), "enclosing grant changed")
					return nil
				})
			})
		})
		logicalMDBXAssert(t, err == nil, "charge scenario: %v", err)
	}
}

type btSyntaxCase struct {
	name  string
	tx    btTx
	valid bool
}

func btSyntaxLimits(t *testing.T) {
	w := btNew(t)
	for _, row := range append(btCountLimitCases(), btDaLimitCases()...) {
		t.Run(row.name, func(t *testing.T) {
			r := btRequest(btBody(148, 1, [32]byte{}, row.tx), 1)
			_, effect, err := btPrepare(t, w, r)
			if row.valid {
				logicalMDBXAssert(t, err == nil && effect.Primitive.Coverage.BlockMeta.TxCount == 1, "admitted syntax: %v", err)
				return
			}
			btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
			logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero(), "invalid syntax published effect")
		})
	}
	base := btTransaction(1, 0, nil, nil, nil, []byte{0}, nil)
	for _, count := range []uint64{0, 2, 4294967296} {
		raw := btBody(148, 1, [32]byte{})
		raw = append(raw[:148], btCompact(count)...)
		raw = append(raw, base.raw...)
		if count == 2 {
			second := btTransaction(2, 0, nil, nil, nil, []byte{0}, nil)
			raw = append(raw, second.raw...)
		}
		r := btRequest(raw, 0)
		r.Kind = 4
		_, effect, err := btPrepare(t, w, r)
		btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
		logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero(), "invalid genesis syntax published effect")
	}
}

func btCountLimitCases() []btSyntaxCase {
	inputs := make([]Outpoint, 1025)
	outputs := make([][]byte, 1025)
	for i := range outputs {
		outputs[i] = btFrame(1, 0, nil)
	}
	witness := append(btCompact(1024), make([]byte, 3*1024)...)
	rows := []btSyntaxCase{
		{"inputs1024", btTransaction(1, 0, inputs[:1024], nil, nil, []byte{0}, nil), true},
		{"outputs1024", btTransaction(1, 0, nil, outputs[:1024], nil, []byte{0}, nil), true},
		{"witness1024", btTransaction(1, 0, nil, nil, nil, witness, nil), true},
		{"covenant65537", btTransaction(1, 0, nil, [][]byte{btFrame(1, 0, make([]byte, 65537))}, nil, []byte{0}, nil), false},
		{"inputs1025", btTransaction(1, 0, inputs, nil, nil, []byte{0}, nil), false},
		{"outputs1025", btTransaction(1, 0, nil, outputs, nil, []byte{0}, nil), false},
		{"witness1025", btTransaction(1, 0, nil, nil, nil, append(btCompact(1025), make([]byte, 3*1025)...), nil), false},
	}
	for _, size := range []int{99992, 99993} {
		witness := []byte{1, 0x7f, 0}
		witness = append(witness, btCompact(uint64(size))...)
		witness = append(witness, make([]byte, size)...)
		rows = append(rows, btSyntaxCase{fmt.Sprintf("witness-bytes%d", size+8), btTransaction(1, 0, nil, nil, nil, witness, nil), size == 99992})
	}
	for _, size := range []int{32, 33} {
		tx := btTransaction(1, 0, []Outpoint{{}}, nil, nil, []byte{0}, nil)
		raw := append(bytes.Clone(tx.raw[:50]), byte(size))
		raw = append(raw, make([]byte, size)...)
		tx.raw = append(raw, tx.raw[51:]...)
		rows = append(rows, btSyntaxCase{fmt.Sprintf("script%d", size), tx, size == 32})
	}
	return rows
}

func btCompactOwners(t *testing.T) {
	w := btNew(t)
	base := btTransaction(1, 0, nil, nil, nil, []byte{0}, nil)
	input := btTransaction(1, 0, []Outpoint{{}}, nil, nil, []byte{0}, nil)
	output := btTransaction(1, 0, nil, [][]byte{btFrame(1, 0, nil)}, nil, []byte{0}, nil)
	da := btTransaction(1, 1, nil, nil, nil, []byte{0}, nil)
	witness := btTransaction(1, 0, nil, nil, nil, []byte{1, 0, 0, 0}, nil)
	for _, row := range []struct {
		name   string
		tx     btTx
		offset int
	}{
		{"input-count", base, 13},
		{"output-count", base, 14},
		{"script-len", input, 50},
		{"covenant-len", output, 25},
		{"batchsig-len", da, 190},
		{"witness-count", base, 19},
		{"pubkey-len", witness, 21},
		{"signature-len", witness, 22},
		{"payload-len", base, 20},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := btRequest(btBody(148, 1, [32]byte{}, row.tx), 1)
			_, _, controlErr := btPrepare(t, w, r)
			logicalMDBXAssert(t, controlErr == nil, "nearest valid owner: %v", controlErr)
			tx := row.tx
			tx.raw = append(bytes.Clone(tx.raw[:row.offset]), 253, tx.raw[row.offset], 0)
			tx.raw = append(tx.raw, row.tx.raw[row.offset+1:]...)
			r.Raw = btBody(148, 1, [32]byte{}, tx)
			_, _, err := btPrepare(t, w, r)
			btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
		})
	}
	txs := make([]btTx, 253)
	for i := range txs {
		txs[i] = base
	}
	r := btRequest(btBody(148, 1, [32]byte{}, txs...), 1)
	_, effect, err := btPrepare(t, w, r)
	logicalMDBXAssert(t, err == nil && effect.Primitive.Coverage.BlockMeta.TxCount == 253 && effect.Primitive.Coverage.BlockMeta.EventCount == 0, "3-byte tx_count: %v", err)
}

func btSpanTruncation(t *testing.T) {
	w := btNew(t)
	for _, kind := range []byte{0, 1, 2} {
		payload := []byte(nil)
		if kind != 0 {
			payload = []byte{1, 2, 3, 4, 5, 6, 7}
		}
		tx := btTransaction(1, kind, []Outpoint{{Txid: [32]byte{3}}}, [][]byte{btFrame(4, 0, []byte{5, 6, 7, 8, 9})}, []byte{1, 2, 3}, []byte{1, 0x7f, 1, 9, 2, 8, 7}, payload)
		r := btRequest(btBody(148, 1, [32]byte{}, tx), 1)
		_, _, err := btPrepare(t, w, r)
		logicalMDBXAssert(t, err == nil, "complete kind%d control: %v", kind, err)
		complete := r.Raw
		for end := 162; end < len(complete); end++ {
			r.Raw = complete[:end]
			_, effect, err := btPrepare(t, w, r)
			btFailure(t, err, logicalStateFailureLocalInvariant, "qualified block tree source framing differs")
			logicalMDBXAssert(t, reflect.ValueOf(effect).IsZero(), "kind%d truncated at%d published effect", kind, end)
		}
	}
}

func btDaLimitCases() []btSyntaxCase {
	rows := []btSyntaxCase{}
	for _, size := range []int{65536, 65537} {
		rows = append(rows, btSyntaxCase{fmt.Sprintf("batchsig%d", size), btTransaction(1, 1, nil, nil, make([]byte, size), []byte{0}, nil), size == 65536})
		rows = append(rows, btSyntaxCase{fmt.Sprintf("manifest-payload%d", size), btTransaction(1, 1, nil, nil, nil, []byte{0}, make([]byte, size)), size == 65536})
	}
	for _, size := range []int{0, 1, 524288, 524289} {
		rows = append(rows, btSyntaxCase{fmt.Sprintf("chunk-payload%d", size), btTransaction(1, 2, nil, nil, nil, []byte{0}, make([]byte, size)), size == 1 || size == 524288})
	}
	for _, kind := range []byte{1, 2} {
		for _, count := range []uint16{0, 60, 61, 62} {
			tx := btTransaction(1, kind, nil, nil, nil, []byte{0}, []byte{1})
			// zero inputs/outputs give core offset19; da_id is32 bytes.
			binary.LittleEndian.PutUint16(tx.raw[51:53], count)
			valid := count != 0 && count <= 61
			if kind == 2 {
				valid = count < 61
			}
			rows = append(rows, btSyntaxCase{fmt.Sprintf("kind%d/chunk%d", kind, count), tx, valid})
		}
	}
	return rows
}

func btLayout(t *testing.T) {
	// Includes two simultaneous output/forward cursors, one reused SHA3 state,
	// count window and local source/request/effect/scalars, plus spare stack cells.
	fixed := 2*unsafe.Sizeof(blockTreeCursorV1{}) + 2*unsafe.Sizeof(sha3.SHA3{}) + 1024 + unsafe.Sizeof(blockTreeSourceV1{}) + unsafe.Sizeof(blockTreeRequestV1{}) + unsafe.Sizeof(blockTreeEffectV1{}) + 256
	logicalMDBXAssert(t, fixed <= 4096, "fixed source/control live layout = %d > 4096", fixed)
}

func btCaptured(t *testing.T) {
	w := btNew(t)
	r := btCapturedRequest()
	want := r
	wantGenerated := *r.Generated
	source, effect, err := btPrepare(t, w, r)
	logicalMDBXAssert(t, err == nil, "captured prepare: %v", err)
	r.Generated.Hi, r.Generated.Lo = 0, 0
	r.DatabaseID, r.Block, r.Generation, r.Height, r.Raw = [32]byte{}, [32]byte{}, 0, 0, nil
	c := source.coverage
	logicalMDBXAssert(t, c.DatabaseID == want.DatabaseID && c.Generation == want.Generation && c.Block == want.Block && c.Height == want.Height && c.HeaderBytes == 148 && c.BodyKind == 1 && c.BlockMeta.TxCount == 1 && c.BlockMeta.EventCount == 1, "captured coverage: %+v", c)
	logicalMDBXAssert(t, c.BlockMeta.Generated == ([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24}), "Generated lost snapshot/order: %x (%+v)", c.BlockMeta.Generated, wantGenerated)
	p := effect.Primitive
	logicalMDBXAssert(t, p.Source == source && p.Coverage == &source.coverage && p.Direction == want.Direction && p.Kind == want.Kind && p.Undo == want.Undo && p.Generation == want.Generation && p.Block == want.Block && p.Height == want.Height && p.Endpoint == want.Endpoint, "captured primitive: %+v", p)
	logicalMDBXAssert(t, bytes.Equal(source.Raw, want.Raw) && &c.CurrentBody[0] == &source.Raw[0] && &effect.CurrentBody.Literal[0] == &source.Raw[0], "borrowed body was not retained")
	zero, refused := prepareBlockTreeEffectV1(source, nil, nil, want)
	btFailure(t, refused, logicalStateFailureLocalInvariant, "invalid block tree source request")
	logicalMDBXAssert(t, reflect.ValueOf(zero).IsZero() && reflect.ValueOf(*source).IsZero(), "failed prepare retained a previously usable destination")
}

func btCapturedRequest() blockTreeRequestV1 {
	tx := btTransaction(8, 0, nil, [][]byte{btFrame(1, 0, nil)}, nil, []byte{0}, nil)
	r := btRequest(btBody(148, 8, [32]byte{2}, tx), 8)
	r.Generated = &Uint128{Hi: 0x0102030405060708, Lo: 0x1112131415161718}
	return r
}

func TestBlockTreeEffectV1(t *testing.T) {
	t.Run("new-body-hash-frames", btNewBody)
	t.Run("spend-cancel-inverse-restore", btRoundTrip)
	t.Run("genesis", btGenesis)
	t.Run("indexes-and-body-admission", btAdmission)
	t.Run("CURRENT-LAG", btCompound)
	t.Run("original-replacement", btReplacement)
}

func btUTXOKey(g uint64, op Outpoint) []byte {
	b := binary.BigEndian.AppendUint64(nil, g)
	b = append(b, op.Txid[:]...)
	return binary.BigEndian.AppendUint32(b, op.Vout)
}

func btValue(frame []byte, height uint64, coinbase bool) []byte {
	b := append(bytes.Clone(frame), make([]byte, 8)...)
	binary.LittleEndian.PutUint64(b[len(frame):], height)
	if coinbase {
		return append(b, 1)
	}
	return append(b, 0)
}

func btManifest(r blockTreeRequestV1, txs, spent uint32) []byte {
	b := binary.BigEndian.AppendUint64([]byte{1}, r.Height)
	b = binary.BigEndian.AppendUint64(b, r.Generated.Hi)
	b = binary.BigEndian.AppendUint64(b, r.Generated.Lo)
	b = binary.BigEndian.AppendUint32(b, txs)
	return binary.BigEndian.AppendUint32(b, spent)
}

func btIndexes(t *testing.T, w *btWorld, r blockTreeRequestV1, present bool) {
	t.Helper()
	canonical := binary.BigEndian.AppendUint64(nil, r.Generation)
	canonical = binary.BigEndian.AppendUint64(canonical, r.Height)
	owner := append(binary.BigEndian.AppendUint64(nil, r.Generation), r.Block[:]...)
	if !present {
		w.read(t, 2, canonical, nil)
		w.read(t, 7, owner, nil)
		return
	}
	value := append(bytes.Clone(r.Block[:]), r.Raw[4:36]...)
	value = append(value, r.Endpoint.CumulativeChainwork[:]...)
	w.read(t, 2, canonical, value)
	w.read(t, 7, owner, binary.BigEndian.AppendUint64(nil, r.Height))
}

func btState(t *testing.T, w *btWorld, generation uint64, endpoint mdbx.TreeEndpointV1, entries map[Outpoint]UtxoEntry) {
	t.Helper()
	var total uint64
	for op, entry := range entries {
		value := btValue(btFrame(entry.Value, entry.CovenantType, entry.CovenantData), entry.CreationHeight, entry.CreatedByCoinbase)
		total += 36 + uint64(len(value))
		w.read(t, 1, btUTXOKey(generation, op), value)
	}
	counter := binary.BigEndian.AppendUint64(nil, total)
	counter = binary.BigEndian.AppendUint64(counter, uint64(len(entries)))
	w.read(t, 0, btMeta(0x10, generation), counter)
	err := w.s.View(func(reader *mdbx.Reader) error {
		value, present, err := reader.Get(mdbx.TreeSchemaV1DBIs()[0], btMeta(0x11, generation))
		logicalMDBXAssert(t, err == nil && present, "root read: %v", err)
		root, decodeErr := mdbx.DecodeRootBindingV1(value)
		logicalMDBXAssert(t, decodeErr == nil && root.Endpoint == endpoint && root.RootDigest == canonicalUTXORoot(entries) && root.DatabaseID == ([32]byte{7}) && root.CommitmentVersion == 1 && root.Assurance.Kind == 1, "complete root: %+v/%v", root, decodeErr)
		btNodes(t, reader, generation, entries, root.Top)
		return nil
	})
	logicalMDBXAssert(t, err == nil, "root View: %v", err)
}

func btEntry(value uint64, kind uint16, data []byte, height uint64, coinbase bool) UtxoEntry {
	return UtxoEntry{Value: value, CovenantType: kind, CovenantData: data, CreationHeight: height, CreatedByCoinbase: coinbase}
}

func btNodes(t *testing.T, reader *mdbx.Reader, generation uint64, entries map[Outpoint]UtxoEntry, top mdbx.TreeTopV1) {
	t.Helper()
	var ordered []Outpoint
	for op := range entries {
		ordered = append(ordered, op)
	}
	slices.SortFunc(ordered, func(a, b Outpoint) int { return bytes.Compare(btUTXOKey(1, a), btUTXOKey(1, b)) })
	var children []mdbx.TreeChildV1
	for _, op := range ordered {
		var key [36]byte
		copy(key[:32], op.Txid[:])
		binary.BigEndian.PutUint32(key[32:], op.Vout)
		id := mdbx.TreeNodeIDV1{Kind: 1, Depth: 288, RoutingKey: key}
		digest := sha3.Sum256(append([]byte("RUBIN_UTXO_TREE_V1\x01"), logicalStateEntryBytes(op, entries[op])...))
		nativeKey := append(binary.BigEndian.AppendUint64(nil, generation), key[:]...)
		nativeKey = append(nativeKey, 0, 0)
		value, present, err := reader.Get(mdbx.TreeSchemaV1DBIs()[8], nativeKey)
		logicalMDBXAssert(t, err == nil && present && bytes.Equal(value, digest[:]), "complete leaf node %x: %x/%t/%v", nativeKey, value, present, err)
		children = append(children, mdbx.TreeChildV1{ID: id, Digest: digest})
	}
	if len(children) == 0 {
		logicalMDBXAssert(t, top.Kind == 0 && top.Node == nil, "empty top")
		return
	}
	if len(children) == 1 {
		logicalMDBXAssert(t, top.Kind == 1 && top.Node != nil && *top.Node == children[0].ID, "leaf top")
		return
	}
	logicalMDBXAssert(t, len(children) == 2, "bounded fixture has %d leaves", len(children))
	depth := canonicalUTXOFirstDifferingBit(children[0].ID.RoutingKey, children[1].ID.RoutingKey)
	prefix := children[0].ID.RoutingKey
	for bit := depth; bit < 288; bit++ {
		prefix[bit/8] &^= 0x80 >> (bit % 8)
	}
	id := mdbx.TreeNodeIDV1{Kind: 2, Depth: depth, Prefix: prefix}
	logicalMDBXAssert(t, top.Kind == 2 && top.Node != nil && *top.Node == id, "branch top")
	nodeKey, err := mdbx.TreeNodeKey(generation, id)
	logicalMDBXAssert(t, err == nil, "branch identity")
	var expected []byte
	for _, child := range children {
		key, keyErr := mdbx.TreeNodeKey(1, child.ID)
		logicalMDBXAssert(t, keyErr == nil, "child identity")
		expected = append(expected, key[8:]...)
		expected = append(expected, child.Digest[:]...)
	}
	value, present, err := reader.Get(mdbx.TreeSchemaV1DBIs()[8], nodeKey)
	logicalMDBXAssert(t, err == nil && present && bytes.Equal(value, expected), "complete branch node %x: %x/%t/%v", nodeKey, value, present, err)
}

func btNewBody(t *testing.T) {
	for _, kind := range []byte{0, 1, 2} {
		for _, length := range []int{0, 1, 252, 253, 65535, 65536} {
			t.Run(fmt.Sprintf("kind%d/length%d", kind, length), func(t *testing.T) {
				w := btNew(t)
				data := bytes.Repeat([]byte{0x4e}, length)
				frames := [][]byte{btFrame(11, 2, nil), btFrame(12, 0, nil), btFrame(13, 0x103, nil), btFrame(14, 0, data)}
				payload := []byte(nil)
				if kind != 0 {
					payload = bytes.Repeat([]byte{0x6c}, 65536)
				}
				tx := btTransaction(3, kind, []Outpoint{{Txid: [32]byte{0xff}, Vout: 19}}, frames, []byte{7, 8, 9}, []byte{1, 0x7f, 1, 3, 2, 4, 5}, payload)
				r := btRequest(btBody(148, byte(length+int(kind)+1), [32]byte{0x31}, tx), 8)
				r.Generated = &Uint128{Hi: 0x0102030405060708, Lo: 0x1112131415161718}
				result, effects, observed := w.run(t, []blockTreeRequestV1{r}, nil)
				result.want(t, 2, 3, -1)
				logicalMDBXAssert(t, result.err == nil, "apply: %v", result.err)
				logicalMDBXAssert(t, effects[0].Primitive.Coverage.BlockMeta.EventCount == 2 && effects[0].Primitive.Coverage.BlockMeta.TxCount == 1 && observed[0].calls == ([3]int{0, 1, 0}), "complete source/count: %+v calls%v", effects[0], observed[0].calls)
				btState(t, w, 1, r.Endpoint, map[Outpoint]UtxoEntry{{Txid: tx.id, Vout: 1}: btEntry(12, 0, nil, 8, true), {Txid: tx.id, Vout: 3}: btEntry(14, 0, data, 8, true)})
				for _, vout := range []uint32{0, 2} {
					w.read(t, 1, btUTXOKey(1, Outpoint{Txid: tx.id, Vout: vout}), nil)
				}
				w.read(t, 4, r.Block[:], r.Raw)
				w.read(t, 5, append(bytes.Clone(r.Block[:]), 0), btManifest(r, 1, 0))
				btIndexes(t, w, r, true)
				logicalMDBXAssert(t, &effects[0].CurrentBody.Literal[0] == &observed[0].source.Raw[0] && &effects[0].Primitive.Coverage.CurrentBody[0] == &observed[0].source.Raw[0], "effect alias differs")
				_, _, expired := observed[0].reader.Get(mdbx.TreeSchemaV1DBIs()[0], []byte{2})
				logicalMDBXAssert(t, expired != nil && observed[0].sink.WindowV1() == nil, "source Reader/window survived")
			})
		}
	}
}

func btRoundTrip(t *testing.T) {
	w := btNew(t)
	seedTx := btTransaction(1, 0, nil, [][]byte{btFrame(20, 0, []byte{1}), btFrame(21, 0, nil)}, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 1, [32]byte{}, seedTx), 1)
	result, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "seed source: %v", result.err)
	op := Outpoint{Txid: seedTx.id}
	op2 := Outpoint{Txid: seedTx.id, Vout: 1}
	coinbase := btTransaction(2, 0, nil, [][]byte{btFrame(30, 0, nil)}, nil, []byte{0}, nil)
	cancel := Outpoint{Txid: coinbase.id}
	spend := btTransaction(3, 0, []Outpoint{op2, op, cancel}, [][]byte{btFrame(40, 0, bytes.Repeat([]byte{5}, 253)), btFrame(41, 0, nil)}, nil, []byte{0}, nil)
	r := btRequest(btBody(148, 2, seed.Block, coinbase, spend), 2)
	r.Generated = &Uint128{Hi: 4, Lo: 0x102030405060708}
	result, forward, _ := w.run(t, []blockTreeRequestV1{r}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "forward source: %v", result.err)
	logicalMDBXAssert(t, forward[0].Primitive.Coverage.BlockMeta.EventCount == 6, "complete SPEND/CREATE count")
	btState(t, w, 1, r.Endpoint, map[Outpoint]UtxoEntry{{Txid: spend.id}: btEntry(40, 0, bytes.Repeat([]byte{5}, 253), 2, false), {Txid: spend.id, Vout: 1}: btEntry(41, 0, nil, 2, false)})
	w.read(t, 1, btUTXOKey(1, op), nil)
	w.read(t, 1, btUTXOKey(1, op2), nil)
	w.read(t, 1, btUTXOKey(1, cancel), nil)
	w.read(t, 5, append(bytes.Clone(r.Block[:]), 0), btManifest(r, 2, 2))
	w.read(t, 5, undoLiteralKey(r.Block, op2, 1, 0), btValue(seedTx.frames[1], 1, true))
	w.read(t, 5, undoLiteralKey(r.Block, op, 1, 1), btValue(seedTx.frames[0], 1, true))
	w.read(t, 5, undoLiteralKey(r.Block, cancel, 1, 2), nil)
	btIndexes(t, w, r, true)
	bad := r
	bad.BodyKind, bad.Raw, bad.Direction, bad.Kind, bad.Undo = 2, nil, 2, 7, 5
	bad.CanonicalBeforePresent, bad.OwnerBeforePresent = true, true
	bad.Endpoint = seed.Endpoint
	bad.Generated = &Uint128{Hi: r.Generated.Hi, Lo: r.Generated.Lo + 1}
	btGeneratedRefusal(t, w, bad, btManifest(r, 2, 2))
	for _, policy := range []struct {
		kind mdbx.TreePrimitiveKindV1
		undo mdbx.TreeUndoEffectV1
	}{{7, 5}, {8, 5}, {9, 5}} {
		inverse := r
		inverse.BodyKind, inverse.Raw = 2, nil
		inverse.Direction, inverse.Kind, inverse.Undo = 2, policy.kind, policy.undo
		inverse.Endpoint = seed.Endpoint
		inverse.CanonicalBeforePresent, inverse.OwnerBeforePresent = true, true
		requests := btInverseRequests(t, w, inverse)
		result, effects, _ := w.run(t, requests, nil)
		result.want(t, 2, 3, -1)
		logicalMDBXAssert(t, result.err == nil && reflect.ValueOf(effects[len(effects)-1].CurrentBody).IsZero(), "inverse: %v", result.err)
		btState(t, w, 1, seed.Endpoint, map[Outpoint]UtxoEntry{op: btEntry(20, 0, []byte{1}, 1, true), op2: btEntry(21, 0, nil, 1, true)})
		btIndexes(t, w, r, false)
		for _, absent := range []Outpoint{{Txid: spend.id}, {Txid: spend.id, Vout: 1}, cancel} {
			w.read(t, 1, btUTXOKey(1, absent), nil)
		}
		w.read(t, 5, append(bytes.Clone(r.Block[:]), 0), btManifest(r, 2, 2))
		restore := r
		restore.BodyKind, restore.Raw, restore.Kind, restore.Undo = 2, nil, 5, 3
		result, _, _ = w.run(t, []blockTreeRequestV1{restore}, nil)
		result.want(t, 2, 3, -1)
		logicalMDBXAssert(t, result.err == nil, "RESTORE_OLD: %v", result.err)
		w.read(t, 5, undoLiteralKey(r.Block, op2, 1, 0), btValue(seedTx.frames[1], 1, true))
		w.read(t, 5, undoLiteralKey(r.Block, op, 1, 1), btValue(seedTx.frames[0], 1, true))
	}
}

func btGeneratedRefusal(t *testing.T, w *btWorld, request blockTreeRequestV1, manifest []byte) {
	t.Helper()
	result, _, observed := w.run(t, []blockTreeRequestV1{request}, nil)
	result.want(t, 1, 1, 0)
	var engine *mdbx.EngineError
	ok := errors.As(result.err, &engine)
	logicalMDBXAssert(t, ok && engine != nil && reflect.ValueOf(result.err).Equal(reflect.ValueOf(engine)) && engine.Operation == "update" && engine.Class == "Integrity" && engine.Code == -30796 && engine.Diagnostic == "invalid tree native representation" && engine.Cause == nil && engine.TreeObservation == nil && observed[0].calls == ([3]int{0, 1, 0}), "retained scalar mismatch: %+v", result.err)
	cached := w.s.View(func(*mdbx.Reader) error { t.Fatal("consumed scalar refusal View"); return nil })
	logicalMDBXAssert(t, reflect.ValueOf(cached).Equal(reflect.ValueOf(result.err)), "scalar refusal did not cache actual error")
	w.reopen(t)
	w.read(t, 5, append(bytes.Clone(request.Block[:]), 0), manifest)
}

func btInverseRequests(t *testing.T, w *btWorld, inverse blockTreeRequestV1) []blockTreeRequestV1 {
	t.Helper()
	if inverse.Kind != 9 {
		return []blockTreeRequestV1{inverse}
	}
	tx := btTransaction(91, 0, nil, nil, nil, []byte{0}, nil)
	seed := btRequest(btBody(148, 91, [32]byte{}, tx), 0)
	seed.Generation, seed.Kind = 2, 4
	result, _, _ := w.run(t, []blockTreeRequestV1{seed}, nil)
	logicalMDBXAssert(t, result.err == nil, "CURRENT before reverse LAG: %v", result.err)
	current := seed
	current.BodyKind, current.Raw, current.Direction, current.Kind, current.Undo = 2, nil, 2, 7, 5
	current.Endpoint = mdbx.TreeEndpointV1{}
	current.CanonicalBeforePresent, current.OwnerBeforePresent = true, true
	return []blockTreeRequestV1{current, inverse}
}

func btGenesis(t *testing.T) {
	w := btNew(t)
	tx := btTransaction(1, 0, []Outpoint{{Txid: [32]byte{0x77}}}, [][]byte{btFrame(9, 0, nil)}, nil, []byte{0}, nil)
	r := btRequest(btBody(148, 8, [32]byte{}, tx), 0)
	r.Kind = 4
	result, _, _ := w.run(t, []blockTreeRequestV1{r}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "genesis: %v", result.err)
	btState(t, w, 1, r.Endpoint, map[Outpoint]UtxoEntry{{Txid: tx.id}: btEntry(9, 0, nil, 0, true)})
	inverse := r
	inverse.Raw, inverse.BodyKind, inverse.Direction, inverse.Kind, inverse.Undo = nil, 2, 2, 8, 6
	inverse.Endpoint = mdbx.TreeEndpointV1{}
	inverse.CanonicalBeforePresent, inverse.OwnerBeforePresent = true, true
	result, _, _ = w.run(t, []blockTreeRequestV1{inverse}, func(_ []blockTreeEffectV1, _ []*btObserved, operation *mdbx.TreeOperationV1) {
		operation.Pair.Mutations = append(operation.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[4], Key: inverse.Block[:], BeforePresent: true, AfterKind: 1})
		btSort(operation.Pair.Mutations)
	})
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "genesis inverse: %v", result.err)
	btState(t, w, 1, mdbx.TreeEndpointV1{}, nil)
	w.read(t, 1, btUTXOKey(1, Outpoint{Txid: tx.id}), nil)
	w.read(t, 5, append(bytes.Clone(r.Block[:]), 0), nil)
	w.read(t, 4, r.Block[:], nil)
}

func btAdmission(t *testing.T) {
	for _, name := range []string{"canonical-omitted", "owner-omitted", "canonical-key", "owner-key", "canonical-presence", "owner-presence", "body-omitted", "body-copy", "coverage-copy", "width116"} {
		t.Run(name, func(t *testing.T) {
			w := btNew(t)
			tx := btTransaction(1, 0, nil, [][]byte{btFrame(1, 0, nil)}, nil, []byte{0}, nil)
			r := btRequest(btBody(148, 1, [32]byte{}, tx), 1)
			if name == "width116" {
				r.Raw = btBody(116, 1, [32]byte{}, tx)
				r.HeaderBytes = 116
				r.Block = sha3.Sum256(r.Raw[:116])
				r.Endpoint.BlockHash = r.Block
			}
			result, _, sources := w.run(t, []blockTreeRequestV1{r}, func(e []blockTreeEffectV1, _ []*btObserved, op *mdbx.TreeOperationV1) {
				body, owner := 2, 3
				if name == "width116" {
					body, owner = 1, 2
				}
				switch name {
				case "canonical-omitted":
					op.Pair.Mutations = op.Pair.Mutations[1:]
				case "owner-omitted":
					op.Pair.Mutations = op.Pair.Mutations[:owner]
				case "canonical-key":
					op.Pair.Mutations[0].Key[15]++
				case "owner-key":
					op.Pair.Mutations[owner].Key[39]++
				case "canonical-presence":
					op.Pair.Mutations[0].BeforePresent = true
				case "owner-presence":
					op.Pair.Mutations[owner].BeforePresent = true
				case "body-omitted":
					op.Pair.Mutations = append(op.Pair.Mutations[:body], op.Pair.Mutations[body+1:]...)
				case "body-copy":
					op.Pair.Mutations[body].Literal = bytes.Clone(e[0].CurrentBody.Literal)
				case "coverage-copy":
					op.Primitives[0].Coverage.CurrentBody = bytes.Clone(e[0].CurrentBody.Literal)
				}
			})
			presence := name == "canonical-presence" || name == "owner-presence"
			if presence {
				result.want(t, 1, 2, -1)
				var engine *mdbx.EngineError
				ok := errors.As(result.err, &engine)
				logicalMDBXAssert(t, ok && engine != nil && reflect.ValueOf(result.err).Equal(reflect.ValueOf(engine)) && engine.Operation == "update" && engine.Class == "StateMismatch" && engine.Code == -30798 && engine.Diagnostic == "MDBX_NOTFOUND: No matching key/data pair found" && engine.Cause == nil && engine.TreeObservation == nil && !engine.ReopenRequired, "index presence refusal: %T %+v", result.err, result.err)
				logicalMDBXAssert(t, sources[0].calls == ([3]int{0, 1, 0}), "index presence source calls %v", sources[0].calls)
				called := 0
				err := w.owner.WithOperation(mdbx.TreeOperation, func(a *mdbx.OperationAccount) error {
					truth, stage, index, err := w.s.UpdateTreeV1(a, func(*mdbx.Reader) (mdbx.TreeOperationV1, error) {
						called++
						t.Fatal("consumed index presence callback")
						return mdbx.TreeOperationV1{}, nil
					})
					(btResult{truth: truth, stage: stage, index: index, err: err}).want(t, 1, 1, -1)
					logicalMDBXAssert(t, reflect.ValueOf(err).Equal(reflect.ValueOf(result.err)) && called == 0 && sources[0].calls == ([3]int{0, 1, 0}), "cached index presence refusal: %v callback%d source%v", err, called, sources[0].calls)
					return nil
				})
				logicalMDBXAssert(t, err == nil, "cached index presence account: %v", err)
				btReservationsReleased(t, w.owner)
			} else {
				result.want(t, 1, 1, -1)
				logicalMDBXAssert(t, result.err != nil && sources[0].calls == ([3]int{}), "admission source calls %v / %v", sources[0].calls, result.err)
			}
			pure := name == "body-omitted" || name == "body-copy" || name == "coverage-copy" || name == "width116"
			if !pure {
				w.reopen(t)
			}
			if presence {
				btState(t, w, 1, mdbx.TreeEndpointV1{}, nil)
				btIndexes(t, w, r, false)
				w.read(t, 1, btUTXOKey(1, Outpoint{Txid: tx.id}), nil)
				w.read(t, 3, r.Block[:], nil)
				inspection, err := w.s.Inspect()
				logicalMDBXAssert(t, err == nil && len(inspection.DBIs) == 9 && inspection.DBIs[1].Entries == 0 && inspection.DBIs[8].Entries == 0, "index presence OLD UTXO/nodes: %+v/%v", inspection, err)
			}
			w.read(t, 4, r.Block[:], nil)
			logicalMDBXAssert(t, w.s.View(func(*mdbx.Reader) error { return nil }) == nil, "admission consumed Store")
		})
	}
}

func btCompound(t *testing.T) {
	w := btNew(t)
	first := btTransaction(1, 0, nil, [][]byte{btFrame(10, 0, nil)}, nil, []byte{0}, nil)
	second := btTransaction(2, 0, nil, [][]byte{btFrame(11, 0, []byte{1})}, nil, []byte{0}, nil)
	r1 := btRequest(btBody(148, 1, [32]byte{}, first), 5)
	r1.Generated = &Uint128{Hi: 5}
	r2 := btRequest(btBody(148, 2, [32]byte{}, second), 4)
	r2.Kind, r2.Generation = 6, 2
	r2.Generated = &Uint128{Lo: 7}
	r3 := r1
	r3.Kind, r3.Generation, r3.BodyKind, r3.Raw = 6, 2, 2, nil
	// r3 must use a stored source: its complete body is persisted independently
	// before the compound, while CURRENT uses a distinct genuinely new block.
	w.pair(t, btMutation(3, r1.Block[:], r1.Raw[:148]), btMutation(4, r1.Block[:], r1.Raw))
	w.read(t, 5, append(bytes.Clone(r1.Block[:]), 0), nil)
	r1.BodyKind, r1.Raw = 2, nil
	result, _, sources := w.run(t, []blockTreeRequestV1{r1, r2, r3}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "CURRENT/LAG: %v", result.err)
	logicalMDBXAssert(t, sources[0].calls == ([3]int{0, 1, 0}) && sources[1].calls == ([3]int{0, 1, 0}) && sources[2].calls == ([3]int{0, 1, 0}), "compound source calls %v/%v/%v", sources[0].calls, sources[1].calls, sources[2].calls)
	btState(t, w, 1, r1.Endpoint, map[Outpoint]UtxoEntry{{Txid: first.id}: btEntry(10, 0, nil, 5, true)})
	btState(t, w, 2, r3.Endpoint, map[Outpoint]UtxoEntry{{Txid: first.id}: btEntry(10, 0, nil, 5, true), {Txid: second.id}: btEntry(11, 0, []byte{1}, 4, true)})
	w.read(t, 5, append(bytes.Clone(r3.Block[:]), 0), btManifest(r3, 1, 0))
	w.read(t, 5, append(bytes.Clone(r2.Block[:]), 0), btManifest(r2, 1, 0))
	current := r1
	current.Direction, current.Kind, current.Undo = 2, 7, 5
	current.CanonicalBeforePresent, current.OwnerBeforePresent = true, true
	current.Endpoint = mdbx.TreeEndpointV1{Kind: 1, Height: 4, CumulativeChainwork: [40]byte{39: 99}}
	last := r3
	last.Direction, last.Kind, last.Undo = 2, 9, 5
	last.CanonicalBeforePresent, last.OwnerBeforePresent = true, true
	last.Endpoint = r2.Endpoint
	firstLag := r2
	firstLag.Raw, firstLag.BodyKind, firstLag.Direction, firstLag.Kind, firstLag.Undo = nil, 2, 2, 9, 5
	firstLag.CanonicalBeforePresent, firstLag.OwnerBeforePresent = true, true
	firstLag.Endpoint = mdbx.TreeEndpointV1{Kind: 1, Height: 3, CumulativeChainwork: [40]byte{39: 99}}
	result, _, sources = w.run(t, []blockTreeRequestV1{current, last, firstLag}, nil)
	result.want(t, 2, 3, -1)
	logicalMDBXAssert(t, result.err == nil, "CURRENT/reverse LAG compound: %v", result.err)
	for _, source := range sources {
		logicalMDBXAssert(t, source.calls == ([3]int{0, 1, 0}), "reverse source calls %v", source.calls)
	}
	btState(t, w, 1, current.Endpoint, nil)
	btState(t, w, 2, firstLag.Endpoint, nil)
	for _, request := range []blockTreeRequestV1{current, last, firstLag} {
		btIndexes(t, w, request, false)
	}
	w.read(t, 5, append(bytes.Clone(r3.Block[:]), 0), btManifest(r3, 1, 0))
	w.read(t, 5, append(bytes.Clone(r2.Block[:]), 0), btManifest(r2, 1, 0))
	inspection, inspectErr := w.s.Inspect()
	logicalMDBXAssert(t, inspectErr == nil && inspection.DBIs[8].Entries == 0, "inverse retained stale tree nodes: %v", inspectErr)
}

func btReplacement(t *testing.T) {
	for _, oldHeight := range []uint64{4, 5} {
		t.Run(fmt.Sprint(oldHeight), func(t *testing.T) {
			w := btNew(t)
			c := btTransaction(9, 0, nil, [][]byte{btFrame(19, 0, []byte{3})}, nil, []byte{0}, nil)
			cOp := Outpoint{Txid: c.id}
			b := btTransaction(10, 0, []Outpoint{cOp}, [][]byte{btFrame(20, 0, bytes.Repeat([]byte{4}, 253))}, nil, []byte{0}, nil)
			bOp := Outpoint{Txid: b.id}
			inert := btTransaction(11, 0, nil, [][]byte{btFrame(0, 2, nil)}, nil, []byte{0}, nil)
			seedC := btRequest(btBody(148, 7, [32]byte{}, c), 1)
			result, _, _ := w.run(t, []blockTreeRequestV1{seedC}, nil)
			logicalMDBXAssert(t, result.err == nil, "seed C: %v", result.err)
			// The repeated core is a projection fixture, not a chain-validity claim.
			// Real prior native operations create BOTH original B and C; no supplied
			// source receipt, hand-written tree or hash fixed point is involved.
			seed := btRequest(btBody(148, 8, seedC.Block, inert, b, c), oldHeight)
			result, _, _ = w.run(t, []blockTreeRequestV1{seed}, nil)
			logicalMDBXAssert(t, result.err == nil, "seed B+C: %v", result.err)
			spendB := btTransaction(12, 0, []Outpoint{bOp}, nil, nil, []byte{0}, nil)
			r := btRequest(btBody(148, 9, seed.Block, inert, spendB, b), 5)
			r.Generated = &Uint128{Hi: 3, Lo: 7}
			r.CanonicalBeforePresent = oldHeight == 5
			result, _, _ = w.run(t, []blockTreeRequestV1{r}, func(_ []blockTreeEffectV1, _ []*btObserved, operation *mdbx.TreeOperationV1) {
				if oldHeight == 5 {
					key := append(binary.BigEndian.AppendUint64(nil, 1), seed.Block[:]...)
					operation.Pair.Mutations = append(operation.Pair.Mutations, mdbx.Mutation{DBI: mdbx.TreeSchemaV1DBIs()[7], Key: key, BeforePresent: true, AfterKind: 1})
					btSort(operation.Pair.Mutations)
				}
			})
			result.want(t, 2, 3, -1)
			logicalMDBXAssert(t, result.err == nil, "replacement: %v", result.err)
			btState(t, w, 1, r.Endpoint, map[Outpoint]UtxoEntry{bOp: btEntry(20, 0, bytes.Repeat([]byte{4}, 253), 5, false)})
			w.read(t, 1, btUTXOKey(1, cOp), nil)
			w.read(t, 5, append(bytes.Clone(r.Block[:]), 0), btManifest(r, 3, 2))
			w.read(t, 5, undoLiteralKey(r.Block, bOp, 1, 0), btValue(b.frames[0], oldHeight, false))
			w.read(t, 5, undoLiteralKey(r.Block, cOp, 2, 0), btValue(c.frames[0], oldHeight, false))
			btIndexes(t, w, r, true)
		})
	}
}
