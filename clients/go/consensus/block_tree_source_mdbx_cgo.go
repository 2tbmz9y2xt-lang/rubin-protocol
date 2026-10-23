//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// The composer qualifies the complete body, header, work, Generated and index
// preconditions, and funds the request/result/backing before allocating them.
// They remain immutable and funded through native readback and cleanup.
type blockTreeRequestV1 struct {
	DatabaseID [32]byte
	Generation uint64
	Block [32]byte
	Height uint64
	HeaderBytes uint16
	BodyKind uint8
	Raw []byte
	Generated *Uint128
	Direction mdbx.TreeDirectionV1
	Kind mdbx.TreePrimitiveKindV1
	Undo mdbx.TreeUndoEffectV1
	Endpoint mdbx.TreeEndpointV1
	CanonicalBeforePresent bool
	OwnerBeforePresent bool
}

type blockTreeSourceV1 struct {
	coverage mdbx.TreeSourceCoverageV1
	Raw []byte
}

type blockTreeEffectV1 struct {
	Primitive mdbx.TreePrimitiveV1
	Index [2]mdbx.Mutation
	CurrentBody mdbx.Mutation
}

func blockTreeRequestValidV1(r blockTreeRequestV1) bool {
	if r.Generation == 0 || r.Generated == nil {
		return false
	}
	if r.HeaderBytes != 116 && r.HeaderBytes != 148 {
		return false
	}
	switch r.BodyKind {
	case 1:
		return len(r.Raw) != 0
	case 2:
		return r.Raw == nil
	}
	return false
}

func prepareBlockTreeEffectV1(dst *blockTreeSourceV1, old *mdbx.Reader, account *mdbx.OperationAccount, request blockTreeRequestV1) (blockTreeEffectV1, error) {
	if dst != nil {
		*dst = blockTreeSourceV1{}
	}
	if dst == nil || old == nil || account == nil {
		return blockTreeEffectV1{}, localLogicalStateFailure("invalid block tree source request")
	}
	if !blockTreeRequestValidV1(request) {
		return blockTreeEffectV1{}, localLogicalStateFailure("invalid block tree source request")
	}
	source := blockTreeSourceV1{Raw: request.Raw, coverage: mdbx.TreeSourceCoverageV1{
		DatabaseID: request.DatabaseID, Generation: request.Generation, Block: request.Block,
		Height: request.Height, HeaderBytes: request.HeaderBytes, BodyKind: request.BodyKind, CurrentBody: request.Raw,
	}}
	binary.BigEndian.PutUint64(source.coverage.BlockMeta.Generated[:8], request.Generated.Hi)
	binary.BigEndian.PutUint64(source.coverage.BlockMeta.Generated[8:], request.Generated.Lo)
	var parent [32]byte
	err := account.WithReservation(4824, func() error {
		var window [1024]byte
		return source.visitV1(old, window[:], func(c *blockTreeCursorV1) error {
			parent = c.blockV1(request.HeaderBytes, request.Height)
			source.coverage.BlockMeta.TxCount = c.txs
			source.coverage.BlockMeta.EventCount = c.events
			return c.err
		})
	})
	if err != nil {
		return blockTreeEffectV1{}, err
	}
	*dst = source
	return dst.effectV1(request, parent), nil
}

func (s *blockTreeSourceV1) effectV1(r blockTreeRequestV1, parent [32]byte) blockTreeEffectV1 {
	canonical, _ := mdbx.HeightKey(r.Generation, r.Height) // nonzero generation was checked before allocation
	owner, _ := mdbx.CanonicalOwnerKey(r.Generation, r.Block)
	dbis := mdbx.TreeSchemaV1DBIs()
	e := blockTreeEffectV1{Primitive: mdbx.TreePrimitiveV1{
		Direction: r.Direction, Kind: r.Kind, Generation: r.Generation, Block: r.Block, Height: r.Height,
		Source: s, Undo: r.Undo, Endpoint: r.Endpoint, Coverage: &s.coverage,
	}, Index: [2]mdbx.Mutation{
		{DBI: dbis[2], Key: canonical, BeforePresent: r.CanonicalBeforePresent, AfterKind: mdbx.AfterAbsent},
		{DBI: dbis[7], Key: owner, BeforePresent: r.OwnerBeforePresent, AfterKind: mdbx.AfterAbsent},
	}}
	if r.Direction == mdbx.TreeForwardV1 {
		e.Index[0].AfterKind, e.Index[1].AfterKind = mdbx.AfterLiteral, mdbx.AfterLiteral
		e.Index[0].Literal = mdbx.ChainValue(r.Block, parent, r.Endpoint.CumulativeChainwork)
		e.Index[1].Literal = mdbx.CanonicalOwnerValue(r.Height)
	}
	if r.BodyKind == 1 {
		e.CurrentBody = mdbx.Mutation{DBI: dbis[4], Key: s.coverage.Block[:], AfterKind: mdbx.AfterLiteral, Literal: s.Raw}
	}
	return e
}

func (s *blockTreeSourceV1) TreeDeltaV1(position mdbx.TreePositionV1, old *mdbx.Reader, sink *mdbx.TreeDeltaSinkV1) error {
	if position != mdbx.TreeWriterV1 && position != mdbx.TreeReadbackV1 {
		return localLogicalStateFailure("invalid block tree source position")
	}
	if s == nil || s.coverage.Generation == 0 {
		return localLogicalStateFailure("invalid block tree source request")
	}
	if err := sink.BeginV1(s.coverage.BlockMeta); err != nil {
		return err
	}
	return s.visitV1(old, sink.WindowV1(), func(c *blockTreeCursorV1) error {
		c.sink = sink
		c.digest = sha3.New256()
		c.blockV1(s.coverage.HeaderBytes, s.coverage.Height)
		if c.txs != s.coverage.BlockMeta.TxCount || c.events != s.coverage.BlockMeta.EventCount {
			c.failV1()
		}
		return c.err
	})
}

func (s *blockTreeSourceV1) framingV1() error {
	if s.coverage.BodyKind == 2 {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("required block tree source framing differs")}
	}
	return localLogicalStateFailure("qualified block tree source framing differs")
}

// Row, Reader, sink, hash, window and cursors are synchronous visit-local state.
// Only the immutable coverage/borrowed Raw survives; no source reservation exists.
func (s *blockTreeSourceV1) visitV1(old *mdbx.Reader, window []byte, visit func(*blockTreeCursorV1) error) error {
	c := blockTreeCursorV1{raw: s.Raw, window: window, source: s, length: uint64(len(s.Raw))}
	if s.coverage.BodyKind == 1 {
		return visit(&c)
	}
	found := false
	err := old.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: s.coverage.Block}, func(row mdbx.LargeImageRowV1) error {
		found = row.Present()
		if !found {
			return nil
		}
		c.row, c.length = row, row.Length()
		return visit(&c)
	})
	if err != nil {
		return err
	}
	if !found {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("required block tree source is absent")}
	}
	return nil
}

type blockTreeCursorV1 struct {
	raw []byte
	row mdbx.LargeImageRowV1
	window []byte
	source *blockTreeSourceV1
	sink *mdbx.TreeDeltaSinkV1
	hash *sha3.SHA3
	digest *sha3.SHA3
	err error
	length, off uint64
	txs, events uint32
	field [40]byte
}

func (c *blockTreeCursorV1) failV1() {
	if c.err == nil {
		c.err = c.source.framingV1()
	}
}

func (c *blockTreeCursorV1) spanV1(n uint64) bool {
	if c.err != nil {
		return false
	}
	if c.off > c.length || n > c.length-c.off {
		c.failV1()
		return false
	}
	return true
}

func (c *blockTreeCursorV1) readV1(dst []byte) {
	if !c.spanV1(uint64(len(dst))) {
		clear(dst)
		return
	}
	if c.raw != nil {
		copy(dst, c.raw[c.off:c.off+uint64(len(dst))])
	} else {
		if len(dst) > len(c.window) {
			c.failV1()
			return
		}
		_, c.err = c.row.ReadAt(c.window[:len(dst)], c.off)
		copy(dst, c.window[:len(dst)])
	}
	if c.hash != nil && c.err == nil {
		_, _ = c.hash.Write(dst)
	}
	c.off += uint64(len(dst))
}

func (c *blockTreeCursorV1) fixedV1(n int) []byte {
	c.readV1(c.field[:n])
	return c.field[:n]
}

func (c *blockTreeCursorV1) skipV1(n uint64) {
	if !c.spanV1(n) {
		return
	}
	if c.raw != nil {
		if c.hash != nil {
			_, _ = c.hash.Write(c.raw[c.off:c.off+n])
		}
		c.off += n
		return
	}
	for n != 0 && c.err == nil {
		chunk := min(n, uint64(len(c.window)))
		if chunk == 0 {
			c.failV1()
			return
		}
		c.readV1(c.window[:chunk])
		n -= chunk
	}
}

func (c *blockTreeCursorV1) compactV1(maximum uint64) uint64 {
	tag := c.fixedV1(1)[0]
	var n, minimum uint64
	switch tag {
	case 253:
		n, minimum = uint64(binary.LittleEndian.Uint16(c.fixedV1(2))), 253
	case 254:
		n, minimum = uint64(binary.LittleEndian.Uint32(c.fixedV1(4))), 65536
	case 255:
		n, minimum = binary.LittleEndian.Uint64(c.fixedV1(8)), 4294967296
	default:
		n = uint64(tag)
	}
	if n < minimum || n > maximum {
		c.failV1()
	}
	return n
}

func (c *blockTreeCursorV1) blockV1(width uint16, height uint64) [32]byte {
	c.skipV1(4)
	var parent [32]byte
	copy(parent[:], c.fixedV1(32))
	c.skipV1(uint64(width)-36)
	n := c.compactV1(math.MaxUint32)
	if n == 0 || height == 0 && n != 1 {
		c.failV1()
	}
	c.txs = uint32(n)
	for tx := uint32(0); tx < c.txs && c.err == nil; tx++ {
		c.txV1(tx)
	}
	if c.off != c.length {
		c.failV1()
	}
	return parent
}

func (c *blockTreeCursorV1) eventV1(e mdbx.TreeEventV1) {
	if c.err != nil {
		return
	}
	if c.events == math.MaxUint32 {
		c.failV1()
		return
	}
	c.events++
	if c.sink != nil {
		c.err = c.sink.EventV1(e)
	}
}

func (c *blockTreeCursorV1) inputV1(tx, input uint32) {
	var e mdbx.TreeEventV1
	e.Kind, e.TxIndex, e.InputIndex = mdbx.TreeEventSpendV1, tx, input
	copy(e.Outpoint.Txid[:], c.fixedV1(32))
	e.Outpoint.Vout = binary.LittleEndian.Uint32(c.fixedV1(4))
	c.skipV1(c.compactV1(MAX_SCRIPT_SIG_BYTES))
	c.skipV1(4)
	if tx != 0 {
		c.eventV1(e)
	}
}

func (c *blockTreeCursorV1) outputV1(tx, vout uint32, id [32]byte, emit bool) {
	start := c.off
	c.skipV1(8)
	kind := binary.LittleEndian.Uint16(c.fixedV1(2))
	c.skipV1(c.compactV1(MAX_COVENANT_DATA_PER_OUTPUT))
	if kind == 0x0002 || kind == 0x0103 || !emit {
		return
	}
	length := c.off-start
	if length > math.MaxUint32 {
		c.failV1()
		return
	}
	c.eventV1(mdbx.TreeEventV1{Kind: mdbx.TreeEventCreateV1, Outpoint: mdbx.TreeOutpointV1{Txid: id, Vout: vout}, TxIndex: tx, FrameOffset: start, FrameLength: uint32(length)})
}

func (c *blockTreeCursorV1) txV1(tx uint32) {
	if c.sink != nil {
		c.hash = c.digest
		c.hash.Reset()
	}
	kind, outputs, start, end := c.coreV1(tx)
	var id [32]byte
	if c.hash != nil {
		c.hash.Sum(id[:0])
		c.hash = nil
	}
	c.witnessV1()
	c.payloadV1(kind)
	if c.sink != nil && c.err == nil {
		c.outputsV1(tx, outputs, start, end, id)
	}
}

func (c *blockTreeCursorV1) coreV1(tx uint32) (uint8, uint64, uint64, uint64) {
	if binary.LittleEndian.Uint32(c.fixedV1(4)) != TX_WIRE_VERSION {
		c.failV1()
	}
	kind := c.fixedV1(1)[0]
	c.skipV1(8)
	inputs := c.compactV1(MAX_TX_INPUTS)
	for i := uint64(0); i < inputs && c.err == nil; i++ {
		c.inputV1(tx, uint32(i))
	}
	outputs := c.compactV1(MAX_TX_OUTPUTS)
	start := c.off
	for i := uint64(0); i < outputs && c.err == nil; i++ {
		c.outputV1(tx, uint32(i), [32]byte{}, c.sink == nil)
	}
	end := c.off
	c.skipV1(4)
	c.daCoreV1(kind)
	return kind, outputs, start, end
}

func (c *blockTreeCursorV1) outputsV1(tx uint32, outputs, start, end uint64, id [32]byte) {
	// Only the output region is revisited. The complete forward cursor remains
	// at the next transaction; no descriptor or input is retained or rescanned.
	r := *c
	r.off, r.length = start, end
	for i := uint64(0); i < outputs && r.err == nil; i++ {
		r.outputV1(tx, uint32(i), id, true)
	}
	c.events, c.err = r.events, r.err
}

func (c *blockTreeCursorV1) daCoreV1(kind uint8) {
	switch kind {
	case 0:
		return
	case 1:
		c.skipV1(32)
		n := binary.LittleEndian.Uint16(c.fixedV1(2))
		if n == 0 || uint64(n) > MAX_DA_CHUNK_COUNT {
			c.failV1()
		}
		c.skipV1(32+8+32+32+32+1)
		c.skipV1(c.compactV1(MAX_DA_MANIFEST_BYTES_PER_TX))
	case 2:
		c.skipV1(32)
		if uint64(binary.LittleEndian.Uint16(c.fixedV1(2))) >= MAX_DA_CHUNK_COUNT {
			c.failV1()
		}
		c.skipV1(32)
	default:
		c.failV1()
	}
}

func (c *blockTreeCursorV1) witnessV1() {
	start := c.off
	n := c.compactV1(MAX_WITNESS_ITEMS)
	for i := uint64(0); i < n && c.err == nil; i++ {
		c.skipV1(1) // suite/signature semantics were qualified by the caller
		c.skipV1(c.compactV1(uint64(math.MaxInt)))
		c.skipV1(c.compactV1(uint64(math.MaxInt)))
		if c.off-start > MAX_WITNESS_BYTES_PER_TX {
			c.failV1()
		}
	}
}

func (c *blockTreeCursorV1) payloadV1(kind uint8) {
	n := c.compactV1(math.MaxUint64)
	switch kind {
	case 0:
		if n != 0 {
			c.failV1()
		}
	case 1:
		if n > MAX_DA_MANIFEST_BYTES_PER_TX {
			c.failV1()
		}
	case 2:
		if n == 0 || n > CHUNK_BYTES {
			c.failV1()
		}
	}
	c.skipV1(n)
}
