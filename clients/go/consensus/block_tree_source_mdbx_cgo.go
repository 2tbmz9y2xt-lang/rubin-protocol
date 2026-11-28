//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"encoding/binary"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/treebody"
)

// The composer qualifies the complete body, header, work, Generated and index
// preconditions, and funds the request/result/backing before allocating them.
// They remain immutable and funded through native readback and cleanup.
// BodyKind 3 borrows nonempty Raw without emitting a CurrentBody mutation;
// that backing remains immutable through the operation's return.
type blockTreeRequestV1 struct {
	DatabaseID             [32]byte
	Generation             uint64
	Block                  [32]byte
	Height                 uint64
	HeaderBytes            uint16
	BodyKind               uint8
	Raw                    []byte
	Generated              *Uint128
	Direction              mdbx.TreeDirectionV1
	Kind                   mdbx.TreePrimitiveKindV1
	Undo                   mdbx.TreeUndoEffectV1
	Endpoint               mdbx.TreeEndpointV1
	CanonicalBeforePresent bool
	OwnerBeforePresent     bool
}

type blockTreeSourceV1 struct {
	coverage mdbx.TreeSourceCoverageV1
	Raw      []byte
}

// blockTreeEffectV1 emits CurrentBody only for BodyKind 1, never held kind 3.
type blockTreeEffectV1 struct {
	Primitive   mdbx.TreePrimitiveV1
	Index       [2]mdbx.Mutation
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
	case 1, 3:
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
		return source.visitV1(old, window[:], func(body treebody.Source) error {
			census, err := source.scanV1(body, nil)
			parent = census.Parent
			source.coverage.BlockMeta.TxCount = census.TxCount
			source.coverage.BlockMeta.EventCount = census.EventCount
			return err
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
	return s.visitV1(old, sink.WindowV1(), func(body treebody.Source) error {
		census, err := s.scanV1(body, func(e treebody.Event) error {
			return sink.EventV1(mdbx.TreeEventV1{
				Kind: mdbx.TreeEventKindV1(e.Kind), Outpoint: mdbx.TreeOutpointV1(e.Outpoint),
				TxIndex: e.TxIndex, InputIndex: e.InputIndex, FrameOffset: e.FrameOffset, FrameLength: e.FrameLength,
			})
		})
		if err == nil && (census.TxCount != s.coverage.BlockMeta.TxCount || census.EventCount != s.coverage.BlockMeta.EventCount) {
			return s.framingV1()
		}
		return err
	})
}

func (s *blockTreeSourceV1) scanV1(body treebody.Source, emit func(treebody.Event) error) (treebody.Census, error) {
	census, err := treebody.Scan(body, s.coverage.HeaderBytes, s.coverage.Height, emit)
	if census.Malformed {
		return census, s.framingV1()
	}
	return census, err
}

func (s *blockTreeSourceV1) framingV1() error {
	if s.coverage.BodyKind == 2 {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("required block tree source framing differs")}
	}
	return localLogicalStateFailure("qualified block tree source framing differs")
}

// Row, Reader, sink, hash, window and cursors are synchronous visit-local state.
// Only the immutable coverage/borrowed Raw survives; no source reservation exists.
func (s *blockTreeSourceV1) visitV1(old *mdbx.Reader, window []byte, visit func(treebody.Source) error) error {
	if s.coverage.BodyKind == 1 || s.coverage.BodyKind == 3 {
		return visit(treebody.Source{Raw: s.Raw})
	}
	found := false
	err := old.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageBlockBodyV1, Hash: s.coverage.Block}, func(row mdbx.LargeImageRowV1) error {
		found = row.Present()
		if !found {
			return nil
		}
		return visit(treebody.Source{ReadAt: row.ReadAt, Window: window, Length: row.Length()})
	})
	if err != nil {
		return err
	}
	if !found {
		return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New("required block tree source is absent")}
	}
	return nil
}
