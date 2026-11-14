//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"encoding/binary"
	"errors"
	"math"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

type initial148RequiredRequestV1 struct {
	Source    blockTreeSourceV1
	Primitive mdbx.TreePrimitiveV1
	Parent    mdbx.TreeEndpointV1
}

type initial148RootReadOutcomeV1 struct {
	root                    [32]byte
	cause                   error
	observation             mdbx.TreeObservationV1
	derived, hasObservation bool
}

// Fixed slices contain only actually obtained point facts. No completeness or
// full-map predicate can be established through this view.
type initial148RequiredScopeV1 struct {
	reader         *mdbx.Reader
	account        *mdbx.OperationAccount
	request        initial148RequiredRequestV1
	keys           []mdbx.TreeOutpointV1
	lengths        []uint32
	counters       logicalStateCounters
	first          error
	calls          uint64
	active, sealed bool
	haveCounters   bool
}

// withInitial148RequiredStateV1 reserves records and transient row decoding for one callback.
func withInitial148RequiredStateV1(reader *mdbx.Reader, account *mdbx.OperationAccount, request initial148RequiredRequestV1, use func(logicalStateView, func() initial148RootReadOutcomeV1) error) error {
	if reader == nil || account == nil || use == nil || !initial148RequiredShapeV1(request) {
		return localLogicalStateFailure("invalid required state request")
	}
	if err := reader.CheckTreeRootReadV1(account, mdbx.TreeRootReadV1{Primitive: request.Primitive, Parent: request.Parent}); err != nil {
		return err
	}
	events := uint64(request.Source.coverage.BlockMeta.EventCount)
	if events > (math.MaxUint64-135192)/48 || events > uint64(math.MaxInt)/36 {
		return localLogicalStateFailure("required state bound exceeds integer domain")
	}
	capacity := int(events)
	return account.WithReservation(135192+48*events, func() error {
		scope := initial148RequiredScopeV1{
			reader: reader, account: account, request: request, active: true,
			keys: make([]mdbx.TreeOutpointV1, 0, capacity), lengths: make([]uint32, 0, capacity),
		}
		defer scope.expireV1()
		err := use(&scope, scope.deriveV1)
		if scope.first == nil || any(err) == any(scope.first) {
			return err
		}
		if err == nil {
			return scope.first
		}
		return errors.Join(err, scope.first)
	})
}

func initial148RequiredShapeV1(request initial148RequiredRequestV1) bool {
	p, s := request.Primitive, request.Source
	bound, ok := p.Source.(*blockTreeSourceV1)
	if !ok || bound == nil || p.Coverage == nil {
		return false
	}
	if !initial148RequiredCoverageV1(s, *bound) || !initial148RequiredCoverageV1(s, blockTreeSourceV1{Raw: p.Coverage.CurrentBody, coverage: *p.Coverage}) {
		return false
	}
	return initial148RequiredPrimitiveIdentityV1(p, s.coverage) && initial148RequiredPrimitiveV1(p) && initial148RequiredParentV1(p.Height, request.Parent)
}

func initial148RequiredCoverageV1(a, b blockTreeSourceV1) bool {
	if !initial148RequiredBackingV1(a.Raw, b.Raw) {
		return false
	}
	if !initial148RequiredBackingV1(a.Raw, a.coverage.CurrentBody) || !initial148RequiredBackingV1(a.Raw, b.coverage.CurrentBody) {
		return false
	}
	return initial148RequiredSourceDomainV1(a.coverage) && initial148RequiredSameCoverageV1(a.coverage, b.coverage)
}

func initial148RequiredBackingV1(a, b []byte) bool {
	return len(a) != 0 && len(a) == len(b) && &a[0] == &b[0]
}

func initial148RequiredSourceDomainV1(c mdbx.TreeSourceCoverageV1) bool {
	return c.DatabaseID != ([32]byte{}) && c.Generation != 0 && c.Height <= math.MaxUint32 && c.HeaderBytes == 148 && c.BodyKind == 1
}

func initial148RequiredSameCoverageV1(a, b mdbx.TreeSourceCoverageV1) bool {
	return a.DatabaseID == b.DatabaseID && a.Generation == b.Generation && a.Block == b.Block && a.Height == b.Height && a.HeaderBytes == b.HeaderBytes && a.BodyKind == b.BodyKind && a.BlockMeta == b.BlockMeta
}

func initial148RequiredPrimitiveIdentityV1(p mdbx.TreePrimitiveV1, c mdbx.TreeSourceCoverageV1) bool {
	return c.Generation == p.Generation && c.Block == p.Block && c.Height == p.Height
}

func initial148RequiredPrimitiveV1(p mdbx.TreePrimitiveV1) bool {
	recipe := p.Direction == mdbx.TreeForwardV1 && p.Kind == mdbx.TreeKindDirectApplyV1 && p.Undo == mdbx.UndoTransientV1
	endpoint := p.Endpoint.Kind == mdbx.TreeEndpointAppliedV1 && p.Endpoint.Height == p.Height && p.Endpoint.BlockHash == p.Block
	return recipe && endpoint
}

func initial148RequiredParentV1(height uint64, parent mdbx.TreeEndpointV1) bool {
	if height == 0 {
		return parent == (mdbx.TreeEndpointV1{Kind: mdbx.TreeEndpointPreGenesisV1})
	}
	return parent.Kind == mdbx.TreeEndpointAppliedV1 && parent.Height == height-1
}

// expireV1 releases both record slices and their borrowed Reader/account bindings.
func (s *initial148RequiredScopeV1) expireV1() {
	s.active, s.sealed = false, true
	s.keys, s.lengths = nil, nil
	s.reader, s.account = nil, nil
	s.request = initial148RequiredRequestV1{}
}

func (s *initial148RequiredScopeV1) availableV1() error {
	if !s.active || s.sealed {
		return localLogicalStateFailure("required state scope is not active")
	}
	return s.first
}

func (s *initial148RequiredScopeV1) failV1(err error) error {
	if s.first == nil {
		s.first = err
	}
	return s.first
}

func initial148RequiredIntegrityV1(message string) error {
	return &logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: errors.New(message)}
}

func (s *initial148RequiredScopeV1) rowFailureV1(err error) logicalStateRowRead {
	err = s.failV1(err)
	_, rowKind := logicalMDBXReadKinds(initial148RequiredFailureKindV1(err))
	return logicalStateRowRead{kind: rowKind, cause: err}
}

func initial148RequiredFailureKindV1(err error) logicalStateFailureKind {
	kind, _ := classifyLogicalMDBXReadError(err)
	var logical *logicalStateFailure
	if errors.As(err, &logical) {
		kind = logical.kind
	}
	return kind
}

// Lookup counts every request and consumes an obtained record before any row read.
func (s *initial148RequiredScopeV1) Lookup(op Outpoint) logicalStateRowRead {
	if err := s.availableV1(); err != nil {
		_, rowKind := logicalMDBXReadKinds(initial148RequiredFailureKindV1(err))
		return logicalStateRowRead{kind: rowKind, cause: err}
	}
	if s.calls >= 2*uint64(cap(s.keys)) {
		return s.rowFailureV1(localLogicalStateFailure("required state point bound exceeded"))
	}
	s.calls++
	if _, present, ok := s.recordedV1(op); ok {
		if present {
			return s.rowFailureV1(localLogicalStateFailure("required state record holds no value"))
		}
		return logicalStateRowRead{kind: logicalStateRowAbsent}
	}
	var value []byte
	var present bool
	if s.request.Primitive.Height != 0 {
		key, _ := mdbx.UTXOKey(s.request.Primitive.Generation, op.Txid, op.Vout)
		var err error
		value, present, err = s.reader.Get(mdbx.TreeSchemaV1DBIs()[1], key)
		if err != nil {
			return s.rowFailureV1(err)
		}
	}
	return s.acceptRowV1(op, value, present)
}

func (s *initial148RequiredScopeV1) acceptRowV1(op Outpoint, value []byte, present bool) logicalStateRowRead {
	var entry UtxoEntry
	if present {
		decoded, err := mdbx.DecodeUTXOValue(value)
		if err != nil {
			return s.rowFailureV1(&logicalStateFailure{kind: logicalStateFailureStoreIntegrity, cause: err})
		}
		entry = UtxoEntry{Value: decoded.Value, CovenantType: decoded.CovenantType, CovenantData: decoded.CovenantData, CreationHeight: decoded.CreationHeight, CreatedByCoinbase: decoded.Coinbase}
	}
	if err := s.rememberV1(op, value, present); err != nil {
		return s.rowFailureV1(err)
	}
	if present {
		return logicalStateRowRead{kind: logicalStateRowPresent, entry: entry}
	}
	return logicalStateRowRead{kind: logicalStateRowAbsent}
}

// rememberV1 retains only a decoded row's key and bounded StateEntryBytes length.
func (s *initial148RequiredScopeV1) rememberV1(op Outpoint, value []byte, present bool) error {
	if len(s.keys) == cap(s.keys) {
		return localLogicalStateFailure("required state fact bound exceeded")
	}
	var length uint32
	if present {
		// DecodeUTXOValue bounds value to 65,560 bytes, so StateEntryBytes is
		// at most 65,596 bytes and the mask preserves its exact length.
		length = uint32((36 + uint64(len(value))) & 0xffffffff)
	}
	s.keys = append(s.keys, mdbx.TreeOutpointV1{Txid: op.Txid, Vout: op.Vout})
	s.lengths = append(s.lengths, length)
	return s.residualV1()
}

// recordedV1 exposes obtained facts only while their key/length pairing is live.
func (s *initial148RequiredScopeV1) recordedV1(op Outpoint) (uint32, bool, bool) {
	if !s.active || s.sealed || s.first != nil {
		return 0, false, false
	}
	for i, key := range s.keys {
		if Outpoint(key) == op {
			return s.lengths[i], s.lengths[i] != 0, true
		}
	}
	return 0, false, false
}

func (s *initial148RequiredScopeV1) Counters() logicalStateCounterRead {
	if err := s.availableV1(); err != nil {
		counterKind, _ := logicalMDBXReadKinds(initial148RequiredFailureKindV1(err))
		return logicalStateCounterRead{kind: counterKind, cause: err}
	}
	if !s.haveCounters {
		if err := s.readCountersV1(); err != nil {
			err = s.failV1(err)
			counterKind, _ := logicalMDBXReadKinds(initial148RequiredFailureKindV1(err))
			return logicalStateCounterRead{kind: counterKind, cause: err}
		}
	}
	return logicalStateCounterRead{kind: logicalStateCountersPresent, counters: s.counters}
}

func (s *initial148RequiredScopeV1) readCountersV1() error {
	if s.request.Primitive.Height != 0 {
		key, _ := mdbx.MetaKey(0x10, s.request.Primitive.Generation)
		value, present, err := s.reader.Get(mdbx.TreeSchemaV1DBIs()[0], key)
		if err != nil {
			return err
		}
		if !present || len(value) != 16 {
			return initial148RequiredIntegrityV1("required logical counters are absent or malformed")
		}
		s.counters = logicalStateCounters{bytes: binary.BigEndian.Uint64(value[:8]), entries: binary.BigEndian.Uint64(value[8:])}
	}
	if !validLogicalStateCounterEnvelope(s.counters, s.request.Primitive.Height) {
		return initial148RequiredIntegrityV1("invalid required logical counter envelope")
	}
	s.haveCounters = true
	return s.residualV1()
}

// residualV1 checks the obtained present subset against the captured parent counters.
func (s *initial148RequiredScopeV1) residualV1() error {
	if !s.haveCounters {
		return nil
	}
	var total, count uint64
	for _, length := range s.lengths {
		if length != 0 {
			total += uint64(length)
			count++
		}
	}
	if total > s.counters.bytes || count > s.counters.entries {
		return initial148RequiredIntegrityV1("required subset exceeds parent counters")
	}
	if !validLogicalStateResidualEnvelope(s.counters.bytes-total, s.counters.entries-count) {
		return initial148RequiredIntegrityV1("invalid required residual counters")
	}
	return nil
}

// deriveV1 seals the records before projecting and sorting their present keys in place.
func (s *initial148RequiredScopeV1) deriveV1() initial148RootReadOutcomeV1 {
	if !s.active || s.sealed {
		return initial148RootReadOutcomeV1{cause: localLogicalStateFailure("required root derive is not available")}
	}
	s.sealed = true
	if s.first != nil {
		return initial148RequiredOutcomeV1(s.first)
	}
	if !initial148RequiredShapeV1(s.request) {
		return initial148RequiredOutcomeV1(s.failV1(localLogicalStateFailure("invalid required state request")))
	}
	present := 0
	for i, length := range s.lengths {
		if length != 0 {
			s.keys[present] = s.keys[i]
			present++
		}
	}
	inputs := s.keys[:present]
	sort.Slice(inputs, func(i, j int) bool {
		return logicalOutpointLess(Outpoint(inputs[i]), Outpoint(inputs[j]))
	})
	root, err := s.reader.DeriveTreeRootV1(s.account, mdbx.TreeRootReadV1{Primitive: s.request.Primitive, Parent: s.request.Parent, Inputs: inputs})
	if err != nil {
		return initial148RequiredOutcomeV1(s.failV1(err))
	}
	return initial148RootReadOutcomeV1{root: root, derived: true}
}

func initial148RequiredOutcomeV1(err error) initial148RootReadOutcomeV1 {
	out := initial148RootReadOutcomeV1{cause: err}
	var engine *mdbx.EngineError
	if errors.As(err, &engine) && engine != nil && engine.TreeObservation != nil {
		out.observation, out.hasObservation = *engine.TreeObservation, true
	}
	return out
}
