package consensus

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"

// simplicityEvalHost adapts a built SimplicityTxContext (plus the spending input's
// eager digest32 / sighash_type) to the RUB-598 step-6 context ABI
// (simplicity.EvalHost): one FRESH host per CORE_SIMPLICITY input carries the single
// shared exec meter and answers each context intrinsic read from the immutable tx
// context. RUB-615 wired this adapter into the CORE_SIMPLICITY spend-validation
// dispatch, but it stays NON-LIVE in production: CORE_SIMPLICITY spends remain
// reject-only because no §23.2.4 deployment activates without a real H_simplicity
// activation pin (activation is test-local only). A future activation-pin issue makes
// it live; until then building or using the host changes no production spend
// accept/reject decision.
type simplicityEvalHost struct {
	ctx      *SimplicityTxContext
	self     SimplicityTxContextSelfView
	group    SimplicityTxContextSameCMRView
	inputIdx uint16
	cost     uint64
}

// newSimplicityEvalHost builds a fresh, zero-cost host bound to the CORE_SIMPLICITY
// input at inputIdx. digest32/sighashType are supplied by the caller (computed via the
// existing SighashV1DigestWithType path — no new digest here).
func newSimplicityEvalHost(ctx *SimplicityTxContext, inputIdx uint16, sighashType uint8, digest32 [32]byte) (*simplicityEvalHost, error) {
	self, err := ctx.SelfView(inputIdx, sighashType, digest32)
	if err != nil {
		return nil, err
	}
	group, err := ctx.SameCMRView(inputIdx)
	if err != nil {
		return nil, err
	}
	return &simplicityEvalHost{ctx: ctx, self: self, group: group, inputIdx: inputIdx}, nil
}

func (h *simplicityEvalHost) Cost() uint64 { return h.cost }

// Charge honours the EvalHost contract: add exactly cost and return nil, or return
// an error and leave Cost UNCHANGED. It never saturates — capping a partially-spent
// budget up to MaxExecCost is chargeCost's job (it calls Charge(MaxExecCost-current)
// itself), so ChargeCost is used only as the shared accept/reject boundary check.
func (h *simplicityEvalHost) Charge(cost uint64) error {
	next, err := simplicity.ChargeCost(h.cost, cost)
	if err != nil {
		return err
	}
	h.cost = next
	return nil
}

// IntrinsicCost pre-charges one intrinsic COST-ONLY and never materializes the value
// (EvalHost contract): every non-descriptor-hash intrinsic costs IntrinsicReadCost
// (== IntrinsicMissCost == 1, so present and Either-miss are indistinguishable by
// cost), and a descriptor-hash costs base+per-byte over the descriptor LENGTH via the
// cost-only accessor. It therefore never runs sha3_256 and never reads the intrinsic
// value; the descriptor-hash accessor is the only arm that can surface a (currently
// unreachable) cost-overflow host fault, which is propagated as an error, not a miss.
func (h *simplicityEvalHost) IntrinsicCost(in simplicity.ContextIntrinsic) (uint64, error) {
	switch in.ID {
	case 0x0122:
		return h.ctx.InputDescriptorHashCost(in.Index)
	case 0x012a:
		return h.ctx.OutputDescriptorHashCost(in.Index)
	default:
		return simplicity.IntrinsicReadCost, nil
	}
}

// ReadIntrinsic returns the intrinsic value without charging the shared meter; an
// out-of-range Either read is the total Failure branch (never an error). It is the
// only path that materializes a descriptor hash — IntrinsicCost stays cost-only.
func (h *simplicityEvalHost) ReadIntrinsic(in simplicity.ContextIntrinsic) (simplicity.IntrinsicResult, error) {
	return h.resolve(in), nil
}

// resolve dispatches by intrinsic-id range to a small category resolver, returning the
// VALUE only (cost is IntrinsicCost's job). It is pure over the immutable tx context, so
// a repeated descriptor-hash read materializes (and IntrinsicCost re-charges) again — no
// memoization discount (E15).
func (h *simplicityEvalHost) resolve(in simplicity.ContextIntrinsic) simplicity.IntrinsicResult {
	id := in.ID
	switch {
	case id <= 0x0108:
		return h.resolveGlobal(id)
	case id <= 0x0115:
		return h.resolveSelf(id)
	case id <= 0x012a:
		return h.resolveIO(id, in.Index)
	case id <= 0x0139:
		return h.resolveGroup(id, in.Index)
	case id <= 0x0152:
		return h.resolveDA(id)
	default:
		return miss()
	}
}

func (h *simplicityEvalHost) resolveGlobal(id uint16) simplicity.IntrinsicResult {
	b := h.ctx.Base
	switch id {
	case 0x0100:
		return read(b32v(b.ChainID))
	case 0x0107:
		return read(u128v(b.TotalIn))
	case 0x0108:
		return read(u128v(b.TotalOut))
	default:
		return h.resolveGlobalScalar(id)
	}
}

func (h *simplicityEvalHost) resolveGlobalScalar(id uint16) simplicity.IntrinsicResult {
	b := h.ctx.Base
	switch id {
	case 0x0101:
		return read(uv(simplicity.ContextValueU64, b.Height))
	case 0x0102:
		return read(uv(simplicity.ContextValueU8, uint64(b.TxKind)))
	case 0x0103:
		return read(uv(simplicity.ContextValueU64, b.TxNonce))
	case 0x0104:
		return read(uv(simplicity.ContextValueU32, uint64(b.Locktime)))
	case 0x0105:
		return read(uv(simplicity.ContextValueU16, uint64(b.InputCount)))
	case 0x0106:
		return read(uv(simplicity.ContextValueU16, uint64(b.OutputCount)))
	default:
		return miss()
	}
}

func (h *simplicityEvalHost) resolveSelf(id uint16) simplicity.IntrinsicResult {
	s := h.self
	switch id {
	case 0x0110:
		return read(uv(simplicity.ContextValueU16, uint64(s.InputIndex)))
	case 0x0111:
		return read(uv(simplicity.ContextValueU64, s.SelfValue))
	case 0x0112:
		return read(bytesv(s.SelfState))
	case 0x0113:
		return read(b32v(s.SelfProgramCMR))
	case 0x0114:
		return read(uv(simplicity.ContextValueU8, uint64(s.SighashType)))
	case 0x0115:
		return read(b32v(s.Digest32))
	default:
		return miss()
	}
}

func (h *simplicityEvalHost) resolveIO(id uint16, index uint16) simplicity.IntrinsicResult {
	switch id {
	case 0x0120:
		return ioScalar(h.ctx.InputViews(), index, false)
	case 0x0121:
		return ioScalar(h.ctx.InputViews(), index, true)
	case 0x0122:
		return h.descriptorHash(true, index)
	case 0x0128:
		return ioScalar(h.ctx.OutputViews(), index, false)
	case 0x0129:
		return ioScalar(h.ctx.OutputViews(), index, true)
	case 0x012a:
		return h.descriptorHash(false, index)
	default:
		return miss()
	}
}

func (h *simplicityEvalHost) resolveGroup(id uint16, index uint16) simplicity.IntrinsicResult {
	switch id {
	case 0x0130:
		return groupValue(h.group.Inputs, index)
	case 0x0131:
		return groupState(h.group.Inputs, index)
	case 0x0138:
		return groupValue(h.group.Outputs, index)
	case 0x0139:
		return groupState(h.group.Outputs, index)
	default:
		return miss()
	}
}

func (h *simplicityEvalHost) resolveDA(id uint16) simplicity.IntrinsicResult {
	switch h.ctx.daView.Kind {
	case SimplicityTxContextDAViewCommit:
		return resolveDACommit(h.ctx.daView.Commit, id)
	case SimplicityTxContextDAViewChunk:
		return resolveDAChunk(h.ctx.daView.Chunk, id)
	default:
		return miss()
	}
}

func resolveDACommit(c SimplicityTxContextDACommitView, id uint16) simplicity.IntrinsicResult {
	switch id {
	case 0x0140:
		return read(b32v(c.DaID))
	case 0x0141:
		return read(uv(simplicity.ContextValueU16, uint64(c.ChunkCount)))
	case 0x0142:
		return read(b32v(c.RetlDomainID))
	case 0x0143:
		return read(uv(simplicity.ContextValueU64, c.BatchNumber))
	case 0x0144:
		return read(b32v(c.TxDataRoot))
	case 0x0145:
		return read(b32v(c.StateRoot))
	case 0x0146:
		return read(b32v(c.WithdrawalsRoot))
	default: // a chunk-view intrinsic read against a commit view is a miss
		return miss()
	}
}

func resolveDAChunk(k SimplicityTxContextDAChunkView, id uint16) simplicity.IntrinsicResult {
	switch id {
	case 0x0150:
		return read(b32v(k.DaID))
	case 0x0151:
		return read(uv(simplicity.ContextValueU16, uint64(k.ChunkIndex)))
	case 0x0152:
		return read(b32v(k.ChunkHash))
	default:
		return miss()
	}
}

// descriptorHash materializes the descriptor hash for ReadIntrinsic only. It uses a
// throwaway local meter (never the shared host meter), so it charges nothing on the host.
// An in-range access with a fresh meter and covenant-data-bounded descriptor length can
// never fault (DescriptorHashAccessCost stays << MaxExecCost), so a nil/absent result is
// always the Either-miss for an out-of-range index (E7 totality), not a swallowed host
// fault — the cost-overflow fault is reachable only on the IntrinsicCost accessor.
func (h *simplicityEvalHost) descriptorHash(input bool, index uint16) simplicity.IntrinsicResult {
	var (
		meter SimplicityTxContextMeter
		res   SimplicityTxContextDescriptorHashResult
		err   error
	)
	if input {
		res, err = h.ctx.InputDescriptorHash(index, &meter)
	} else {
		res, err = h.ctx.OutputDescriptorHash(index, &meter)
	}
	if err != nil || !res.Present {
		return miss()
	}
	return simplicity.IntrinsicResult{Value: b32v(res.Hash)}
}

// ── small value constructors (keep every resolver a one-liner) ──

func read(v simplicity.ContextValue) simplicity.IntrinsicResult {
	return simplicity.IntrinsicResult{Value: v}
}

func miss() simplicity.IntrinsicResult {
	return simplicity.IntrinsicResult{Failure: true}
}

func uv(kind simplicity.ContextValueKind, v uint64) simplicity.ContextValue {
	return simplicity.ContextValue{Kind: kind, Uint: v}
}

func b32v(v [32]byte) simplicity.ContextValue {
	return simplicity.ContextValue{Kind: simplicity.ContextValueBytes32, Bytes32: v}
}

func bytesv(v []byte) simplicity.ContextValue {
	return simplicity.ContextValue{Kind: simplicity.ContextValueBytes, Bytes: v}
}

func u128v(v Uint128) simplicity.ContextValue {
	return simplicity.ContextValue{Kind: simplicity.ContextValueU128, Uint128: simplicity.Uint128{Hi: v.Hi, Lo: v.Lo}}
}

func ioScalar(views []SimplicityTxContextIOView, index uint16, covenant bool) simplicity.IntrinsicResult {
	if int(index) >= len(views) {
		return miss()
	}
	if covenant {
		return read(uv(simplicity.ContextValueU16, uint64(views[index].CovenantType)))
	}
	return read(uv(simplicity.ContextValueU64, views[index].Value))
}

func groupValue(entries []SimplicityTxContextGroupEntry, index uint16) simplicity.IntrinsicResult {
	if int(index) >= len(entries) {
		return miss()
	}
	return read(uv(simplicity.ContextValueU64, entries[index].Value))
}

func groupState(entries []SimplicityTxContextGroupEntry, index uint16) simplicity.IntrinsicResult {
	if int(index) >= len(entries) {
		return miss()
	}
	return read(bytesv(entries[index].State))
}
