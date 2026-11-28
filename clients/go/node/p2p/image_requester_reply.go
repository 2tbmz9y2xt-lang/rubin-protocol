package p2p

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var errImageHolderLimit = errors.New("image requester: verified range exceeds holder capacity")

// ImageAttribution identifies a verified response in its current body-round scope
// (RUBIN_L1_P2P_AUX.md Section 7.8).
type ImageAttribution struct {
	generation *imageGeneration
}

type imageQualificationKey struct {
	session  *imageSession
	bodyHash [32]byte
}

// imageGeneration carries publication and pending claims without retaining their owners.
type imageGeneration struct {
	pending   uint64
	published bool
}

func (g *imageGeneration) record(ready bool) {
	if ready {
		g.published = true
		return
	}
	g.pending++
}

// ValidFor reports current attribution for the supplied round, source, anchor and
// body hash. It takes no Service lease and has no admission effect.
func (a *ImageAttribution) ValidFor(supplied *ImageRound, sourceID string, anchor ImageAnchor, expectedBodyHash [32]byte) bool {
	if a == nil || a.generation == nil || supplied == nil {
		return false
	}
	round := *supplied
	if round.imageRoundUsage == nil || !round.probe {
		return false
	}
	req := round.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if !round.matchesImageAttributionLocked(a.generation, sourceID, anchor, expectedBodyHash) {
		return false
	}
	now := round.service.cfg.Now()
	return !now.After(round.roundDeadline) && round.service.workAuthorized()
}

// matchesImageAttributionLocked checks the exact captured scope of a generation.
func (r *ImageRound) matchesImageAttributionLocked(g *imageGeneration, sourceID string, anchor ImageAnchor, bodyHash [32]byte) bool {
	session := r.sources[sourceID]
	if r.closed || r.anchor != anchor || session == nil || session.transport == nil {
		return false
	}
	key := imageQualificationKey{session: session, bodyHash: bodyHash}
	return r.qualified[key] == g && r.ctx.Err() == nil
}

// qualifyImageReplyLocked selects the current generation at the successful comparison.
func (r *imageRoundUsage) qualifyImageReplyLocked(key imageQualificationKey) *ImageAttribution {
	if r.qualified == nil {
		r.qualified = make(map[imageQualificationKey]*imageGeneration)
	}
	generation := r.qualified[key]
	if generation == nil {
		generation = new(imageGeneration)
		r.qualified[key] = generation
	}
	return &ImageAttribution{generation: generation}
}

// publish releases the pending claim and makes the original record available to Receive.
func (o *imageOutcome) publish() {
	if o.result.Attribution != nil {
		g := o.result.Attribution.generation
		g.pending--
		g.published = true
	}
	o.ready = true
}

// dropImageGenerationLocked releases a provisional claim from the exact generation.
func (r *imageRoundUsage) dropImageGenerationLocked(o *imageOutcome) {
	if o.ready || o.result.Attribution == nil {
		return
	}
	g := o.result.Attribution.generation
	g.pending--
	if !g.published && g.pending == 0 && r.qualified[o.bodyKey] == g {
		delete(r.qualified, o.bodyKey)
	}
}

// discardImageOutcomeLocked clears the actual record and ends its charged ownership.
func (req *imageRequester) discardImageOutcomeLocked(o *imageOutcome) {
	owner := req.held[o]
	amount, session := o.holderBytes, o.bodyKey.session
	if owner != nil {
		owner.dropImageGenerationLocked(o)
	}
	*o = imageOutcome{}
	if owner != nil {
		owner.release(session, unitHolderBytes, amount)
		delete(req.held, o)
	}
}

// discardImageOutcomesLocked clears records still reachable from their senders.
func (r *ImageRound) discardImageOutcomesLocked() {
	req := r.service.imageRequester
	for _, queue := range r.outcomes {
		for _, outcome := range queue {
			req.discardImageOutcomeLocked(outcome)
		}
	}
	r.outcomes = nil
}

// handleOptionalImageReply accepts only requester reply commands on the worker's frame lease.
func (p *peer) handleOptionalImageReply(frame message) error {
	ceiling := imageReplyPayloadCap(frame.Command)
	if ceiling == 0 || p.service == nil || !p.service.cfg.EnableImageRequester {
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
	if uint64(len(frame.Payload)) <= uint64(ceiling) && len(frame.Payload) >= 8 {
		command, _ := encodeWireCommand(frame.Command)
		p.handleImageReply(command, frame.Payload)
	}
	return nil
}

// imageReplyWork holds transient decode and verification charges of one frame.
type imageReplyWork struct {
	peer        *peer
	inst        *imageInstance
	decodeBytes uint64
	proof       imageUnitVector
}

// handleImageReply completes the admitted phases under the original peer worker lease.
func (p *peer) handleImageReply(command [12]byte, payload []byte) {
	work := imageReplyWork{peer: p}
	defer work.release()
	id := binary.LittleEndian.Uint64(payload[:8])
	if !work.admitDecode(id, uint64(len(payload))) {
		return
	}
	reply, decoded, reason := consensus.DecodeUTXOImageReply(command, payload)
	if !work.classify(reply, decoded, reason) {
		return
	}
	rangeResult, verified, reason := consensus.VerifyUTXOImageChunk(reply)
	work.finishProof(rangeResult, verified, reason)
}

// admitDecode looks up the prefix on the actual registration before charging parse work.
func (w *imageReplyWork) admitDecode(id, n uint64) bool {
	req := w.peer.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	session := w.peer.imageSession
	if id == 0 || session == nil {
		return false
	}
	inst := session.currentByID[id]
	now, current := req.observeImageReplyLocked(w.peer, inst)
	if !current || !now.Before(inst.round.roundDeadline) {
		return false
	}
	delta := imageUnitVector{unitScalarProofWork: n, unitPasses: 1, unitCopies: 1, unitCopyHoldingBytes: n}
	if !inst.chargeImageReplyLocked(delta) {
		return false
	}
	w.inst, w.decodeBytes = inst, n
	return true
}

// observeImageReplyLocked checks membership and applies an observed local end before reply effects.
func (req *imageRequester) observeImageReplyLocked(p *peer, inst *imageInstance) (time.Time, bool) {
	if !req.imageReplyCurrentLocked(p, inst) {
		return time.Time{}, false
	}
	now := p.service.cfg.Now()
	if end := inst.endAt(now); end != nil {
		req.completeImageEndLocked(inst, end)
		return time.Time{}, false
	}
	if now.After(inst.round.roundDeadline) {
		req.completeImageEndLocked(inst, errImageExpired)
		return time.Time{}, false
	}
	return now, true
}

func (req *imageRequester) imageReplyCurrentLocked(p *peer, inst *imageInstance) bool {
	if inst == nil || inst.session.transport != p || inst.round.closed {
		return false
	}
	q := inst.query
	return inst.session.currentByID[q.RequestID] == inst && req.current[imageKey{inst.round.anchor, q.StartKey}] == inst
}

// chargeImageReplyLocked checks and applies per-source and aggregate deltas in the same span.
func (inst *imageInstance) chargeImageReplyLocked(delta imageUnitVector) bool {
	r := &inst.round
	perPeer := r.perPeer[inst.session]
	if !perPeer.fits(delta, r.limits.PerPeer.vector()) || !r.global.fits(delta, r.limits.Global.vector()) {
		return false
	}
	perPeer.add(delta)
	r.global.add(delta)
	return true
}

// classify applies the current source disposition or admits proof against the frozen query.
func (w *imageReplyWork) classify(reply consensus.UTXOImageReply, decoded bool, reason string) bool {
	req := w.peer.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	inst := w.inst
	now, current := req.observeImageReplyLocked(w.peer, inst)
	if !current {
		return false
	}
	command := reply.Command()
	switch {
	case !decoded:
		if reason != "" {
			req.completeImageReplyLocked(inst, reason, false)
		}
	case reply.Query() != inst.query:
		req.completeImageReplyLocked(inst, "image_identity", false)
	case string(command[:]) == messageUTXONotAvail:
		req.completeImageReplyLocked(inst, "", true)
	case reply.PayloadLength() > inst.query.ByteLimit:
		req.completeImageReplyLocked(inst, "image_count", false)
	default:
		return w.admitProofLocked(now)
	}
	return false
}

// completeImageReplyLocked records a classified response with no verified range.
func (req *imageRequester) completeImageReplyLocked(inst *imageInstance, diagnostic string, negative bool) {
	req.detachImageInstanceLocked(inst, nil)
	r := &inst.round
	if negative && r.probe {
		delete(r.qualified, imageQualificationKey{session: inst.session, bodyHash: inst.expectedBodyHash})
	}
	inst.recordOutcomeLocked(&imageOutcome{result: ImageResult{Diagnostic: diagnostic}})
	r.wakeImageWaitersLocked()
}

// admitProofLocked reserves the bounded verifier recipe before invoking the verifier.
func (w *imageReplyWork) admitProofLocked(now time.Time) bool {
	if !now.Before(w.inst.round.roundDeadline) {
		return false
	}
	delta := imageProofDelta(w.decodeBytes)
	if !w.inst.chargeImageReplyLocked(delta) {
		return false
	}
	w.proof = delta
	return true
}

// imageProofDelta uses the successful chunk layout's 129..2097152 byte envelope.
// The resulting bounds on leaves, edges and visits keep the arithmetic in uint64.
func imageProofDelta(n uint64) imageUnitVector {
	t, e := min(37447, (n-129)/56), min(576, (n-129)/34)
	h, frontier := uint64(1), uint64(1)
	if t+e > 1 {
		frontier += min(288, t+e-1)
	}
	if 2*t+e > 1 {
		h = 2*t + e - 1
	}
	return imageUnitVector{
		unitScalarProofWork:   11*n + 2048*h,
		unitHashes:            h,
		unitPasses:            6,
		unitCopies:            8*t + 2*e + 32*h + 8,
		unitProofHoldingBytes: 128*t + 40*e + 512*frontier + n,
		unitCopyHoldingBytes:  n,
	}
}

// finishProof compares the original assignment and transfers its verified backing once.
func (w *imageReplyWork) finishProof(result consensus.UTXOImageRange, verified bool, reason string) {
	var holderBytes uint64
	if verified {
		holderBytes = imageRangeHolderBytes(&result)
	}
	req := w.peer.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	inst := w.inst
	if _, current := req.observeImageReplyLocked(w.peer, inst); !current {
		return
	}
	if !verified {
		req.completeImageReplyLocked(inst, reason, false)
		return
	}
	req.detachImageInstanceLocked(inst, nil)
	outcome := req.holdImageRangeLocked(inst, &result, holderBytes)
	w.releaseLocked()
	inst.recordOutcomeLocked(outcome)
	inst.round.wakeImageWaitersLocked()
}

// imageRangeHolderBytes measures an independently owned verified range within the original frame bound.
func imageRangeHolderBytes(r *consensus.UTXOImageRange) uint64 {
	total := 128 + 128*uint64(len(r.Entries)) + 40*uint64(len(r.RightEdge))
	for i := range r.Entries {
		total += uint64(len(r.Entries[i].Entry.CovenantData))
	}
	if r.Predecessor != nil {
		total += 128 + uint64(len(r.Predecessor.Entry.CovenantData))
	}
	return total
}

// holdImageRangeLocked admits the verified backing in the finite outcome holder.
func (req *imageRequester) holdImageRangeLocked(inst *imageInstance, result *consensus.UTXOImageRange, n uint64) *imageOutcome {
	if !inst.chargeImageReplyLocked(imageUnitVector{unitHolderBytes: n}) {
		return &imageOutcome{end: errImageHolderLimit}
	}
	r := &inst.round
	key := imageQualificationKey{session: inst.session, bodyHash: inst.expectedBodyHash}
	o := &imageOutcome{result: ImageResult{Range: result}, bodyKey: key, holderBytes: n}
	if r.probe {
		o.result.Attribution = r.qualifyImageReplyLocked(key)
	}
	if req.held == nil {
		req.held = make(map[*imageOutcome]*imageRoundUsage)
	}
	req.held[o] = r.imageRoundUsage
	return o
}

// release ends only this frame's transient holdings, including on unwind.
func (w *imageReplyWork) release() {
	if w.decodeBytes == 0 {
		return
	}
	req := w.peer.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	w.releaseLocked()
}

func (w *imageReplyWork) releaseLocked() {
	inst := w.inst
	r := &inst.round
	r.release(inst.session, unitProofHoldingBytes, w.proof[unitProofHoldingBytes])
	r.release(inst.session, unitCopyHoldingBytes, w.decodeBytes)
	r.release(inst.session, unitCopyHoldingBytes, w.proof[unitCopyHoldingBytes])
	w.decodeBytes, w.proof = 0, imageUnitVector{}
}
