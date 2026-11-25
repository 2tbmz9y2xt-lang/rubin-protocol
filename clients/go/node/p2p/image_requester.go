package p2p

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	messageGetUTXOImage = "getutxoimg"
	imageRequestBytes   = 120
	imageMaxHeight      = 0xffffffff
	imageMaxRequestID   = ^uint64(0)
)

var (
	errImageNilContext        = errors.New("image requester: nil context")
	errImagePolicy            = errors.New("image requester: invalid local policy value")
	errImageSourceSet         = errors.New("image requester: invalid source set")
	errImageUnknownSource     = errors.New("image requester: source is not in the round")
	errImageRoundDeadline     = errors.New("image requester: no new work at or after the round deadline")
	errImageAssignmentCurrent = errors.New("image requester: anchor and start already have a current assignment")
	errImageAttempted         = errors.New("image requester: start already attempted on this session in this round")
	errImageLimit             = errors.New("image requester: captured limit refuses the prospective usage")
	errImageIDExhausted       = errors.New("image requester: request ID space of this session is exhausted")
	errImageRequestDomain     = errors.New("image requester: request outside the request domain")
	errImageExpired           = errors.New("image requester: attempt expired")
)

// ImageAnchor names the committed UTXO image (RUBIN_L1_P2P_AUX.md Section 7.1). A Service holds at most one current
// assignment per anchor and start, and a Request waits on no other session's frame write
// (RUBIN_L1_P2P_AUX.md Section 7.5).
type ImageAnchor struct {
	Height    uint64
	BlockHash [32]byte
	Root      [32]byte
}

// ImageUnits holds one finite positive limit per requester IMAGE unit (RUBIN_L1_P2P_AUX.md Section 7.5 and
// RUBIN_L1_P2P_AUX.md Section 7.8). Retirement releases an assignment's current-assignment unit, and its Request
// releases its pending request bytes once: at the pre-write refusal, after the write or on an unwind. Its request ID
// and its distinct-start, source-attempt and admitted-request units are never released; a session's request IDs start
// at 1 and strictly increase across the rounds of the Service, with no reuse or wrap
// (RUBIN_L1_P2P_AUX.md Section 6.1).
type ImageUnits struct {
	CurrentAssignments  uint64
	DistinctStarts      uint64
	SourceAttempts      uint64
	AdmittedRequests    uint64
	ScalarProofWork     uint64
	Hashes              uint64
	Passes              uint64
	Copies              uint64
	PendingNetworkBytes uint64
	ProofHoldingBytes   uint64
	CopyHoldingBytes    uint64
	HolderBytes         uint64
}

// ImageLimits are the per-peer and round-global limits and the positive durations a round captures by value
// (RUBIN_L1_P2P_AUX.md Section 6.5). A Request is admitted only when its round's own usage plus the charge fits each
// per-peer limit on the session and each global limit on the round's sources, without overflow; a release decrements
// the round that admitted the assignment. An assignment's D = min(now + AttemptLifetime, RD) is fixed at admission. A
// done ctx, a done round ctx or now after D ends it once, recorded in that precedence as the ctx error, the round ctx
// error or errImageExpired, when seen under the requester mutex with a Service lease by its Request, a later
// Request's pass, its ctx or round ctx callback or its deadline timer, which acts only after D and is not re-armed
// (RUBIN_L1_P2P_AUX.md Section 7.5).
type ImageLimits struct {
	PerPeer         ImageUnits
	Global          ImageUnits
	AttemptLifetime time.Duration
	RoundLifetime   time.Duration
	Backoff         time.Duration
}

// ImageRoundConfig is the input of BeginImageRound, which captures it once by value; nothing renews the captured ctx,
// sources, limits or RD. SourceIDs are Service.peers keys; each resolves once to the exact connection it names.
type ImageRoundConfig struct {
	Anchor    ImageAnchor
	SourceIDs []string
	Limits    ImageLimits
}

const (
	unitCurrentAssignments = iota
	unitDistinctStarts
	unitSourceAttempts
	unitAdmittedRequests
	unitPendingNetworkBytes = 8
	imageUnitCount          = 12
)

type imageUnitVector [imageUnitCount]uint64

func (u ImageUnits) vector() imageUnitVector {
	return imageUnitVector{
		u.CurrentAssignments, u.DistinctStarts, u.SourceAttempts, u.AdmittedRequests,
		u.ScalarProofWork, u.Hashes, u.Passes, u.Copies, u.PendingNetworkBytes,
		u.ProofHoldingBytes, u.CopyHoldingBytes, u.HolderBytes,
	}
}

// fits reports used+delta <= limit for every unit without overflow.
func (used *imageUnitVector) fits(delta, limit imageUnitVector) bool {
	for i := range used {
		if delta[i] > limit[i] || used[i] > limit[i]-delta[i] {
			return false
		}
	}
	return true
}

func (used *imageUnitVector) add(delta imageUnitVector) {
	for i := range used {
		used[i] += delta[i]
	}
}

func positiveUnits(u imageUnitVector) bool {
	for _, value := range u {
		if value == 0 {
			return false
		}
	}
	return true
}

// exactDeadline returns now+d and reports whether the sum is exact in now's clock domain: the wall sum did not
// saturate and a monotonic reading of now, when present, is kept (RUBIN_L1_P2P_AUX.md Section 6.5).
func exactDeadline(now time.Time, d time.Duration) (time.Time, bool) {
	deadline := now.Add(d)
	wallExact := deadline.Round(0).Sub(now.Round(0)) == d
	return deadline, wallExact && hasMonotonicReading(deadline) == hasMonotonicReading(now)
}

// hasMonotonicReading reports whether t carries a monotonic clock reading; Round(0) strips
// only that reading and == compares it.
func hasMonotonicReading(t time.Time) bool { return t != t.Round(0) }

type imageKey struct {
	anchor ImageAnchor
	start  [36]byte
}

type imageAttemptKey struct {
	start   [36]byte
	session *peer
}

// imageRequester is the Service-wide registry: the last request ID per session
// and the one current assignment per anchor and start. Guarded by mu.
type imageRequester struct {
	mu      sync.Mutex
	lastID  map[*peer]uint64
	current map[imageKey]*imageInstance
}

func newImageRequester() *imageRequester {
	return &imageRequester{lastID: make(map[*peer]uint64), current: make(map[imageKey]*imageInstance)}
}

// imageInstance is one admitted assignment. round is its own value copy of the admitting round, through which its end
// appliers and its write path reach that round. published, retired, end, pendingHeld and the stop handles are guarded
// by imageRequester.mu; published reports that admission charged, allocated and registered it, end is the error of
// the end that retired it and pendingHeld reports that its pending request bytes are still charged.
type imageInstance struct {
	round       ImageRound
	session     *peer
	ctx         context.Context
	query       consensus.UTXOImageQuery
	deadline    time.Time
	retired     bool
	end         error
	stopCtx     func() bool
	stopRound   func() bool
	timer       *time.Timer
	pendingHeld bool
	published   bool
}

// endAt returns, without reading whether inst is retired, its ctx error, else its round ctx
// error, else errImageExpired when now is after D, else nil.
func (inst *imageInstance) endAt(now time.Time) error {
	if err := inst.round.doneErr(inst.ctx); err != nil {
		return err
	}
	if now.After(inst.deadline) {
		return errImageExpired
	}
	return nil
}

// preWriteEnd is the currency decision of the writeMu wait and of the pre-write decision: the recorded end of a
// retired instance, else endAt, else errImageRoundDeadline at or after RD.
func (inst *imageInstance) preWriteEnd(now time.Time) error {
	if inst.retired {
		return inst.end
	}
	if err := inst.endAt(now); err != nil {
		return err
	}
	if !now.Before(inst.round.roundDeadline) {
		return errImageRoundDeadline
	}
	return nil
}

// ImageRound is one admitted acquisition round; a value copy is that round. A Request's last currency decision, under
// the session's writeMu right before the write, is the frame's last check: an ended assignment, or now at RD
// (errImageRoundDeadline), gets no frame and the admitted query with the end's error; an end applied during the write
// does not stop it and leaves the admitted query and nil, otherwise a failed write returns the admitted query and its
// error and retires the assignment; once that outcome is fixed, with no mutex held, Request sets a failed write's
// error as the session's last error and closes its connection once. An unwind of Request after admission releases the
// writeMu and pending request bytes it holds, once each, retires nothing and propagates unchanged; after a failed
// write it also sets the last error and closes once (RUBIN_L1_P2P_AUX.md Section 7.5).
type ImageRound struct {
	service       *Service
	ctx           context.Context
	anchor        ImageAnchor
	limits        ImageLimits
	sources       map[string]*peer
	roundDeadline time.Time
	*imageRoundUsage
}

// imageRoundUsage is the mutable state of one round, which every value copy of the round shares; the Service
// requester mutex guards it.
type imageRoundUsage struct {
	global    imageUnitVector
	perPeer   map[*peer]*imageUnitVector
	attempted map[imageAttemptKey]struct{}
	starts    map[[36]byte]struct{}
}

// BeginImageRound admits an acquisition round under one Service lease. Refusals, in order, return a nil round and
// fault no peer: errServiceClosed, errImageNilContext, errImageRequestDomain for a height above 0xffffffff,
// errImagePolicy for a zero limit or nonpositive duration, errImageSourceSet for an empty source list, more sources
// than Service.peers entries (decided before any table sized by the list is allocated) or a source with no entry or
// resolving to a listed connection; then, right after its one clock read, errServiceClosed once Close has moved the
// Service out of OPEN and errImagePolicy for an RD = now + RoundLifetime that is not exact. A done ctx is captured,
// not refused. Its Requests for different starts can hold assignments on several sources at once, none waiting behind
// another (RUBIN_L1_P2P_AUX.md Section 7.5).
func (s *Service) BeginImageRound(ctx context.Context, config ImageRoundConfig) (*ImageRound, error) {
	if !s.acquireWork() {
		return nil, errServiceClosed
	}
	defer s.releaseWork()
	if err := checkImageRoundConfig(ctx, config); err != nil {
		return nil, err
	}
	sources, err := s.resolveImageSources(config.SourceIDs)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	if !s.workAuthorized() {
		return nil, errServiceClosed
	}
	roundDeadline, ok := exactDeadline(now, config.Limits.RoundLifetime)
	if !ok {
		return nil, errImagePolicy
	}
	return &ImageRound{
		service: s, ctx: ctx, anchor: config.Anchor, limits: config.Limits,
		sources: sources, roundDeadline: roundDeadline, imageRoundUsage: &imageRoundUsage{
			perPeer: make(map[*peer]*imageUnitVector), attempted: make(map[imageAttemptKey]struct{}),
			starts: make(map[[36]byte]struct{}),
		},
	}, nil
}

func checkImageRoundConfig(ctx context.Context, config ImageRoundConfig) error {
	if ctx == nil {
		return errImageNilContext
	}
	if config.Anchor.Height > imageMaxHeight {
		return errImageRequestDomain
	}
	limits := config.Limits
	if !positiveUnits(limits.PerPeer.vector()) || !positiveUnits(limits.Global.vector()) ||
		!positiveDurations(limits.AttemptLifetime, limits.RoundLifetime, limits.Backoff) {
		return errImagePolicy
	}
	return nil
}

func positiveDurations(durations ...time.Duration) bool {
	for _, d := range durations {
		if d <= 0 {
			return false
		}
	}
	return true
}

// resolveImageSources copies Service.peers in one read section that decides nothing and, after that section,
// resolves the source IDs against the copy with imageSources (RUBIN_L1_P2P_AUX.md Section 5).
func (s *Service) resolveImageSources(ids []string) (map[string]*peer, error) {
	if len(ids) == 0 {
		return nil, errImageSourceSet
	}
	s.peersMu.RLock()
	peers := make(map[string]*peer, len(s.peers))
	for id, session := range s.peers {
		peers[id] = session
	}
	s.peersMu.RUnlock()
	return imageSources(ids, peers)
}

// imageSources resolves every source ID through peers into a new map of those IDs: more IDs than peers entries
// refuse before any table is allocated; an ID with no entry or naming an already resolved connection refuses too.
func imageSources(ids []string, peers map[string]*peer) (map[string]*peer, error) {
	if len(ids) > len(peers) {
		return nil, errImageSourceSet
	}
	sources := make(map[string]*peer, len(ids))
	seen := make(map[*peer]struct{}, len(ids))
	for _, id := range ids {
		session := peers[id]
		if _, dup := seen[session]; session == nil || dup {
			return nil, errImageSourceSet
		}
		seen[session] = struct{}{}
		sources[id] = session
	}
	return sources, nil
}

// Request admits one assignment for start on source sourceID of the round *r holds at entry and writes its getutxoimg
// frame, holding one Service lease until it returns. Admission, the only request-ID allocator, arms its ctx callbacks
// and timer before it charges, allocates or registers and is all-or-nothing: a refusal, with a zero query, or an
// unwind while arming adds no ID, registry entry, charge or mark, faults no peer and retires only ended assignments,
// by the pass. Refusals, in order: errServiceClosed, errImageNilContext, the ctx's then the round ctx's Err(),
// errImageUnknownSource, errImageRequestDomain; under the requester mutex after the clock read dating admission,
// errServiceClosed, the two Err() reads, then after the pass errImageRoundDeadline at or after RD, errImagePolicy for
// an inexact now + AttemptLifetime, errImageAssignmentCurrent, errImageAttempted, errImageLimit, errImageIDExhausted.
func (r *ImageRound) Request(ctx context.Context, sourceID string, start [36]byte, byteLimit uint32) (consensus.UTXOImageQuery, error) {
	round := *r
	s := round.service
	if !s.acquireWork() {
		return consensus.UTXOImageQuery{}, errServiceClosed
	}
	defer s.releaseWork()
	inst, payload, err := round.admit(ctx, sourceID, start, byteLimit)
	if err != nil {
		return consensus.UTXOImageQuery{}, err
	}
	return inst.query, inst.round.send(inst, payload)
}

// checkRequest runs the refusals that need no registry state.
func (r *ImageRound) checkRequest(ctx context.Context, sourceID string, byteLimit uint32) (*peer, error) {
	if ctx == nil {
		return nil, errImageNilContext
	}
	if err := r.doneErr(ctx); err != nil {
		return nil, err
	}
	session := r.sources[sourceID]
	if session == nil {
		return nil, errImageUnknownSource
	}
	probe := consensus.UTXOImageQuery{RequestID: 1, Height: r.anchor.Height, ByteLimit: byteLimit}
	if _, ok := consensus.EncodeUTXOImageRequest(probe); !ok {
		return nil, errImageRequestDomain
	}
	return session, nil
}

// doneErr returns the error of ctx when it is done, else the error of the round ctx.
func (r *ImageRound) doneErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.ctx.Err()
}

func (r *ImageRound) admit(ctx context.Context, sourceID string, start [36]byte, byteLimit uint32) (*imageInstance, [imageRequestBytes]byte, error) {
	var payload [imageRequestBytes]byte
	session, err := r.checkRequest(ctx, sourceID, byteLimit)
	if err != nil {
		return nil, payload, err
	}
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	now := r.service.cfg.Now()
	if !r.service.workAuthorized() {
		return nil, payload, errServiceClosed
	}
	if err := r.doneErr(ctx); err != nil {
		return nil, payload, err
	}
	req.retireEndedLocked(now)
	inst, err := r.prepareLocked(ctx, now, session, start, byteLimit)
	if err != nil {
		return nil, payload, err
	}
	r.commitLocked(inst, now)
	// The ID is at least 1 and the height and byte limit passed their checks.
	payload, _ = consensus.EncodeUTXOImageRequest(inst.query)
	return inst, payload, nil
}

// prepareLocked runs the round-deadline, attempt-deadline, current-assignment, attempted,
// limit and ID checks in that order and builds the instance without mutating any owner state.
func (r *ImageRound) prepareLocked(ctx context.Context, now time.Time, session *peer, start [36]byte, byteLimit uint32) (*imageInstance, error) {
	if !now.Before(r.roundDeadline) {
		return nil, errImageRoundDeadline
	}
	deadline, ok := exactDeadline(now, r.limits.AttemptLifetime)
	if !ok {
		return nil, errImagePolicy
	}
	if err := r.checkAssignableLocked(session, start); err != nil {
		return nil, err
	}
	last := r.service.imageRequester.lastID[session]
	if last == imageMaxRequestID {
		return nil, errImageIDExhausted
	}
	if deadline.After(r.roundDeadline) {
		deadline = r.roundDeadline
	}
	query := consensus.UTXOImageQuery{
		RequestID: last + 1, Height: r.anchor.Height, BlockHash: r.anchor.BlockHash,
		Root: r.anchor.Root, StartKey: start, ByteLimit: byteLimit,
	}
	return &imageInstance{round: *r, session: session, ctx: ctx, query: query, deadline: deadline}, nil
}

func (r *ImageRound) checkAssignableLocked(session *peer, start [36]byte) error {
	if _, busy := r.service.imageRequester.current[imageKey{r.anchor, start}]; busy {
		return errImageAssignmentCurrent
	}
	if _, done := r.attempted[imageAttemptKey{start, session}]; done {
		return errImageAttempted
	}
	perPeer, global := r.admissionDelta(start)
	if !r.usageFor(session).fits(perPeer, r.limits.PerPeer.vector()) || !r.global.fits(global, r.limits.Global.vector()) {
		return errImageLimit
	}
	return nil
}

// admissionDelta is the per-peer and global charge of admitting start: one current assignment, source attempt and
// admitted request, the request bytes, and one distinct start, globally only for the round's first admission of
// start. The per-peer distinct start is always one: both callers run after the attempted check, so start has no
// earlier admission on that session in the round.
func (r *ImageRound) admissionDelta(start [36]byte) (imageUnitVector, imageUnitVector) {
	perPeer := imageUnitVector{
		unitCurrentAssignments: 1, unitDistinctStarts: 1, unitSourceAttempts: 1, unitAdmittedRequests: 1,
		unitPendingNetworkBytes: imageRequestBytes,
	}
	global := perPeer
	if _, admitted := r.starts[start]; admitted {
		global[unitDistinctStarts] = 0
	}
	return perPeer, global
}

func (r *ImageRound) usageFor(session *peer) *imageUnitVector {
	if usage := r.perPeer[session]; usage != nil {
		return usage
	}
	return &imageUnitVector{}
}

// commitLocked arms the instance's ctx callback, its round ctx callback and its deadline timer, in that order, and
// only then charges, allocates the ID, registers the instance and marks the start attempted and admitted, in one
// linearization with the checks of prepareLocked. When arming unwinds, nothing is charged, allocated, registered or
// marked, and a callback already armed finds the instance unpublished and changes nothing.
func (r *ImageRound) commitLocked(inst *imageInstance, now time.Time) {
	s := r.service
	onCtx := func() { s.applyImageEnd(inst, false) }
	inst.stopCtx = context.AfterFunc(inst.ctx, onCtx)
	inst.stopRound = context.AfterFunc(r.ctx, onCtx)
	inst.timer = time.AfterFunc(imageTimerDuration(inst.deadline.Sub(now)), func() { s.applyImageEnd(inst, true) })
	req := s.imageRequester
	start := inst.query.StartKey
	perPeer, global := r.admissionDelta(start)
	usage := r.usageFor(inst.session)
	r.perPeer[inst.session] = usage
	usage.add(perPeer)
	r.global.add(global)
	req.lastID[inst.session] = inst.query.RequestID
	req.current[imageKey{r.anchor, start}] = inst
	r.attempted[imageAttemptKey{start, inst.session}] = struct{}{}
	r.starts[start] = struct{}{}
	inst.pendingHeld = true
	inst.published = true
}

// imageTimerDuration returns untilDeadline plus 1ns, saturating at the largest Duration.
func imageTimerDuration(untilDeadline time.Duration) time.Duration {
	if untilDeadline == math.MaxInt64 {
		return untilDeadline
	}
	return untilDeadline + 1
}

// applyImageEnd is the body of the Request-ctx callback, the round-ctx callback (byTimer false) and the deadline
// timer (byTimer true) of one instance. With a Service lease, under the requester mutex and with one now read, it
// retires a published, not yet retired instance whose ctx or round ctx is done or whose D is before now, once,
// recording endAt(now). The timer does nothing when now is not after D and is not re-armed. A refused lease or an
// unpublished instance changes nothing and reads no clock.
func (s *Service) applyImageEnd(inst *imageInstance, byTimer bool) {
	if !s.acquireWork() {
		return
	}
	defer s.releaseWork()
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if !inst.published {
		return
	}
	now := s.cfg.Now()
	if byTimer && !now.After(inst.deadline) {
		return
	}
	req.retireIfEndedLocked(inst, now)
}

// send runs writeRequest; when writeRequest unwinds, send releases the instance's pending request bytes not yet
// released, once, after writeRequest has released the writeMu it held, if it held writeMu, and the unwind propagates.
func (r *ImageRound) send(inst *imageInstance, payload [imageRequestBytes]byte) error {
	returned := false
	defer func() {
		if !returned {
			r.releasePending(inst)
		}
	}()
	err := r.writeRequest(inst, payload)
	returned = true
	return err
}

// releasePending releases the instance's pending request bytes once under the requester mutex.
func (r *ImageRound) releasePending(inst *imageInstance) {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	inst.releasePendingLocked()
}

// releasePendingLocked releases the instance's pending request bytes in its own round once.
func (inst *imageInstance) releasePendingLocked() {
	if inst.pendingHeld {
		inst.pendingHeld = false
		inst.round.release(inst.session, unitPendingNetworkBytes, imageRequestBytes)
	}
}

// writeRequest waits for the session's writeMu, taking the currency decision at every failed
// attempt and once more under writeMu, then writes the frame with only its own frame
// deadlines, none derived from D, RD or a ctx (RUBIN_L1_P2P_AUX.md Section 2.1). After a failed
// write it runs closeAfterFailedWrite once the post-write section returns or unwinds.
func (r *ImageRound) writeRequest(inst *imageInstance, payload [imageRequestBytes]byte) error {
	session := inst.session
	stop := func() (bool, error) {
		end := r.endBeforeWrite(inst)
		return end != nil, end
	}
	if acquired, end := session.lockWriteUnless(stop); !acquired {
		return end
	}
	writeErr := writeImageFrame(session, payload)
	if writeErr != nil {
		defer r.closeAfterFailedWrite(inst, writeErr)
	}
	return r.finishWrite(inst, writeErr)
}

// closeAfterFailedWrite releases the instance's pending request bytes not yet released, then records writeErr as the
// session's last error and closes its connection once. It runs with neither writeMu nor the requester mutex held,
// after the post-write section returns or while it unwinds (RUBIN_L1_P2P_AUX.md Section 2.1).
func (r *ImageRound) closeAfterFailedWrite(inst *imageInstance, writeErr error) {
	r.releasePending(inst)
	inst.session.setLastError(writeErr.Error())
	_ = inst.session.conn.Close()
}

// writeImageFrame writes the request frame with writeMu held and releases writeMu when the
// write returns or unwinds.
func writeImageFrame(session *peer, payload [imageRequestBytes]byte) error {
	defer session.writeMu.Unlock()
	return session.writePostHandshakeFrame(messageGetUTXOImage, payload[:], time.Time{})
}

// endBeforeWrite returns nil while the instance may be written; otherwise it retires the
// instance once, releases its pending request bytes and returns the end's error.
func (r *ImageRound) endBeforeWrite(inst *imageInstance) error {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	end := inst.preWriteEnd(r.service.cfg.Now())
	if end == nil {
		return nil
	}
	req.retireLocked(inst, end)
	inst.releasePendingLocked()
	return end
}

// finishWrite is the post-write section: it returns nil when the instance is already retired as it takes the
// requester mutex, which an end applied after the pre-write decision does; otherwise it retires the instance on a
// write failure and returns writeErr. It releases the pending request bytes once, after that retirement.
func (r *ImageRound) finishWrite(inst *imageInstance, writeErr error) error {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if inst.retired {
		inst.releasePendingLocked()
		return nil
	}
	if writeErr != nil {
		req.retireLocked(inst, writeErr)
	}
	inst.releasePendingLocked()
	return writeErr
}

// release subtracts amount of unit from r's usage on session and from r's global usage. Its
// callers pass only the current-assignment and pending-request-byte units of an instance of r.
func (r *ImageRound) release(session *peer, unit int, amount uint64) {
	r.perPeer[session][unit] -= amount
	r.global[unit] -= amount
}

// retireEndedLocked retires every registered instance of the Service that has ended by
// now, recording its end.
func (req *imageRequester) retireEndedLocked(now time.Time) {
	for _, inst := range req.current {
		req.retireIfEndedLocked(inst, now)
	}
}

// retireIfEndedLocked retires inst once, recording endAt(now), when that is not nil.
func (req *imageRequester) retireIfEndedLocked(inst *imageInstance, now time.Time) {
	if end := inst.endAt(now); end != nil {
		req.retireLocked(inst, end)
	}
}

// retireLocked retires exactly that instance once: it stops its ctx callback, its round ctx
// callback and its deadline timer, then records end, deletes its registry entry and releases its
// current assignment in its own round. When a stop call unwinds, the instance stays unretired,
// registered and charged, with no end recorded; a later call has no effect once it is retired.
func (req *imageRequester) retireLocked(inst *imageInstance, end error) {
	if inst.retired {
		return
	}
	inst.stopCtx()
	inst.stopRound()
	inst.timer.Stop()
	inst.retired, inst.end = true, end
	delete(req.current, imageKey{inst.round.anchor, inst.query.StartKey})
	inst.round.release(inst.session, unitCurrentAssignments, 1)
}
