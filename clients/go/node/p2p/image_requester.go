package p2p

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
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
	errImageBackoff           = errors.New("image requester: round admission before the retry backoff ends")
)

// ImageAnchor names the committed UTXO image (RUBIN_L1_P2P_AUX.md Section 7.1).
type ImageAnchor struct {
	Height    uint64
	BlockHash [32]byte
	Root      [32]byte
}

// ImageUnits holds one positive limit per requester IMAGE unit (RUBIN_L1_P2P_AUX.md Sections 7.5 and 7.8). A session's
// request IDs start at 1 and strictly increase across the rounds of the Service, with no reuse or wrap. Retirement
// releases the current-assignment unit and Request the pending request bytes, once each; no other unit is released
// (RUBIN_L1_P2P_AUX.md Sections 6.1 and 7.5).
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

// ImageLimits holds the positive per-peer and round limits and durations captured by a round.
// Admission checks prospective charges without overflow and fixes D at min(start + AttemptLifetime, RD)
// (RUBIN_L1_P2P_AUX.md Sections 6.5 and 7.5).
type ImageLimits struct {
	PerPeer         ImageUnits
	Global          ImageUnits
	AttemptLifetime time.Duration
	RoundLifetime   time.Duration
	Backoff         time.Duration
}

// ImageRoundConfig is captured once by value by BeginImageRound; nothing renews the captured ctx, sources, limits or
// RD. SourceIDs are Service.peers keys, each resolved once to the connection it names. A nonzero NotBefore is the
// earliest round admission instant in the clock domain of ServiceConfig.Now; zero applies no backoff
// (RUBIN_L1_P2P_AUX.md Section 6.6).
type ImageRoundConfig struct {
	Anchor    ImageAnchor
	SourceIDs []string
	Limits    ImageLimits
	NotBefore time.Time
}

// ImageProbeRoundConfig supplies the original admission time, deadline and IMAGE limits of a body round.
type ImageProbeRoundConfig struct {
	Anchor            ImageAnchor
	SourceIDs         []string
	Limits            ImageLimits
	BodyAdmissionTime time.Time
	BodyRD            time.Time
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

// hasMonotonicReading reports whether t carries a monotonic clock reading.
func hasMonotonicReading(t time.Time) bool { return t != t.Round(0) }

type imageKey struct {
	anchor ImageAnchor
	start  [36]byte
}

type imageAttemptKey struct {
	start   [36]byte
	session *imageSession
}

// imageRequester holds captured live sessions and the current assignment per anchor and start.
// The Service closes drain when it publishes DRAINING. The registry is guarded by mu.
type imageRequester struct {
	mu       sync.Mutex
	sessions map[*imageSession]struct{}
	current  map[imageKey]*imageInstance
	drain    chan struct{}
}

func newImageRequester() *imageRequester {
	return &imageRequester{
		sessions: make(map[*imageSession]struct{}),
		current:  make(map[imageKey]*imageInstance),
		drain:    make(chan struct{}),
	}
}

// imageInstance is one admitted assignment; round is its value copy of the admitting round. Its mutable fields are
// guarded by imageRequester.mu; ref is the end appliers' only path to it and retirement clears it last.
type imageInstance struct {
	round            ImageRound
	session          *imageSession
	ctx              context.Context
	query            consensus.UTXOImageQuery
	expectedBodyHash [32]byte
	deadline         time.Time
	retired          bool
	end              error
	stopCtx          func() bool
	stopRound        func() bool
	timer            *time.Timer
	pendingHeld      bool
	published        bool
	ref              *atomic.Pointer[imageInstance]
	sendPhase        imageSendPhase
	staged           *imageOutcome
}

type imageSendPhase uint8

const (
	imageBeforeWrite imageSendPhase = iota
	imageWriting
	imageSent
)

// endAt returns the ctx error, else the round ctx error, else errImageExpired when now is after D, else nil.
func (inst *imageInstance) endAt(now time.Time) error {
	if err := inst.round.doneErr(inst.ctx); err != nil {
		return err
	}
	if now.After(inst.deadline) {
		return errImageExpired
	}
	return nil
}

// preWriteEnd returns the recorded end of a retired instance, else endAt, else errImageRoundDeadline at or after RD.
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

// ImageRound shares its assignments, accounting and local outcomes with its value copies.
// An anchor and start have at most one current assignment across the Service (RUBIN_L1_P2P_AUX.md Section 7.5).
type ImageRound struct {
	service       *Service
	ctx           context.Context
	anchor        ImageAnchor
	limits        ImageLimits
	sources       map[string]*imageSession
	admissionTime time.Time
	roundDeadline time.Time
	probe         bool
	*imageRoundUsage
}

// imageRoundUsage is the mutable state shared by every value copy of a round, guarded by the requester mutex.
type imageRoundUsage struct {
	global    imageUnitVector
	perPeer   map[*imageSession]*imageUnitVector
	attempted map[imageAttemptKey]struct{}
	starts    map[[36]byte]struct{}
	closed    bool
	wake      chan struct{}
	outcomes  map[[36]byte][]*imageOutcome
}

// BeginImageRound admits an acquisition round under one Service lease. Refusals, in order, return a nil round and fault
// no peer: errServiceClosed, errImageNilContext, errImageRequestDomain for a height above 0xffffffff, errImagePolicy
// for a zero limit or nonpositive duration, errImageSourceSet for an empty list, more IDs than live peer identifiers
// (before any table sized by the list) or an unknown, retired or duplicate source; then, after its one clock
// read, errServiceClosed once Close has moved the Service out of OPEN, errImagePolicy for an inexact RD or a nonzero
// NotBefore outside now's clock domain, and errImageBackoff when now is before a nonzero NotBefore. A done ctx is
// captured, not refused (RUBIN_L1_P2P_AUX.md Sections 6.6 and 7.5).
func (s *Service) BeginImageRound(ctx context.Context, config ImageRoundConfig) (*ImageRound, error) {
	if !s.acquireWork() {
		return nil, errServiceClosed
	}
	defer s.releaseWork()
	if err := checkImageRoundConfig(ctx, config.Anchor, config.Limits); err != nil {
		return nil, err
	}
	sources, err := s.resolveImageSources(config.SourceIDs)
	if err != nil {
		return nil, err
	}
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if err := checkImageSourcesLocked(sources); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	if !s.workAuthorized() {
		return nil, errServiceClosed
	}
	roundDeadline, err := roundAdmission(now, config)
	if err != nil {
		return nil, err
	}
	round := ImageRound{service: s, ctx: ctx, anchor: config.Anchor, limits: config.Limits, admissionTime: now, roundDeadline: roundDeadline}
	return req.captureImageRoundLocked(round, sources), nil
}

// BeginImageProbeRound captures the existing body round's context, sources, times and IMAGE limits
// (RUBIN_L1_P2P_AUX.md Section 7.8).
func (s *Service) BeginImageProbeRound(ctx context.Context, config ImageProbeRoundConfig) (*ImageRound, error) {
	if !s.acquireWork() {
		return nil, errServiceClosed
	}
	defer s.releaseWork()
	if err := checkImageRoundConfig(ctx, config.Anchor, config.Limits); err != nil {
		return nil, err
	}
	admission, deadline := config.BodyAdmissionTime, config.BodyRD
	if hasMonotonicReading(admission) != hasMonotonicReading(deadline) || admission.After(deadline) {
		return nil, errImagePolicy
	}
	sources, err := s.resolveImageSources(config.SourceIDs)
	if err != nil {
		return nil, err
	}
	round := ImageRound{
		service: s, ctx: ctx, anchor: config.Anchor, limits: config.Limits,
		admissionTime: admission, roundDeadline: deadline, probe: true,
	}
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if err := checkImageSourcesLocked(sources); err != nil {
		return nil, err
	}
	return req.captureImageRoundLocked(round, sources), nil
}

// captureImageRoundLocked captures stable identities for the validated source entries.
func (req *imageRequester) captureImageRoundLocked(round ImageRound, sources map[string]*peer) *ImageRound {
	round.sources = make(map[string]*imageSession, len(sources))
	for id, p := range sources {
		if p.imageSession == nil {
			p.imageSession = &imageSession{transport: p}
			req.sessions[p.imageSession] = struct{}{}
		}
		round.sources[id] = p.imageSession
	}
	round.imageRoundUsage = &imageRoundUsage{
		perPeer: make(map[*imageSession]*imageUnitVector), attempted: make(map[imageAttemptKey]struct{}),
		starts: make(map[[36]byte]struct{}),
	}
	return &round
}

// roundAdmission returns RD or the clock-domain and NotBefore refusal of now (RUBIN_L1_P2P_AUX.md Section 6.6).
func roundAdmission(now time.Time, config ImageRoundConfig) (time.Time, error) {
	roundDeadline, ok := exactDeadline(now, config.Limits.RoundLifetime)
	notBefore := config.NotBefore
	if !ok || !notBefore.IsZero() && hasMonotonicReading(notBefore) != hasMonotonicReading(now) {
		return time.Time{}, errImagePolicy
	}
	if !notBefore.IsZero() && now.Before(notBefore) {
		return time.Time{}, errImageBackoff
	}
	return roundDeadline, nil
}

func checkImageRoundConfig(ctx context.Context, anchor ImageAnchor, limits ImageLimits) error {
	if ctx == nil {
		return errImageNilContext
	}
	if anchor.Height > imageMaxHeight {
		return errImageRequestDomain
	}
	positiveDurations := limits.AttemptLifetime > 0 && limits.RoundLifetime > 0 && limits.Backoff > 0
	if !positiveDurations || !positiveUnits(limits.PerPeer.vector()) || !positiveUnits(limits.Global.vector()) {
		return errImagePolicy
	}
	return nil
}

// resolveImageSources observes the requested live peers in one read section and copies their names after it.
func (s *Service) resolveImageSources(ids []string) (map[string]*peer, error) {
	if len(ids) == 0 {
		return nil, errImageSourceSet
	}
	s.peersMu.RLock()
	if len(ids) > len(s.peers) || !imageSourcesLive(ids, s.peers) {
		s.peersMu.RUnlock()
		return nil, errImageSourceSet
	}
	observed := make(map[string]*peer, len(ids))
	for _, id := range ids {
		observed[id] = s.peers[id]
	}
	s.peersMu.RUnlock()
	return imageSources(ids, observed)
}

// imageSourcesLive bounds the requested list by live identifiers and checks its entries before allocation.
func imageSourcesLive(ids []string, peers map[string]*peer) bool {
	live := 0
	for _, p := range peers {
		if p != nil && !p.imageRetired.Load() {
			live++
		}
	}
	if len(ids) > live {
		return false
	}
	for _, id := range ids {
		if p := peers[id]; p == nil || p.imageRetired.Load() {
			return false
		}
	}
	return true
}

// imageSources keys each resolved connection by a copy of its ID; more IDs than entries refuse before any allocation.
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
		sources[strings.Clone(id)] = session
	}
	return sources, nil
}

// Request admits an ordinary assignment and sends its frame under one Service lease.
// Admission refusal returns a zero query. After admission the call returns the admitted query and send result
// (RUBIN_L1_P2P_AUX.md Sections 2.1 and 7.5).
func (r *ImageRound) Request(ctx context.Context, sourceID string, start [36]byte, byteLimit uint32) (consensus.UTXOImageQuery, error) {
	return r.request(ctx, sourceID, imageRequest{start: start, byteLimit: byteLimit})
}

// Probe admits a body-round assignment for the by-value expected body hash and sends the ordinary image request frame
// (RUBIN_L1_P2P_AUX.md Section 7.8).
func (r *ImageRound) Probe(ctx context.Context, sourceID string, start [36]byte, byteLimit uint32, expectedBodyHash [32]byte) (consensus.UTXOImageQuery, error) {
	return r.request(ctx, sourceID, imageRequest{start: start, byteLimit: byteLimit, probe: true, expectedBodyHash: expectedBodyHash})
}

type imageRequest struct {
	start            [36]byte
	byteLimit        uint32
	probe            bool
	expectedBodyHash [32]byte
}

func (r *ImageRound) request(ctx context.Context, sourceID string, attempt imageRequest) (consensus.UTXOImageQuery, error) {
	round := *r
	s := round.service
	if !s.acquireWork() {
		return consensus.UTXOImageQuery{}, errServiceClosed
	}
	defer s.releaseWork()
	inst, transport, payload, err := round.admit(ctx, sourceID, attempt)
	if err != nil {
		return consensus.UTXOImageQuery{}, err
	}
	return inst.query, inst.round.send(inst, transport, payload)
}

// checkRequestLocked refuses the closed round, source, mode and wire domain before the admission sample.
func (r *ImageRound) checkRequestLocked(sourceID string, attempt imageRequest) (*imageSession, error) {
	if r.closed {
		return nil, errImageRoundClosed
	}
	session := r.sources[sourceID]
	if session == nil {
		return nil, errImageUnknownSource
	}
	if session.transport == nil {
		return nil, errImageDisconnected
	}
	if r.probe != attempt.probe {
		return nil, errImageRoundMode
	}
	query := consensus.UTXOImageQuery{RequestID: 1, Height: r.anchor.Height, ByteLimit: attempt.byteLimit}
	if _, ok := consensus.EncodeUTXOImageRequest(query); !ok {
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

// admit linearizes one assignment after its clock sample, OPEN read and ordered refusal checks.
func (r *ImageRound) admit(ctx context.Context, sourceID string, attempt imageRequest) (*imageInstance, *peer, [imageRequestBytes]byte, error) {
	var payload [imageRequestBytes]byte
	if ctx == nil {
		return nil, nil, payload, errImageNilContext
	}
	if err := r.doneErr(ctx); err != nil {
		return nil, nil, payload, err
	}
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	session, err := r.checkRequestLocked(sourceID, attempt)
	if err != nil {
		return nil, nil, payload, err
	}
	now := r.service.cfg.Now()
	if !r.service.workAuthorized() {
		return nil, nil, payload, errServiceClosed
	}
	if err := r.doneErr(ctx); err != nil {
		return nil, nil, payload, err
	}
	for _, current := range req.current {
		req.retireIfEndedLocked(current, now)
	}
	inst, err := r.prepareLocked(ctx, now, session, attempt)
	if err != nil {
		return nil, nil, payload, err
	}
	r.commitLocked(inst, now)
	// The ID is at least 1 and the height and byte limit passed their checks.
	payload, _ = consensus.EncodeUTXOImageRequest(inst.query)
	return inst, session.transport, payload, nil
}

// prepareLocked runs the checks after the pass in order and builds the instance without mutating owner state.
func (r *ImageRound) prepareLocked(ctx context.Context, now time.Time, session *imageSession, attempt imageRequest) (*imageInstance, error) {
	deadline, err := r.attemptDeadline(now)
	if err != nil {
		return nil, err
	}
	if err := r.checkAssignableLocked(session, attempt.start); err != nil {
		return nil, err
	}
	last := session.lastID
	if last == imageMaxRequestID {
		return nil, errImageIDExhausted
	}
	query := consensus.UTXOImageQuery{
		RequestID: last + 1, Height: r.anchor.Height, BlockHash: r.anchor.BlockHash,
		Root: r.anchor.Root, StartKey: attempt.start, ByteLimit: attempt.byteLimit,
	}
	return &imageInstance{
		round: *r, session: session, ctx: ctx, query: query, deadline: deadline, expectedBodyHash: attempt.expectedBodyHash,
	}, nil
}

// attemptDeadline checks the original clock domain, cutoff and exact sum before capping the attempt.
func (r *ImageRound) attemptDeadline(now time.Time) (time.Time, error) {
	if r.probe && hasMonotonicReading(now) != hasMonotonicReading(r.admissionTime) {
		return time.Time{}, errImagePolicy
	}
	if !now.Before(r.roundDeadline) {
		return time.Time{}, errImageRoundDeadline
	}
	deadline, ok := exactDeadline(now, r.limits.AttemptLifetime)
	if !ok {
		return time.Time{}, errImagePolicy
	}
	if deadline.After(r.roundDeadline) {
		return r.roundDeadline, nil
	}
	return deadline, nil
}

func (r *ImageRound) checkAssignableLocked(session *imageSession, start [36]byte) error {
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

// admissionDelta is the per-peer and global charge of start; the per-peer distinct start is 1 because both callers run
// after the attempted check.
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

func (r *ImageRound) usageFor(session *imageSession) *imageUnitVector {
	if usage := r.perPeer[session]; usage != nil {
		return usage
	}
	return &imageUnitVector{}
}

type imageCancelLookup struct {
	key, value any
}

// imageCancelSignal schedules cancellation from a captured Done channel.
type imageCancelSignal struct {
	source context.Context
	done   <-chan struct{}
	lookup atomic.Pointer[imageCancelLookup]
}

func (c *imageCancelSignal) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *imageCancelSignal) Done() <-chan struct{}       { return c.done }

// Err preserves synchronous observation before the scheduler looks up the parent.
func (c *imageCancelSignal) Err() error {
	if c.lookup.Load() == nil {
		return c.source.Err()
	}
	select {
	case <-c.done:
		return context.Canceled
	default:
		return nil
	}
}

// Value saves the scheduler's parent lookup before it installs a callback.
func (c *imageCancelSignal) Value(key any) any {
	if lookup := c.lookup.Load(); lookup != nil {
		if key == lookup.key {
			return lookup.value
		}
		return nil
	}
	value := c.source.Value(key)
	c.lookup.Store(&imageCancelLookup{key: key, value: value})
	return value
}

type imageAfterFuncer interface {
	AfterFunc(func()) func() bool
}

type imageAfterFuncSignal struct {
	*imageCancelSignal
	imageAfterFuncer
}

// afterImageCancel retains the parent's optional scheduling and stop hooks.
func afterImageCancel(ctx context.Context, f func()) func() bool {
	return context.AfterFunc(imageCancellationContext(ctx), f)
}

func imageCancellationContext(ctx context.Context) context.Context {
	signal := &imageCancelSignal{source: ctx, done: ctx.Done()}
	if scheduler, ok := ctx.(imageAfterFuncer); ok {
		return imageAfterFuncSignal{signal, scheduler}
	}
	return signal
}

// commitLocked arms the ctx callbacks and the timer, each holding only inst.ref, then charges, allocates, registers and
// marks; an unwind while arming leaves no effect and clears inst.ref, so the armed callbacks find no instance.
func (r *ImageRound) commitLocked(inst *imageInstance, now time.Time) {
	ref := new(atomic.Pointer[imageInstance])
	ref.Store(inst)
	inst.ref = ref
	defer func() {
		if !inst.published {
			ref.Store(nil)
		}
	}()
	onCtx := func() { applyImageEnd(ref, false) }
	inst.stopCtx = afterImageCancel(inst.ctx, onCtx)
	inst.stopRound = afterImageCancel(r.ctx, onCtx)
	inst.timer = time.AfterFunc(imageTimerDuration(inst.deadline.Sub(now)), func() { applyImageEnd(ref, true) })
	req := r.service.imageRequester
	start := inst.query.StartKey
	perPeer, global := r.admissionDelta(start)
	usage := r.usageFor(inst.session)
	r.perPeer[inst.session] = usage
	usage.add(perPeer)
	r.global.add(global)
	inst.session.lastID = inst.query.RequestID
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

// applyImageEnd retires the instance ref holds, under a Service lease and the requester mutex, when it is published,
// not retired and ended; the timer acts only after D. Otherwise it reads no clock or ctx.
func applyImageEnd(ref *atomic.Pointer[imageInstance], byTimer bool) {
	inst := ref.Load()
	if inst == nil {
		return
	}
	s := inst.round.service
	if !s.acquireWork() {
		return
	}
	defer s.releaseWork()
	req := s.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if inst.retired || !inst.published {
		return
	}
	now := s.cfg.Now()
	if byTimer && !now.After(inst.deadline) {
		return
	}
	req.retireIfEndedLocked(inst, now)
}

// send resolves any staged outcome after writeRequest returns or unwinds.
func (r *ImageRound) send(inst *imageInstance, transport *peer, payload [imageRequestBytes]byte) (err error) {
	returned := false
	defer func() {
		r.finishSend(inst, returned && err == nil)
	}()
	err = r.writeRequest(inst, transport, payload)
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

// writeRequest writes only after the currency decision under writeMu
// (RUBIN_L1_P2P_AUX.md Section 2.1).
func (r *ImageRound) writeRequest(inst *imageInstance, transport *peer, payload [imageRequestBytes]byte) error {
	if acquired, end := r.lockImageWrite(inst, transport); !acquired {
		return end
	}
	writeErr := writeImageFrame(transport, payload)
	if writeErr != nil {
		defer r.closeAfterFailedWrite(inst, transport, writeErr)
	}
	return r.finishWrite(inst, writeErr)
}

// lockImageWrite can refuse while waiting. Only the check with writeMu held can authorize a write.
func (r *ImageRound) lockImageWrite(inst *imageInstance, transport *peer) (acquired bool, err error) {
	for !transport.writeMu.TryLock() {
		if end := r.endBeforeWrite(inst, false); end != nil {
			return false, end
		}
		time.Sleep(time.Millisecond)
	}
	defer func() {
		if !acquired {
			transport.writeMu.Unlock()
		}
	}()
	if end := r.endBeforeWrite(inst, true); end != nil {
		return false, end
	}
	return true, nil
}

// closeAfterFailedWrite releases pending bytes still held, records writeErr as the session's last error and closes the
// connection once, with no mutex held (RUBIN_L1_P2P_AUX.md Section 2.1).
func (r *ImageRound) closeAfterFailedWrite(inst *imageInstance, transport *peer, writeErr error) {
	r.releasePending(inst)
	transport.setLastError(writeErr.Error())
	_ = transport.conn.Close()
}

// writeImageFrame writes the request frame with writeMu held and releases writeMu when the write returns or unwinds.
func writeImageFrame(session *peer, payload [imageRequestBytes]byte) error {
	defer session.writeMu.Unlock()
	return session.writePostHandshakeFrame(messageGetUTXOImage, payload[:], time.Time{})
}

// endBeforeWrite records write authorization with writeMu held. A refusal releases the pending bytes.
func (r *ImageRound) endBeforeWrite(inst *imageInstance, holdsWrite bool) error {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	end := inst.preWriteEnd(r.service.cfg.Now())
	if end == nil {
		if holdsWrite {
			inst.sendPhase = imageWriting
		}
		return nil
	}
	req.retireLocked(inst, end)
	inst.releasePendingLocked()
	return end
}

// finishWrite returns nil for an instance retired during the write, else retires it on writeErr and returns writeErr;
// it releases the pending bytes last.
func (r *ImageRound) finishWrite(inst *imageInstance, writeErr error) error {
	req := r.service.imageRequester
	req.mu.Lock()
	defer req.mu.Unlock()
	if inst.retired {
		writeErr = nil
	} else if writeErr != nil {
		inst.sendPhase = imageBeforeWrite
		req.retireLocked(inst, writeErr)
	}
	inst.releasePendingLocked()
	return writeErr
}

// release subtracts amount of unit from r's usage on session and from r's global usage.
func (r *ImageRound) release(session *imageSession, unit int, amount uint64) {
	r.perPeer[session][unit] -= amount
	r.global[unit] -= amount
}

// retireIfEndedLocked retires inst once, recording endAt(now), when that is not nil.
func (req *imageRequester) retireIfEndedLocked(inst *imageInstance, now time.Time) {
	if end := inst.endAt(now); end != nil {
		req.retireLocked(inst, end)
	}
}

// retireLocked stops the end appliers, records end, deletes the registry entry, releases the current assignment and
// clears ref last; a stop that unwinds leaves the instance unretired.
func (req *imageRequester) retireLocked(inst *imageInstance, end error) {
	if inst.retired {
		return
	}
	inst.stopCtx()
	inst.stopRound()
	req.completeImageEndLocked(inst, end)
}
