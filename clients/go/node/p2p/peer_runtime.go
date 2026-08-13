package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

type postHandshakeUnknownCommandError struct {
	command string
}

func (e postHandshakeUnknownCommandError) Error() string {
	return fmt.Sprintf("unknown message type: %s", e.command)
}

func (e postHandshakeUnknownCommandError) peerReason() string {
	return fmt.Sprintf("unknown command: %s", e.command)
}

type blockTxnStaleBodyError struct{}

func (e blockTxnStaleBodyError) Error() string {
	return "stale blocktxn response has body"
}

var errLateBlockTxnIgnored = errors.New("ignored late blocktxn response")

type postHandshakeFrameTiming struct {
	peer             *peer
	frameStart       time.Time
	lastProgress     time.Time
	absoluteDeadline time.Time
	payloadSize      uint32
	bytesRead        int
	validated        bool
	deadlineErr      error
}

func (t *postHandshakeFrameTiming) beforeRead() error {
	if t.deadlineErr != nil {
		return t.deadlineErr
	}
	if t.frameStart.IsZero() {
		return nil
	}
	return t.armReadDeadline(true)
}

func (t *postHandshakeFrameTiming) recordRead(n int) {
	if n <= 0 {
		return
	}
	now := time.Now()
	if t.frameStart.IsZero() {
		t.frameStart = now
	}
	t.lastProgress = now
	t.bytesRead += n
	if err := t.armReadDeadline(true); err != nil {
		t.deadlineErr = err
	}
}

func (t *postHandshakeFrameTiming) validatePayload(size uint32) error {
	if t.deadlineErr != nil {
		return t.deadlineErr
	}
	if t.validated {
		return nil
	}
	now := time.Now()
	if frameDeadlineExpired(now, t.frameStart.Add(frameMinimumBudget)) {
		return t.timeoutError("header", wireHeaderSize)
	}
	t.payloadSize = size
	t.absoluteDeadline = t.frameStart.Add(frameBudgetDuration(uint64(size)))
	t.validated = true
	if frameDeadlineExpired(now, t.absoluteDeadline) {
		return t.timeoutError("payload", wireHeaderSize+int(size))
	}
	return t.armReadDeadline(true)
}

func (t *postHandshakeFrameTiming) finishHeader(err error) error {
	if err != nil && t.bytesRead < wireHeaderSize {
		return err
	}
	if t.deadlineErr != nil {
		return t.deadlineErr
	}
	if frameDeadlineExpired(time.Now(), t.frameStart.Add(frameMinimumBudget)) {
		return t.timeoutError("header", wireHeaderSize)
	}
	return err
}

func (t *postHandshakeFrameTiming) complete() error {
	if t.deadlineErr != nil {
		return t.deadlineErr
	}
	if t.validated && frameDeadlineExpired(time.Now(), t.absoluteDeadline) {
		return t.timeoutError("payload", wireHeaderSize+int(t.payloadSize))
	}
	return nil
}

func (t *postHandshakeFrameTiming) finishPayload(err error) error {
	if t.deadlineErr != nil || err == nil || t.validated && t.bytesRead >= wireHeaderSize+int(t.payloadSize) {
		if deadlineErr := t.complete(); deadlineErr != nil {
			return deadlineErr
		}
	}
	return err
}

func (t *postHandshakeFrameTiming) armReadDeadline(includeCompact bool) error {
	deadline := t.transportDeadline()
	if frameDeadlineExpired(time.Now(), deadline) {
		part, want := "header", wireHeaderSize
		if t.validated {
			part, want = "payload", wireHeaderSize+int(t.payloadSize)
		}
		return t.timeoutError(part, want)
	}
	if includeCompact {
		if expiry, ok := t.peer.compactOutstandingExpiry(); ok {
			remaining := expiry.Sub(t.peer.service.cfg.Now())
			compactDeadline := time.Now()
			if remaining > 0 {
				compactDeadline = compactDeadline.Add(remaining)
			}
			deadline = earlierDeadline(deadline, compactDeadline)
		}
	}
	return t.peer.conn.SetReadDeadline(deadline)
}

func (t *postHandshakeFrameTiming) transportDeadline() time.Time {
	stallDeadline := t.lastProgress.Add(boundedFrameStallBudget(t.peer.service.cfg.PeerRuntimeConfig.ReadDeadline))
	if !t.validated {
		return earlierDeadline(t.frameStart.Add(frameMinimumBudget), stallDeadline)
	}
	return earlierDeadline(t.absoluteDeadline, stallDeadline)
}

func (t *postHandshakeFrameTiming) timeoutError(part string, want int) error {
	return partialFrameTimeoutError{part: part, read: t.bytesRead, want: want, err: os.ErrDeadlineExceeded}
}

const frameMinimumBudget = time.Duration(frameMinimumBudgetMS) * time.Millisecond

func frameDeadlineExpired(now, deadline time.Time) bool { return now.After(deadline) }

func frameBudgetDuration(size uint64) time.Duration {
	budgetMS := absoluteBudgetMS(size)
	if budgetMS > uint64(math.MaxInt64)/uint64(time.Millisecond) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(budgetMS) * time.Millisecond
}

func earlierDeadline(a, b time.Time) time.Time {
	if b.IsZero() || (!a.IsZero() && !b.Before(a)) {
		return a
	}
	return b
}

func boundedFrameStallBudget(configured time.Duration) time.Duration {
	if configured > 0 && configured < frameMinimumBudget {
		return configured
	}
	return frameMinimumBudget
}

func (p *peer) run(ctx context.Context) error {
	var lateBlockTxn *compactOutstandingRequest
	recordExpiredFallback := func() error {
		expired, err := p.sendExpiredCompactOutstandingFallback(ctx)
		if err != nil {
			return err
		}
		if expired != nil {
			lateBlockTxn = expired
		}
		return nil
	}
	// #lizard forgive
	for {
		if peerRunContextDone(ctx) {
			return nil
		}
		if err := recordExpiredFallback(); err != nil {
			return err
		}
		// Read authorization: an OPEN observation here authorizes exactly
		// one further frame attempt. It sits after the compact fallback an
		// already-authorized message is permitted to finish and before the
		// read deadline is armed, so once Close has published the non-OPEN
		// state this worker sets no deadline and starts no further read.
		if !p.service.workAuthorized() {
			return nil
		}
		frameStart := time.Now()
		_, activeCompact := p.compactOutstandingExpiry()
		specializedDeadline := p.readDeadlineAt(frameStart, lateBlockTxn == nil || activeCompact)
		if err := p.conn.SetReadDeadline(specializedDeadline); err != nil {
			return err
		}
		frame, nextLateBlockTxn, err := p.readPostHandshakeFrame(ctx, frameStart, specializedDeadline, lateBlockTxn)
		lateBlockTxn = nextLateBlockTxn
		if err != nil {
			if errors.Is(err, errLateBlockTxnIgnored) || shouldIgnoreReadError(err) {
				continue
			}
			return normalizeReadError(err)
		}
		fallbackBeforeMessage := frame.Command == messagePing || frame.Command == messagePong || frame.Command == messageHeaders || frame.Command == messageCmpctBlock
		if fallbackBeforeMessage {
			if err := recordExpiredFallback(); err != nil {
				return err
			}
		}
		if err := p.handleMessage(frame); err != nil {
			return err
		}
		if !fallbackBeforeMessage {
			if err := recordExpiredFallback(); err != nil {
				return err
			}
		}
	}
}

const blockTxnHashPayloadBytes = 32

func (p *peer) readPostHandshakeFrame(ctx context.Context, frameStart, specializedDeadline time.Time, lateBlockTxn *compactOutstandingRequest) (message, *compactOutstandingRequest, error) {
	var frame message
	timing := &postHandshakeFrameTiming{peer: p}
	reader := &compactFallbackReader{peer: p, ctx: ctx, frameStart: frameStart, specializedDeadline: specializedDeadline, timing: timing, lateBlockTxn: lateBlockTxn}
	header, err := readFrameHeader(reader, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	lateBlockTxn = reader.lateBlockTxn
	if err := timing.finishHeader(err); err != nil {
		return frame, lateBlockTxn, err
	}
	if header.Command == messageBlockTxn {
		if frame, nextLate, handled, err := p.readRecognizedBlockTxnFrame(header, reader.specializedDeadline, lateBlockTxn); handled {
			return frame, nextLate, err
		}
	}
	limit := p.postHandshakePayloadCap()
	if header.Size > limit(header.Command) {
		return frame, lateBlockTxn, commandPayloadCapError{command: header.Command}
	}
	if err := timing.validatePayload(header.Size); err != nil {
		return frame, lateBlockTxn, err
	}
	payload, err := readPayloadWithChecksum(reader, header.Size, header.Checksum)
	lateBlockTxn = reader.lateBlockTxn
	if err := timing.finishPayload(err); err != nil {
		return frame, lateBlockTxn, err
	}
	return message{Command: header.Command, Payload: payload}, lateBlockTxn, nil
}

func (p *peer) readRecognizedBlockTxnFrame(header frameHeader, deadline time.Time, lateBlockTxn *compactOutstandingRequest) (message, *compactOutstandingRequest, bool, error) {
	acceptsBlockTxn := p.acceptsBlockTxnResponses()
	if lateBlockTxn == nil && !acceptsBlockTxn {
		return message{}, nil, false, nil
	}
	if err := p.conn.SetReadDeadline(deadline); err != nil {
		return message{}, lateBlockTxn, true, err
	}
	if lateBlockTxn != nil {
		frame, nextLate, err := p.readLateBlockTxnFrame(header, lateBlockTxn)
		return frame, nextLate, true, err
	}
	frame, err := p.readBlockTxnFrame(header)
	return frame, nil, true, err
}

type compactFallbackReader struct {
	peer                *peer
	ctx                 context.Context
	frameStart          time.Time
	specializedDeadline time.Time
	timing              *postHandshakeFrameTiming
	sent                bool
	lateBlockTxn        *compactOutstandingRequest
}

func (r *compactFallbackReader) Read(p []byte) (int, error) {
	for {
		if err := r.timing.beforeRead(); err != nil {
			return 0, err
		}
		n, err := r.peer.conn.Read(p)
		if n > 0 {
			r.timing.recordRead(n)
			return n, err
		}
		if !r.canRecoverReadTimeout(err) {
			return n, err
		}
		lateBlockTxn, sendErr := r.peer.sendExpiredCompactOutstandingFallback(r.ctx)
		if sendErr != nil {
			return 0, sendErr
		}
		if lateBlockTxn == nil {
			return n, err
		}
		r.sent = true
		r.lateBlockTxn = lateBlockTxn
		r.specializedDeadline = r.peer.readDeadlineAt(r.frameStart, false)
		if err := r.peer.conn.SetReadDeadline(r.specializedDeadline); err != nil {
			return 0, err
		}
	}
}

func (r *compactFallbackReader) canRecoverReadTimeout(err error) bool {
	return isReadTimeout(err) && !r.sent
}

func (p *peer) sendExpiredCompactOutstandingFallback(ctx context.Context) (*compactOutstandingRequest, error) {
	if peerRunContextDone(ctx) {
		return nil, nil
	}
	blockHash, payloadCap, ok := p.popExpiredCompactOutstandingBlockHashAndPayloadCap()
	if !ok || peerRunContextDone(ctx) {
		return nil, nil
	}
	body := append([]byte{MSG_BLOCK}, blockHash[:]...)
	if err := p.send(messageGetData, body); err != nil {
		return nil, err
	}
	return &compactOutstandingRequest{BlockHash: blockHash, BlockTxnPayloadCap: payloadCap}, nil
}

func (p *peer) readBlockTxnFrame(header frameHeader) (message, error) {
	cap := p.blockTxnPayloadCap()
	if cap == 0 {
		return p.readUnexpectedBlockTxnFrame(header)
	}
	if header.Size > cap {
		if stale, err := p.readOversizedBlockTxnStaleHash(header); err != nil || stale {
			return message{}, err
		}
		return message{}, commandPayloadCapError{command: header.Command}
	}
	if header.Size > blockTxnHashPayloadBytes {
		return p.readMatchedBlockTxnFrame(header)
	}
	return p.readFullCommandFramePayload(header)
}

func (p *peer) readLateBlockTxnFrame(header frameHeader, lateBlockTxn *compactOutstandingRequest) (message, *compactOutstandingRequest, error) {
	prefix, err := readPayloadPrefix(p.conn, header.Size, blockTxnHashPayloadBytes)
	if err != nil {
		return message{}, nil, err
	}
	payloadReader := io.MultiReader(bytes.NewReader(prefix), p.conn)
	if p.blockTxnPrefixMatchesOutstanding(prefix) {
		return p.readActiveBlockTxnFrame(header, payloadReader, lateBlockTxn)
	}
	if header.Size > lateBlockTxn.BlockTxnPayloadCap || header.Size > compactRelayPayloadCap(messageBlockTxn) {
		if p.blockTxnPayloadCap() == 0 && bytes.Equal(prefix, lateBlockTxn.BlockHash[:]) {
			return message{}, nil, commandPayloadCapError{command: header.Command}
		}
		return message{}, nil, blockTxnStaleBodyError{}
	}
	payload, err := readPayloadWithChecksum(payloadReader, header.Size, header.Checksum)
	if err != nil {
		return message{}, nil, err
	}
	return p.classifyLateBlockTxnPayload(payload, lateBlockTxn, header.Command)
}

func (p *peer) readActiveBlockTxnFrame(header frameHeader, payloadReader io.Reader, lateBlockTxn *compactOutstandingRequest) (message, *compactOutstandingRequest, error) {
	if activeCap := p.blockTxnPayloadCap(); activeCap == 0 || header.Size > activeCap {
		return message{}, lateBlockTxn, commandPayloadCapError{command: header.Command}
	}
	payload, err := readPayloadWithChecksum(payloadReader, header.Size, header.Checksum)
	if err != nil {
		return message{}, lateBlockTxn, err
	}
	return message{Command: header.Command, Payload: payload}, lateBlockTxn, nil
}

func (p *peer) classifyLateBlockTxnPayload(payload []byte, lateBlockTxn *compactOutstandingRequest, command string) (message, *compactOutstandingRequest, error) {
	if len(payload) < blockTxnHashPayloadBytes {
		if p.blockTxnPayloadCap() != 0 {
			return message{Command: command, Payload: payload}, lateBlockTxn, nil
		}
		return message{}, nil, errors.New("blocktxn payload missing block hash")
	}
	if bytes.Equal(payload[:blockTxnHashPayloadBytes], lateBlockTxn.BlockHash[:]) {
		p.setLastError(errLateBlockTxnIgnored.Error())
		return message{}, nil, errLateBlockTxnIgnored
	}
	if len(payload) > blockTxnHashPayloadBytes {
		return message{}, nil, blockTxnStaleBodyError{}
	}
	p.setLastError("ignored stale blocktxn response")
	return message{}, nil, errLateBlockTxnIgnored
}

func (p *peer) readOversizedBlockTxnStaleHash(header frameHeader) (bool, error) {
	if header.Size <= blockTxnHashPayloadBytes {
		return false, nil
	}
	var responseHash [32]byte
	n, err := io.ReadFull(p.conn, responseHash[:])
	if err != nil {
		return false, payloadReadError(header.Size, 0, n, err)
	}
	blockHash, ok := p.compactOutstandingBlockHash()
	if !ok || responseHash != blockHash {
		return true, blockTxnStaleBodyError{}
	}
	return false, nil
}

func (p *peer) readUnexpectedBlockTxnFrame(header frameHeader) (message, error) {
	if header.Size > blockTxnHashPayloadBytes {
		return message{}, commandPayloadCapError{command: header.Command}
	}
	return p.readFullCommandFramePayload(header)
}

func (p *peer) readFullCommandFramePayload(header frameHeader) (message, error) {
	payload, err := readPayloadWithChecksum(p.conn, header.Size, header.Checksum)
	if err != nil {
		return message{}, err
	}
	return message{Command: header.Command, Payload: payload}, nil
}

func (p *peer) readMatchedBlockTxnFrame(header frameHeader) (message, error) {
	prefix, err := readPayloadPrefix(p.conn, header.Size, blockTxnHashPayloadBytes)
	if err != nil {
		return message{}, err
	}
	if !p.blockTxnPrefixMatchesOutstanding(prefix) {
		return message{}, blockTxnStaleBodyError{}
	}
	payload, err := readPayloadWithChecksum(io.MultiReader(bytes.NewReader(prefix), p.conn), header.Size, header.Checksum)
	if err != nil {
		return message{}, err
	}
	return message{Command: header.Command, Payload: payload}, nil
}

func (p *peer) blockTxnPrefixMatchesOutstanding(prefix []byte) bool {
	if len(prefix) < blockTxnHashPayloadBytes {
		return false
	}
	var responseHash [32]byte
	copy(responseHash[:], prefix[:blockTxnHashPayloadBytes])
	blockHash, ok := p.compactOutstandingBlockHash()
	return ok && responseHash == blockHash
}

func (p *peer) postHandshakePayloadCap() payloadLimitFn {
	base := postHandshakePayloadCap(p.service.cfg.LocatorLimit, p.service.cfg.SyncConfig.HeaderBatchLimit)
	return func(command string) uint32 {
		switch command {
		case messageCmpctBlock, messageGetBlockTxn, messageGetDAChunk:
			if p.acceptsCompactBlocks() {
				return compactRelayPayloadCap(command)
			}
			return 0
		case messageBlockTxn:
			return p.blockTxnPostHandshakePayloadCap()
		default:
			return base(command)
		}
	}
}

func (p *peer) blockTxnPostHandshakePayloadCap() uint32 {
	if !p.compactReceiveEnabled() {
		return 0
	}
	if cap := p.blockTxnPayloadCap(); cap != 0 {
		return cap
	}
	if p.acceptsCompactBlocks() {
		return blockTxnHashPayloadBytes
	}
	return 0
}

func (p *peer) compactReceiveEnabled() bool {
	return p != nil && p.service != nil && p.service.cfg.EnableCompactReceive
}

func (p *peer) acceptsCompactBlocks() bool {
	if !p.compactReceiveEnabled() {
		return false
	}
	mode := p.remoteCompactMode()
	return mode.Version == compactRelayVersion && mode.Mode != 0
}

func (p *peer) acceptsBlockTxnResponses() bool {
	if !p.compactReceiveEnabled() {
		return false
	}
	return p.acceptsCompactBlocks() || p.blockTxnPayloadCap() != 0
}

func peerRunContextDone(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (p *peer) setReadDeadline() error {
	return p.setReadDeadlineAt(time.Now(), true)
}

func (p *peer) setReadDeadlineAt(wallNow time.Time, includeCompact bool) error {
	return p.conn.SetReadDeadline(p.readDeadlineAt(wallNow, includeCompact))
}

func (p *peer) readDeadlineAt(wallNow time.Time, includeCompact bool) time.Time {
	var deadlineTime time.Time
	if deadline := p.service.cfg.PeerRuntimeConfig.ReadDeadline; deadline > 0 {
		deadlineTime = wallNow.Add(deadline)
	}
	if includeCompact {
		if expiry, ok := p.compactOutstandingExpiry(); ok {
			remaining := expiry.Sub(p.service.cfg.Now())
			compactDeadline := wallNow
			if remaining > 0 {
				compactDeadline = wallNow.Add(remaining)
			}
			if deadlineTime.IsZero() || compactDeadline.Before(deadlineTime) {
				deadlineTime = compactDeadline
			}
		}
	}
	return deadlineTime
}

func (p *peer) writePostHandshakeFrame(command string, payload []byte) error {
	if uint64(len(payload)) > uint64(p.service.cfg.PeerRuntimeConfig.MaxMessageSize) {
		return errors.New("message exceeds cap")
	}
	header, err := buildEnvelopeHeader(networkMagic(p.service.cfg.PeerRuntimeConfig.Network), command, payload)
	if err != nil {
		return err
	}
	frameStart := time.Now()
	absoluteDeadline := frameStart.Add(frameBudgetDuration(uint64(len(payload))))
	lastProgress := frameStart
	if err := p.writePostHandshakeChunk(header[:], &lastProgress, absoluteDeadline); err != nil {
		return err
	}
	for offset := 0; offset < len(payload); {
		end := offset + streamReadChunkBytes
		if end > len(payload) {
			end = len(payload)
		}
		if err := p.writePostHandshakeChunk(payload[offset:end], &lastProgress, absoluteDeadline); err != nil {
			return err
		}
		offset = end
	}
	if frameDeadlineExpired(time.Now(), absoluteDeadline) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (p *peer) writePostHandshakeChunk(chunk []byte, lastProgress *time.Time, absoluteDeadline time.Time) error {
	for len(chunk) > 0 {
		deadline := earlierDeadline(absoluteDeadline, lastProgress.Add(boundedFrameStallBudget(p.service.cfg.PeerRuntimeConfig.WriteDeadline)))
		if frameDeadlineExpired(time.Now(), deadline) {
			return os.ErrDeadlineExceeded
		}
		if err := p.conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
		n, err := p.conn.Write(chunk)
		if n > 0 {
			if n > len(chunk) {
				return io.ErrShortWrite
			}
			*lastProgress = time.Now()
			chunk = chunk[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func shouldIgnoreReadError(err error) bool {
	return !isPartialFrameTimeout(err) && isReadTimeout(err)
}

func normalizeReadError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
		return nil
	default:
		return err
	}
}

func (p *peer) handleMessage(frame message) error {
	switch frame.Command {
	case messageInv, messageGetData, messageBlock, messageTx, messageGetBlk, messageCmpctBlock, messageGetBlockTxn, messageBlockTxn, messageGetDAChunk:
		return p.handleRelayMessage(frame)
	case messageSendCmpct:
		return p.handleSendCmpct(frame.Payload)
	case messageGetAddr, messageAddr:
		return p.handleAddressMessage(frame)
	case messagePing, messagePong, messageHeaders:
		return nil
	case messageVersion:
		return errors.New("invalid version message after handshake")
	case messageVerAck:
		return errors.New("invalid verack after handshake")
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleRelayMessage(frame message) error {
	switch frame.Command {
	case messageInv, messageGetData:
		return p.handleInventoryRelayMessage(frame)
	case messageGetDAChunk:
		if !p.acceptsCompactBlocks() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleGetDAChunk(frame.Payload)
	case messageBlock, messageTx, messageGetBlk, messageCmpctBlock, messageGetBlockTxn, messageBlockTxn:
		return p.handleObjectRelayMessage(frame)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleInventoryRelayMessage(frame message) error {
	switch frame.Command {
	case messageInv:
		return p.handleInv(frame.Payload)
	case messageGetData:
		return p.handleGetData(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func (p *peer) handleObjectRelayMessage(frame message) error {
	switch frame.Command {
	case messageBlock:
		return p.handleBlock(frame.Payload)
	case messageTx:
		return p.handleTx(frame.Payload)
	case messageGetBlk:
		return p.handleGetBlocks(frame.Payload)
	case messageCmpctBlock:
		if !p.acceptsCompactBlocks() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleCmpctBlock(frame.Payload)
	case messageGetBlockTxn:
		if !p.acceptsCompactBlocks() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleGetBlockTxn(frame.Payload)
	case messageBlockTxn:
		if !p.acceptsBlockTxnResponses() {
			return postHandshakeUnknownCommandError{command: frame.Command}
		}
		return p.handleBlockTxn(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func isCompactRelayObjectCommand(command string) bool {
	switch command {
	case messageCmpctBlock, messageGetBlockTxn, messageBlockTxn:
		return true
	default:
		return false
	}
}

func (p *peer) handleAddressMessage(frame message) error {
	switch frame.Command {
	case messageGetAddr:
		return p.handleGetAddr(frame.Payload)
	case messageAddr:
		return p.handleAddr(frame.Payload)
	default:
		return postHandshakeUnknownCommandError{command: frame.Command}
	}
}

func unknownCommandPolicyReason(err error) (string, bool) {
	var unknownErr postHandshakeUnknownCommandError
	if errors.As(err, &unknownErr) {
		return unknownErr.peerReason(), true
	}
	return "", false
}

func (p *peer) send(command string, payload []byte) error {
	announcementHash, hasAnnouncement := compactAnnouncementHashForSentMessage(command, payload)
	p.writeMu.Lock()
	if hasAnnouncement {
		p.beginCompactBlockAnnouncementSend(announcementHash)
	}
	err := p.writePostHandshakeFrame(command, payload)
	if hasAnnouncement {
		p.finishCompactBlockAnnouncementSend(announcementHash, err)
	}
	p.writeMu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func (p *peer) compactSendBarrier() {
	p.writeMu.Lock()
	p.writeMu.Unlock()
}

func (p *peer) addr() string {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state.Addr
}

func (p *peer) snapshotState() node.PeerState {
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	return p.state
}

func (p *peer) setLastError(reason string) {
	p.stateMu.Lock()
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
}

func (p *peer) applyPostHandshakeDisconnectError(err error) {
	if err == nil {
		return
	}
	if p.applyBlockTxnStaleBodyDisconnect(err) {
		return
	}
	if p.applyBlockTxnCapDisconnect(err) {
		return
	}
	if reason, ok := unknownCommandPolicyReason(err); ok {
		p.setLastError(reason)
		return
	}
	if reason, ok := payloadCapDiagnosticReason(err); ok {
		p.setLastError(reason)
		return
	}
	p.setLastError(err.Error())
}

func (p *peer) applyBlockTxnStaleBodyDisconnect(err error) bool {
	var staleErr blockTxnStaleBodyError
	if !errors.As(err, &staleErr) {
		return false
	}
	p.setLastError(staleErr.Error())
	return true
}

func (p *peer) applyBlockTxnCapDisconnect(err error) bool {
	var commandCapErr commandPayloadCapError
	if errors.As(err, &commandCapErr) && commandCapErr.command == messageBlockTxn {
		if p.blockTxnPayloadCap() == 0 {
			p.setLastError("unexpected blocktxn")
			return true
		}
		p.clearCompactOutstandingRequest()
		p.bumpBan(10, "blocktxn payload exceeds outstanding cap")
		return true
	}
	var messageCapErr inboundMessagePayloadCapError
	if errors.As(err, &messageCapErr) && messageCapErr.command == messageBlockTxn {
		if p.blockTxnPayloadCap() == 0 {
			p.setLastError("unexpected blocktxn")
			return true
		}
		p.setLastError("message exceeds cap: blocktxn")
		return true
	}
	return false
}

func payloadCapDiagnosticReason(err error) (string, bool) {
	command, ok := capErrorCommand(err)
	if !ok || command == "" {
		return "", false
	}
	return fmt.Sprintf("%s: %s", err.Error(), command), true
}

func capErrorCommand(err error) (string, bool) {
	var commandCapErr commandPayloadCapError
	if errors.As(err, &commandCapErr) {
		return commandCapErr.command, true
	}
	var messageCapErr inboundMessagePayloadCapError
	if errors.As(err, &messageCapErr) {
		return messageCapErr.command, true
	}
	return "", false
}

func (p *peer) bumpBan(delta int, reason string) bool {
	p.stateMu.Lock()
	p.state.BanScore += delta
	p.state.LastError = reason
	state := p.state
	p.stateMu.Unlock()
	_ = p.service.cfg.PeerManager.UpsertPeer(&state)
	return state.BanScore >= p.service.cfg.PeerRuntimeConfig.BanThreshold
}
