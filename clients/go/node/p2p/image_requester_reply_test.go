package p2p

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	replyChunk    = "utxoimg"
	replyNegative = "utxonotavail"
	replyLimit    = 150905
)

var replyEmptyAnchor = ImageAnchor{
	Height: 7, BlockHash: [32]byte{0x57}, Root: sha3.Sum256([]byte("RUBIN_UTXO_TREE_V1\x00")),
}

func TestImageRequesterReplies(t *testing.T) {
	t.Run("Transport", testImageReplyTransport)
	t.Run("Prefix", testImageReplyPrefix)
	t.Run("Grammar", testImageReplyGrammar)
	t.Run("Query", testImageReplyQuery)
	t.Run("Proof", testImageReplyProof)
	t.Run("Time", testImageReplyTime)
	t.Run("Ledger", testImageReplyLedger)
	t.Run("Receive", testImageReplyReceive)
	t.Run("Send", testImageReplySend)
	t.Run("Join", testImageReplyJoin)
	t.Run("Body", testImageReplyBody)
	t.Run("Generation", testImageReplyGeneration)
	t.Run("Retention", testImageReplyRetention)
}

func runReplyCases(t *testing.T, check func(*testing.T, string), names ...string) {
	for _, name := range names {
		t.Run(name, func(t *testing.T) { check(t, name) })
	}
}

type imageReplyPeer struct {
	current *peer
	remote  net.Conn
	wire    *imageReplySocket
	conn    *blockRetryConn
	done    <-chan struct{}
}

type imageReplySocket struct {
	net.Conn
	readBytes    atomic.Int64
	readCalls    atomic.Int64
	readHold     atomic.Pointer[replyReadHold]
	readEntry    atomic.Pointer[replyReadHold]
	nextReads    atomic.Int64
	nextDeadline atomic.Pointer[chan struct{}]
}

func (c *imageReplySocket) Read(b []byte) (int, error) {
	c.readCalls.Add(1)
	if hold := c.readEntry.Load(); hold != nil && c.readBytes.Load() == hold.at && c.readEntry.CompareAndSwap(hold, nil) {
		hold.wait()
	}
	n, err := c.Conn.Read(b)
	count := c.readBytes.Add(int64(n))
	if hold := c.readHold.Load(); hold != nil && count == hold.at && c.readHold.CompareAndSwap(hold, nil) {
		hold.wait()
	}
	return n, err
}

func (c *imageReplySocket) SetReadDeadline(deadline time.Time) error {
	c.nextReads.Add(1)
	if entered := c.nextDeadline.Swap(nil); entered != nil {
		close(*entered)
	}
	return c.Conn.SetReadDeadline(deadline)
}

type replyReadHold struct {
	at       int64
	entered  chan struct{}
	released chan struct{}
}

func (h *replyReadHold) wait() { close(h.entered); <-h.released }

func holdReplyRead(t *testing.T, socket *imageReplySocket, relative int) (<-chan struct{}, func()) {
	t.Helper()
	h := &replyReadHold{at: socket.readBytes.Load() + int64(relative), entered: make(chan struct{}), released: make(chan struct{})}
	socket.readHold.Store(h)
	release := sync.OnceFunc(func() { close(h.released) })
	t.Cleanup(release)
	return h.entered, release
}

type replyCallEvent struct {
	point string
	peer  *peer
	value any
}

type replyCallTrace struct {
	mu     sync.Mutex
	events []replyCallEvent
	visit  func(replyCallEvent)
}

var (
	replyCallTracing bool
	replyCallOwner   atomic.Pointer[replyCallTrace]
)

func observeReplyCalls(t *testing.T, visit func(replyCallEvent)) *replyCallTrace {
	t.Helper()
	trace := &replyCallTrace{visit: visit}
	old := replyCallOwner.Swap(trace)
	t.Cleanup(func() { replyCallOwner.Store(old) })
	return trace
}

// RecordImageReplyActualCall observes a selected call before its effect.
func RecordImageReplyActualCall(point string, source *peer, value any) {
	trace := replyCallOwner.Load()
	if trace == nil {
		return
	}
	event := replyCallEvent{point: point, peer: source, value: value}
	trace.mu.Lock()
	trace.events = append(trace.events, event)
	trace.mu.Unlock()
	if trace.visit != nil {
		trace.visit(event)
	}
}

func (trace *replyCallTrace) requireCount(t *testing.T, point string, want int) {
	t.Helper()
	if !replyCallTracing {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	count := 0
	for _, event := range trace.events {
		if event.point == point {
			count++
		}
	}
	requireEqual(t, count, want, "actual "+point+" calls")
}

func (trace *replyCallTrace) requireLookup(t *testing.T, source *peer, want *imageInstance) {
	t.Helper()
	if !replyCallTracing {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	var seen int
	for _, event := range trace.events {
		if event.point == "lookup" && event.peer == source {
			found, ok := event.value.(*imageInstance)
			require(t, ok || event.value == nil, "unexpected lookup result type %T", event.value)
			require(t, found == want, "wrong instance returned by registration lookup")
			seen++
		}
	}
	requireEqual(t, seen, 1, "actual lookups on the receiving registration")
}

func (trace *replyCallTrace) requireAbsentCall(t *testing.T, source *peer, point string) {
	t.Helper()
	if !replyCallTracing {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	for _, event := range trace.events {
		require(t, event.peer != source || event.point != point, "unexpected %s on competing registration", point)
	}
}

func holdReplyCall(t *testing.T, point string, current *peer) (<-chan struct{}, func()) {
	t.Helper()
	entered, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	once := sync.OnceFunc(func() { close(entered); <-proceed })
	observeReplyCalls(t, func(event replyCallEvent) {
		if event.point == point && event.peer == current {
			once()
		}
	})
	return entered, release
}

func awaitReplyBefore[T any](t *testing.T, done <-chan T, unexpected <-chan struct{}, effect string) T {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-unexpected:
		t.Fatalf("unexpected %s", effect)
	case <-time.After(lifecycleWatchdog):
		t.Fatalf("wait for completion before %s timed out", effect)
	}
	var zero T
	return zero
}

type imageReplyFixture struct {
	*imageTestFixture
	workers []imageReplyPeer
}

func newImageReplyFixture(t *testing.T, enabled bool, sources int) *imageReplyFixture {
	f := &imageReplyFixture{imageTestFixture: newImageTestFixture(t, 0)}
	blockRetryService(t, f.s)
	f.s.cfg.PeerRuntimeConfig.ReadDeadline = 0
	f.s.cfg.EnableImageRequester = enabled
	for i := range sources {
		f.addReplyPeer(fmt.Sprintf("192.0.2.%d:18100", 80+i))
	}
	return f
}

func (f *imageReplyFixture) addReplyPeer(address string) {
	f.startReplyPeer(address, startImagePipeWorker)
}

func (f *imageReplyFixture) startReplyPeer(address string, start func(*testing.T, *Service, net.Conn, net.Conn) <-chan struct{}) {
	t := f.t
	t.Helper()
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	socket := &imageReplySocket{Conn: endpointConn{Conn: local, remote: stubAddr(address)}}
	conn := newBlockRetryConn(socket)
	done := start(t, f.s, conn, remote)
	for f.readReplyPeer(remote).Command != "getaddr" {
	}
	current := f.serviceEntry(address)
	require(t, current != nil, "handshaken peer missing")
	f.ids = append(f.ids, address)
	f.workers = append(f.workers, imageReplyPeer{current: current, remote: remote, wire: socket, conn: conn, done: done})
}

func (f *imageReplyFixture) readReplyPeer(conn net.Conn) message {
	t := f.t
	t.Helper()
	cfg := f.s.cfg.PeerRuntimeConfig
	frame, err := readFrame(conn, networkMagic(cfg.Network), cfg.MaxMessageSize)
	must(t, err, "read outgoing frame")
	return frame
}

func imageReplyLimits() ImageLimits {
	l := imageTestLimits(10*time.Second, 100*time.Second)
	l.PerPeer, l.Global = imageTestUnits(1<<32), imageTestUnits(1<<32)
	return l
}

func (f *imageReplyFixture) beginReplyRound(ctx context.Context, anchor ImageAnchor, limits ImageLimits, probe bool, sources ...int) *ImageRound {
	t := f.t
	t.Helper()
	cfg := f.config(limits, sources...)
	cfg.Anchor = anchor
	if !probe {
		round, err := f.s.BeginImageRound(ctx, cfg)
		must(t, err, "begin IMAGE round")
		return round
	}
	now := f.clock.add(0)
	round, err := f.s.BeginImageProbeRound(ctx, ImageProbeRoundConfig{
		Anchor: anchor, SourceIDs: cfg.SourceIDs, Limits: limits, BodyAdmissionTime: now, BodyRD: now.Add(limits.RoundLifetime),
	})
	must(t, err, "begin body probe round")
	return round
}

func imageReplyQuery(anchor ImageAnchor, id uint64, start byte, limit uint32) consensus.UTXOImageQuery {
	return consensus.UTXOImageQuery{
		RequestID: id, Height: anchor.Height, BlockHash: anchor.BlockHash, Root: anchor.Root, StartKey: [36]byte{start}, ByteLimit: limit,
	}
}

func newReplyRound(t *testing.T, peers int, anchor ImageAnchor, limits ImageLimits, probe bool) (*imageReplyFixture, *ImageRound) {
	t.Helper()
	f := newImageReplyFixture(t, true, peers)
	sources := make([]int, peers)
	for i := range sources {
		sources[i] = i
	}
	return f, f.beginReplyRound(t.Context(), anchor, limits, probe, sources...)
}

func (f *imageReplyFixture) withInitialQuery(ctx context.Context) (*imageReplyFixture, *ImageRound, consensus.UTXOImageQuery) {
	f.t.Helper()
	r, err := f.s.BeginImageRound(ctx, ImageRoundConfig{Anchor: replyEmptyAnchor, SourceIDs: f.ids, Limits: imageReplyLimits()})
	must(f.t, err, "begin round on connected sources")
	return f, r, f.sendQuery(r, ctx, 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
}

func imageReplyQBytes(q consensus.UTXOImageQuery) []byte {
	b := make([]byte, 120)
	binary.LittleEndian.PutUint64(b[0:8], q.RequestID)
	binary.LittleEndian.PutUint64(b[8:16], q.Height)
	copy(b[16:48], q.BlockHash[:])
	copy(b[48:80], q.Root[:])
	copy(b[80:116], q.StartKey[:])
	binary.LittleEndian.PutUint32(b[116:120], q.ByteLimit)
	return b
}

func imageReplyCall(r *ImageRound, ctx context.Context, source string, q consensus.UTXOImageQuery, body [32]byte) imageResult {
	var got imageResult
	if r.probe {
		got.q, got.err = r.Probe(ctx, source, q.StartKey, q.ByteLimit, body)
	} else {
		got.q, got.err = r.Request(ctx, source, q.StartKey, q.ByteLimit)
	}
	return got
}

// tryReplyAdmission lets even an unexpected admitted write complete at the local socket.
func (f *imageReplyFixture) tryReplyAdmission(r *ImageRound, source int, q consensus.UTXOImageQuery, hash [32]byte) imageResult {
	c := f.workers[source].conn
	c.mu.Lock()
	old := c.writeHook
	c.writeHook = func(b []byte) (int, error) { return len(b), nil }
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.writeHook = old; c.mu.Unlock() }()
	return imageReplyCall(r, f.t.Context(), f.ids[source], q, hash)
}

func (f *imageReplyFixture) sendQuery(r *ImageRound, ctx context.Context, source int, q consensus.UTXOImageQuery, body [32]byte) consensus.UTXOImageQuery {
	t := f.t
	t.Helper()
	sent := make(chan imageResult, 1)
	go func() { sent <- imageReplyCall(r, ctx, f.ids[source], q, body) }()
	type wireRead struct {
		frame message
		err   error
	}
	frames := make(chan wireRead, 1)
	go func() {
		cfg := f.s.cfg.PeerRuntimeConfig
		frame, err := readFrame(f.workers[source].remote, networkMagic(cfg.Network), cfg.MaxMessageSize)
		frames <- wireRead{frame, err}
	}()
	var packet wireRead
	select {
	case got := <-sent:
		requireQueryResult(t, got, q, nil, "public send result")
		packet = awaitImageResult(t, frames, "outgoing request bytes")
	case packet = <-frames:
		requireQueryResult(t, awaitImageResult(t, sent, "request frame returned"), q, nil, "sent query")
	}
	must(t, packet.err, "outgoing request frame")
	frame := packet.frame
	requireEqual(t, frame.Command, "getutxoimg", "outgoing command")
	require(t, bytes.Equal(frame.Payload, imageReplyQBytes(q)), "outgoing literal query differs")
	return q
}

func (f *imageReplyFixture) sendHeader(source int, command string, size uint32, payload []byte, corrupt bool) {
	t := f.t
	t.Helper()
	var header [24]byte
	magic := networkMagic(f.s.cfg.PeerRuntimeConfig.Network)
	checksum := sha3.Sum256(payload)
	copy(header[:4], magic[:])
	copy(header[4:16], command)
	binary.LittleEndian.PutUint32(header[16:20], size)
	copy(header[20:24], checksum[:4])
	if corrupt {
		header[20] ^= 1
	}
	n, err := f.workers[source].remote.Write(header[:])
	must(t, err, "write inbound header")
	requireEqual(t, n, 24, "header bytes written")
}

func (f *imageReplyFixture) sendFrame(source int, command string, payload []byte, corrupt bool) {
	t := f.t
	t.Helper()
	f.sendHeader(source, command, uint32(len(payload)), payload, corrupt)
	if len(payload) != 0 {
		n, err := f.workers[source].remote.Write(payload)
		must(t, err, "write inbound payload")
		requireEqual(t, n, len(payload), "payload bytes written")
	}
}

func (f *imageReplyFixture) deliver(source int, command string, payload []byte) {
	f.sendFrame(source, command, payload, false)
	f.sendFrame(source, "ping", nil, false)
}

type imageReplyLeaf struct {
	key   [36]byte
	entry []byte
}

func replyLeaf(prefix byte, vout uint32, data []byte) imageReplyLeaf {
	leaf := imageReplyLeaf{key: [36]byte{prefix}}
	binary.BigEndian.PutUint32(leaf.key[32:], vout)
	entry := make([]byte, 0, 46)
	entry = append(entry, leaf.key[:32]...)
	entry = binary.LittleEndian.AppendUint32(entry, vout)
	entry = binary.LittleEndian.AppendUint64(entry, 23)
	entry = binary.LittleEndian.AppendUint16(entry, 5)
	if len(data) < 253 {
		entry = append(entry, byte(len(data)))
	} else {
		entry = append(entry, 0xfd, byte(len(data)), byte(len(data)>>8))
	}
	entry = append(entry, data...)
	leaf.entry = append(entry, 6, 0, 0, 0, 0, 0, 0, 0, 1)
	return leaf
}

func replyLeafHash(leaf imageReplyLeaf) [32]byte {
	preimage := append([]byte("RUBIN_UTXO_TREE_V1\x01"), leaf.entry...)
	return sha3.Sum256(preimage)
}

func replyBranch(depth int, prefix [36]byte, left, right [32]byte) [32]byte {
	var wire [121]byte
	copy(wire[:19], "RUBIN_UTXO_TREE_V1\x02")
	binary.BigEndian.PutUint16(wire[19:21], uint16(depth))
	boundary := depth / 8
	prefix[boundary] &= byte(0xff << (8 - depth%8))
	copy(wire[21:57], prefix[:boundary+1])
	copy(wire[57:89], left[:])
	copy(wire[89:], right[:])
	return sha3.Sum256(wire[:])
}

func replyTree(leaves []imageReplyLeaf) [32]byte {
	if len(leaves) == 0 {
		return replyEmptyAnchor.Root
	}
	if len(leaves) == 1 {
		return replyLeafHash(leaves[0])
	}
	first, last := leaves[0].key, leaves[len(leaves)-1].key
	at := 0
	for first[at] == last[at] {
		at++
	}
	bit := bits.LeadingZeros8(first[at] ^ last[at])
	split := 1
	for leaves[split].key[at]&(0x80>>bit) == 0 {
		split++
	}
	return replyBranch(8*at+bit, first, replyTree(leaves[:split]), replyTree(leaves[split:]))
}

func replyAnchor(leaves ...imageReplyLeaf) ImageAnchor {
	anchor := replyEmptyAnchor
	anchor.Root = replyTree(leaves)
	return anchor
}

func replyChunkBytes(q consensus.UTXOImageQuery, entries []imageReplyLeaf, pred *imageReplyLeaf, left, right []consensus.UTXOImageEdge) []byte {
	b := binary.LittleEndian.AppendUint32(imageReplyQBytes(q), uint32(len(entries)))
	for _, entry := range entries {
		b = append(b, entry.entry...)
	}
	if pred == nil {
		b = append(b, 0)
	} else {
		b = append(append(b, 1), pred.entry...)
	}
	for _, side := range [][]consensus.UTXOImageEdge{left, right} {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(side)))
		for _, e := range side {
			b = binary.BigEndian.AppendUint16(b, e.Depth)
			b = append(b, e.Hash[:]...)
		}
	}
	return b
}

func (f *imageReplyFixture) requireReceive(r *ImageRound, q consensus.UTXOImageQuery, diagnostic string, wantErr error) ImageResult {
	f.t.Helper()
	got := f.receiveReplyRaw(r, q.StartKey, wantErr)
	requireEqual(f.t, got.Query, q, "Receive query")
	requireEqual(f.t, got.Diagnostic, diagnostic, "Receive diagnostic")
	return got
}

func (f *imageReplyFixture) requireEmpty(r *ImageRound, start byte, want error) {
	f.t.Helper()
	got := f.receiveReplyRaw(r, [36]byte{start}, want)
	requireEqual(f.t, got, ImageResult{}, "result without outcome")
}

func requireReplyNoRange(t *testing.T, got ImageResult) {
	t.Helper()
	require(t, got.Range == nil, "unexpected verified range: %+v", got.Range)
	require(t, got.Attribution == nil, "unexpected body attribution")
}

func requireReplyRange(t *testing.T, got ImageResult, want consensus.UTXOImageRange, token bool) {
	t.Helper()
	require(t, got.Range != nil, "verified range is absent")
	require(t, reflect.DeepEqual(*got.Range, want), "whole range differs: entries=%d, predecessor=%v, right=%d, terminal=%v",
		len(got.Range.Entries), got.Range.Predecessor != nil, len(got.Range.RightEdge), got.Range.Terminal)
	requireEqual(t, got.Attribution != nil, token, "body attribution presence")
}

func (f *imageReplyFixture) takeNegativeReply(r *ImageRound, source int, q consensus.UTXOImageQuery) {
	f.t.Helper()
	f.deliver(source, replyNegative, imageReplyQBytes(q))
	requireReplyNoRange(f.t, f.requireReceive(r, q, "", nil))
}

func (f *imageReplyFixture) takeEmptyRange(r *ImageRound, q consensus.UTXOImageQuery, token bool) *ImageAttribution {
	f.t.Helper()
	got := f.requireReceive(r, q, "", nil)
	requireReplyRange(f.t, got, consensus.UTXOImageRange{Terminal: true}, token)
	return got.Attribution
}

func replyEntry(prefix byte, vout uint32, data []byte) consensus.UTXOImageEntry {
	return consensus.UTXOImageEntry{
		Outpoint: consensus.Outpoint{Txid: [32]byte{prefix}, Vout: vout},
		Entry: consensus.UtxoEntry{
			Value: 23, CovenantType: 5, CovenantData: data, CreationHeight: 6, CreatedByCoinbase: true,
		},
	}
}

type replyTransportCase struct {
	name, command string
	size          uint32
	enabled       bool
	empty         bool
}

func testImageReplyTransport(t *testing.T) {
	for _, tc := range []replyTransportCase{
		{name: "DisabledNonemptyChunk", command: replyChunk, size: 129},
		{name: "DisabledNonemptyNegative", command: replyNegative, size: 120},
		{name: "DisabledEmptyChunk", command: replyChunk, empty: true},
		{name: "DisabledEmptyNegative", command: replyNegative, empty: true},
		{name: "ResponderNonempty", command: "getutxoimg", size: 120, enabled: true},
		{name: "ResponderEmpty", command: "getutxoimg", enabled: true, empty: true},
		{name: "ChunkCapOver", command: replyChunk, size: 2097153, enabled: true},
		{name: "NegativeCapOver", command: replyNegative, size: 121, enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) { checkReplyTransportHeader(t, tc) })
	}
	t.Run("BadChecksum", checkReplyBadChecksum)
	t.Run("PartialPayload", checkReplyPartial)
	t.Run("CapEqualNegative", func(t *testing.T) { checkReplyNegative(t, false) })
	t.Run("CapEqualChunk", checkReplyMaximumFrame)
}

func checkReplyTransportHeader(t *testing.T, tc replyTransportCase) {
	f := newImageReplyFixture(t, tc.enabled, 1)
	p := f.workers[0]
	prior := p.wire.readBytes.Load()
	payload := make([]byte, tc.size)
	f.sendHeader(0, tc.command, tc.size, payload, false)
	_, _ = p.remote.Write(payload)
	_ = p.remote.Close()
	requireChannelClosed(t, p.done, "terminal framed header")
	requireEqual(t, p.wire.readBytes.Load()-prior, int64(24), "count of envelope bytes read")
	want := "message exceeds command cap: " + tc.command
	if tc.empty {
		want = "unknown command: " + tc.command
	}
	requireEqual(t, p.current.snapshotState().LastError, want, "terminal header diagnostic")
}

func checkReplyBadChecksum(t *testing.T) {
	for _, id := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("ID%d", id), func(t *testing.T) { checkReplyChecksumID(t, id) })
	}
}

func checkReplyChecksumID(t *testing.T, id uint64) {
	f, round, q := newImageReplyFixture(t, true, 1).withInitialQuery(t.Context())
	wire := q
	wire.RequestID = id
	p := f.workers[0]
	dispatched, _ := holdReplyCall(t, "checked-frame", p.current)
	f.sendFrame(0, replyNegative, imageReplyQBytes(wire), true)
	awaitReplyBefore(t, p.done, dispatched, "dispatch of a frame with a bad checksum")
	requireReplyNoRange(t, f.requireReceive(round, q, "", errImageDisconnected))
	f.requireEmpty(round, 1, errImageNoAssignment)
	requireEqual(t, p.current.snapshotState().LastError, "invalid envelope checksum", "checksum diagnostic")
}

func checkReplyPartial(t *testing.T) {
	f, round, q := newImageReplyFixture(t, true, 2).withInitialQuery(t.Context())
	payload := imageReplyQBytes(q)
	p := f.workers[0]
	partial := p.wire.readBytes.Load() + 24 + 60
	dispatched, _ := holdReplyCall(t, "checked-frame", p.current)
	f.sendHeader(0, replyNegative, 120, payload, false)
	h := &replyReadHold{at: partial, entered: make(chan struct{}), released: make(chan struct{})}
	release := sync.OnceFunc(func() { close(h.released) })
	defer release()
	p.wire.readEntry.Store(h)
	written := make(chan error, 1)
	go func() {
		_, err := p.remote.Write(payload[:60])
		written <- err
	}()
	must(t, awaitReplyBefore(t, written, dispatched, "dispatch of a partial frame"), "part of payload")
	awaitReplyBefore(t, h.entered, dispatched, "dispatch of a partial frame")
	f.requireEmpty(round, 1, context.Canceled)
	requireQueryResult(t, f.tryReplyAdmission(round, 1, q, [32]byte{}),
		consensus.UTXOImageQuery{}, errImageAssignmentCurrent, "current while frame is partial")
	must(t, p.wire.Conn.SetReadDeadline(time.Now().Add(-time.Second)), "expire actual partial read")
	release()
	awaitReplyBefore(t, p.done, dispatched, "dispatch of a partial frame")
	requireReplyNoRange(t, f.requireReceive(round, q, "", errImageDisconnected))
	f.requireEmpty(round, 1, errImageNoAssignment)
	requireEqual(t, p.current.snapshotState().LastError, "payload timeout after partial frame read: 84/144 bytes", "partial frame diagnostic")
	replyCallOwner.Load().requireCount(t, "decode", 0)
}

func replySizedLeaves(sizes []int) ([]imageReplyLeaf, []consensus.UTXOImageEntry) {
	leaves := make([]imageReplyLeaf, len(sizes))
	entries := make([]consensus.UTXOImageEntry, len(sizes))
	for i, n := range sizes {
		data := bytes.Repeat([]byte{byte(i + 1)}, n)
		leaves[i] = replyLeaf(0x20, uint32(i), data)
		entries[i] = replyEntry(0x20, uint32(i), data)
	}
	return leaves, entries
}

func replyMaxLeaves() ([]imageReplyLeaf, []consensus.UTXOImageEntry) {
	sizes := make([]int, 32)
	for i := range sizes[:31] {
		sizes[i] = 65535
	}
	sizes[31] = 63582
	return replySizedLeaves(sizes)
}

func checkReplyMaximumFrame(t *testing.T) {
	leaves, entries := replyMaxLeaves()
	anchor := replyAnchor(leaves...)
	f, round := newReplyRound(t, 1, anchor, imageReplyLimits(), false)
	q := f.sendQuery(round, t.Context(), 0, imageReplyQuery(anchor, 1, 1, 2097152), [32]byte{})
	payload := replyChunkBytes(q, leaves, nil, nil, nil)
	requireEqual(t, len(payload), 2097152, "maximum chunk layout bytes")
	charges := make(chan [6]uint64, 1)
	f.clock.onReadFrom(".(*imageReplyWork).finishProof", func(now time.Time) time.Time {
		u := round.global
		charges <- [6]uint64{u[unitScalarProofWork], u[unitHashes], u[unitPasses], u[unitCopies], u[unitProofHoldingBytes], u[unitCopyHoldingBytes]}
		return now
	})
	f.deliver(0, replyChunk, payload)
	requireReplyRange(t, f.requireReceive(round, q, "", nil), consensus.UTXOImageRange{Entries: entries, Terminal: true}, false)
	f.requireEmpty(round, 1, errImageNoAssignment)
	requireEqual(t, awaitImageResult(t, charges, "maximum proof reservation"), [6]uint64{179722240, 75467, 7, 2715673, 7061248, 4194304}, "maximum payload work and held volume")
}

func checkReplyNegative(t *testing.T, retry bool) {
	f, round, q := newImageReplyFixture(t, true, 2).withInitialQuery(t.Context())
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyNegative, imageReplyQBytes(q))
	trace.requireCount(t, "verify", 0)
	requireReplyNoRange(t, f.requireReceive(round, q, "", nil))
	f.requireEmpty(round, 1, errImageNoAssignment)
	if retry {
		got := f.tryReplyAdmission(round, 0, q, [32]byte{})
		requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageAttempted, "same source/start retry")
		f.sendQuery(round, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit), [32]byte{})
		f.sendQuery(round, t.Context(), 1, q, [32]byte{})
	}
}

func testImageReplyPrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint64
		size int
	}{
		{"ShortZero", 1, 0},
		{"ShortSeven", 1, 7},
		{"ZeroID", 0, 60},
		{"UnknownID", 2, 60},
		{"ForeignID", 1, 60},
	} {
		t.Run(tc.name, func(t *testing.T) { checkImageReplyPrefix(t, tc.name, tc.id, tc.size) })
	}
	t.Run("EqualNumericSessions", checkReplyEqualNumericSessions)
	t.Run("InsertOrdinary", func(t *testing.T) { checkReplyInsert(t, false) })
	t.Run("InsertProbe", func(t *testing.T) { checkReplyInsert(t, true) })
	runReplyCases(t, checkReplyRetiredPrefix, "RetiredPrefix", "DetachReply", "DetachTimeout", "DetachCancel", "DetachRound")
	t.Run("DetachPeer", func(t *testing.T) { checkReplyIndexLastUse(t, false) })
	t.Run("DetachService", func(t *testing.T) { checkReplyIndexLastUse(t, true) })
	t.Run("BadEchoMalformed", func(t *testing.T) { checkReplyGrammar(t, "MixedEncodingFirst", replyChunk, "image_encoding") })
	t.Run("StaleReplacement", func(t *testing.T) { checkReplyEndRace(t, "Replacement") })
	t.Run("DetachedFrame", checkReplyDetachedFrame)
	t.Run("ArmingUnallocated/RequestContext", func(t *testing.T) { checkReplyArmingUnallocated(t, false) })
	t.Run("ArmingUnallocated/RoundContext", func(t *testing.T) { checkReplyArmingUnallocated(t, true) })
}

func checkImageReplyPrefix(t *testing.T, name string, id uint64, size int) {
	f, round, q := newImageReplyFixture(t, true, 2).withInitialQuery(t.Context())
	unknown := q
	unknown.RequestID = id
	source := 0
	if name == "ForeignID" {
		source = 1
	}
	trace := observeReplyCalls(t, nil)
	f.deliver(source, replyNegative, imageReplyQBytes(unknown)[:size])
	if size < 8 {
		trace.requireCount(t, "lookup", 0)
	} else if id != 0 {
		trace.requireLookup(t, f.workers[source].current, nil)
	}
	trace.requireCount(t, "decode", 0)
	f.requireEmpty(round, 1, context.Canceled)
	f.takeNegativeReply(round, 0, q)
}

func checkReplyEqualNumericSessions(t *testing.T) {
	f, r, a := newImageReplyFixture(t, true, 2).withInitialQuery(t.Context())
	b := f.sendQuery(r, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit), [32]byte{})
	member := replyCurrentInstance(f, r, a)
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyNegative, imageReplyQBytes(a)[:8])
	trace.requireLookup(t, f.workers[0].current, member)
	requireReplyNoRange(t, f.requireReceive(r, a, "image_encoding", nil))
	f.requireEmpty(r, 2, context.Canceled)
	f.takeNegativeReply(r, 1, b)
}

func checkReplyInsert(t *testing.T, probe bool) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), probe)
	q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	body := [32]byte{0x91}
	f.sendQuery(r, t.Context(), 0, q, body)
	member := replyCurrentInstance(f, r, q)
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	trace.requireLookup(t, f.workers[0].current, member)
	token := f.takeEmptyRange(r, q, probe)
	if probe {
		require(t, token.ValidFor(r, f.ids[0], replyEmptyAnchor, body), "exact attribution is not current")
	}
}

func replyCurrentInstance(f *imageReplyFixture, r *ImageRound, q consensus.UTXOImageQuery) *imageInstance {
	f.t.Helper()
	req := f.lockRequester()
	defer req.mu.Unlock()
	inst := req.current[imageKey{r.anchor, q.StartKey}]
	require(f.t, inst != nil && inst.query == q, "expected admitted assignment missing")
	return inst
}

func checkReplyRetiredPrefix(t *testing.T, how string) {
	f := newImageReplyFixture(t, true, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := f.beginReplyRound(t.Context(), replyEmptyAnchor, imageReplyLimits(), false, 0)
	q := f.sendQuery(r, ctx, 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
	session := f.workers[0].current.imageSession
	want := errImageNoAssignment
	switch how {
	case "RetiredPrefix", "DetachReply":
		f.takeNegativeReply(r, 0, q)
	case "DetachTimeout":
		f.clock.add(10*time.Second + 1)
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
	case "DetachCancel":
		cancel()
		requireReplyNoRange(t, f.requireReceive(r, q, "", context.Canceled))
	case "DetachRound":
		r.Close()
		want = errImageRoundClosed
	}
	f.requireEmpty(r, 1, want)
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	f.requireEmpty(r, 1, want)
	requireReplyIndexGone(f, trace, session, q.RequestID)
}

func requireReplyIndexGone(f *imageReplyFixture, trace *replyCallTrace, session *imageSession, id uint64) {
	f.t.Helper()
	trace.requireLookup(f.t, f.workers[0].current, nil)
	req := f.lockRequester()
	defer req.mu.Unlock()
	require(f.t, session.currentByID[id] == nil, "request ID remains in receiving session")
	require(f.t, session.currentByID == nil, "receiving session retains its empty request index")
}

type replyGrammarCase struct{ name, command, diagnostic string }

func testImageReplyGrammar(t *testing.T) {
	for _, tc := range []replyGrammarCase{
		{"Negative120", replyNegative, ""},
		{"Chunk120", replyChunk, "image_encoding"},
		{"Chunk184Count", replyChunk, "image_count"},
		{"Chunk185Valid", replyChunk, ""},
		{"Chunk185Truncated", replyChunk, "image_encoding"},
		{"Edge33", replyChunk, "image_count"},
		{"Edge34", replyChunk, ""},
		{"NonminimalCompactSize", replyChunk, "image_encoding"},
		{"PrevFlag", replyChunk, "image_encoding"},
		{"Trailing", replyChunk, "image_encoding"},
		{"Coinbase", replyChunk, "image_encoding"},
		{"Depth288", replyChunk, "image_encoding"},
		{"MixedEncodingFirst", replyChunk, "image_encoding"},
		{"MixedCountFirst", replyChunk, "image_count"},
		{"EncodingMapped", replyChunk, "image_encoding"},
		{"CountMapped", replyChunk, "image_count"},
	} {
		t.Run(tc.name, func(t *testing.T) { checkReplyGrammar(t, tc.name, tc.command, tc.diagnostic) })
	}
	for _, length := range []int{8, 60, 100, 119} {
		for _, command := range []string{replyNegative, replyChunk} {
			suffix := "Negative"
			if command == replyChunk {
				suffix = "Chunk"
			}
			t.Run(fmt.Sprintf("MissingQ%d%s", length, suffix), func(t *testing.T) { checkReplyMissingQ(t, command, length) })
		}
	}
	t.Run("RefusedBeforeGrammar", func(t *testing.T) { checkReplyParseHolding(t, 59) })
	t.Run("AdmittedBeforeGrammar", func(t *testing.T) { checkReplyParseHolding(t, 60) })
}

func checkReplyMissingQ(t *testing.T, command string, length int) {
	f, r, q := newImageReplyFixture(t, true, 1).withInitialQuery(t.Context())
	f.deliver(0, command, imageReplyQBytes(q)[:length])
	requireReplyNoRange(t, f.requireReceive(r, q, "image_encoding", nil))
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func checkReplyGrammar(t *testing.T, name, command, diagnostic string) {
	leaf, rightLeaf := replyLeaf(0x20, 0, nil), replyLeaf(0x80, 0, nil)
	anchor, edge := replyAnchor(leaf), []consensus.UTXOImageEdge(nil)
	if name == "Edge33" || name == "Edge34" || name == "Depth288" {
		anchor = replyAnchor(leaf, rightLeaf)
		edge = []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(rightLeaf)}}
	}
	q := imageReplyQuery(anchor, 1, 1, replyLimit)
	frame := replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, edge)
	requireEqual(t, len(frame), 185+34*len(edge), "literal one-entry geometry")
	frame = changeReplyGrammar(name, frame)
	f, r := newReplyRound(t, 1, anchor, imageReplyLimits(), false)
	f.sendQuery(r, t.Context(), 0, q, [32]byte{})
	trace := observeReplyCalls(t, nil)
	f.deliver(0, command, frame)
	trace.requireCount(t, "decode", 1)
	if diagnostic != "" || command == replyNegative {
		trace.requireCount(t, "verify", 0)
	}
	got := f.requireReceive(r, q, diagnostic, nil)
	if diagnostic != "" || command == replyNegative {
		requireReplyNoRange(t, got)
	} else {
		want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x20, 0, nil)}, RightEdge: edge, Terminal: len(edge) == 0}
		requireReplyRange(t, got, want, false)
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
	requireReplyHealthy(t, f.workers[0].current)
}

func changeReplyGrammar(name string, b []byte) []byte {
	switch name {
	case "Negative120", "Chunk120", "EncodingMapped":
		return b[:120]
	case "Chunk184Count", "CountMapped":
		return b[:184]
	case "MixedEncodingFirst":
		b[16] ^= 1
		return b[:120]
	case "MixedCountFirst":
		b[16] ^= 1
		return b[:184]
	case "Chunk185Truncated":
		b[170] = 15
	case "Edge33":
		return b[:len(b)-1]
	case "NonminimalCompactSize":
		return append(append(bytes.Clone(b[:170]), 0xfd, 0, 0), b[171:]...)
	case "PrevFlag":
		b[180] = 2
	case "Trailing":
		return append(b, 0)
	case "Coinbase":
		b[179] = 2
	case "Depth288":
		binary.BigEndian.PutUint16(b[len(b)-34:], 288)
	}
	return b
}

func requireReplyHealthy(t *testing.T, p *peer) {
	t.Helper()
	state := p.snapshotState()
	requireEqual(t, state.LastError, "", "classified reply LastError")
	requireEqual(t, state.BanScore, 0, "classified reply ban score")
}

func checkReplyParseHolding(t *testing.T, limit uint64) {
	l := imageReplyLimits()
	l.PerPeer.CopyHoldingBytes = limit
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, false)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyNegative, imageReplyQBytes(q)[:60])
	if limit < 60 {
		trace.requireCount(t, "decode", 0)
		f.requireEmpty(r, 1, context.Canceled)
		got := f.tryReplyAdmission(r, 1, q, [32]byte{})
		requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageAssignmentCurrent, "unexamined assignment stays current")
		f.clock.add(10*time.Second + 1)
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
	} else {
		trace.requireCount(t, "decode", 1)
		requireReplyNoRange(t, f.requireReceive(r, q, "image_encoding", nil))
	}
}

func testImageReplyQuery(t *testing.T) {
	runReplyCases(t, checkReplyQuery, "Height", "BlockHash", "Root", "Start", "ByteLimit", "HeightDomain",
		"LowLimitDomain", "HighLimitDomain", "IdentityBeforePayloadLimit", "PayloadLimitBeforeProof", "PayloadEqual", "PayloadPlusOne")
	t.Run("NegativeNoProof", func(t *testing.T) { checkReplyNegative(t, false) })
	t.Run("NegativeShape", func(t *testing.T) { checkReplyNegative(t, true) })
}

func checkReplyQuery(t *testing.T, name string) {
	leaves, entries := replySizedLeaves([]int{50000, 50000, 50603})
	anchor := replyAnchor(leaves...)
	limit := uint32(150906)
	if name == "PayloadLimitBeforeProof" || name == "PayloadPlusOne" || name == "IdentityBeforePayloadLimit" {
		limit = 150905
	}
	if name == "PayloadLimitBeforeProof" {
		anchor.Root[0] ^= 1
	}
	q := imageReplyQuery(anchor, 1, 1, limit)
	echo, diagnostic := changeReplyEcho(name, q)
	f, r := newReplyRound(t, 2, anchor, imageReplyLimits(), false)
	sibling := imageReplyQuery(anchor, 1, 2, 150906)
	f.sendQuery(r, t.Context(), 0, q, [32]byte{})
	f.sendQuery(r, t.Context(), 1, sibling, [32]byte{})
	payload := replyChunkBytes(echo, leaves, nil, nil, nil)
	requireEqual(t, len(payload), 150906, "requested-bound chunk layout")
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, payload)
	if diagnostic != "" {
		trace.requireCount(t, "verify", 0)
	}
	got := f.requireReceive(r, q, diagnostic, nil)
	if diagnostic == "" {
		requireReplyRange(t, got, consensus.UTXOImageRange{Entries: entries, Terminal: true}, false)
	} else {
		requireReplyNoRange(t, got)
	}
	f.requireEmpty(r, 2, context.Canceled)
	f.takeNegativeReply(r, 1, sibling)
	requireReplyHealthy(t, f.workers[0].current)
	requireReplyHealthy(t, f.workers[1].current)
}

func changeReplyEcho(name string, q consensus.UTXOImageQuery) (consensus.UTXOImageQuery, string) {
	switch name {
	case "Height":
		q.Height++
	case "BlockHash":
		q.BlockHash[0] ^= 1
	case "Root":
		q.Root[0] ^= 1
	case "Start":
		q.StartKey[0]++
	case "ByteLimit":
		q.ByteLimit++
	case "HeightDomain":
		q.Height = 0x100000000
	case "LowLimitDomain":
		q.ByteLimit = 150904
	case "HighLimitDomain":
		q.ByteLimit = 2097153
	case "IdentityBeforePayloadLimit":
		q.ByteLimit = 150905
		q.BlockHash[0] ^= 1
	case "PayloadLimitBeforeProof", "PayloadPlusOne":
		return q, "image_count"
	case "PayloadEqual":
		return q, ""
	}
	return q, "image_identity"
}

type imageProofFixture struct {
	anchor      ImageAnchor
	start       byte
	entries     []imageReplyLeaf
	pred        *imageReplyLeaf
	left, right []consensus.UTXOImageEdge
}

func testImageReplyProof(t *testing.T) {
	runReplyCases(t, checkReplyProof, "VerifyReached", "VerifyFailure", "WrongRootDependency", "WrongRootTaxonomy", "NoVerifiedPrefix",
		"KeyOrder", "Duplicate", "WrongStart", "WrongPredecessor", "InDomainEdgeOrder", "ContradictoryProof", "Root", "BadCover", "FutureEntryBadRoot")
}

func checkReplyProof(t *testing.T, name string) {
	proof := replyProofCase(name)
	f, r := newReplyRound(t, 2, proof.anchor, imageReplyLimits(), false)
	q := imageReplyQuery(proof.anchor, 1, proof.start, replyLimit)
	sibling := f.sendQuery(r, t.Context(), 1, imageReplyQuery(proof.anchor, 1, 0xea, replyLimit), [32]byte{})
	f.sendQuery(r, t.Context(), 0, q, [32]byte{})
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, proof.entries, proof.pred, proof.left, proof.right))
	trace.requireCount(t, "verify", 1)
	if name == "VerifyReached" {
		want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x20, 0, []byte{0x6d})}, Terminal: true}
		requireReplyRange(t, f.requireReceive(r, q, "", nil), want, false)
	} else {
		got := f.receiveReplyRaw(r, q.StartKey, nil)
		requireEqual(t, got.Query, q, "admitted query in completed reply")
		requireReplyNoRange(t, got)
		requireEqual(t, got.Diagnostic, "image_range", "whole proof rejection diagnostic")
	}
	f.requireEmpty(r, proof.start, errImageNoAssignment)
	f.requireEmpty(r, 0xea, context.Canceled)
	f.takeNegativeReply(r, 1, sibling)
	requireReplyHealthy(t, f.workers[0].current)
	requireReplyHealthy(t, f.workers[1].current)
}

func (f *imageReplyFixture) receiveReplyRaw(r *ImageRound, start [36]byte, want error) ImageResult {
	f.t.Helper()
	wait, cancel := context.WithCancel(f.t.Context())
	cancel()
	got, err := r.Receive(wait, start)
	requireEqual(f.t, err, want, "Receive error")
	return got
}

func replyProofCase(name string) imageProofFixture {
	a, b := replyLeaf(0x20, 0, []byte{0x6d}), replyLeaf(0x80, 0, []byte{0x7e})
	p := imageProofFixture{anchor: replyAnchor(a), start: 1, entries: []imageReplyLeaf{a}}
	switch name {
	case "VerifyReached":
	case "KeyOrder":
		p.anchor, p.entries = replyAnchor(a, b), []imageReplyLeaf{b, a}
	case "Duplicate":
		p.entries = append(p.entries, a)
	case "WrongStart":
		p.start = 0x21
	case "WrongPredecessor":
		p.anchor, p.entries, p.pred = replyAnchor(a, b), []imageReplyLeaf{b}, &a
	case "InDomainEdgeOrder":
		p.right = []consensus.UTXOImageEdge{{Depth: 4, Hash: replyLeafHash(b)}, {Depth: 1, Hash: replyLeafHash(a)}}
	case "ContradictoryProof":
		p.anchor, p.entries = replyAnchor(a, b), []imageReplyLeaf{a, b}
		p.right = []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(b)}}
	case "BadCover":
		p.anchor, p.entries = replyAnchor(a, b), []imageReplyLeaf{b}
		p.left = []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(a)}}
	case "FutureEntryBadRoot":
		a.entry[len(a.entry)-9] = 8
	default:
		p.anchor.Root[0] ^= 1
	}
	return p
}

func testImageReplyTime(t *testing.T) {
	runReplyCases(t, checkReplyTime, "AdmitAtD", "AdmitParseAtRD", "AdmitProofAtRD", "FinalAtD", "FinalAtRD", "FinalAfterD", "FinalAfterRD", "CancelRequest", "CancelRound")
	runReplyCases(t, checkReplyEndRace, "DetachedSession", "Replacement", "PriorEnd")
	t.Run("SpentAfterStale", checkReplySpentAfterStale)
	runReplyCases(t, checkReplyCompletionOrder, "CancelBeforeProof", "CancelAfterCompare", "RoundCancelAfterCompare", "NegativeAtRD", "MalformedAtRD")
}

func checkReplyCompletionOrder(t *testing.T, name string) {
	f := newImageReplyFixture(t, true, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner, closeOwner := context.WithCancel(t.Context())
	defer closeOwner()
	l := imageReplyLimits()
	l.RoundLifetime = l.AttemptLifetime
	r := f.beginReplyRound(owner, replyEmptyAnchor, l, true, 0)
	h, q := [32]byte{0x34}, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	f.sendQuery(r, ctx, 0, q, h)
	command, payload, diagnostic := replyChunk, replyChunkBytes(q, nil, nil, nil, nil), ""
	expires := f.clock.add(0).Add(l.RoundLifetime)
	switch name {
	case "CancelBeforeProof":
		f.clock.onReadFrom(".(*imageReplyWork).classify", func(now time.Time) time.Time { cancel(); return now })
	case "NegativeAtRD", "MalformedAtRD":
		f.clock.set(expires.Add(-1))
		f.clock.onReadFrom(".(*imageReplyWork).classify", func(time.Time) time.Time { return expires })
		command, payload = replyNegative, imageReplyQBytes(q)
		if name == "MalformedAtRD" {
			payload, diagnostic = payload[:100], "image_encoding"
		}
	}
	trace := observeReplyCalls(t, nil)
	f.deliver(0, command, payload)
	switch name {
	case "CancelAfterCompare", "RoundCancelAfterCompare":
		if name == "CancelAfterCompare" {
			cancel()
		} else {
			closeOwner()
		}
		f.requireToken(f.takeEmptyRange(r, q, true), r, 0, h, name == "CancelAfterCompare")
	case "CancelBeforeProof":
		trace.requireCount(t, "verify", 0)
		requireReplyNoRange(t, f.requireReceive(r, q, "", context.Canceled))
	default:
		trace.requireCount(t, "decode", 1)
		trace.requireCount(t, "verify", 0)
		requireReplyNoRange(t, f.requireReceive(r, q, diagnostic, nil))
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func checkReplyTime(t *testing.T, name string) {
	f := newImageReplyFixture(t, true, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	owner, stopOwner := context.WithCancel(t.Context())
	defer stopOwner()
	limits, base := imageReplyLimits(), f.clock.add(0)
	if name == "AdmitParseAtRD" || name == "AdmitProofAtRD" || name == "FinalAtRD" || name == "FinalAfterRD" {
		limits.RoundLifetime = 10 * time.Second
	}
	r := f.beginReplyRound(owner, replyEmptyAnchor, limits, true, 0)
	body := [32]byte{0xc1}
	q := f.sendQuery(r, ctx, 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), body)
	d := base.Add(10 * time.Second)
	admitAt := map[string]time.Time{"AdmitAtD": d, "FinalAtRD": d.Add(-1)}[name]
	trace := observeReplyCalls(t, func(event replyCallEvent) {
		if !admitAt.IsZero() && (event.point == "verify" || event.point == "decode") {
			if at := f.clock.add(0); !at.Equal(admitAt) {
				t.Errorf("%s at %v, want %v", event.point, at, admitAt)
			}
		}
	})
	want := prepareReplyTime(f.clock, name, d, cancel, stopOwner)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	if name == "AdmitParseAtRD" || name == "AdmitProofAtRD" {
		checkReplyRDRefusal(f, trace, r, q, name)
		return
	}
	trace.requireCount(t, "decode", 1)
	trace.requireCount(t, "verify", 1)
	got := f.requireReceive(r, q, "", want)
	switch name {
	case "AdmitAtD", "FinalAtD", "FinalAtRD":
		requireEqual(t, f.clock.add(0), d, "final boundary sample")
	case "FinalAfterD", "FinalAfterRD":
		requireEqual(t, f.clock.add(0), d.Add(1), "late final sample")
	}
	if want == nil {
		requireReplyRange(t, got, consensus.UTXOImageRange{Terminal: true}, true)
		require(t, got.Attribution.ValidFor(r, f.ids[0], replyEmptyAnchor, body), "timely proof lost attribution")
	} else {
		requireReplyNoRange(t, got)
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func prepareReplyTime(clock *imageTestClock, name string, d time.Time, cancel, stopOwner func()) error {
	switch name {
	case "AdmitAtD", "AdmitParseAtRD":
		clock.set(d)
	case "AdmitProofAtRD":
		clock.onReadFrom(".(*imageReplyWork).classify", func(time.Time) time.Time { return d })
	case "FinalAfterD", "FinalAfterRD":
		clock.set(d.Add(-1))
		clock.onReadFrom(".(*imageReplyWork).finishProof", func(time.Time) time.Time { return d.Add(1) })
		return errImageExpired
	case "CancelRequest", "CancelRound":
		if name == "CancelRound" {
			cancel = stopOwner
		}
		clock.onReadFrom(".(*imageReplyWork).finishProof", func(now time.Time) time.Time { cancel(); return now })
		return context.Canceled
	default:
		clock.set(d.Add(-1))
		clock.onReadFrom(".(*imageReplyWork).finishProof", func(time.Time) time.Time { return d })
	}
	return nil
}

func checkReplyRDRefusal(f *imageReplyFixture, trace *replyCallTrace, r *ImageRound, q consensus.UTXOImageQuery, name string) {
	f.t.Helper()
	trace.requireCount(f.t, "verify", 0)
	if name == "AdmitParseAtRD" {
		trace.requireCount(f.t, "decode", 0)
	}
	f.requireEmpty(r, q.StartKey[0], context.Canceled)
	f.clock.add(1)
	requireReplyNoRange(f.t, f.requireReceive(r, q, "", errImageExpired))
	f.requireEmpty(r, q.StartKey[0], errImageNoAssignment)
}

func holdReplyStage(t *testing.T, p imageReplyPeer, point string, frameLen int) (<-chan struct{}, func()) {
	t.Helper()
	if replyCallTracing {
		return holdReplyCall(t, point, p.current)
	}
	return holdReplyRead(t, p.wire, 24+frameLen)
}

func checkReplyEndRace(t *testing.T, name string) {
	leaf := replyLeaf(0x20, 0, []byte{0x42})
	anchor := replyAnchor(leaf)
	f, r := newReplyRound(t, 2, anchor, imageReplyLimits(), false)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	q := f.sendQuery(r, ctx, 0, imageReplyQuery(anchor, 1, 1, replyLimit), [32]byte{})
	payload := replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, nil)
	wantRange := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x20, 0, []byte{0x42})}, Terminal: true}
	finish := f.pauseReplyProof(name, payload, wantRange)
	want := context.Canceled
	if name == "DetachedSession" {
		f.s.retireImagePeer(f.workers[0].current)
		want = errImageDisconnected
	} else {
		cancel()
	}
	requireReplyNoRange(t, f.requireReceive(r, q, "", want))
	if name == "Replacement" {
		q.ByteLimit++
		f.sendQuery(r, t.Context(), 1, q, [32]byte{})
	}
	finish()
	if name != "Replacement" {
		f.requireEmpty(r, 1, errImageNoAssignment)
		return
	}
	f.requireEmpty(r, q.StartKey[0], context.Canceled)
	f.deliver(1, replyChunk, replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, nil))
	requireReplyRange(t, f.requireReceive(r, q, "", nil), wantRange, false)
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func (f *imageReplyFixture) pauseReplyProof(name string, payload []byte, want consensus.UTXOImageRange) func() {
	t := f.t
	t.Helper()
	p := f.workers[0]
	if name != "Replacement" || replyCallTracing {
		entered, release := holdReplyStage(t, p, "verify-return", len(payload))
		f.sendFrame(0, replyChunk, payload, false)
		requireChannelClosed(t, entered, "admitted reply before final compare")
		return func() { release(); f.sendFrame(0, "ping", nil, false) }
	}
	release := holdWorkLease(t, f.s)
	work := imageReplyWork{peer: p.current}
	t.Cleanup(work.release)
	require(t, work.admitDecode(binary.LittleEndian.Uint64(payload[:8]), uint64(len(payload))), "original decode admission")
	command, _ := encodeWireCommand(replyChunk)
	reply, decoded, reason := consensus.DecodeUTXOImageReply(command, payload)
	require(t, work.classify(reply, decoded, reason), "original proof admission: %s", reason)
	result, verified, reason := consensus.VerifyUTXOImageChunk(reply)
	require(t, verified && reason == "" && reflect.DeepEqual(result, want), "original proof before replacement: %s", reason)
	return func() {
		work.finishProof(result, verified, reason)
		work.release()
		release()
	}
}

func checkReplySpentAfterStale(t *testing.T) {
	f := newImageReplyFixture(t, true, 2)
	now := f.clock.add(0)
	limits := imageReplyLimits()
	limits.Global.ScalarProofWork = 7191
	r := f.beginReplyRound(t.Context(), replyEmptyAnchor, limits, false, 0, 1)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
	prepareReplyTime(f.clock, "FinalAfterD", now.Add(10*time.Second), nil, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
	second := f.sendQuery(r, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit), [32]byte{})
	trace := observeReplyCalls(t, nil)
	f.deliver(1, replyChunk, replyChunkBytes(second, nil, nil, nil, nil))
	trace.requireCount(t, "decode", 1)
	trace.requireCount(t, "verify", 0)
	f.requireEmpty(r, 2, context.Canceled)
}

func checkReplyDetachedFrame(t *testing.T) {
	f, r, q := newImageReplyFixture(t, true, 1).withInitialQuery(t.Context())
	f.addReplyPeer(f.ids[0])
	other := f.beginReplyRound(t.Context(), replyEmptyAnchor, imageReplyLimits(), false, 1)
	replacement := f.sendQuery(other, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit), [32]byte{})
	payload := replyChunkBytes(q, nil, nil, nil, nil)
	entered, release := holdReplyStage(t, f.workers[0], "checked-frame", len(payload))
	defer release()
	f.sendFrame(0, replyChunk, payload, false)
	requireChannelClosed(t, entered, "original checked frame")
	f.s.unregisterPeer(f.workers[0].current)
	trace := observeReplyCalls(t, nil)
	release()
	f.sendFrame(0, "ping", nil, false)
	requireReplyNoRange(t, f.requireReceive(r, q, "", errImageDisconnected))
	f.requireEmpty(r, 1, errImageNoAssignment)
	trace.requireLookup(t, f.workers[0].current, nil)
	f.requireEmpty(other, 2, context.Canceled)
	f.deliver(1, replyChunk, replyChunkBytes(replacement, nil, nil, nil, nil))
	requireReplyRange(t, f.requireReceive(other, replacement, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
}

func checkReplyArmingUnallocated(t *testing.T, roundContext bool) {
	f := newImageReplyFixture(t, true, 1)
	hook := newImageHookCtx()
	owner, ctx := imageUnwindCtx(hook, newImageHookCtx(), roundContext)
	r := f.beginReplyRound(owner, replyEmptyAnchor, imageReplyLimits(), false, 0)
	session := f.workers[0].current.imageSession
	q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	hook.onAfterFunc = imageUnwinder(false)
	requireImageUnwindReport(t, goReplySend(r, ctx, f.ids[0], q, [32]byte{}), false)
	f.requireEmpty(r, 1, errImageNoAssignment)
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	f.requireEmpty(r, 1, errImageNoAssignment)
	requireReplyIndexGone(f, trace, session, q.RequestID)
	f.sendQuery(r, context.Background(), 0, q, [32]byte{})
}

func checkReplyIndexLastUse(t *testing.T, closeService bool) {
	f, r, q := newImageReplyFixture(t, true, 1).withInitialQuery(context.Background())
	session, instance := observeReplyIndex(f, q)
	if closeService {
		must(t, f.s.Close(), "close image Service")
		f.requireEmpty(r, 1, errServiceClosed)
	} else {
		must(t, f.workers[0].remote.Close(), "end image peer")
		requireChannelClosed(t, f.workers[0].done, "peer unregister completed")
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageDisconnected))
		f.requireEmpty(r, 1, errImageNoAssignment)
		requireReplyHealthy(t, f.workers[0].current)
	}
	requireChannelClosed(t, f.workers[0].done, "original worker join")
	runtime.GC()
	require(t, instance.Value() == nil, "old registration retains a retired instance")
	runtime.KeepAlive(session)
}

func observeReplyIndex(f *imageReplyFixture, q consensus.UTXOImageQuery) (*imageSession, weak.Pointer[imageInstance]) {
	req := f.lockRequester()
	defer req.mu.Unlock()
	session := f.workers[0].current.imageSession
	inst := req.current[imageKey{replyEmptyAnchor, q.StartKey}]
	return session, weak.Make(inst)
}

type replyLedgerAxis struct {
	phase, name string
	prospective uint64
	amount      uint64
	limit       func(*ImageUnits) *uint64
	unit        int
	spent       bool
}

var replyLedgerAxes = []replyLedgerAxis{
	{"Parse", "ScalarProofWork", 129, 129, func(u *ImageUnits) *uint64 { return &u.ScalarProofWork }, 4, true},
	{"Parse", "Passes", 1, 1, func(u *ImageUnits) *uint64 { return &u.Passes }, 6, true},
	{"Parse", "Copies", 1, 1, func(u *ImageUnits) *uint64 { return &u.Copies }, 7, true},
	{"Parse", "CopyHoldingBytes", 129, 129, func(u *ImageUnits) *uint64 { return &u.CopyHoldingBytes }, 10, false},
	{"Proof", "ScalarProofWork", 3596, 3467, func(u *ImageUnits) *uint64 { return &u.ScalarProofWork }, 4, true},
	{"Proof", "Hashes", 1, 1, func(u *ImageUnits) *uint64 { return &u.Hashes }, 5, true},
	{"Proof", "Passes", 7, 6, func(u *ImageUnits) *uint64 { return &u.Passes }, 6, true},
	{"Proof", "Copies", 41, 40, func(u *ImageUnits) *uint64 { return &u.Copies }, 7, true},
	{"Proof", "ProofHoldingBytes", 641, 641, func(u *ImageUnits) *uint64 { return &u.ProofHoldingBytes }, 9, false},
	{"Proof", "CopyHoldingBytes", 258, 129, func(u *ImageUnits) *uint64 { return &u.CopyHoldingBytes }, 10, false},
	{"Holder", "HolderBytes", 128, 128, func(u *ImageUnits) *uint64 { return &u.HolderBytes }, 11, false},
}

func testImageReplyLedger(t *testing.T) {
	for _, axis := range replyLedgerAxes {
		for _, ledger := range []string{"PerPeer", "Global"} {
			runReplyLedgerAxis(t, axis, ledger)
		}
	}
	t.Run("HolderTransferEqual", func(t *testing.T) { checkReplyLedger(t, replyLedgerAxes[10], "Global", "Equal") })
	t.Run("HolderRetainedUntilTake", func(t *testing.T) { checkReplyOverlap(t, replyLedgerAxes[10], 1) })
	t.Run("HolderPerPeerOverlap", func(t *testing.T) { checkReplyOverlap(t, replyLedgerAxes[10], 0) })
	t.Run("MaximumCopyRefused", func(t *testing.T) { checkReplyMaximumAllocation(t, 2097151, false) })
	t.Run("MaximumCopyAdmitted", func(t *testing.T) { checkReplyMaximumAllocation(t, 2097152, false) })
	t.Run("MaximumUnknownUncharged", func(t *testing.T) { checkReplyMaximumAllocation(t, 2097152, true) })
	for _, pred := range []bool{false, true} {
		for _, over := range []bool{false, true} {
			name := map[bool]string{false: "RightEdge", true: "Predecessor"}[pred] + map[bool]string{false: "Equal", true: "Over"}[over]
			t.Run("NonemptyHolder"+name, func(t *testing.T) { checkReplyNonemptyHolder(t, pred, over) })
		}
	}
}

func checkReplyNonemptyHolder(t *testing.T, pred, over bool) {
	f := newImageReplyFixture(t, true, 1)
	a, b := replyLeaf(0x20, 0, []byte{0x24, 0x25}), replyLeaf(0x80, 0, []byte{0xa1, 0xa2, 0xa3})
	anchor := replyAnchor(a, b)
	l := imageReplyLimits()
	l.Global.HolderBytes = 298
	start, entries := byte(1), []imageReplyLeaf{a}
	right := []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(b)}}
	var before *imageReplyLeaf
	want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x20, 0, []byte{0x24, 0x25})}, RightEdge: right}
	if pred {
		l.Global.HolderBytes, start, entries, before, right = 389, 0x40, []imageReplyLeaf{b}, &a, nil
		previous := want.Entries[0]
		want = consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x80, 0, []byte{0xa1, 0xa2, 0xa3})}, Predecessor: &previous, Terminal: true}
	}
	if over {
		l.Global.HolderBytes--
	}
	r := f.beginReplyRound(t.Context(), anchor, l, true, 0)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(anchor, 1, start, replyLimit), [32]byte{0xa8})
	f.deliver(0, replyChunk, replyChunkBytes(q, entries, before, nil, right))
	if over {
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageHolderLimit))
	} else {
		requireReplyRange(t, f.requireReceive(r, q, "", nil), want, true)
	}
	f.requireEmpty(r, start, errImageNoAssignment)
}

func runReplyLedgerAxis(t *testing.T, axis replyLedgerAxis, ledger string) {
	prefix := axis.phase + axis.name + ledger
	for _, mode := range []string{"Equal", "Over"} {
		t.Run(prefix+mode, func(t *testing.T) { checkReplyLedger(t, axis, ledger, mode) })
	}
	if axis.spent {
		t.Run(prefix+"Spent", func(t *testing.T) { checkReplyLedger(t, axis, ledger, "Spent") })
		return
	}
	t.Run(prefix+"Ended", func(t *testing.T) { checkReplyHoldingEnded(t, axis, ledger) })
	if ledger == "Global" {
		t.Run(prefix+"Overlap", func(t *testing.T) { checkReplyOverlap(t, axis, 1) })
	} else {
		t.Run(prefix+"Owned", func(t *testing.T) { checkReplyHoldingOwned(t, axis) })
	}
}

func replyLedgerLimits(axis replyLedgerAxis, ledger, mode string) (ImageLimits, bool) {
	l := imageReplyLimits()
	base := axis.prospective
	prelude := mode == "Spent" || base == 1
	if prelude {
		history := base
		if axis.phase == "Parse" && axis.name == "ScalarProofWork" {
			history = 120
		}
		base += history
	}
	if mode != "Equal" {
		base--
	}
	units := &l.PerPeer
	if ledger == "Global" {
		units = &l.Global
	}
	*axis.limit(units) = base
	return l, prelude
}

func checkReplyLedger(t *testing.T, axis replyLedgerAxis, ledger, mode string) {
	l, prelude := replyLedgerLimits(axis, ledger, mode)
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, true)
	if prelude {
		source := 0
		if ledger == "Global" {
			source = 1
		}
		f.replyPreSpend(r, source, axis.phase == "Proof")
	}
	id := uint64(1)
	if prelude && ledger == "PerPeer" {
		id = 2
	}
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, id, 2, replyLimit), [32]byte{0xa5})
	before := replyCharged(f, r, 0)
	trace := observeReplyCalls(t, nil)
	payload := replyChunkBytes(q, nil, nil, nil, nil)
	if axis.phase == "Parse" {
		payload[124] = 2
	}
	f.deliver(0, replyChunk, payload)
	f.checkReplyLedgerResult(r, q, axis.phase, mode == "Equal", trace)
	after := replyCharged(f, r, 0)
	want := [7]uint64{129, 0, 1, 1}
	if axis.phase == "Parse" && mode != "Equal" {
		want = [7]uint64{}
	}
	if axis.phase == "Holder" || axis.phase == "Proof" && mode == "Equal" {
		want = [7]uint64{3596, 1, 7, 41}
	}
	for owner := range after {
		for i, w := range want {
			requireEqual(t, after[owner][i]-before[owner][i], w, fmt.Sprintf("ledger %d component %d after disposition", owner, i))
		}
	}
}

func replyCharged(f *imageReplyFixture, r *ImageRound, source int) (counts [2][7]uint64) {
	req := f.lockRequester()
	defer req.mu.Unlock()
	for i, u := range [2]imageUnitVector{*r.perPeer[f.workers[source].current.imageSession], r.global} {
		counts[i] = [7]uint64{u[unitScalarProofWork], u[unitHashes], u[unitPasses], u[unitCopies], u[unitCopyHoldingBytes], u[unitProofHoldingBytes], u[unitHolderBytes]}
	}
	return counts
}

func (f *imageReplyFixture) replyPreSpend(r *ImageRound, source int, proof bool) {
	q := f.sendQuery(r, f.t.Context(), source, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{0x32})
	if proof {
		f.deliver(source, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
		requireReplyRange(f.t, f.requireReceive(r, q, "", nil), consensus.UTXOImageRange{Terminal: true}, r.probe)
	} else {
		f.takeNegativeReply(r, source, q)
	}
}

func (f *imageReplyFixture) checkReplyLedgerResult(r *ImageRound, q consensus.UTXOImageQuery, phase string, admits bool, trace *replyCallTrace) {
	t := f.t
	t.Helper()
	if admits {
		trace.requireCount(t, "decode", 1)
		if phase == "Parse" {
			trace.requireCount(t, "verify", 0)
			requireReplyNoRange(t, f.requireReceive(r, q, "image_encoding", nil))
			return
		}
		trace.requireCount(t, "verify", 1)
		requireReplyRange(t, f.requireReceive(r, q, "", nil), consensus.UTXOImageRange{Terminal: true}, r.probe)
		return
	}
	switch phase {
	case "Parse":
		trace.requireCount(t, "decode", 0)
		f.rejectReplyLedgerWhileCurrent(r, q)
	case "Proof":
		trace.requireCount(t, "decode", 1)
		trace.requireCount(t, "verify", 0)
		f.rejectReplyLedgerWhileCurrent(r, q)
	case "Holder":
		trace.requireCount(t, "verify", 1)
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageHolderLimit))
	}
	f.requireEmpty(r, q.StartKey[0], errImageNoAssignment)
}

func (f *imageReplyFixture) rejectReplyLedgerWhileCurrent(r *ImageRound, q consensus.UTXOImageQuery) {
	t := f.t
	t.Helper()
	f.requireEmpty(r, q.StartKey[0], context.Canceled)
	got := f.tryReplyAdmission(r, 1, q, [32]byte{0x65})
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageAssignmentCurrent, "capacity refund cannot admit replacement")
	f.clock.add(10*time.Second + 1)
	requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
}

func checkReplyHoldingEnded(t *testing.T, axis replyLedgerAxis, ledger string) {
	l, _ := replyLedgerLimits(axis, ledger, "Equal")
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, false)
	source, id := 0, uint64(2)
	if ledger == "Global" {
		source, id = 1, 1
	}
	f.replyPreSpend(r, 0, axis.phase != "Parse")
	q := f.sendQuery(r, t.Context(), source, imageReplyQuery(replyEmptyAnchor, id, 2, replyLimit), [32]byte{})
	if axis.phase == "Parse" {
		payload := replyChunkBytes(q, nil, nil, nil, nil)
		payload[124] = 2
		f.deliver(source, replyChunk, payload)
		requireReplyNoRange(t, f.requireReceive(r, q, "image_encoding", nil))
	} else {
		f.deliver(source, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
		requireReplyRange(t, f.requireReceive(r, q, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
	}
}

func checkReplyHoldingOwned(t *testing.T, axis replyLedgerAxis) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), false)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
	session := f.workers[0].current.imageSession
	held := make(chan uint64, 1)
	observe := func(now time.Time) time.Time { held <- r.perPeer[session][axis.unit]; return now }
	switch axis.phase {
	case "Parse":
		f.clock.onReadFrom(".(*imageReplyWork).classify", observe)
	case "Proof":
		f.clock.onReadFrom(".(*imageReplyWork).finishProof", observe)
	}
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	if axis.phase == "Holder" {
		req := f.lockRequester()
		held <- r.perPeer[session][axis.unit]
		req.mu.Unlock()
	}
	requireEqual(t, awaitImageResult(t, held, "live volume"), axis.prospective, "active ownership volume")
	requireReplyRange(t, f.requireReceive(r, q, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
}

func checkReplyOverlap(t *testing.T, axis replyLedgerAxis, source int) {
	if axis.phase != "Holder" {
		checkReplyScratchOverlap(t, axis)
		return
	}
	l := imageReplyLimits()
	id := uint64(1)
	if source == 0 {
		l.PerPeer.HolderBytes, id = 128, 2
	} else {
		l.Global.HolderBytes = 128
	}
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, false)
	a, b := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), imageReplyQuery(replyEmptyAnchor, id, 2, replyLimit)
	f.sendQuery(r, t.Context(), 0, a, [32]byte{})
	f.sendQuery(r, t.Context(), source, b, [32]byte{})
	f.deliver(0, replyChunk, replyChunkBytes(a, nil, nil, nil, nil))
	f.deliver(source, replyChunk, replyChunkBytes(b, nil, nil, nil, nil))
	requireReplyNoRange(t, f.requireReceive(r, b, "", errImageHolderLimit))
	if source == 0 {
		other := f.beginReplyRound(t.Context(), replyEmptyAnchor, l, false, 0)
		c := f.sendQuery(other, t.Context(), source, imageReplyQuery(replyEmptyAnchor, 3, 3, replyLimit), [32]byte{})
		f.deliver(source, replyChunk, replyChunkBytes(c, nil, nil, nil, nil))
		requireReplyRange(t, f.requireReceive(other, c, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
		id = c.RequestID
	}
	requireReplyRange(t, f.requireReceive(r, a, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
	b.RequestID, b.StartKey[0] = id+1, 3
	f.sendQuery(r, t.Context(), source, b, [32]byte{})
	f.deliver(source, replyChunk, replyChunkBytes(b, nil, nil, nil, nil))
	requireReplyRange(t, f.requireReceive(r, b, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
}

func checkReplyScratchOverlap(t *testing.T, axis replyLedgerAxis) {
	l := imageReplyLimits()
	*axis.limit(&l.Global) = 2*axis.prospective - 1
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, false)
	a, b := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit)
	f.sendQuery(r, t.Context(), 0, a, [32]byte{})
	f.sendQuery(r, t.Context(), 1, b, [32]byte{})
	first := replyChunkBytes(a, nil, nil, nil, nil)
	point := "verify"
	if axis.phase == "Parse" {
		point = "decode"
		first[124] = 2
	}
	f.finishReplyScratchOverlap(r, a, b, first, point)
}

func (f *imageReplyFixture) finishReplyScratchOverlap(r *ImageRound, a, b consensus.UTXOImageQuery, first []byte, point string) {
	t := f.t
	t.Helper()
	if replyCallTracing {
		entered, release := holdReplyCall(t, point, f.workers[0].current)
		defer release()
		f.sendFrame(0, replyChunk, first, false)
		requireChannelClosed(t, entered, "real scratch ownership")
		f.deliver(1, replyChunk, replyChunkBytes(b, nil, nil, nil, nil))
		replyCallOwner.Load().requireAbsentCall(t, f.workers[1].current, point)
		f.requireEmpty(r, 2, context.Canceled)
		release()
		f.sendFrame(0, "ping", nil, false)
	} else {
		f.deliver(0, replyChunk, first)
	}
	if point == "decode" {
		requireReplyNoRange(t, f.requireReceive(r, a, "image_encoding", nil))
		f.takeNegativeReply(r, 1, b)
	} else {
		want := consensus.UTXOImageRange{Terminal: true}
		requireReplyRange(t, f.requireReceive(r, a, "", nil), want, false)
		f.deliver(1, replyChunk, replyChunkBytes(b, nil, nil, nil, nil))
		requireReplyRange(t, f.requireReceive(r, b, "", nil), want, false)
	}
}

func checkReplyMaximumAllocation(t *testing.T, capBytes uint64, unknown bool) {
	leaves, entries := replyMaxLeaves()
	anchor := replyAnchor(leaves...)
	l := imageReplyLimits()
	l.PerPeer.CopyHoldingBytes = capBytes
	f, r := newReplyRound(t, 1, anchor, l, false)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(anchor, 1, 1, 2097152), [32]byte{})
	other := f.beginReplyRound(t.Context(), anchor, l, false, 0)
	f.sendQuery(other, t.Context(), 0, imageReplyQuery(anchor, 2, 2, 2097152), [32]byte{})
	wire := q
	if unknown {
		wire.RequestID = 7
	}
	payload := replyChunkBytes(wire, leaves, nil, nil, nil)
	requireEqual(t, len(payload), 2097152, "maximum input length")
	release := holdWorkLease(t, f.s)
	defer release()
	old, independent := replyCharged(f, r, 0), replyCharged(f, other, 0)
	admitted := capBytes == 2097152 && !unknown
	if admitted {
		command, _ := encodeWireCommand(replyChunk)
		reply, decoded, reason := consensus.DecodeUTXOImageReply(command, payload)
		require(t, decoded && reason == "", "maximum scalar layout: %s", reason)
		const firstCovenantByte = 120 + 4 + 46 + 3
		payload[firstCovenantByte] ^= 0xff
		result, verified, reason := consensus.VerifyUTXOImageChunk(reply)
		payload[firstCovenantByte] ^= 0xff
		require(t, verified, "owned maximum reply proof after transport byte reuse: %s", reason)
		require(t, reflect.DeepEqual(result, consensus.UTXOImageRange{Entries: entries, Terminal: true}), "owned maximum result differs from original entries")
	}
	trace := observeReplyCalls(t, nil)
	must(t, f.workers[0].current.handleMessage(message{Command: replyChunk, Payload: payload}), "process checksum-valid maximum frame")
	trace.requireCount(t, "decode", map[bool]int{false: 0, true: 1}[admitted])
	f.requireEmpty(r, 1, context.Canceled)
	f.requireEmpty(other, 2, context.Canceled)
	if admitted {
		for i := range old {
			old[i][0] += 2097152
			old[i][2]++
			old[i][3]++
		}
	}
	requireEqual(t, replyCharged(f, r, 0), old, "original round actual accounting after maximum input")
	requireEqual(t, replyCharged(f, other, 0), independent, "independent round accounting")
}

func testImageReplyReceive(t *testing.T) {
	t.Run("DisconnectAfterCompare", checkReplyReadyDisconnect)
	t.Run("Oldest", func(t *testing.T) { checkReplyFIFO(t, true) })
	t.Run("OneTake", func(t *testing.T) { checkReplyFIFO(t, false) })
	t.Run("RejectedWhole", func(t *testing.T) { checkReplyProof(t, "NoVerifiedPrefix") })
	runReplyCases(t, checkReplyIntervals, "ExactStart", "ExactRound", "Predecessor", "RightEdge", "Terminal", "FullEntries", "HeldTake", "DataIsolation")
}

func checkReplyReadyDisconnect(t *testing.T) {
	f := newImageReplyFixture(t, true, 1)
	r := f.beginReplyRound(context.Background(), replyEmptyAnchor, imageReplyLimits(), true, 0)
	q, h := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{0x31}
	f.sendQuery(r, t.Context(), 0, q, h)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	must(t, f.workers[0].remote.Close(), "end registration after reply comparison")
	requireChannelClosed(t, f.workers[0].done, "original registration exit")
	f.requireToken(f.takeEmptyRange(r, q, true), r, 0, h, false)
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func checkReplyFIFO(t *testing.T, two bool) {
	x, y := replyLeaf(0x20, 0, []byte{4}), replyLeaf(0x80, 0, []byte{8})
	anchor := replyAnchor(x, y)
	f, r := newReplyRound(t, 2, anchor, imageReplyLimits(), false)
	a, b := imageReplyQuery(anchor, 1, 1, replyLimit), imageReplyQuery(anchor, 1, 1, replyLimit+1)
	sibling := imageReplyQuery(anchor, 2, 3, replyLimit)
	entries := []consensus.UTXOImageEntry{replyEntry(0x20, 0, []byte{4}), replyEntry(0x80, 0, []byte{8})}
	right := []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(y)}}
	f.sendQuery(r, t.Context(), 0, a, [32]byte{})
	f.deliver(0, replyChunk, replyChunkBytes(a, []imageReplyLeaf{x}, nil, nil, right))
	if two {
		f.sendQuery(r, t.Context(), 0, sibling, [32]byte{})
		f.sendQuery(r, t.Context(), 1, b, [32]byte{})
		f.deliver(1, replyChunk, replyChunkBytes(b, []imageReplyLeaf{x, y}, nil, nil, nil))
	}
	requireReplyRange(t, f.requireReceive(r, a, "", nil), consensus.UTXOImageRange{Entries: entries[:1], RightEdge: right}, false)
	if two {
		requireReplyRange(t, f.requireReceive(r, b, "", nil), consensus.UTXOImageRange{Entries: entries, Terminal: true}, false)
		f.requireEmpty(r, 3, context.Canceled)
		f.takeNegativeReply(r, 0, sibling)
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func checkReplyIntervals(t *testing.T, name string) {
	a, b := replyLeaf(0x20, 0, []byte{0x26, 0x27}), replyLeaf(0x80, 0, []byte{0x81, 0x82})
	anchor := replyAnchor(a, b)
	l := imageReplyLimits()
	l.Global.DistinctStarts = 2
	f, r := newReplyRound(t, 2, anchor, l, false)
	first, later := imageReplyQuery(anchor, 1, 1, replyLimit), imageReplyQuery(anchor, 1, 0x40, replyLimit)
	f.sendQuery(r, t.Context(), 1, later, [32]byte{})
	f.deliver(1, replyChunk, replyChunkBytes(later, []imageReplyLeaf{b}, &a, nil, nil))
	if name == "ExactStart" {
		f.requireEmpty(r, 1, errImageNoAssignment)
	}
	if name == "ExactRound" {
		other := f.beginReplyRound(t.Context(), anchor, l, false, 1)
		f.requireEmpty(other, 0x40, errImageNoAssignment)
	}
	checkReplyIntervalTakes(f, r, first, later, a, b, name)
	got := f.tryReplyAdmission(r, 0, imageReplyQuery(anchor, 2, 3, replyLimit), [32]byte{})
	requireQueryResult(t, got, consensus.UTXOImageQuery{}, errImageLimit, "distinct-start budget remains spent after take")
}

func checkReplyIntervalTakes(f *imageReplyFixture, r *ImageRound, first, later consensus.UTXOImageQuery, a, b imageReplyLeaf, name string) {
	t := f.t
	t.Helper()
	right := []consensus.UTXOImageEdge{{Depth: 0, Hash: replyLeafHash(b)}}
	aEntry := replyEntry(0x20, 0, []byte{0x26, 0x27})
	bEntry := replyEntry(0x80, 0, []byte{0x81, 0x82})
	entries := []imageReplyLeaf{a}
	want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{aEntry}, RightEdge: right}
	if name == "FullEntries" || name == "DataIsolation" {
		entries, right = []imageReplyLeaf{a, b}, nil
		want = consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{aEntry, bEntry}, Terminal: true}
	}
	f.sendQuery(r, t.Context(), 0, first, [32]byte{})
	f.deliver(0, replyChunk, replyChunkBytes(first, entries, nil, nil, right))
	got := f.requireReceive(r, first, "", nil)
	requireReplyRange(t, got, want, false)
	if name == "DataIsolation" {
		got.Range.Entries[0].Entry.CovenantData[0] = 0xda
		got.Range.Entries[1].Entry.CovenantData[0] = 0xdb
	}
	got = f.requireReceive(r, later, "", nil)
	requireReplyRange(t, got, consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{bEntry}, Predecessor: &aEntry, Terminal: true}, false)
	f.requireEmpty(r, 0x40, errImageNoAssignment)
}

func testImageReplySend(t *testing.T) {
	runReplyCases(t, checkReplyBeforeWrite, "TerminalNilBeforeWrite", "CancelBeforeWrite", "ExpireBeforeWrite")
	runReplyCases(t, checkReplyWhileWriting, "ProvisionalDuringWrite", "PendingLastUse", "ReplyWinsWriteError",
		"CancelWhileWriting", "ExpireWhileWriting", "PeerWhileWriting", "RoundWhileWriting")
	runReplyCases(t, checkReplyStagedUnwind, "StagedPanic", "StagedGoexit", "StagedNegativePanic", "StagedRejectionPanic", "StagedHolderRefusalPanic")
	t.Run("WriteFailureFirst", func(t *testing.T) { checkReplyWriteFailure(t, false) })
	t.Run("OldReplyAfterWriteFailure", func(t *testing.T) { checkReplyWriteFailure(t, true) })
	runReplyCases(t, checkReplyAfterUnwind, "AfterPanicOrdinary", "AfterGoexitOrdinary", "AfterPanicProbe", "AfterGoexitProbe")
}

// goReplySend captures the value that escapes the actual Request or Probe call.
func goReplySend(r *ImageRound, ctx context.Context, source string, q consensus.UTXOImageQuery, hash [32]byte) <-chan any {
	done := make(chan any, 1)
	go func() {
		var result any = imageGoexit
		defer func() { done <- cmp.Or(recover(), result) }()
		result = imageReplyCall(r, ctx, source, q, hash)
	}()
	return done
}

type parkedReplySend struct {
	done    <-chan any
	release func()
}

// parkReplySend passes the full request to the receiving endpoint, then holds the payload Write before its return.
func (f *imageReplyFixture) parkReplySend(r *ImageRound, ctx context.Context, source int, q consensus.UTXOImageQuery, hash [32]byte, finish func() error) parkedReplySend {
	t := f.t
	t.Helper()
	p := f.workers[source]
	want := imageReplyQBytes(q)
	entered, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	p.conn.mu.Lock()
	p.conn.writeHook = func(b []byte) (int, error) {
		n, err := p.wire.Write(b)
		if err != nil || !bytes.Equal(b, want) {
			return n, err
		}
		close(entered)
		<-proceed
		if finish != nil {
			return n, finish()
		}
		return n, nil
	}
	p.conn.mu.Unlock()
	done := goReplySend(r, ctx, f.ids[source], q, hash)
	frame := f.readReplyPeer(p.remote)
	requireEqual(t, frame.Command, "getutxoimg", "parked send command")
	require(t, bytes.Equal(frame.Payload, want), "parked send carried a different query")
	requireChannelClosed(t, entered, "request payload Write")
	return parkedReplySend{done, release}
}

func requireReplySent(t *testing.T, done <-chan any, q consensus.UTXOImageQuery, err error) {
	t.Helper()
	requireEqual(t, awaitImageResult(t, done, "send completion"), any(imageResult{q, err}), "send result")
}

func unwindReplyWrite(goexit bool) func() error {
	return func() error { imageUnwinder(goexit)(); return nil }
}

func checkReplyBeforeWrite(t *testing.T, name string) {
	traced := replyCallTracing && name == "TerminalNilBeforeWrite"
	for _, mode := range []string{"Request", "Probe", "ProbePositive", "RequestAfterLock", "ProbeAfterLock"} {
		final := strings.HasSuffix(mode, "AfterLock")
		positive := mode == "ProbePositive"
		if final && !traced || positive && name != "TerminalNilBeforeWrite" {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), strings.HasPrefix(mode, "Probe"))
			q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
			p, ctx := f.workers[0], newImageHookCtx()
			p.current.writeMu.Lock()
			unlock := sync.OnceFunc(p.current.writeMu.Unlock)
			defer unlock()
			p.conn.mu.Lock()
			before := len(p.conn.writes)
			p.conn.writeHook = func(b []byte) (int, error) { return len(b), nil }
			p.conn.mu.Unlock()
			waiting := f.clock.readFrom(".(*imageInstance).preWriteEnd")
			release := func() {}
			if traced {
				waiting, release = holdReplyCall(t, map[bool]string{false: "write-check-wait", true: "write-check-held"}[final], p.current)
				if final {
					unlock()
				}
			}
			hash := [32]byte{0x26}
			done := goReplySend(r, ctx, f.ids[0], q, hash)
			requireChannelClosed(t, waiting, "admitted send before authorization")
			var want error
			switch name {
			case "CancelBeforeWrite":
				ctx.end(errImageRequestEnd)
				want = errImageRequestEnd
			case "ExpireBeforeWrite":
				f.clock.add(10*time.Second + 1)
				want = errImageExpired
			}
			if positive {
				f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
			} else {
				f.deliver(0, replyNegative, imageReplyQBytes(q))
			}
			var continued <-chan struct{}
			if traced && !final {
				continued, _ = holdReplyCall(t, "write-wait", p.current)
			}
			release()
			got := awaitReplyBefore(t, done, continued, "continued write wait after terminal reply")
			p.conn.mu.Lock()
			writes := len(p.conn.writes) - before
			p.conn.mu.Unlock()
			requireEqual(t, writes, 0, "writes after terminal decision")
			requireEqual(t, got, any(imageResult{q, want}), "pre-write result")
			unlock()
			if positive {
				f.requireToken(f.takeEmptyRange(r, q, true), r, 0, hash, true)
			} else if want == nil {
				requireReplyNoRange(t, f.requireReceive(r, q, "", nil))
			}
			f.requireEmpty(r, 1, errImageNoAssignment)
		})
	}
}

func checkReplyWhileWriting(t *testing.T, name string) {
	l := imageReplyLimits()
	if name == "ExpireWhileWriting" {
		l.Global.ScalarProofWork = 3596
	}
	l.Global.PendingNetworkBytes = 120
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, false)
	q, next := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit)
	ctx := newImageHookCtx()
	var writeErr error
	var recorded chan string
	if name == "ReplyWinsWriteError" {
		writeErr = errImageScriptedWrite
		recorded = make(chan string, 1)
		p := f.workers[0]
		p.conn.mu.Lock()
		p.conn.closeHook = sync.OnceFunc(func() { recorded <- p.current.snapshotState().LastError })
		p.conn.mu.Unlock()
	}
	send := f.parkReplySend(r, ctx, 0, q, [32]byte{}, func() error { return writeErr })
	defer send.release()
	want := applyReplyWritingEnd(f, r, ctx, name)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	if name == "RoundWhileWriting" {
		f.requireEmpty(r, 1, errImageRoundClosed)
	} else {
		f.requireEmpty(r, 1, context.Canceled)
		requireQueryResult(t, f.tryReplyAdmission(r, 1, next, [32]byte{}),
			consensus.UTXOImageQuery{}, errImageLimit, "pending send retains its 120 bytes")
	}
	send.release()
	requireReplySent(t, send.done, q, nil)
	if name == "RoundWhileWriting" {
		f.requireEmpty(r, 1, want)
		return
	}
	got := f.requireReceive(r, q, "", want)
	if want == nil {
		requireReplyRange(t, got, consensus.UTXOImageRange{Terminal: true}, false)
	} else {
		requireReplyNoRange(t, got)
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
	if writeErr != nil {
		requireEqual(t, awaitImageResult(t, recorded, "failed write Close"), writeErr.Error(), "later write error at socket Close")
		requireChannelClosed(t, f.workers[0].conn.closed, "failed writer closes its transport")
	}
	f.sendQuery(r, t.Context(), 1, next, [32]byte{})
	if name == "ExpireWhileWriting" {
		f.deliver(1, replyChunk, replyChunkBytes(next, nil, nil, nil, nil))
		requireReplyRange(t, f.requireReceive(r, next, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
	}
}

func applyReplyWritingEnd(f *imageReplyFixture, r *ImageRound, ctx *imageHookCtx, name string) error {
	switch name {
	case "CancelWhileWriting":
		ctx.end(errImageRequestEnd)
		return errImageRequestEnd
	case "ExpireWhileWriting":
		f.clock.onReadFrom(".(*imageReplyWork).admitDecode", func(now time.Time) time.Time { return now.Add(10*time.Second + 1) })
		return errImageExpired
	case "PeerWhileWriting":
		f.s.unregisterPeer(f.workers[0].current)
		return errImageDisconnected
	case "RoundWhileWriting":
		r.Close()
		return errImageRoundClosed
	}
	return nil
}

func checkReplyWriteFailure(t *testing.T, delayedLookup bool) {
	f, r := newReplyRound(t, 2, replyEmptyAnchor, imageReplyLimits(), false)
	q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	replacement := q
	replacement.ByteLimit++
	if delayedLookup {
		replacement.StartKey[0] = 2
		f.sendQuery(r, t.Context(), 1, replacement, [32]byte{})
	}
	old := f.workers[0]
	send := f.parkReplySend(r, t.Context(), 0, q, [32]byte{}, func() error { return errImageScriptedWrite })
	defer send.release()
	payload := replyChunkBytes(q, nil, nil, nil, nil)
	entered, release := holdReplyStage(t, old, "checked-frame", len(payload))
	defer release()
	f.sendFrame(0, replyChunk, payload, false)
	requireChannelClosed(t, entered, "old frame before classification")
	send.release()
	requireReplySent(t, send.done, q, errImageScriptedWrite)
	if !delayedLookup {
		f.requireEmpty(r, 1, errImageNoAssignment)
	}
	requireEqual(t, old.current.snapshotState().LastError, errImageScriptedWrite.Error(), "failed write LastError")
	requireChannelClosed(t, old.conn.closed, "failed write closes original socket")
	if !delayedLookup {
		f.sendQuery(r, t.Context(), 1, replacement, [32]byte{})
	}
	trace := observeReplyCalls(t, nil)
	release()
	requireChannelClosed(t, old.done, "old read worker finishes its checked frame")
	if delayedLookup {
		f.requireEmpty(r, 1, errImageNoAssignment)
	}
	f.requireEmpty(r, replacement.StartKey[0], context.Canceled)
	trace.requireLookup(t, old.current, nil)
	f.deliver(1, replyChunk, replyChunkBytes(replacement, nil, nil, nil, nil))
	requireReplyRange(t, f.requireReceive(r, replacement, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
	f.requireEmpty(r, replacement.StartKey[0], errImageNoAssignment)
}

func checkReplyStagedUnwind(t *testing.T, name string) {
	l := imageReplyLimits()
	l.Global.HolderBytes = 128
	f, r := newReplyRound(t, 1, replyEmptyAnchor, l, true)
	h := [32]byte{0x63}
	prior := f.positiveEmpty(r, 0, 1, 1, h)
	f.requireToken(prior, r, 0, h, true)
	q := imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit)
	if name == "StagedHolderRefusalPanic" {
		held := q
		f.sendQuery(r, t.Context(), 0, held, h)
		f.deliver(0, replyChunk, replyChunkBytes(held, nil, nil, nil, nil))
		q.RequestID, q.StartKey[0] = 3, 3
	}
	goexit := name == "StagedGoexit"
	send := f.parkReplySend(r, t.Context(), 0, q, h, unwindReplyWrite(goexit))
	defer send.release()
	cmd, frame := replyChunk, replyChunkBytes(q, nil, nil, nil, nil)
	switch name {
	case "StagedNegativePanic", "NegativeOwnsEvenIfSendUnwinds":
		cmd, frame = replyNegative, imageReplyQBytes(q)
	case "StagedRejectionPanic":
		frame = frame[:120]
	}
	f.deliver(0, cmd, frame)
	f.requireEmpty(r, q.StartKey[0], context.Canceled)
	if cmd == replyNegative {
		f.requireToken(prior, r, 0, h, false)
	}
	requireReplyStagedShape(f, r, q, name, cmd)
	send.release()
	requireImageUnwindReport(t, send.done, goexit)
	requireEqual(t, prior.ValidFor(r, f.ids[0], replyEmptyAnchor, h), cmd != replyNegative, "earlier generation after write unwind")
	f.requireEmpty(r, q.StartKey[0], errImageNoAssignment)
	if name == "StagedHolderRefusalPanic" {
		held := imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit)
		requireReplyRange(t, f.requireReceive(r, held, "", nil), consensus.UTXOImageRange{Terminal: true}, true)
	}
	f.requireToken(f.positiveEmpty(r, 0, q.RequestID+1, 4, h), r, 0, h, true)
}

func requireReplyStagedShape(f *imageReplyFixture, r *ImageRound, q consensus.UTXOImageQuery, name, command string) *ImageAttribution {
	t := f.t
	t.Helper()
	req := f.lockRequester()
	defer req.mu.Unlock()
	queue := r.outcomes[q.StartKey]
	requireEqual(t, len(queue), 1, "compared outcome before writer returns")
	o := queue[0]
	requireEqual(t, o.result.Query, q, "staged query")
	require(t, !o.ready, "staged result published before writer returns")
	var end error
	diagnostic := ""
	if name == "StagedHolderRefusalPanic" {
		end = errImageHolderLimit
	}
	if name == "StagedRejectionPanic" {
		diagnostic = "image_encoding"
	}
	requireEqual(t, o.end, end, "staged local error")
	requireEqual(t, o.result.Diagnostic, diagnostic, "staged diagnostic")
	if end != nil || diagnostic != "" || command == replyNegative {
		requireReplyNoRange(t, o.result)
	} else {
		requireReplyRange(t, o.result, consensus.UTXOImageRange{Terminal: true}, true)
	}
	return o.result.Attribution
}

func checkReplyAfterUnwind(t *testing.T, name string) {
	probe, goexit := strings.HasSuffix(name, "Probe"), strings.HasPrefix(name, "AfterGoexit")
	l := imageReplyLimits()
	l.Global.PendingNetworkBytes = 120
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, probe)
	q, h := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{0x83}
	send := f.parkReplySend(r, t.Context(), 0, q, h, unwindReplyWrite(goexit))
	send.release()
	requireImageUnwindReport(t, send.done, goexit)
	requireQueryResult(t, f.tryReplyAdmission(r, 1, q, h),
		consensus.UTXOImageQuery{}, errImageAssignmentCurrent, "same-start competitor after actual send unwind")
	f.sendQuery(r, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit), h)
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	token := f.takeEmptyRange(r, q, probe)
	if probe {
		require(t, token.ValidFor(r, f.ids[0], replyEmptyAnchor, h), "post-unwind probe attribution is not current")
	}
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func (f *imageReplyFixture) positiveEmpty(r *ImageRound, source int, id uint64, start byte, hash [32]byte) *ImageAttribution {
	f.t.Helper()
	q := f.sendQuery(r, f.t.Context(), source, imageReplyQuery(replyEmptyAnchor, id, start, replyLimit), hash)
	f.deliver(source, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	return f.takeEmptyRange(r, q, true)
}

func (f *imageReplyFixture) requireToken(token *ImageAttribution, r *ImageRound, source int, hash [32]byte, want bool) {
	f.t.Helper()
	requireEqual(f.t, token.ValidFor(r, f.ids[source], replyEmptyAnchor, hash), want, "token validity in supplied scope")
}

func testImageReplyBody(t *testing.T) {
	t.Run("OrdinaryHasNoToken", func(t *testing.T) { checkReplyInsert(t, false) })
	runReplyCases(t, checkReplyBodyClock, "BeyondProbeD", "AtBodyRD", "AfterBodyRD", "TimelyNonempty", "LateProbe", "SeparateProbeDeadlines")
	runReplyCases(t, checkReplyBodyScope, "SameHandle", "CopiedHandle", "WrongSource", "WrongAnchor", "CancelledContext", "ClosedRound",
		"ClosedService", "OrdinaryHandle", "EmptyAttribution", "ReadOnlySnapshot", "ReassignedDuringClock")
	runReplyCases(t, checkReplyBodySibling, "WrongRound", "WrongSession", "WrongHash")
	t.Run("ReconnectedSource", checkReplyReconnectedToken)
	runReplyCases(t, checkReplyDrainingToken, "DrainingService", "DrainingDuringSnapshot", "ReassignedServiceDuringDrain")
}

func checkReplyBodyClock(t *testing.T, name string) {
	f := newImageReplyFixture(t, true, 1)
	base := f.clock.add(0)
	l := imageReplyLimits()
	leaf, h := replyLeaf(0x40, 0, []byte{0x43, 0x45}), [32]byte{0xa3}
	anchor := replyAnchor(leaf)
	r := f.beginReplyRound(t.Context(), anchor, l, true, 0)
	if name != "BeyondProbeD" {
		f.clock.set(base.Add(5 * time.Second))
	}
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(anchor, 1, 1, replyLimit), h)
	when := 12 * time.Second
	switch name {
	case "BeyondProbeD":
		when = 4 * time.Second
	case "LateProbe":
		f.clock.onReadFrom(".(*imageReplyWork).finishProof", func(time.Time) time.Time { return base.Add(16 * time.Second) })
	case "SeparateProbeDeadlines":
		f.clock.set(base.Add(20 * time.Second))
		q2 := f.sendQuery(r, t.Context(), 0, imageReplyQuery(anchor, 2, 2, replyLimit), h)
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
		q, when = q2, 25*time.Second
	}
	f.clock.set(base.Add(when))
	trace := observeReplyCalls(t, nil)
	f.deliver(0, replyChunk, replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, nil))
	trace.requireCount(t, "verify", 1)
	if name == "LateProbe" {
		requireReplyNoRange(t, f.requireReceive(r, q, "", errImageExpired))
		f.requireEmpty(r, 1, errImageNoAssignment)
		return
	}
	got := f.requireReceive(r, q, "", nil)
	requireReplyRange(t, got, consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x40, 0, []byte{0x43, 0x45})}, Terminal: true}, true)
	require(t, got.Attribution.ValidFor(r, f.ids[0], anchor, h), "timely body qualification missing")
	for _, at := range []time.Duration{10*time.Second + 1, 15 * time.Second, 16 * time.Second, 100 * time.Second, 100*time.Second + 1} {
		if at >= when {
			f.clock.set(base.Add(at))
			requireEqual(t, got.Attribution.ValidFor(r, f.ids[0], anchor, h), at <= 100*time.Second, "body token at "+at.String())
			if at == 100*time.Second {
				next := imageReplyQuery(anchor, q.RequestID+1, 3, replyLimit)
				requireQueryResult(t, f.tryReplyAdmission(r, 0, next, h), consensus.UTXOImageQuery{}, errImageRoundDeadline, "original body cutoff on next probe")
			}
		}
	}
}

func checkReplyBodyScope(t *testing.T, name string) {
	f := newImageReplyFixture(t, true, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := f.beginReplyRound(ctx, replyEmptyAnchor, imageReplyLimits(), true, 0)
	h := [32]byte{0x74}
	token := f.positiveEmpty(r, 0, 1, 1, h)
	if name != "CopiedHandle" {
		f.requireToken(token, r, 0, h, true)
	}
	switch name {
	case "SameHandle":
		f.requireEmpty(r, 1, errImageNoAssignment)
	case "CopiedHandle":
		copyOfRound := *r
		f.requireToken(token, &copyOfRound, 0, h, true)
	case "ReassignedDuringClock":
		f.clock.add(time.Second)
		later := f.beginReplyRound(ctx, replyEmptyAnchor, imageReplyLimits(), true, 0)
		fresh := f.positiveEmpty(later, 0, 2, 2, h)
		called := *r
		f.clock.add(100 * time.Second)
		f.clock.onReadFrom(".(*ImageAttribution).ValidFor", func(now time.Time) time.Time { called = *later; return now })
		f.requireToken(token, &called, 0, h, false)
		f.requireToken(fresh, &called, 0, h, true)
	case "WrongSource":
		require(t, !token.ValidFor(r, "other source", replyEmptyAnchor, h), "unknown supplied source matched the token")
		f.requireToken(token, r, 0, h, true)
	case "WrongAnchor":
		for i := range 3 {
			a := replyEmptyAnchor
			switch i {
			case 0:
				a.Height++
			case 1:
				a.BlockHash[0] ^= 1
			case 2:
				a.Root[0] ^= 1
			}
			require(t, !token.ValidFor(r, f.ids[0], a, h), "different supplied anchor matched at component %d", i)
		}
		f.requireToken(token, r, 0, h, true)
	case "CancelledContext":
		cancel()
		f.requireToken(token, r, 0, h, false)
	case "ClosedRound":
		checkReplyClosedGeneration(f, r, token, h)
	case "ClosedService":
		requireReturned(t, lifecycleClose(f.s), "close qualified service")
		f.requireToken(token, r, 0, h, false)
	case "OrdinaryHandle":
		ordinary := f.beginReplyRound(ctx, replyEmptyAnchor, imageReplyLimits(), false, 0)
		f.requireToken(token, ordinary, 0, h, false)
	case "EmptyAttribution":
		f.requireToken(nil, r, 0, h, false)
		f.requireToken(&ImageAttribution{}, r, 0, h, false)
		require(t, !token.ValidFor(nil, f.ids[0], replyEmptyAnchor, h), "missing round accepted")
		require(t, !token.ValidFor(&ImageRound{}, f.ids[0], replyEmptyAnchor, h), "zero round accepted")
	case "ReadOnlySnapshot":
		checkReplyScopeRead(f, r, token, h)
	}
}

func checkReplyClosedGeneration(f *imageReplyFixture, r *ImageRound, token *ImageAttribution, h [32]byte) {
	t := f.t
	t.Helper()
	key := imageQualificationKey{session: f.workers[0].current.imageSession, bodyHash: h}
	req := f.lockRequester()
	previous := r.qualified[key]
	req.mu.Unlock()
	require(t, previous != nil && previous == token.generation, "body owner did not hold the original generation")
	r.Close()
	f.requireToken(token, r, 0, h, false)
	t.Run("ClosedRoundClearsGeneration", func(t *testing.T) {
		req := f.lockRequester()
		_, present := r.qualified[key]
		req.mu.Unlock()
		require(t, !present, "closed round retained its original session/hash generation")
	})
}

func checkReplyScopeRead(f *imageReplyFixture, r *ImageRound, token *ImageAttribution, h [32]byte) {
	t := f.t
	t.Helper()
	before := f.leases()
	observed := make(chan uint64, 1)
	f.clock.onReadFrom(".(*ImageAttribution).ValidFor", func(now time.Time) time.Time {
		observed <- f.leases()
		return now
	})
	trace := observeReplyCalls(t, nil)
	f.requireToken(token, r, 0, h, true)
	trace.requireCount(t, "scope-register", 0)
	requireEqual(t, awaitImageResult(t, observed, "lease count during scope read"), before, "work registration at scope read")
	f.requireEmpty(r, 1, errImageNoAssignment)
}

func checkReplyBodySibling(t *testing.T, name string) {
	f, r := newReplyRound(t, 2, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0x36}
	token := f.positiveEmpty(r, 0, 1, 1, h)
	other, source, id, hash := r, 0, uint64(2), h
	switch name {
	case "WrongRound":
		other = f.beginReplyRound(t.Context(), replyEmptyAnchor, imageReplyLimits(), true, 0, 1)
	case "WrongSession":
		source, id = 1, 1
	case "WrongHash":
		hash[0]++
	}
	sibling := f.positiveEmpty(other, source, id, 2, hash)
	f.requireToken(token, r, 0, h, true)
	f.requireToken(sibling, other, source, hash, true)
	f.requireToken(token, other, source, hash, false)
	f.requireToken(sibling, other, source, hash, true)
	f.requireToken(token, r, 0, h, true)
}

func checkReplyReconnectedToken(t *testing.T) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0xd5}
	old := f.positiveEmpty(r, 0, 1, 1, h)
	f.requireToken(old, r, 0, h, true)
	f.addReplyPeer(f.ids[0])
	f.requireToken(old, r, 0, h, true)
	next := f.beginReplyRound(t.Context(), replyEmptyAnchor, imageReplyLimits(), true, 1)
	fresh := f.positiveEmpty(next, 1, 1, 2, h)
	f.requireToken(old, next, 1, h, false)
	f.requireToken(fresh, next, 1, h, true)
	must(t, f.workers[0].remote.Close(), "disconnect original source")
	requireChannelClosed(t, f.workers[0].done, "old registration exited")
	f.requireToken(old, r, 0, h, false)
	f.requireToken(fresh, next, 1, h, true)
}

func testImageReplyGeneration(t *testing.T) {
	t.Run("HashSelective", checkReplyGenerationRefresh)
	t.Run("NoResurrection", checkReplyGenerationRefresh)
	t.Run("EarlierStagedLaterNegative", checkReplyStagedBeforeNegative)
	t.Run("ExistingGenerationSurvivesUnwind", func(t *testing.T) { checkReplyStagedUnwind(t, "ExistingGenerationSurvivesUnwind") })
	if replyCallTracing {
		t.Run("SharedPendingClaims", checkReplySharedPending)
	}
	t.Run("NegativeOwnsEvenIfSendUnwinds", func(t *testing.T) { checkReplyStagedUnwind(t, "NegativeOwnsEvenIfSendUnwinds") })
	t.Run("UnpublishedLastClaim", func(t *testing.T) { checkReplyUnpublished(t, false) })
	t.Run("NewGenerationSurvivesOldUnwind", func(t *testing.T) { checkReplyUnpublished(t, true) })
	runReplyCases(t, checkReplyUnrelatedGeneration, "OtherRound", "OtherSession", "Malformed", "WrongQ", "Stale", "Refused", "BadProof")
}

func checkReplyGenerationRefresh(t *testing.T) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	a, b := [32]byte{0xad}, [32]byte{0xbe}
	old, sibling := f.positiveEmpty(r, 0, 1, 1, a), f.positiveEmpty(r, 0, 2, 2, b)
	f.requireToken(old, r, 0, a, true)
	f.requireToken(sibling, r, 0, b, true)
	q := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 3, 3, replyLimit), a)
	f.deliver(0, replyNegative, imageReplyQBytes(q))
	f.requireToken(old, r, 0, a, false)
	f.requireToken(sibling, r, 0, b, true)
	requireReplyNoRange(t, f.requireReceive(r, q, "", nil))
	fresh := f.positiveEmpty(r, 0, 4, 4, a)
	f.requireToken(old, r, 0, a, false)
	f.requireToken(fresh, r, 0, a, true)
	f.requireToken(sibling, r, 0, b, true)
}

func checkReplyUnpublished(t *testing.T, replace bool) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0x77}
	negative := f.sendQuery(r, t.Context(), 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), h)
	q := imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit)
	send := f.parkReplySend(r, t.Context(), 0, q, h, unwindReplyWrite(false))
	defer send.release()
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	f.requireEmpty(r, 2, context.Canceled)
	key := imageQualificationKey{session: f.workers[0].current.imageSession, bodyHash: h}
	req := f.lockRequester()
	original := r.qualified[key]
	req.mu.Unlock()
	require(t, original != nil, "provisional generation missing")
	var fresh *ImageAttribution
	if replace {
		f.takeNegativeReply(r, 0, negative)
		next := imageReplyQuery(replyEmptyAnchor, 3, 3, replyLimit)
		parked := f.clock.readFrom(".(*imageInstance).preWriteEnd")
		later := goReplySend(r, t.Context(), f.ids[0], next, h)
		requireChannelClosed(t, parked, "next probe waiting for the original writer")
		f.deliver(0, replyChunk, replyChunkBytes(next, nil, nil, nil, nil))
		requireReplySent(t, later, next, nil)
		fresh = f.takeEmptyRange(r, next, true)
		f.requireToken(fresh, r, 0, h, true)
	}
	send.release()
	requireImageUnwindReport(t, send.done, false)
	if replace {
		f.requireToken(fresh, r, 0, h, true)
	}
	f.requireEmpty(r, 2, errImageNoAssignment)
	req = f.lockRequester()
	now := r.qualified[key]
	req.mu.Unlock()
	if replace {
		require(t, now == fresh.generation && now != original, "unwind changed the newer generation")
	} else {
		require(t, now == nil, "last unpublished claim was left in the owning round")
	}
}

func checkReplySharedPending(t *testing.T) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0x77}
	a, b := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit)
	first := f.parkReplySend(r, t.Context(), 0, a, h, unwindReplyWrite(false))
	defer first.release()
	entered, release := holdReplyCall(t, "write-check-wait", f.workers[0].current)
	second := goReplySend(r, t.Context(), f.ids[0], b, h)
	requireChannelClosed(t, entered, "second probe waiting for the first writer")
	for _, q := range []consensus.UTXOImageQuery{a, b} {
		f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
		f.requireEmpty(r, q.StartKey[0], context.Canceled)
	}
	one := requireReplyStagedShape(f, r, a, "", replyChunk)
	two := requireReplyStagedShape(f, r, b, "", replyChunk)
	require(t, one.generation == two.generation, "staged probes use different generations")
	first.release()
	requireImageUnwindReport(t, first.done, false)
	f.requireEmpty(r, 1, errImageNoAssignment)
	release()
	requireReplySent(t, second, b, nil)
	f.requireToken(f.takeEmptyRange(r, b, true), r, 0, h, true)
}

func checkReplyStagedBeforeNegative(t *testing.T) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0x5e}
	negative, positive := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), imageReplyQuery(replyEmptyAnchor, 2, 2, replyLimit)
	f.sendQuery(r, t.Context(), 0, negative, h)
	send := f.parkReplySend(r, t.Context(), 0, positive, h, nil)
	defer send.release()
	f.deliver(0, replyChunk, replyChunkBytes(positive, nil, nil, nil, nil))
	f.requireEmpty(r, 2, context.Canceled)
	f.takeNegativeReply(r, 0, negative)
	send.release()
	requireReplySent(t, send.done, positive, nil)
	token := f.takeEmptyRange(r, positive, true)
	f.requireToken(token, r, 0, h, false)
	fresh := f.positiveEmpty(r, 0, 3, 3, h)
	f.requireToken(token, r, 0, h, false)
	f.requireToken(fresh, r, 0, h, true)
}

func checkReplyUnrelatedGeneration(t *testing.T, name string) {
	l := imageReplyLimits()
	if name == "Refused" {
		l.Global.Hashes = 1
	}
	f, r := newReplyRound(t, 2, replyEmptyAnchor, l, true)
	h := [32]byte{0xca}
	old := f.positiveEmpty(r, 0, 1, 1, h)
	f.requireToken(old, r, 0, h, true)
	other, source, id := r, 0, uint64(2)
	switch name {
	case "OtherRound":
		other = f.beginReplyRound(t.Context(), replyEmptyAnchor, l, true, 0)
	case "OtherSession":
		source, id = 1, 1
	case "Stale":
		retired := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
		f.deliver(0, replyNegative, imageReplyQBytes(retired))
		f.requireToken(old, r, 0, h, true)
		f.requireEmpty(r, 1, errImageNoAssignment)
		return
	}
	var otherToken *ImageAttribution
	if name == "OtherRound" || name == "OtherSession" {
		otherToken = f.positiveEmpty(other, source, id, 3, h)
		f.requireToken(otherToken, other, source, h, true)
		id++
	}
	q := f.sendQuery(other, t.Context(), source, imageReplyQuery(replyEmptyAnchor, id, 2, replyLimit), h)
	command, payload, diagnostic := replyNegative, imageReplyQBytes(q), ""
	switch name {
	case "Malformed":
		payload, diagnostic = payload[:100], "image_encoding"
	case "WrongQ":
		payload[16] ^= 1
		diagnostic = "image_identity"
	case "Refused":
		command, payload = replyChunk, replyChunkBytes(q, nil, nil, nil, nil)
	case "BadProof":
		command, diagnostic = replyChunk, "image_range"
		payload = replyChunkBytes(q, []imageReplyLeaf{replyLeaf(0x60, 0, []byte{9})}, nil, nil, nil)
	}
	f.deliver(source, command, payload)
	f.requireToken(old, r, 0, h, true)
	if otherToken != nil {
		f.requireToken(otherToken, other, source, h, false)
	}
	if name == "Refused" {
		f.requireEmpty(other, 2, context.Canceled)
	} else {
		requireReplyNoRange(t, f.requireReceive(other, q, diagnostic, nil))
	}
}

func testImageReplyJoin(t *testing.T) {
	runReplyCases(t, checkReplyJoinedFrame, "AlreadyAuthorized", "NoNextRead", "VerifyBacking", "FrameBacking", "DecodeBacking", "CompareBacking")
	t.Run("WriteBacking", checkReplyJoinedWrite)
	t.Run("PassiveReceive", checkReplyPassiveReceive)
	t.Run("OutcomeOnlyClose", func(t *testing.T) { checkReplyHolderEnd(t, "service") })
	t.Run("ClockUnwind", func(t *testing.T) { checkReplyObservationUnwind(t, false) })
	t.Run("ContextUnwind", func(t *testing.T) { checkReplyObservationUnwind(t, true) })
	t.Run("CustomStopLocalEnd", checkReplyExternalStop)
}

// parkReplyStart holds the real Start before its listener is published or a transport is canceled.
func parkReplyStart(t *testing.T, s *Service) func() {
	t.Helper()
	serviceStartPostListenHookMu.Lock()
	old := serviceStartPostListenHook
	restore := sync.OnceFunc(func() {
		serviceStartPostListenHook = old
		serviceStartPostListenHookMu.Unlock()
	})
	entered, proceed := make(chan struct{}), make(chan struct{})
	serviceStartPostListenHook = func(current *Service, _ net.Listener) {
		if current == s {
			restore()
			close(entered)
			<-proceed
		}
	}
	started := make(chan error, 1)
	go func() {
		err := s.Start(context.Background())
		restore()
		started <- err
	}()
	finish := sync.OnceFunc(func() {
		close(proceed)
		err := awaitImageResult(t, started, "joined Start")
		if !t.Failed() {
			requireClosedRejection(t, err, "Start after Close")
		}
	})
	t.Cleanup(finish)
	requireChannelClosed(t, entered, "Start before listener publication")
	require(t, serviceStartPostListenHookMu.TryLock(), "parked Start still owns the post-listen hook mutex")
	serviceStartPostListenHookMu.Unlock()
	return finish
}

func holdReplyClock(t *testing.T, clock *imageTestClock, owner string, at func()) (<-chan struct{}, func()) {
	t.Helper()
	entered, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(release)
	clock.onReadFrom(owner, func(now time.Time) time.Time {
		at()
		close(entered)
		<-proceed
		return now
	})
	return entered, release
}

func checkReplyDrainingToken(t *testing.T, name string) {
	f, r := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
	h := [32]byte{0xe3}
	token := f.positiveEmpty(r, 0, 1, 1, h)
	f.requireToken(token, r, 0, h, true)
	called := r
	reassign, checkOther := func() {}, func() {}
	if name == "ReassignedServiceDuringDrain" {
		handle := *r
		called = &handle
		other, next := newReplyRound(t, 1, replyEmptyAnchor, imageReplyLimits(), true)
		fresh := other.positiveEmpty(next, 0, 1, 1, h)
		reassign = func() { handle = *next }
		checkOther = func() { other.requireToken(fresh, called, 0, h, true) }
	}
	finishStart := parkReplyStart(t, f.s)
	valid := make(chan bool, 1)
	read := func() { valid <- token.ValidFor(called, f.ids[0], replyEmptyAnchor, h) }
	afterDrain := read
	observeReplyCalls(t, nil)
	if name != "DrainingService" {
		var entered <-chan struct{}
		if replyCallTracing && name == "DrainingDuringSnapshot" {
			entered, afterDrain = holdReplyCall(t, "scope-open", nil)
		} else {
			entered, afterDrain = holdReplyClock(t, f.clock, ".(*ImageAttribution).ValidFor", reassign)
		}
		defer afterDrain()
		go read()
		requireChannelClosed(t, entered, "scope read inside ValidFor")
	}
	joined := lifecycleClose(f.s)
	waitDraining(t, f.s)
	require(t, f.s.ctx.Err() == nil && !isClosed(f.workers[0].conn.closed), "transport ended before the scope read")
	afterDrain()
	requireEqual(t, awaitImageResult(t, valid, "scope read after DRAINING"), false, "original token during DRAINING")
	checkOther()
	replyCallOwner.Load().requireCount(t, "scope-register", 0)
	f.requireEmpty(r, 1, errServiceClosed)
	finishStart()
	requireReturned(t, joined, "Close after token observation")
	f.requireToken(token, r, 0, h, false)
}

func checkReplyJoinedFrame(t *testing.T, name string) {
	f, r, q := newImageReplyFixture(t, true, 1).withInitialQuery(context.Background())
	p, payload := f.workers[0], replyChunkBytes(q, nil, nil, nil, nil)
	var finishStart func()
	if name == "AlreadyAuthorized" || name == "NoNextRead" {
		finishStart = parkReplyStart(t, f.s)
	}
	phase := map[string]string{
		"AlreadyAuthorized": "checked-frame", "FrameBacking": "checked-frame", "DecodeBacking": "decode",
		"VerifyBacking": "verify", "CompareBacking": "verify-return", "NoNextRead": "verify-return",
	}[name]
	entered, release := holdReplyJoinPhase(f, r, phase, len(payload))
	defer release()
	f.sendFrame(0, replyChunk, payload, false)
	requireChannelClosed(t, entered, "authorized frame at "+phase)
	joined := lifecycleClose(f.s)
	waitDraining(t, f.s)
	f.requireEmpty(r, 1, errServiceClosed)
	if finishStart != nil {
		require(t, f.s.ctx.Err() == nil && !isClosed(p.conn.closed), "transport ended before the authorized frame")
	} else {
		requireChannelClosed(t, p.conn.closed, "Close reached connection teardown while frame still held")
		requireStillBlocked(t, joined, "Close joins original frame owner")
	}
	if replyCallTracing && (phase == "verify" || phase == "verify-return" || phase == "decode") {
		req := f.lockRequester()
		copyBytes, proofBytes := r.global[unitCopyHoldingBytes], r.global[unitProofHoldingBytes]
		req.mu.Unlock()
		expected := [2]uint64{258, 641}
		if phase == "decode" {
			expected = [2]uint64{129, 0}
		}
		requireEqual(t, [2]uint64{copyBytes, proofBytes}, expected, "retained backing at actual call")
	}
	if name == "NoNextRead" {
		checkReplyNextRead(t, p, release)
	} else {
		release()
	}
	requireChannelClosed(t, p.done, "authorized worker before releasing Start")
	f.requireEmpty(r, 1, errServiceClosed)
	if finishStart == nil {
		requireReturned(t, joined, "Close after real frame owner left")
		return
	}
	req := f.lockRequester()
	queue := r.outcomes[q.StartKey]
	var got ImageResult
	if len(queue) == 1 && queue[0].ready {
		got = queue[0].result
	}
	req.mu.Unlock()
	requireEqual(t, got.Query, q, "winning authorized query before Service final cleanup")
	requireReplyRange(t, got, consensus.UTXOImageRange{Terminal: true}, false)
	finishStart()
	requireReturned(t, joined, "Close after authorized disposition")
}

func holdReplyJoinPhase(f *imageReplyFixture, r *ImageRound, phase string, n int) (<-chan struct{}, func()) {
	if replyCallTracing {
		return holdReplyCall(f.t, phase, f.workers[0].current)
	}
	if phase == "checked-frame" {
		return holdReplyRead(f.t, f.workers[0].wire, 24+n)
	}
	owner := ".(*imageReplyWork).finishProof"
	expect := [2]uint64{258, 641}
	if phase == "decode" {
		owner, expect = ".(*imageReplyWork).classify", [2]uint64{129, 0}
	}
	return holdReplyClock(f.t, f.clock, owner, func() {
		if got := [2]uint64{r.global[unitCopyHoldingBytes], r.global[unitProofHoldingBytes]}; got != expect {
			f.t.Errorf("charged temporary backing at %s = %v, want %v", phase, got, expect)
		}
	})
}

func checkReplyNextRead(t *testing.T, p imageReplyPeer, release func()) {
	t.Helper()
	deadlines, reads := p.wire.nextReads.Load(), p.wire.readCalls.Load()
	attempt := make(chan struct{})
	p.wire.nextDeadline.Store(&attempt)
	release()
	select {
	case <-attempt:
	case <-p.done:
	case <-time.After(lifecycleWatchdog):
		t.Fatal("worker neither exited nor attempted its next read")
	}
	requireEqual(t, p.wire.nextReads.Load()-deadlines, int64(0), "new read deadlines after authorized frame")
	requireEqual(t, p.wire.readCalls.Load()-reads, int64(0), "new Reads after authorized frame")
}

func checkReplyJoinedWrite(t *testing.T) {
	f := newImageReplyFixture(t, true, 1)
	r := f.beginReplyRound(context.Background(), replyEmptyAnchor, imageReplyLimits(), false, 0)
	q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	send := f.parkReplySend(r, context.Background(), 0, q, [32]byte{}, nil)
	defer send.release()
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	f.requireEmpty(r, 1, context.Canceled)
	joined := lifecycleClose(f.s)
	waitDraining(t, f.s)
	f.requireEmpty(r, 1, errServiceClosed)
	requireStillBlocked(t, joined, "Close at authorized Write")
	req := f.lockRequester()
	pending := r.global[unitPendingNetworkBytes]
	req.mu.Unlock()
	requireEqual(t, pending, uint64(120), "request bytes while Close joins Write")
	send.release()
	requireReplySent(t, send.done, q, nil)
	requireReturned(t, joined, "Close after request Write")
	f.requireEmpty(r, 1, errServiceClosed)
}

func checkReplyPassiveReceive(t *testing.T) {
	f, r, q := newImageReplyFixture(t, true, 1).withInitialQuery(context.Background())
	entered, proceed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	defer release()
	type replyReturn struct {
		result ImageResult
		err    error
	}
	done := make(chan replyReturn, 1)
	go func() {
		result, err := r.Receive(imageWaitBarrier{Context: context.Background(), entered: entered, release: proceed}, q.StartKey)
		done <- replyReturn{result, err}
	}()
	requireChannelClosed(t, entered, "passive Receive")
	requireReturned(t, lifecycleClose(f.s), "Close while passive caller is still parked")
	release()
	requireEqual(t, awaitImageResult(t, done, "passive Receive after join"), replyReturn{err: errServiceClosed}, "passive result")
}

type replyFinalContext struct {
	*imageHookCtx
	armed atomic.Bool
}

func (c *replyFinalContext) Err() error {
	if imageCalledFrom(".(*imageReplyWork).finishProof") && c.armed.CompareAndSwap(true, false) {
		imageUnwinder(true)()
	}
	return c.imageHookCtx.Err()
}

func startReplyObservedWorker(t *testing.T, s *Service, local, remote net.Conn, report chan<- any) <-chan struct{} {
	t.Helper()
	require(t, s.acquireWork(), "work lease for observed connection")
	done := make(chan struct{})
	go func() {
		defer close(done)
		var value any = imageGoexit
		defer func() { report <- cmp.Or(recover(), value) }()
		s.runConn(local, false)
		value = nil
	}()
	must(t, remote.SetDeadline(time.Now().Add(lifecycleWatchdog)), "observed worker deadline")
	version := testVersionPayload(s.cfg.SyncConfig.ChainID, s.cfg.GenesisHash, "remote", 0)
	must(t, completeRemoteHandshake(remote, s.cfg.PeerRuntimeConfig, version), "observed worker handshake")
	return done
}

func checkReplyObservationUnwind(t *testing.T, goexit bool) {
	f := newImageReplyFixture(t, true, 0)
	report := make(chan any, 1)
	f.startReplyPeer("192.0.2.80:18100", func(t *testing.T, s *Service, a, b net.Conn) <-chan struct{} {
		return startReplyObservedWorker(t, s, a, b, report)
	})
	f.addReplyPeer("192.0.2.81:18100")
	l := imageReplyLimits()
	l.Global.CopyHoldingBytes, l.Global.ProofHoldingBytes, l.Global.ScalarProofWork = 258, 641, 10787
	r := f.beginReplyRound(t.Context(), replyEmptyAnchor, l, false, 0, 1)
	q := imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit)
	ctx := &replyFinalContext{imageHookCtx: newImageHookCtx()}
	f.sendQuery(r, ctx, 0, q, [32]byte{})
	if goexit {
		ctx.armed.Store(true)
	} else {
		f.clock.onReadFrom(".(*imageReplyWork).finishProof", func(now time.Time) time.Time { imageUnwinder(false)(); return now })
	}
	trace := observeReplyCalls(t, nil)
	f.sendFrame(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil), false)
	requireImageUnwindReport(t, report, goexit)
	requireReplyNoRange(t, f.requireReceive(r, q, "", errImageDisconnected))
	trace.requireCount(t, "verify", 1)
	trace.requireCount(t, "verify-return", 1)
	second := f.sendQuery(r, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 1, 2, replyLimit), [32]byte{})
	f.deliver(1, replyChunk, replyChunkBytes(second, nil, nil, nil, nil))
	requireReplyRange(t, f.requireReceive(r, second, "", nil), consensus.UTXOImageRange{Terminal: true}, false)
	third := f.sendQuery(r, t.Context(), 1, imageReplyQuery(replyEmptyAnchor, 2, 3, replyLimit), [32]byte{})
	f.deliver(1, replyChunk, replyChunkBytes(third, nil, nil, nil, nil))
	f.requireEmpty(r, 3, context.Canceled)
}

func checkReplyExternalStop(t *testing.T) {
	f := newImageReplyFixture(t, true, 1)
	ctx, owner := newImageHookCtx(), newImageHookCtx()
	var stops atomic.Int32
	ctx.onStop = func() { stops.Add(1) }
	owner.onStop = func() { stops.Add(1) }
	r := f.beginReplyRound(owner, replyEmptyAnchor, imageReplyLimits(), false, 0)
	q := f.sendQuery(r, ctx, 0, imageReplyQuery(replyEmptyAnchor, 1, 1, replyLimit), [32]byte{})
	f.clock.onReadFrom(".(*imageReplyWork).finishProof", func(now time.Time) time.Time { ctx.end(errImageRequestEnd); return now })
	f.deliver(0, replyChunk, replyChunkBytes(q, nil, nil, nil, nil))
	requireReplyNoRange(t, f.requireReceive(r, q, "", errImageRequestEnd))
	f.requireEmpty(r, 1, errImageNoAssignment)
	requireEqual(t, stops.Load(), int32(0), "external stop calls at reply retirement")
}

func testImageReplyRetention(t *testing.T) {
	t.Run("StagedRoundDiscard", func(t *testing.T) { checkReplyHolderEnd(t, "staged") })
	t.Run("HolderIndexLastUse", func(t *testing.T) { checkReplyHolderEnd(t, "take") })
	t.Run("ClosedRoundKeepsSibling", func(t *testing.T) { checkReplyHolderEnd(t, "round") })
	t.Run("TokenDoesNotRootOwner", checkReplyTokenLastUse)
}

type replyHeldRefs struct {
	record     weak.Pointer[imageOutcome]
	whole      weak.Pointer[consensus.UTXOImageRange]
	entry      weak.Pointer[consensus.UTXOImageEntry]
	data       weak.Pointer[byte]
	token      weak.Pointer[ImageAttribution]
	generation weak.Pointer[imageGeneration]
}

func captureReplyHeld(f *imageReplyFixture, r *ImageRound, q consensus.UTXOImageQuery) replyHeldRefs {
	t := f.t
	t.Helper()
	req := f.lockRequester()
	defer req.mu.Unlock()
	queue := r.outcomes[q.StartKey]
	requireEqual(t, len(queue), 1, "outcomes at the selected start")
	o := queue[0]
	require(t, req.held[o] == r.imageRoundUsage && o.result.Query == q, "actual record missing from its charged owner")
	out, token := o.result.Range, o.result.Attribution
	require(t, out != nil && len(out.Entries) == 1 && len(out.Entries[0].Entry.CovenantData) > 16, "verified record lacks owned data")
	refs := replyHeldRefs{
		record: weak.Make(o), whole: weak.Make(out), entry: weak.Make(&out.Entries[0]),
		data: weak.Make(&out.Entries[0].Entry.CovenantData[0]), token: weak.Make(token),
	}
	requireEqual(t, token != nil, r.probe, "held range token")
	if token != nil {
		require(t, token.generation != nil, "verified probe record lacks generation")
		refs.generation = weak.Make(token.generation)
	}
	return refs
}

func requireReplyReleased(f *imageReplyFixture, r *ImageRound, refs replyHeldRefs, generationEnded bool) {
	t := f.t
	t.Helper()
	runtime.GC()
	require(t, refs.whole.Value() == nil, "original verified range remains reachable after discard")
	require(t, refs.entry.Value() == nil && refs.data.Value() == nil, "discarded verified entries or nested data remain reachable")
	require(t, refs.token.Value() == nil, "discarded result still retains its token")
	if generationEnded {
		require(t, refs.generation.Value() == nil, "closed body owner still retains its generation")
	}
	req := f.lockRequester()
	defer req.mu.Unlock()
	_, present := req.held[refs.record.Value()]
	require(t, !present, "service retains the original uncharged holder record")
	requireEqual(t, r.global[unitHolderBytes], uint64(0), "global holder bytes after actual last use")
	for _, units := range r.perPeer {
		requireEqual(t, units[unitHolderBytes], uint64(0), "peer holder bytes after actual last use")
	}
}

func checkReplyHolderEnd(t *testing.T, how string) {
	f := newImageReplyFixture(t, true, 2)
	data := bytes.Repeat([]byte{0x65}, 64)
	leaf := replyLeaf(0x70, 0, data)
	anchor, h := replyAnchor(leaf), [32]byte{0x6c}
	l := imageReplyLimits()
	l.Global.HolderBytes = 320
	r := f.beginReplyRound(context.Background(), anchor, l, true, 0)
	other := f.beginReplyRound(context.Background(), anchor, l, false, 1)
	q, sibling := imageReplyQuery(anchor, 1, 1, replyLimit), imageReplyQuery(anchor, 1, 2, replyLimit)
	f.sendQuery(other, context.Background(), 1, sibling, [32]byte{})
	f.deliver(1, replyChunk, replyChunkBytes(sibling, []imageReplyLeaf{leaf}, nil, nil, nil))
	var send parkedReplySend
	if how == "staged" {
		send = f.parkReplySend(r, context.Background(), 0, q, h, nil)
		defer send.release()
	} else {
		f.sendQuery(r, context.Background(), 0, q, h)
	}
	f.deliver(0, replyChunk, replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, nil))
	want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x70, 0, data)}, Terminal: true}
	refs := captureReplyHeld(f, r, q)
	switch how {
	case "service":
		ordinary := captureReplyHeld(f, other, sibling)
		requireReturned(t, lifecycleClose(f.s), "Close with outcome-only owners")
		f.requireEmpty(r, 1, errServiceClosed)
		f.requireEmpty(other, 2, errServiceClosed)
		requireReplyReleased(f, other, ordinary, false)
	case "take":
		requireReplyRange(t, f.requireReceive(r, q, "", nil), want, true)
		f.requireEmpty(r, 1, errImageNoAssignment)
	default:
		r.Close()
		f.requireEmpty(r, 1, errImageRoundClosed)
	}
	if how != "service" {
		requireReplyRange(t, f.requireReceive(other, sibling, "", nil), want, false)
	}
	requireReplyReleased(f, r, refs, how == "staged" || how == "round")
	if how == "staged" {
		req := f.lockRequester()
		pending := r.global[unitPendingNetworkBytes]
		req.mu.Unlock()
		requireEqual(t, pending, uint64(120), "parked sender bytes after round Close")
		send.release()
		requireReplySent(t, send.done, q, nil)
	}
}

func checkReplyTokenLastUse(t *testing.T) {
	var token *ImageAttribution
	var service weak.Pointer[Service]
	var usage weak.Pointer[imageRoundUsage]
	var round weak.Pointer[ImageRound]
	var result weak.Pointer[consensus.UTXOImageRange]
	var backing weak.Pointer[byte]
	if !t.Run("CloseAndReconnect", func(t *testing.T) {
		f := newImageReplyFixture(t, true, 1)
		data := bytes.Repeat([]byte{0x3d}, 48)
		leaf, h := replyLeaf(0x40, 0, data), [32]byte{0xd6}
		anchor := replyAnchor(leaf)
		ctx, cancel := context.WithCancel(t.Context())
		r := f.beginReplyRound(ctx, anchor, imageReplyLimits(), true, 0)
		q := imageReplyQuery(anchor, 1, 1, replyLimit)
		want := consensus.UTXOImageRange{Entries: []consensus.UTXOImageEntry{replyEntry(0x40, 0, data)}, Terminal: true}
		take := func(f *imageReplyFixture, r *ImageRound) ImageResult {
			f.sendQuery(r, t.Context(), 0, q, h)
			f.deliver(0, replyChunk, replyChunkBytes(q, []imageReplyLeaf{leaf}, nil, nil, nil))
			got := f.requireReceive(r, q, "", nil)
			requireReplyRange(t, got, want, true)
			return got
		}
		old := take(f, r)
		token = old.Attribution
		require(t, token.ValidFor(r, f.ids[0], anchor, h), "old token before Close")
		service, usage, round = weak.Make(f.s), weak.Make(r.imageRoundUsage), weak.Make(r)
		result, backing = weak.Make(old.Range), weak.Make(&old.Range.Entries[0].Entry.CovenantData[0])
		cancel()
		r.Close()
		other, freshRound := newReplyRound(t, 1, anchor, imageReplyLimits(), true)
		fresh := take(other, freshRound)
		require(t, !token.ValidFor(r, f.ids[0], anchor, h), "old token remained current in closed round")
		require(t, !token.ValidFor(freshRound, other.ids[0], anchor, h), "old token matched independent same-address round")
		require(t, fresh.Attribution.ValidFor(freshRound, other.ids[0], anchor, h), "fresh token lost its own scope")
	}) {
		t.FailNow()
	}
	runtime.GC()
	require(t, service.Value() == nil, "caller token retains old Service")
	require(t, round.Value() == nil && usage.Value() == nil, "caller token retains old round")
	require(t, result.Value() == nil && backing.Value() == nil, "caller token retains old verified result")
	runtime.KeepAlive(token)
}
