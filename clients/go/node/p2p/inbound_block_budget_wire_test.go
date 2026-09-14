package p2p

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"testing"
	"time"
)

func TestInboundBlockPayload(t *testing.T) {
	for _, row := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"lengths", func(t *testing.T) {
			for _, size := range []int{0, 1, 115, 116, 117, 32768, 32769} {
				for _, command := range []struct {
					name   string
					factor uint64
				}{{"block", 6}, {"cmpctblock", 3}} {
					payload := patternBytes(size)
					stream := &blockStream{size: uint32(size), payload: payload}
					b := newTestBudget(t, 1073741824)
					got, lease, err := readInboundBlockPayload(stream, inboundTestHeader(command.name, payload), b)
					requireTrue(t, err == nil && got != nil && bytes.Equal(got, payload) && lease != nil, "%s size %d: (%x, %v, %v)", command.name, size, got, lease, err)
					requireTrue(t, stream.served == uint32(size), "%s size %d: physical reads delivered %d bytes", command.name, size, stream.served)
					requireUsed(t, b, command.factor*uint64(size))
					lease.Release()
					requireUsed(t, b, 0)
				}
			}
		}},
		{"zero_length", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			payload, lease, err := readInboundBlockPayload(&blockStream{}, frameHeader{Command: "block", Checksum: [4]byte{0xa7, 0xff, 0xc6, 0xf8}}, b)
			requireTrue(t, err == nil && payload != nil && len(payload) == 0 && lease != nil, "zero-length read = (%#v, %v, %v)", payload, lease, err)
			requireUsed(t, b, 0)
			lease.Release()
			requireUsed(t, b, 0)
		}},
		{"full_charge", func(t *testing.T) { requireHeldCharge(t, "block", 117, 702) }},
		{"compact_charge", func(t *testing.T) { requireHeldCharge(t, "cmpctblock", 117, 351) }},
		{"success_keeps_lease", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			mustReserve(t, b, 4096)
			payload := patternBytes(200)
			got, lease, err := readInboundBlockPayload(&blockStream{size: 200, payload: payload}, inboundTestHeader("block", payload), b)
			requireTrue(t, err == nil && got != nil && lease != nil, "read = (%x, %v, %v)", got, lease, err)
			requireUsed(t, b, 5296)
			lease.Release()
			requireUsed(t, b, 4096)
		}},
		{"unsupported_command", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			for _, command := range []string{"", "blocktxn", "tx", "getdata"} {
				_ = rejectRead(t, frameHeader{Command: command, Size: 200}, b, "unsupported inbound block budget command")
			}
			requireUsed(t, b, 0)
		}},
		{"nil_budget", func(t *testing.T) {
			_ = rejectRead(t, frameHeader{Command: "block", Size: 200}, nil, "nil inbound block budget")
		}},
		{"command_before_nil_budget", func(t *testing.T) {
			_ = rejectRead(t, frameHeader{Command: "blocktxn", Size: 200}, nil, "unsupported inbound block budget command")
		}},
		{"cap_before_nil_budget", func(t *testing.T) {
			requireCapCommand(t, rejectRead(t, frameHeader{Command: "block", Size: 72000001}, nil, "message exceeds command cap"), "block")
		}},
		{"block_cap", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			requireCapCommand(t, rejectRead(t, frameHeader{Command: "block", Size: 72000001}, b, "message exceeds command cap"), "block")
			requireUsed(t, b, 0)
			mirror := variablePostHandshakePayloadCap("block", 0, 0)
			requireTrue(t, mirror == 72000000, "existing block cap = %d, want 72000000", mirror)
		}},
		{"compact_cap", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			requireCapCommand(t, rejectRead(t, frameHeader{Command: "cmpctblock", Size: 96000001}, b, "message exceeds command cap"), "cmpctblock")
			requireUsed(t, b, 0)
			mirror := compactRelayPayloadCap("cmpctblock")
			requireTrue(t, mirror == 96000000, "existing cmpctblock cap = %d, want 96000000", mirror)
		}},
		{"block_exact_cap", func(t *testing.T) { requireExactCapDiscard(t, "block", 72000000, [4]byte{0x35, 0x06, 0xff, 0xb3}) }},
		{"compact_exact_cap", func(t *testing.T) { requireExactCapDiscard(t, "cmpctblock", 96000000, [4]byte{0x6f, 0xc4, 0x1f, 0xc3}) }},
		{"prefix_before_reserve", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			payload := patternBytes(300)
			var observed [][2]uint64
			stream := &blockStream{size: 300, payload: payload, hook: func(served uint32) { observed = append(observed, [2]uint64{uint64(served), usedBytes(b)}) }}
			_, lease, err := readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
			requireTrue(t, err == nil && lease != nil && len(observed) > 0, "read = (%v, %v) after %d physical reads", lease, err, len(observed))
			for _, sample := range observed {
				requireTrue(t, sample[0] >= 116 || sample[1] == 0, "reader had charged %d bytes at payload offset %d", sample[1], sample[0])
			}
			lease.Release()
			_, lease, err = readInboundBlockPayload(&blockStream{size: 50}, frameHeader{Command: "block", Size: 300}, b)
			requireTrue(t, errors.Is(err, io.ErrUnexpectedEOF) && lease == nil, "short prefix = (%v, %v)", lease, err)
			requireUsed(t, b, 0)
		}},
		{"no_lock_during_io", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			payload := patternBytes(300)
			var duringIO, readErr error
			stream := &blockStream{size: 300, payload: payload, hook: func(uint32) {
				lease, err := b.TryReserveOrSubscribe(0)
				duringIO = errors.Join(duringIO, err)
				lease.Release()
			}}
			done := make(chan struct{})
			var held *inboundBlockLease
			go func() {
				defer close(done)
				_, held, readErr = readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
				held.Release()
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("reader did not finish: the budget mutex is held across payload I/O")
			}
			requireTrue(t, duringIO == nil && readErr == nil, "reservation during I/O = %v, read = %v", duringIO, readErr)
			requireUsed(t, b, 0)
		}},
		{"capacity_refused", func(t *testing.T) {
			for _, refused := range []struct {
				command  string
				size     uint32
				checksum [4]byte
			}{
				{"block", 1048576, [4]byte{0x7e, 0x18, 0x39, 0xfd}},
				{"cmpctblock", 1048576, [4]byte{0x7e, 0x18, 0x39, 0xfd}},
				{"block", 16777216, [4]byte{0x90, 0x50, 0xbe, 0x05}},
				{"cmpctblock", 16777216, [4]byte{0x90, 0x50, 0xbe, 0x05}},
			} {
				stream := &blockStream{size: refused.size}
				err := refuseRead(t, stream, frameHeader{Command: refused.command, Size: refused.size, Checksum: refused.checksum})
				_ = requireCapacityRefusal(t, err)
				requireTrue(t, stream.served == refused.size, "%s %d: drained %d bytes", refused.command, refused.size, stream.served)
			}
		}},
		{"failure_tuple", func(t *testing.T) {
			payload := patternBytes(300)
			_ = requireCapacityRefusal(t, refuseRead(t, &blockStream{size: 300, payload: payload}, inboundTestHeader("block", payload)))
		}},
		{"discard_window", func(t *testing.T) {
			stream := &blockStream{size: 70000, requests: []int{}}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 70000, Checksum: wireChecksum(make([]byte, 70000))})
			_ = requireCapacityRefusal(t, err)
			want := []int{116, 32652, 32768, 4464}
			requireTrue(t, slices.Equal(stream.requests, want), "physical requests %v, want %v", stream.requests, want)
		}},
		{"no_overread", func(t *testing.T) {
			for _, refuse := range []bool{false, true} {
				payload := patternBytes(300)
				trailer := []byte{0xde, 0xad, 0xbe, 0xef}
				stream := &blockStream{size: 300, payload: payload, trailer: trailer}
				b := newTestBudget(t, 1073741824)
				if refuse {
					mustReserve(t, b, 1073741824)
				}
				got, lease, err := readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
				requireTrue(t, refuse == isCapacityRefusal(err) && (refuse || bytes.Equal(got, payload)) && stream.served == 300, "refuse=%v: read = (%x, %v) after %d bytes", refuse, got, err, stream.served)
				rest, readErr := io.ReadAll(stream)
				requireTrue(t, readErr == nil && bytes.Equal(rest, trailer), "refuse=%v: next frame bytes = %x (%v)", refuse, rest, readErr)
				lease.Release()
			}
		}},
		{"no_retry_during_discard", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			holder := mustReserve(t, b, 1073741824)
			gen := generationOf(b)
			var second *inboundBlockLease
			stream := &blockStream{size: 70000, hook: func(served uint32) {
				if served >= 40000 && second == nil {
					holder.Release()
					second = mustReserve(t, b, 4096)
				}
			}}
			payload, lease, err := readInboundBlockPayload(stream, frameHeader{Command: "block", Size: 70000, Checksum: wireChecksum(make([]byte, 70000))}, b)
			refusal := requireCapacityRefusal(t, err)
			requireTrue(t, payload == nil && lease == nil, "discard retried the reservation: payload=%x lease=%v", payload, lease)
			requireTrue(t, refusal.Notification() == gen && isClosed(gen), "refusal registered a second generation instead of keeping the closed one")
			requireTrue(t, second != nil && stream.served == 70000, "freed bytes taken=%v after %d drained bytes", second != nil, stream.served)
			requireUsed(t, b, 4096)
		}},
		{"discard_allocated_bytes", func(t *testing.T) {
			for _, sized := range []struct {
				size     uint32
				checksum [4]byte
			}{
				{1048576, [4]byte{0x7e, 0x18, 0x39, 0xfd}},
				{16777216, [4]byte{0x90, 0x50, 0xbe, 0x05}},
			} {
				b := preheldBudget(t)
				header := frameHeader{Command: "block", Size: sized.size, Checksum: sized.checksum}
				stream := &blockStream{size: sized.size}
				refused := true
				measured := allocBytesPerOp(t, func() {
					stream.served = 0
					body, held, refusal := readInboundBlockPayload(stream, header, b)
					if body != nil || held != nil || !isCapacityRefusal(refusal) {
						refused = false
					}
				})
				requireTrue(t, refused, "size %d: the measured reader stopped refusing", sized.size)
				requireTrue(t, stream.served == sized.size, "size %d: last refusal drained %d bytes", sized.size, stream.served)
				requireTrue(t, measured <= 131072, "size %d allocated %d bytes per refusal, want <= 131072", sized.size, measured)
				requireUsed(t, b, 1073741824)
			}
		}},
		{"capacity_short_prefix", func(t *testing.T) {
			stream := &blockStream{size: 50, requests: []int{}}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 300})
			requireOrdinaryError(t, err)
			requireTrue(t, errors.Is(err, io.ErrUnexpectedEOF) && len(stream.requests) == 2 && stream.served == 50, "short prefix = %v after %d requests / %d bytes", err, len(stream.requests), stream.served)
		}},
		{"capacity_short_body", func(t *testing.T) {
			stream := &blockStream{size: 40000}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 70000})
			requireOrdinaryError(t, err)
			requireTrue(t, errors.Is(err, io.ErrUnexpectedEOF) && stream.served == 40000, "short body = %v after %d drained bytes", err, stream.served)
		}},
		{"capacity_wrapped_read_error", func(t *testing.T) {
			sentinel := errors.New("transport failure")
			wrapped := fmt.Errorf("stream: %w", sentinel)
			stream := &blockStream{size: 70000, failAt: 33000, failErr: wrapped}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 70000})
			requireOrdinaryError(t, err)
			requireTrue(t, err == wrapped && errors.Is(err, sentinel) && stream.served == 33000, "read error %v after %d drained bytes", err, stream.served)
		}},
		{"capacity_timeout", func(t *testing.T) {
			stream := &blockStream{size: 70000, failAt: 33000, failErr: os.ErrDeadlineExceeded}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 70000})
			requireOrdinaryError(t, err)
			var partial partialFrameTimeoutError
			requireTrue(t, errors.As(err, &partial) && errors.Is(err, os.ErrDeadlineExceeded), "timeout error = %v", err)
			requireTrue(t, partial.part == "payload" && partial.read == 33024 && partial.want == 70024, "partial frame timeout = {%q, %d, %d}, want {payload, 33024, 70024}", partial.part, partial.read, partial.want)
		}},
		{"capacity_bad_checksum", func(t *testing.T) {
			checksum := wireChecksum(make([]byte, 200))
			checksum[0] ^= 0xff
			stream := &blockStream{size: 200}
			err := refuseRead(t, stream, frameHeader{Command: "block", Size: 200, Checksum: checksum})
			requireOrdinaryError(t, err)
			requireTrue(t, err != nil && err.Error() == "invalid envelope checksum" && stream.served == 200, "checksum error %v after %d drained bytes", err, stream.served)
		}},
		{"error_cleanup", func(t *testing.T) {
			sentinel := errors.New("body failure")
			payload := patternBytes(32770)
			b := newTestBudget(t, 1073741824)
			stream := &blockStream{size: 32770, payload: payload, failAt: 32769, failErr: sentinel}
			got, lease, err := readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
			requireTrue(t, got == nil && lease == nil && err == sentinel && stream.served == 32769, "incomplete last chunk = (%x, %v, %v) after %d bytes", got, lease, err, stream.served)
			requireUsed(t, b, 0)

			header := inboundTestHeader("block", payload)
			header.Checksum[0] ^= 0xff
			got, lease, err = readInboundBlockPayload(&blockStream{size: 32770, payload: payload}, header, b)
			requireTrue(t, got == nil && lease == nil && err != nil && err.Error() == "invalid envelope checksum", "checksum failure after acquisition = (%x, %v, %v)", got, lease, err)
			requireUsed(t, b, 0)
		}},
		{"panic_cleanup", func(t *testing.T) {
			b := newTestBudget(t, 1073741824)
			boom := errors.New("reader exploded")
			payload := patternBytes(300)
			stream := &blockStream{size: 300, payload: payload, hook: func(served uint32) {
				if served >= 116 {
					panic(boom)
				}
			}}
			func() {
				defer func() {
					requireTrue(t, recover() == boom, "the reader's own panic value was not propagated")
				}()
				_, _, _ = readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
				t.Fatalf("reader returned instead of propagating the panic")
			}()
			requireUsed(t, b, 0)
		}},
		{"header_hash", func(t *testing.T) {
			const want = "0cb94a64118ca106b5d62b7b0323085551b7688abb99fc47ad6f46aef79ad0e7"
			for _, suffix := range []byte{0x00, 0xff} {
				payload := make([]byte, 200)
				for i := range payload[:116] {
					payload[i] = byte(i)
				}
				for i := 116; i < len(payload); i++ {
					payload[i] = suffix
				}
				err := refuseRead(t, &blockStream{size: 200, payload: payload}, inboundTestHeader("block", payload))
				hash, ok := requireCapacityRefusal(t, err).BlockHash()
				requireTrue(t, ok && hex.EncodeToString(hash[:]) == want, "suffix %#x: BlockHash = (%x, %v)", suffix, hash, ok)
			}
		}},
		{"exact_header_hash_presence", func(t *testing.T) {
			for _, sized := range []struct {
				size    int
				present bool
			}{{116, true}, {115, false}} {
				payload := patternBytes(sized.size)
				err := refuseRead(t, &blockStream{size: uint32(sized.size), payload: payload}, inboundTestHeader("block", payload))
				hash, ok := requireCapacityRefusal(t, err).BlockHash()
				requireTrue(t, ok == sized.present && (sized.present || hash == [32]byte{}), "size %d: BlockHash = (%x, %v), want presence %v", sized.size, hash, ok, sized.present)
			}
		}},
		{"short_prefix_no_hash", func(t *testing.T) {
			payload := patternBytes(32)
			err := refuseRead(t, &blockStream{size: 32, payload: payload}, inboundTestHeader("block", payload))
			hash, ok := requireCapacityRefusal(t, err).BlockHash()
			requireTrue(t, !ok && hash == [32]byte{}, "32-byte payload yielded hash evidence (%x, %v)", hash, ok)
		}},
		{"prefix_completed_with_error", func(t *testing.T) {
			sentinel := errors.New("prefix boundary failure")
			payload := patternBytes(117)
			for _, preheld := range []bool{false, true} {
				b := newTestBudget(t, 1073741824)
				var used uint64
				if preheld {
					mustReserve(t, b, 1073741824)
					used = 1073741824
				}
				stream := &blockStream{size: 117, payload: payload, failAt: 116, failErr: sentinel}
				got, lease, err := readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
				requireTrue(t, got == nil && lease == nil && err == sentinel && stream.served == 116, "preheld=%v: completed prefix = (%x, %v, %v) after %d bytes", preheld, got, lease, err, stream.served)
				requireUsed(t, b, used)
			}
		}},
		{"full_prefix_completed_with_error", func(t *testing.T) {
			sentinel := errors.New("final byte failure")
			payload := patternBytes(116)
			newStream := func() *blockStream {
				return &blockStream{size: 116, payload: payload, failAt: 116, failErr: sentinel}
			}
			b := newTestBudget(t, 1073741824)
			got, lease, err := readInboundBlockPayload(newStream(), inboundTestHeader("block", payload), b)
			requireTrue(t, err == nil && bytes.Equal(got, payload) && lease != nil, "complete payload with a co-returned error = (%x, %v, %v)", got, lease, err)
			requireUsed(t, b, 696)
			lease.Release()

			err = refuseRead(t, newStream(), inboundTestHeader("block", payload))
			hash, ok := requireCapacityRefusal(t, err).BlockHash()
			requireTrue(t, ok && hash != [32]byte{}, "refused complete payload hash = (%x, %v)", hash, ok)

			header := inboundTestHeader("block", payload)
			header.Checksum[0] ^= 0xff
			got, lease, err = readInboundBlockPayload(newStream(), header, b)
			requireTrue(t, got == nil && lease == nil && err != nil && err.Error() == "invalid envelope checksum", "wrong checksum on a complete payload = (%x, %v, %v)", got, lease, err)
			requireUsed(t, b, 0)
		}},
		{"original_chunk_completed_with_error", func(t *testing.T) {
			sentinel := errors.New("chunk boundary failure")
			payload := patternBytes(32769)
			for _, preheld := range []bool{false, true} {
				b := newTestBudget(t, 1073741824)
				if preheld {
					mustReserve(t, b, 1073741824)
				}
				stream := &blockStream{size: 32769, payload: payload, failAt: 32768, failErr: sentinel}
				got, lease, err := readInboundBlockPayload(stream, inboundTestHeader("block", payload), b)
				if preheld {
					_ = requireCapacityRefusal(t, err)
					requireTrue(t, got == nil && lease == nil, "refused frame returned payload=%x lease=%v", got, lease)
				} else {
					requireTrue(t, err == nil && bytes.Equal(got, payload) && lease != nil, "suppressed chunk co-error = (%x, %v, %v)", got, lease, err)
					lease.Release()
				}
				requireTrue(t, stream.served == 32769, "preheld=%v: read %d bytes, want 32769", preheld, stream.served)
			}
		}},
	} {
		t.Run(row.name, row.run)
	}
}

// blockStream serves one declared payload (explicit bytes, or zeros when payload is nil)
// followed by trailer bytes. It records physical request lengths, runs a hook before each
// request, and can co-return one scripted error at a fixed cumulative payload offset while
// still serving the bytes read before it.
type blockStream struct {
	size     uint32
	payload  []byte
	trailer  []byte
	served   uint32
	requests []int
	failAt   uint32
	failErr  error
	failed   bool
	hook     func(served uint32)
}

func (s *blockStream) Read(p []byte) (int, error) {
	if s.requests != nil {
		s.requests = append(s.requests, len(p))
	}
	if s.hook != nil {
		s.hook(s.served)
	}
	available := s.size - s.served
	if s.served >= s.size {
		available = s.size + uint32(len(s.trailer)) - s.served
	}
	n := min(uint32(len(p)), available)
	if s.failErr != nil && !s.failed && s.served+n >= s.failAt {
		n = s.failAt - s.served
		s.failed = true
		s.fill(p[:n])
		s.served += n
		return int(n), s.failErr
	}
	if n == 0 {
		return 0, io.EOF
	}
	s.fill(p[:n])
	s.served += n
	return int(n), nil
}

func (s *blockStream) fill(p []byte) {
	if s.served >= s.size {
		copy(p, s.trailer[s.served-s.size:])
	} else if s.payload != nil {
		copy(p, s.payload[s.served:])
	} else {
		clear(p)
	}
}

func patternBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 1)
	}
	return out
}

func inboundTestHeader(command string, payload []byte) frameHeader {
	return frameHeader{Command: command, Size: uint32(len(payload)), Checksum: wireChecksum(payload)}
}

// preheldBudget returns a budget whose whole limit is already held, so every further
// reservation is refused for capacity.
func preheldBudget(t *testing.T) *inboundBlockBudget {
	t.Helper()
	b := newTestBudget(t, 1073741824)
	mustReserve(t, b, 1073741824)
	return b
}

// refuseRead reads one frame against a fully preheld budget and pins that the call kept
// no payload, no lease and no bytes; a resource result must carry the generation current
// at the refusal.
func refuseRead(t *testing.T, stream *blockStream, header frameHeader) error {
	t.Helper()
	b := preheldBudget(t)
	gen := generationOf(b)
	payload, lease, err := readInboundBlockPayload(stream, header, b)
	requireTrue(t, payload == nil && lease == nil, "refused read returned payload=%x lease=%v", payload, lease)
	requireUsed(t, b, 1073741824)
	if isCapacityRefusal(err) {
		requireTrue(t, requireCapacityRefusal(t, err).Notification() == gen, "refusal notification is not the generation current at the refusal")
	}
	return err
}

// rejectRead pins a refusal that read no payload byte and charged nothing.
func rejectRead(t *testing.T, header frameHeader, budget *inboundBlockBudget, wantText string) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reader panicked on a refused frame: %v", r)
		}
	}()
	stream := &blockStream{size: 200, requests: []int{}}
	payload, lease, err := readInboundBlockPayload(stream, header, budget)
	requireTrue(t, payload == nil && lease == nil && err != nil && err.Error() == wantText, "refusal = (%x, %v, %v), want error %q", payload, lease, err, wantText)
	requireTrue(t, stream.served == 0 && len(stream.requests) == 0, "refusal read %d payload bytes in %d requests", stream.served, len(stream.requests))
	requireOrdinaryError(t, err)
	return err
}

// requireHeldCharge pins the charge a successful read holds until its caller releases.
func requireHeldCharge(t *testing.T, command string, size int, wantUsed uint64) {
	t.Helper()
	b := newTestBudget(t, 1073741824)
	payload := patternBytes(size)
	got, lease, err := readInboundBlockPayload(&blockStream{size: uint32(size), payload: payload}, inboundTestHeader(command, payload), b)
	requireTrue(t, err == nil && got != nil && lease != nil, "%s read = (%x, %v, %v)", command, got, lease, err)
	requireUsed(t, b, wantUsed)
	lease.Release()
	requireUsed(t, b, 0)
}

// requireExactCapDiscard pins that a payload exactly at its command cap passes the cap
// check and is drained under refusal.
func requireExactCapDiscard(t *testing.T, command string, size uint32, checksum [4]byte) {
	t.Helper()
	stream := &blockStream{size: size}
	err := refuseRead(t, stream, frameHeader{Command: command, Size: size, Checksum: checksum})
	_, ok := requireCapacityRefusal(t, err).BlockHash()
	requireTrue(t, stream.served == size && ok, "%s exact cap drained %d bytes with hash evidence %v", command, stream.served, ok)
}

func requireCapCommand(t *testing.T, err error, want string) {
	t.Helper()
	var capErr commandPayloadCapError
	requireTrue(t, errors.As(err, &capErr) && capErr.command == want, "cap error = %v, want commandPayloadCapError{%q}", err, want)
}
