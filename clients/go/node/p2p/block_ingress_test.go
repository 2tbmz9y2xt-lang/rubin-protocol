package p2p

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

// delayedFinalReadConn serves its scripted reads and sleeps for delay before the Read that
// returns the last scripted bytes.
type delayedFinalReadConn struct {
	scriptedConn
	delay time.Duration
}

func (c *delayedFinalReadConn) Read(p []byte) (int, error) {
	if len(c.reads) == 1 && len(p) >= len(c.reads[0].data) {
		time.Sleep(c.delay)
	}
	return c.scriptedConn.Read(p)
}

// gatedZeroConn serves its scripted header, then size zero bytes. With release set, the Read
// that follows the first 1048576 zero bytes closes entered and waits for release.
type gatedZeroConn struct {
	scriptedConn
	size, served     int
	entered, release chan struct{}
}

func (c *gatedZeroConn) Read(p []byte) (int, error) {
	if len(c.reads) > 0 {
		return c.scriptedConn.Read(p)
	}
	if c.served == 1048576 && c.release != nil {
		close(c.entered)
		<-c.release
	}
	n := min(len(p), c.size-c.served)
	if c.served < 1048576 {
		n = min(n, 1048576-c.served)
	}
	if n == 0 {
		return 0, io.EOF
	}
	clear(p[:n])
	c.served += n
	return n, nil
}

func TestBlockIngressBudget(t *testing.T) {
	const rangeError = "inbound block budget must be zero or between 1073741824 and 8589934592 bytes"
	requireLimit := func(t *testing.T, configured, limit uint64) {
		t.Helper()
		cfg := unclaimedServiceConfig(t)
		cfg.InboundBlockBudgetBytes = configured
		s, err := NewService(cfg)
		must(t, err, "NewService")
		require(t, s.inboundBudget != nil, "NewService(%d) built no inbound budget", configured)
		mustReserve(t, s.inboundBudget, limit)
		_, err = s.inboundBudget.TryReserveOrSubscribe(1)
		require(t, isCapacityRefusal(err), "one byte above %d: %v, want a capacity refusal", limit, err)
	}
	requireRefused := func(t *testing.T, cfg ServiceConfig, configured uint64, want string) {
		t.Helper()
		cfg.InboundBlockBudgetBytes = configured
		_, err := NewService(cfg)
		require(t, err != nil && err.Error() == want, "NewService(%d) error=%v, want %q", configured, err, want)
	}
	for _, row := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"service_default_budget", func(t *testing.T) { requireLimit(t, 0, 1073741824) }},
		{"service_explicit_budget", func(t *testing.T) {
			requireLimit(t, 8589934592, 8589934592)
			requireLimit(t, 1073741824, 1073741824)
		}},
		{"config_out_of_range", func(t *testing.T) {
			for _, configured := range []uint64{1, 1073741823, 8589934593, math.MaxUint64} {
				requireRefused(t, unclaimedServiceConfig(t), configured, rangeError)
			}
			cfg := unclaimedServiceConfig(t)
			cfg.PeerManager = nil
			requireRefused(t, cfg, 1, "nil peer manager")
		}},
		{"config_error_precedes_claim", func(t *testing.T) {
			cfg := unclaimedServiceConfig(t)
			requireRefused(t, cfg, 1073741823, rangeError)
			cfg.InboundBlockBudgetBytes = 1073741824
			_, err := NewService(cfg)
			must(t, err, "NewService on the engine of the failed construction")
		}},
	} {
		t.Run(row.name, row.run)
	}
}

func TestBlockIngressReader(t *testing.T) {
	source := newTestHarness(t, 3, "127.0.0.1:0", nil)
	block1, block2 := blockAtHeight(t, source, 1), blockAtHeight(t, source, 2)
	hash1, hash2 := sha3.Sum256(block1[:116]), sha3.Sum256(block2[:116])
	corrupted := bytes.Clone(block1)
	for i := 36; i < 68; i++ {
		corrupted[i] = 0xff // merkle root: the block still parses and fails to apply
	}
	refused := bytes.Repeat([]byte{0xd1}, 200)
	refusedHash := sha3.Sum256(refused[:116])
	blockFrame := func(payload []byte) message { return message{Command: messageBlock, Payload: payload} }
	// sinkPeer is a registered peer over a genesis-only sink Service.
	sinkPeer := func(t *testing.T) (*peer, *testHarness) {
		t.Helper()
		sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
		p := &peer{conn: newBlockRetryConn(nil), service: sink.service, state: node.PeerState{Addr: "block-ingress-peer"}}
		must(t, sink.service.cfg.PeerManager.AddPeer(&p.state), "AddPeer")
		return p, sink
	}
	// serve installs a recording connection on p that serves frames, then EOF.
	serve := func(t *testing.T, p *peer, frames ...message) (*blockRetryConn, *expiryWakeConn) {
		t.Helper()
		wake := &expiryWakeConn{}
		for _, frame := range frames {
			wake.reads = append(wake.reads, scriptedRead{data: mustPeerRuntimeFrameBytes(t, p, frame)})
		}
		conn := newBlockRetryConn(wake)
		p.conn = conn
		return conn, wake
	}
	// hold lets p's Service arm a re-request slot and holds its whole inbound budget.
	hold := func(t *testing.T, p *peer) *inboundBlockLease {
		t.Helper()
		blockRetryService(t, p.service)
		return mustReserve(t, p.service.inboundBudget, 1073741824)
	}
	// direct hands the refused payload to readBudgetedBlockFrame as readPostHandshakeFrame does
	// after validatePayload: header bytes counted, the frame started at frameStart, the absolute
	// deadline deadlineIn after construction, and the final payload Read held back by delay.
	direct := func(p *peer, frameStart time.Time, deadlineIn, delay time.Duration) (*delayedFinalReadConn, error) {
		conn := &delayedFinalReadConn{scriptedConn: scriptedConn{reads: []scriptedRead{{data: refused}}}, delay: delay}
		p.conn = conn
		now := time.Now()
		timing := &postHandshakeFrameTiming{peer: p, frameStart: frameStart, lastProgress: now, absoluteDeadline: now.Add(deadlineIn), payloadSize: uint32(len(refused)), bytesRead: 24, validated: true}
		_, _, err := p.readBudgetedBlockFrame(inboundTestHeader(messageBlock, refused), &compactFallbackReader{peer: p, ctx: context.Background(), timing: timing})
		return conn, err
	}
	// runHeight1 runs the sink loop over the valid height-1 block for a peer claiming height 2, so
	// handleBlock writes getblocks through hook after apply; done carries the result or the panic.
	runHeight1 := func(t *testing.T, hook func([]byte) (int, error)) (*peer, chan any) {
		t.Helper()
		p, _ := sinkPeer(t)
		blockRetryService(t, p.service)
		p.state.RemoteVersion.BestHeight = 2
		conn, _ := serve(t, p, blockFrame(block1))
		conn.writeHook = hook
		done := make(chan any, 1)
		go func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					done <- recovered
				}
			}()
			done <- p.run(context.Background())
		}()
		return p, done
	}

	t.Run("success_holds_lease_until_apply_returns", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		p, done := runHeight1(t, func(b []byte) (int, error) {
			once.Do(func() { close(entered) })
			<-release
			return len(b), nil
		})
		requireChannelClosed(t, entered, "the getblocks write after apply")
		have, err := p.service.hasBlock(hash1)
		require(t, usedBytes(p.service.inboundBudget) == 6*uint64(len(block1)) && err == nil && have, "used=%d hasBlock=(%v, %v) inside handleBlock after apply, want %d and the block", usedBytes(p.service.inboundBudget), have, err, 6*len(block1))
		close(release)
		result := <-done
		require(t, result == nil && usedBytes(p.service.inboundBudget) == 0, "run=%v used=%d after return, want nil and 0", result, usedBytes(p.service.inboundBudget))
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("run_exit_releases_lease", func(t *testing.T) {
		p, done := runHeight1(t, func([]byte) (int, error) { panic("block ingress getblocks write") })
		result := <-done
		require(t, result == "block ingress getblocks write" && usedBytes(p.service.inboundBudget) == 0, "recovered=%v used=%d, want the write panic and 0", result, usedBytes(p.service.inboundBudget))
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	for _, row := range []struct {
		name  string
		block []byte // nil selects the sink's own genesis
		ban   int
		state func(t *testing.T, p *peer, conn *blockRetryConn)
	}{
		{"known_block_releases_after_presence", nil, 0, func(t *testing.T, _ *peer, conn *blockRetryConn) {
			written, _ := conn.snapshot()
			requireEqual(t, len(written), 0, "bytes written for a known block")
		}},
		{"orphan_copy_then_release", block2, 0, func(t *testing.T, p *peer, _ *blockRetryConn) {
			requireEqual(t, p.service.orphans.Len(), 1, "orphan pool length")
			children := p.service.orphans.TakeChildren(hash1)
			require(t, len(children) == 1 && bytes.Equal(children[0].blockBytes, block2), "the retained orphan is not the payload")
		}},
		{"parse_error_releases_before_return", []byte{0x00}, 10, func(*testing.T, *peer, *blockRetryConn) {}},
		{"apply_error_releases", corrupted, 100, func(*testing.T, *peer, *blockRetryConn) {}},
	} {
		t.Run(row.name, func(t *testing.T) {
			p, sink := sinkPeer(t)
			if row.block == nil {
				_, row.block = testHarnessBlockAtHeight(t, sink, 0)
			}
			conn, _ := serve(t, p, blockFrame(row.block))
			err := p.run(context.Background())
			requireEqual(t, usedBytes(p.service.inboundBudget), uint64(0), "used bytes after the run loop returned")
			row.state(t, p, conn)
			var txErr *consensus.TxError
			ban := p.snapshotState().BanScore
			require(t, ban == row.ban && (err == nil) == (row.ban == 0) && (err == nil || errors.As(err, &txErr)), "run=%v ban=%d, want ban %d with a consensus error exactly when banned", err, ban, row.ban)
		})
	}
	t.Run("dispose_on_disposition", func(t *testing.T) {
		p, sink := sinkPeer(t)
		blockRetryService(t, p.service)
		genesisHash, genesis := testHarnessBlockAtHeight(t, sink, 0)
		for _, class := range []struct {
			name  string
			hash  [32]byte
			block []byte
		}{
			{"known block", genesisHash, genesis},
			{"apply error", sha3.Sum256(corrupted[:116]), corrupted},
			{"retained orphan", hash2, block2},
			{"accepted block", hash1, block1},
		} {
			slot := armBlockRetrySlot(t, p, class.hash, make(chan struct{}), time.Now())
			summary, err := p.processRelayedBlock(class.block)
			got := "known block"
			switch {
			case err != nil:
				got = "apply error"
			case summary != nil:
				got = "accepted block"
			case p.service.orphans.Len() == 1:
				got = "retained orphan"
			}
			requireEqual(t, got, class.name, "processRelayedBlock exit class")
			waitBlockRetryDone(t, slot, class.name)
		}
		armBlockRetrySlot(t, p, hash1, make(chan struct{}), time.Now())
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("capacity_refusal_arms_retry", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		hold(t, p)
		notify := generationOf(p.service.inboundBudget)
		first := bytes.Repeat([]byte{0xa6}, 116)
		conn, wake := serve(t, p, blockFrame(first), blockFrame(refused), message{Command: messagePing})
		var armed *blockRetrySlot
		var seen blockRetrySlot // a copy of the slot at the first Read after the first refusal
		wake.onRead = func(int) {
			p.retryMu.Lock()
			if armed == nil && p.retry != nil {
				armed, seen = p.retry, *p.retry
			}
			p.retryMu.Unlock()
		}
		start := time.Now()
		err := p.run(context.Background())
		end := time.Now()
		require(t, err == nil && len(wake.reads) == 0 && armed != nil, "run=%v unread=%d armed=%v, want every frame read and a slot after the first refusal", err, len(wake.reads), armed != nil)
		require(t, seen.notify == notify && seen.hash == sha3.Sum256(first) && !seen.deadline.Before(start.Add(30*time.Second)) && !seen.deadline.After(end.Add(30*time.Second)), "notify is the generation=%v hash=%x deadline=%v, want within [%v, %v]", seen.notify == notify, seen.hash, seen.deadline, start.Add(30*time.Second), end.Add(30*time.Second))
		requireBlockRetrySlot(t, p, armed, seen.hash, seen.deadline, blockRetryWaiting, "slot after the second refusal")
		written, _ := conn.snapshot()
		state := p.snapshotState()
		require(t, usedBytes(p.service.inboundBudget) == 1073741824 && len(written) == 0 && state.LastError == "" && state.BanScore == 0, "used=%d written=%d lastError=%q ban=%d, want no effect", usedBytes(p.service.inboundBudget), len(written), state.LastError, state.BanScore)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("capacity_release_sends_retry", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		lease := hold(t, p)
		notify := generationOf(p.service.inboundBudget)
		conn, _ := serve(t, p, blockFrame(refused))
		must(t, p.run(context.Background()), "run over the refused frame")
		lease.Release()
		require(t, isClosed(notify), "releasing the held lease left the notification open")
		waitBlockRetrySent(t, p)
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(refusedHash)), "written=%x, want exactly one getdata for the refused hash", written)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("capacity_refusal_without_hash_drops", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		hold(t, p)
		conn, wake := serve(t, p, blockFrame(refused[:115]), message{Command: messagePing})
		err := p.run(context.Background())
		require(t, err == nil && len(wake.reads) == 0 && usedBytes(p.service.inboundBudget) == 1073741824, "run=%v unread=%d used=%d, want every frame read and the held bytes only", err, len(wake.reads), usedBytes(p.service.inboundBudget))
		requireNoBlockRetryEffect(t, p, conn, "115-byte refused frame")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("wire_error_precedence_over_capacity", func(t *testing.T) {
		for _, wire := range []struct {
			name string
			edit func(frame []byte) []byte
			is   func(err error) bool
		}{
			{"checksum", func(f []byte) []byte { f[20] ^= 0xff; return f }, func(err error) bool { return err != nil && err.Error() == "invalid envelope checksum" }},
			{"EOF mid-payload", func(f []byte) []byte { return f[:24+150] }, func(err error) bool { return errors.Is(err, io.ErrUnexpectedEOF) }},
		} {
			p := newPeerRuntimeTestPeer(t)
			hold(t, p)
			_, wake := serve(t, p, blockFrame(refused))
			wake.reads[0].data = wire.edit(wake.reads[0].data)
			err := p.run(context.Background())
			require(t, wire.is(err) && blockRetrySlotOf(p) == nil && p.snapshotState().BanScore == 0 && usedBytes(p.service.inboundBudget) == 1073741824, "%s: run=%v slot=%v ban=%d used=%d", wire.name, err, blockRetrySlotOf(p) != nil, p.snapshotState().BanScore, usedBytes(p.service.inboundBudget))
			requireReturned(t, lifecycleClose(p.service), wire.name+" Close")
		}
	})
	t.Run("refusal_with_compact_outstanding", func(t *testing.T) {
		p, _ := setupCompactFallbackPeer(t)
		p.activateCompactOutstandingRequest(compactOutstandingTestRequest(refusedHash))
		hold(t, p)
		conn, _ := serve(t, p, blockFrame(refused))
		must(t, p.run(context.Background()), "run over the refused frame")
		outstanding, ok := p.compactOutstandingRequestSnapshot()
		slot := blockRetrySlotOf(p)
		written, _ := conn.snapshot()
		require(t, ok && outstanding.BlockHash == refusedHash && slot != nil && slot.hash == refusedHash && len(written) == 0 && usedBytes(p.service.inboundBudget) == 1073741824,
			"outstanding=%v slot=%v written=%d used=%d, want the request and the slot for the hash and no other effect", ok && outstanding.BlockHash == refusedHash, slot != nil, len(written), usedBytes(p.service.inboundBudget))
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("compact_frame_unbudgeted", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		p.service.cfg.EnableCompactReceive = true
		p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
		header, genesisHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
		payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
		mustReserve(t, p.service.inboundBudget, 1073741824)
		conn, _ := serve(t, p, message{Command: messageCmpctBlock, Payload: payload})
		must(t, p.run(context.Background()), "run over the cmpctblock frame")
		written, _ := conn.snapshot()
		have, err := p.service.hasBlock(genesisHash)
		require(t, len(written) == 0 && err == nil && have && usedBytes(p.service.inboundBudget) == 1073741824, "written=%d hasBlock=(%v, %v) used=%d, want no bytes, the reconstructed genesis and the held bytes only", len(written), have, err, usedBytes(p.service.inboundBudget))
	})
	t.Run("capacity_refusal_uses_frame_start", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		hold(t, p)
		frameStart := time.Now().Add(-10 * time.Second)
		_, err := direct(p, frameStart, 15*time.Second, 0)
		require(t, errors.Is(err, errInboundBlockDrained) && err.Error() == "inbound block frame drained for capacity", "error=%v, want the drained sentinel", err)
		slot := blockRetrySlotOf(p)
		require(t, slot != nil, "the refusal armed no slot")
		requireBlockRetrySlot(t, p, slot, refusedHash, frameStart.Add(30*time.Second), blockRetryWaiting, "slot armed at the frame start")
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("refusal_on_closed_service", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		hold(t, p)
		requireReturned(t, lifecycleClose(p.service), "Close")
		_, err := direct(p, time.Now(), 15*time.Second, 0)
		require(t, errors.Is(err, errInboundBlockDrained) && blockRetrySlotOf(p) == nil && usedBytes(p.service.inboundBudget) == 1073741824, "error=%v slot=%v used=%d, want the drained sentinel, no slot and the held bytes only", err, blockRetrySlotOf(p) != nil, usedBytes(p.service.inboundBudget))
	})
	for _, row := range []struct {
		name              string
		held              bool
		deadlineIn, delay time.Duration
	}{
		{"deadline_precedence_over_capacity", true, 200 * time.Millisecond, 2 * time.Second},
		{"expired_before_read", true, -time.Second, 0},
		{"deadline_after_complete_read", false, 200 * time.Millisecond, 2 * time.Second},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := newPeerRuntimeTestPeer(t)
			blockRetryService(t, p.service)
			used := uint64(0)
			if row.held {
				used = 1073741824
				mustReserve(t, p.service.inboundBudget, used)
			}
			conn, err := direct(p, time.Now(), row.deadlineIn, row.delay)
			require(t, isPartialFrameTimeout(err), "error=%v, want the partial-frame timeout", err)
			require(t, p.inboundLease == nil && blockRetrySlotOf(p) == nil, "lease=%v slot=%v, want neither after the timeout", p.inboundLease != nil, blockRetrySlotOf(p) != nil)
			requireEqual(t, usedBytes(p.service.inboundBudget), used, "used bytes after the call")
			require(t, row.deadlineIn > 0 || (len(conn.reads) == 1 && len(conn.reads[0].data) == len(refused)), "the expired frame read payload bytes: %d scripted reads left", len(conn.reads))
			requireReturned(t, lifecycleClose(p.service), "Close")
		})
	}
	t.Run("largest_block_charge", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		header := func(size uint32, checksum ...byte) scriptedConn {
			raw := binary.LittleEndian.AppendUint32(append([]byte("RBDV"), "block\x00\x00\x00\x00\x00\x00\x00"...), size)
			return scriptedConn{reads: []scriptedRead{{data: append(raw, checksum...)}}}
		}
		stream := &gatedZeroConn{scriptedConn: header(72000000, 0x35, 0x06, 0xff, 0xb3), size: 72000000, entered: make(chan struct{}), release: make(chan struct{})}
		p.conn = stream
		done := make(chan error, 1)
		go func() { done <- p.run(context.Background()) }()
		requireChannelClosed(t, stream.entered, "the body read past 1048576 bytes")
		requireEqual(t, usedBytes(p.service.inboundBudget), uint64(432000000), "used bytes during the body read")
		close(stream.release)
		err := <-done
		var txErr *consensus.TxError
		require(t, errors.As(err, &txErr) && p.snapshotState().BanScore == 10 && usedBytes(p.service.inboundBudget) == 0, "run=%v ban=%d used=%d, want the parse error, ban 10 and no used bytes", err, p.snapshotState().BanScore, usedBytes(p.service.inboundBudget))
		over := &gatedZeroConn{scriptedConn: header(72000001, 0, 0, 0, 0), size: 72000001}
		p.conn = over
		err = p.run(context.Background())
		require(t, err != nil && err.Error() == "message exceeds command cap" && over.served == 0 && usedBytes(p.service.inboundBudget) == 0, "72000001-byte frame: run=%v served=%d used=%d, want the command cap before any payload read", err, over.served, usedBytes(p.service.inboundBudget))
	})
}
