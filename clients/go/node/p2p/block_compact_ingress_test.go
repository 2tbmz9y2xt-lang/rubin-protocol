package p2p

import (
	"bytes"
	"context"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestBlockCompactIngress(t *testing.T) {
	// ingressWrite is one frame header a peer wrote: the used bytes of the peer's inbound budget and
	// whether the peer held a compact outstanding request at that write.
	type ingressWrite struct {
		used        uint64
		outstanding bool
	}
	header, genesisHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cmpct := func(payload cmpctBlockPayload) message {
		return message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, payload)}
	}
	full := cmpct(cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	partial := cmpct(cmpctBlockPayload{Header: header, Nonce1: 7, Nonce2: 9, ShortIDs: []compactShortID{compactShortIDForTx(t, txs[0], 7, 9)}})
	threeUnknown := cmpct(cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xa1}, {0xa2}, {0xa3}}})
	unknownHeader := compactHeaderWithPrev(header, [32]byte{0xab})
	unknownHash := sha3.Sum256(unknownHeader[:])
	unknownPartial := cmpct(cmpctBlockPayload{Header: unknownHeader, ShortIDs: []compactShortID{{0xaa}}})
	// wantGetBlockTxn is the getblocktxn frame for index 0 of the genesis block, from literals.
	getBlockTxnPayload := append(genesisHash[:], 0x01, 0, 0, 0, 0)
	sum := sha3.Sum256(getBlockTxnPayload)
	wantGetBlockTxn := binary.LittleEndian.AppendUint32(append([]byte("RBDV"), "getblocktxn\x00"...), 37)
	wantGetBlockTxn = append(append(wantGetBlockTxn, sum[:4]...), getBlockTxnPayload...)
	used := func(p *peer) uint64 { return usedBytes(p.service.inboundBudget) }
	// chainPeer has an empty block store, a MemoryTxPool, the default budget, an injected clock and
	// compact receive enabled locally and negotiated at mode 1.
	chainPeer := func(t *testing.T) (*peer, *clock) {
		t.Helper()
		p := newPeerRuntimeTestPeer(t)
		p.service.cfg.EnableCompactReceive = true
		p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
		ck := &clock{now: time.Now()}
		p.service.cfg.Now = ck.Now
		return p, ck
	}
	// serve installs on p a connection that serves frames, then EOF, and records every frame header
	// p writes to it.
	serve := func(t *testing.T, p *peer, frames ...message) (*blockRetryConn, *expiryWakeConn, *[]ingressWrite) {
		t.Helper()
		wake := &expiryWakeConn{}
		for _, frame := range frames {
			wake.reads = append(wake.reads, scriptedRead{data: mustPeerRuntimeFrameBytes(t, p, frame)})
		}
		conn, writes := newBlockRetryConn(wake), []ingressWrite{}
		conn.writeHook = func(b []byte) (int, error) {
			if len(b) == 24 {
				_, outstanding := p.compactOutstandingExpiry()
				writes = append(writes, ingressWrite{used(p), outstanding})
			}
			return len(b), nil
		}
		p.conn = conn
		return conn, wake, &writes
	}
	// pastTTL advances ck by 16 s, past the 15 s outstanding TTL, on wake's first Read.
	pastTTL := func(wake *expiryWakeConn, ck *clock) {
		wake.onRead = func(n int) {
			if n == 1 {
				ck.advance(16 * time.Second)
			}
		}
	}
	// parkRun holds lock, starts p's run loop and returns finish, which releases lock once and
	// returns the run result; cleanup finishes a row that failed first.
	parkRun := func(t *testing.T, p *peer, lock sync.Locker) func() error {
		t.Helper()
		lock.Lock()
		done := make(chan error, 1)
		go func() { done <- p.run(context.Background()) }()
		finish := sync.OnceValue(func() error { lock.Unlock(); return <-done })
		t.Cleanup(func() { _ = finish() })
		return finish
	}
	// requireFallback requires exactly one getdata frame for hash on conn, written while the budget
	// held want bytes.
	requireFallback := func(t *testing.T, conn *blockRetryConn, writes *[]ingressWrite, hash [32]byte, want uint64) {
		t.Helper()
		written, _ := conn.snapshot()
		require(t, bytes.Equal(written, blockRetryFrame(hash)) && len(*writes) == 1, "written=%x, want exactly one getdata frame for %x", written, hash)
		requireEqual(t, (*writes)[0].used, want, "used bytes at the getdata write")
	}
	// partialState runs p over the partial frame and requires exactly the getblocktxn frame for index
	// 0, the outstanding request for the genesis hash and 864000000 more used bytes after EOF. It
	// returns the used bytes read before the frame.
	partialState := func(t *testing.T, p *peer) uint64 {
		t.Helper()
		before := used(p)
		conn, _, _ := serve(t, p, partial)
		must(t, p.run(context.Background()), "run over the partial frame")
		written, _ := conn.snapshot()
		outstanding, ok := p.compactOutstandingRequestSnapshot()
		require(t, bytes.Equal(written, wantGetBlockTxn) && ok && outstanding.BlockHash == genesisHash, "written=%x outstanding=%v, want one getblocktxn frame for index 0 and the genesis request", written, ok)
		requireEqual(t, used(p), before+864000000, "used bytes after EOF")
		return before
	}

	t.Run("known_block_no_replacement", func(t *testing.T) {
		p, _ := chainPeer(t)
		serve(t, p, full)
		// The stored-block premise is required after the park, so a routing change fails at the 3x wait.
		firstRun := p.run(context.Background())
		stored, storedErr := p.service.hasBlock(genesisHash)
		p.activateCompactOutstandingRequest(compactOutstandingTestRequest(genesisHash))
		before, frameCharge := used(p), 3*uint64(len(full.Payload))
		conn, _, _ := serve(t, p, full)
		finish := parkRun(t, p, &p.service.chainMu)
		waitUntil(t, func() bool { return used(p) == before+frameCharge }, "the 3x frame lease")
		stack := make([]byte, 1<<22)
		waitUntil(t, func() bool {
			n := runtime.Stack(stack, true)
			return bytes.Contains(stack[:n], []byte("(*Service).hasBlock")) && bytes.Contains(stack[:n], []byte("(*peer).handleCmpctBlock"))
		}, "the run loop parked at the presence check")
		requireEqual(t, used(p), before+frameCharge, "used bytes parked at the presence check")
		require(t, firstRun == nil && storedErr == nil && stored, "first run=%v hasBlock=(%v, %v), want the genesis block stored by the full compact frame", firstRun, stored, storedErr)
		must(t, finish(), "run over the known block")
		written, _ := conn.snapshot()
		_, outstanding := p.compactOutstandingExpiry()
		require(t, used(p) == before && !outstanding && len(written) == 0, "used=%d outstanding=%v written=%d, want %d, the request cleared and no bytes", used(p), outstanding, len(written), before)
	})
	t.Run("replacement_before_mempool_snapshot", func(t *testing.T) {
		for _, frame := range []message{partial, threeUnknown} {
			p, _ := chainPeer(t)
			before := used(p)
			serve(t, p, frame)
			finish := parkRun(t, p, &p.service.cfg.TxPool.(*MemoryTxPool).mu)
			waitUntil(t, func() bool { return used(p) == before+864000000 }, "the reconstruction charge at the local candidate snapshot")
			must(t, finish(), "run over a partial frame")
		}
	})
	t.Run("partial_holds_lease_across_frames", func(t *testing.T) {
		p, _ := chainPeer(t)
		partialState(t, p)
	})
	t.Run("blocktxn_consume_transfers_lease", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := partialState(t, p)
		response, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: genesisHash, Transactions: [][]byte{txs[0]}})
		must(t, err, "encode blocktxn")
		serve(t, p, message{Command: messageBlockTxn, Payload: response})
		finish := parkRun(t, p, &p.service.chainMu)
		waitUntil(t, func() bool { _, ok := p.compactOutstandingExpiry(); return !ok }, "the consume site clearing the request")
		requireEqual(t, used(p), before+864000000, "used bytes parked at the second presence check")
		must(t, finish(), "run over the blocktxn frame")
		have, err := p.service.hasBlock(genesisHash)
		require(t, used(p) == before && err == nil && have, "used=%d hasBlock=(%v, %v), want %d and the genesis block", used(p), have, err, before)
	})
	t.Run("expiry_releases_before_fallback_write", func(t *testing.T) {
		p, ck := chainPeer(t)
		before := partialState(t, p)
		conn, wake, writes := serve(t, p, message{Command: messagePing})
		pastTTL(wake, ck)
		must(t, p.run(context.Background()), "run over the ping frame")
		requireFallback(t, conn, writes, genesisHash, before)
		_, outstanding := p.compactOutstandingExpiry()
		require(t, (*writes)[0].outstanding && !outstanding, "outstanding at the write=%v after=%v, want the request cleared after the write", (*writes)[0].outstanding, outstanding)
	})
	t.Run("idle_expiry_releases_before_fallback_write", func(t *testing.T) {
		p, ck := setupCompactFallbackPeer(t)
		before := used(p)
		p.bindCompactOutstandingLease(mustReserve(t, p.service.inboundBudget, 864000000))
		conn, wake, writes := serve(t, p)
		wake.reads = []scriptedRead{{err: timeoutErr{}}, {err: io.EOF}}
		pastTTL(wake, ck)
		must(t, p.run(context.Background()), "run over the idle timeout")
		requireFallback(t, conn, writes, [32]byte{0x11}, before)
		requireEqual(t, used(p), before, "used bytes after run returned")
	})
	t.Run("full_block_clears_and_releases", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := partialState(t, p)
		genesis := node.DevnetGenesisBlockBytes()
		serve(t, p, message{Command: messageBlock, Payload: genesis})
		finish := parkRun(t, p, &p.service.chainMu)
		waitUntil(t, func() bool { return used(p) == before+864000000+6*uint64(len(genesis)) }, "the compact state lease beside the 6x frame lease")
		must(t, finish(), "run over the full block")
		_, outstanding := p.compactOutstandingExpiry()
		have, err := p.service.hasBlock(genesisHash)
		require(t, !outstanding && err == nil && have, "outstanding=%v hasBlock=(%v, %v), want the request gone and the block stored", outstanding, have, err)
		requireEqual(t, used(p), before, "used bytes after EOF")
	})
	t.Run("peer_exit_releases", func(t *testing.T) {
		s := blockRetryService(t, newTestHarness(t, 1, "127.0.0.1:0", nil).service)
		s.cfg.EnableCompactReceive = true
		s.cfg.PeerRuntimeConfig.ReadDeadline = 0
		cfg := s.cfg.PeerRuntimeConfig
		local, remote := net.Pipe()
		defer func() { _ = remote.Close() }()
		const addr = "127.0.0.1:19113"
		handled := make(chan error, 1)
		go func() { handled <- s.handleConn(local, addr) }()
		must(t, remote.SetDeadline(time.Now().Add(lifecycleWatchdog)), "SetDeadline")
		must(t, completeRemoteHandshake(remote, cfg, testVersionPayload(node.DevnetGenesisChainID(), node.DevnetGenesisBlockHash(), "remote", 0)), "remote handshake")
		readUntil := func(want string) {
			for command := ""; command != want; {
				frame, err := readFrame(remote, networkMagic(cfg.Network), cfg.MaxMessageSize)
				must(t, err, "read until "+want)
				command = frame.Command
			}
		}
		readUntil(messageGetAddr)
		before := usedBytes(s.inboundBudget)
		for _, frame := range []message{{Command: messageSendCmpct, Payload: consensus.AppendU64le([]byte{1}, compactRelayVersion)}, unknownPartial} {
			must(t, writeFrame(remote, networkMagic(cfg.Network), frame, cfg.MaxMessageSize), "write "+frame.Command)
		}
		readUntil(messageGetBlockTxn)
		requireEqual(t, usedBytes(s.inboundBudget), before+864000000, "used bytes after the getblocktxn frame")
		must(t, remote.Close(), "close the remote end")
		select {
		case <-handled:
		case <-time.After(lifecycleWatchdog):
			t.Fatalf("handleConn did not return within %s", lifecycleWatchdog)
		}
		s.peersMu.RLock()
		registered := s.peers[addr] != nil
		s.peersMu.RUnlock()
		require(t, !registered, "peer %q is still registered after handleConn returned", addr)
		requireEqual(t, usedBytes(s.inboundBudget), before, "used bytes after handleConn returned")
		requireReturned(t, lifecycleClose(s), "Close")
	})
	t.Run("refused_replacement_falls_back", func(t *testing.T) {
		p, _ := chainPeer(t)
		blockRetryService(t, p.service)
		prehold := mustReserve(t, p.service.inboundBudget, 209741825)
		conn, _, writes := serve(t, p, partial)
		must(t, p.run(context.Background()), "run over the partial frame")
		requireFallback(t, conn, writes, genesisHash, 209741825)
		_, outstanding := p.compactOutstandingExpiry()
		state := p.snapshotState()
		require(t, !outstanding && blockRetrySlotOf(p) == nil && state.LastError == "" && state.BanScore == 0 && used(p) == 209741825, "outstanding=%v slot=%v lastError=%q ban=%d used=%d, want no request, slot, error or ban and the prehold only", outstanding, blockRetrySlotOf(p) != nil, state.LastError, state.BanScore, used(p))
		prehold.Release()
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("refused_compact_frame_arms_slot", func(t *testing.T) {
		p, _ := chainPeer(t)
		blockRetryService(t, p.service)
		mustReserve(t, p.service.inboundBudget, 1073741824)
		conn, _, _ := serve(t, p, partial)
		err := p.run(context.Background())
		slot := blockRetrySlotOf(p)
		require(t, err == nil && slot != nil && slot.hash == genesisHash, "run=%v slot=%v, want nil and a slot for the genesis hash", err, slot != nil)
		written, _ := conn.snapshot()
		_, outstanding := p.compactOutstandingExpiry()
		state := p.snapshotState()
		require(t, len(written) == 0 && !outstanding && used(p) == 1073741824 && state.LastError == "" && state.BanScore == 0, "written=%d outstanding=%v used=%d lastError=%q ban=%d, want no effect beside the slot", len(written), outstanding, used(p), state.LastError, state.BanScore)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
	t.Run("post_replacement_error_releases_before_fallback", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := used(p)
		conn, _, writes := serve(t, p, message{Command: messageCmpctBlock, Payload: oversizedCmpctBlockShortIDPayload(header)})
		must(t, p.run(context.Background()), "run over the missing-request-too-large frame")
		requireFallback(t, conn, writes, genesisHash, before)
		_, outstanding := p.compactOutstandingExpiry()
		require(t, !outstanding && used(p) == before, "outstanding=%v used=%d, want no request and %d", outstanding, used(p), before)
	})
	t.Run("send_failure_keeps_frame_lease", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := used(p)
		conn, _, _ := serve(t, p, partial)
		failure := errors.New("getblocktxn write failure")
		conn.writeHook = func(b []byte) (int, error) {
			if bytes.Contains(b, []byte("getblocktxn")) {
				return 0, failure
			}
			return len(b), nil
		}
		err := p.run(context.Background())
		_, outstanding := p.compactOutstandingExpiry()
		require(t, errors.Is(err, failure) && !outstanding, "run=%v outstanding=%v, want the write failure and no request", err, outstanding)
		requireEqual(t, used(p), before, "used bytes after the failed send")
	})
	t.Run("stale_blocktxn_keeps_lease_until_exit", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := partialState(t, p)
		kept, _ := p.compactOutstandingRequestSnapshot()
		serve(t, p, message{Command: messageBlockTxn, Payload: append(bytes.Repeat([]byte{0x5a}, 32), 0x01)})
		err := p.run(context.Background())
		var stale blockTxnStaleBodyError
		outstanding, ok := p.compactOutstandingRequestSnapshot()
		require(t, errors.As(err, &stale) && ok && reflect.DeepEqual(outstanding, kept), "run=%v outstanding=%v, want the stale-body error and the request unchanged", err, ok)
		requireEqual(t, used(p), before+864000000, "used bytes after the stale blocktxn")
		p.releaseCompactOutstandingLease()
		requireEqual(t, used(p), before, "used bytes after the exit release")
	})
	t.Run("blocktxn_cap_disconnect_releases", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := partialState(t, p)
		req, _ := p.compactOutstandingRequestSnapshot()
		frame := binary.LittleEndian.AppendUint32(append([]byte("RBDV"), "blocktxn\x00\x00\x00\x00"...), req.BlockTxnPayloadCap+1)
		_, wake, _ := serve(t, p)
		wake.reads = []scriptedRead{{data: append(append(frame, 0, 0, 0, 0), genesisHash[:]...)}}
		err := p.run(context.Background())
		require(t, err != nil && err.Error() == "message exceeds command cap", "run=%v, want the command cap error", err)
		p.applyPostHandshakeDisconnectError(err)
		_, outstanding := p.compactOutstandingExpiry()
		require(t, !outstanding && p.snapshotState().BanScore == 10, "outstanding=%v ban=%d, want the request gone and ban 10", outstanding, p.snapshotState().BanScore)
		requireEqual(t, used(p), before, "used bytes after the disconnect error is applied")
	})
	t.Run("second_partial_takes_fallback", func(t *testing.T) {
		p, _ := chainPeer(t)
		p.service.inboundBudget = newTestBudget(t, 2147483648)
		before := partialState(t, p)
		conn, _, writes := serve(t, p, unknownPartial)
		must(t, p.run(context.Background()), "run over the second partial frame")
		requireFallback(t, conn, writes, unknownHash, before+864000000)
		outstanding, ok := p.compactOutstandingRequestSnapshot()
		require(t, ok && outstanding.BlockHash == genesisHash && used(p) == before+864000000, "outstanding=%v used=%d, want the genesis request and its lease kept", ok, used(p))
	})
	t.Run("late_blocktxn_after_fallback_unbudgeted", func(t *testing.T) {
		p, ck := chainPeer(t)
		before := partialState(t, p)
		_, wake, _ := serve(t, p, message{Command: messagePing}, message{Command: messageBlockTxn, Payload: append(genesisHash[:], 0x01)}, message{Command: messageVersion})
		pastTTL(wake, ck)
		err := p.run(context.Background())
		require(t, err != nil && err.Error() == "invalid version message after handshake" && p.snapshotState().LastError == "ignored late blocktxn response", "run=%v lastError=%q, want the late blocktxn drained and the next frame read", err, p.snapshotState().LastError)
		requireEqual(t, used(p), before, "used bytes after the late blocktxn")
	})
	t.Run("zero_size_cmpctblock_without_negotiation", func(t *testing.T) {
		p := newPeerRuntimeTestPeer(t)
		serve(t, p, message{Command: messageCmpctBlock})
		err := p.run(context.Background())
		var unknown postHandshakeUnknownCommandError
		require(t, errors.As(err, &unknown) && err.Error() == "unknown message type: cmpctblock" && used(p) == 0, "run=%v used=%d, want the unknown-command error and no used bytes", err, used(p))
	})
	t.Run("invalid_lease_direct_call", func(t *testing.T) {
		p := newCompactScriptedPeer(t)
		err := p.handleCmpctBlock(partial.Payload)
		require(t, errors.Is(err, errInboundBlockLease) && err.Error() == "invalid inbound block lease", "handleCmpctBlock=%v, want the invalid-lease error unchanged", err)
		_, outstanding := p.compactOutstandingExpiry()
		require(t, p.conn.(*scriptedConn).Len() == 0 && !outstanding && used(p) == 0, "written=%d outstanding=%v used=%d, want no effect", p.conn.(*scriptedConn).Len(), outstanding, used(p))
	})
	t.Run("short_cmpctblock_refusal_drains", func(t *testing.T) {
		for _, held := range []bool{true, false} {
			p, _ := chainPeer(t)
			blockRetryService(t, p.service)
			prehold := uint64(0)
			if held {
				prehold = 1073741824
				mustReserve(t, p.service.inboundBudget, prehold)
			}
			conn, _, _ := serve(t, p, message{Command: messageCmpctBlock, Payload: []byte{0x00}})
			err := p.run(context.Background())
			written, _ := conn.snapshot()
			_, outstanding := p.compactOutstandingExpiry()
			state := p.snapshotState()
			require(t, blockRetrySlotOf(p) == nil && !outstanding && len(written) == 0 && used(p) == prehold, "held=%v: slot=%v outstanding=%v written=%d used=%d, want none and %d", held, blockRetrySlotOf(p) != nil, outstanding, len(written), used(p), prehold)
			if held {
				require(t, err == nil && state.BanScore == 0 && state.LastError == "", "held: run=%v ban=%d lastError=%q, want the frame drained with no effect", err, state.BanScore, state.LastError)
			} else {
				require(t, err != nil && state.BanScore == 10 && state.LastError == err.Error(), "free: run=%v ban=%d lastError=%q, want the decode refusal and ban 10", err, state.BanScore, state.LastError)
			}
			requireReturned(t, lifecycleClose(p.service), "Close")
		}
	})
	t.Run("activate_over_existing_releases_previous", func(t *testing.T) {
		p, _ := chainPeer(t)
		before := partialState(t, p)
		first := p.compact.outstandingLease
		require(t, first != nil, "no lease bound after the partial frame")
		p.bindCompactOutstandingLease(mustReserve(t, p.service.inboundBudget, 1000))
		requireEqual(t, used(p), before+1000, "used bytes after binding the second lease")
		require(t, errors.Is(p.service.inboundBudget.ReplaceOrSubscribe(first, 1), errInboundBlockLease), "the first lease is still active")
	})
	t.Run("same_hash_refusal_releases_outstanding", func(t *testing.T) {
		p, _ := chainPeer(t)
		blockRetryService(t, p.service)
		before := partialState(t, p)
		conn, _, writes := serve(t, p, partial)
		must(t, p.run(context.Background()), "run over the same partial frame")
		requireFallback(t, conn, writes, genesisHash, before)
		_, outstanding := p.compactOutstandingExpiry()
		require(t, !outstanding && blockRetrySlotOf(p) == nil, "outstanding=%v slot=%v, want neither", outstanding, blockRetrySlotOf(p) != nil)
		requireReturned(t, lifecycleClose(p.service), "Close")
	})
}
