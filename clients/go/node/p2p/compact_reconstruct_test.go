package p2p

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestReconstructCompactBlockCompletesExactPositionsFromWTxID(t *testing.T) {
	nonce1, nonce2 := uint64(0x0102030405060708), uint64(0x1112131415161718)
	prefilledTx := minimalBlockTxnTestTxBytes(1)
	tx2 := minimalBlockTxnTestTxBytes(2)
	tx3 := minimalBlockTxnTestTxBytes(3)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, tx2, nonce1, nonce2), compactShortIDForTx(t, tx3, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{tx3, tx2})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	want := [][]byte{prefilledTx, tx2, tx3}
	if !reflect.DeepEqual(result.Transactions, want) || len(result.MissingIndexes) != 0 {
		t.Fatalf("result=%+v want txs=%v", result, want)
	}

	tx2[0] ^= 0xff
	if reflect.DeepEqual(result.Transactions[1], tx2) {
		t.Fatal("result aliases local transaction bytes")
	}
}

func TestReconstructCompactBlockReportsAbsoluteMissingIndexes(t *testing.T) {
	nonce1, nonce2 := uint64(4), uint64(5)
	tx1 := minimalBlockTxnTestTxBytes(11)
	tx2 := minimalBlockTxnTestTxBytes(12)
	tx3 := minimalBlockTxnTestTxBytes(13)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, tx1, nonce1, nonce2), compactShortIDForTx(t, tx3, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 1, Tx: tx2},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{tx3})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{0}) || result.Transactions != nil {
		t.Fatalf("missing=%v txs=%v, want absolute missing [0] and no completed block", result.MissingIndexes, result.Transactions)
	}
}

func TestReconstructCompactBlockDoesNotUseTxIDShortIDs(t *testing.T) {
	nonce1, nonce2 := uint64(6), uint64(7)
	prefilledTx := minimalBlockTxnTestTxBytes(21)
	localTx := minimalBlockTxnTestTxBytes(22)
	_, txid, _, consumed, err := consensus.ParseTx(localTx)
	if err != nil || consumed != len(localTx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortID(consensus.CompactShortID(txid, nonce1, nonce2))},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want missing absolute index 1 from TXID short ID mismatch", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnDuplicatePayloadShortIDs(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	localTx := minimalBlockTxnTestTxBytes(32)
	shortID := compactShortIDForTx(t, localTx, nonce1, nonce2)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{shortID, shortID},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1, 2}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want duplicate short IDs as bounded missing indexes", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnAmbiguousLocalShortID(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	localTx := minimalBlockTxnTestTxBytes(32)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, localTx, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{localTx, append([]byte(nil), localTx...)})
	if err != nil {
		t.Fatalf("reconstructCompactBlock duplicate local: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want ambiguous local short ID as missing index", result)
	}
}

func TestReconstructCompactBlockFailsClosedOnPrefilledShortIDCollision(t *testing.T) {
	nonce1, nonce2 := uint64(8), uint64(9)
	prefilledTx := minimalBlockTxnTestTxBytes(31)
	payload := cmpctBlockPayload{
		Nonce1:   nonce1,
		Nonce2:   nonce2,
		ShortIDs: []compactShortID{compactShortIDForTx(t, prefilledTx, nonce1, nonce2)},
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: prefilledTx},
		},
	}

	result, err := reconstructCompactBlock(payload, [][]byte{prefilledTx})
	if err != nil {
		t.Fatalf("reconstructCompactBlock prefilled collision: %v", err)
	}
	if !reflect.DeepEqual(result.MissingIndexes, []uint64{1}) || result.Transactions != nil {
		t.Fatalf("result=%+v, want prefilled short ID collision as missing index", result)
	}
}

func TestReconstructCompactBlockRejectsMalformedInputs(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(41)
	shortID := compactShortIDForTx(t, validTx, 1, 2)
	for _, tc := range []struct {
		name    string
		payload cmpctBlockPayload
		local   [][]byte
		wantErr string
	}{
		{
			name:    "out_of_range_prefilled",
			payload: cmpctBlockPayload{ShortIDs: []compactShortID{shortID}, Prefilled: []prefilledTxn{{Index: 2, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "duplicate_prefilled",
			payload: cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: validTx}, {Index: 0, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "unsorted_prefilled",
			payload: cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 1, Tx: validTx}, {Index: 0, Tx: validTx}}},
			wantErr: "compact relay index out of range",
		},
		{
			name:    "noncanonical_prefilled",
			payload: cmpctBlockPayload{ShortIDs: []compactShortID{shortID}, Prefilled: []prefilledTxn{{Index: 0, Tx: append(validTx, 0x00)}}},
			wantErr: "cmpctblock prefilled transaction is non-canonical",
		},
		{
			name:    "noncanonical_local",
			payload: cmpctBlockPayload{ShortIDs: []compactShortID{shortID}, Prefilled: []prefilledTxn{{Index: 0, Tx: validTx}}},
			local:   [][]byte{append(validTx, 0x00)},
			wantErr: "compact local transaction is non-canonical",
		},
	} {
		_, err := reconstructCompactBlock(tc.payload, tc.local)
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: err=%v, want %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestReconstructCompactBlockReportsBoundedMissingForLargeCodecValidPayload(t *testing.T) {
	exact, err := reconstructCompactBlock(cmpctBlockPayload{ShortIDs: make([]compactShortID, maxCompactRelayEntries)}, nil)
	if err != nil || len(exact.MissingIndexes) != maxCompactRelayEntries {
		t.Fatalf("exact max result=%+v err=%v", exact, err)
	}
	_, err = reconstructCompactBlock(cmpctBlockPayload{
		ShortIDs: make([]compactShortID, maxCompactRelayEntries+1),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "too many compact relay missing transactions") {
		t.Fatalf("overflow err=%v", err)
	}
	if exact.MissingIndexes[0] != 0 || exact.MissingIndexes[len(exact.MissingIndexes)-1] != maxCompactRelayEntries-1 {
		t.Fatalf("missing bounds got first=%d last=%d", exact.MissingIndexes[0], exact.MissingIndexes[len(exact.MissingIndexes)-1])
	}
}

func TestCompactFillShortIDTransactionsRejectsCumulativeOversize(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(51)
	shortID := compactShortID{0x51}
	txs := make([][]byte, 1)
	err := compactFillShortIDTransactions(
		txs,
		1,
		nil,
		[]compactShortID{shortID},
		map[compactShortID][]byte{shortID: tx},
		uint64(consensus.MAX_BLOCK_BYTES-len(tx)+1),
	)
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("compactFillShortIDTransactions err=%v, want cumulative size failure", err)
	}
	if txs[0] != nil {
		t.Fatalf("compactFillShortIDTransactions mutated txs before validation: %x", txs[0])
	}
}

func TestCompactLocalTxIndexUsesBoundedPerCandidateValidation(t *testing.T) {
	nonce1, nonce2 := uint64(51), uint64(52)
	validTx := minimalBlockTxnTestTxBytes(53)
	localIndex, err := compactLocalTxIndex([][]byte{validTx}, nonce1, nonce2)
	if err != nil {
		t.Fatalf("compactLocalTxIndex: %v", err)
	}
	shortID := compactShortIDForTx(t, validTx, nonce1, nonce2)
	if !reflect.DeepEqual(localIndex[shortID], validTx) {
		t.Fatalf("localIndex[%v]=%x want %x", shortID, localIndex[shortID], validTx)
	}

	_, err = compactLocalTxIndex([][]byte{append(minimalBlockTxnTestTxBytes(54), 0x00)}, nonce1, nonce2)
	if err == nil || !strings.Contains(err.Error(), "compact local transaction is non-canonical") {
		t.Fatalf("compactLocalTxIndex noncanonical err=%v", err)
	}
}

func TestReconstructCompactBlockSkipsLocalLookupForPrefilledOnlyBlock(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(61)
	result, err := reconstructCompactBlock(cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: validTx}}}, [][]byte{{0xff}})
	if err != nil {
		t.Fatalf("prefilled-only compact block should not index local candidates: %v", err)
	}
	if !reflect.DeepEqual(result.Transactions, [][]byte{validTx}) || result.MissingIndexes != nil {
		t.Fatalf("result=%+v, want prefilled-only reconstruction", result)
	}
}

func TestCompactBlockTxnFlowRequestsMissingTransactions(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestBlockWithoutPrefill(t, blockBytes, 11, 12)
	_, txs, err := compactTestBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactTestBlockTransactions: %v", err)
	}

	p, conn := compactTestPeerWithConn(sink)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(cmpctblock): %v", err)
	}
	req := mustReadCompactGetBlockTxn(t, p, conn)
	if req.BlockHash != blockHash || !reflect.DeepEqual(req.Indexes, []uint64{0}) {
		t.Fatalf("getblocktxn=%+v, want block %x index [0]", req, blockHash)
	}
	body, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: txs[:1]})
	if err != nil {
		t.Fatalf("encodeBlockTxnPayload: %v", err)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: body}); err != nil {
		t.Fatalf("handleMessage(blocktxn): %v", err)
	}
	assertHarnessTip(t, sink, 1, blockHash)

}

func TestHandleCmpctBlockRejectsMalformedAndSkipsKnownBlock(t *testing.T) {
	p, conn := compactTestPeerWithConn(newTestHarness(t, 1, "127.0.0.1:0", nil))
	if err := p.handleMessage(message{Command: messageCmpctBlock}); err == nil {
		t.Fatal("malformed cmpctblock accepted")
	}
	if conn.Len() != 0 {
		t.Fatalf("malformed cmpctblock wrote %d bytes", conn.Len())
	}

	known := newTestHarness(t, 2, "127.0.0.1:0", nil)
	_, blockBytes := testHarnessBlockAtHeight(t, known, 1)
	p, conn = compactTestPeerWithConn(known)
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, compactTestBlockWithoutPrefill(t, blockBytes, 21, 22))}); err != nil {
		t.Fatalf("known cmpctblock should be ignored: %v", err)
	}
	if conn.Len() != 0 {
		t.Fatalf("known cmpctblock wrote %d bytes", conn.Len())
	}
}

func TestHandleCmpctBlockPrefilledOnlyAppliesBlock(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	sink := newTestHarness(t, 1, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	header, txs, err := compactTestBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactTestBlockTransactions: %v", err)
	}
	p, conn := compactTestPeerWithConn(sink)
	block := cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}}
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: mustEncodeCmpctBlockPayload(t, block)}); err != nil {
		t.Fatalf("handleMessage(prefilled cmpctblock): %v", err)
	}
	if conn.Len() != 0 {
		t.Fatalf("prefilled cmpctblock wrote %d bytes", conn.Len())
	}
	assertHarnessTip(t, sink, 1, blockHash)
}

func TestRequestMissingCompactTransactionsFallbackAndSendFailure(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	block := compactTestBlockWithoutPrefill(t, blockBytes, 31, 32)
	p, conn := compactTestPeerWithConn(newTestHarness(t, 1, "127.0.0.1:0", nil))

	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: [32]byte{0xee}, BlockTxnPayloadCap: 64})
	if err := p.requestMissingCompactTransactions(block, blockHash, []uint64{0}); err != nil {
		t.Fatalf("requestMissingCompactTransactions(existing): %v", err)
	}
	frame, err := readFrame(&conn.Buffer, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("read fallback frame: %v", err)
	}
	if frame.Command != messageGetData {
		t.Fatalf("fallback command=%q, want getdata", frame.Command)
	}

	p.clearCompactOutstandingRequest()
	if err := p.requestMissingCompactTransactions(block, blockHash, nil); err == nil {
		t.Fatal("empty missing request accepted")
	}
	conn.writeErr = errWriterFailed
	if err := p.requestMissingCompactTransactions(block, blockHash, []uint64{0}); !errors.Is(err, errWriterFailed) {
		t.Fatalf("send failure err=%v, want %v", err, errWriterFailed)
	}
	if _, ok := p.compactOutstandingRequest(); ok {
		t.Fatal("send failure left outstanding request")
	}
}

func TestHandleBlockTxnRejectsUnsolicitedAndShortPayload(t *testing.T) {
	p, _ := compactTestPeerWithConn(newTestHarness(t, 1, "127.0.0.1:0", nil))
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: make([]byte, 32)}); err == nil {
		t.Fatal("unsolicited blocktxn accepted")
	}
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: [32]byte{0x01}, BlockTxnPayloadCap: 64})
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: make([]byte, 31)}); err == nil {
		t.Fatal("short blocktxn accepted")
	}
	if _, ok := p.compactOutstandingRequest(); ok {
		t.Fatal("short blocktxn did not clear outstanding request")
	}
}

func TestCompactBlockTxnFallsBackWhenResponseCannotComplete(t *testing.T) {
	p, conn := compactTestPeerWithConn(newTestHarness(t, 1, "127.0.0.1:0", nil))
	blockHash := [32]byte{1}
	p.setCompactOutstandingRequest(compactOutstandingRequest{BlockHash: blockHash, MissingShortIDs: []compactShortID{{2}}, BlockTxnPayloadCap: 64})
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: append(make([]byte, 32), 0)}); err == nil {
		t.Fatal("wrong blocktxn hash accepted")
	}
	if got := p.blockTxnPayloadCap(); got == 0 {
		t.Fatal("wrong blocktxn hash cleared outstanding request")
	}
	body := append(append([]byte(nil), blockHash[:]...), 0)
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: body}); err != nil {
		t.Fatalf("handleMessage(blocktxn fallback): %v", err)
	}
	frame, err := readFrame(&conn.Buffer, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	items, err := decodeInventoryVectors(frame.Payload)
	if err != nil {
		t.Fatalf("decodeInventoryVectors: %v", err)
	}
	if frame.Command != messageGetData || len(items) != 1 || items[0].Type != MSG_BLOCK {
		t.Fatalf("fallback frame command=%q items=%+v, want getdata MSG_BLOCK", frame.Command, items)
	}
}

func compactShortIDForTx(t *testing.T, tx []byte, nonce1, nonce2 uint64) compactShortID {
	t.Helper()
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	return compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
}

func compactTestBlockTransactions(blockBytes []byte) ([consensus.BLOCK_HEADER_BYTES]byte, [][]byte, error) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return header, nil, err
	}
	copy(header[:], pb.HeaderBytes)
	txs := make([][]byte, 0, len(pb.Txs))
	for _, tx := range pb.Txs {
		raw, err := consensus.MarshalTx(tx)
		if err != nil {
			return header, nil, err
		}
		txs = append(txs, raw)
	}
	return header, txs, nil
}

func compactTestBlockWithoutPrefill(t *testing.T, blockBytes []byte, nonce1, nonce2 uint64) cmpctBlockPayload {
	t.Helper()
	header, txs, err := compactTestBlockTransactions(blockBytes)
	if err != nil {
		t.Fatalf("compactTestBlockTransactions: %v", err)
	}
	shortIDs := make([]compactShortID, len(txs))
	for i, tx := range txs {
		shortIDs[i] = compactShortIDForTx(t, tx, nonce1, nonce2)
	}
	return cmpctBlockPayload{Header: header, Nonce1: nonce1, Nonce2: nonce2, ShortIDs: shortIDs}
}

func compactTestPeerWithConn(h *testHarness) (*peer, *scriptedConn) {
	conn := &scriptedConn{}
	p := testPeerForService(h.service, "rubin-go/test-peer", 1)
	p.conn = conn
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 2, Version: compactRelayVersion})
	return p, conn
}

func mustReadCompactGetBlockTxn(t *testing.T, p *peer, conn *scriptedConn) getBlockTxnPayload {
	t.Helper()
	frame, err := readFrame(&conn.Buffer, networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("command=%q, want getblocktxn", frame.Command)
	}
	req, err := decodeGetBlockTxnPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decodeGetBlockTxnPayload: %v", err)
	}
	return req
}

func mustEncodeCmpctBlockPayload(t *testing.T, block cmpctBlockPayload) []byte {
	t.Helper()
	raw, err := encodeCmpctBlockPayload(block)
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload: %v", err)
	}
	return raw
}
