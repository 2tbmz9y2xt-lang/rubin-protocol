package p2p

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
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
	prefilledTx[0] ^= 0xff
	if reflect.DeepEqual(result.Transactions[0], prefilledTx) {
		t.Fatal("result aliases prefilled transaction bytes")
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

func TestReconstructCompactBlockFailsClosedWhenMissingRequestExceedsCap(t *testing.T) {
	exact, err := reconstructCompactBlock(cmpctBlockPayload{ShortIDs: make([]compactShortID, maxCompactRelayEntries)}, nil)
	if err != nil || len(exact.MissingIndexes) != maxCompactRelayEntries {
		t.Fatalf("exact max result=%+v err=%v", exact, err)
	}
	_, err = reconstructCompactBlock(cmpctBlockPayload{
		ShortIDs: make([]compactShortID, maxCompactRelayEntries+1),
	}, nil)
	if !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("overflow err=%v", err)
	}
	if exact.MissingIndexes[0] != 0 || exact.MissingIndexes[len(exact.MissingIndexes)-1] != maxCompactRelayEntries-1 {
		t.Fatalf("missing bounds got first=%d last=%d", exact.MissingIndexes[0], exact.MissingIndexes[len(exact.MissingIndexes)-1])
	}
}

func TestCompactFillShortIDTransactionsRejectsCumulativeOversize(t *testing.T) {
	shortID := compactShortID{0x51}
	txs := [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES), nil}
	err := compactFillShortIDTransactions(
		txs,
		2,
		[]prefilledTxn{{Index: 0, Tx: txs[0]}},
		[]compactShortID{shortID},
		map[compactShortID][]byte{shortID: {0x01}},
	)
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("compactFillShortIDTransactions err=%v, want cumulative size failure", err)
	}
	if txs[1] != nil {
		t.Fatalf("compactFillShortIDTransactions mutated short-id tx before validation: %x", txs[1])
	}
}

func TestCompactFillShortIDTransactionsDoesNotDoubleCountPrefilledBytes(t *testing.T) {
	prefilledTx := minimalBlockTxnTestTxBytes(50)
	shortTx := minimalBlockTxnTestTxBytes(51)
	shortID := compactShortID{0x51}
	txs := [][]byte{prefilledTx, nil}
	err := compactFillShortIDTransactions(
		txs,
		2,
		[]prefilledTxn{{Index: 0, Tx: prefilledTx}},
		[]compactShortID{shortID},
		map[compactShortID][]byte{shortID: shortTx},
	)
	if err != nil {
		t.Fatalf("compactFillShortIDTransactions double-counted prefilled bytes: %v", err)
	}
	if !reflect.DeepEqual(txs[1], shortTx) {
		t.Fatalf("filled tx=%x, want %x", txs[1], shortTx)
	}
	prefilledTx[0], shortTx[0] = 0xff, 0xee
	if txs[0][0] == 0xff || txs[1][0] == 0xee {
		t.Fatal("filled txs alias source bytes")
	}
}

func TestCompactFillShortIDTransactionsRejectsInvalidCompletionShapes(t *testing.T) {
	shortID := compactShortID{0x61}
	if err := compactFillShortIDTransactions(make([][]byte, 1), 1, nil, []compactShortID{shortID}, nil); err == nil || !strings.Contains(err.Error(), "compact block transaction missing") {
		t.Fatalf("missing short-id err=%v, want missing", err)
	}
	if err := compactFillShortIDTransactions(make([][]byte, maxCompactRelayEntries+1), maxCompactRelayEntries+1, nil, make([]compactShortID, maxCompactRelayEntries+1), nil); !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("overflow err=%v", err)
	}
	txs := make([][]byte, 2)
	err := compactFillShortIDTransactions(txs, 2, nil, []compactShortID{shortID}, map[compactShortID][]byte{shortID: minimalBlockTxnTestTxBytes(60)})
	if err == nil || !strings.Contains(err.Error(), "compact block transaction missing") {
		t.Fatalf("incomplete staged txs err=%v, want completion failure", err)
	}
}

func TestCompactFillOrCollectMissingRecomputesSizeAfterDuplicateReclassification(t *testing.T) {
	dup := compactShortID{0x01}
	later := compactShortID{0x02}
	txs := make([][]byte, 3)
	missing, _, overflow, err := compactFillOrCollectMissing(
		txs,
		3,
		nil,
		[]compactShortID{dup, later, dup},
		map[compactShortID][]byte{
			dup:   make([]byte, consensus.MAX_BLOCK_BYTES),
			later: {0x01},
		},
		nil,
	)
	if err != nil || overflow {
		t.Fatalf("compactFillOrCollectMissing duplicate reclassification err=%v overflow=%v", err, overflow)
	}
	if !reflect.DeepEqual(missing, []uint64{0, 2}) || txs[0] != nil || !reflect.DeepEqual(txs[1], []byte{0x01}) {
		t.Fatalf("missing=%v txs[0]=%v txs[1]=%v, want late duplicate missing and intervening tx retained", missing, txs[0], txs[1])
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

func TestNewCompactOutstandingRequestBuildsPartialState(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(90)
	shortID := compactShortIDForTx(t, tx, 91, 92)
	blockHash := [32]byte{0x33}
	block := cmpctBlockPayload{Header: [consensus.BLOCK_HEADER_BYTES]byte{0x44}, Nonce1: 91, Nonce2: 92}
	result := compactReconstructionResult{PartialTransactions: [][]byte{nil, tx}, MissingIndexes: []uint64{0}, MissingShortIDs: []compactShortID{shortID}}
	req, err := newCompactOutstandingRequest(block, blockHash, result)
	if err != nil {
		t.Fatalf("newCompactOutstandingRequest: %v", err)
	}
	wantPayloadCap := uint32(32 + len(consensus.EncodeCompactSize(1)) + maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES - len(tx))
	if req.BlockHash != blockHash || req.Header != block.Header || req.Nonce1 != block.Nonce1 || req.Nonce2 != block.Nonce2 || req.BlockTxnPayloadCap != wantPayloadCap {
		t.Fatalf("request metadata mismatch: %+v", req)
	}
	if !reflect.DeepEqual(req.MissingIndexes, []uint64{0}) || !reflect.DeepEqual(req.MissingShortIDs, []compactShortID{shortID}) || !reflect.DeepEqual(req.Transactions, [][]byte{nil, tx}) {
		t.Fatalf("request state mismatch: %+v", req)
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{}); err == nil {
		t.Fatal("empty missing request should fail")
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{MissingIndexes: []uint64{0}}); err == nil {
		t.Fatal("mismatched missing short-id request should fail")
	}
	if _, err := newCompactOutstandingRequest(block, blockHash, compactReconstructionResult{PartialTransactions: [][]byte{tx}, MissingIndexes: []uint64{0}, MissingShortIDs: []compactShortID{shortID}}); err == nil {
		t.Fatal("non-missing partial slot should fail")
	}
}

func TestCompactMissingRequestCapPrecedesPartialTableAllocation(t *testing.T) {
	shortIDs := make([]compactShortID, maxCompactRelayEntries+1)
	_, _, overflow, err := compactFillOrCollectMissing(nil, len(shortIDs), nil, shortIDs, nil, nil)
	if err != nil || !overflow {
		t.Fatal("missing-heavy compact block should hit request cap before partial table allocation")
	}
}

func TestCompactBlockTxnResponsePayloadCapUsesRemainingBudget(t *testing.T) {
	tx := minimalBlockTxnTestTxBytes(93)
	cap, err := compactBlockTxnResponsePayloadCap([][]byte{tx, nil}, 1)
	if err != nil {
		t.Fatalf("compactBlockTxnResponsePayloadCap: %v", err)
	}
	want := uint32(32 + len(consensus.EncodeCompactSize(1)) + maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES - len(tx))
	if cap != want || cap >= compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("cap=%d want=%d and below global cap %d", cap, want, compactRelayPayloadCap(messageBlockTxn))
	}
	wantFull := uint32(32 + len(consensus.EncodeCompactSize(maxCompactRelayEntries)) + maxCompactRelayEntries*maxCompactSizeBytes + consensus.MAX_BLOCK_BYTES)
	if full, err := compactBlockTxnResponsePayloadCap(nil, maxCompactRelayEntries); err != nil || full != wantFull || full >= compactRelayPayloadCap(messageBlockTxn) {
		t.Fatalf("full missing cap=%d err=%v want %d below global %d", full, err, wantFull, compactRelayPayloadCap(messageBlockTxn))
	}
}

func TestCompactFillResponseTransactionsValidatesExpectedShortIDs(t *testing.T) {
	blockHash := [32]byte{0x71}
	nonce1, nonce2 := uint64(71), uint64(72)
	tx1 := minimalBlockTxnTestTxBytes(73)
	tx2 := minimalBlockTxnTestTxBytes(74)
	req := compactOutstandingRequest{
		BlockHash:       blockHash,
		Transactions:    [][]byte{nil, tx2},
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{compactShortIDForTx(t, tx1, nonce1, nonce2)},
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	}
	response := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx1}, WTxIDs: [][32]byte{compactWTxIDForTx(t, tx1)}}
	filled, err := compactFillResponseTransactions(req, response)
	if err != nil {
		t.Fatalf("compactFillResponseTransactions: %v", err)
	}
	tx1[0] ^= 0xff
	if filled[0][0] == tx1[0] {
		t.Fatal("filled blocktxn response aliases source bytes")
	}
	wrongShortIDResponse := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx2}, WTxIDs: [][32]byte{compactWTxIDForTx(t, tx2)}}
	if _, err := compactFillResponseTransactions(req, wrongShortIDResponse); err == nil || !strings.Contains(err.Error(), "short id mismatch") {
		t.Fatalf("wrong short ID err=%v, want short id mismatch", err)
	}
	mismatchedWTxIDResponse := blockTxnRuntimePayload{BlockHash: blockHash, Transactions: [][]byte{tx2}, WTxIDs: [][32]byte{compactWTxIDForTx(t, filled[0])}}
	if _, err := compactFillResponseTransactions(req, mismatchedWTxIDResponse); err == nil || !strings.Contains(err.Error(), "wtxid mismatch") {
		t.Fatalf("mismatched response wtxid err=%v, want wtxid mismatch", err)
	}
	wrongHashResponse := response
	wrongHashResponse.BlockHash[0] ^= 0xff
	if _, err := compactFillResponseTransactions(req, wrongHashResponse); err == nil || !strings.Contains(err.Error(), "block hash mismatch") {
		t.Fatalf("wrong response block hash err=%v, want block hash mismatch", err)
	}
}

func TestCompactFillResponseTransactionsRejectsAggregateOversize(t *testing.T) {
	nonce1, nonce2 := uint64(81), uint64(82)
	wtxid := [32]byte{0x01}
	req := compactOutstandingRequest{
		Transactions:    [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES), nil},
		MissingIndexes:  []uint64{1},
		MissingShortIDs: []compactShortID{compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))},
		Nonce1:          nonce1,
		Nonce2:          nonce2,
	}
	_, err := compactFillResponseTransactions(req, blockTxnRuntimePayload{Transactions: [][]byte{{0x01}}, WTxIDs: [][32]byte{wtxid}})
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("aggregate oversize err=%v, want block size rejection", err)
	}
}

func TestHandleCmpctBlockRequestsMissingTransactions(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	header, blockHash, _ := devnetGenesisCompactParts(t)
	payload, err := encodeCmpctBlockPayload(cmpctBlockPayload{
		Header:   header,
		Nonce1:   101,
		Nonce2:   102,
		ShortIDs: []compactShortID{{0xaa}},
	})
	if err != nil {
		t.Fatalf("encodeCmpctBlockPayload: %v", err)
	}
	if err := p.handleMessage(message{Command: messageCmpctBlock, Payload: payload}); err != nil {
		t.Fatalf("handle cmpctblock: %v", err)
	}
	frame := readScriptedConnFrame(t, p)
	if frame.Command != messageGetBlockTxn {
		t.Fatalf("command=%s, want getblocktxn", frame.Command)
	}
	req, err := decodeGetBlockTxnPayload(frame.Payload)
	if err != nil {
		t.Fatalf("decode getblocktxn: %v", err)
	}
	if req.BlockHash != blockHash || !reflect.DeepEqual(req.Indexes, []uint64{0}) {
		t.Fatalf("getblocktxn=%+v want hash=%x indexes=[0]", req, blockHash)
	}
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != blockHash || snap.BlockTxnPayloadCap == 0 {
		t.Fatalf("outstanding=%+v ok=%v, want stored request", snap, ok)
	}
}

func TestHandleBlockTxnCompletesOutstandingBlock(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	header, blockHash, txs := devnetGenesisCompactParts(t)
	tx := txs[0]
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             header,
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{compactShortIDForTx(t, tx, 201, 202)},
		Transactions:       [][]byte{nil},
		Nonce1:             201,
		Nonce2:             202,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
	})
	body, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{tx}})
	if err != nil {
		t.Fatalf("encode blocktxn: %v", err)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: body}); err != nil {
		t.Fatalf("handle blocktxn: %v", err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v, want applied compact block", have, err)
	}
}

func TestHandleBlockTxnMismatchFallsBackFullBlock(t *testing.T) {
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	header, blockHash, txs := devnetGenesisCompactParts(t)
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             header,
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{{0xbb}},
		Transactions:       [][]byte{nil},
		Nonce1:             301,
		Nonce2:             302,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
	})
	body, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	if err != nil {
		t.Fatalf("encode blocktxn: %v", err)
	}
	if err := p.handleMessage(message{Command: messageBlockTxn, Payload: body}); err != nil {
		t.Fatalf("handle blocktxn mismatch: %v", err)
	}
	frame := readScriptedConnFrame(t, p)
	if frame.Command != messageGetData {
		t.Fatalf("fallback command=%s, want getdata", frame.Command)
	}
	items, err := decodeInventoryVectors(frame.Payload)
	if err != nil {
		t.Fatalf("decode getdata: %v", err)
	}
	if len(items) != 1 || items[0] != (InventoryVector{Type: MSG_BLOCK, Hash: blockHash}) {
		t.Fatalf("fallback items=%+v, want MSG_BLOCK %x", items, blockHash)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("fallback did not clear outstanding request")
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

func compactShortIDForTx(t *testing.T, tx []byte, nonce1, nonce2 uint64) compactShortID {
	t.Helper()
	wtxid := compactWTxIDForTx(t, tx)
	return compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
}

func compactWTxIDForTx(t *testing.T, tx []byte) [32]byte {
	t.Helper()
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	return wtxid
}

func devnetGenesisCompactParts(t *testing.T) ([consensus.BLOCK_HEADER_BYTES]byte, [32]byte, [][]byte) {
	t.Helper()
	block := node.DevnetGenesisBlockBytes()
	pb, err := consensus.ParseBlockBytes(block)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(genesis): %v", err)
	}
	var header [consensus.BLOCK_HEADER_BYTES]byte
	copy(header[:], pb.HeaderBytes)
	offset := consensus.BLOCK_HEADER_BYTES + len(consensus.EncodeCompactSize(pb.TxCount))
	return header, blockHash, [][]byte{append([]byte(nil), block[offset:]...)}
}

func readScriptedConnFrame(t *testing.T, p *peer) message {
	t.Helper()
	conn, ok := p.conn.(*scriptedConn)
	if !ok {
		t.Fatalf("peer conn=%T, want *scriptedConn", p.conn)
	}
	frame, err := readFrame(bytes.NewReader(conn.Buffer.Bytes()), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	conn.Buffer.Reset()
	return frame
}
