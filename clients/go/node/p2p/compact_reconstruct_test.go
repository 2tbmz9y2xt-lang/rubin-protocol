package p2p

import (
	"bytes"
	"context"
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

func TestInternalHandleBlockTxnCompletesOutstandingBlock(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newPeerRuntimeTestPeer(t)
	if err := p.handleBlockTxn(nil); err == nil || !strings.Contains(err.Error(), "missing block hash") || p.snapshotState().BanScore == 0 {
		t.Fatalf("short blocktxn err=%v state=%+v", err, p.snapshotState())
	}

	p = newPeerRuntimeTestPeer(t)
	if err := p.handleBlockTxn(make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "unexpected blocktxn response") || p.snapshotState().BanScore == 0 {
		t.Fatalf("unexpected blocktxn err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	if err := p.handleBlockTxn(make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "block hash mismatch") {
		t.Fatalf("wrong hash blocktxn err=%v", err)
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	malformed := append(blockHash[:], 0xff)
	if err := p.handleBlockTxn(malformed); err == nil || p.snapshotState().BanScore == 0 {
		t.Fatalf("malformed blocktxn err=%v state=%+v", err, p.snapshotState())
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("malformed blocktxn did not clear matching outstanding request")
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	valid, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	requireNoCompactErr(t, p.handleBlockTxn(valid), "handle blocktxn")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestHandleCmpctBlockValidationAndFallbackEdges(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	full := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	missing := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xaa}}})

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	requireNoCompactErr(t, p.handleCmpctBlock(full), "already-have compact block")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("already-have compact block did not clear matching outstanding request")
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("already-have compact block sent fallback")
	}

	tinyTarget := [32]byte{}
	tinyTarget[31] = 0x01
	powInvalidHeader := compactHeaderWithTarget(header, tinyTarget)
	p = newCompactScriptedPeer(t)
	err := p.handleCmpctBlock(mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: powInvalidHeader, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}}))
	if err == nil || !strings.Contains(err.Error(), "pow invalid") || p.snapshotState().BanScore == 0 {
		t.Fatalf("pow-invalid compact header err=%v state=%+v", err, p.snapshotState())
	}

	wrongExpected := compactFilledTarget(0xee)
	p = newCompactScriptedPeer(t)
	p.service.cfg.SyncConfig.ExpectedTarget = &wrongExpected
	err = p.handleCmpctBlock(full)
	if err == nil || !strings.Contains(err.Error(), "target mismatch") || p.snapshotState().BanScore == 0 {
		t.Fatalf("target-mismatch compact header err=%v state=%+v", err, p.snapshotState())
	}

	pool := NewMemoryTxPool()
	pool.txs[[32]byte{0x42}] = &relayTxEntry{raw: []byte{0x01}, size: 1}
	p = newCompactScriptedPeer(t)
	p.service.cfg.TxPool = pool
	requireNoCompactErr(t, p.handleCmpctBlock(missing), "malformed local candidate fallback")
	requireCompactFrame(t, p, messageGetData)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("malformed local candidate ban_score=%d, want no ban", p.snapshotState().BanScore)
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 301, 302), 301, 302)
	requireNoCompactErr(t, p.handleCmpctBlock(missing), "missing compact block with existing outstanding")
	requireCompactFrame(t, p, messageGetData)

	p = newCompactScriptedPeer(t)
	err = p.requestMissingCompactTransactions(cmpctBlockPayload{Header: header}, blockHash, compactReconstructionResult{
		PartialTransactions: [][]byte{nil},
		MissingIndexes:      []uint64{1},
		MissingShortIDs:     []compactShortID{{0x01}},
	})
	if err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("invalid missing request err=%v, want index out of range", err)
	}
}

func TestCompactProcessErrorEdges(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, nil, true), "short-id assembly fallback")
	requireCompactFrame(t, p, messageGetData)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("short-id assembly state=%+v, want no ban fallback", p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	if err := p.processCompactTransactions(blockHash, header, nil, false); err == nil || !strings.Contains(err.Error(), "compact block has no transactions") || p.snapshotState().BanScore == 0 {
		t.Fatalf("prefilled empty compact transactions err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	if fallback, accepted, err := p.processCompactRelayedBlockWithFallback([32]byte{0x99}, node.DevnetGenesisBlockBytes(), true); !fallback || accepted || err != nil {
		t.Fatalf("mismatched expected hash fallback=%v accepted=%v err=%v", fallback, accepted, err)
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 401, 402), 401, 402)
	p.service.cfg.BlockStore = nil
	if fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true); fallback || accepted || err == nil {
		t.Fatalf("hasBlock error fallback=%v accepted=%v err=%v", fallback, accepted, err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("hasBlock error did not clear matching compact outstanding request")
	}
}

func TestCompactApplyErrorFallbackEdges(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	pb, parsedHash, err := parseRelayedBlock(blockBytes)
	requireNoCompactErr(t, err, "parse relayed block")
	if parsedHash != blockHash {
		t.Fatalf("parsed block hash=%x, want %x", parsedHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	fallback, accepted, err := p.compactApplyErrorFallback(pb, blockHash, blockBytes, node.ErrParentNotFound, false)
	requireNoCompactErr(t, err, "parent-not-found retain")
	if fallback || accepted || p.service.orphans.Len() != 1 {
		t.Fatalf("parent-not-found fallback=%v accepted=%v orphans=%d", fallback, accepted, p.service.orphans.Len())
	}

	p = newCompactScriptedPeer(t)
	applyErr := &consensus.TxError{Code: consensus.BLOCK_ERR_MERKLE_INVALID, Msg: "merkle mismatch"}
	fallback, accepted, err = p.compactApplyErrorFallback(pb, blockHash, blockBytes, applyErr, true)
	requireNoCompactErr(t, err, "consensus apply fallback")
	if !fallback || accepted || !strings.Contains(p.snapshotState().LastError, "merkle mismatch") {
		t.Fatalf("consensus fallback=%v accepted=%v state=%+v", fallback, accepted, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	errBoom := errors.New("local apply failure")
	fallback, accepted, err = p.compactApplyErrorFallback(pb, blockHash, blockBytes, errBoom, false)
	if fallback || accepted || !errors.Is(err, errBoom) || !strings.Contains(p.snapshotState().LastError, "local apply failure") {
		t.Fatalf("local apply fallback=%v accepted=%v err=%v state=%+v", fallback, accepted, err, p.snapshotState())
	}
}

func TestCompactBlockBytesRejectsInvalidAssembly(t *testing.T) {
	header, _, _ := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	cases := []struct {
		name string
		txs  [][]byte
		want string
	}{
		{name: "empty", txs: nil, want: "compact block has no transactions"},
		{name: "missing", txs: [][]byte{nil}, want: "compact block transaction missing"},
		{name: "empty_tx", txs: [][]byte{{}}, want: "blocktxn transaction is empty"},
		{name: "oversize_block", txs: [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES)}, want: "compact block exceeds block size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compactBlockBytes(header, tc.txs)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compactBlockBytes err=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompactPrefilledParentNotFoundRetainsOrphanWithoutFallback(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	header, gotHash, txs := compactPartsFromBlockBytes(t, blockBytes)
	if gotHash != blockHash {
		t.Fatalf("block hash=%x, want %x", gotHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, false), "parent-not-found prefilled compact apply")
	if got := p.service.orphans.Len(); got != 1 {
		t.Fatalf("orphans.Len()=%d, want 1", got)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("parent-not-found compact apply sent full-block fallback")
	}
}

func TestCompactShortIDParentNotFoundFallsBackWithoutBlockSeen(t *testing.T) {
	source := newTestHarness(t, 2, "127.0.0.1:0", nil)
	blockHash, blockBytes := testHarnessBlockAtHeight(t, source, 1)
	header, gotHash, txs := compactPartsFromBlockBytes(t, blockBytes)
	if gotHash != blockHash {
		t.Fatalf("block hash=%x, want %x", gotHash, blockHash)
	}

	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, true), "parent-not-found short-id compact apply")
	requireCompactFrame(t, p, messageGetData)
	if got := p.service.orphans.Len(); got != 0 {
		t.Fatalf("orphans.Len()=%d, want 0 for short-id reconstructed bytes", got)
	}
	if p.service.blockSeen.Has(blockHash) {
		t.Fatal("short-id reconstructed orphan poisoned blockSeen")
	}
}

func TestRunRoutesNegotiatedCmpctBlock(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	p.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageCmpctBlock, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run cmpctblock")
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestRunRoutesOutstandingBlockTxn(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	p := newPeerRuntimeTestPeer(t)
	p.service.cfg.EnableCompactReceive = true
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)
	p.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, p, message{Command: messageBlockTxn, Payload: payload})}}}

	requireNoCompactErr(t, p.run(context.Background()), "run blocktxn")
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("outstanding request was not cleared")
	}
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestHandleBlockTxnFallsBackWithoutBanOnShortIDMismatch(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortID{0xbb}, 301, 302)
	valid, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")
	requireNoCompactErr(t, p.handleBlockTxn(valid), "mismatched blocktxn fallback")
	requireCompactFrame(t, p, messageGetData)
	if p.snapshotState().BanScore != 0 {
		t.Fatalf("mismatched blocktxn state=%+v, want no ban", p.snapshotState())
	}
}

func TestHandleBlockTxnBansMalformedFillWithoutFallback(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 301, 302), 301, 302)
	payload, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0], txs[0]}})
	requireNoCompactErr(t, err, "encode blocktxn")

	err = p.handleBlockTxn(payload)
	if err == nil || !strings.Contains(err.Error(), "transaction count mismatch") {
		t.Fatalf("malformed blocktxn fill err=%v, want transaction count mismatch", err)
	}
	state := p.snapshotState()
	if state.BanScore == 0 || !strings.Contains(state.LastError, "transaction count mismatch") {
		t.Fatalf("malformed blocktxn fill state=%+v, want ban and last error", state)
	}
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("malformed blocktxn fill sent fallback instead of returning an error")
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("malformed blocktxn fill did not clear matching outstanding request")
	}
}

func TestInternalCompactReceiveMissingAndFallbackBranches(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	missing := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xaa}}})
	full := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, Prefilled: []prefilledTxn{{Index: 0, Tx: txs[0]}}})

	p := newCompactScriptedPeer(t)
	if err := p.handleCmpctBlock(nil); err == nil || p.snapshotState().BanScore == 0 {
		t.Fatalf("malformed cmpctblock err=%v state=%+v", err, p.snapshotState())
	}

	p = newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 801, 802), 801, 802)
	p.service.cfg.BlockStore = nil
	if err := p.handleCmpctBlock(full); err == nil || !strings.Contains(err.Error(), "nil blockstore") {
		t.Fatalf("hasBlock cmpctblock err=%v, want nil blockstore", err)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("hasBlock error did not clear matching compact outstanding request")
	}

	p = newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleCmpctBlock(missing), "missing compact block")
	requireCompactFrame(t, p, messageGetBlockTxn)
	if snap, ok := p.compactOutstandingRequestSnapshot(); !ok || snap.BlockHash != blockHash || snap.BlockTxnPayloadCap == 0 {
		t.Fatalf("outstanding=%+v ok=%v", snap, ok)
	}

	p = newCompactScriptedPeer(t)
	tooMany := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: make([]compactShortID, maxCompactRelayEntries+1)})
	requireNoCompactErr(t, p.handleCmpctBlock(tooMany), "missing overflow fallback")
	requireCompactFrame(t, p, messageGetData)

	p = newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleCmpctBlock(full), "prefilled compact block")
	if have, err := p.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("hasBlock=%v err=%v", have, err)
	}
}

func TestInternalCompactApplySuccessClearsMatchingOutstanding(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 601, 602), 601, 602)
	fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true)
	requireNoCompactErr(t, err, "compact apply success")
	if fallback || !accepted {
		t.Fatalf("compact apply success fallback=%v accepted=%v, want accepted without fallback", fallback, accepted)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("compact apply success did not clear matching compact outstanding request")
	}
}

func TestInternalCompactApplyEarlyHaveClearsMatchingOutstanding(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 701, 702), 701, 702)
	fallback, accepted, err := p.processCompactRelayedBlockWithFallback(blockHash, node.DevnetGenesisBlockBytes(), true)
	requireNoCompactErr(t, err, "compact apply early-have")
	if fallback || accepted {
		t.Fatalf("compact apply early-have fallback=%v accepted=%v, want no accepted sync trigger", fallback, accepted)
	}
	if _, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatal("compact apply early-have did not clear matching compact outstanding request")
	}
}

func TestProcessCompactTransactionsAlreadyHaveSkipsSyncRequest(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	p := newCompactScriptedPeer(t)
	requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "seed existing block")
	p.state.RemoteVersion.BestHeight = 1

	requireNoCompactErr(t, p.processCompactTransactions(blockHash, header, txs, true), "compact apply early-have")
	if p.conn.(*scriptedConn).Buffer.Len() != 0 {
		t.Fatal("already-have compact block requested more blocks")
	}
}

func TestProcessCompactTransactionsRejectsAcceptedBlockMissingAfterApply(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	for _, tc := range []struct {
		name            string
		fallbackOnApply bool
	}{
		{name: "short_id", fallbackOnApply: true},
		{name: "prefilled_only", fallbackOnApply: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newCompactScriptedPeer(t)
			otherStore, err := node.OpenBlockStore(node.BlockStorePath(t.TempDir()))
			requireNoCompactErr(t, err, "open alternate blockstore")
			p.service.cfg.BlockStore = otherStore

			err = p.processCompactTransactions(blockHash, header, txs, tc.fallbackOnApply)
			if err == nil || !strings.Contains(err.Error(), "compact block apply succeeded without accepting block") {
				t.Fatalf("processCompactTransactions err=%v, want explicit missing accepted block error", err)
			}
			if p.service.blockSeen.Has(blockHash) {
				t.Fatal("accepted-but-missing compact block marked blockSeen before storage verification")
			}
			if p.conn.(*scriptedConn).Buffer.Len() != 0 {
				t.Fatal("accepted-but-missing compact block path sent fallback instead of returning an error")
			}
		})
	}
}

func TestCompactPartsFromBlockBytesDecodesCompactSizeTxCountWidth(t *testing.T) {
	const txCount = 253
	genesis := node.DevnetGenesisBlockBytes()
	block := append([]byte(nil), genesis[:consensus.BLOCK_HEADER_BYTES]...)
	block = consensus.AppendCompactSize(block, txCount)
	firstTx := minimalBlockTxnTestTxBytes(1000)
	block = append(block, firstTx...)
	for i := uint64(1); i < txCount; i++ {
		block = append(block, minimalBlockTxnTestTxBytes(1000+i)...)
	}

	_, _, txs := compactPartsFromBlockBytes(t, block)
	if len(txs) != txCount {
		t.Fatalf("tx count=%d, want %d", len(txs), txCount)
	}
	if !bytes.Equal(txs[0], firstTx) {
		t.Fatalf("first tx was sliced from the wrong offset")
	}
}

func TestCompactRelayLocalTransactionsBoundsMemoryPoolSnapshot(t *testing.T) {
	pool := compactRelayTestMemoryPool(t, 4)
	if got := compactRelayLocalTransactions(pool, 2); len(got) != 2 {
		t.Fatalf("bounded snapshot len=%d, want 2", len(got))
	}
	if got := compactRelayLocalTransactions(pool, 0); got != nil {
		t.Fatalf("zero-limit snapshot=%v, want nil", got)
	}
	byteCap := len(minimalBlockTxnTestTxBytes(1))
	if got := compactRelayLocalTransactionsWithBudget(pool, 4, byteCap); len(got) != 1 {
		t.Fatalf("byte-bounded snapshot len=%d, want 1", len(got))
	}
}

func TestCompactRelayLocalCandidateCollectorCountsSkippedEntries(t *testing.T) {
	smallRaw := minimalBlockTxnTestTxBytes(90)
	smallCap := len(smallRaw)
	collector := newCompactLocalTxCandidateCollector(4, 4, smallCap)
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(smallRaw)
	if len(collector.out) != 1 || !bytes.Equal(collector.out[0], smallRaw) {
		t.Fatalf("oversized local candidates stopped bounded scan: len=%d", len(collector.out))
	}

	collector = newCompactLocalTxCandidateCollector(4, 4, smallCap)
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	collector.consider(make([]byte, smallCap+1))
	continued := collector.consider(smallRaw)
	if continued || len(collector.out) != 0 {
		t.Fatalf("scan budget accepted late candidate: continue=%v len=%d", continued, len(collector.out))
	}
}

func TestCompactRelayLocalTransactionsCopiesMemoryPoolBytes(t *testing.T) {
	aliasPool := NewMemoryTxPoolWithLimit(1)
	aliasRaw := minimalBlockTxnTestTxBytes(99)
	_, aliasTxid, _, _, err := consensus.ParseTx(aliasRaw)
	if err != nil {
		t.Fatalf("ParseTx alias: %v", err)
	}
	if !aliasPool.Put(aliasTxid, aliasRaw, 1, len(aliasRaw)) {
		t.Fatal("Put alias tx rejected")
	}
	got := compactRelayLocalTransactions(aliasPool, 1)
	if len(got) != 1 || len(got[0]) == 0 {
		t.Fatalf("alias snapshot=%v", got)
	}
	got[0][0] ^= 0xff
	if stored, ok := aliasPool.Get(aliasTxid); !ok || stored[0] == got[0][0] {
		t.Fatal("bounded snapshot aliases memory pool transaction bytes")
	}
}

func TestCompactRelayLocalTransactionsUsesPurposeSpecificByteCap(t *testing.T) {
	if compactLocalTxCandidateBytesLimit >= consensus.MAX_BLOCK_BYTES {
		t.Fatalf("local candidate byte limit=%d, want below MAX_BLOCK_BYTES=%d", compactLocalTxCandidateBytesLimit, consensus.MAX_BLOCK_BYTES)
	}
	pool := NewMemoryTxPoolWithLimit(1)
	raw := make([]byte, compactLocalTxCandidateBytesLimit+1)
	if !pool.Put([32]byte{0x44}, raw, 1, len(raw)) {
		t.Fatal("Put oversized local candidate")
	}
	if got := compactRelayLocalTransactions(pool, 1); len(got) != 0 {
		t.Fatalf("default local candidate cap accepted %d oversized txs", len(got))
	}
}

func compactRelayTestMemoryPool(t *testing.T, count int) *MemoryTxPool {
	t.Helper()
	pool := NewMemoryTxPoolWithLimit(count)
	for i := 0; i < count; i++ {
		raw := minimalBlockTxnTestTxBytes(uint64(i + 1))
		_, txid, _, _, err := consensus.ParseTx(raw)
		if err != nil {
			t.Fatalf("ParseTx[%d]: %v", i, err)
		}
		if !pool.Put(txid, raw, uint64(i+1), len(raw)) {
			t.Fatalf("Put[%d] rejected", i)
		}
	}
	return pool
}

func TestCompactRelayLocalTransactionsForBlockSkipsPrefilledOnly(t *testing.T) {
	pool := NewMemoryTxPoolWithLimit(1)
	if !pool.Put([32]byte{0x01}, []byte{0xaa}, 1, 1) {
		t.Fatal("Put local candidate")
	}
	if got := compactRelayLocalTransactionsForBlock(cmpctBlockPayload{Prefilled: []prefilledTxn{{Index: 0, Tx: []byte{0xbb}}}}, pool); got != nil {
		t.Fatalf("prefilled-only compact block candidates=%v, want nil", got)
	}
	if got := compactRelayLocalTransactionsForBlock(cmpctBlockPayload{ShortIDs: []compactShortID{{0x01}}}, pool); len(got) != 1 {
		t.Fatalf("short-id compact block candidates len=%d, want 1", len(got))
	}
}

func TestCompactRelayLocalTransactionsCoversCanonicalAndUnknownPools(t *testing.T) {
	if got := compactRelayLocalTransactionsWithBudget(rejectingTxPool{}, 1, 1); got != nil {
		t.Fatalf("unknown pool candidates=%v, want nil", got)
	}
	if got := compactRelayLocalTransactionsWithBudget(NewCanonicalMempoolTxPool(nil), 1, 1); got != nil {
		t.Fatalf("nil canonical candidates=%v, want nil", got)
	}

	h := newTestHarness(t, 1, "127.0.0.1:0", nil)
	mempool := wireCanonicalMempoolForP2PTest(t, h)
	tx1, _, _ := signedCanonicalP2PTxForHarness(t, h, 9001)
	if err := mempool.AddTx(tx1); err != nil {
		t.Fatalf("AddTx tx1: %v", err)
	}

	pool := NewCanonicalMempoolTxPool(mempool)
	if got := compactRelayLocalTransactionsWithBudget(pool, 1, consensus.MAX_BLOCK_BYTES); len(got) != 1 {
		t.Fatalf("limit-bounded canonical candidates len=%d, want 1", len(got))
	}
	if got := compactRelayLocalTransactionsWithBudget(pool, 2, len(tx1)-1); len(got) != 0 {
		t.Fatalf("byte-bounded canonical candidates len=%d, want 0", len(got))
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

func mustEncodeCmpctBlockPayload(t *testing.T, in cmpctBlockPayload) []byte {
	t.Helper()
	raw, err := encodeCmpctBlockPayload(in)
	requireNoCompactErr(t, err, "encode cmpctblock")
	return raw
}

func newCompactScriptedPeer(t *testing.T) *peer {
	t.Helper()
	p := newPeerRuntimeTestPeer(t)
	p.conn = &scriptedConn{}
	return p
}

func setCompactTestOutstanding(p *peer, blockHash [32]byte, header [consensus.BLOCK_HEADER_BYTES]byte, shortID compactShortID, nonce1, nonce2 uint64) {
	p.activateCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:          blockHash,
		Header:             header,
		MissingIndexes:     []uint64{0},
		MissingShortIDs:    []compactShortID{shortID},
		Transactions:       [][]byte{nil},
		Nonce1:             nonce1,
		Nonce2:             nonce2,
		BlockTxnPayloadCap: compactRelayPayloadCap(messageBlockTxn),
	})
}

func compactPartsFromBlockBytes(t *testing.T, block []byte) ([consensus.BLOCK_HEADER_BYTES]byte, [32]byte, [][]byte) {
	t.Helper()
	if len(block) < consensus.BLOCK_HEADER_BYTES+1 {
		t.Fatalf("block too short: %d", len(block))
	}
	var header [consensus.BLOCK_HEADER_BYTES]byte
	copy(header[:], block[:consensus.BLOCK_HEADER_BYTES])
	blockHash, _ := consensus.BlockHash(header[:])
	txCount, countLen, err := consensus.DecodeCompactSize(block[consensus.BLOCK_HEADER_BYTES:])
	if err != nil {
		t.Fatalf("decode tx_count: %v", err)
	}
	offset := consensus.BLOCK_HEADER_BYTES + countLen
	txs := make([][]byte, 0)
	for i := uint64(0); i < txCount; i++ {
		_, _, _, consumed, err := consensus.ParseTx(block[offset:])
		if err != nil {
			t.Fatalf("parse tx[%d]: %v", i, err)
		}
		if consumed <= 0 || offset+consumed > len(block) {
			t.Fatalf("parse tx[%d] consumed invalid length %d at offset %d", i, consumed, offset)
		}
		txs = append(txs, append([]byte(nil), block[offset:offset+consumed]...))
		offset += consumed
	}
	if offset != len(block) {
		t.Fatalf("block has trailing bytes after tx list: %d", len(block)-offset)
	}
	return header, blockHash, txs
}

func requireCompactFrame(t *testing.T, p *peer, command string) {
	t.Helper()
	conn := p.conn.(*scriptedConn)
	frame, err := readFrame(bytes.NewReader(conn.Buffer.Bytes()), networkMagic(p.service.cfg.PeerRuntimeConfig.Network), p.service.cfg.PeerRuntimeConfig.MaxMessageSize)
	conn.Buffer.Reset()
	if err != nil || frame.Command != command {
		t.Fatalf("compact frame=%+v err=%v want %s", frame, err, command)
	}
}

func requireNoCompactErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
}

func compactHeaderWithTarget(header [consensus.BLOCK_HEADER_BYTES]byte, target [32]byte) [consensus.BLOCK_HEADER_BYTES]byte {
	const targetOffset = 4 + 32 + 32 + 8
	copy(header[targetOffset:targetOffset+32], target[:])
	return header
}

func compactFilledTarget(fill byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = fill
	}
	return out
}
