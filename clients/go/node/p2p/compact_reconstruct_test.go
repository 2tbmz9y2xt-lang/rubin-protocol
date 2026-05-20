package p2p

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

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

func TestReconstructCompactBlockRejectsMissingAboveRequestCap(t *testing.T) {
	_, err := reconstructCompactBlock(cmpctBlockPayload{
		ShortIDs: make([]compactShortID, maxCompactRelayEntries+1),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "too many compact relay missing indexes") {
		t.Fatalf("reconstructCompactBlock err=%v, want missing cap rejection", err)
	}
}

func TestCompactValidateTransactionTotalRejectsCumulativeOversize(t *testing.T) {
	txs := [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES), []byte{0x01}}
	err := compactValidateTransactionTotal(txs)
	if err == nil || !strings.Contains(err.Error(), "blocktxn transactions exceed block size") {
		t.Fatalf("compactValidateTransactionTotal err=%v, want cumulative size failure", err)
	}
}

func TestCompactReconstructionHelperErrorBranches(t *testing.T) {
	validTx := minimalBlockTxnTestTxBytes(81)
	shortID := compactShortIDForTx(t, validTx, 1, 2)

	if _, _, err := compactBlockHeaderAndHash(make([]byte, consensus.MAX_RELAY_MSG_BYTES+1)); err == nil || !strings.Contains(err.Error(), "cmpctblock payload too large") {
		t.Fatalf("compactBlockHeaderAndHash oversized err=%v, want payload cap", err)
	}
	if _, _, err := compactBlockHeaderAndHash(make([]byte, consensus.BLOCK_HEADER_BYTES-1)); err == nil || !strings.Contains(err.Error(), "cmpctblock payload missing header or nonce") {
		t.Fatalf("compactBlockHeaderAndHash short err=%v, want missing header", err)
	}

	for _, tc := range []struct {
		name    string
		payload []byte
		wantErr string
	}{
		{
			name:    "oversized",
			payload: make([]byte, consensus.MAX_RELAY_MSG_BYTES+1),
			wantErr: "cmpctblock payload too large",
		},
		{
			name:    "missing nonce",
			payload: make([]byte, consensus.BLOCK_HEADER_BYTES+15),
			wantErr: "cmpctblock payload missing header or nonce",
		},
		{
			name:    "short count varint",
			payload: append(make([]byte, consensus.BLOCK_HEADER_BYTES+16), 0xfd),
			wantErr: "EOF",
		},
		{
			name:    "truncated short ids",
			payload: append(make([]byte, consensus.BLOCK_HEADER_BYTES+16), 0x02, 1, 2, 3, 4, 5),
			wantErr: "cmpctblock payload truncated short IDs",
		},
		{
			name:    "prefilled count varint",
			payload: append(make([]byte, consensus.BLOCK_HEADER_BYTES+16), 0x00, 0xfd),
			wantErr: "EOF",
		},
		{
			name:    "zero entries",
			payload: append(make([]byte, consensus.BLOCK_HEADER_BYTES+16), 0x00, 0x00),
			wantErr: "invalid compact relay entry count",
		},
	} {
		if _, err := compactBlockRuntimeEntryCount(tc.payload); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("%s: compactBlockRuntimeEntryCount err=%v, want %q", tc.name, err, tc.wantErr)
		}
	}

	if _, _, err := compactAppendMissingIndex(make([]uint64, maxCompactRelayEntries), nil, 0, shortID); !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("compactAppendMissingIndex cap err=%v, want missing request cap", err)
	}
	if _, _, err := compactAppendResolvedShortID(make([][]byte, 1), make([]uint64, maxCompactRelayEntries), nil, map[compactShortID]uint64{shortID: 0}, shortID, 0, validTx, false); !errors.Is(err, errCompactRelayMissingRequestTooLarge) {
		t.Fatalf("compactAppendResolvedShortID duplicate cap err=%v, want missing request cap", err)
	}
	if _, _, err := compactResolveShortIDTransactions(make([][]byte, 1), 1, nil, []compactShortID{shortID}, map[compactShortID][]byte{shortID: validTx}, map[compactShortID]bool{shortID: true}); err != nil {
		t.Fatalf("compactResolveShortIDTransactions blocked short id should become missing without error: %v", err)
	}

	if err := compactValidateTransactionTotal([][]byte{nil}); err == nil || !strings.Contains(err.Error(), "compact block transaction missing") {
		t.Fatalf("compactValidateTransactionTotal nil err=%v, want missing tx", err)
	}
}

func TestCompactBlockByteAndTransactionHelperErrors(t *testing.T) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	validTx := minimalBlockTxnTestTxBytes(82)
	validBlock, err := compactBlockBytes(header, [][]byte{validTx})
	if err != nil {
		t.Fatalf("compactBlockBytes(valid): %v", err)
	}

	for _, tc := range []struct {
		name string
		txs  [][]byte
		want string
	}{
		{name: "empty", txs: nil, want: "compact block has no transactions"},
		{name: "nil tx", txs: [][]byte{nil}, want: "compact block transaction missing"},
		{name: "tx too large", txs: [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES+1)}, want: "blocktxn transaction too large"},
		{name: "block too large", txs: [][]byte{make([]byte, consensus.MAX_BLOCK_BYTES)}, want: "compact block exceeds block size"},
	} {
		if _, err := compactBlockBytes(header, tc.txs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: compactBlockBytes err=%v, want %q", tc.name, err, tc.want)
		}
	}

	for _, tc := range []struct {
		name  string
		block []byte
		want  string
	}{
		{name: "short", block: make([]byte, consensus.BLOCK_HEADER_BYTES), want: "block too short"},
		{name: "bad varint", block: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0xfd), want: "EOF"},
		{name: "zero tx count", block: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0x00), want: "invalid compact relay entry count"},
		{name: "bad tx", block: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0x01, 0x00), want: "unexpected EOF"},
		{name: "trailing", block: append(append([]byte(nil), validBlock...), 0xff), want: "trailing bytes after tx list"},
	} {
		if _, _, err := compactBlockTransactions(tc.block); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: compactBlockTransactions err=%v, want %q", tc.name, err, tc.want)
		}
	}

	for _, tc := range []struct {
		name  string
		block []byte
		want  string
	}{
		{name: "short", block: make([]byte, consensus.BLOCK_HEADER_BYTES), want: "block too short"},
		{name: "bad varint", block: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0xfd), want: "EOF"},
		{name: "zero tx count", block: append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0x00), want: "invalid compact relay entry count"},
	} {
		if _, _, err := compactBlockTransactionCount(tc.block); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: compactBlockTransactionCount err=%v, want %q", tc.name, err, tc.want)
		}
	}

	if got, err := compactRequestedTransactionsFromBlock(validBlock, nil); err != nil || len(got) != 0 {
		t.Fatalf("compactRequestedTransactionsFromBlock empty indexes=%x err=%v, want empty", got, err)
	}
	if _, err := compactRequestedTransactionsFromBlock(validBlock, []uint64{1}); err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("compactRequestedTransactionsFromBlock high in-block index err=%v, want out of range", err)
	}
	if _, err := compactRequestedTransactionsFromBlock(append(make([]byte, consensus.BLOCK_HEADER_BYTES), 0x01, 0x00), []uint64{0}); err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("compactRequestedTransactionsFromBlock bad tx err=%v, want parse error", err)
	}
	secondTx := minimalBlockTxnTestTxBytes(83)
	twoTxBlock, err := compactBlockBytes(header, [][]byte{validTx, secondTx})
	if err != nil {
		t.Fatalf("compactBlockBytes(two): %v", err)
	}
	if got, err := compactRequestedTransactionsFromBlock(twoTxBlock, []uint64{1}); err != nil || !reflect.DeepEqual(got, [][]byte{secondTx}) {
		t.Fatalf("compactRequestedTransactionsFromBlock index 1=%x err=%v, want second tx", got, err)
	}
}

func TestCompactFallbackAndOutstandingHelperBranches(t *testing.T) {
	if !errors.Is(compactFullBlockFallbackError(nil), errCompactFullBlockFallbackRequired) {
		t.Fatal("compactFullBlockFallbackError(nil) did not preserve fallback sentinel")
	}
	if !compactTxErrorNeedsFallback(consensus.ErrorCode("TX_ERR_TEST")) {
		t.Fatal("TX_ERR_* should require compact full-block fallback")
	}
	if !compactTxErrorNeedsFallback(consensus.BLOCK_ERR_DA_BATCH_EXCEEDED) {
		t.Fatal("DA body error should require compact full-block fallback")
	}
	if compactTxErrorNeedsFallback(consensus.BLOCK_ERR_TARGET_INVALID) {
		t.Fatal("header-context target error must not be hidden by full-block fallback")
	}

	p := newPeerRuntimeTestPeer(t)
	cause := errors.New("test cause")
	if got := p.requestCompactFullBlockFallbackForOutstanding(cause); got != cause {
		t.Fatalf("requestCompactFullBlockFallbackForOutstanding no outstanding=%v, want original cause", got)
	}
	p.setCompactOutstandingRequest(compactOutstandingRequest{
		BlockHash:       [32]byte{0x01},
		MissingIndexes:  []uint64{0},
		MissingShortIDs: []compactShortID{{0x01}},
		Transactions:    make([][]byte, 1),
	})
	p.clearCompactOutstandingRequest()
	if outstanding, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("clearCompactOutstandingRequest left outstanding=%+v", outstanding)
	}

	bare := &peer{}
	if bare.compactOutstandingTTL() != defaultCompactOutstandingTTL {
		t.Fatalf("bare peer TTL=%s, want default", bare.compactOutstandingTTL())
	}
	if bare.compactNow().Before(time.Unix(1, 0)) {
		t.Fatalf("bare peer compactNow returned invalid timestamp")
	}

	if got := compactRelayLocalTransactions((*MemoryTxPool)(nil)); got != nil {
		t.Fatalf("nil MemoryTxPool local txs=%x, want nil", got)
	}
	if got := compactRelayLocalTransactions((*CanonicalMempoolTxPool)(nil)); got != nil {
		t.Fatalf("nil CanonicalMempoolTxPool local txs=%x, want nil", got)
	}
	if got := compactRelayLocalTransactions(&CanonicalMempoolTxPool{}); got != nil {
		t.Fatalf("empty CanonicalMempoolTxPool local txs=%x, want nil", got)
	}
	if got := compactRelayLocalTransactions(compactNoopTxPool{}); got != nil {
		t.Fatalf("unsupported TxPool local txs=%x, want nil", got)
	}
	if _, err := compactTransactionShortID([]byte{0x00}, 1, 2); err == nil || !strings.Contains(err.Error(), "compact local transaction is non-canonical") {
		t.Fatalf("compactTransactionShortID malformed err=%v, want canonical error", err)
	}
}

func TestCompactOutstandingRequestValidationBranches(t *testing.T) {
	if _, err := newCompactOutstandingRequest(cmpctBlockPayload{}, [32]byte{}, compactReconstructionResult{}); err == nil || !strings.Contains(err.Error(), "compact reconstruction missing request mismatch") {
		t.Fatalf("newCompactOutstandingRequest empty err=%v, want mismatch", err)
	}
	tx := minimalBlockTxnTestTxBytes(84)
	shortID, err := compactTransactionShortID(tx, 0, 0)
	if err != nil {
		t.Fatalf("compactTransactionShortID: %v", err)
	}
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	req := compactOutstandingRequest{
		MissingIndexes:  []uint64{1},
		MissingShortIDs: []compactShortID{shortID},
		Transactions:    make([][]byte, 1),
	}
	if _, err := compactFillResponseTransactions(req, [][]byte{tx}, [][32]byte{wtxid}); err == nil || !strings.Contains(err.Error(), "compact relay index out of range") {
		t.Fatalf("compactFillResponseTransactions out-of-range err=%v, want range error", err)
	}
}

func TestCompactRequestedTransactionsRejectsDuplicateBeforeBlockScan(t *testing.T) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	blockBytes, err := compactBlockBytes(header, [][]byte{minimalBlockTxnTestTxBytes(71), minimalBlockTxnTestTxBytes(72)})
	if err != nil {
		t.Fatalf("compactBlockBytes: %v", err)
	}
	if _, err := compactRequestedTransactionsFromBlock(blockBytes, []uint64{0, 0}); err == nil || !strings.Contains(err.Error(), "duplicate compact relay index") {
		t.Fatalf("compactRequestedTransactionsFromBlock duplicate err=%v, want duplicate rejection", err)
	}
}

func TestCompactRequestedTransactionsRejectsRuntimeIndexCapBeforeScan(t *testing.T) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	blockBytes, err := compactBlockBytes(header, [][]byte{minimalBlockTxnTestTxBytes(73)})
	if err != nil {
		t.Fatalf("compactBlockBytes: %v", err)
	}
	_, err = compactRequestedTransactionsFromBlock(blockBytes, []uint64{maxCompactRelayEntries})
	if err == nil || !strings.Contains(err.Error(), "compact relay index exceeds runtime cap") {
		t.Fatalf("compactRequestedTransactionsFromBlock high index err=%v, want runtime cap rejection", err)
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

func compactShortIDForTx(t *testing.T, tx []byte, nonce1, nonce2 uint64) compactShortID {
	t.Helper()
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		t.Fatalf("ParseTx: consumed=%d err=%v", consumed, err)
	}
	return compactShortID(consensus.CompactShortID(wtxid, nonce1, nonce2))
}

type compactNoopTxPool struct{}

func (compactNoopTxPool) Get([32]byte) ([]byte, bool) { return nil, false }
func (compactNoopTxPool) Has([32]byte) bool           { return false }
func (compactNoopTxPool) Put([32]byte, []byte, uint64, int) bool {
	return false
}
