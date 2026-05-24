package p2p

import (
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestCompactFlowHardeningMatrix(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	missing := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{Header: header, ShortIDs: []compactShortID{{0xaa}}})

	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "missing compact block sends bounded getblocktxn",
			run: func(t *testing.T) {
				p := newCompactScriptedPeer(t)

				requireNoCompactErr(t, p.handleCmpctBlock(missing), "missing compact block")
				requireGetBlockTxnRequest(t, p, blockHash, []uint64{0})
				snap, ok := p.compactOutstandingRequestSnapshot()
				if !ok || snap.BlockHash != blockHash || snap.BlockTxnPayloadCap <= blockTxnHashPayloadBytes {
					t.Fatalf("outstanding=%+v ok=%v, want bounded request for %x", snap, ok, blockHash)
				}
			},
		},
		{
			name: "overlapping compact miss falls back and clears matching outstanding",
			run: func(t *testing.T) {
				p := newCompactScriptedPeer(t)
				setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 201, 202), 201, 202)

				requireNoCompactErr(t, p.handleCmpctBlock(missing), "overlapping missing compact block")
				requireFallbackGetData(t, p, blockHash)
				requireNoCompactOutstanding(t, p)
			},
		},
		{
			name: "short-id mismatch blocktxn falls back without banning",
			run: func(t *testing.T) {
				p := newCompactScriptedPeer(t)
				setCompactTestOutstanding(p, blockHash, header, compactShortID{0xbb}, 301, 302)
				response, err := encodeBlockTxnPayload(blockTxnPayload{BlockHash: blockHash, Transactions: [][]byte{txs[0]}})
				requireNoCompactErr(t, err, "encode mismatched blocktxn")

				requireNoCompactErr(t, p.handleBlockTxn(response), "mismatched blocktxn")
				requireFallbackGetData(t, p, blockHash)
				requireNoCompactOutstanding(t, p)
				if state := p.snapshotState(); state.BanScore != 0 {
					t.Fatalf("state=%+v, want no-ban short-id mismatch fallback", state)
				}
			},
		},
		{
			name: "late blocktxn after fallback drains before next frame",
			run: func(t *testing.T) {
				req := compactOutstandingTestRequest(blockHash)
				payload := append(blockHash[:], 0x01)

				p, conn, err := runExpiredLateBlockTxnFrame(t, req, payload, message{Command: messageVersion})
				state := p.snapshotState()
				if err == nil || !strings.Contains(err.Error(), "invalid version message after handshake") {
					t.Fatalf("run err=%v, want next frame after late blocktxn drain", err)
				}
				if state.BanScore != 0 || !strings.Contains(state.LastError, "ignored late blocktxn response") {
					t.Fatalf("state=%+v, want ignored late blocktxn without ban", state)
				}
				requireFirstGetDataBlock(t, p, conn.Bytes(), blockHash)
			},
		},
		{
			name: "explicit fallback request clears outstanding before full block arrives",
			run: func(t *testing.T) {
				p := newCompactScriptedPeer(t)
				setCompactTestOutstanding(p, blockHash, header, compactShortIDForTx(t, txs[0], 401, 402), 401, 402)

				requireNoCompactErr(t, p.requestCompactFullBlockFallback(blockHash), "request full block fallback")
				requireFallbackGetData(t, p, blockHash)
				requireNoCompactOutstanding(t, p)
				requireNoCompactErr(t, p.handleBlock(node.DevnetGenesisBlockBytes()), "fallback full block")
				if have, err := p.service.hasBlock(blockHash); err != nil || !have {
					t.Fatalf("hasBlock=%v err=%v, want fallback full block stored", have, err)
				}
			},
		},
	} {
		t.Run(tc.name, tc.run)
	}
}

func requireGetBlockTxnRequest(t *testing.T, p *peer, blockHash [32]byte, indexes []uint64) {
	t.Helper()
	frame := requireCompactFrame(t, p, messageGetBlockTxn)
	req, err := decodeGetBlockTxnPayload(frame.Payload)
	requireNoCompactErr(t, err, "decode getblocktxn")
	if req.BlockHash != blockHash || !reflect.DeepEqual(req.Indexes, indexes) {
		t.Fatalf("getblocktxn=%+v, want hash %x indexes %v", req, blockHash, indexes)
	}
}

func requireFallbackGetData(t *testing.T, p *peer, blockHash [32]byte) {
	t.Helper()
	frame := requireCompactFrame(t, p, messageGetData)
	items, err := decodeInventoryVectors(frame.Payload)
	requireNoCompactErr(t, err, "decode fallback getdata")
	if len(items) != 1 || items[0].Type != MSG_BLOCK || items[0].Hash != blockHash {
		t.Fatalf("fallback inventory=%+v, want MSG_BLOCK %x", items, blockHash)
	}
}

func requireNoCompactOutstanding(t *testing.T, p *peer) {
	t.Helper()
	if snap, ok := p.compactOutstandingRequestSnapshot(); ok {
		t.Fatalf("outstanding=%+v, want cleared", snap)
	}
}
