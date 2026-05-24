package p2p

import (
	"context"
	"errors"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/node"
)

func TestCompactProcessEvidenceSummaryMarkers(t *testing.T) {
	header, blockHash, txs := compactPartsFromBlockBytes(t, node.DevnetGenesisBlockBytes())
	payload := mustEncodeCmpctBlockPayload(t, cmpctBlockPayload{
		Header: header,
		Prefilled: []prefilledTxn{
			{Index: 0, Tx: txs[0]},
		},
	})

	enabled := newPeerRuntimeTestPeer(t)
	enabled.service.cfg.EnableCompactReceive = true
	enabled.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	enabled.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, enabled, message{Command: messageCmpctBlock, Payload: payload})}}}

	requireNoCompactErr(t, enabled.run(context.Background()), "runtime cmpctblock evidence path")
	if have, err := enabled.service.hasBlock(blockHash); err != nil || !have {
		t.Fatalf("compact_reconstructed=false hasBlock=%v err=%v", have, err)
	}
	if got := enabled.conn.(*scriptedConn).Buffer.Len(); got != 0 {
		t.Fatalf("fallback_used=true wrote %d fallback bytes", got)
	}

	disabled := newPeerRuntimeTestPeer(t)
	disabled.setRemoteCompactMode(compactModeSnapshot{Mode: 1, Version: compactRelayVersion})
	disabled.conn = &scriptedConn{reads: []scriptedRead{{data: mustPeerRuntimeFrameBytes(t, disabled, message{Command: messageCmpctBlock, Payload: payload})}}}

	err := disabled.run(context.Background())
	var capErr commandPayloadCapError
	if !errors.As(err, &capErr) || capErr.command != messageCmpctBlock {
		t.Fatalf("disabled compact receive err=%v, want cmpctblock cap rejection", err)
	}
	if have, haveErr := disabled.service.hasBlock(blockHash); haveErr != nil || have {
		t.Fatalf("disabled compact receive stored block: have=%v err=%v", have, haveErr)
	}
}
