package p2p

import (
	"encoding/binary"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	messageSendCmpct              = "sendcmpct"
	messageCmpctBlock             = "cmpctblock"
	messageGetBlockTxn            = "getblocktxn"
	messageBlockTxn               = "blocktxn"
	compactRelayVersion    uint64 = 1
	sendCmpctPayloadBytes         = 9
	compactShortIDBytes           = 6
	maxCompactRelayEntries        = maxInventoryVectors
)

type sendCmpctPayload struct {
	Mode    uint8
	Version uint64
}

func encodeSendCmpctPayload(p sendCmpctPayload) ([]byte, error) {
	if p.Mode > 2 {
		return nil, errors.New("unsupported compact relay mode")
	}
	if p.Version != compactRelayVersion {
		return nil, errors.New("unsupported compact relay version")
	}
	return consensus.AppendU64le([]byte{p.Mode}, p.Version), nil
}

func decodeSendCmpctPayload(payload []byte) (sendCmpctPayload, error) {
	if len(payload) != sendCmpctPayloadBytes {
		return sendCmpctPayload{}, errors.New("sendcmpct payload width mismatch")
	}
	out := sendCmpctPayload{Mode: payload[0], Version: binary.LittleEndian.Uint64(payload[1:])}
	_, err := encodeSendCmpctPayload(out)
	return out, err
}
