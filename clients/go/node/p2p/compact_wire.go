package p2p

import (
	"encoding/binary"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	messageSendCmpct                 = "sendcmpct"
	messageCmpctBlock                = "cmpctblock"
	messageGetBlockTxn               = "getblocktxn"
	messageBlockTxn                  = "blocktxn"
	compactRelayVersion       uint64 = 1
	sendCmpctPayloadBytes            = 9
	compactShortIDBytes              = 6
	maxCompactRelayEntries           = maxInventoryVectors
	maxCompactRelayIndexValue        = consensus.MAX_BLOCK_BYTES - 1
)

type sendCmpctPayload struct {
	Mode    uint8
	Version uint64
}

type getBlockTxnPayload struct {
	BlockHash [32]byte
	Indexes   []uint64
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

func encodeGetBlockTxnPayload(p getBlockTxnPayload) ([]byte, error) {
	if len(p.Indexes) > maxCompactRelayEntries {
		return nil, errors.New("too many compact relay indexes")
	}
	out := make([]byte, 0, 32+maxCompactSizeBytes+len(p.Indexes)*maxCompactSizeBytes)
	out = append(out, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Indexes)))
	var prev uint64
	for i, idx := range p.Indexes {
		if idx > maxCompactRelayIndexValue {
			return nil, errors.New("compact relay index out of range")
		}
		if i == 0 {
			out = consensus.AppendCompactSize(out, idx)
		} else {
			if idx <= prev {
				return nil, errors.New("compact relay indexes not strictly increasing")
			}
			out = consensus.AppendCompactSize(out, idx-prev-1)
		}
		prev = idx
	}
	return out, nil
}

func decodeGetBlockTxnPayload(payload []byte) (getBlockTxnPayload, error) {
	var out getBlockTxnPayload
	if len(payload) < 32 {
		return out, errors.New("getblocktxn payload missing block hash")
	}
	copy(out.BlockHash[:], payload[:32])
	count, consumed, err := consensus.DecodeCompactSize(payload[32:])
	if err != nil {
		return getBlockTxnPayload{}, err
	}
	if count > maxCompactRelayEntries {
		return getBlockTxnPayload{}, errors.New("too many compact relay indexes")
	}
	offset := 32 + consumed
	indexes := make([]uint64, 0, int(count)) // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	var prev uint64
	for i := uint64(0); i < count; i++ {
		delta, n, err := consensus.DecodeCompactSize(payload[offset:])
		if err != nil {
			return getBlockTxnPayload{}, err
		}
		offset += n
		idx, err := getBlockTxnAbsoluteIndex(prev, delta, i == 0)
		if err != nil {
			return getBlockTxnPayload{}, err
		}
		indexes = append(indexes, idx)
		prev = idx
	}
	if offset != len(payload) {
		return getBlockTxnPayload{}, errors.New("getblocktxn payload has trailing bytes")
	}
	out.Indexes = indexes
	return out, nil
}

func getBlockTxnAbsoluteIndex(prev, delta uint64, first bool) (uint64, error) {
	if first {
		if delta > maxCompactRelayIndexValue {
			return 0, errors.New("compact relay index out of range")
		}
		return delta, nil
	}
	if delta > ^uint64(0)-prev-1 {
		return 0, errors.New("compact relay index overflow")
	}
	idx := prev + delta + 1
	if idx > maxCompactRelayIndexValue {
		return 0, errors.New("compact relay index out of range")
	}
	return idx, nil
}
