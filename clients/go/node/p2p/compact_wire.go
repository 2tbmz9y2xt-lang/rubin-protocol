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

type blockTxnPayload struct {
	BlockHash    [32]byte
	Transactions [][]byte
}

type compactShortID [compactShortIDBytes]byte

type prefilledTxn struct {
	Index uint64
	Tx    []byte
}

type cmpctBlockPayload struct {
	Header    [consensus.BLOCK_HEADER_BYTES]byte
	Nonce     uint64
	ShortIDs  []compactShortID
	Prefilled []prefilledTxn
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

func encodeBlockTxnPayload(p blockTxnPayload) ([]byte, error) {
	if len(p.Transactions) > maxCompactRelayEntries {
		return nil, errors.New("too many compact relay transactions")
	}
	if err := validateCompactRelayTransactions(p.Transactions, "blocktxn transaction is non-canonical"); err != nil {
		return nil, err
	}
	totalTxBytes := uint64(0)
	for _, tx := range p.Transactions {
		totalTxBytes += uint64(len(tx))
	}
	capHint := 32 + maxCompactSizeBytes + int(totalTxBytes) // #nosec G115 -- totalTxBytes is capped at consensus.MAX_BLOCK_BYTES above.
	out := make([]byte, 0, capHint)
	out = append(out, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Transactions)))
	for _, tx := range p.Transactions {
		out = append(out, tx...)
	}
	return out, nil
}

func decodeBlockTxnPayload(payload []byte) (blockTxnPayload, error) {
	var out blockTxnPayload
	if len(payload) < 32 {
		return out, errors.New("blocktxn payload missing block hash")
	}
	copy(out.BlockHash[:], payload[:32])
	count, consumed, err := consensus.DecodeCompactSize(payload[32:])
	if err != nil {
		return blockTxnPayload{}, err
	}
	if count > maxCompactRelayEntries {
		return blockTxnPayload{}, errors.New("too many compact relay transactions")
	}
	offset := 32 + consumed
	transactions := make([][]byte, 0, int(count)) // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	var totalTxBytes uint64
	for i := uint64(0); i < count; i++ {
		tx, n, nextTotal, err := decodeBlockTxnTransaction(payload[offset:], totalTxBytes)
		if err != nil {
			return blockTxnPayload{}, err
		}
		transactions = append(transactions, append([]byte(nil), tx...))
		offset += n
		totalTxBytes = nextTotal
	}
	if offset != len(payload) {
		return blockTxnPayload{}, errors.New("blocktxn payload has trailing bytes")
	}
	out.Transactions = transactions
	return out, nil
}

func encodeCmpctBlockPayload(p cmpctBlockPayload) ([]byte, error) {
	if len(p.ShortIDs) > consensus.MAX_BLOCK_BYTES-len(p.Prefilled) {
		return nil, errors.New("too many compact block transactions")
	}
	prefilledTxs := make([][]byte, 0, len(p.Prefilled))
	for _, tx := range p.Prefilled {
		prefilledTxs = append(prefilledTxs, tx.Tx)
	}
	if err := validateCompactRelayTransactions(prefilledTxs, "cmpctblock prefilled transaction is non-canonical"); err != nil {
		return nil, err
	}
	capHint, ok := cmpctBlockPayloadByteLen(uint64(len(p.ShortIDs)), p.Prefilled)
	if !ok {
		return nil, errors.New("cmpctblock payload too large")
	}
	out := make([]byte, 0, int(capHint)) // #nosec G115 -- cmpctBlockPayloadByteLen caps capHint at MAX_RELAY_MSG_BYTES.
	out = append(out, p.Header[:]...)
	out = consensus.AppendU64le(out, p.Nonce)
	out = consensus.AppendCompactSize(out, uint64(len(p.ShortIDs)))
	for _, shortID := range p.ShortIDs {
		out = append(out, shortID[:]...)
	}
	out = consensus.AppendCompactSize(out, uint64(len(p.Prefilled)))
	var prevPlusOne uint64
	for _, tx := range p.Prefilled {
		delta := tx.Index - prevPlusOne
		out = consensus.AppendCompactSize(out, delta)
		out = append(out, tx.Tx...)
		prevPlusOne = tx.Index + 1
	}
	_, err := decodeCmpctBlockPayload(out)
	return out, err
}

func decodeCmpctBlockPayload(payload []byte) (cmpctBlockPayload, error) {
	if len(payload) > consensus.MAX_RELAY_MSG_BYTES {
		return cmpctBlockPayload{}, errors.New("cmpctblock payload too large")
	}
	out, prefilledCount, totalEntries, offset, err := decodeCmpctBlockPrefix(payload)
	if err != nil {
		return cmpctBlockPayload{}, err
	}
	var prev uint64
	var totalTxBytes uint64
	for i := uint64(0); i < prefilledCount; i++ {
		delta, n, err := consensus.DecodeCompactSize(payload[offset:])
		if err != nil {
			return cmpctBlockPayload{}, err
		}
		idx, err := getBlockTxnAbsoluteIndex(prev, delta, i == 0)
		if err != nil {
			return cmpctBlockPayload{}, err
		}
		if idx >= totalEntries {
			return cmpctBlockPayload{}, errors.New("compact relay index out of range")
		}
		tx, txConsumed, nextTotal, err := decodeBlockTxnTransaction(payload[offset+n:], totalTxBytes)
		if err != nil {
			return cmpctBlockPayload{}, err
		}
		out.Prefilled = append(out.Prefilled, prefilledTxn{Index: idx, Tx: append([]byte(nil), tx...)})
		offset += n + txConsumed
		prev = idx
		totalTxBytes = nextTotal
	}
	return finishCmpctBlockPayload(out, offset, len(payload))
}

func decodeCmpctBlockPrefix(payload []byte) (cmpctBlockPayload, uint64, uint64, int, error) {
	var out cmpctBlockPayload
	if len(payload) < consensus.BLOCK_HEADER_BYTES+8 {
		return out, 0, 0, 0, errors.New("cmpctblock payload missing header or nonce")
	}
	copy(out.Header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	out.Nonce = binary.LittleEndian.Uint64(payload[consensus.BLOCK_HEADER_BYTES:])
	offset := consensus.BLOCK_HEADER_BYTES + 8
	shortCount, consumed, err := consensus.DecodeCompactSize(payload[offset:])
	if err != nil {
		return cmpctBlockPayload{}, 0, 0, 0, err
	}
	offset += consumed
	if shortCount > uint64(len(payload[offset:]))/compactShortIDBytes {
		return cmpctBlockPayload{}, 0, 0, 0, errors.New("cmpctblock payload truncated short IDs")
	}
	shortIDEnd := offset + int(shortCount)*compactShortIDBytes // #nosec G115 -- shortCount is bounded by remaining payload width above.
	prefilledCount, consumed, err := consensus.DecodeCompactSize(payload[shortIDEnd:])
	if err != nil {
		return cmpctBlockPayload{}, 0, 0, 0, err
	}
	totalEntries := shortCount + prefilledCount
	if totalEntries > consensus.MAX_BLOCK_BYTES || totalEntries < shortCount {
		return cmpctBlockPayload{}, 0, 0, 0, errors.New("too many compact relay entries")
	}
	out.ShortIDs = make([]compactShortID, 0, int(shortCount)) // #nosec G115 -- totalEntries is capped above.
	for ; offset < shortIDEnd; offset += compactShortIDBytes {
		var shortID compactShortID
		copy(shortID[:], payload[offset:offset+compactShortIDBytes])
		out.ShortIDs = append(out.ShortIDs, shortID)
	}
	return out, prefilledCount, totalEntries, shortIDEnd + consumed, nil
}

func decodeBlockTxnTransaction(payload []byte, totalTxBytes uint64) ([]byte, int, uint64, error) {
	_, _, _, consumed, err := consensus.ParseTx(payload)
	if err != nil {
		return nil, 0, totalTxBytes, err
	}
	txLen := uint64(consumed) // #nosec G115 -- consumed is non-negative and bounded by len(payload).
	nextTotal, err := validateBlockTxnTransactionSize(txLen, totalTxBytes)
	return payload[:consumed], consumed, nextTotal, err
}

func validateBlockTxnTransactionSize(txLen, totalTxBytes uint64) (uint64, error) {
	if txLen == 0 {
		return totalTxBytes, errors.New("blocktxn transaction is empty")
	}
	if txLen > consensus.MAX_BLOCK_BYTES {
		return totalTxBytes, errors.New("blocktxn transaction too large")
	}
	if totalTxBytes > consensus.MAX_BLOCK_BYTES-txLen {
		return totalTxBytes, errors.New("blocktxn transactions exceed block size")
	}
	return totalTxBytes + txLen, nil
}

func validateCompactRelayTransactions(transactions [][]byte, nonCanonicalErr string) error {
	var totalTxBytes uint64
	for _, tx := range transactions {
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return err
		}
		_, _, _, consumed, err := consensus.ParseTx(tx)
		if err != nil || consumed != len(tx) {
			return errors.New(nonCanonicalErr)
		}
		totalTxBytes = nextTotal
	}
	return nil
}

func finishCmpctBlockPayload(out cmpctBlockPayload, offset, payloadLen int) (cmpctBlockPayload, error) {
	if offset != payloadLen {
		return cmpctBlockPayload{}, errors.New("cmpctblock payload has trailing bytes")
	}
	return out, nil
}

func cmpctBlockPayloadByteLen(shortCount uint64, prefilled []prefilledTxn) (uint64, bool) {
	limit := uint64(consensus.MAX_RELAY_MSG_BYTES)
	total := uint64(consensus.BLOCK_HEADER_BYTES + 8 + len(consensus.EncodeCompactSize(shortCount)) + len(consensus.EncodeCompactSize(uint64(len(prefilled)))))
	if shortCount > (limit-total)/compactShortIDBytes {
		return 0, false
	}
	total += shortCount * compactShortIDBytes
	var prevPlusOne uint64
	for _, tx := range prefilled {
		delta := tx.Index - prevPlusOne
		add := uint64(len(consensus.EncodeCompactSize(delta)) + len(tx.Tx))
		if add > limit-total {
			return 0, false
		}
		total += add
		prevPlusOne = tx.Index + 1
	}
	return total, true
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
