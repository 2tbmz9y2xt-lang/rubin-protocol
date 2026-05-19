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
	var totalTxBytes uint64
	for _, tx := range p.Transactions {
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx)), totalTxBytes)
		if err != nil {
			return nil, err
		}
		_, _, _, consumed, err := consensus.ParseTx(tx)
		if err != nil || consumed != len(tx) {
			return nil, errors.New("blocktxn transaction is non-canonical")
		}
		totalTxBytes = nextTotal
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
	if err := validateCompactRelayEntryCounts(uint64(len(p.ShortIDs)), uint64(len(p.Prefilled))); err != nil {
		return nil, err
	}
	totalTxCount := uint64(len(p.ShortIDs) + len(p.Prefilled))
	capHint := consensus.BLOCK_HEADER_BYTES + 8 + 2*maxCompactSizeBytes + len(p.ShortIDs)*compactShortIDBytes + len(p.Prefilled)*maxCompactSizeBytes
	out := make([]byte, 0, capHint)
	out = append(out, p.Header[:]...)
	out = consensus.AppendU64le(out, p.Nonce)
	out = consensus.AppendCompactSize(out, uint64(len(p.ShortIDs)))
	for _, shortID := range p.ShortIDs {
		out = append(out, shortID[:]...)
	}
	out = consensus.AppendCompactSize(out, uint64(len(p.Prefilled)))
	return appendEncodedPrefilledTransactions(out, p.Prefilled, totalTxCount)
}

func appendEncodedPrefilledTransactions(out []byte, prefilled []prefilledTxn, totalTxCount uint64) ([]byte, error) {
	var prev uint64
	var totalTxBytes uint64
	for i, tx := range prefilled {
		delta, err := compactRelayIndexDelta(prev, tx.Index, i == 0)
		if err != nil {
			return nil, err
		}
		if err := validateCompactRelayIndexInVector(tx.Index, totalTxCount); err != nil {
			return nil, err
		}
		nextTotal, err := validateBlockTxnTransactionSize(uint64(len(tx.Tx)), totalTxBytes)
		if err != nil {
			return nil, err
		}
		_, _, _, consumed, err := consensus.ParseTx(tx.Tx)
		if err != nil || consumed != len(tx.Tx) {
			return nil, errors.New("cmpctblock prefilled transaction is non-canonical")
		}
		out = consensus.AppendCompactSize(out, delta)
		out = append(out, tx.Tx...)
		prev = tx.Index
		totalTxBytes = nextTotal
	}
	return out, nil
}

func decodeCmpctBlockPayload(payload []byte) (cmpctBlockPayload, error) {
	var out cmpctBlockPayload
	if len(payload) < consensus.BLOCK_HEADER_BYTES+8 {
		return out, errors.New("cmpctblock payload missing header or nonce")
	}
	copy(out.Header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	out.Nonce = binary.LittleEndian.Uint64(payload[consensus.BLOCK_HEADER_BYTES:])
	offset := consensus.BLOCK_HEADER_BYTES + 8
	shortCount, consumed, err := consensus.DecodeCompactSize(payload[offset:])
	if err != nil {
		return cmpctBlockPayload{}, err
	}
	offset += consumed
	shortIDOffset := offset
	shortIDBytes, err := compactShortIDPayloadBytes(payload[offset:], shortCount)
	if err != nil {
		return cmpctBlockPayload{}, err
	}
	shortIDEnd := offset + shortIDBytes
	prefilledCount, consumed, err := consensus.DecodeCompactSize(payload[shortIDEnd:])
	if err != nil {
		return cmpctBlockPayload{}, err
	}
	offset = shortIDEnd + consumed
	if err := validateCompactRelayEntryCounts(shortCount, prefilledCount); err != nil {
		return cmpctBlockPayload{}, err
	}
	out.ShortIDs = decodeCompactShortIDs(payload[shortIDOffset:shortIDEnd], shortCount)
	out.Prefilled, consumed, err = decodePrefilledTransactions(payload[offset:], prefilledCount, shortCount+prefilledCount)
	if err != nil {
		return cmpctBlockPayload{}, err
	}
	offset += consumed
	if offset != len(payload) {
		return cmpctBlockPayload{}, errors.New("cmpctblock payload has trailing bytes")
	}
	return out, nil
}

func compactShortIDPayloadBytes(payload []byte, count uint64) (int, error) {
	if count > maxCompactRelayEntries {
		return 0, errors.New("too many compact relay short IDs")
	}
	needed := int(count) * compactShortIDBytes // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	if len(payload) < needed {
		return 0, errors.New("cmpctblock payload truncated short IDs")
	}
	return needed, nil
}

func decodeCompactShortIDs(payload []byte, count uint64) []compactShortID {
	shortIDs := make([]compactShortID, 0, int(count)) // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	for offset := 0; offset < len(payload); offset += compactShortIDBytes {
		var shortID compactShortID
		copy(shortID[:], payload[offset:offset+compactShortIDBytes])
		shortIDs = append(shortIDs, shortID)
	}
	return shortIDs
}

func decodePrefilledTransactions(payload []byte, count, totalTxCount uint64) ([]prefilledTxn, int, error) {
	prefilled := make([]prefilledTxn, 0, int(count)) // #nosec G115 -- count is aggregate-capped before this helper is called.
	var offset int
	var prev uint64
	var totalTxBytes uint64
	for i := uint64(0); i < count; i++ {
		tx, consumed, nextPrev, nextTotal, err := decodePrefilledTransaction(payload[offset:], prev, totalTxCount, totalTxBytes, i == 0)
		if err != nil {
			return nil, 0, err
		}
		prefilled = append(prefilled, tx)
		offset += consumed
		prev = nextPrev
		totalTxBytes = nextTotal
	}
	return prefilled, offset, nil
}

func decodePrefilledTransaction(payload []byte, prev, totalTxCount, totalTxBytes uint64, first bool) (prefilledTxn, int, uint64, uint64, error) {
	delta, consumed, err := consensus.DecodeCompactSize(payload)
	if err != nil {
		return prefilledTxn{}, 0, prev, totalTxBytes, err
	}
	idx, err := getBlockTxnAbsoluteIndex(prev, delta, first)
	if err != nil {
		return prefilledTxn{}, 0, prev, totalTxBytes, err
	}
	if err := validateCompactRelayIndexInVector(idx, totalTxCount); err != nil {
		return prefilledTxn{}, 0, prev, totalTxBytes, err
	}
	tx, txConsumed, nextTotal, err := decodeBlockTxnTransaction(payload[consumed:], totalTxBytes)
	if err != nil {
		return prefilledTxn{}, 0, prev, totalTxBytes, err
	}
	return prefilledTxn{Index: idx, Tx: append([]byte(nil), tx...)}, consumed + txConsumed, idx, nextTotal, nil
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

func validateCompactRelayEntryCounts(shortCount, prefilledCount uint64) error {
	if shortCount > maxCompactRelayEntries || prefilledCount > maxCompactRelayEntries {
		return errors.New("too many compact relay entries")
	}
	if shortCount > maxCompactRelayEntries-prefilledCount {
		return errors.New("too many compact relay entries")
	}
	return nil
}

func validateCompactRelayIndexInVector(idx, totalTxCount uint64) error {
	if idx >= totalTxCount {
		return errors.New("compact relay index out of range")
	}
	return nil
}

func compactRelayIndexDelta(prev, idx uint64, first bool) (uint64, error) {
	if idx > maxCompactRelayIndexValue {
		return 0, errors.New("compact relay index out of range")
	}
	if first {
		return idx, nil
	}
	if idx <= prev {
		return 0, errors.New("compact relay indexes not strictly increasing")
	}
	return idx - prev - 1, nil
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
