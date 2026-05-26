package p2p

import (
	"encoding/binary"
	"errors"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const (
	messageSendCmpct                    = "sendcmpct"
	messageCmpctBlock                   = "cmpctblock"
	messageGetBlockTxn                  = "getblocktxn"
	messageBlockTxn                     = "blocktxn"
	messageGetDAChunk                   = "getdachunk"
	compactRelayVersion          uint64 = 1
	daChunkRequestVersion        uint64 = 1
	sendCmpctPayloadBytes               = 9
	compactShortIDBytes                 = 6
	compactRelayIndexBytes              = 4
	daChunkIndexBytes                   = 2
	getDAChunkPayloadPrefixBytes        = 8 + 32
	maxCompactRelayEntries              = maxInventoryVectors
	maxCmpctBlockEntries                = consensus.MAX_BLOCK_BYTES
	maxCompactRelayIndexValue           = consensus.MAX_BLOCK_BYTES - 1
)

type sendCmpctPayload struct {
	Mode    uint8
	Version uint64
}

type getBlockTxnPayload struct {
	BlockHash [32]byte
	Indexes   []uint64
}

type getDAChunkPayload struct {
	Version uint64
	DAID    [32]byte
	Indexes []uint16
}

type blockTxnPayload struct {
	BlockHash    [32]byte
	Transactions [][]byte
}

type blockTxnRuntimePayload struct {
	BlockHash    [32]byte
	Transactions [][]byte
	WTxIDs       [][32]byte
}

type compactShortID [compactShortIDBytes]byte

type prefilledTxn struct {
	Index uint64
	Tx    []byte
}

type cmpctBlockPayload struct {
	Header    [consensus.BLOCK_HEADER_BYTES]byte
	Nonce1    uint64
	Nonce2    uint64
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
	out := make([]byte, 0, 32+maxCompactSizeBytes+len(p.Indexes)*compactRelayIndexBytes)
	out = append(out, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Indexes)))
	for _, idx := range p.Indexes {
		if idx > maxCompactRelayIndexValue {
			return nil, errors.New("compact relay index out of range")
		}
		out = consensus.AppendU32le(out, uint32(idx)) // #nosec G115 -- maxCompactRelayIndexValue is below uint32 max.
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
	for i := uint64(0); i < count; i++ {
		if len(payload[offset:]) < compactRelayIndexBytes {
			return getBlockTxnPayload{}, errors.New("getblocktxn payload truncated index")
		}
		idx := uint64(binary.LittleEndian.Uint32(payload[offset:]))
		offset += compactRelayIndexBytes
		if idx > maxCompactRelayIndexValue {
			return getBlockTxnPayload{}, errors.New("compact relay index out of range")
		}
		indexes = append(indexes, idx)
	}
	if offset != len(payload) {
		return getBlockTxnPayload{}, errors.New("getblocktxn payload has trailing bytes")
	}
	out.Indexes = indexes
	return out, nil
}

func getDAChunkPayloadCap() uint32 {
	return uint32(getDAChunkPayloadPrefixBytes + maxCompactSizeBytes + int(consensus.MAX_DA_CHUNK_COUNT)*daChunkIndexBytes)
}

func encodeGetDAChunkPayload(p getDAChunkPayload) ([]byte, error) {
	if p.Version != daChunkRequestVersion {
		return nil, errors.New("unsupported DA chunk request version")
	}
	if err := validateDAChunkRequestIndexCount(uint64(len(p.Indexes))); err != nil {
		return nil, err
	}
	out := make([]byte, 0, getDAChunkPayloadCap())
	out = consensus.AppendU64le(out, p.Version)
	out = append(out, p.DAID[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Indexes)))
	var prev uint16
	for i, idx := range p.Indexes {
		if err := validateDAChunkRequestIndex(uint64(i), idx, prev); err != nil {
			return nil, err
		}
		out = consensus.AppendU16le(out, idx)
		prev = idx
	}
	return out, nil
}

func decodeGetDAChunkPayload(payload []byte) (getDAChunkPayload, error) {
	var out getDAChunkPayload
	if len(payload) < getDAChunkPayloadPrefixBytes {
		return out, errors.New("getdachunk payload missing version or da_id")
	}
	out.Version = binary.LittleEndian.Uint64(payload[:8])
	if out.Version != daChunkRequestVersion {
		return getDAChunkPayload{}, errors.New("unsupported DA chunk request version")
	}
	copy(out.DAID[:], payload[8:getDAChunkPayloadPrefixBytes])
	count, consumed, err := consensus.DecodeCompactSize(payload[getDAChunkPayloadPrefixBytes:])
	if err != nil {
		return getDAChunkPayload{}, err
	}
	if err := validateDAChunkRequestIndexCount(count); err != nil {
		return getDAChunkPayload{}, err
	}
	offset := getDAChunkPayloadPrefixBytes + consumed
	indexes, offset, err := decodeGetDAChunkIndexes(payload, offset, count)
	if err != nil {
		return getDAChunkPayload{}, err
	}
	if offset != len(payload) {
		return getDAChunkPayload{}, errors.New("getdachunk payload has trailing bytes")
	}
	out.Indexes = indexes
	return out, nil
}

func decodeGetDAChunkIndexes(payload []byte, offset int, count uint64) ([]uint16, int, error) {
	indexes := make([]uint16, 0, int(count)) // #nosec G115 -- count is capped at MAX_DA_CHUNK_COUNT before this helper.
	var prev uint16
	for i := uint64(0); i < count; i++ {
		if len(payload[offset:]) < daChunkIndexBytes {
			return nil, 0, errors.New("getdachunk payload truncated index")
		}
		idx := binary.LittleEndian.Uint16(payload[offset:])
		offset += daChunkIndexBytes
		if err := validateDAChunkRequestIndex(i, idx, prev); err != nil {
			return nil, 0, err
		}
		indexes = append(indexes, idx)
		prev = idx
	}
	return indexes, offset, nil
}

func validateDAChunkRequestIndexCount(count uint64) error {
	if count == 0 || count > consensus.MAX_DA_CHUNK_COUNT {
		return errors.New("invalid DA chunk request index count")
	}
	return nil
}

func validateDAChunkRequestIndex(pos uint64, idx uint16, prev uint16) error {
	if uint64(idx) >= consensus.MAX_DA_CHUNK_COUNT {
		return errors.New("DA chunk request index out of range")
	}
	if pos > 0 && idx <= prev {
		return errors.New("DA chunk request indexes not strictly increasing")
	}
	return nil
}

func encodeBlockTxnPayload(p blockTxnPayload) ([]byte, error) {
	if len(p.Transactions) > maxCompactRelayEntries {
		return nil, errors.New("too many compact relay transactions")
	}
	if err := validateCompactRelayTransactions(p.Transactions, "blocktxn transaction is non-canonical"); err != nil {
		return nil, err
	}
	capHint, err := blockTxnPayloadByteLen(p.Transactions)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, int(capHint)) // #nosec G115 -- blockTxnPayloadByteLen caps capHint near MAX_BLOCK_BYTES.
	out = append(out, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Transactions)))
	for _, tx := range p.Transactions {
		out = consensus.AppendCompactSize(out, uint64(len(tx)))
		out = append(out, tx...)
	}
	return out, nil
}

func decodeBlockTxnPayload(payload []byte) (blockTxnPayload, error) {
	runtimePayload, err := decodeBlockTxnRuntimePayload(payload)
	if err != nil {
		return blockTxnPayload{}, err
	}
	return blockTxnPayload{BlockHash: runtimePayload.BlockHash, Transactions: runtimePayload.Transactions}, nil
}

func decodeBlockTxnRuntimePayload(payload []byte) (blockTxnRuntimePayload, error) {
	var blockHash [32]byte
	if len(payload) < 32 {
		return blockTxnRuntimePayload{}, errors.New("blocktxn payload missing block hash")
	}
	copy(blockHash[:], payload[:32])
	count, consumed, err := consensus.DecodeCompactSize(payload[32:])
	if err != nil {
		return blockTxnRuntimePayload{}, err
	}
	if count > maxCompactRelayEntries {
		return blockTxnRuntimePayload{}, errors.New("too many compact relay transactions")
	}
	offset := 32 + consumed
	transactions := make([][]byte, 0, int(count)) // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	wtxids := make([][32]byte, 0, int(count))     // #nosec G115 -- count is capped at maxCompactRelayEntries above.
	var totalTxBytes uint64
	for i := uint64(0); i < count; i++ {
		txLen, n, err := consensus.DecodeCompactSize(payload[offset:])
		if err != nil {
			return blockTxnRuntimePayload{}, err
		}
		offset += n
		tx, wtxid, txConsumed, nextTotal, err := decodeCompactRelayTxEnvelope(payload[offset:], txLen, totalTxBytes, "blocktxn transaction is non-canonical")
		if err != nil {
			return blockTxnRuntimePayload{}, err
		}
		transactions = append(transactions, append([]byte(nil), tx...))
		wtxids = append(wtxids, wtxid)
		offset += txConsumed
		totalTxBytes = nextTotal
	}
	if offset != len(payload) {
		return blockTxnRuntimePayload{}, errors.New("blocktxn payload has trailing bytes")
	}
	return blockTxnRuntimePayload{BlockHash: blockHash, Transactions: transactions, WTxIDs: wtxids}, nil
}

func encodeCmpctBlockPayload(p cmpctBlockPayload) ([]byte, error) {
	if _, err := validateCmpctBlockEntryCount(uint64(len(p.ShortIDs)), uint64(len(p.Prefilled))); err != nil {
		return nil, err
	}
	capHint, err := cmpctBlockPayloadByteLen(uint64(len(p.ShortIDs)), p.Prefilled)
	if err != nil {
		return nil, err
	}
	prefilledTxs := make([][]byte, 0, len(p.Prefilled))
	for _, tx := range p.Prefilled {
		prefilledTxs = append(prefilledTxs, tx.Tx)
	}
	if err := validateCompactRelayTransactions(prefilledTxs, "cmpctblock prefilled transaction is non-canonical"); err != nil {
		return nil, err
	}
	out := make([]byte, 0, int(capHint)) // #nosec G115 -- cmpctBlockPayloadByteLen caps capHint at MAX_RELAY_MSG_BYTES.
	out = append(out, p.Header[:]...)
	out = consensus.AppendU64le(out, p.Nonce1)
	out = consensus.AppendU64le(out, p.Nonce2)
	out = consensus.AppendCompactSize(out, uint64(len(p.ShortIDs)))
	for _, shortID := range p.ShortIDs {
		out = append(out, shortID[:]...)
	}
	out = consensus.AppendCompactSize(out, uint64(len(p.Prefilled)))
	for _, tx := range p.Prefilled {
		out = consensus.AppendU32le(out, uint32(tx.Index)) // #nosec G115 -- cmpctBlockPayloadByteLen caps Index below MAX_BLOCK_BYTES.
		out = consensus.AppendCompactSize(out, uint64(len(tx.Tx)))
		out = append(out, tx.Tx...)
	}
	_, err = decodeCmpctBlockPayload(out)
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
		entry, nextOffset, nextTotal, err := decodeCmpctBlockPrefilled(payload, offset, i, prev, totalEntries, totalTxBytes)
		if err != nil {
			return cmpctBlockPayload{}, err
		}
		out.Prefilled = append(out.Prefilled, entry)
		offset = nextOffset
		prev = entry.Index
		totalTxBytes = nextTotal
	}
	return finishCmpctBlockPayload(out, offset, len(payload))
}

func decodeCmpctBlockPrefix(payload []byte) (cmpctBlockPayload, uint64, uint64, int, error) {
	var out cmpctBlockPayload
	if len(payload) < consensus.BLOCK_HEADER_BYTES+16 {
		return out, 0, 0, 0, errors.New("cmpctblock payload missing header or nonce")
	}
	copy(out.Header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	out.Nonce1 = binary.LittleEndian.Uint64(payload[consensus.BLOCK_HEADER_BYTES:])
	out.Nonce2 = binary.LittleEndian.Uint64(payload[consensus.BLOCK_HEADER_BYTES+8:])
	offset := consensus.BLOCK_HEADER_BYTES + 16
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
	totalEntries, err := validateCmpctBlockEntryCount(shortCount, prefilledCount)
	if err != nil {
		return cmpctBlockPayload{}, 0, 0, 0, errors.New("invalid compact relay entry count")
	}
	out.ShortIDs = make([]compactShortID, 0, int(shortCount)) // #nosec G115 -- totalEntries is capped above.
	for ; offset < shortIDEnd; offset += compactShortIDBytes {
		var shortID compactShortID
		copy(shortID[:], payload[offset:offset+compactShortIDBytes])
		out.ShortIDs = append(out.ShortIDs, shortID)
	}
	return out, prefilledCount, totalEntries, shortIDEnd + consumed, nil
}

func cmpctBlockHeaderValidationCandidate(payload []byte) ([consensus.BLOCK_HEADER_BYTES]byte, bool) {
	var header [consensus.BLOCK_HEADER_BYTES]byte
	if !hasCmpctBlockHeaderValidationShape(payload) {
		return header, false
	}
	copy(header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	return header, true
}

func hasCmpctBlockHeaderValidationShape(payload []byte) bool {
	if len(payload) < consensus.BLOCK_HEADER_BYTES+16 {
		return false
	}
	offset := consensus.BLOCK_HEADER_BYTES + 16
	shortCount, consumed, err := consensus.DecodeCompactSize(payload[offset:])
	if err != nil {
		return false
	}
	offset += consumed
	if shortCount > uint64(len(payload[offset:]))/compactShortIDBytes {
		return false
	}
	shortIDEnd := offset + int(shortCount)*compactShortIDBytes // #nosec G115 -- shortCount is bounded by the remaining payload width above.
	prefilledCount, consumed, err := consensus.DecodeCompactSize(payload[shortIDEnd:])
	if err != nil {
		return false
	}
	totalEntries, err := validateCmpctBlockEntryCount(shortCount, prefilledCount)
	if err != nil {
		return false
	}
	return validateCmpctBlockPrefilledShape(payload, shortIDEnd+consumed, prefilledCount, totalEntries) == nil
}

func decodeCmpctBlockPrefilled(payload []byte, offset int, entryPos, prev, totalEntries, totalTxBytes uint64) (prefilledTxn, int, uint64, error) {
	idx, tx, nextOffset, nextTotal, err := parseCmpctBlockPrefilled(payload, offset, entryPos, prev, totalEntries, totalTxBytes)
	if err != nil {
		return prefilledTxn{}, 0, totalTxBytes, err
	}
	return prefilledTxn{Index: idx, Tx: append([]byte(nil), tx...)}, nextOffset, nextTotal, nil
}

func validateCmpctBlockPrefilledShape(payload []byte, offset int, prefilledCount, totalEntries uint64) error {
	var prev uint64
	var totalTxBytes uint64
	for i := uint64(0); i < prefilledCount; i++ {
		idx, nextOffset, nextTotal, err := scanCmpctBlockPrefilledShape(payload, offset, i, prev, totalEntries, totalTxBytes)
		if err != nil {
			return err
		}
		offset = nextOffset
		prev = idx
		totalTxBytes = nextTotal
	}
	if offset != len(payload) {
		return errors.New("cmpctblock payload has trailing bytes")
	}
	return nil
}

func scanCmpctBlockPrefilledShape(payload []byte, offset int, entryPos, prev, totalEntries, totalTxBytes uint64) (uint64, int, uint64, error) {
	if len(payload[offset:]) < compactRelayIndexBytes {
		return 0, 0, totalTxBytes, errors.New("cmpctblock payload truncated prefilled index")
	}
	idx := uint64(binary.LittleEndian.Uint32(payload[offset:]))
	offset += compactRelayIndexBytes
	if (entryPos > 0 && idx <= prev) || idx >= totalEntries {
		return 0, 0, totalTxBytes, errors.New("compact relay index out of range")
	}
	txLen, n, err := consensus.DecodeCompactSize(payload[offset:])
	if err != nil {
		return 0, 0, totalTxBytes, err
	}
	offset += n
	if txLen > uint64(len(payload[offset:])) {
		return 0, 0, totalTxBytes, errors.New("compact relay transaction truncated")
	}
	nextTotal, err := validateBlockTxnTransactionSize(txLen, totalTxBytes)
	if err != nil {
		return 0, 0, totalTxBytes, err
	}
	return idx, offset + int(txLen), nextTotal, nil // #nosec G115 -- txLen is bounded by len(payload[offset:]) above.
}

func parseCmpctBlockPrefilled(payload []byte, offset int, entryPos, prev, totalEntries, totalTxBytes uint64) (uint64, []byte, int, uint64, error) {
	if len(payload[offset:]) < compactRelayIndexBytes {
		return 0, nil, 0, totalTxBytes, errors.New("cmpctblock payload truncated prefilled index")
	}
	idx := uint64(binary.LittleEndian.Uint32(payload[offset:]))
	offset += compactRelayIndexBytes
	if (entryPos > 0 && idx <= prev) || idx >= totalEntries {
		return 0, nil, 0, totalTxBytes, errors.New("compact relay index out of range")
	}
	txLen, n, err := consensus.DecodeCompactSize(payload[offset:])
	if err != nil {
		return 0, nil, 0, totalTxBytes, err
	}
	offset += n
	tx, _, txConsumed, nextTotal, err := decodeCompactRelayTxEnvelope(payload[offset:], txLen, totalTxBytes, "cmpctblock prefilled transaction is non-canonical")
	if err != nil {
		return 0, nil, 0, totalTxBytes, err
	}
	return idx, tx, offset + txConsumed, nextTotal, nil
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

func blockTxnPayloadByteLen(transactions [][]byte) (uint64, error) {
	total := uint64(32 + len(consensus.EncodeCompactSize(uint64(len(transactions)))))
	for _, tx := range transactions {
		add := uint64(len(consensus.EncodeCompactSize(uint64(len(tx)))) + len(tx))
		if add > uint64(consensus.MAX_RELAY_MSG_BYTES)-total {
			return 0, errors.New("blocktxn payload too large")
		}
		total += add
	}
	return total, nil
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

func validateCmpctBlockEntryCount(shortCount, prefilledCount uint64) (uint64, error) {
	totalEntries := shortCount + prefilledCount
	if totalEntries < shortCount || totalEntries == 0 || totalEntries > maxCmpctBlockEntries {
		return 0, errors.New("invalid compact relay entry count")
	}
	return totalEntries, nil
}

func decodeCompactRelayTxEnvelope(payload []byte, txLen, totalTxBytes uint64, nonCanonicalErr string) ([]byte, [32]byte, int, uint64, error) {
	var zero [32]byte
	if txLen > uint64(len(payload)) {
		return nil, zero, 0, totalTxBytes, errors.New("compact relay transaction truncated")
	}
	tx := payload[:int(txLen)] // #nosec G115 -- txLen is bounded by len(payload) above.
	nextTotal, err := validateBlockTxnTransactionSize(txLen, totalTxBytes)
	if err != nil {
		return nil, zero, 0, totalTxBytes, err
	}
	_, _, wtxid, consumed, err := consensus.ParseTx(tx)
	if err != nil || consumed != len(tx) {
		return nil, zero, 0, totalTxBytes, errors.New(nonCanonicalErr)
	}
	return tx, wtxid, len(tx), nextTotal, nil
}

func finishCmpctBlockPayload(out cmpctBlockPayload, offset, payloadLen int) (cmpctBlockPayload, error) {
	if offset != payloadLen {
		return cmpctBlockPayload{}, errors.New("cmpctblock payload has trailing bytes")
	}
	return out, nil
}

func cmpctBlockPayloadByteLen(shortCount uint64, prefilled []prefilledTxn) (uint64, error) {
	limit := uint64(consensus.MAX_RELAY_MSG_BYTES)
	total := uint64(consensus.BLOCK_HEADER_BYTES + 16 + len(consensus.EncodeCompactSize(shortCount)) + len(consensus.EncodeCompactSize(uint64(len(prefilled)))))
	if shortCount > (limit-total)/compactShortIDBytes {
		return 0, errors.New("cmpctblock payload too large")
	}
	total += shortCount * compactShortIDBytes
	totalEntries, err := validateCmpctBlockEntryCount(shortCount, uint64(len(prefilled)))
	if err != nil {
		return 0, err
	}
	var prevPlusOne uint64
	for _, tx := range prefilled {
		if tx.Index < prevPlusOne || tx.Index >= totalEntries {
			return 0, errors.New("compact relay index out of range")
		}
		add := uint64(compactRelayIndexBytes + len(consensus.EncodeCompactSize(uint64(len(tx.Tx)))) + len(tx.Tx))
		if add > limit-total {
			return 0, errors.New("cmpctblock payload too large")
		}
		total += add
		prevPlusOne = tx.Index + 1
	}
	return total, nil
}
