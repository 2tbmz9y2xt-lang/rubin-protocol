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
type compactPrefilledTx struct {
	Index uint64
	Tx    []byte
}
type compactBlockPayload struct {
	Header    [consensus.BLOCK_HEADER_BYTES]byte
	Nonce     uint64
	ShortIDs  [][compactShortIDBytes]byte
	Prefilled []compactPrefilledTx
}
type getBlockTxnPayload struct {
	BlockHash [32]byte
	Indexes   []uint64
}
type blockTxnPayload struct {
	BlockHash [32]byte
	Txs       [][]byte
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
func encodeCompactBlockPayload(p compactBlockPayload) ([]byte, error) {
	total := len(p.ShortIDs) + len(p.Prefilled)
	if total > maxCompactRelayEntries {
		return nil, errors.New("compact block item count exceeds limit")
	}
	if err := validatePrefilledTxs(p.Prefilled, total); err != nil {
		return nil, err
	}
	out := consensus.AppendU64le(append([]byte{}, p.Header[:]...), p.Nonce)
	out = consensus.AppendCompactSize(out, uint64(len(p.ShortIDs)))
	for _, id := range p.ShortIDs {
		out = append(out, id[:]...)
	}
	out = consensus.AppendCompactSize(out, uint64(len(p.Prefilled)))
	for _, tx := range p.Prefilled {
		out = appendCompactBytes(consensus.AppendCompactSize(out, tx.Index), tx.Tx)
	}
	return out, nil
}
func decodeCompactBlockPayload(payload []byte) (compactBlockPayload, error) {
	var out compactBlockPayload
	if len(payload) < consensus.BLOCK_HEADER_BYTES+8 {
		return out, errors.New("cmpctblock payload too short")
	}
	copy(out.Header[:], payload[:consensus.BLOCK_HEADER_BYTES])
	off := consensus.BLOCK_HEADER_BYTES
	out.Nonce = binary.LittleEndian.Uint64(payload[off : off+8])
	off += 8
	shortCount, err := readCompactCount(payload, &off)
	if err != nil {
		return out, err
	}
	shortBytes := shortCount * compactShortIDBytes
	if len(payload)-off < shortBytes {
		return out, errors.New("compact shortid payload too short")
	}
	out.ShortIDs = make([][compactShortIDBytes]byte, shortCount)
	for i := range out.ShortIDs {
		copy(out.ShortIDs[i][:], payload[off:off+compactShortIDBytes])
		off += compactShortIDBytes
	}
	prefilledCount, err := readCompactCount(payload, &off)
	if err != nil {
		return out, err
	}
	if shortCount+prefilledCount > maxCompactRelayEntries {
		return out, errors.New("compact block item count exceeds limit")
	}
	out.Prefilled = make([]compactPrefilledTx, 0, prefilledCount)
	for i := 0; i < prefilledCount; i++ {
		index, err := readCompactUint64(payload, &off)
		if err != nil {
			return out, err
		}
		if index >= uint64(shortCount+prefilledCount) { // #nosec G115 -- aggregate count is capped by maxCompactRelayEntries.
			return out, errors.New("compact prefilled index out of range")
		}
		if i > 0 && index <= out.Prefilled[i-1].Index {
			return out, errors.New("compact prefilled indexes must be strictly increasing")
		}
		tx, err := readCompactBytes(payload, &off)
		if err != nil {
			return out, err
		}
		out.Prefilled = append(out.Prefilled, compactPrefilledTx{Index: index, Tx: tx})
	}
	if off != len(payload) {
		return out, errors.New("trailing bytes in cmpctblock payload")
	}
	return out, validatePrefilledTxs(out.Prefilled, shortCount+prefilledCount)
}
func encodeGetBlockTxnPayload(p getBlockTxnPayload) ([]byte, error) {
	if err := validateCompactIndexes(p.Indexes); err != nil {
		return nil, err
	}
	out := append([]byte{}, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Indexes)))
	for _, index := range p.Indexes {
		out = consensus.AppendCompactSize(out, index)
	}
	return out, nil
}
func decodeGetBlockTxnPayload(payload []byte) (getBlockTxnPayload, error) {
	var out getBlockTxnPayload
	if len(payload) < 33 {
		return out, errors.New("getblocktxn payload too short")
	}
	copy(out.BlockHash[:], payload[:32])
	off := 32
	count, err := readCompactCount(payload, &off)
	if err != nil {
		return out, err
	}
	out.Indexes = make([]uint64, 0, count)
	for i := 0; i < count; i++ {
		index, err := readCompactUint64(payload, &off)
		if err != nil {
			return out, err
		}
		out.Indexes = append(out.Indexes, index)
	}
	if off != len(payload) {
		return out, errors.New("trailing bytes in getblocktxn payload")
	}
	return out, validateCompactIndexes(out.Indexes)
}
func encodeBlockTxnPayload(p blockTxnPayload) ([]byte, error) {
	if len(p.Txs) > maxCompactRelayEntries {
		return nil, errors.New("blocktxn tx count exceeds limit")
	}
	out := append([]byte{}, p.BlockHash[:]...)
	out = consensus.AppendCompactSize(out, uint64(len(p.Txs)))
	for _, tx := range p.Txs {
		if len(tx) == 0 || uint64(len(tx)) > consensus.MAX_BLOCK_BYTES {
			return nil, errors.New("blocktxn tx length invalid")
		}
		out = appendCompactBytes(out, tx)
	}
	return out, nil
}
func decodeBlockTxnPayload(payload []byte) (blockTxnPayload, error) {
	var out blockTxnPayload
	if len(payload) < 33 {
		return out, errors.New("blocktxn payload too short")
	}
	copy(out.BlockHash[:], payload[:32])
	off := 32
	count, err := readCompactCount(payload, &off)
	if err != nil {
		return out, err
	}
	out.Txs = make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		tx, err := readCompactBytes(payload, &off)
		if err != nil {
			return out, err
		}
		out.Txs = append(out.Txs, tx)
	}
	if off != len(payload) {
		return out, errors.New("trailing bytes in blocktxn payload")
	}
	return out, nil
}
func appendCompactBytes(out []byte, raw []byte) []byte {
	out = consensus.AppendCompactSize(out, uint64(len(raw)))
	return append(out, raw...)
}
func readCompactCount(payload []byte, off *int) (int, error) {
	count, err := readCompactUint64(payload, off)
	if err != nil {
		return 0, err
	}
	if count > maxCompactRelayEntries {
		return 0, errors.New("compact count exceeds limit")
	}
	return int(count), nil // #nosec G115 -- count is capped by maxCompactRelayEntries.
}
func readCompactUint64(payload []byte, off *int) (uint64, error) {
	value, consumed, err := consensus.DecodeCompactSize(payload[*off:])
	if err != nil {
		return 0, err
	}
	*off += consumed
	return value, nil
}
func readCompactBytes(payload []byte, off *int) ([]byte, error) {
	n, err := readCompactUint64(payload, off)
	if err != nil {
		return nil, err
	}
	if n == 0 || n > consensus.MAX_BLOCK_BYTES {
		return nil, errors.New("compact payload bytes invalid")
	}
	nInt := int(n) // #nosec G115 -- n is capped by MAX_BLOCK_BYTES before conversion.
	if nInt > len(payload)-*off {
		return nil, errors.New("compact payload bytes invalid")
	}
	end := *off + nInt
	out := append([]byte(nil), payload[*off:end]...)
	*off = end
	return out, nil
}
func validateCompactIndexes(indexes []uint64) error {
	if len(indexes) > maxCompactRelayEntries {
		return errors.New("compact index count exceeds limit")
	}
	for i, index := range indexes {
		if index >= maxCompactRelayEntries {
			return errors.New("compact index out of range")
		}
		if i > 0 && index <= indexes[i-1] {
			return errors.New("compact indexes must be strictly increasing")
		}
	}
	return nil
}
func validatePrefilledTxs(prefilled []compactPrefilledTx, txCount int) error {
	for i, tx := range prefilled {
		if tx.Index >= uint64(txCount) { // #nosec G115 -- caller caps txCount with maxCompactRelayEntries.
			return errors.New("compact prefilled index out of range")
		}
		if len(tx.Tx) == 0 || uint64(len(tx.Tx)) > consensus.MAX_BLOCK_BYTES {
			return errors.New("compact prefilled tx length invalid")
		}
		if i > 0 && tx.Index <= prefilled[i-1].Index {
			return errors.New("compact prefilled indexes must be strictly increasing")
		}
	}
	return nil
}
