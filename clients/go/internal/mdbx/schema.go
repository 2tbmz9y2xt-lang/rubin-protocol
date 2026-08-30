package mdbx

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"math"
)

const (
	MaxMetadataBytes = 1_048_576
	MaxCovenantBytes = 65_536
	MaxBlockBytes    = 68_000_125
)

var errSchema = errors.New("invalid MDBX SchemaV1 bytes")

type DBI struct {
	Name  string
	Rank  uint8
	Flags uint32
}

var schemaDBIs = [...]DBI{{Name: "meta-v1", Rank: 0}, {Name: "utxo-v1", Rank: 1}, {Name: "canonical-v1", Rank: 2}, {Name: "headers-v1", Rank: 3}, {Name: "blocks-v1", Rank: 4}, {Name: "undo-v1", Rank: 5}, {Name: "staged-v1", Rank: 6}}

func SchemaV1DBIs() [7]DBI { return schemaDBIs }

func ValidateDBI(d DBI) error {
	if int(d.Rank) >= len(schemaDBIs) || d != schemaDBIs[d.Rank] {
		return errSchema
	}
	return nil
}

type ConfigV1 struct {
	Lower, Now, Upper, Growth, Shrink uint64
	PageSize, MaxReaders              uint32
}

func (c ConfigV1) valid() bool {
	if !validPageSize(c.PageSize) || c.MaxReaders == 0 || c.MaxReaders > 32_767 {
		return false
	}
	if !c.validGeometry() {
		return false
	}
	return c.Lower <= c.Now && c.Now <= c.Upper && c.Shrink > c.Growth
}

func (c ConfigV1) validGeometry() bool {
	for _, n := range [...]uint64{c.Lower, c.Now, c.Upper, c.Growth, c.Shrink} {
		if n == 0 || n > math.MaxInt64 || n%uint64(c.PageSize) != 0 {
			return false
		}
	}
	return true
}

func validPageSize(n uint32) bool {
	return n >= 256 && n <= 65_536 && n&(n-1) == 0
}

func (c ConfigV1) Encode() ([]byte, error) {
	if !c.valid() {
		return nil, errSchema
	}
	b := make([]byte, 48)
	for i, n := range [...]uint64{c.Lower, c.Now, c.Upper, c.Growth, c.Shrink} {
		binary.BigEndian.PutUint64(b[i*8:], n)
	}
	binary.BigEndian.PutUint32(b[40:], c.PageSize)
	binary.BigEndian.PutUint32(b[44:], c.MaxReaders)
	return b, nil
}

func DecodeConfigV1(b []byte) (ConfigV1, error) {
	if len(b) != 48 {
		return ConfigV1{}, errSchema
	}
	c := ConfigV1{Lower: binary.BigEndian.Uint64(b), Now: binary.BigEndian.Uint64(b[8:]), Upper: binary.BigEndian.Uint64(b[16:]), Growth: binary.BigEndian.Uint64(b[24:]), Shrink: binary.BigEndian.Uint64(b[32:]), PageSize: binary.BigEndian.Uint32(b[40:]), MaxReaders: binary.BigEndian.Uint32(b[44:])}
	if !c.valid() {
		return ConfigV1{}, errSchema
	}
	return c, nil
}

func MetaKey(kind byte, imageID uint64) ([]byte, error) {
	if kind == 0x00 || kind == 0x01 || kind == 0x02 {
		if imageID != 0 {
			return nil, errSchema
		}
		return []byte{kind}, nil
	}
	if kind != 0x10 || imageID == 0 {
		return nil, errSchema
	}
	b := make([]byte, 9)
	b[0] = kind
	binary.BigEndian.PutUint64(b[1:], imageID)
	return b, nil
}

func SchemaVersionValue() []byte { return []byte{0, 0, 0, 1} }

func DecodeSchemaVersionValue(value []byte) error {
	if len(value) != 4 || binary.BigEndian.Uint32(value) != 1 {
		return errSchema
	}
	return nil
}

func LogicalCounterValue(bytes, entries uint64) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, bytes)
	binary.BigEndian.PutUint64(b[8:], entries)
	return b
}

func DecodeLogicalCounterValue(value []byte) (uint64, uint64, error) {
	if len(value) != 16 {
		return 0, 0, errSchema
	}
	return binary.BigEndian.Uint64(value), binary.BigEndian.Uint64(value[8:]), nil
}

func MetaValue(kind byte, value []byte) ([]byte, error) {
	if validateMetaValue(kind, value) != nil {
		return nil, errSchema
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, nil
}

func validateMetaValue(kind byte, value []byte) error {
	switch kind {
	case 0x00:
		return DecodeSchemaVersionValue(value)
	case 0x01:
		_, err := DecodeConfigV1(value)
		return err
	case 0x02:
		if len(value) > MaxMetadataBytes {
			return errSchema
		}
		return nil
	case 0x10:
		_, _, err := DecodeLogicalCounterValue(value)
		return err
	default:
		return errSchema
	}
}

func UTXOKey(imageID uint64, txid [32]byte, vout uint32) ([]byte, error) {
	if imageID == 0 {
		return nil, errSchema
	}
	b := make([]byte, 44)
	binary.BigEndian.PutUint64(b, imageID)
	copy(b[8:], txid[:])
	binary.BigEndian.PutUint32(b[40:], vout)
	return b, nil
}

type UTXOValue struct {
	Value          uint64
	CovenantType   uint16
	CovenantData   []byte
	CreationHeight uint64
	Coinbase       bool
}

func (u UTXOValue) Encode() ([]byte, error) {
	if len(u.CovenantData) > MaxCovenantBytes {
		return nil, errSchema
	}
	b := make([]byte, 0, 25+len(u.CovenantData))
	b = binary.LittleEndian.AppendUint64(b, u.Value)
	b = binary.LittleEndian.AppendUint16(b, u.CovenantType)
	b = appendCompactSize(b, uint64(len(u.CovenantData)))
	b = append(b, u.CovenantData...)
	b = binary.LittleEndian.AppendUint64(b, u.CreationHeight)
	if u.Coinbase {
		return append(b, 1), nil
	}
	return append(b, 0), nil
}

func DecodeUTXOValue(b []byte) (UTXOValue, error) {
	if len(b) < 20 || len(b) > 65_560 {
		return UTXOValue{}, errSchema
	}
	n, used, ok := readCompactSize(b[10:])
	if !ok {
		return UTXOValue{}, errSchema
	}
	off, end := 10+used, 10+used+n
	if end+9 != uint64(len(b)) {
		return UTXOValue{}, errSchema
	}
	coinbase := b[len(b)-1]
	if coinbase > 1 {
		return UTXOValue{}, errSchema
	}
	return UTXOValue{Value: binary.LittleEndian.Uint64(b), CovenantType: binary.LittleEndian.Uint16(b[8:]), CovenantData: append([]byte(nil), b[off:end]...), CreationHeight: binary.LittleEndian.Uint64(b[end:]), Coinbase: coinbase == 1}, nil
}

func HeightKey(imageID, height uint64) ([]byte, error) {
	if imageID == 0 {
		return nil, errSchema
	}
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b, imageID)
	binary.BigEndian.PutUint64(b[8:], height)
	return b, nil
}

func ChainValue(blockHash, parentHash [32]byte, chainwork [40]byte) []byte {
	b := make([]byte, 104)
	copy(b, blockHash[:])
	copy(b[32:], parentHash[:])
	copy(b[64:], chainwork[:])
	return b
}

func HashBoundValue(key [32]byte, value []byte, block bool) ([]byte, error) {
	if (!block && len(value) != 116) || (block && (len(value) < 116 || len(value) > MaxBlockBytes)) || sha3.Sum256(value[:min(len(value), 116)]) != key {
		return nil, errSchema
	}
	return append([]byte(nil), value...), nil
}

func UndoManifestKey(blockHash [32]byte) []byte {
	return append(append([]byte(nil), blockHash[:]...), 0)
}

func UndoEntryKey(blockHash, spentTxid [32]byte, txIndex, inputIndex, spentVout uint32) []byte {
	b := make([]byte, 77)
	copy(b, blockHash[:])
	b[32] = 1
	binary.BigEndian.PutUint32(b[33:], txIndex)
	binary.BigEndian.PutUint32(b[37:], inputIndex)
	copy(b[41:], spentTxid[:])
	binary.BigEndian.PutUint32(b[73:], spentVout)
	return b
}

func UndoManifestValue(height uint64, generated [16]byte, txCount, spentCount uint32) []byte {
	b := make([]byte, 33)
	b[0] = 1
	binary.BigEndian.PutUint64(b[1:], height)
	copy(b[9:], generated[:])
	binary.BigEndian.PutUint32(b[25:], txCount)
	binary.BigEndian.PutUint32(b[29:], spentCount)
	return b
}

func ValidateRow(d DBI, key, value []byte) error {
	if ValidateDBI(d) != nil {
		return errSchema
	}
	if !validKey(d.Rank, key) {
		return errSchema
	}
	return validateValue(d.Rank, key, value)
}

func validateValue(rank uint8, key, value []byte) error {
	switch rank {
	case 0:
		_, err := MetaValue(key[0], value)
		return err
	case 1:
		_, err := DecodeUTXOValue(value)
		return err
	case 2, 6:
		return validateChainValue(value)
	case 3:
		var hash [32]byte
		copy(hash[:], key)
		_, err := HashBoundValue(hash, value, false)
		return err
	case 4:
		var hash [32]byte
		copy(hash[:], key)
		_, err := HashBoundValue(hash, value, true)
		return err
	case 5:
		return validateUndoValue(key, value)
	default:
		return errSchema
	}
}

func validateChainValue(value []byte) error {
	if len(value) != 104 {
		return errSchema
	}
	return nil
}

func validateUndoValue(key, value []byte) error {
	if key[32] == 0 {
		if len(value) != 33 || value[0] != 1 {
			return errSchema
		}
		return nil
	}
	_, err := DecodeUTXOValue(value)
	return err
}

func validKey(rank uint8, key []byte) bool {
	switch rank {
	case 0:
		return validMetaKey(key)
	case 1:
		return validImageKey(key, 44)
	case 2, 6:
		return validImageKey(key, 16)
	case 3, 4:
		return len(key) == 32
	case 5:
		return validUndoKey(key)
	default:
		return false
	}
}

func validMetaKey(key []byte) bool {
	if len(key) == 1 {
		return key[0] <= 2
	}
	return len(key) == 9 && key[0] == 0x10 && binary.BigEndian.Uint64(key[1:]) != 0
}

func validImageKey(key []byte, width int) bool {
	return len(key) == width && binary.BigEndian.Uint64(key) != 0
}

func validUndoKey(key []byte) bool {
	return len(key) == 33 && key[32] == 0 || len(key) == 77 && key[32] == 1
}

func appendCompactSize(b []byte, n uint64) []byte {
	switch {
	case n < 253:
		return append(b, byte(n))
	case n <= math.MaxUint16:
		b = append(b, 0xfd)
		return binary.LittleEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xfe)
		return append(b, binary.LittleEndian.AppendUint64(nil, n)[:4]...)
	}
}

func readCompactSize(b []byte) (uint64, uint64, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, false
		}
		n := uint64(binary.LittleEndian.Uint16(b[1:]))
		return n, 3, n >= 253
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, false
		}
		n := uint64(binary.LittleEndian.Uint32(b[1:]))
		return n, 5, n > math.MaxUint16
	case 0xff:
		return 0, 0, false
	default:
		return uint64(b[0]), 1, true
	}
}
