package node

import (
	"bytes"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type BlockUndo struct {
	BlockHeight              uint64
	PreviousAlreadyGenerated consensus.Uint128
	Txs                      []TxUndo
}

type TxUndo struct {
	Spent []SpentUndo
}

type SpentUndo struct {
	Outpoint consensus.Outpoint
	Entry    consensus.UtxoEntry
}

type ChainStateDisconnectSummary struct {
	DisconnectedHeight uint64
	BlockHash          [32]byte
	NewHeight          uint64
	NewTipHash         [32]byte
	HasTip             bool
	AlreadyGenerated   consensus.Uint128
	UtxoCount          uint64
}

type blockUndoDisk struct {
	BlockHeight              uint64       `json:"block_height"`
	PreviousAlreadyGenerated uint64       `json:"previous_already_generated"`
	Txs                      []txUndoDisk `json:"txs"`
}

type blockUndoDiskV2 struct {
	BlockHeight              uint64       `json:"block_height"`
	PreviousAlreadyGenerated string       `json:"previous_already_generated"`
	Txs                      []txUndoDisk `json:"txs"`
}

type blockUndoDiskRaw struct {
	BlockHeight              uint64          `json:"block_height"`
	PreviousAlreadyGenerated json.RawMessage `json:"previous_already_generated"`
	Txs                      []txUndoDisk    `json:"txs"`
}

type validatedBlockUndoDisk struct {
	blockHeight              uint64
	previousAlreadyGenerated consensus.Uint128
	txs                      []txUndoDisk
}

type txUndoDisk struct {
	Spent []spentUndoDisk `json:"spent"`
}

type spentUndoDisk struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantData      string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

var errUndoPayloadNotCanonical = errors.New("decode undo: payload is not the canonical encoding")

func buildBlockUndo(prevState *ChainState, pb *consensus.ParsedBlock, blockHeight uint64) (*BlockUndo, error) {
	if prevState == nil {
		return nil, errors.New("nil previous chainstate")
	}
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txs) != len(pb.Txids) {
		return nil, errors.New("parsed block txid length mismatch")
	}

	work := copyUtxoSet(prevState.Utxos)
	txUndos, err := buildTxUndos(work, pb, blockHeight)
	if err != nil {
		return nil, err
	}
	return &BlockUndo{
		BlockHeight:              blockHeight,
		PreviousAlreadyGenerated: prevState.AlreadyGenerated,
		Txs:                      txUndos,
	}, nil
}

// buildTxUndos iterates transactions and builds undo entries.
func buildTxUndos(work map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, blockHeight uint64) ([]TxUndo, error) {
	txUndos := make([]TxUndo, len(pb.Txs))
	for i := 0; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		if tx == nil {
			return nil, fmt.Errorf("nil tx at index %d", i)
		}
		spent, err := spendUndoInputs(work, tx, i)
		if err != nil {
			return nil, err
		}
		addUndoCreatedOutputs(work, pb.Txids[i], tx, blockHeight, i == 0)
		txUndos[i] = TxUndo{Spent: spent}
	}
	return txUndos, nil
}

func spendUndoInputs(work map[consensus.Outpoint]consensus.UtxoEntry, tx *consensus.Tx, txIndex int) ([]SpentUndo, error) {
	spent := make([]SpentUndo, 0, len(tx.Inputs))
	if txIndex == 0 {
		return spent, nil
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := work[op]
		if !ok {
			return nil, fmt.Errorf("undo missing utxo for %x:%d", op.Txid, op.Vout)
		}
		spent = append(spent, SpentUndo{Outpoint: op, Entry: copyUtxoEntry(entry)})
		delete(work, op)
	}
	return spent, nil
}

func addUndoCreatedOutputs(work map[consensus.Outpoint]consensus.UtxoEntry, txid [32]byte, tx *consensus.Tx, blockHeight uint64, coinbase bool) {
	for outputIndex, out := range tx.Outputs {
		if out.CovenantType != consensus.COV_TYPE_ANCHOR && out.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			work[consensus.Outpoint{Txid: txid, Vout: uint32(outputIndex)}] = consensus.UtxoEntry{
				Value:             out.Value,
				CovenantType:      out.CovenantType,
				CovenantData:      append([]byte(nil), out.CovenantData...),
				CreationHeight:    blockHeight,
				CreatedByCoinbase: coinbase,
			}
		}
	}
}

func (s *ChainState) DisconnectBlock(blockBytes []byte, undo *BlockUndo) (*ChainStateDisconnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.HasTip {
		return nil, errors.New("chainstate has no tip")
	}
	if undo == nil {
		return nil, errors.New("nil block undo")
	}

	pb, blockHash, err := parseAndValidateDisconnectBlock(blockBytes, undo, s.TipHash, s.Height)
	if err != nil {
		return nil, err
	}
	return s.disconnectParsedBlockLocked(pb, blockHash, undo)
}

// disconnectVerifiedStoredBlock mirrors DisconnectBlock after the caller has
// retained the one parsed, hash-verified stored block. It deliberately keeps
// the public method's lock and validation order while sharing the mutation
// path below, so a prepared disconnect does not parse the block a second time.
func (s *ChainState) disconnectVerifiedStoredBlock(storedBlock verifiedStoredBlock, undo *BlockUndo) (*ChainStateDisconnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.HasTip {
		return nil, errors.New("chainstate has no tip")
	}
	if undo == nil {
		return nil, errors.New("nil block undo")
	}
	pb, err := validateVerifiedDisconnectStoredBlock(storedBlock, undo, s.TipHash, s.Height)
	if err != nil {
		return nil, err
	}
	return s.disconnectParsedBlockLocked(pb, storedBlock.lookupHash, undo)
}

// disconnectParsedBlockLocked performs the common post-parse disconnect
// transition. Callers hold admissionMu and mu and have checked their distinct
// raw or retained-block preconditions before entering this method.
func (s *ChainState) disconnectParsedBlockLocked(pb *consensus.ParsedBlock, blockHash [32]byte, undo *BlockUndo) (*ChainStateDisconnectSummary, error) {
	work := copyUtxoSet(s.Utxos)
	if err := applyDisconnectUndo(work, pb, undo); err != nil {
		return nil, err
	}

	s.Utxos = work
	s.AlreadyGenerated = undo.PreviousAlreadyGenerated
	if s.Height == 0 {
		s.HasTip = false
		s.Height = 0
		s.TipHash = [32]byte{}
	} else {
		s.Height--
		s.TipHash = pb.Header.PrevBlockHash
		s.HasTip = true
	}

	return &ChainStateDisconnectSummary{
		DisconnectedHeight: undo.BlockHeight,
		BlockHash:          blockHash,
		NewHeight:          s.Height,
		NewTipHash:         s.TipHash,
		HasTip:             s.HasTip,
		AlreadyGenerated:   s.AlreadyGenerated,
		UtxoCount:          uint64(len(s.Utxos)),
	}, nil
}

func validateVerifiedDisconnectStoredBlock(storedBlock verifiedStoredBlock, undo *BlockUndo, tipHash [32]byte, height uint64) (*consensus.ParsedBlock, error) {
	if storedBlock.parsed == nil {
		return nil, errors.New("nil verified stored block")
	}
	pb := storedBlock.parsed
	if len(pb.Txs) != len(pb.Txids) {
		return nil, errors.New("parsed block txid length mismatch")
	}
	if len(undo.Txs) != len(pb.Txs) {
		return nil, errors.New("undo tx count mismatch")
	}
	if tipHash != storedBlock.lookupHash {
		return nil, errors.New("disconnect block is not current tip")
	}
	if height != undo.BlockHeight {
		return nil, fmt.Errorf("disconnect height mismatch: chainstate=%d undo=%d", height, undo.BlockHeight)
	}
	return pb, nil
}

// parseAndValidateDisconnectBlock parses block bytes and validates undo against chain state.
func parseAndValidateDisconnectBlock(blockBytes []byte, undo *BlockUndo, tipHash [32]byte, height uint64) (*consensus.ParsedBlock, [32]byte, error) {
	pb, blockHash, err := parseDisconnectBlock(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(undo.Txs) != len(pb.Txs) {
		return nil, [32]byte{}, errors.New("undo tx count mismatch")
	}
	if tipHash != blockHash {
		return nil, [32]byte{}, errors.New("disconnect block is not current tip")
	}
	if height != undo.BlockHeight {
		return nil, [32]byte{}, fmt.Errorf("disconnect height mismatch: chainstate=%d undo=%d", height, undo.BlockHeight)
	}
	return pb, blockHash, nil
}

func parseDisconnectBlock(blockBytes []byte) (*consensus.ParsedBlock, [32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(pb.Txs) != len(pb.Txids) {
		return nil, [32]byte{}, errors.New("parsed block txid length mismatch")
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return pb, blockHash, nil
}

func applyDisconnectUndo(work map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, undo *BlockUndo) error {
	for txIndex := len(pb.Txs) - 1; txIndex >= 0; txIndex-- {
		for outputIndex, out := range pb.Txs[txIndex].Outputs {
			if out.CovenantType != consensus.COV_TYPE_ANCHOR && out.CovenantType != consensus.COV_TYPE_DA_COMMIT {
				delete(work, consensus.Outpoint{Txid: pb.Txids[txIndex], Vout: uint32(outputIndex)})
			}
		}
		for _, item := range undo.Txs[txIndex].Spent {
			if _, exists := work[item.Outpoint]; exists {
				return fmt.Errorf("undo restore collision for %x:%d", item.Outpoint.Txid, item.Outpoint.Vout)
			}
			work[item.Outpoint] = copyUtxoEntry(item.Entry)
		}
	}
	return nil
}

// marshalBlockUndo produces the canonical v1 undo payload for pinned vectors
// and legacy-v1 writer tests. Reads use unmarshalBlockUndo; new records use v2.
func marshalBlockUndo(undo *BlockUndo) ([]byte, error) {
	disk, err := blockUndoToDisk(undo)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return nil, fmt.Errorf("encode undo: %w", err)
	}
	return raw, nil
}

func marshalBlockUndoV2(undo *BlockUndo) ([]byte, error) {
	disk, err := blockUndoToDiskV2(undo)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return nil, fmt.Errorf("encode undo: %w", err)
	}
	return raw, nil
}

// unmarshalBlockUndo checks shape, supply, and scalar domains before conversion,
// preserving error priority. Rust twin: `unmarshal_block_undo`.
func unmarshalBlockUndo(raw []byte) (*BlockUndo, error) {
	disk, err := decodeValidatedBlockUndoV1(raw)
	if err != nil {
		return nil, err
	}
	return blockUndoFromValidatedDisk(disk)
}

func unmarshalBlockUndoV2(raw []byte) (*BlockUndo, error) {
	disk, err := decodeValidatedBlockUndoV2(raw)
	if err != nil {
		return nil, err
	}
	return blockUndoFromValidatedDisk(disk)
}

func decodeValidatedBlockUndoV1(raw []byte) (validatedBlockUndoDisk, error) {
	disk, err := decodeBlockUndoDiskV1(raw)
	if err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if err := checkUndoDiskCanonicalFields(disk); err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if ok, err := canonicalBlockUndoMatches(raw, disk); err != nil {
		return validatedBlockUndoDisk{}, err
	} else if !ok {
		return validatedBlockUndoDisk{}, errUndoPayloadNotCanonical
	}
	return validatedBlockUndoDisk{
		blockHeight:              disk.BlockHeight,
		previousAlreadyGenerated: consensus.Uint128FromU64(disk.PreviousAlreadyGenerated),
		txs:                      disk.Txs,
	}, nil
}

func decodeValidatedBlockUndoV2(raw []byte) (validatedBlockUndoDisk, error) {
	disk, supply, err := decodeBlockUndoDiskV2(raw)
	if err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if err := checkUndoDiskCanonicalFieldsV2(disk); err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if ok, err := canonicalBlockUndoMatches(raw, disk); err != nil {
		return validatedBlockUndoDisk{}, err
	} else if !ok {
		return validatedBlockUndoDisk{}, errUndoPayloadNotCanonical
	}
	return validatedBlockUndoDisk{
		blockHeight:              disk.BlockHeight,
		previousAlreadyGenerated: supply,
		txs:                      disk.Txs,
	}, nil
}

func canonicalBlockUndoMatches(raw []byte, disk any) (bool, error) {
	canonical, err := json.Marshal(disk)
	if err != nil {
		return false, fmt.Errorf("encode undo: %w", err)
	}
	return bytes.Equal(canonical, raw), nil
}

func decodeBlockUndoDiskV1(raw []byte) (blockUndoDisk, error) {
	var supplyToken json.RawMessage
	var scalarNull bool
	if err := validateBlockUndoFieldSet(raw, &supplyToken, &scalarNull); err != nil {
		return blockUndoDisk{}, err
	}
	supplyRaw := bytes.TrimSpace(supplyToken)
	var supply uint64
	if len(supplyRaw) == 0 || bytes.Equal(supplyRaw, []byte("null")) ||
		json.Unmarshal(supplyRaw, &supply) != nil || string(supplyRaw) != strconv.FormatUint(supply, 10) {
		return blockUndoDisk{}, errors.New("decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64")
	}
	if scalarNull {
		return blockUndoDisk{}, errUndoPayloadNotCanonical
	}
	decoded, err := decodeBlockUndoTyped(raw)
	if err != nil {
		return blockUndoDisk{}, err
	}
	return blockUndoDisk{
		BlockHeight:              decoded.BlockHeight,
		PreviousAlreadyGenerated: supply,
		Txs:                      decoded.Txs,
	}, nil
}

func decodeBlockUndoDiskV2(raw []byte) (blockUndoDiskV2, consensus.Uint128, error) {
	var supplyToken json.RawMessage
	var scalarNull bool
	if err := validateBlockUndoFieldSet(raw, &supplyToken, &scalarNull); err != nil {
		return blockUndoDiskV2{}, consensus.Uint128{}, err
	}
	supplyText, supply, err := parseBlockUndoV2Supply(supplyToken)
	if err != nil {
		return blockUndoDiskV2{}, consensus.Uint128{}, err
	}
	if scalarNull {
		return blockUndoDiskV2{}, consensus.Uint128{}, errUndoPayloadNotCanonical
	}
	decoded, err := decodeBlockUndoTyped(raw)
	if err != nil {
		return blockUndoDiskV2{}, consensus.Uint128{}, err
	}
	return blockUndoDiskV2{
		BlockHeight:              decoded.BlockHeight,
		PreviousAlreadyGenerated: supplyText,
		Txs:                      decoded.Txs,
	}, supply, nil
}

func parseBlockUndoV2Supply(token json.RawMessage) (string, consensus.Uint128, error) {
	raw := bytes.TrimSpace(token)
	var text string
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) ||
		json.Unmarshal(raw, &text) != nil || string(raw) != `"`+text+`"` {
		return "", consensus.Uint128{}, errors.New("decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128")
	}
	value, err := consensus.ParseUint128Decimal(text)
	if err != nil {
		return "", consensus.Uint128{}, errors.New("decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128")
	}
	return text, value, nil
}

func decodeBlockUndoTyped(raw []byte) (blockUndoDiskRaw, error) {
	var decoded blockUndoDiskRaw
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return blockUndoDiskRaw{}, errUndoPayloadNotCanonical
	}
	return decoded, nil
}

// validateBlockUndoFieldSet proves nested shape before supply and scalar conversion.
func validateBlockUndoFieldSet(raw []byte, supplyToken *json.RawMessage, scalarNull *bool) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if !startUndoObject(decoder) {
		return errUndoPayloadNotCanonical
	}
	var seen uint8
	for decoder.More() {
		key, ok := readUndoKey(decoder)
		field := blockUndoField(key, seen)
		if !validUndoField(ok, field) {
			return errUndoPayloadNotCanonical
		}
		if err := readBlockUndoField(decoder, field, supplyToken, scalarNull); err != nil {
			return err
		}
		seen |= field
	}
	if !finishUndoContainer(decoder, '}') || seen != (1<<3)-1 {
		return errUndoPayloadNotCanonical
	}
	return nil
}

func readBlockUndoField(decoder *json.Decoder, field uint8, supplyToken *json.RawMessage, scalarNull *bool) error {
	switch field {
	case 1 << 0:
		value, ok := readUndoRawValue(decoder)
		if !ok {
			return errUndoPayloadNotCanonical
		}
		*scalarNull = *scalarNull || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
	case 1 << 1:
		if decoder.Decode(supplyToken) != nil {
			return errUndoPayloadNotCanonical
		}
	case 1 << 2:
		return validateTxUndoArray(decoder, scalarNull)
	}
	return nil
}

func blockUndoField(key string, seen uint8) uint8 {
	for index, name := range [...]string{"block_height", "previous_already_generated", "txs"} {
		if key == name {
			field := uint8(1 << index)
			if seen&field == 0 {
				return field
			}
		}
	}
	return 0
}

func validateTxUndoArray(decoder *json.Decoder, scalarNull *bool) error {
	return validateUndoArray(decoder, scalarNull, validateTxUndoFieldSet)
}

func validateTxUndoFieldSet(decoder *json.Decoder, scalarNull *bool) error {
	if !startUndoObject(decoder) {
		return errUndoPayloadNotCanonical
	}
	if !decoder.More() {
		return errUndoPayloadNotCanonical
	}
	key, ok := readUndoKey(decoder)
	if !ok || key != "spent" {
		return errUndoPayloadNotCanonical
	}
	if err := validateSpentUndoArray(decoder, scalarNull); err != nil {
		return err
	}
	if decoder.More() {
		return errUndoPayloadNotCanonical
	}
	if !closeUndoContainer(decoder, '}') {
		return errUndoPayloadNotCanonical
	}
	return nil
}

func validateSpentUndoArray(decoder *json.Decoder, scalarNull *bool) error {
	return validateUndoArray(decoder, scalarNull, validateSpentUndoFieldSet)
}

func validateUndoArray(decoder *json.Decoder, scalarNull *bool, validate func(*json.Decoder, *bool) error) error {
	start, err := decoder.Token()
	if err != nil || start != json.Delim('[') {
		return errUndoPayloadNotCanonical
	}
	for decoder.More() {
		if err := validate(decoder, scalarNull); err != nil {
			return err
		}
	}
	if !closeUndoContainer(decoder, ']') {
		return errUndoPayloadNotCanonical
	}
	return nil
}

func validateSpentUndoFieldSet(decoder *json.Decoder, scalarNull *bool) error {
	if !startUndoObject(decoder) {
		return errUndoPayloadNotCanonical
	}
	var seen uint8
	for decoder.More() {
		key, ok := readUndoKey(decoder)
		field := spentUndoField(key, seen)
		if !validUndoField(ok, field) {
			return errUndoPayloadNotCanonical
		}
		value, ok := readUndoRawValue(decoder)
		if !ok {
			return errUndoPayloadNotCanonical
		}
		seen |= field
		*scalarNull = *scalarNull || bytes.Equal(bytes.TrimSpace(value), []byte("null"))
	}
	if !closeUndoContainer(decoder, '}') || seen != (1<<7)-1 {
		return errUndoPayloadNotCanonical
	}
	return nil
}

func spentUndoField(key string, seen uint8) uint8 {
	fields := [...]string{"txid", "vout", "value", "covenant_type", "covenant_data", "creation_height", "created_by_coinbase"}
	for index, name := range fields {
		if key == name {
			field := uint8(1 << index)
			if seen&field == 0 {
				return field
			}
		}
	}
	return 0
}

func validUndoField(ok bool, field uint8) bool { return ok && field != 0 }

func startUndoObject(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	return err == nil && token == json.Delim('{')
}

func readUndoKey(decoder *json.Decoder) (string, bool) {
	token, err := decoder.Token()
	if err != nil {
		return "", false
	}
	key, ok := token.(string)
	return key, ok
}

func readUndoRawValue(decoder *json.Decoder) (json.RawMessage, bool) {
	var value json.RawMessage
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	return value, true
}

func closeUndoContainer(decoder *json.Decoder, want json.Delim) bool {
	end, err := decoder.Token()
	return err == nil && end == want
}

func undoDecoderEOF(decoder *json.Decoder) bool {
	_, err := decoder.Token()
	return err == io.EOF
}

func finishUndoContainer(decoder *json.Decoder, want json.Delim) bool {
	return closeUndoContainer(decoder, want) && undoDecoderEOF(decoder)
}

// checkUndoDiskCanonicalFields covers the remaining domain property the
// disk-level byte comparison is blind to. Container shape
// ran before supply validation; remaining scalar/null conversion ran after it.
// Hex strings pass through the disk struct verbatim, so an uppercase txid
// survives the round trip, and two spellings of one undo must not
// both be canonical when a checksum is bound to the bytes. Both used to be
// enforced implicitly by re-encoding the CONVERTED value; stating them is what
// lets the decision precede conversion.
func checkUndoDiskCanonicalFields(disk blockUndoDisk) error {
	return checkUndoTxsCanonicalFields(disk.Txs)
}

func checkUndoDiskCanonicalFieldsV2(disk blockUndoDiskV2) error {
	return checkUndoTxsCanonicalFields(disk.Txs)
}

func checkUndoTxsCanonicalFields(txs []txUndoDisk) error {
	if txs == nil {
		return errUndoPayloadNotCanonical
	}
	for txIndex, txUndo := range txs {
		if txUndo.Spent == nil {
			return errUndoPayloadNotCanonical
		}
		for spentIndex, input := range txUndo.Spent {
			if !validCanonicalHashHex(input.Txid) || !validLowercaseHex(input.CovenantData) {
				return fmt.Errorf(
					"decode undo: txs[%d].spent[%d] txid/covenant_data must be lowercase hex",
					txIndex, spentIndex)
			}
		}
	}
	return nil
}

// validLowercaseHex: an even number of lowercase hex digits, any length.
func validLowercaseHex(value string) bool {
	if len(value)%2 != 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func blockUndoToDisk(undo *BlockUndo) (blockUndoDisk, error) {
	if undo == nil {
		return blockUndoDisk{}, errors.New("nil block undo")
	}
	if undo.PreviousAlreadyGenerated.Hi != 0 {
		return blockUndoDisk{}, errors.New("encode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64")
	}
	txs := blockUndoTxsToDisk(undo.Txs)
	return blockUndoDisk{
		BlockHeight:              undo.BlockHeight,
		PreviousAlreadyGenerated: undo.PreviousAlreadyGenerated.Lo,
		Txs:                      txs,
	}, nil
}

func blockUndoToDiskV2(undo *BlockUndo) (blockUndoDiskV2, error) {
	if undo == nil {
		return blockUndoDiskV2{}, errors.New("nil block undo")
	}
	return blockUndoDiskV2{
		BlockHeight:              undo.BlockHeight,
		PreviousAlreadyGenerated: undo.PreviousAlreadyGenerated.String(),
		Txs:                      blockUndoTxsToDisk(undo.Txs),
	}, nil
}

func blockUndoTxsToDisk(src []TxUndo) []txUndoDisk {
	txs := make([]txUndoDisk, 0, len(src))
	for _, txUndo := range src {
		spent := make([]spentUndoDisk, 0, len(txUndo.Spent))
		for _, input := range txUndo.Spent {
			spent = append(spent, spentUndoDisk{
				Txid:              hex.EncodeToString(input.Outpoint.Txid[:]),
				Vout:              input.Outpoint.Vout,
				Value:             input.Entry.Value,
				CovenantType:      input.Entry.CovenantType,
				CovenantData:      hex.EncodeToString(input.Entry.CovenantData),
				CreationHeight:    input.Entry.CreationHeight,
				CreatedByCoinbase: input.Entry.CreatedByCoinbase,
			})
		}
		txs = append(txs, txUndoDisk{Spent: spent})
	}
	return txs
}

func blockUndoFromDisk(disk blockUndoDisk) (*BlockUndo, error) {
	return blockUndoFromParts(disk.BlockHeight, consensus.Uint128FromU64(disk.PreviousAlreadyGenerated), disk.Txs)
}

func blockUndoFromValidatedDisk(disk validatedBlockUndoDisk) (*BlockUndo, error) {
	return blockUndoFromParts(disk.blockHeight, disk.previousAlreadyGenerated, disk.txs)
}

func validatedBlockUndoMatches(disk validatedBlockUndoDisk, candidate *BlockUndo) bool {
	return validatedBlockUndoHeaderMatches(disk, candidate) &&
		slices.EqualFunc(disk.txs, candidate.Txs, validatedTxUndoMatches)
}

func validatedBlockUndoHeaderMatches(disk validatedBlockUndoDisk, candidate *BlockUndo) bool {
	return candidate != nil &&
		disk.blockHeight == candidate.BlockHeight &&
		disk.previousAlreadyGenerated == candidate.PreviousAlreadyGenerated
}

func validatedTxUndoMatches(disk txUndoDisk, candidate TxUndo) bool {
	return slices.EqualFunc(disk.Spent, candidate.Spent, validatedSpentUndoMatches)
}

func validatedSpentUndoMatches(disk spentUndoDisk, candidate SpentUndo) bool {
	return disk.Vout == candidate.Outpoint.Vout &&
		disk.Value == candidate.Entry.Value &&
		disk.CovenantType == candidate.Entry.CovenantType &&
		disk.CreationHeight == candidate.Entry.CreationHeight &&
		disk.CreatedByCoinbase == candidate.Entry.CreatedByCoinbase &&
		lowercaseHexMatchesBytes(disk.Txid, candidate.Outpoint.Txid[:]) &&
		lowercaseHexMatchesBytes(disk.CovenantData, candidate.Entry.CovenantData)
}

func lowercaseHexMatchesBytes(value string, bytes []byte) bool {
	if len(value) != len(bytes)*2 {
		return false
	}
	const hexDigits = "0123456789abcdef"
	for index, valueByte := range bytes {
		if value[index*2] != hexDigits[valueByte>>4] || value[index*2+1] != hexDigits[valueByte&0x0f] {
			return false
		}
	}
	return true
}

func blockUndoFromParts(blockHeight uint64, previousAlreadyGenerated consensus.Uint128, diskTxs []txUndoDisk) (*BlockUndo, error) {
	txs := make([]TxUndo, 0, len(diskTxs))
	for txIndex, txUndo := range diskTxs {
		spent := make([]SpentUndo, 0, len(txUndo.Spent))
		for spentIndex, input := range txUndo.Spent {
			txid, err := parseHex32(fmt.Sprintf("undo[%d].spent[%d].txid", txIndex, spentIndex), input.Txid)
			if err != nil {
				return nil, err
			}
			covData, err := parseHex(fmt.Sprintf("undo[%d].spent[%d].covenant_data", txIndex, spentIndex), input.CovenantData)
			if err != nil {
				return nil, err
			}
			spent = append(spent, SpentUndo{
				Outpoint: consensus.Outpoint{
					Txid: txid,
					Vout: input.Vout,
				},
				Entry: consensus.UtxoEntry{
					Value:             input.Value,
					CovenantType:      input.CovenantType,
					CovenantData:      covData,
					CreationHeight:    input.CreationHeight,
					CreatedByCoinbase: input.CreatedByCoinbase,
				},
			})
		}
		txs = append(txs, TxUndo{Spent: spent})
	}
	return &BlockUndo{
		BlockHeight:              blockHeight,
		PreviousAlreadyGenerated: previousAlreadyGenerated,
		Txs:                      txs,
	}, nil
}

// ---------------------------------------------------------------------------
// undo_envelope_v1/v2
//
// The stored undo record is one compact JSON object binding the canonical
// payload bytes to the block hash they were built for:
//
//	{"version":2,"block_hash":"<64hex>","payload_b64":"<b64>","checksum":"<64hex>"}\n
//
// The checksum domain is RUBIN_BLOCK_UNDO_V1 for v1 and RUBIN_BLOCK_UNDO_V2
// for v2. In both versions the preimage appends block_hash[32],
// uint64_be(len(payload)), then payload. The length prefix keeps the framing
// injective. New records use v2; valid existing v1 records remain readable and
// are never eagerly rewritten.
// The trailing LF counts against the read bound but is NOT in the preimage.
//
// The v1 byte contract remains pinned by conformance/fixtures/protocol/
// undo_integrity_v1.json.
//
// Claim boundary: this detects accidental, torn, misnamed and parse-valid local
// corruption before an undo is used. It is NOT authentication — a local actor
// able to rewrite the payload can recompute the checksum. There is no secret
// here and none is claimed.
// ---------------------------------------------------------------------------

// ErrUndoIntegrity is the stable identity behind the envelope, version, hash,
// base64 and checksum rejection classes named in the issue's error_contract:
// errors.Is(err, ErrUndoIntegrity) holds for all of them, and err.Error() is the
// exact cross-client message the Rust client returns verbatim from get_undo.
//
// The payload-conversion class is deliberately OUTSIDE this identity. A record
// that clears the checksum is intact on disk; a failure past that point is a
// schema fault, not a storage-integrity fault, and the contract does not put it
// under the prefix.
var ErrUndoIntegrity = errors.New("UNDO_INTEGRITY")

var (
	// Pinned cross-client messages. Rust returns these same strings.
	// Deliberately no repair command: this build ships no --reindex.
	errUndoLegacyRecord      = fmt.Errorf("%w: legacy/unversioned undo; pre-devnet datadir reset and full resync required", ErrUndoIntegrity)
	errUndoBlockHashMismatch = fmt.Errorf("%w: block hash mismatch", ErrUndoIntegrity)
	errUndoChecksumMismatch  = fmt.Errorf("%w: checksum mismatch", ErrUndoIntegrity)
)

// The canonical envelope's byte layout is fully determined by these fixed
// segments plus the two 64-character hex fields, so the reader validates the
// layout by index arithmetic instead of decoding JSON. That is what keeps peak
// memory near the file size: no value is materialized on the accept path and
// payload_b64 is a SLICE of the caller's buffer, never a copy. Rust twin:
// UNDO_ENVELOPE_PREFIX and friends in crates/rubin-node/src/undo.rs.
const (
	undoEnvelopePrefixV1    = `{"version":1,"block_hash":"`
	undoEnvelopePrefixV2    = `{"version":2,"block_hash":"`
	undoEnvelopePayloadSep  = `","payload_b64":"`
	undoEnvelopeChecksumSep = `","checksum":"`
	undoEnvelopeSuffix      = "\"}\n"
)

const (
	undoEnvelopeVersionV1 = 1
	undoEnvelopeVersion   = 2
	undoEnvelopeDomainV1  = "RUBIN_BLOCK_UNDO_V1"
	undoEnvelopeDomainV2  = "RUBIN_BLOCK_UNDO_V2"
	undoHashHexLen        = 64

	// undoEnvelopeFrameBytes is the envelope minus the base64 body. Derived from
	// the segments above rather than written down, so a format edit cannot leave
	// the bound behind. Cross-checked against a real envelope by
	// TestUndoEnvelopeBoundDerivation.
	undoEnvelopeFrameBytes = len(undoEnvelopePrefixV2) + undoHashHexLen +
		len(undoEnvelopePayloadSep) + len(undoEnvelopeChecksumSep) +
		undoHashHexLen + len(undoEnvelopeSuffix)

	// undoPayloadMaxBytes is the decoded-payload ceiling, run BACKWARDS from the
	// unchanged undo class bound: a payload of n bytes occupies ceil(n/3)*4
	// base64 characters, so the largest n whose complete envelope still fits is
	// 3*floor((undoFileMaxBytes - frame) / 4). The floor MUST come before the
	// multiply — (bound-frame)*3/4 overshoots by two bytes and would let
	// PutUndo emit a 2_000_000_001-byte envelope that GetUndo then refuses.
	//
	// The envelope reuses undoFileMaxBytes itself as the outer read/save bound
	// rather than the raw derivation (~2.67e9): every storage-read bound in this
	// package must stay below 2^31-2 because readAllCapped probes with
	// maxBytes+1, and 2e9 already admits the consensus-reachable envelope
	// maximum (1_371_851_881 bytes) with ~1.46x margin. Revision conditions are
	// recorded in the issue's bound-audit amendment.
	undoPayloadMaxBytes = 3 * ((undoFileMaxBytes - undoEnvelopeFrameBytes) / 4)
)

// undoEnvelopeDisk is the writer's shape; the reader never decodes into it.
// Field ORDER is part of the format: encoding/json emits struct fields in
// declaration order and serde does the same, which is what makes the two
// clients' bytes identical — and what the segment constants above mirror.
type undoEnvelopeDisk struct {
	Version    uint32 `json:"version"`
	BlockHash  string `json:"block_hash"`
	PayloadB64 string `json:"payload_b64"`
	Checksum   string `json:"checksum"`
}

// undoEnvelopeChecksum STREAMS the preimage into the hash rather than
// materializing it. Concatenating first would copy the whole payload — a second
// payload-sized buffer on a path whose entire point is bounded memory before the
// integrity decision. hash.Hash.Write never returns an error. Rust twin:
// `undo_envelope_checksum`, which streams the same four segments.
func undoEnvelopeChecksum(blockHash [32]byte, payload []byte) [32]byte {
	return undoEnvelopeChecksumForVersion(undoEnvelopeVersionV1, blockHash, payload)
}

func undoEnvelopeChecksumForVersion(version uint32, blockHash [32]byte, payload []byte) [32]byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	hasher := sha3.New256()
	domain := undoEnvelopeDomainV2
	if version == undoEnvelopeVersionV1 {
		domain = undoEnvelopeDomainV1
	}
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write(blockHash[:])
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(payload)
	var out [32]byte
	hasher.Sum(out[:0])
	return out
}

// marshalUndoEnvelope also enforces the SAVE-side bounds, so the node can never
// persist a record it would refuse to read back. Both ends test the same two
// quantities — decoded payload and complete envelope — which is what makes the
// refusal boundary byte-symmetric rather than off by a rounding step.
func marshalUndoEnvelope(blockHash [32]byte, undo *BlockUndo) ([]byte, error) {
	return marshalUndoEnvelopeVersion(undoEnvelopeVersion, blockHash, undo)
}

func marshalUndoEnvelopeV1(blockHash [32]byte, undo *BlockUndo) ([]byte, error) {
	return marshalUndoEnvelopeVersion(undoEnvelopeVersionV1, blockHash, undo)
}

func marshalUndoEnvelopeVersion(version uint32, blockHash [32]byte, undo *BlockUndo) ([]byte, error) {
	var payload []byte
	var err error
	if version == undoEnvelopeVersionV1 {
		payload, err = marshalBlockUndo(undo)
	} else {
		payload, err = marshalBlockUndoV2(undo)
	}
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > int64(undoPayloadMaxBytes) {
		return nil, fmt.Errorf("refusing to save undo: payload is %d bytes, class bound %d: %w",
			len(payload), int64(undoPayloadMaxBytes), errStoreFileTooLarge)
	}
	checksum := undoEnvelopeChecksumForVersion(version, blockHash, payload)
	raw, err := json.Marshal(undoEnvelopeDisk{
		Version:    version,
		BlockHash:  hex.EncodeToString(blockHash[:]),
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Checksum:   hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode undo envelope: %w", err)
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > int64(undoFileMaxBytes) {
		return nil, fmt.Errorf("refusing to save undo: envelope is %d bytes, class bound %d: %w",
			len(raw), int64(undoFileMaxBytes), errStoreFileTooLarge)
	}
	return raw, nil
}

// unmarshalUndoEnvelope runs the validation order: bound, canonical layout
// (which subsumes shape, version-literal, duplicate, unknown, missing, null,
// ordering, whitespace and trailing-token rejection), hash equality against the
// hash the CALLER asked for, canonical base64, decoded payload bound, checksum —
// and only then the payload decode into the validated disk tree.
//
// MEMORY: everything before the checksum decision allocates exactly ONE
// payload-sized buffer — the base64 output, which is unavoidable because the
// checksum covers those bytes. Nothing copies or re-encodes the base64 body, and
// the preimage is streamed rather than concatenated. Measured on an 11.9 MB
// envelope: 0.750x the file in 7 allocations, so peak resident before the
// decision is the caller's buffer plus 3/4 of it, ~1.75x. The payload decode
// past the checksum is far more expensive (~5.7x cumulative, dominated by the
// per-spent-entry structs) and runs only once the bytes are proven intact.
func unmarshalUndoEnvelopeDisk(blockHash [32]byte, raw []byte) (validatedBlockUndoDisk, error) {
	if int64(len(raw)) > int64(undoFileMaxBytes) {
		return validatedBlockUndoDisk{}, fmt.Errorf("%w: undo record is %d bytes, class bound %d",
			ErrUndoIntegrity, len(raw), int64(undoFileMaxBytes))
	}
	version, hashHex, payloadB64, checksumHex, err := splitUndoEnvelopeVersioned(raw)
	if err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if string(hashHex) != hex.EncodeToString(blockHash[:]) {
		return validatedBlockUndoDisk{}, errUndoBlockHashMismatch
	}
	payload, err := decodeCanonicalBase64(payloadB64)
	if err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if int64(len(payload)) > int64(undoPayloadMaxBytes) {
		return validatedBlockUndoDisk{}, fmt.Errorf("%w: decoded payload is %d bytes, class bound %d",
			ErrUndoIntegrity, len(payload), int64(undoPayloadMaxBytes))
	}
	if err := validateUndoEnvelopeChecksum(version, blockHash, payload, checksumHex); err != nil {
		return validatedBlockUndoDisk{}, err
	}
	if version == undoEnvelopeVersionV1 {
		return decodeValidatedBlockUndoV1(payload)
	}
	return decodeValidatedBlockUndoV2(payload)
}

func unmarshalUndoEnvelope(blockHash [32]byte, raw []byte) (*BlockUndo, error) {
	disk, err := unmarshalUndoEnvelopeDisk(blockHash, raw)
	if err != nil {
		return nil, err
	}
	return blockUndoFromValidatedDisk(disk)
}

func validateUndoEnvelopeChecksum(version uint32, blockHash [32]byte, payload, checksumHex []byte) error {
	// splitUndoEnvelope already proved this is 64 lowercase hex characters.
	stored, err := hex.DecodeString(string(checksumHex))
	if err != nil {
		return fmt.Errorf("%w: checksum is not hexadecimal", ErrUndoIntegrity)
	}
	computed := undoEnvelopeChecksumForVersion(version, blockHash, payload)
	if subtle.ConstantTimeCompare(stored, computed[:]) != 1 {
		return errUndoChecksumMismatch
	}
	return nil
}

// splitUndoEnvelope validates the canonical layout and returns sub-slices of
// raw. The body length is DERIVED (len(raw) - frame) rather than searched for,
// so the whole check is a handful of fixed-length comparisons: any inserted,
// removed, reordered, duplicated or renamed field shifts the trailing segments
// and fails. On failure it hands off to classifyUndoEnvelopeFailure for the
// operator-facing reason, which is the only path that parses JSON at all.
func splitUndoEnvelope(raw []byte) (hashHex, payloadB64, checksumHex []byte, err error) {
	_, hashHex, payloadB64, checksumHex, err = splitUndoEnvelopeVersioned(raw)
	return hashHex, payloadB64, checksumHex, err
}

func splitUndoEnvelopeVersioned(raw []byte) (version uint32, hashHex, payloadB64, checksumHex []byte, err error) {
	body := len(raw) - undoEnvelopeFrameBytes
	if body < 0 {
		return 0, nil, nil, nil, classifyUndoEnvelopeFailure(raw)
	}
	version, prefix, ok := undoEnvelopePrefixVersion(raw)
	if !ok {
		return 0, nil, nil, nil, classifyUndoEnvelopeFailure(raw)
	}
	hashAt := len(prefix)
	payloadSepAt := hashAt + undoHashHexLen
	payloadAt := payloadSepAt + len(undoEnvelopePayloadSep)
	checksumSepAt := payloadAt + body
	checksumAt := checksumSepAt + len(undoEnvelopeChecksumSep)
	suffixAt := checksumAt + undoHashHexLen
	if string(raw[payloadSepAt:payloadAt]) != undoEnvelopePayloadSep ||
		string(raw[checksumSepAt:checksumAt]) != undoEnvelopeChecksumSep ||
		string(raw[suffixAt:]) != undoEnvelopeSuffix {
		return 0, nil, nil, nil, classifyUndoEnvelopeFailure(raw)
	}
	hashHex, checksumHex = raw[hashAt:payloadSepAt], raw[checksumAt:suffixAt]
	if !validCanonicalHashHex(string(hashHex)) || !validCanonicalHashHex(string(checksumHex)) {
		return 0, nil, nil, nil, fmt.Errorf(
			"%w: block_hash and checksum must be 64 lowercase hex characters", ErrUndoIntegrity)
	}
	return version, hashHex, raw[payloadAt:checksumSepAt], checksumHex, nil
}

func undoEnvelopePrefixVersion(raw []byte) (uint32, string, bool) {
	for _, candidate := range [...]struct {
		version uint32
		prefix  string
	}{{undoEnvelopeVersionV1, undoEnvelopePrefixV1}, {undoEnvelopeVersion, undoEnvelopePrefixV2}} {
		if bytes.HasPrefix(raw, []byte(candidate.prefix)) {
			return candidate.version, candidate.prefix, true
		}
	}
	return 0, "", false
}

type jsonIgnoredValue struct{}

func (*jsonIgnoredValue) UnmarshalJSON([]byte) error { return nil }
func undoVersionKey(token json.Token, count *int, alias *bool) (exact, ok bool) {
	name, ok := token.(string)
	if !ok {
		return false, false
	}
	if name == "version" {
		*count++
		return true, true
	}
	if len(name) == len("version") && strings.EqualFold(name, "version") {
		*alias = true
	}
	return false, true
}

func decodeUndoVersionValue(decoder *json.Decoder, typed, exact bool, version **uint32) error {
	if typed && exact {
		return decoder.Decode(version)
	}
	var ignored jsonIgnoredValue
	return decoder.Decode(&ignored)
}

func scanUndoVersion(raw []byte, typed bool) (count int, alias bool, version *uint32, ok bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return 0, false, nil, false
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return 0, false, nil, false
		}
		exact, keyOK := undoVersionKey(key, &count, &alias)
		if !keyOK {
			return 0, false, nil, false
		}
		if err := decodeUndoVersionValue(decoder, typed, exact, &version); err != nil {
			return 0, false, nil, false
		}
	}
	token, err := decoder.Token()
	return count, alias, version, err == nil && token == json.Delim('}')
}

func classifyUndoVersion(version *uint32) error {
	if version == nil {
		return errUndoLegacyRecord
	}
	if *version != undoEnvelopeVersionV1 && *version != undoEnvelopeVersion {
		return fmt.Errorf("%w: unsupported undo envelope version %d", ErrUndoIntegrity, *version)
	}
	return fmt.Errorf("%w: envelope is not the canonical encoding", ErrUndoIntegrity)
}

// classifyUndoEnvelopeFailure names WHY a record that failed the layout check
// failed it. It runs only on records already being rejected, so its JSON scan is
// never paid on the accept path and retains no semantic tree.
//
// It decodes ONE value and ignores anything after it, so an unversioned record
// with trailing garbage still reports the actionable legacy message instead of a
// generic one. The Rust twin classifies identically.
func classifyUndoEnvelopeFailure(raw []byte) error {
	versionCount, alias, _, ok := scanUndoVersion(raw, false)
	if !ok {
		return fmt.Errorf("%w: undo record is not a single JSON object", ErrUndoIntegrity)
	}
	if versionCount > 1 || versionCount == 1 && alias {
		return fmt.Errorf("%w: envelope is not the canonical encoding", ErrUndoIntegrity)
	}
	if versionCount == 0 {
		return errUndoLegacyRecord
	}
	_, _, version, ok := scanUndoVersion(raw, true)
	if !ok {
		return fmt.Errorf("%w: undo record is not a single JSON object", ErrUndoIntegrity)
	}
	return classifyUndoVersion(version)
}

// decodeCanonicalBase64 accepts only the one padded RFC 4648 spelling of the
// payload. Strict() covers non-zero padding bits; the EncodedLen equality covers
// the rest, notably the \r and \n that Go's decoder silently SKIPS — a skipped
// byte makes the symbol count disagree with the slice length. Checking the
// length instead of re-encoding keeps this O(1) on top of the output buffer.
func decodeCanonicalBase64(value []byte) ([]byte, error) {
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Strict().Decode(payload, value)
	if err != nil || base64.StdEncoding.EncodedLen(n) != len(value) {
		return nil, fmt.Errorf("%w: payload_b64 is not canonical padded base64", ErrUndoIntegrity)
	}
	return payload[:n], nil
}
