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
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type BlockUndo struct {
	BlockHeight              uint64
	PreviousAlreadyGenerated uint64
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
	AlreadyGenerated   uint64
	UtxoCount          uint64
}

type blockUndoDisk struct {
	BlockHeight              uint64       `json:"block_height"`
	PreviousAlreadyGenerated uint64       `json:"previous_already_generated"`
	Txs                      []txUndoDisk `json:"txs"`
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

// marshalBlockUndo produces the canonical undo PAYLOAD: compact JSON in
// blockUndoDisk field order with no trailing whitespace or newline. It is not
// the on-disk record — undo_envelope_v1 wraps these bytes and binds them to a
// block hash (marshalUndoEnvelope). Rust twin: `marshal_block_undo`.
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

// unmarshalBlockUndo strictly decodes a canonical payload. Strictness is one
// rule rather than a field-by-field walk: decode, convert, re-encode, and
// require byte equality with the input. That single comparison rejects
// duplicate, unknown, missing, null, and reordered fields at every nesting
// level, plus insignificant whitespace and uppercase hex — none of which the
// struct decode alone would catch. json.Unmarshal already rejects trailing
// tokens. blockUndoFromDisk/blockUndoToDisk always rebuild non-nil slices, so a
// `null` txs/spent re-encodes as `[]` and fails the comparison; without that
// normalization Go would accept a null the Rust twin's Vec decode rejects.
// Rust twin: `unmarshal_block_undo`.
func unmarshalBlockUndo(raw []byte) (*BlockUndo, error) {
	var disk blockUndoDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, fmt.Errorf("decode undo: %w", err)
	}
	undo, err := blockUndoFromDisk(disk)
	if err != nil {
		return nil, err
	}
	canonical, err := marshalBlockUndo(undo)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, errors.New("decode undo: payload is not the canonical encoding")
	}
	return undo, nil
}

func blockUndoToDisk(undo *BlockUndo) (blockUndoDisk, error) {
	if undo == nil {
		return blockUndoDisk{}, errors.New("nil block undo")
	}
	txs := make([]txUndoDisk, 0, len(undo.Txs))
	for _, txUndo := range undo.Txs {
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
	return blockUndoDisk{
		BlockHeight:              undo.BlockHeight,
		PreviousAlreadyGenerated: undo.PreviousAlreadyGenerated,
		Txs:                      txs,
	}, nil
}

func blockUndoFromDisk(disk blockUndoDisk) (*BlockUndo, error) {
	txs := make([]TxUndo, 0, len(disk.Txs))
	for txIndex, txUndo := range disk.Txs {
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
		BlockHeight:              disk.BlockHeight,
		PreviousAlreadyGenerated: disk.PreviousAlreadyGenerated,
		Txs:                      txs,
	}, nil
}

// ---------------------------------------------------------------------------
// undo_envelope_v1 (RUB-1132)
//
// The stored undo record is one compact JSON object binding the canonical
// payload bytes to the block hash they were built for:
//
//	{"version":1,"block_hash":"<64hex>","payload_b64":"<b64>","checksum":"<64hex>"}\n
//
// checksum = SHA3-256("RUBIN_BLOCK_UNDO_V1" || block_hash[32] ||
// uint64_be(len(payload)) || payload). The length term makes the preimage
// injective, so no two (hash, payload) pairs share a digest by concatenation.
// The trailing LF counts against the read bound but is NOT in the preimage.
//
// Rust twin: the same section in crates/rubin-node/src/undo.rs. Both clients
// must emit byte-identical envelopes; conformance/fixtures/protocol/
// undo_integrity_v1.json pins the bytes.
//
// Claim boundary: this detects accidental, torn, misnamed and parse-valid local
// corruption before an undo is used. It is NOT authentication — a local actor
// able to rewrite the payload can recompute the checksum. There is no secret
// here and none is claimed.
// ---------------------------------------------------------------------------

// ErrUndoIntegrity is the stable identity behind every undo_envelope_v1
// rejection: errors.Is(err, ErrUndoIntegrity) holds for the legacy, block-hash
// and checksum classes and for every other envelope/version/base64 failure,
// while err.Error() keeps the exact cross-client message the Rust client
// returns verbatim from get_undo.
var ErrUndoIntegrity = errors.New("UNDO_INTEGRITY")

var (
	// Pinned cross-client messages. Rust returns these same strings.
	// Deliberately no repair command: this build ships no --reindex.
	errUndoLegacyRecord      = fmt.Errorf("%w: legacy/unversioned undo; pre-devnet datadir reset and full resync required", ErrUndoIntegrity)
	errUndoBlockHashMismatch = fmt.Errorf("%w: block hash mismatch", ErrUndoIntegrity)
	errUndoChecksumMismatch  = fmt.Errorf("%w: checksum mismatch", ErrUndoIntegrity)
)

const (
	undoEnvelopeVersion = 1
	undoEnvelopeDomain  = "RUBIN_BLOCK_UNDO_V1"

	// undoEnvelopeFrameBytes is the envelope minus the base64 body: the four
	// keys, the punctuation, the two 64-char hashes and the trailing LF.
	// Pinned by TestUndoEnvelopeFrameOverhead.
	undoEnvelopeFrameBytes = 189

	// undoEnvelopeFileMaxBytes is the OUTER read bound, derived mechanically
	// from the payload bound: base64 expands n bytes to ceil(n/3)*4, plus the
	// fixed frame. The decoded payload is separately re-checked against
	// undoFileMaxBytes before conversion, so the envelope bound never widens
	// what a BlockUndo may hold.
	//
	// This constant is ~2.67e9 and therefore EXCEEDS 2^31 — unlike
	// undoFileMaxBytes, whose safeio.go note relies on staying below it. Every
	// comparison against it must widen first (int64(len(x))); a bare
	// `len(x) > undoEnvelopeFileMaxBytes` does not compile on a 32-bit build,
	// which is the intended loud failure rather than a silent narrowing.
	undoEnvelopeFileMaxBytes = ((undoFileMaxBytes+2)/3)*4 + undoEnvelopeFrameBytes
)

// undoEnvelopeDisk is the exact stored shape. Field ORDER is part of the
// format: encoding/json emits struct fields in declaration order and serde does
// the same, which is what makes the two clients' bytes identical.
type undoEnvelopeDisk struct {
	Version    uint32 `json:"version"`
	BlockHash  string `json:"block_hash"`
	PayloadB64 string `json:"payload_b64"`
	Checksum   string `json:"checksum"`
}

func undoEnvelopeChecksum(blockHash [32]byte, payload []byte) [32]byte {
	preimage := make([]byte, 0, len(undoEnvelopeDomain)+32+8+len(payload))
	preimage = append(preimage, undoEnvelopeDomain...)
	preimage = append(preimage, blockHash[:]...)
	preimage = binary.BigEndian.AppendUint64(preimage, uint64(len(payload)))
	preimage = append(preimage, payload...)
	return sha3.Sum256(preimage)
}

func marshalUndoEnvelope(blockHash [32]byte, undo *BlockUndo) ([]byte, error) {
	payload, err := marshalBlockUndo(undo)
	if err != nil {
		return nil, err
	}
	checksum := undoEnvelopeChecksum(blockHash, payload)
	raw, err := json.Marshal(undoEnvelopeDisk{
		Version:    undoEnvelopeVersion,
		BlockHash:  hex.EncodeToString(blockHash[:]),
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Checksum:   hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode undo envelope: %w", err)
	}
	return append(raw, '\n'), nil
}

// unmarshalUndoEnvelope runs the fixed validation order: shape, version, hash
// equality against the hash the CALLER asked for, canonical base64, decoded
// payload bound, checksum — and only then the payload decode and BlockUndo
// conversion. Every step before the checksum is cheap and side-effect free, so
// a corrupt record costs one hash at most and never reaches a converted undo.
func unmarshalUndoEnvelope(blockHash [32]byte, raw []byte) (*BlockUndo, error) {
	env, err := decodeUndoEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if env.Version != undoEnvelopeVersion {
		return nil, fmt.Errorf("%w: unsupported undo envelope version %d", ErrUndoIntegrity, env.Version)
	}
	if !validCanonicalHashHex(env.BlockHash) || !validCanonicalHashHex(env.Checksum) {
		return nil, fmt.Errorf("%w: block_hash and checksum must be 64 lowercase hex characters", ErrUndoIntegrity)
	}
	if env.BlockHash != hex.EncodeToString(blockHash[:]) {
		return nil, errUndoBlockHashMismatch
	}
	payload, err := decodeCanonicalBase64(env.PayloadB64)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > int64(undoFileMaxBytes) {
		return nil, fmt.Errorf("%w: decoded payload is %d bytes, class bound %d",
			ErrUndoIntegrity, len(payload), int64(undoFileMaxBytes))
	}
	// validCanonicalHashHex already proved this decodes to 32 bytes.
	stored, err := hex.DecodeString(env.Checksum)
	if err != nil {
		return nil, fmt.Errorf("%w: checksum is not hexadecimal", ErrUndoIntegrity)
	}
	computed := undoEnvelopeChecksum(blockHash, payload)
	if subtle.ConstantTimeCompare(stored, computed[:]) != 1 {
		return nil, errUndoChecksumMismatch
	}
	return unmarshalBlockUndo(payload)
}

// decodeUndoEnvelope enforces step 2 of the validation order. The key multiset
// is collected first because struct decoding sees none of duplicate, unknown or
// missing fields — and because an unversioned legacy record must be recognised
// by the ABSENCE of "version" before the exact-field-set check, or its pinned
// message becomes unreachable.
func decodeUndoEnvelope(raw []byte) (undoEnvelopeDisk, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: undo record is not JSON", ErrUndoIntegrity)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: undo record must be a JSON object", ErrUndoIntegrity)
	}
	keys, err := collectTopLevelFieldNames(dec)
	if err != nil {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: undo record is not a well-formed JSON object", ErrUndoIntegrity)
	}
	hasVersion := false
	for _, key := range keys {
		if key == "version" {
			hasVersion = true
			break
		}
	}
	if !hasVersion {
		return undoEnvelopeDisk{}, errUndoLegacyRecord
	}
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	if len(sorted) != 4 || sorted[0] != "block_hash" || sorted[1] != "checksum" ||
		sorted[2] != "payload_b64" || sorted[3] != "version" {
		return undoEnvelopeDisk{}, fmt.Errorf(
			"%w: envelope fields must be exactly block_hash, checksum, payload_b64, version, got %q",
			ErrUndoIntegrity, sorted)
	}

	var env undoEnvelopeDisk
	value := json.NewDecoder(bytes.NewReader(raw))
	if err := value.Decode(&env); err != nil {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: envelope field has the wrong type", ErrUndoIntegrity)
	}
	if _, err := value.Token(); !errors.Is(err, io.EOF) {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: unexpected trailing JSON value", ErrUndoIntegrity)
	}
	// Same canonical-form rule as the payload, and it is load-bearing for
	// PARITY, not just strictness: encoding/json treats a JSON null as "leave
	// the field at its zero value", so `"payload_b64":null` would otherwise
	// decode to "" and surface as a checksum mismatch here while serde rejects
	// it outright. Re-encoding pins nulls, silently-zeroed types, field order,
	// insignificant whitespace and the single trailing LF in one comparison, so
	// both clients accept exactly the same byte strings.
	canonical, err := json.Marshal(env)
	if err != nil {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: envelope is not re-encodable", ErrUndoIntegrity)
	}
	if !bytes.Equal(append(canonical, '\n'), raw) {
		return undoEnvelopeDisk{}, fmt.Errorf("%w: envelope is not the canonical encoding", ErrUndoIntegrity)
	}
	return env, nil
}

// decodeCanonicalBase64 accepts only the one padded RFC 4648 spelling of the
// payload. The re-encode comparison is what makes it canonical: Go's decoder
// silently skips \r and \n (reachable here as JSON escapes) and Strict() alone
// only covers non-zero padding bits.
func decodeCanonicalBase64(value string) ([]byte, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != value {
		return nil, fmt.Errorf("%w: payload_b64 is not canonical padded base64", ErrUndoIntegrity)
	}
	return payload, nil
}
