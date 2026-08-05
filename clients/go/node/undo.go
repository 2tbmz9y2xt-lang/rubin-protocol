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
	undoEnvelopePrefix      = `{"version":1,"block_hash":"`
	undoEnvelopePayloadSep  = `","payload_b64":"`
	undoEnvelopeChecksumSep = `","checksum":"`
	undoEnvelopeSuffix      = "\"}\n"
)

const (
	undoEnvelopeVersion = 1
	undoEnvelopeDomain  = "RUBIN_BLOCK_UNDO_V1"
	undoHashHexLen      = 64

	// undoEnvelopeFrameBytes is the envelope minus the base64 body. Derived from
	// the segments above rather than written down, so a format edit cannot leave
	// the bound behind. Cross-checked against a real envelope by
	// TestUndoEnvelopeBoundDerivation.
	undoEnvelopeFrameBytes = len(undoEnvelopePrefix) + undoHashHexLen +
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
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(undoEnvelopeDomain))
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
	payload, err := marshalBlockUndo(undo)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > int64(undoPayloadMaxBytes) {
		return nil, fmt.Errorf("refusing to save undo: payload is %d bytes, class bound %d: %w",
			len(payload), int64(undoPayloadMaxBytes), errStoreFileTooLarge)
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
// and only then the payload decode and BlockUndo conversion.
//
// MEMORY: everything before the checksum decision allocates exactly ONE
// payload-sized buffer — the base64 output, which is unavoidable because the
// checksum covers those bytes. Nothing copies or re-encodes the base64 body, and
// the preimage is streamed rather than concatenated. Measured on an 11.9 MB
// envelope: 0.750x the file in 7 allocations, so peak resident before the
// decision is the caller's buffer plus 3/4 of it, ~1.75x. The payload decode
// past the checksum is far more expensive (~5.7x cumulative, dominated by the
// per-spent-entry structs) and runs only once the bytes are proven intact.
func unmarshalUndoEnvelope(blockHash [32]byte, raw []byte) (*BlockUndo, error) {
	if int64(len(raw)) > int64(undoFileMaxBytes) {
		return nil, fmt.Errorf("%w: undo record is %d bytes, class bound %d",
			ErrUndoIntegrity, len(raw), int64(undoFileMaxBytes))
	}
	hashHex, payloadB64, checksumHex, err := splitUndoEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if string(hashHex) != hex.EncodeToString(blockHash[:]) {
		return nil, errUndoBlockHashMismatch
	}
	payload, err := decodeCanonicalBase64(payloadB64)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > int64(undoPayloadMaxBytes) {
		return nil, fmt.Errorf("%w: decoded payload is %d bytes, class bound %d",
			ErrUndoIntegrity, len(payload), int64(undoPayloadMaxBytes))
	}
	// splitUndoEnvelope already proved this is 64 lowercase hex characters.
	stored, err := hex.DecodeString(string(checksumHex))
	if err != nil {
		return nil, fmt.Errorf("%w: checksum is not hexadecimal", ErrUndoIntegrity)
	}
	computed := undoEnvelopeChecksum(blockHash, payload)
	if subtle.ConstantTimeCompare(stored, computed[:]) != 1 {
		return nil, errUndoChecksumMismatch
	}
	return unmarshalBlockUndo(payload)
}

// splitUndoEnvelope validates the canonical layout and returns sub-slices of
// raw. The body length is DERIVED (len(raw) - frame) rather than searched for,
// so the whole check is a handful of fixed-length comparisons: any inserted,
// removed, reordered, duplicated or renamed field shifts the trailing segments
// and fails. On failure it hands off to classifyUndoEnvelopeFailure for the
// operator-facing reason, which is the only path that parses JSON at all.
func splitUndoEnvelope(raw []byte) (hashHex, payloadB64, checksumHex []byte, err error) {
	body := len(raw) - undoEnvelopeFrameBytes
	if body < 0 {
		return nil, nil, nil, classifyUndoEnvelopeFailure(raw)
	}
	hashAt := len(undoEnvelopePrefix)
	payloadSepAt := hashAt + undoHashHexLen
	payloadAt := payloadSepAt + len(undoEnvelopePayloadSep)
	checksumSepAt := payloadAt + body
	checksumAt := checksumSepAt + len(undoEnvelopeChecksumSep)
	suffixAt := checksumAt + undoHashHexLen
	if string(raw[:hashAt]) != undoEnvelopePrefix ||
		string(raw[payloadSepAt:payloadAt]) != undoEnvelopePayloadSep ||
		string(raw[checksumSepAt:checksumAt]) != undoEnvelopeChecksumSep ||
		string(raw[suffixAt:]) != undoEnvelopeSuffix {
		return nil, nil, nil, classifyUndoEnvelopeFailure(raw)
	}
	hashHex, checksumHex = raw[hashAt:payloadSepAt], raw[checksumAt:suffixAt]
	if !validCanonicalHashHex(string(hashHex)) || !validCanonicalHashHex(string(checksumHex)) {
		return nil, nil, nil, fmt.Errorf(
			"%w: block_hash and checksum must be 64 lowercase hex characters", ErrUndoIntegrity)
	}
	return hashHex, raw[payloadAt:checksumSepAt], checksumHex, nil
}

// classifyUndoEnvelopeFailure names WHY a record that failed the layout check
// failed it. It runs only on records already being rejected, so its JSON scan is
// never paid on the accept path, and it decodes into a probe holding just the
// version — encoding/json skips the other fields without materializing them, so
// even a maximum-size hostile record costs no proportional allocation.
//
// It decodes ONE value and ignores anything after it, so an unversioned record
// with trailing garbage still reports the actionable legacy message instead of a
// generic one. The Rust twin classifies identically.
func classifyUndoEnvelopeFailure(raw []byte) error {
	var probe struct {
		Version *uint32 `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&probe); err != nil {
		return fmt.Errorf("%w: undo record is not a single JSON object", ErrUndoIntegrity)
	}
	if probe.Version == nil {
		return errUndoLegacyRecord
	}
	if *probe.Version != undoEnvelopeVersion {
		return fmt.Errorf("%w: unsupported undo envelope version %d", ErrUndoIntegrity, *probe.Version)
	}
	return fmt.Errorf("%w: envelope is not the canonical encoding", ErrUndoIntegrity)
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
