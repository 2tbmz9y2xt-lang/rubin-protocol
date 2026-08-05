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
)

// ---------------------------------------------------------------------------
// store_envelope_v1 (RUB-1134) — authoritative description of the format the
// Rust twin (crates/rubin-node/src/store_envelope.rs) mirrors byte for byte.
// chainstate.json and the canonical blockstore index.json are each stored as one
// compact JSON object binding the exact inner payload bytes to a domain-tagged
// checksum:
//
//	{"version":1,"payload_b64":"<b64>","checksum":"<64hex>"}\n
//
// checksum = SHA3-256(ASCII(domain_tag) || uint64_be(len(payload)) || payload).
// The length term makes the preimage injective, so no two payloads share a
// digest by concatenation. The trailing LF is NOT in the preimage. Domain tags
// are "RUBIN_CHAINSTATE_V1" and "RUBIN_BLOCKSTORE_INDEX_V1": both files are
// per-datadir singletons, so the domain tag is the identity, and chain identity
// is enforced by the separate genesis anchor (BlockStore.VerifyGenesisAnchor),
// never by an envelope field. Both payloads grow with accumulated state and are
// deliberately UNBOUNDED per the RUB-1057 standing decision: no size bound may
// be added.
//
// These helpers are 3-field siblings of the merged undo_envelope_v1 frame
// (undo.go, RUB-1132), which embeds block_hash in its prefix and preimage and so
// cannot be reused as-is; its structure is mirrored deliberately (strict field
// order, compact JSON, trailing LF outside the preimage, constant-time compare,
// layout validation by index arithmetic with JSON parsed only on the reject
// path).
//
// Claim boundary: this detects accidental, torn, tool-mediated and parse-valid
// local corruption before either file is adopted. It is NOT authentication — a
// local actor able to rewrite payload and checksum together defeats it.
// ---------------------------------------------------------------------------

// ErrStoreIntegrity is the stable identity behind every envelope, version,
// base64, checksum and genesis-anchor rejection class in the RUB-1134
// error_contract: errors.Is(err, ErrStoreIntegrity) holds for all of them, and
// the pinned messages are the exact cross-client strings Rust returns verbatim.
// None of these is, wraps, or satisfies fs.ErrNotExist: absent-file fallbacks
// must never trigger on a corrupt file. The inner payload-decode class is
// deliberately OUTSIDE this identity: a file that clears the checksum is intact
// on disk, so a failure past it is a schema fault.
var ErrStoreIntegrity = errors.New("STORE_INTEGRITY")

var (
	// Pinned cross-client messages. Rust returns these same strings.
	// Deliberately no repair command: this build ships no --reindex.
	errStoreLegacyChainState = fmt.Errorf("%w: legacy/unversioned chainstate; delete chainstate.json and restart to rebuild by validated replay.", ErrStoreIntegrity)
	errStoreLegacyBlockIndex = fmt.Errorf("%w: legacy/unversioned blockstore index; pre-devnet datadir reset and full resync required.", ErrStoreIntegrity)
	errStoreChecksumMismatch = fmt.Errorf("%w: checksum mismatch.", ErrStoreIntegrity)
	errStoreGenesisAnchor    = fmt.Errorf("%w: canonical index genesis mismatch.", ErrStoreIntegrity)
)

// The canonical byte layout is fully determined by these fixed segments plus the
// 64-character checksum, so the reader validates it by index arithmetic instead
// of decoding JSON: nothing is materialized on the accept path.
const (
	storeEnvelopePrefix      = `{"version":1,"payload_b64":"`
	storeEnvelopeChecksumSep = `","checksum":"`
	storeEnvelopeSuffix      = "\"}\n"
	storeEnvelopeVersion     = 1
	storeChecksumHexLen      = 64
	storeEnvelopeFrameBytes  = len(storeEnvelopePrefix) + len(storeEnvelopeChecksumSep) +
		storeChecksumHexLen + len(storeEnvelopeSuffix)
	storeChainStateDomain = "RUBIN_CHAINSTATE_V1"
	storeBlockIndexDomain = "RUBIN_BLOCKSTORE_INDEX_V1"
)

// storeEnvelopeKind carries the per-file frame parameters.
type storeEnvelopeKind struct {
	domain    string
	noun      string
	legacyErr error
}

var (
	storeEnvelopeChainState = storeEnvelopeKind{
		domain:    storeChainStateDomain,
		noun:      "chainstate",
		legacyErr: errStoreLegacyChainState,
	}
	storeEnvelopeBlockIndex = storeEnvelopeKind{
		domain:    storeBlockIndexDomain,
		noun:      "blockstore index",
		legacyErr: errStoreLegacyBlockIndex,
	}
)

// storeEnvelopeDisk is the writer's shape; the reader never decodes into it.
// Field ORDER is part of the format: encoding/json and serde both emit
// declaration order, which is what makes the two clients' bytes identical.
type storeEnvelopeDisk struct {
	Version    uint32 `json:"version"`
	PayloadB64 string `json:"payload_b64"`
	Checksum   string `json:"checksum"`
}

// storeEnvelopeChecksum streams the preimage rather than materializing it
// (unbounded payload class); hash.Hash.Write never returns an error.
func storeEnvelopeChecksum(domain string, payload []byte) [32]byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(payload)))
	hasher := sha3.New256()
	_, _ = hasher.Write([]byte(domain))
	_, _ = hasher.Write(length[:])
	_, _ = hasher.Write(payload)
	var out [32]byte
	hasher.Sum(out[:0])
	return out
}

// marshalStoreEnvelope wraps the exact payload bytes in the v1 frame. New
// writes emit v1 only, and deliberately without a size bound (RUB-1057).
func marshalStoreEnvelope(kind storeEnvelopeKind, payload []byte) ([]byte, error) {
	checksum := storeEnvelopeChecksum(kind.domain, payload)
	raw, err := json.Marshal(storeEnvelopeDisk{
		Version:    storeEnvelopeVersion,
		PayloadB64: base64.StdEncoding.EncodeToString(payload),
		Checksum:   hex.EncodeToString(checksum[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode %s envelope: %w", kind.noun, err)
	}
	return append(raw, '\n'), nil
}

// openStoreEnvelope runs the validation order on one protected file: strict
// canonical layout (which subsumes shape, version, duplicate, unknown, missing,
// null, wrong-type, ordering, whitespace and trailing-token rejection, with
// unversioned legacy classified first), canonical padded base64, then the
// constant-time checksum compare. Only after checksum success does the caller
// decode the inner schema.
func openStoreEnvelope(kind storeEnvelopeKind, raw []byte) ([]byte, error) {
	payloadB64, checksumHex, err := splitStoreEnvelope(kind, raw)
	if err != nil {
		return nil, err
	}
	payload, err := decodeCanonicalStoreBase64(payloadB64)
	if err != nil {
		return nil, err
	}
	// splitStoreEnvelope already proved this is 64 lowercase hex characters.
	stored, err := hex.DecodeString(string(checksumHex))
	if err != nil {
		return nil, fmt.Errorf("%w: checksum is not hexadecimal", ErrStoreIntegrity)
	}
	computed := storeEnvelopeChecksum(kind.domain, payload)
	if subtle.ConstantTimeCompare(stored, computed[:]) != 1 {
		return nil, errStoreChecksumMismatch
	}
	return payload, nil
}

// splitStoreEnvelope validates the canonical layout and returns sub-slices of
// raw. The body length is DERIVED (len(raw) - frame), never searched for, so
// any inserted, removed, reordered, duplicated or renamed field shifts the
// trailing segments and fails.
func splitStoreEnvelope(kind storeEnvelopeKind, raw []byte) (payloadB64, checksumHex []byte, err error) {
	body := len(raw) - storeEnvelopeFrameBytes
	if body < 0 {
		return nil, nil, classifyStoreEnvelopeFailure(kind, raw)
	}
	payloadAt := len(storeEnvelopePrefix)
	checksumSepAt := payloadAt + body
	checksumAt := checksumSepAt + len(storeEnvelopeChecksumSep)
	suffixAt := checksumAt + storeChecksumHexLen
	if string(raw[:payloadAt]) != storeEnvelopePrefix ||
		string(raw[checksumSepAt:checksumAt]) != storeEnvelopeChecksumSep ||
		string(raw[suffixAt:]) != storeEnvelopeSuffix {
		return nil, nil, classifyStoreEnvelopeFailure(kind, raw)
	}
	checksumHex = raw[checksumAt:suffixAt]
	if !validCanonicalHashHex(string(checksumHex)) {
		return nil, nil, fmt.Errorf("%w: checksum must be 64 lowercase hex characters", ErrStoreIntegrity)
	}
	return raw[payloadAt:checksumSepAt], checksumHex, nil
}

// classifyStoreEnvelopeFailure names WHY a file failed the layout check; it runs
// only on already-rejected files. It decodes ONE value, ignores anything after
// it, and duplicate keys last-win (as in Rust), so a legacy file with trailing
// garbage still reports the actionable legacy message. Legacy detection keys on
// the ENVELOPE fields and precedes the version verdicts: both legacy inner
// schemas carry a top-level "version": 1.
func classifyStoreEnvelopeFailure(kind storeEnvelopeKind, raw []byte) error {
	var probe map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&probe); err != nil || probe == nil {
		return fmt.Errorf("%w: %s is not a single JSON object", ErrStoreIntegrity, kind.noun)
	}
	_, hasPayload := probe["payload_b64"]
	_, hasChecksum := probe["checksum"]
	if !hasPayload && !hasChecksum {
		return kind.legacyErr
	}
	// A POINTER target: JSON null decodes into it as nil WITHOUT an error, so
	// `"version":null` is a non-canonical frame, not "unsupported version 0".
	// Any non-integer spelling errors instead; Rust classifies all three the same.
	var version *uint64
	if err := json.Unmarshal(probe["version"], &version); err == nil && version != nil && *version != storeEnvelopeVersion {
		return fmt.Errorf("%w: unsupported store envelope version %d", ErrStoreIntegrity, *version)
	}
	return fmt.Errorf("%w: envelope is not the canonical encoding", ErrStoreIntegrity)
}

// decodeCanonicalStoreBase64 accepts only the one padded RFC 4648 spelling:
// Strict() covers non-zero padding bits and the EncodedLen equality covers the
// rest, notably the \r and \n Go's decoder silently skips.
func decodeCanonicalStoreBase64(value []byte) ([]byte, error) {
	payload := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Strict().Decode(payload, value)
	if err != nil || base64.StdEncoding.EncodedLen(n) != len(value) {
		return nil, fmt.Errorf("%w: payload_b64 is not canonical padded base64", ErrStoreIntegrity)
	}
	return payload[:n], nil
}
