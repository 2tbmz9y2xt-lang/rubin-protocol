package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// storeEnvelopeVectors are the RUB-1134 cross-client vectors. Both clients
// embed these SAME literals: given identical payload bytes, the preimage,
// checksum and complete envelope bytes must be byte-identical in Go and Rust.
// Rust twin: `store_envelope_v1_cross_client_vectors`. The two empty-payload
// rows differ only by domain tag, so they pin domain separation; the two
// non-empty rows pin the length term and the base64 body. Row 4's payload is
// the exact Go empty canonical-index payload, so its envelope is also the
// on-disk marker pinned by TestCreateBlockStoreCommitsExactEmptyMarker.
var storeEnvelopeVectors = []struct {
	name         string
	kind         storeEnvelopeKind
	payload      string
	wantChecksum string
	wantEnvelope string
}{
	{
		name:         "chainstate_empty_payload",
		kind:         storeEnvelopeChainState,
		payload:      "",
		wantChecksum: "51e3d3a67f6a7c4439465328314723099ea753c512f22a1f197e1528b1f24afe",
		wantEnvelope: `{"version":1,"payload_b64":"","checksum":"51e3d3a67f6a7c4439465328314723099ea753c512f22a1f197e1528b1f24afe"}` + "\n",
	},
	{
		name:         "chainstate_small_payload",
		kind:         storeEnvelopeChainState,
		payload:      "{\"version\":1}\n",
		wantChecksum: "6d8ced24b9b3f05ed1aebb46c3bfe0a0bfc96508ce51e1ca6de3dc643ec659d0",
		wantEnvelope: `{"version":1,"payload_b64":"eyJ2ZXJzaW9uIjoxfQo=","checksum":"6d8ced24b9b3f05ed1aebb46c3bfe0a0bfc96508ce51e1ca6de3dc643ec659d0"}` + "\n",
	},
	{
		name:         "blockstore_index_empty_payload",
		kind:         storeEnvelopeBlockIndex,
		payload:      "",
		wantChecksum: "bf1cd3af0b95b8861e3abf40b776f315117e55b28b5c5dbdb811d3fd33018e5a",
		wantEnvelope: `{"version":1,"payload_b64":"","checksum":"bf1cd3af0b95b8861e3abf40b776f315117e55b28b5c5dbdb811d3fd33018e5a"}` + "\n",
	},
	{
		name:         "blockstore_index_empty_marker_payload",
		kind:         storeEnvelopeBlockIndex,
		payload:      "{\n  \"canonical\": [],\n  \"version\": 1\n}\n",
		wantChecksum: "7c120c21bc3ffdda6482c8d18a3c669542e89d8500928ce166700a7c7a40fe15",
		wantEnvelope: `{"version":1,"payload_b64":"ewogICJjYW5vbmljYWwiOiBbXSwKICAidmVyc2lvbiI6IDEKfQo=","checksum":"7c120c21bc3ffdda6482c8d18a3c669542e89d8500928ce166700a7c7a40fe15"}` + "\n",
	},
}

// TestStoreEnvelopeV1CrossClientVectors pins the frame, the preimage and the
// checksum. The expected checksum is ALSO recomputed here from the contract's
// stated preimage (ASCII(domain) || uint64_be(len) || payload), so the pin
// cannot drift with the production helper.
func TestStoreEnvelopeV1CrossClientVectors(t *testing.T) {
	for _, tc := range storeEnvelopeVectors {
		t.Run(tc.name, func(t *testing.T) {
			var length [8]byte
			binary.BigEndian.PutUint64(length[:], uint64(len(tc.payload)))
			hasher := sha3.New256()
			hasher.Write([]byte(tc.kind.domain))
			hasher.Write(length[:])
			hasher.Write([]byte(tc.payload))
			if got := hex.EncodeToString(hasher.Sum(nil)); got != tc.wantChecksum {
				t.Fatalf("independent preimage checksum = %s, want %s", got, tc.wantChecksum)
			}
			if got := storeEnvelopeChecksum(tc.kind.domain, []byte(tc.payload)); hex.EncodeToString(got[:]) != tc.wantChecksum {
				t.Fatalf("storeEnvelopeChecksum = %x, want %s", got, tc.wantChecksum)
			}

			raw, err := marshalStoreEnvelope(tc.kind, []byte(tc.payload))
			if err != nil {
				t.Fatalf("marshalStoreEnvelope: %v", err)
			}
			if string(raw) != tc.wantEnvelope {
				t.Fatalf("envelope =\n%q\nwant\n%q", raw, tc.wantEnvelope)
			}
			if !bytes.HasSuffix(raw, []byte("\n")) {
				t.Fatalf("envelope must end with exactly one LF: %q", raw)
			}
			back, err := openStoreEnvelope(tc.kind, raw)
			if err != nil {
				t.Fatalf("openStoreEnvelope: %v", err)
			}
			if string(back) != tc.payload {
				t.Fatalf("round trip = %q, want %q", back, tc.payload)
			}
		})
	}

	// Domain separation: the same payload under the other domain tag must not
	// verify, and the two pinned empty-payload checksums differ.
	if storeEnvelopeVectors[0].wantChecksum == storeEnvelopeVectors[2].wantChecksum {
		t.Fatalf("domain tags must produce distinct checksums for the same payload")
	}
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, []byte("{\"version\":1}\n"))
	if err != nil {
		t.Fatalf("marshalStoreEnvelope: %v", err)
	}
	if _, err := openStoreEnvelope(storeEnvelopeBlockIndex, raw); !errors.Is(err, ErrStoreIntegrity) ||
		err.Error() != errStoreChecksumMismatch.Error() {
		t.Fatalf("cross-domain open = %v, want %v", err, errStoreChecksumMismatch)
	}
}

// storeIntegrityRow is one hostile/malformed on-disk body. `body` receives the
// VALID envelope bytes and the valid inner payload bytes for that file and
// returns the bytes to plant.
type storeIntegrityRow struct {
	name    string
	body    func(t *testing.T, valid, payload []byte) []byte
	wantMsg string // exact message, when the contract pins one
	wantSub string // substring, when the message carries a variable
	// notIntegrity marks the inner-schema class, which is deliberately OUTSIDE
	// the STORE_INTEGRITY identity: those bytes are intact on disk.
	notIntegrity bool
}

// storeEnvelopeSharedRejectRows are the frame-level rows both protected files
// must reject identically. Per-file rows (legacy message, payload edits) are
// added by each caller.
func storeEnvelopeSharedRejectRows() []storeIntegrityRow {
	replaceOnce := func(old, new string) func(*testing.T, []byte, []byte) []byte {
		return func(t *testing.T, valid, _ []byte) []byte {
			t.Helper()
			out := strings.Replace(string(valid), old, new, 1)
			if out == string(valid) {
				t.Fatalf("row did not modify the envelope")
			}
			return []byte(out)
		}
	}
	// replaceChecksum rewrites the checksum field through `next`.
	replaceChecksum := func(next func(string) string) func(*testing.T, []byte, []byte) []byte {
		return func(t *testing.T, valid, payload []byte) []byte {
			t.Helper()
			return replaceOnce(hexChecksumOf(t, valid), next(hexChecksumOf(t, valid)))(t, valid, payload)
		}
	}
	// duplicateChecksum appends a SECOND checksum field carrying `next` of the
	// real one, so both the identical and the conflicting spelling are reachable.
	duplicateChecksum := func(next func(string) string) func(*testing.T, []byte, []byte) []byte {
		return func(t *testing.T, valid, payload []byte) []byte {
			t.Helper()
			return replaceOnce(`"}`+"\n", `","checksum":"`+next(hexChecksumOf(t, valid))+`"}`+"\n")(t, valid, payload)
		}
	}
	// reframe rebuilds the whole envelope from an alternative SPELLING of the
	// base64 body, keeping a correct checksum over the real payload.
	reframe := func(spell func(string) string) func(*testing.T, []byte, []byte) []byte {
		return func(t *testing.T, _, payload []byte) []byte {
			t.Helper()
			checksum := storeEnvelopeChecksum(storeEnvelopeChainState.domain, payload)
			return fmt.Appendf(nil, "{\"version\":1,\"payload_b64\":%q,\"checksum\":%q}\n",
				spell(base64.StdEncoding.EncodeToString(payload)), hex.EncodeToString(checksum[:]))
		}
	}
	static := func(out string) func(*testing.T, []byte, []byte) []byte {
		return func(*testing.T, []byte, []byte) []byte { return []byte(out) }
	}
	same := func(value string) string { return value }
	fixed := func(value string) func(string) string { return func(string) string { return value } }
	const (
		notObject      = "is not a single JSON object"
		notCanonical   = "envelope is not the canonical encoding"
		notBase64      = "payload_b64 is not canonical padded base64"
		badChecksumHex = "checksum must be 64 lowercase hex characters"
	)
	sub := func(name string, body func(*testing.T, []byte, []byte) []byte, want string) storeIntegrityRow {
		return storeIntegrityRow{name: name, body: body, wantSub: want}
	}
	// A duplicated field lands INSIDE the derived body slice (the body length
	// is len(raw) - frame, not a searched delimiter), so the canonical-base64
	// check is what refuses it. Both clients derive the same slice and
	// therefore return that same message; those rows pin the agreement.
	return []storeIntegrityRow{
		sub("empty_file", static(""), notObject),
		sub("not_an_object", static("[]\n"), notObject),
		sub("json_null", static("null\n"), notObject),
		sub("version_zero", replaceOnce(`{"version":1,`, `{"version":0,`), "unsupported store envelope version 0"),
		sub("version_two", replaceOnce(`{"version":1,`, `{"version":2,`), "unsupported store envelope version 2"),
		sub("version_wrong_type", replaceOnce(`{"version":1,`, `{"version":"1",`), notCanonical),
		sub("version_null", replaceOnce(`{"version":1,`, `{"version":null,`), notCanonical),
		sub("unknown_field", replaceOnce(`{"version":1,`, `{"version":1,"extra":0,`), notCanonical),
		sub("field_order_swapped", func(t *testing.T, _, payload []byte) []byte {
			t.Helper()
			checksum := storeEnvelopeChecksum(storeEnvelopeChainState.domain, payload)
			return fmt.Appendf(nil, "{\"payload_b64\":%q,\"version\":1,\"checksum\":%q}\n",
				base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(checksum[:]))
		}, notCanonical),
		sub("duplicate_payload_b64_identical", replaceOnce(`,"checksum":"`, `,"payload_b64":"DUPLICATE","checksum":"`), notBase64),
		sub("duplicate_payload_b64_conflicting", replaceOnce(`,"checksum":"`, `,"payload_b64":"Zm9vYmFy","checksum":"`), notBase64),
		sub("duplicate_checksum_identical", duplicateChecksum(same), notBase64),
		sub("duplicate_checksum_conflicting", duplicateChecksum(fixed(strings.Repeat("b", 64))), notBase64),
		sub("missing_checksum", replaceOnce(`","checksum":"`, `","checksu":"`), notCanonical),
		sub("missing_payload_b64", replaceOnce(`,"payload_b64":"`, `,"payloadb64":"`), notCanonical),
		sub("trailing_second_json_value", func(_ *testing.T, valid, _ []byte) []byte {
			return append(append([]byte(nil), valid...), []byte(`{"version":1}`)...)
		}, notCanonical),
		sub("no_trailing_newline", func(_ *testing.T, valid, _ []byte) []byte {
			return bytes.TrimSuffix(valid, []byte("\n"))
		}, notCanonical),
		sub("leading_whitespace", func(_ *testing.T, valid, _ []byte) []byte {
			return append([]byte(" "), valid...)
		}, notCanonical),
		sub("checksum_uppercase_hex", replaceChecksum(strings.ToUpper), badChecksumHex),
		sub("checksum_not_hex", replaceChecksum(fixed(strings.Repeat("z", 64))), badChecksumHex),
		sub("checksum_short", replaceChecksum(fixed(strings.Repeat("a", 63))), notCanonical),
		sub("payload_b64_unpadded", reframe(func(encoded string) string {
			return strings.TrimRight(encoded, "=")
		}), notBase64),
		sub("payload_b64_embedded_newline", reframe(func(encoded string) string {
			return encoded[:4] + "\\n" + encoded[4:]
		}), notBase64),
		{
			name:    "checksum_mismatch_zeroed",
			body:    replaceChecksum(fixed(strings.Repeat("0", 64))),
			wantMsg: errStoreChecksumMismatch.Error(),
		},
		{
			// Shared with the undo-class rows (blockstore_test.go): one interior
			// symbol changes, so the file stays canonical base64 and only the
			// checksum can catch it.
			name: "payload_base64_bitflip",
			body: func(t *testing.T, valid, payload []byte) []byte {
				t.Helper()
				return replaceOnce(payloadB64Of(t, valid), flipBase64Symbol(payloadB64Of(t, valid)))(t, valid, payload)
			},
			wantMsg: errStoreChecksumMismatch.Error(),
		},
	}
}

func decodeValidEnvelope(t *testing.T, valid []byte) storeEnvelopeDisk {
	t.Helper()
	var probe storeEnvelopeDisk
	if err := json.Unmarshal(bytes.TrimSuffix(valid, []byte("\n")), &probe); err != nil {
		t.Fatalf("decode valid envelope: %v", err)
	}
	return probe
}

func hexChecksumOf(t *testing.T, valid []byte) string {
	return decodeValidEnvelope(t, valid).Checksum
}

func payloadB64Of(t *testing.T, valid []byte) string {
	return decodeValidEnvelope(t, valid).PayloadB64
}

// runStoreIntegrityRows plants each row at `path`, calls `load`, and pins the
// message, the ErrStoreIntegrity identity, the fs.ErrNotExist exclusion, and
// that the refusal never rewrote the file. Rust twin: run_store_integrity_rows.
func runStoreIntegrityRows(t *testing.T, path string, valid, payload []byte, load func() error, rows []storeIntegrityRow) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			body := row.body(t, valid, payload)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatalf("plant body: %v", err)
			}
			err := load()
			if err == nil {
				t.Fatalf("row must be rejected")
			}
			if row.wantMsg != "" && err.Error() != row.wantMsg {
				t.Fatalf("message = %q, want %q", err.Error(), row.wantMsg)
			}
			if row.wantSub != "" && !strings.Contains(err.Error(), row.wantSub) {
				t.Fatalf("message = %q, want substring %q", err.Error(), row.wantSub)
			}
			if got := errors.Is(err, ErrStoreIntegrity); got == row.notIntegrity {
				t.Fatalf("errors.Is(err, ErrStoreIntegrity) = %v for %v", got, err)
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("a corrupt file must never satisfy fs.ErrNotExist: %v", err)
			}
			after, readErr := os.ReadFile(path) // #nosec G304 -- test-local path.
			if readErr != nil {
				t.Fatalf("read back: %v", readErr)
			}
			if !bytes.Equal(after, body) {
				t.Fatalf("a failed load rewrote the file: got %q want %q", after, body)
			}
		})
	}
}

// TestLoadChainStateRejectsIntegrityFailures: every malformed, legacy,
// checksum-mismatched or parse-valid-but-edited chainstate.json fails BEFORE
// the inner decode, with the pinned identity, and never rides the absent-file
// fallback. Rust twin: `load_chainstate_rejects_integrity_failures`.
func TestLoadChainStateRejectsIntegrityFailures(t *testing.T) {
	dir := t.TempDir()
	path := ChainStatePath(dir)
	state := NewChainState()
	state.HasTip = true
	state.Height = 9
	state.AlreadyGenerated = 4_200
	state.TipHash = [32]byte{0x11, 0x22}
	if err := state.Save(path); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}
	valid, err := os.ReadFile(path) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read chainstate: %v", err)
	}
	payload, err := openStoreEnvelope(storeEnvelopeChainState, valid)
	if err != nil {
		t.Fatalf("open valid envelope: %v", err)
	}

	rows := append(storeEnvelopeSharedRejectRows(),
		storeIntegrityRow{
			// The whole pre-envelope file, byte for byte: what a first
			// post-upgrade startup finds on disk.
			name:    "legacy_unversioned_chainstate",
			body:    func(_ *testing.T, _, payload []byte) []byte { return payload },
			wantMsg: errStoreLegacyChainState.Error(),
		},
		storeIntegrityRow{
			name: "legacy_unversioned_with_trailing_garbage",
			body: func(_ *testing.T, _, payload []byte) []byte {
				return append(append([]byte(nil), payload...), []byte("trailing")...)
			},
			wantMsg: errStoreLegacyChainState.Error(),
		},
		storeIntegrityRow{
			// already_generated is a SCALAR outside the UTXO set and the tip is
			// preserved, so the payload stays parse-valid and every downstream
			// chainstate check passes: only the stale checksum catches it.
			name: "already_generated_edited_stale_checksum",
			body: func(t *testing.T, valid, payload []byte) []byte {
				t.Helper()
				edited := bytes.Replace(payload, []byte(`"already_generated": 4200`), []byte(`"already_generated": 4201`), 1)
				if bytes.Equal(edited, payload) {
					t.Fatalf("already_generated edit did not apply: %s", payload)
				}
				return []byte(strings.Replace(string(valid), payloadB64Of(t, valid),
					base64.StdEncoding.EncodeToString(edited), 1))
			},
			wantMsg: errStoreChecksumMismatch.Error(),
		},
		storeIntegrityRow{
			// A checksum-VALID envelope over a malformed inner payload: the
			// bytes on disk are intact, so this is a schema fault and stays
			// OUTSIDE the STORE_INTEGRITY identity.
			name: "inner_payload_malformed",
			body: func(t *testing.T, _, _ []byte) []byte {
				t.Helper()
				raw, err := marshalStoreEnvelope(storeEnvelopeChainState, []byte("{not json"))
				if err != nil {
					t.Fatalf("marshalStoreEnvelope: %v", err)
				}
				return raw
			},
			wantSub:      "decode chainstate",
			notIntegrity: true,
		},
	)
	runStoreIntegrityRows(t, path, valid, payload, func() error {
		_, err := LoadChainState(path)
		return err
	}, rows)

	// Positive control on the same path: the valid envelope still round-trips.
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("restore valid envelope: %v", err)
	}
	loaded, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("valid envelope must load: %v", err)
	}
	if !loaded.HasTip || loaded.Height != 9 || loaded.AlreadyGenerated != 4_200 {
		t.Fatalf("round trip lost state: %+v", loaded)
	}
}

// TestBlockstoreIndexRejectsIntegrityFailures: the same frame rows plus the
// canonical-row swap, through the real OpenBlockStore path. Rust twin:
// `blockstore_index_rejects_integrity_failures`.
func TestBlockstoreIndexRejectsIntegrityFailures(t *testing.T) {
	dir := t.TempDir()
	root := BlockStorePath(dir)
	store, _, _ := storeAtGenesis(t, dir)
	sibling := storeSameHeightSibling(t, store)
	marker := filepath.Join(root, "index.json")
	valid, err := os.ReadFile(marker) // #nosec G304 -- test-local path.
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	payload, err := openStoreEnvelope(storeEnvelopeBlockIndex, valid)
	if err != nil {
		t.Fatalf("open valid envelope: %v", err)
	}

	swapRow := func(t *testing.T, valid []byte, payload []byte, recompute bool) []byte {
		t.Helper()
		var index blockStoreIndexDisk
		if err := json.Unmarshal(payload, &index); err != nil {
			t.Fatalf("decode index payload: %v", err)
		}
		if len(index.Canonical) == 0 {
			t.Fatalf("index has no canonical rows")
		}
		index.Canonical[len(index.Canonical)-1] = hex.EncodeToString(sibling[:])
		edited, err := json.MarshalIndent(index, "", "  ")
		if err != nil {
			t.Fatalf("encode index payload: %v", err)
		}
		edited = append(edited, '\n')
		if recompute {
			raw, err := marshalStoreEnvelope(storeEnvelopeBlockIndex, edited)
			if err != nil {
				t.Fatalf("marshalStoreEnvelope: %v", err)
			}
			return raw
		}
		return []byte(strings.Replace(string(valid), payloadB64Of(t, valid),
			base64.StdEncoding.EncodeToString(edited), 1))
	}

	rows := append(storeEnvelopeSharedRejectRows(),
		storeIntegrityRow{
			name:    "legacy_unversioned_blockstore_index",
			body:    func(_ *testing.T, _, payload []byte) []byte { return payload },
			wantMsg: errStoreLegacyBlockIndex.Error(),
		},
		storeIntegrityRow{
			// The swapped row names a same-height sibling whose header, block
			// and undo artifacts ALL exist, so the stored-identity and undo
			// bindings both pass: only the envelope catches the file edit.
			name: "canonical_row_swapped_to_existing_sibling",
			body: func(t *testing.T, valid, payload []byte) []byte {
				return swapRow(t, valid, payload, false)
			},
			wantMsg: errStoreChecksumMismatch.Error(),
		},
		storeIntegrityRow{
			name: "inner_payload_malformed",
			body: func(t *testing.T, _, _ []byte) []byte {
				t.Helper()
				raw, err := marshalStoreEnvelope(storeEnvelopeBlockIndex, []byte(`{"version":1,"canonical":["zz"]}`))
				if err != nil {
					t.Fatalf("marshalStoreEnvelope: %v", err)
				}
				return raw
			},
			wantSub:      "decode blockstore index",
			notIntegrity: true,
		},
	)
	runStoreIntegrityRows(t, marker, valid, payload, func() error {
		_, err := OpenBlockStore(root)
		return err
	}, rows)

	// The envelope is the ONLY guard on that swap: with the checksum
	// recomputed over the swapped payload the store opens, which is exactly
	// why the checksum may never be waived.
	if err := os.WriteFile(marker, swapRow(t, valid, payload, true), 0o600); err != nil {
		t.Fatalf("plant recomputed swap: %v", err)
	}
	if _, err := OpenBlockStore(root); err != nil {
		t.Fatalf("recomputed-checksum swap must clear the envelope: %v", err)
	}

	if err := os.WriteFile(marker, valid, 0o600); err != nil {
		t.Fatalf("restore valid marker: %v", err)
	}
	if _, err := OpenBlockStore(root); err != nil {
		t.Fatalf("valid marker must open: %v", err)
	}
}

// storeSameHeightSibling writes a complete header/block/undo artifact set for a
// non-canonical block at the canonical tip's height, so a swapped index row can
// point at a block every downstream identity check accepts.
func storeSameHeightSibling(t *testing.T, store *BlockStore) [32]byte {
	t.Helper()
	parsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 0, 1)
	blockBytes := buildSingleTxBlock(t, parsed.Header.PrevBlockHash, consensus.POW_LIMIT, parsed.Header.Timestamp+1, coinbase)
	siblingParsed, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(sibling): %v", err)
	}
	hash, err := consensus.BlockHash(siblingParsed.HeaderBytes)
	if err != nil {
		t.Fatalf("BlockHash(sibling): %v", err)
	}
	if err := store.StoreBlock(hash, siblingParsed.HeaderBytes, blockBytes); err != nil {
		t.Fatalf("StoreBlock(sibling): %v", err)
	}
	if err := store.PutUndo(hash, &BlockUndo{BlockHeight: 0}); err != nil {
		t.Fatalf("PutUndo(sibling): %v", err)
	}
	return hash
}

// TestStartupGenesisAnchorMismatchFails pins the RUB-1134 genesis anchor: a
// non-empty canonical index whose row 0 is not the configured genesis hash is
// a foreign datadir and is refused BEFORE reconcile adopts the index; an EMPTY
// canonical index skips the anchor. Startup wiring lives in
// cmd/rubin-node/main.go, which calls this method before
// ReconcileChainStateWithBlockStore. Rust twin:
// `startup_genesis_anchor_mismatch_fails`.
func TestStartupGenesisAnchorMismatchFails(t *testing.T) {
	empty := mustCreateBlockStore(t, BlockStorePath(t.TempDir()))
	if err := empty.VerifyGenesisAnchor([32]byte{0xff}); err != nil {
		t.Fatalf("an empty canonical index must skip the anchor: %v", err)
	}

	dir := t.TempDir()
	store, _, cfg := storeAtGenesis(t, dir)
	if err := store.VerifyGenesisAnchor(devnetGenesisBlockHash); err != nil {
		t.Fatalf("a legitimate datadir must pass the anchor: %v", err)
	}

	// A coherent FOREIGN datadir: both envelopes verify and the tips agree, so
	// only the anchor refuses it.
	foreign := [32]byte{0xab}
	err := store.VerifyGenesisAnchor(foreign)
	if err == nil {
		t.Fatalf("a foreign canonical index must be refused")
	}
	if err.Error() != errStoreGenesisAnchor.Error() {
		t.Fatalf("message = %q, want %q", err.Error(), errStoreGenesisAnchor.Error())
	}
	if !errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("anchor failure must carry the ErrStoreIntegrity identity: %v", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("anchor failure must never satisfy fs.ErrNotExist: %v", err)
	}

	// The anchor precedes adoption: the refused store is untouched, and the
	// reconcile that would have adopted it is never reached on the wired path.
	snapshot, err := store.CanonicalIndexSnapshot()
	if err != nil || len(snapshot) != 1 || snapshot[0] != hex.EncodeToString(devnetGenesisBlockHash[:]) {
		t.Fatalf("anchor refusal mutated the canonical index: %v (%v)", snapshot, err)
	}
	if _, err := ReconcileChainStateWithBlockStore(NewChainState(), store, cfg); err != nil {
		t.Fatalf("reconcile over the anchored store: %v", err)
	}
}

// TestAbsentChainstateRebuildsByReplay: an ABSENT chainstate.json keeps the
// NewChainState-plus-full-validated-replay repair path over an enveloped
// index, and a corrupt one does NOT. Rust twin:
// `absent_chainstate_rebuilds_by_replay`.
func TestAbsentChainstateRebuildsByReplay(t *testing.T) {
	dir := t.TempDir()
	store, live, cfg := storeAtGenesis(t, dir)
	path := ChainStatePath(dir)
	if err := live.Save(path); err != nil {
		t.Fatalf("save chainstate: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove chainstate: %v", err)
	}

	rebuilt, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("absent chainstate must load as a fresh state: %v", err)
	}
	if rebuilt.HasTip || len(rebuilt.Utxos) != 0 {
		t.Fatalf("absent chainstate must load empty: %+v", rebuilt)
	}
	changed, err := ReconcileChainStateWithBlockStore(rebuilt, store, cfg)
	if err != nil {
		t.Fatalf("replay from an absent chainstate: %v", err)
	}
	if !changed || !rebuilt.HasTip || rebuilt.Height != 0 || rebuilt.TipHash != devnetGenesisBlockHash {
		t.Fatalf("replay did not rebuild the tip: changed=%v state=%+v", changed, rebuilt)
	}

	// The absent-file fallback must NOT extend to a corrupt file.
	if err := os.WriteFile(path, []byte("{\"version\":1}\n"), 0o600); err != nil {
		t.Fatalf("plant legacy chainstate: %v", err)
	}
	if _, err := LoadChainState(path); err == nil || err.Error() != errStoreLegacyChainState.Error() {
		t.Fatalf("legacy chainstate = %v, want %v", err, errStoreLegacyChainState)
	}
}

// TestReconcileCrashRecoveryOverEnvelopedFiles re-proves every baseline
// crash-recovery reconcile scenario over enveloped files: a crash at each
// atomic-write boundary (scratch open/write, rename, parent sync) for each of
// the two files, in BOTH write orders, then reopen from disk and reconcile.
// Rust twin: `reconcile_crash_recovery_over_enveloped_files`.
func TestReconcileCrashRecoveryOverEnvelopedFiles(t *testing.T) {
	for _, boundary := range []string{"scratch_open", "scratch_write", "rename", "parent_sync"} {
		for _, order := range []string{"index_first", "chainstate_first"} {
			t.Run(boundary+"_"+order, func(t *testing.T) {
				dir := t.TempDir()
				store, live, cfg := storeAtGenesis(t, dir)
				chainStatePath := ChainStatePath(dir)
				if err := live.Save(chainStatePath); err != nil {
					t.Fatalf("baseline save: %v", err)
				}
				block1 := appendCanonicalBlock(t, store, live, cfg)

				crashed := crashAtBoundary(t, boundary, order, store, live, chainStatePath)

				// Whatever the crash left on disk, the reopened datadir must be
				// envelope-clean and reconcile back to the canonical tip.
				reopened := mustOpenBlockStore(t, BlockStorePath(dir))
				state, err := LoadChainState(chainStatePath)
				if err != nil {
					t.Fatalf("post-crash chainstate load: %v", err)
				}
				if _, err := ReconcileChainStateWithBlockStore(state, reopened, cfg); err != nil {
					t.Fatalf("post-crash reconcile: %v", err)
				}
				tipHeight, tipHash, ok, err := reopened.Tip()
				if err != nil || !ok {
					t.Fatalf("post-crash tip: ok=%v err=%v", ok, err)
				}
				if !state.HasTip || state.Height != tipHeight || state.TipHash != tipHash {
					t.Fatalf("reconcile did not restore the canonical tip: state=%+v tip=(%d,%x)", state, tipHeight, tipHash)
				}
				if crashed && tipHash == block1 && state.Height != 1 {
					t.Fatalf("committed index row lost its replay: %+v", state)
				}
			})
		}
	}
}

// appendCanonicalBlock applies one real block on top of the canonical genesis
// and returns its hash.
func appendCanonicalBlock(t *testing.T, store *BlockStore, live *ChainState, cfg SyncConfig) [32]byte {
	t.Helper()
	engine, err := NewSyncEngine(live, store, cfg)
	if err != nil {
		t.Fatalf("NewSyncEngine: %v", err)
	}
	parsed, err := consensus.ParseBlockBytes(devnetGenesisBlockBytes)
	if err != nil {
		t.Fatalf("ParseBlockBytes(genesis): %v", err)
	}
	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block := buildSingleTxBlock(t, devnetGenesisBlockHash, consensus.POW_LIMIT, parsed.Header.Timestamp+1, coinbase)
	summary, err := engine.ApplyBlock(block, nil)
	if err != nil {
		t.Fatalf("ApplyBlock(block1): %v", err)
	}
	return summary.BlockHash
}

// crashAtBoundary injects one failure at one atomic-write boundary while the
// two files are written in the given order, scoped to the file the row names,
// and reports whether the injected write actually failed.
func crashAtBoundary(t *testing.T, boundary, order string, store *BlockStore, live *ChainState, chainStatePath string) bool {
	t.Helper()
	victim := store.indexPath
	if order == "chainstate_first" {
		victim = chainStatePath
	}
	armed := false
	withAtomicWriteOps(t, func(ops *atomicWriteOps) {
		previousOpen, previousRename, previousSync := ops.openScratch, ops.rename, ops.syncParent
		scratch := filepath.Join(filepath.Dir(victim), atomicWriteScratchLeaf)
		ops.openScratch = func(path string, flag int, mode os.FileMode) (atomicWriteScratchFile, error) {
			if path == scratch && boundary == "scratch_open" {
				armed = true
				return nil, os.ErrPermission
			}
			if path == scratch && boundary == "scratch_write" {
				armed = true
				return &atomicScratchStub{writeErr: os.ErrPermission}, nil
			}
			return previousOpen(path, flag, mode)
		}
		ops.rename = func(from, to string) error {
			if to == victim && boundary == "rename" {
				armed = true
				return os.ErrPermission
			}
			return previousRename(from, to)
		}
		ops.syncParent = func(path string) error {
			if path == filepath.Dir(victim) && boundary == "parent_sync" {
				armed = true
				return os.ErrPermission
			}
			return previousSync(path)
		}
	})

	writes := []func() error{
		func() error { return saveBlockStoreIndex(store.indexPath, store.index) },
		func() error { return live.Save(chainStatePath) },
	}
	if order == "chainstate_first" {
		writes[0], writes[1] = writes[1], writes[0]
	}
	failed := false
	for _, write := range writes {
		if err := write(); err != nil {
			failed = true
			break
		}
	}
	if !armed {
		t.Fatalf("boundary %s (%s) was never reached", boundary, order)
	}
	return failed
}
