package node

import (
	"bytes"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func TestLoadChainState_InvalidFileName(t *testing.T) {
	// readFileFromDir rejects "." and ".." and LoadChainState should surface the error.
	st, err := LoadChainState(filepath.Join(t.TempDir(), "."))
	if err == nil {
		t.Fatalf("expected error")
	}
	if st != nil {
		t.Fatalf("state should be nil on read error")
	}
}

func TestLoadChainState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chainstate.json")
	// RUB-1134: planted INSIDE a valid frame so the row still reaches the INNER
	// chainStateDisk decode rather than the legacy verdict (owned by
	// TestLoadChainStateRejectsIntegrityFailures).
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, []byte("{\n"))
	if err != nil {
		t.Fatalf("wrap chainstate: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadChainState(path); err == nil {
		t.Fatalf("expected error")
	} else if errors.Is(err, ErrStoreIntegrity) {
		t.Fatalf("row must fail on the inner decode class, got %v", err)
	}
}

func TestChainStateSchemaV1ReadAndV2RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chainstate.json")
	v1 := []byte(`{"tip_hash":"` + strings.Repeat("00", 32) + `","utxos":[],"height":9,"already_generated":18446744073709551615,"version":1,"has_tip":true}`)
	writeChainStatePayload(t, path, v1)
	loaded, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("LoadChainState(v1): %v", err)
	}
	if loaded.AlreadyGenerated != consensus.Uint128FromU64(^uint64(0)) {
		t.Fatalf("v1 supply=%s, want u64 max", loaded.AlreadyGenerated.String())
	}

	reachableMax := reachableMaximumAccumulatedSubsidy(t)
	loaded.AlreadyGenerated = reachableMax
	if err := loaded.Save(path); err != nil {
		t.Fatalf("Save(v2): %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(v2): %v", err)
	}
	payload, err := openStoreEnvelope(storeEnvelopeChainState, raw)
	if err != nil {
		t.Fatalf("openStoreEnvelope(v2): %v", err)
	}
	if !bytes.Contains(payload, []byte(`"already_generated": "350965446908158964928367166"`)) ||
		!bytes.Contains(payload, []byte(`"version": 2`)) {
		t.Fatalf("v2 payload lacks canonical string/version: %s", payload)
	}
	roundTrip, err := LoadChainState(path)
	if err != nil {
		t.Fatalf("LoadChainState(v2): %v", err)
	}
	if roundTrip.AlreadyGenerated != reachableMax {
		t.Fatalf("v2 supply=%s, want %s", roundTrip.AlreadyGenerated.String(), reachableMax.String())
	}

	const canonicalV2Payload = `{
  "tip_hash": "1111111111111111111111111111111111111111111111111111111111111111",
  "utxos": [
    {
      "txid": "2222222222222222222222222222222222222222222222222222222222222222",
      "covenant_data": "aabb",
      "value": 9,
      "creation_height": 5,
      "vout": 3,
      "covenant_type": 1,
      "created_by_coinbase": false
    }
  ],
  "height": 7,
  "already_generated": "18446744073709551615",
  "version": 2,
  "has_tip": true
}
`
	const canonicalV2Envelope = `{"version":1,"payload_b64":"ewogICJ0aXBfaGFzaCI6ICIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwKICAidXR4b3MiOiBbCiAgICB7CiAgICAgICJ0eGlkIjogIjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLAogICAgICAiY292ZW5hbnRfZGF0YSI6ICJhYWJiIiwKICAgICAgInZhbHVlIjogOSwKICAgICAgImNyZWF0aW9uX2hlaWdodCI6IDUsCiAgICAgICJ2b3V0IjogMywKICAgICAgImNvdmVuYW50X3R5cGUiOiAxLAogICAgICAiY3JlYXRlZF9ieV9jb2luYmFzZSI6IGZhbHNlCiAgICB9CiAgXSwKICAiaGVpZ2h0IjogNywKICAiYWxyZWFkeV9nZW5lcmF0ZWQiOiAiMTg0NDY3NDQwNzM3MDk1NTE2MTUiLAogICJ2ZXJzaW9uIjogMiwKICAiaGFzX3RpcCI6IHRydWUKfQo=","checksum":"30b3867741b76acdc408c8e668a5c015dec9660a4403df4cdb8451f0379c737b"}
`
	const historicalGoV1 = `{"tip_hash":"1111111111111111111111111111111111111111111111111111111111111111","utxos":[{"txid":"2222222222222222222222222222222222222222222222222222222222222222","covenant_data":"aabb","value":9,"creation_height":5,"vout":3,"covenant_type":1,"created_by_coinbase":false}],"height":7,"already_generated":18446744073709551615,"version":1,"has_tip":true}`
	const historicalRustV1 = `{"version":1,"has_tip":true,"height":7,"tip_hash":"1111111111111111111111111111111111111111111111111111111111111111","already_generated":18446744073709551615,"utxos":[{"txid":"2222222222222222222222222222222222222222222222222222222222222222","vout":3,"value":9,"covenant_type":1,"covenant_data":"aabb","creation_height":5,"created_by_coinbase":false}]}`
	var tipHash, txid [32]byte
	for i := range tipHash {
		tipHash[i], txid[i] = 0x11, 0x22
	}
	wantState := NewChainState()
	wantState.HasTip, wantState.Height, wantState.TipHash = true, 7, tipHash
	wantState.AlreadyGenerated = consensus.Uint128FromU64(^uint64(0))
	wantState.Utxos[consensus.Outpoint{Txid: txid, Vout: 3}] = consensus.UtxoEntry{Value: 9, CovenantType: 1, CovenantData: []byte{0xaa, 0xbb}, CreationHeight: 5}
	if err := wantState.Save(path); err != nil {
		t.Fatalf("save canonical v2: %v", err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != canonicalV2Envelope {
		t.Fatalf("canonical v2 envelope mismatch: err=%v\n%s", err, raw)
	}
	if payload, err := openStoreEnvelope(storeEnvelopeChainState, []byte(canonicalV2Envelope)); err != nil || string(payload) != canonicalV2Payload {
		t.Fatalf("canonical v2 payload mismatch: err=%v\n%s", err, payload)
	}
	for _, tc := range []struct{ name, raw string }{{"canonical_v2", canonicalV2Envelope}, {"historical_go_v1", historicalGoV1}, {"historical_rust_v1", historicalRustV1}} {
		if tc.name == "canonical_v2" {
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatalf("seed %s: %v", tc.name, err)
			}
		} else {
			writeChainStatePayload(t, path, []byte(tc.raw))
		}
		before, _ := os.ReadFile(path)
		loaded, err := LoadChainState(path)
		if err != nil || !equalChainState(loaded, wantState) {
			t.Fatalf("load %s: state=%+v err=%v", tc.name, loaded, err)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(after, before) {
			t.Fatalf("load rewrote %s", tc.name)
		}
		if err := loaded.Save(path); err != nil {
			t.Fatalf("save migrated %s: %v", tc.name, err)
		}
		if migrated, _ := os.ReadFile(path); string(migrated) != canonicalV2Envelope {
			t.Fatalf("%s did not save canonical v2 bytes\n%s", tc.name, migrated)
		}
	}
}

func TestChainStateSchemaErrorsAndPrecedence(t *testing.T) {
	zeroHash := strings.Repeat("00", 32)
	validUtxo := `{"txid":"` + strings.Repeat("11", 32) + `","covenant_data":"","value":1,"creation_height":0,"vout":0,"covenant_type":0,"created_by_coinbase":false}`
	covenantUtxo := strings.Replace(validUtxo, `"covenant_data":""`, `"covenant_data":"aa"`, 1)
	wrapV2 := func(utxos string) string {
		return `{"tip_hash":"` + zeroHash + `","utxos":` + utxos + `,"height":0,"already_generated":"0","version":2,"has_tip":false}`
	}
	validV2 := wrapV2("[]")
	for _, tc := range []struct {
		name    string
		payload string
		want    string
	}{
		{name: "missing_version", payload: `{}`, want: "CHAINSTATE_SCHEMA: missing version"},
		{name: "null_version", payload: `{"version":null,"already_generated":"bad"}`, want: "CHAINSTATE_SCHEMA: missing version"},
		{name: "null_duplicate_version", payload: `{"version":null,"version":2,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: missing version"},
		{name: "duplicate_version", payload: `{"version":2,"version":2,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: duplicate version"},
		{name: "duplicate_version_later_extreme", payload: `{"version":2,"version":1e400,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: duplicate version"},
		{name: "null_version_later_extreme", payload: `{"version":null,"version":1e400,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: missing version"},
		{name: "extreme_version_then_duplicate", payload: `{"version":1e400,"version":2,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: duplicate version"},
		{name: "extreme_version_then_null", payload: `{"version":1e400,"version":null,"already_generated":"0","has_tip":false,"height":0,"tip_hash":"` + strings.Repeat("00", 32) + `","utxos":[]}`, want: "CHAINSTATE_SCHEMA: missing version"},
		{name: "invalid_version_before_supply", payload: `{"version":"2","already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "bool_version_before_supply", payload: `{"version":false,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "array_version_before_supply", payload: `{"version":[],"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "object_version_before_supply", payload: `{"version":{},"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "negative_version_before_supply", payload: `{"version":-1,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "fractional_version_before_supply", payload: `{"version":2.0,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "exponent_version_before_supply", payload: `{"version":2e0,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "extreme_exponent_version_before_supply", payload: `{"version":1e400,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "version_range_before_supply", payload: `{"version":4294967296,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "unsupported_before_supply", payload: `{"version":3,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: unsupported version 3"},
		{name: "missing_supply", payload: `{"version":2}`, want: "CHAINSTATE_SCHEMA: missing already_generated"},
		{name: "null_supply", payload: `{"version":2,"already_generated":null}`, want: "CHAINSTATE_SCHEMA: missing already_generated"},
		{name: "null_duplicate_supply", payload: `{"version":2,"already_generated":null,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: missing already_generated"},
		{name: "duplicate_supply", payload: `{"version":2,"already_generated":"0","already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: duplicate already_generated"},
		{name: "duplicate_supply_later_extreme", payload: `{"version":2,"already_generated":"0","already_generated":1e400}`, want: "CHAINSTATE_SCHEMA: duplicate already_generated"},
		{name: "null_supply_later_extreme", payload: `{"version":2,"already_generated":null,"already_generated":1e400}`, want: "CHAINSTATE_SCHEMA: missing already_generated"},
		{name: "extreme_supply_then_duplicate", payload: `{"version":2,"already_generated":1e400,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: duplicate already_generated"},
		{name: "extreme_supply_then_null", payload: `{"version":2,"already_generated":1e400,"already_generated":null,"has_tip":false,"height":0,"tip_hash":"` + strings.Repeat("00", 32) + `","utxos":[]}`, want: "CHAINSTATE_SCHEMA: missing already_generated"},
		{name: "v1_string", payload: `{"version":1,"already_generated":"0"}`, want: "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_negative", payload: `{"version":1,"already_generated":-1}`, want: "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_fraction", payload: `{"version":1,"already_generated":0.0}`, want: "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_overflow", payload: `{"version":1,"already_generated":18446744073709551616}`, want: "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64"},
		{name: "v1_extreme_exponent", payload: `{"version":1,"already_generated":1e400}`, want: "CHAINSTATE_SCHEMA: v1 already_generated must be a nonnegative JSON integer through u64"},
		{name: "v2_number", payload: `{"version":2,"already_generated":0}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_extreme_number", payload: `{"version":2,"already_generated":1e400}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "remaining_before_invalid_v2_supply", payload: `{"height":1e400,"version":2,"already_generated":0}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "invalid_v2_supply_before_remaining", payload: `{"version":2,"already_generated":0,"height":1e400}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_leading_zero", payload: `{"version":2,"already_generated":"00"}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_escaped_zero", payload: `{"version":2,"already_generated":"\u0030"}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "v2_overflow", payload: `{"version":2,"already_generated":"340282366920938463463374607431768211456"}`, want: "CHAINSTATE_SCHEMA: v2 already_generated must be a canonical unsigned decimal string within u128"},
		{name: "remaining_missing", payload: strings.Replace(validV2, `,"has_tip":false`, "", 1), want: chainStatePayloadNotCanonical},
		{name: "remaining_null", payload: strings.Replace(validV2, `"has_tip":false`, `"has_tip":null`, 1), want: chainStatePayloadNotCanonical},
		{name: "remaining_duplicate", payload: strings.Replace(validV2, `"height":0`, `"height":0,"height":0`, 1), want: chainStatePayloadNotCanonical},
		{name: "remaining_unknown", payload: strings.Replace(validV2, `{`, `{"extra":0,`, 1), want: chainStatePayloadNotCanonical},
		{name: "remaining_wrong_range", payload: strings.Replace(validV2, `"height":0`, `"height":1e400`, 1), want: chainStatePayloadNotCanonical},
		{name: "utxos_null", payload: wrapV2("null"), want: chainStatePayloadNotCanonical},
		{name: "utxos_non_array", payload: wrapV2(`{}`), want: chainStatePayloadNotCanonical},
		{name: "utxo_non_object", payload: wrapV2(`[0]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_missing", payload: wrapV2(`[` + strings.Replace(validUtxo, `,"created_by_coinbase":false`, "", 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_null", payload: wrapV2(`[` + strings.Replace(validUtxo, `"created_by_coinbase":false`, `"created_by_coinbase":null`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_duplicate", payload: wrapV2(`[` + strings.Replace(validUtxo, `"vout":0`, `"vout":0,"vout":0`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_unknown", payload: wrapV2(`[` + strings.Replace(validUtxo, `}`, `,"extra":0}`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_wrong_range", payload: wrapV2(`[` + strings.Replace(validUtxo, `"vout":0`, `"vout":4294967296`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_wrong_token", payload: wrapV2(`[` + strings.Replace(validUtxo, `"created_by_coinbase":false`, `"created_by_coinbase":0`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "tip_hash_leading", payload: strings.Replace(validV2, zeroHash, " "+zeroHash, 1), want: chainStatePayloadNotCanonical},
		{name: "tip_hash_trailing", payload: strings.Replace(validV2, zeroHash, zeroHash+" ", 1), want: chainStatePayloadNotCanonical},
		{name: "tip_hash_vertical_tab", payload: strings.Replace(validV2, zeroHash, `\u000b`+zeroHash, 1), want: chainStatePayloadNotCanonical},
		{name: "utxo_txid_leading", payload: wrapV2(`[` + strings.Replace(validUtxo, `"txid":"`, `"txid":" `, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_txid_trailing", payload: wrapV2(`[` + strings.Replace(validUtxo, strings.Repeat("11", 32)+`"`, strings.Repeat("11", 32)+` "`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_txid_vertical_tab", payload: wrapV2(`[` + strings.Replace(validUtxo, `"txid":"`, `"txid":"\u000b`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_covenant_leading", payload: wrapV2(`[` + strings.Replace(covenantUtxo, `"covenant_data":"aa"`, `"covenant_data":" aa"`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_covenant_trailing", payload: wrapV2(`[` + strings.Replace(covenantUtxo, `"covenant_data":"aa"`, `"covenant_data":"aa "`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "utxo_covenant_vertical_tab", payload: wrapV2(`[` + strings.Replace(covenantUtxo, `"covenant_data":"aa"`, `"covenant_data":"\u000baa"`, 1) + `]`), want: chainStatePayloadNotCanonical},
		{name: "mixed_invalid_targets_and_remaining", payload: strings.NewReplacer(`"version":2`, `"version":"2"`, `"already_generated":"0"`, `"already_generated":0`, `"height":0`, `"height":1e400`).Replace(validV2), want: "CHAINSTATE_SCHEMA: version must be a canonical unsigned JSON integer through u32"},
		{name: "empty_object_with_trailing_object", payload: `{}{}`, want: "decode chainstate: trailing content"},
		{name: "malformed_trailing_content", payload: validV2 + `x`, want: "decode chainstate: trailing content"},
		{name: "trailing_content", payload: `{"version":2,"already_generated":"0"}{}`, want: "decode chainstate: trailing content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "chainstate.json")
			writeChainStatePayload(t, path, []byte(tc.payload))
			got, err := LoadChainState(path)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err=%v, want exactly %q", err, tc.want)
			}
			if got != nil {
				t.Fatalf("schema failure returned state: %+v", got)
			}
			if errors.Is(err, ErrStoreIntegrity) {
				t.Fatalf("inner schema error gained STORE_INTEGRITY: %v", err)
			}
		})
	}

	path := filepath.Join(t.TempDir(), "chainstate.json")
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, []byte(`{"version":2,"already_generated":0}`))
	if err != nil {
		t.Fatalf("marshalStoreEnvelope: %v", err)
	}
	if raw[len(raw)-4] == '0' {
		raw[len(raw)-4] = '1'
	} else {
		raw[len(raw)-4] = '0'
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadChainState(path); !errors.Is(err, ErrStoreIntegrity) || err.Error() != errStoreChecksumMismatch.Error() {
		t.Fatalf("outer error=%v, want STORE_INTEGRITY checksum precedence", err)
	}
}

func writeChainStatePayload(t *testing.T, path string, payload []byte) {
	t.Helper()
	raw, err := marshalStoreEnvelope(storeEnvelopeChainState, payload)
	if err != nil {
		t.Fatalf("marshalStoreEnvelope: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func reachableMaximumAccumulatedSubsidy(t *testing.T) consensus.Uint128 {
	t.Helper()
	height := uint64(1)
	accumulated := uint64(0)
	for {
		baseReward := (uint64(consensus.MINEABLE_CAP) - accumulated) >> consensus.EMISSION_SPEED_FACTOR
		subsidy := baseReward
		if subsidy < consensus.TAIL_EMISSION_PER_BLOCK {
			subsidy = consensus.TAIL_EMISSION_PER_BLOCK
		}
		if subsidy == consensus.TAIL_EMISSION_PER_BLOCK {
			break
		}
		if ^uint64(0)-accumulated < subsidy {
			t.Fatal("pre-tail accumulated subsidy overflowed u64")
		}
		accumulated += subsidy
		height++
	}
	if height != 5_771_107 || accumulated != 4_880_049_936_696_791 {
		t.Fatalf("first tail boundary=(height %d, accumulated %d)", height, accumulated)
	}
	if got := consensus.BlockSubsidy(height, accumulated); got != consensus.TAIL_EMISSION_PER_BLOCK {
		t.Fatalf("BlockSubsidy(first tail)=%d, want %d", got, consensus.TAIL_EMISSION_PER_BLOCK)
	}

	tailBlocks := new(big.Int).SetUint64(^uint64(0) - height + 1)
	total := new(big.Int).Mul(tailBlocks, new(big.Int).SetUint64(consensus.TAIL_EMISSION_PER_BLOCK))
	total.Add(total, new(big.Int).SetUint64(accumulated))
	want, err := consensus.ParseUint128Decimal("350965446908158964928367166")
	if err != nil {
		t.Fatalf("ParseUint128Decimal(reachable max): %v", err)
	}
	if total.Cmp(want.Big()) != 0 {
		t.Fatalf("reachable accumulated subsidy=%s, want %s", total, want.String())
	}
	return want
}

func TestChainStateSave_NilReceiver(t *testing.T) {
	var st *ChainState
	if err := st.Save(filepath.Join(t.TempDir(), "x.json")); err == nil {
		t.Fatalf("expected error")
	}
}

func TestNextBlockContext_Errors(t *testing.T) {
	if _, _, err := nextBlockContext(nil); err == nil {
		t.Fatalf("expected error")
	}
	if _, _, err := nextBlockContext(&ChainState{HasTip: true, Height: ^uint64(0)}); err == nil {
		t.Fatalf("expected height overflow error")
	}
}

func TestStateToDisk_NilReceiver(t *testing.T) {
	if _, err := stateToDisk(nil); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCopySelectedUtxoSetCopiesRequestedEntries(t *testing.T) {
	t.Parallel()

	var txidA, txidB [32]byte
	txidA[0] = 0xaa
	txidB[0] = 0xbb
	opA := consensus.Outpoint{Txid: txidA, Vout: 1}
	opB := consensus.Outpoint{Txid: txidB, Vout: 2}
	src := map[consensus.Outpoint]consensus.UtxoEntry{
		opA: {
			Value:             11,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      []byte{0x01, 0x02},
			CreationHeight:    7,
			CreatedByCoinbase: true,
		},
		opB: {
			Value:             22,
			CovenantType:      consensus.COV_TYPE_P2PK,
			CovenantData:      []byte{0x03, 0x04},
			CreationHeight:    8,
			CreatedByCoinbase: false,
		},
	}

	out := copySelectedUtxoSet(src, []consensus.Outpoint{opA, opA, {Txid: [32]byte{0xcc}, Vout: 9}})
	if len(out) != 1 {
		t.Fatalf("len(out)=%d, want 1", len(out))
	}
	if _, ok := out[opA]; !ok {
		t.Fatal("copied set missing requested outpoint")
	}
	if _, ok := out[opB]; ok {
		t.Fatal("copied set unexpectedly contains unrelated outpoint")
	}

	entry := out[opA]
	entry.CovenantData[0] ^= 0xff
	out[opA] = entry
	if src[opA].CovenantData[0] == out[opA].CovenantData[0] {
		t.Fatal("copySelectedUtxoSet aliased covenant data")
	}
}

func TestCountExistingUniqueOutpointsSkipsMissingAndDuplicates(t *testing.T) {
	t.Parallel()

	var txidA, txidB [32]byte
	txidA[0] = 0xaa
	txidB[0] = 0xbb
	opA := consensus.Outpoint{Txid: txidA, Vout: 1}
	opB := consensus.Outpoint{Txid: txidB, Vout: 2}

	src := map[consensus.Outpoint]consensus.UtxoEntry{
		opA: {Value: 11, CovenantType: consensus.COV_TYPE_P2PK},
	}

	count := countExistingUniqueOutpoints(src, []consensus.Outpoint{opA, opA, opB})
	if count != 1 {
		t.Fatalf("countExistingUniqueOutpoints=%d, want 1", count)
	}
}

func TestStateToDisk_SortsByVoutWhenSameTxid(t *testing.T) {
	txid := mustHash32Hex(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	st := &ChainState{
		HasTip:           true,
		Height:           1,
		TipHash:          txid,
		AlreadyGenerated: consensus.Uint128{},
		Utxos: map[consensus.Outpoint]consensus.UtxoEntry{
			{Txid: txid, Vout: 2}: {Value: 1, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: []byte{0x01}},
			{Txid: txid, Vout: 1}: {Value: 2, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: []byte{0x02}},
		},
	}
	disk, err := stateToDisk(st)
	if err != nil {
		t.Fatalf("stateToDisk: %v", err)
	}
	if len(disk.Utxos) != 2 {
		t.Fatalf("utxos=%d, want 2", len(disk.Utxos))
	}
	if disk.Utxos[0].Txid != disk.Utxos[1].Txid {
		t.Fatalf("expected same txid in both entries")
	}
	if disk.Utxos[0].Vout != 1 || disk.Utxos[1].Vout != 2 {
		t.Fatalf("vout order=%d,%d; want 1,2", disk.Utxos[0].Vout, disk.Utxos[1].Vout)
	}
}

func TestChainStateFromDisk_Errors(t *testing.T) {
	zeros64 := strings.Repeat("00", 32)

	t.Run("version_mismatch", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{Version: chainStateDiskVersion + 1})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_tip_hash", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{Version: chainStateDiskVersion, TipHash: "zz"})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_utxo_txid", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: "zz", Vout: 0, CovenantData: ""},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("bad_utxo_covenant_data", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: zeros64, Vout: 0, CovenantData: "abc"},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("duplicate_outpoint", func(t *testing.T) {
		_, err := chainStateFromDisk(chainStateDisk{
			Version: chainStateDiskVersion,
			TipHash: zeros64,
			Utxos: []utxoDiskEntry{
				{Txid: zeros64, Vout: 1, CovenantData: ""},
				{Txid: zeros64, Vout: 1, CovenantData: ""},
			},
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestParseHex_Errors(t *testing.T) {
	if _, err := parseHex("x", "a"); err == nil {
		t.Fatalf("expected odd-length error")
	}
	if _, err := parseHex("x", "zz"); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestParseHex32_Errors(t *testing.T) {
	if _, err := parseHex32("x", ""); err == nil {
		t.Fatalf("expected length mismatch error")
	}
}

func TestWriteFileAtomic_Errors(t *testing.T) {
	t.Run("write_fails_missing_dir", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nope", "x.json")
		if err := writeFileAtomic(path, []byte("x"), 0o600); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("rename_fails_target_is_dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeFileAtomic(dir, []byte("x"), 0o600); err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestDevnetGenesisBlockBytes_NonEmpty(t *testing.T) {
	raw := DevnetGenesisBlockBytes()
	if len(raw) == 0 {
		t.Fatal("DevnetGenesisBlockBytes returned empty slice")
	}
	// Defensive copy: mutating returned slice must not affect source.
	raw[0] = 0xFF
	raw2 := DevnetGenesisBlockBytes()
	if raw2[0] == 0xFF {
		t.Fatal("DevnetGenesisBlockBytes must return a defensive copy")
	}
}

func TestDevnetGenesisBlockHash_NonZero(t *testing.T) {
	hash := DevnetGenesisBlockHash()
	var zero [32]byte
	if hash == zero {
		t.Fatal("DevnetGenesisBlockHash returned all zeros")
	}
}

func TestChainStateConnectBlock_NilReceiver(t *testing.T) {
	var st *ChainState
	if _, err := st.ConnectBlock(nil, nil, nil, [32]byte{}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestChainStateConnectBlock_NilUtxoMapInitialized(t *testing.T) {
	target := consensus.POW_LIMIT
	st := &ChainState{HasTip: true, Height: 0, Utxos: nil}
	st.TipHash = mustHash32Hex(t, "1111111111111111111111111111111111111111111111111111111111111111")

	coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, 1)
	block := buildSingleTxBlock(t, st.TipHash, target, 2, coinbase)

	if _, err := st.ConnectBlock(block, &target, nil, devnetGenesisChainID); err != nil {
		t.Fatalf("ConnectBlock: %v", err)
	}
	if st.Utxos == nil {
		t.Fatalf("utxo map should be initialized")
	}
}

func TestChainStateConnectSupplyOverflowPreservesNonzeroState(t *testing.T) {
	const height = uint64(5_771_107)
	target := consensus.POW_LIMIT

	for _, parallel := range []bool{false, true} {
		path := "sequential"
		if parallel {
			path = "parallel"
		}
		t.Run(path, func(t *testing.T) {
			tip := mustHash32Hex(t, "1212121212121212121212121212121212121212121212121212121212121212")
			originalUtxos := map[consensus.Outpoint]consensus.UtxoEntry{
				{Txid: mustHash32Hex(t, "3434343434343434343434343434343434343434343434343434343434343434"), Vout: 2}: {
					Value:             17,
					CovenantType:      consensus.COV_TYPE_P2PK,
					CovenantData:      testP2PKCovenantData(0x34),
					CreationHeight:    11,
					CreatedByCoinbase: false,
				},
			}
			st := &ChainState{
				HasTip:           true,
				Height:           height - 1,
				TipHash:          tip,
				AlreadyGenerated: consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)},
				Utxos:            originalUtxos,
			}
			before, err := stateToDisk(st)
			if err != nil {
				t.Fatalf("stateToDisk(before): %v", err)
			}
			coinbase := coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, height, consensus.TAIL_EMISSION_PER_BLOCK)
			block := buildSingleTxBlock(t, tip, target, height, coinbase)

			var summary *ChainStateConnectSummary
			if parallel {
				summary, err = st.ConnectBlockParallelSigs(block, &target, nil, devnetGenesisChainID, 2)
			} else {
				summary, err = st.ConnectBlock(block, &target, nil, devnetGenesisChainID)
			}
			if err == nil || summary != nil || err.Error() != "BLOCK_ERR_PARSE: already_generated overflow" {
				t.Fatalf("summary=%#v err=%v, want durable supply overflow", summary, err)
			}
			after, diskErr := stateToDisk(st)
			if diskErr != nil {
				t.Fatalf("stateToDisk(after): %v", diskErr)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("durable state changed on supply overflow")
			}
			probe := consensus.Outpoint{Txid: [32]byte{0x56}, Vout: 3}
			originalUtxos[probe] = consensus.UtxoEntry{Value: 18}
			if _, ok := st.Utxos[probe]; !ok {
				t.Fatal("durable UTXO map was replaced on supply overflow")
			}
		})
	}
}

func TestChainStateConnectDisconnectSupplyBoundaries(t *testing.T) {
	maxU128 := consensus.Uint128{Hi: ^uint64(0), Lo: ^uint64(0)}
	for _, tc := range []struct {
		name    string
		before  consensus.Uint128
		genesis bool
	}{
		{name: "zero", before: consensus.Uint128{}, genesis: true},
		{name: "u64_max", before: consensus.Uint128FromU64(^uint64(0))},
		{name: "u64_max_plus_one", before: consensus.Uint128{Hi: 1}},
		{name: "reachable_max", before: reachableMaximumAccumulatedSubsidy(t)},
		{name: "u128_max", before: maxU128, genesis: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := consensus.POW_LIMIT
			state := NewChainState()
			state.AlreadyGenerated = tc.before
			block := devnetGenesisBlockBytes
			if !tc.genesis {
				state.HasTip = true
				state.TipHash = [32]byte{0x41}
				block = buildSingleTxBlock(t, state.TipHash, target, 2,
					coinbaseWithWitnessCommitmentAndP2PKValueAtHeight(t, 1, consensus.TAIL_EMISSION_PER_BLOCK))
			}
			parsed, err := consensus.ParseBlockBytes(block)
			if err != nil {
				t.Fatalf("ParseBlockBytes: %v", err)
			}
			undoHeight := state.Height + 1
			if tc.genesis {
				undoHeight = 0
			}
			undo, err := buildBlockUndo(state, parsed, undoHeight)
			if err != nil {
				t.Fatalf("buildBlockUndo: %v", err)
			}
			wantAfter := tc.before
			if !tc.genesis {
				var ok bool
				wantAfter, ok = tc.before.CheckedAdd(consensus.Uint128FromU64(consensus.TAIL_EMISSION_PER_BLOCK))
				if !ok {
					t.Fatal("test setup overflow")
				}
			}
			summary, err := state.ConnectBlock(block, &target, nil, devnetGenesisChainID)
			if err != nil {
				t.Fatalf("ConnectBlock: %v", err)
			}
			if summary.AlreadyGenerated != tc.before || summary.AlreadyGeneratedN1 != wantAfter || state.AlreadyGenerated != wantAfter {
				t.Fatalf("connect supply=%s -> %s state=%s, want %s -> %s", summary.AlreadyGenerated.String(), summary.AlreadyGeneratedN1.String(), state.AlreadyGenerated.String(), tc.before.String(), wantAfter.String())
			}
			disconnected, err := state.DisconnectBlock(block, undo)
			if err != nil {
				t.Fatalf("DisconnectBlock: %v", err)
			}
			if disconnected.AlreadyGenerated != tc.before || state.AlreadyGenerated != tc.before {
				t.Fatalf("disconnect supply summary=%s state=%s, want %s", disconnected.AlreadyGenerated.String(), state.AlreadyGenerated.String(), tc.before.String())
			}
		})
	}
}

func TestApplyConnectedBlockConvertsAllSupplyValuesBeforeMutation(t *testing.T) {
	wide := consensus.Uint128{Hi: 1}
	wideN1, ok := wide.CheckedAdd(consensus.Uint128FromU64(1))
	if !ok {
		t.Fatal("wide test setup overflow")
	}
	t.Run("accepts_above_u64", func(t *testing.T) {
		st := &ChainState{Utxos: map[consensus.Outpoint]consensus.UtxoEntry{}}
		work := &consensus.InMemoryChainState{AlreadyGenerated: wide.Big(), Utxos: map[consensus.Outpoint]consensus.UtxoEntry{}}
		result := &consensus.ConnectBlockBasicSummary{AlreadyGenerated: wide, AlreadyGeneratedN1: wideN1}
		out, err := st.applyConnectedBlockLocked(0, [32]byte{0x74}, work, result)
		if err != nil {
			t.Fatalf("applyConnectedBlockLocked: %v", err)
		}
		if st.AlreadyGenerated != wide || out.AlreadyGenerated != wide || out.AlreadyGeneratedN1 != wideN1 {
			t.Fatalf("wide supply narrowed: state=%s summary=%s->%s", st.AlreadyGenerated.String(), out.AlreadyGenerated.String(), out.AlreadyGeneratedN1.String())
		}
	})

	t.Run("rejects_above_u128_before_mutation", func(t *testing.T) {
		tip := [32]byte{0x71}
		originalUtxos := map[consensus.Outpoint]consensus.UtxoEntry{
			{Txid: [32]byte{0x72}, Vout: 1}: {Value: 21, CovenantData: []byte{0xaa}},
		}
		st := &ChainState{HasTip: true, Height: 7, TipHash: tip, AlreadyGenerated: consensus.Uint128FromU64(9), Utxos: originalUtxos}
		beforeState, err := stateToDisk(st)
		if err != nil {
			t.Fatalf("stateToDisk(before): %v", err)
		}
		work := &consensus.InMemoryChainState{
			AlreadyGenerated: new(big.Int).Lsh(big.NewInt(1), 128),
			Utxos: map[consensus.Outpoint]consensus.UtxoEntry{
				{Txid: [32]byte{0x73}, Vout: 2}: {Value: 22},
			},
		}
		result := &consensus.ConnectBlockBasicSummary{AlreadyGenerated: wide, AlreadyGeneratedN1: wideN1}
		out, err := st.applyConnectedBlockLocked(8, [32]byte{0x74}, work, result)
		if err == nil || out != nil || err.Error() != "already_generated overflow" {
			t.Fatalf("out=%#v err=%v, want supply overflow", out, err)
		}
		afterState, diskErr := stateToDisk(st)
		if diskErr != nil {
			t.Fatalf("stateToDisk(after): %v", diskErr)
		}
		if !reflect.DeepEqual(beforeState, afterState) {
			t.Fatal("durable state changed before supply conversion completed")
		}
		probe := consensus.Outpoint{Txid: [32]byte{0x75}, Vout: 3}
		originalUtxos[probe] = consensus.UtxoEntry{Value: 23}
		if _, ok := st.Utxos[probe]; !ok {
			t.Fatal("durable UTXO map was replaced before supply conversion completed")
		}
	})
}
