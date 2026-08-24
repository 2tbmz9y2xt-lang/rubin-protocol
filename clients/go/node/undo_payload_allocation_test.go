package node

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

const undoPayloadAllocationRows = 1 << 17

func undoPayloadAllocationCorpus(t *testing.T, hash [32]byte, version uint32, covenantBytes int) (*BlockUndo, []byte, []byte) {
	txs := []TxUndo{{Spent: []SpentUndo{{
		Outpoint: consensus.Outpoint{Txid: [32]byte{1}, Vout: 2},
		Entry: consensus.UtxoEntry{
			Value: 3, CovenantType: 4, CovenantData: bytes.Repeat([]byte{0xab}, covenantBytes),
			CreationHeight: 5, CreatedByCoinbase: true,
		},
	}}}}
	undo := &BlockUndo{BlockHeight: 0, PreviousAlreadyGenerated: consensus.Uint128FromU64(7), Txs: txs}
	marshalPayload := marshalBlockUndoV2
	if version == undoEnvelopeVersionV1 {
		marshalPayload = marshalBlockUndo
	}
	payload, payloadErr := marshalPayload(undo)
	raw, rawErr := marshalUndoEnvelopeVersion(version, hash, undo)
	if payloadErr != nil || rawErr != nil || len(undo.Txs[0].Spent[0].Entry.CovenantData) != covenantBytes {
		t.Fatalf("build undo corpus: payload=%v envelope=%v bytes=%d", payloadErr, rawErr, len(payload))
	}
	return undo, payload, raw
}

func undoPayloadAllocationDelta(t *testing.T, warm, run func() error) uint64 {
	procs, gc := runtime.GOMAXPROCS(1), debug.SetGCPercent(-1)
	defer func() { debug.SetGCPercent(gc); runtime.GOMAXPROCS(procs) }()
	if err := warm(); err != nil {
		t.Fatalf("warm public path: %v", err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := run(); err != nil {
		t.Fatalf("measure public path: %v", err)
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestUndoPayloadAllocationPublicPaths(t *testing.T) {
	// Under -race sync.Pool.Put randomly drops values and encoding/json pools its encode/scan state, so per-call TotalAlloc is nondeterministic.
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" && setting.Value == "true" {
				t.Skip("allocation accounting is nondeterministic in race builds because sync.Pool randomly drops values")
			}
		}
	}
	type sample struct {
		undo         *BlockUndo
		payload, raw []byte
		store        *BlockStore
		path         string
		get, put     uint64
	}
	for _, version := range []uint32{undoEnvelopeVersionV1, undoEnvelopeVersion} {
		hash := mustHeaderHash(t, testHeaderBytes(byte(version), 1))
		var samples [2]sample
		for i, size := range [2]int{8 << 20, 12 << 20} {
			undo, payload, raw := undoPayloadAllocationCorpus(t, hash, version, size)
			store := mustCreateBlockStore(t, filepath.Join(t.TempDir(), "blockstore"))
			path := filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json")
			mustWriteFile(t, path, raw)
			samples[i] = sample{undo, payload, raw, store, path, 0, 0}
		}
		for i := range samples {
			s := &samples[i]
			if got, err := s.store.GetUndo(hash); err != nil || !reflect.DeepEqual(got, s.undo) {
				t.Fatalf("v%d GetUndo: equal=%t err=%v", version, reflect.DeepEqual(got, s.undo), err)
			}
			s.get = undoPayloadAllocationDelta(t, func() error { _, err := s.store.GetUndo(hash); return err }, func() error { _, err := s.store.GetUndo(hash); return err })
			s.put = undoPayloadAllocationDelta(t, func() error { return s.store.PutUndo(hash, s.undo) }, func() error { return s.store.PutUndo(hash, s.undo) })
			if after, err := os.ReadFile(s.path); err != nil || !bytes.Equal(after, s.raw) {
				t.Fatalf("v%d existing bytes changed: %v", version, err)
			}
		}
		small, large := samples[0], samples[1]
		deltaR, deltaP := len(large.raw)-len(small.raw), len(large.payload)-len(small.payload)
		deltaL := 2 * (len(large.undo.Txs[0].Spent[0].Entry.CovenantData) - len(small.undo.Txs[0].Spent[0].Entry.CovenantData))
		if large.get < small.get || large.get-small.get > uint64(deltaR+4*deltaP+deltaL+1<<20) {
			t.Fatalf("v%d GetUndo paired allocation exceeded bound", version)
		}
		if large.put < small.put || large.put-small.put > uint64(4*deltaR+7*deltaP+1<<20) {
			t.Fatalf("v%d PutUndo paired allocation exceeded bound", version)
		}
		for _, mutation := range []struct {
			name  string
			apply func(*BlockUndo)
		}{
			{"outer_txs_length", func(undo *BlockUndo) { undo.Txs = append(undo.Txs, TxUndo{}) }},
			{"inner_spent_length", func(undo *BlockUndo) { undo.Txs[0].Spent = append(undo.Txs[0].Spent, SpentUndo{}) }},
			{"nested_entry_value", func(undo *BlockUndo) { undo.Txs[0].Spent[0].Entry.Value++ }},
		} {
			candidate, err := small.store.GetUndo(hash)
			if err != nil {
				t.Fatalf("v%d %s setup: %v", version, mutation.name, err)
			}
			mutation.apply(candidate)
			if err := small.store.PutUndo(hash, candidate); err == nil || !strings.Contains(err.Error(), "file already exists with different content") {
				t.Fatalf("v%d %s PutUndo: %v", version, mutation.name, err)
			}
			if after, err := os.ReadFile(small.path); err != nil || !bytes.Equal(after, small.raw) {
				t.Fatalf("v%d %s changed existing bytes: %v", version, mutation.name, err)
			}
		}
	}
	rows := `{"spent":[]}` + strings.Repeat(`,{"spent":[]}`, undoPayloadAllocationRows-1)
	for _, tc := range []struct {
		version      uint32
		supply, want string
	}{
		{undoEnvelopeVersionV1, `"0"`, "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64"},
		{undoEnvelopeVersion, `0`, "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128"},
	} {
		payload := []byte(`{"block_height":0,"previous_already_generated":` + tc.supply + `,"txs":[` + rows + `]}`)
		hash, store := [32]byte{byte(tc.version)}, mustCreateBlockStore(t, filepath.Join(t.TempDir(), "invalid"))
		raw := marshalUndoEnvelopePayload(t, tc.version, hash, payload)
		mustWriteFile(t, filepath.Join(store.undoDir, hex.EncodeToString(hash[:])+".json"), raw)
		if _, err := store.GetUndo(hash); err == nil || err.Error() != tc.want {
			t.Fatalf("v%d invalid supply: %v", tc.version, err)
		}
	}
}
