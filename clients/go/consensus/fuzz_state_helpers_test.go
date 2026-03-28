package consensus

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

type fuzzTxContextOutputSnapshot struct {
	Value      uint64
	ExtPayload []byte
}

type fuzzTxContextBundleSnapshot struct {
	Present      bool
	TotalIn      Uint128
	TotalOut     Uint128
	Height       uint64
	OrderedExtID []uint16
	Continuing   map[uint16][]fuzzTxContextOutputSnapshot
}

type fuzzUtxoSetHashEntry struct {
	op    Outpoint
	entry UtxoEntry
}

func seedBuildTxContextFuzzBytes() []byte {
	tx := &Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs: []TxInput{
			{
				PrevTxid: [32]byte{0x07, 0x00, 0x02, 0xAA, 0xBB},
				PrevVout: 0,
				Sequence: 0,
			},
		},
		Outputs: []TxOutput{
			{
				Value:        90,
				CovenantType: COV_TYPE_CORE_EXT,
				CovenantData: makeCoreExtCovenantDataWithPayload(7, []byte{0x10, 0x20}),
			},
			{
				Value:        10,
				CovenantType: COV_TYPE_P2PK,
				CovenantData: validP2PKCovenantData(),
			},
		},
		Locktime: 0,
	}
	raw, err := MarshalTx(tx)
	if err != nil {
		panic(err)
	}
	return raw
}

func buildFuzzTxContextResolvedInputs(tx *Tx) ([]UtxoEntry, *staticMapCoreExtProfileProvider) {
	profiles := make(map[uint16]CoreExtProfile)
	resolved := make([]UtxoEntry, 0, len(tx.Inputs))
	for i, in := range tx.Inputs {
		value := uint64(i + 1)
		useCoreExt := i == 0 || (in.PrevTxid[0]&0x01) == 0
		if useCoreExt {
			extID := binary.LittleEndian.Uint16(in.PrevTxid[:2])
			if extID == 0 {
				extID = uint16(i + 1)
			}
			payloadLen := int(in.PrevTxid[2] & 0x03)
			payload := append([]byte(nil), in.PrevTxid[3:3+payloadLen]...)
			resolved = append(resolved, UtxoEntry{
				Value:        value,
				CovenantType: COV_TYPE_CORE_EXT,
				CovenantData: makeCoreExtCovenantDataWithPayload(extID, payload),
			})
			profiles[extID] = CoreExtProfile{Active: true, TxContextEnabled: true}
			continue
		}
		resolved = append(resolved, UtxoEntry{
			Value:        value,
			CovenantType: COV_TYPE_P2PK,
			CovenantData: validP2PKCovenantData(),
		})
	}
	return resolved, &staticMapCoreExtProfileProvider{profiles: profiles}
}

func snapshotTxContextBundle(bundle *TxContextBundle) fuzzTxContextBundleSnapshot {
	if bundle == nil {
		return fuzzTxContextBundleSnapshot{}
	}
	snapshot := fuzzTxContextBundleSnapshot{
		Present:      true,
		OrderedExtID: append([]uint16(nil), bundle.OrderedExtIDs()...),
		Continuing:   make(map[uint16][]fuzzTxContextOutputSnapshot),
	}
	if bundle.Base != nil {
		snapshot.TotalIn = bundle.Base.TotalIn
		snapshot.TotalOut = bundle.Base.TotalOut
		snapshot.Height = bundle.Base.Height
	}
	for extID, continuing := range bundle.ContinuingByExt {
		if continuing == nil {
			snapshot.Continuing[extID] = nil
			continue
		}
		count := int(continuing.ContinuingOutputCount)
		if count > len(continuing.ContinuingOutputs) {
			count = len(continuing.ContinuingOutputs)
		}
		outputs := make([]fuzzTxContextOutputSnapshot, 0, count)
		for i := 0; i < count; i++ {
			out := continuing.ContinuingOutputs[i]
			outputs = append(outputs, fuzzTxContextOutputSnapshot{
				Value:      out.Value,
				ExtPayload: append([]byte(nil), out.ExtPayload...),
			})
		}
		snapshot.Continuing[extID] = outputs
	}
	return snapshot
}

func decodeUtxoSetHashEntries(data []byte) []fuzzUtxoSetHashEntry {
	const stride = 72
	count := len(data) / stride
	if count > 32 {
		count = 32
	}
	out := make([]fuzzUtxoSetHashEntry, 0, count)
	for i := 0; i < count; i++ {
		chunk := data[i*stride : (i+1)*stride]
		var op Outpoint
		copy(op.Txid[:], chunk[:32])
		op.Vout = binary.LittleEndian.Uint32(chunk[32:36])
		payloadLen := int(chunk[55] % 17)
		out = append(out, fuzzUtxoSetHashEntry{
			op: op,
			entry: UtxoEntry{
				Value:             binary.LittleEndian.Uint64(chunk[36:44]),
				CreationHeight:    binary.LittleEndian.Uint64(chunk[44:52]),
				CovenantType:      binary.LittleEndian.Uint16(chunk[52:54]),
				CreatedByCoinbase: (chunk[54] & 0x01) != 0,
				CovenantData:      append([]byte(nil), chunk[56:56+payloadLen]...),
			},
		})
	}
	return out
}

func canonicalizeUtxoSetHashEntries(entries []fuzzUtxoSetHashEntry) []fuzzUtxoSetHashEntry {
	lastByOutpoint := make(map[Outpoint]UtxoEntry, len(entries))
	order := make([]Outpoint, 0, len(entries))
	seen := make(map[Outpoint]struct{}, len(entries))
	for _, item := range entries {
		if _, ok := seen[item.op]; !ok {
			order = append(order, item.op)
			seen[item.op] = struct{}{}
		}
		lastByOutpoint[item.op] = item.entry
	}
	out := make([]fuzzUtxoSetHashEntry, 0, len(lastByOutpoint))
	for _, op := range order {
		entry, ok := lastByOutpoint[op]
		if !ok {
			continue
		}
		out = append(out, fuzzUtxoSetHashEntry{op: op, entry: entry})
		delete(lastByOutpoint, op)
	}
	return out
}

func FuzzBuildTxContext(f *testing.F) {
	f.Add(seedBuildTxContextFuzzBytes(), uint64(55))
	f.Add(minimalTxBytesForFuzz(), uint64(1))

	f.Fuzz(func(t *testing.T, txBytes []byte, blockHeight uint64) {
		if len(txBytes) > 1<<20 {
			return
		}
		tx, _, _, _, err := ParseTx(txBytes)
		if err != nil {
			return
		}
		cache, err := BuildTxContextOutputExtIDCache(tx)
		if err != nil {
			return
		}

		resolvedInputs, profiles := buildFuzzTxContextResolvedInputs(tx)
		bundle1, err1 := BuildTxContext(tx, resolvedInputs, cache, blockHeight, profiles)
		bundle2, err2 := BuildTxContext(tx, resolvedInputs, cache, blockHeight, profiles)

		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("BuildTxContext error presence mismatch: %v vs %v", err1, err2)
		}
		if err1 != nil {
			if err1.Error() != err2.Error() {
				t.Fatalf("BuildTxContext error text mismatch: %q vs %q", err1, err2)
			}
			return
		}

		snap1 := snapshotTxContextBundle(bundle1)
		snap2 := snapshotTxContextBundle(bundle2)
		if !reflect.DeepEqual(snap1, snap2) {
			t.Fatalf("BuildTxContext non-deterministic snapshot")
		}
		if bundle1 != nil && bundle1.Base != nil && bundle1.Base.Height != blockHeight {
			t.Fatalf("bundle height=%d want %d", bundle1.Base.Height, blockHeight)
		}
	})
}

func FuzzUtxoSetHashDeterminism(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x11}, 72))
	f.Add(append(bytes.Repeat([]byte{0x22}, 72), bytes.Repeat([]byte{0x33}, 72)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 72*32 {
			return
		}
		entries := canonicalizeUtxoSetHashEntries(decodeUtxoSetHashEntries(data))

		forward := make(map[Outpoint]UtxoEntry, len(entries))
		reverse := make(map[Outpoint]UtxoEntry, len(entries))
		for _, item := range entries {
			forward[item.op] = item.entry
		}
		for i := len(entries) - 1; i >= 0; i-- {
			reverse[entries[i].op] = entries[i].entry
		}

		hash1 := UtxoSetHash(forward)
		hash2 := UtxoSetHash(reverse)
		hash3 := UtxoSetHash(forward)

		if hash1 != hash2 {
			t.Fatalf("UtxoSetHash map-order mismatch: %x vs %x", hash1, hash2)
		}
		if hash1 != hash3 {
			t.Fatalf("UtxoSetHash non-deterministic repeat: %x vs %x", hash1, hash3)
		}
	})
}
