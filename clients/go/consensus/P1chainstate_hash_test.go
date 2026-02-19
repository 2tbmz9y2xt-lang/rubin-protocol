package consensus

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func makeUtxoSetOutput(t *testing.T, suiteID byte, value uint64) TxOutput {
	t.Helper()
	key := bytes.Repeat([]byte{byte(suiteID)}, ML_DSA_PUBKEY_BYTES)
	keyID := mustSHA3ForTest(t, applyTxStubProvider{}, key)
	return TxOutput{
		Value:        value,
		CovenantType: CORE_P2PK,
		CovenantData: append([]byte{SUITE_ID_ML_DSA}, keyID[:]...),
	}
}

func makeTestUtxoEntry(value uint64, createdByCoinbase bool) map[TxOutPoint]UtxoEntry {
	key := [32]byte{1, 2, 3, 4}
	point := TxOutPoint{TxID: key, Vout: 7}
	return map[TxOutPoint]UtxoEntry{
		point: {
			Output: TxOutput{
				Value:        value,
				CovenantType: CORE_P2PK,
				CovenantData: make([]byte, 33),
			},
			CreationHeight:    4,
			CreatedByCoinbase: createdByCoinbase,
		},
	}
}

func TestUtxoSetHash(t *testing.T) {
	t.Run("empty utxo -> deterministic non-zero hash", func(t *testing.T) {
		h1, err := UtxoSetHash(applyTxStubProvider{}, map[TxOutPoint]UtxoEntry{})
		if err != nil {
			t.Fatalf("empty hash failed: %v", err)
		}
		h2, err := UtxoSetHash(applyTxStubProvider{}, map[TxOutPoint]UtxoEntry{})
		if err != nil {
			t.Fatalf("empty hash failed: %v", err)
		}
		var zero [32]byte
		if h1 == zero {
			t.Fatalf("expected non-zero hash for empty set")
		}
		if h1 != h2 {
			t.Fatalf("empty-set hash not deterministic: %x != %x", h1, h2)
		}
	})

	t.Run("1 entry -> manual SHA3", func(t *testing.T) {
		point := TxOutPoint{
			TxID: [32]byte{0x99, 0x88, 0x77},
			Vout: 3,
		}
		entry := UtxoEntry{
			Output: TxOutput{
				Value:        12345,
				CovenantType: CORE_P2PK,
				CovenantData: make([]byte, 33),
			},
			CreationHeight:    55,
			CreatedByCoinbase: true,
		}
		utxo := map[TxOutPoint]UtxoEntry{
			point: entry,
		}
		got, err := UtxoSetHash(applyTxStubProvider{}, utxo)
		if err != nil {
			t.Fatalf("UtxoSetHash failed: %v", err)
		}

		var payload []byte
		payload = append(payload, []byte(utxoSetHashDST)...)
		payload = append(payload, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

		keyBytes := outpointKeyBytes(point)
		payload = append(payload, keyBytes[:]...)

		var u64b [8]byte
		binary.LittleEndian.PutUint64(u64b[:], entry.Output.Value)
		payload = append(payload, u64b[:]...)
		var u16b [2]byte
		binary.LittleEndian.PutUint16(u16b[:], entry.Output.CovenantType)
		payload = append(payload, u16b[:]...)
		payload = append(payload, CompactSize(uint64(len(entry.Output.CovenantData))).Encode()...)

		payload = append(payload, entry.Output.CovenantData...)
		binary.LittleEndian.PutUint64(u64b[:], entry.CreationHeight)
		payload = append(payload, u64b[:]...)
		payload = append(payload, 0x01)

		expected, err := applyTxStubProvider{}.SHA3_256(payload)
		if err != nil {
			t.Fatalf("SHA3_256 failed: %v", err)
		}
		if got != expected {
			t.Fatalf("hash mismatch: got %x expected %x payload=%x", got, expected, payload)
		}
	})

	t.Run("order of map insertion does not change hash", func(t *testing.T) {
		pointA := TxOutPoint{TxID: [32]byte{0x01}, Vout: 0}
		pointB := TxOutPoint{TxID: [32]byte{0x02}, Vout: 1}
		utxo1 := map[TxOutPoint]UtxoEntry{
			pointA: {
				Output:         makeUtxoSetOutput(t, 0x11, 10),
				CreationHeight: 1,
			},
			pointB: {
				Output:         makeUtxoSetOutput(t, 0x22, 20),
				CreationHeight: 2,
			},
		}
		utxo2 := map[TxOutPoint]UtxoEntry{
			pointB: {
				Output:         makeUtxoSetOutput(t, 0x22, 20),
				CreationHeight: 2,
			},
			pointA: {
				Output:         makeUtxoSetOutput(t, 0x11, 10),
				CreationHeight: 1,
			},
		}

		h1, err := UtxoSetHash(applyTxStubProvider{}, utxo1)
		if err != nil {
			t.Fatalf("UtxoSetHash 1 failed: %v", err)
		}
		h2, err := UtxoSetHash(applyTxStubProvider{}, utxo2)
		if err != nil {
			t.Fatalf("UtxoSetHash 2 failed: %v", err)
		}
		if h1 != h2 {
			t.Fatalf("order-dependent hash: %x != %x", h1, h2)
		}
	})

	t.Run("different utxo set -> different hash", func(t *testing.T) {
		base := map[TxOutPoint]UtxoEntry{
			{TxID: [32]byte{0x01}, Vout: 0}: {
				Output: TxOutput{
					Value:        1,
					CovenantType: CORE_P2PK,
					CovenantData: make([]byte, 33),
				},
				CreationHeight: 1,
			},
		}
		other := map[TxOutPoint]UtxoEntry{
			{TxID: [32]byte{0x01}, Vout: 0}: {
				Output: TxOutput{
					Value:        2,
					CovenantType: CORE_P2PK,
					CovenantData: make([]byte, 33),
				},
				CreationHeight: 1,
			},
		}
		h1, err := UtxoSetHash(applyTxStubProvider{}, base)
		if err != nil {
			t.Fatalf("UtxoSetHash base failed: %v", err)
		}
		h2, err := UtxoSetHash(applyTxStubProvider{}, other)
		if err != nil {
			t.Fatalf("UtxoSetHash other failed: %v", err)
		}
		if h1 == h2 {
			t.Fatalf("different utxo sets produced same hash")
		}
	})
}

func TestOutpointKeyBytes(t *testing.T) {
	point := TxOutPoint{
		TxID: [32]byte{0x01, 0x02, 0x03, 0x04},
		Vout: 0x01020304,
	}
	expected := make([]byte, 36)
	copy(expected[:32], point.TxID[:])
	binary.LittleEndian.PutUint32(expected[32:36], point.Vout)
	got := outpointKeyBytes(point)
	if !bytes.Equal(got[:], expected) {
		t.Fatalf("expected %x got %x", expected, got[:])
	}
}
