package mdbx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strconv"
	"testing"
)

type codecLiteralCase struct {
	name string
	a    StorageAuthorityV1
	b    []byte
}

func mustCodecHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func codecLiteralCases(t *testing.T) []codecLiteralCase {
	t.Helper()
	none := modelBase(1, 0, 0)
	prune := modelPrune(false)
	prune.B, prune.U, prune.NextGenerationID = 4, 13684, 4
	prune.Cleanup.Spans = []CleanupSpanV1{
		{Kind: 1, GenerationID: 3},
		{Kind: 2, GenerationID: 1, FirstHeight: 1, LastHeight: 3, NextHeight: 2},
		{Kind: 3, GenerationID: 1, FirstHeight: 4, LastHeight: 6, NextHeight: 5},
		{Kind: 4, GenerationID: 2, FirstHeight: 7, LastHeight: 9, NextHeight: 8},
	}
	prune.SelectedSide = modelSide(2, 9, 11, 2, 3)
	pruneRecovery := modelPrune(true)
	pruneRecovery.DetachedSuffix = modelDetached(1, 1)
	pruneRecovery.DetachedSuffix.Entries[0].Height = 7
	pruneRecovery.DetachedSuffix.Cursor.Height = 7
	replay := modelReplay(2)
	copy(replay.Replay.Target.ChainID[:], mustCodecHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	replay.Replay.Cursor.Height, replay.Replay.Cursor.BlockHash = 1, modelHash(14)
	replay.ExcludedInvalidBranch = &InvalidBranchV1{7, modelHash(72), []byte{0, 0xff, 0x80}}
	ordinary := modelOrdinary(3, 1, 2, 15120, 1, 1, 13681)
	ordinary.Ordinary.CarriedCleanup = modelCleanup()
	hash := ordinary.Ordinary.NewSuffix[1].BlockHash
	ordinary.Ordinary.RecordedFailure = &RecordedFailureV1{1, &hash, []byte{0, 0x31, 0xff}, []byte{0x80, 0x41}}
	replayPruned, pendingPruned := modelReplay(1), modelPrune(true)
	replayPruned.Replay.TargetProfile, *pendingPruned.PendingTargetProfile = 1, 1
	return []codecLiteralCase{
		{"none-stable", none, mustCodecHex(t, "01010000000000000000000000000000000000000000000000010000000000000002010100000000")},
		{"prune-stable-adjacent-SIDE", prune, mustCodecHex(t, "0101000000000000000400000000000035740000000000000001000000000000000402010401000000000000000302000000000000000100000000000000010000000000000003000000000000000203000000000000000100000000000000040000000000000006000000000000000504000000000000000200000000000000070000000000000009000000000000000800000100000000000000020000000000000009000000000000000b000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000000000000000000010002000000000000000300")},
		{"prune-recovery", pruneRecovery, mustCodecHex(t, "01010000000000000001000000000000357100000000000000010000000000000002020201020000000000000001000000000000000000000000000000000000000000000000010200000100010000000000000007000000000000000000000000000000000000000000000000000000000000000100000000000000010000000000000007000000000000000000000000000000000000000000000000000000000000000100010000000000000001")},
		{"replay-recovery", replay, mustCodecHex(t, "010100000000000000000000000000000000000000000000000100000000000000030302020000000000000002000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000001020000000000000001000000000000000000000000000000000000000000000000000000000000000e0001000000000000000700000000000000000000000000000000000000000000000000000000000000480000000300ff800000")},
		{"ordinary-recovery", ordinary, mustCodecHex(t, "01010000000000000001000000000000357100000000000000010000000000000003040203010000000000003b1000000000000000000000000000000000000000000000000000000000000007d00000000000003b1100000000000000000000000000000000000000000000000000000000000007d100010000000000003b1000000000000000000000000000000000000000000000000000000000000003e800020000000000003b1000000000000000000000000000000000000000000000000000000000000007d00000000000003b1100000000000000000000000000000000000000000000000000000000000007d10100000000000000020000000000003b0f0000000000003b1100000000000000000000000000000000000000000000000000000000000007d10000000000000000000000000000000000000000000000000000000000000000000000000000000100020000000000000002010102000000000000000100000000000000000000000000000000000000000000000001010100000000000000000000000000000000000000000000000000000000000007d1000000030031ff00000002804100000000")},
		{"ordinary-absent-options", modelOrdinary(1, 1, 0, 1, 1, 0, 0), mustCodecHex(t, "010100000000000000000000000000000000000000000000000100000000000000020402010000000000000000000000000000000000000000000000000000000000000000000000000000000bb80001000000000000000100000000000000000000000000000000000000000000000000000000000003e8000000000000000000")},
		{"archive-none", modelBase(2, 0, 0), mustCodecHex(t, "01020000000000000000000000000000000000000000000000010000000000000002010100000000")},
		{"replay-pre-genesis", modelReplay(1), mustCodecHex(t, "010100000000000000000000000000000000000000000000000100000000000000030302020000000000000002000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d0000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000010100000000")},
		{"replay-target-pruned", replayPruned, mustCodecHex(t, "010100000000000000000000000000000000000000000000000100000000000000030302010000000000000002000000000000000000000000000000000000000000000000000000000000000b000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000d0000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000010100000000")},
		{"pending-target-pruned", pendingPruned, mustCodecHex(t, "010100000000000000010000000000003571000000000000000100000000000000020202010200000000000000010000000000000000000000000000000000000000000000000101000000")},
	}
}

func wantCodecRoundTrip(t *testing.T, a StorageAuthorityV1) []byte {
	t.Helper()
	b, err := a.Encode()
	if err != nil {
		t.Fatalf("Encode error = %v", err)
	}
	got, err := DecodeStorageAuthorityV1(b)
	if err != nil || !reflect.DeepEqual(got, a) {
		t.Fatalf("round trip = %#v, %v; want %#v", got, err, a)
	}
	return b
}

func wantCodecDecodeError(t *testing.T, b []byte) {
	t.Helper()
	before := append([]byte(nil), b...)
	got, err := DecodeStorageAuthorityV1(b)
	if got != (StorageAuthorityV1{}) || !exactErr(err) || !bytes.Equal(b, before) {
		t.Fatalf("Decode = %#v, %v; want zero, exact errSchema", got, err)
	}
}

func runCodecCases(t *testing.T, rows []authorityCase) {
	t.Helper()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) { wantCodecRoundTrip(t, row.a) })
	}
}

func TestStorageAuthorityV1CodecLiterals(t *testing.T) {
	rows := codecLiteralCases(t)
	encoded := make([][]byte, len(rows))
	for index, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got, err := row.a.Encode()
			encoded[index] = got
			if err != nil || !bytes.Equal(got, row.b) {
				t.Fatalf("Encode = %x, %v; want %x", got, err, row.b)
			}
			decoded, err := DecodeStorageAuthorityV1(row.b)
			if err != nil || !reflect.DeepEqual(decoded, row.a) {
				t.Fatalf("Decode = %#v, %v; want %#v", decoded, err, row.a)
			}
			reencoded, err := decoded.Encode()
			if err != nil || !bytes.Equal(reencoded, row.b) {
				t.Fatalf("re-Encode = %x, %v; want %x", reencoded, err, row.b)
			}
		})
	}
	for _, field := range []struct {
		name          string
		record, start int
		hex           string
	}{
		{"version", 0, 0, "01"},
		{"active-profile", 0, 1, "01"},
		{"B", 1, 2, "0000000000000004"},
		{"U", 1, 10, "0000000000003574"},
		{"active-generation", 0, 18, "0000000000000001"},
		{"next-generation", 0, 26, "0000000000000002"},
		{"phase", 0, 34, "01"},
		{"lifecycle", 0, 35, "01"},
		{"cleanup-count", 1, 36, "04"},
		{"cleanup-generation-kind", 1, 37, "01"},
		{"cleanup-generation-id", 1, 38, "0000000000000003"},
		{"cleanup-blocks-kind", 1, 46, "02"},
		{"cleanup-blocks-id", 1, 47, "0000000000000001"},
		{"cleanup-blocks-first", 1, 55, "0000000000000001"},
		{"cleanup-blocks-last", 1, 63, "0000000000000003"},
		{"cleanup-blocks-next", 1, 71, "0000000000000002"},
		{"cleanup-undo-kind", 1, 79, "03"},
		{"cleanup-undo-id", 1, 80, "0000000000000001"},
		{"cleanup-undo-first", 1, 88, "0000000000000004"},
		{"cleanup-undo-last", 1, 96, "0000000000000006"},
		{"cleanup-undo-next", 1, 104, "0000000000000005"},
		{"cleanup-side-kind", 1, 112, "04"},
		{"cleanup-side-id", 1, 113, "0000000000000002"},
		{"cleanup-side-first", 1, 121, "0000000000000007"},
		{"cleanup-side-last", 1, 129, "0000000000000009"},
		{"cleanup-side-next", 1, 137, "0000000000000008"},
		{"selected-option", 1, 147, "01"},
		{"selected-generation", 1, 148, "0000000000000002"},
		{"selected-F", 1, 156, "0000000000000009"},
		{"selected-tip-height", 1, 164, "000000000000000b"},
		{"selected-tip-hash", 1, 172, "000000000000000000000000000000000000000000000000000000000000000b"},
		{"selected-work", 1, 204, "00000000000000000000000000000000000000000000000000000000000000000000000000000001"},
		{"selected-row-count", 1, 244, "0002"},
		{"selected-logical-bytes", 1, 246, "0000000000000003"},
		{"replay-profile", 3, 36, "02"},
		{"replay-generation", 3, 37, "0000000000000002"},
		{"replay-chain-id", 3, 45, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},
		{"replay-genesis-hash", 3, 77, "000000000000000000000000000000000000000000000000000000000000000c"},
		{"replay-tip-hash", 3, 109, "000000000000000000000000000000000000000000000000000000000000000d"},
		{"replay-tip-height", 3, 141, "0000000000000002"},
		{"replay-work", 3, 149, "00000000000000000000000000000000000000000000000000000000000000000000000000000001"},
		{"replay-cursor-kind", 3, 189, "02"},
		{"replay-cursor-height", 3, 190, "0000000000000001"},
		{"replay-cursor-hash", 3, 198, "000000000000000000000000000000000000000000000000000000000000000e"},
		{"invalid-option", 3, 231, "01"},
		{"invalid-height", 3, 232, "0000000000000007"},
		{"invalid-hash", 3, 240, "0000000000000000000000000000000000000000000000000000000000000048"},
		{"invalid-blob-length", 3, 272, "00000003"},
		{"invalid-blob", 3, 276, "00ff80"},
		{"pending-option", 2, 70, "01"},
		{"pending-profile", 2, 71, "02"},
		{"detached-option", 2, 74, "01"},
		{"detached-count", 2, 75, "0001"},
		{"detached-entry-height", 2, 77, "0000000000000007"},
		{"detached-entry-hash", 2, 85, "0000000000000000000000000000000000000000000000000000000000000001"},
		{"detached-entry-byte-length", 2, 117, "0000000000000001"},
		{"detached-cursor-height", 2, 125, "0000000000000007"},
		{"detached-cursor-hash", 2, 133, "0000000000000000000000000000000000000000000000000000000000000001"},
		{"detached-entry-count", 2, 165, "0001"},
		{"detached-logical-bytes", 2, 167, "0000000000000001"},
		{"ordinary-stage", 4, 36, "03"},
		{"ordinary-cursor-option", 4, 37, "01"},
		{"ordinary-cursor-height", 4, 38, "0000000000003b10"},
		{"ordinary-cursor-hash", 4, 46, "00000000000000000000000000000000000000000000000000000000000007d0"},
		{"ordinary-target-height", 4, 78, "0000000000003b11"},
		{"ordinary-target-hash", 4, 86, "00000000000000000000000000000000000000000000000000000000000007d1"},
		{"ordinary-old-count", 4, 118, "0001"},
		{"ordinary-old-point", 4, 120, "0000000000003b1000000000000000000000000000000000000000000000000000000000000003e8"},
		{"ordinary-new-count", 4, 160, "0002"},
		{"ordinary-new-first", 4, 162, "0000000000003b1000000000000000000000000000000000000000000000000000000000000007d0"},
		{"ordinary-new-second", 4, 202, "0000000000003b1100000000000000000000000000000000000000000000000000000000000007d1"},
		{"captured-option", 4, 242, "01"},
		{"carried-option", 4, 349, "01"},
		{"failure-option", 4, 384, "01"},
		{"failure-kind", 4, 385, "01"},
		{"failure-hash-option", 4, 386, "01"},
		{"failure-hash", 4, 387, "00000000000000000000000000000000000000000000000000000000000007d1"},
		{"failure-result-length", 4, 419, "00000003"},
		{"failure-result", 4, 423, "0031ff"},
		{"failure-evidence-length", 4, 426, "00000002"},
		{"failure-evidence", 4, 430, "8041"},
	} {
		t.Run("field/"+field.name, func(t *testing.T) {
			want := mustCodecHex(t, field.hex)
			end := field.start + len(want)
			if len(encoded[field.record]) < end {
				t.Fatalf("encoded length = %d, need field end %d", len(encoded[field.record]), end)
			}
			got := encoded[field.record][field.start:end]
			decoded, err := DecodeStorageAuthorityV1(rows[field.record].b)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := decoded.Encode()
			if err != nil || len(roundTrip) < end || !bytes.Equal(got, want) || !bytes.Equal(roundTrip[field.start:end], want) {
				t.Fatalf("bytes[%d:%d] = %x / len %d, want %x", field.start, end, got, len(roundTrip), want)
			}
		})
	}
}

func TestStorageAuthorityV1CodecVariants(t *testing.T) {
	runCodecCases(t, []authorityCase{{"profile pruned", modelBase(1, 0, 0)}, {"profile archive", modelBase(2, 0, 0)}})
	rows := codecLiteralCases(t)
	prune, replay, ordinary := rows[1].b, rows[3].b, rows[4].b
	runCodecCases(t, []authorityCase{{"replay PRE_GENESIS", modelReplay(1)}, {"replay APPLIED genesis", modelReplay(2)}})
	t.Run("replay PRE_GENESIS tag literal", func(t *testing.T) {
		b := wantCodecRoundTrip(t, modelReplay(1))
		if b[189] != 1 {
			t.Fatalf("cursor tag = %d, want 1", b[189])
		}
	})
	runCodecCases(t, []authorityCase{
		{"stage DISCONNECT D1/C0", modelOrdinary(1, 1, 0, 1, 1, 0, 0)},
		{"stage CONNECT D0/C2", modelOrdinary(2, 0, 2, 0, 1, 0, 0)},
		{"D1/C1", modelOrdinary(1, 1, 1, 1, 1, 0, 0)},
		{"D>0/C>0", modelOrdinary(2, 1, 2, 15120, 1, 1, 13681)},
		{"stage ROLLBACK_NEW", modelOrdinary(3, 1, 2, 1, 1, 0, 0)},
		{"stage RESTORE_OLD", modelOrdinary(4, 2, 2, 2, 1, 0, 0)},
	})
	runCodecCases(t, []authorityCase{
		{"replay minimum tip 1", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.Target.TipHeight = 1 })},
		{"replay maximum tip", edit(modelReplay(1), func(a *StorageAuthorityV1) { a.Replay.Target.TipHeight = 0xffffffff })},
		{"replay APPLIED tip", edit(modelReplay(2), func(a *StorageAuthorityV1) {
			a.Replay.Cursor.Height, a.Replay.Cursor.BlockHash = 2, a.Replay.Target.TipHash
		})},
	})
	disconnect := modelOrdinary(1, 2, 0, 2, 1, 0, 0)
	cursor := disconnect.Ordinary.OldSuffix[0]
	disconnect.Ordinary.Cursor = &cursor
	t.Run("disconnect partial cursor", func(t *testing.T) { wantCodecRoundTrip(t, disconnect) })
	disconnect = modelOrdinary(1, 2, 0, 2, 1, 0, 0)
	cursor = disconnect.Ordinary.OldSuffix[1]
	disconnect.Ordinary.Cursor = &cursor
	t.Run("disconnect exhausted cursor", func(t *testing.T) { wantCodecRoundTrip(t, disconnect) })
	rollback := modelOrdinary(3, 0, 2, 0, 1, 0, 0)
	cursor = rollback.Ordinary.NewSuffix[1]
	rollback.Ordinary.Cursor = &cursor
	t.Run("rollback nonterminal cursor", func(t *testing.T) { wantCodecRoundTrip(t, rollback) })
	connect := modelOrdinary(2, 1, 2, 1, 1, 0, 0)
	cursor = connect.Ordinary.NewSuffix[1]
	connect.Ordinary.Cursor = &cursor
	t.Run("connect exhausted cursor", func(t *testing.T) { wantCodecRoundTrip(t, connect) })
	for _, kind := range []byte{1, 2, 3, 4} {
		t.Run("failure kind "+strconv.Itoa(int(kind)), func(t *testing.T) {
			a := modelOrdinary(3, 1, 2, 1, 1, 0, 0)
			a.Ordinary.RecordedFailure = modelFailure(kind)
			b := wantCodecRoundTrip(t, a)
			if b[351] != kind {
				t.Fatalf("failure kind byte = %d, want %d", b[351], kind)
			}
		})
	}
	for _, stage := range []struct {
		name string
		want byte
		a    StorageAuthorityV1
	}{
		{"DISCONNECT", 1, modelOrdinary(1, 1, 0, 1, 1, 0, 0)},
		{"CONNECT", 2, modelOrdinary(2, 0, 2, 0, 1, 0, 0)},
		{"ROLLBACK_NEW", 3, modelOrdinary(3, 1, 2, 1, 1, 0, 0)},
		{"RESTORE_OLD", 4, modelOrdinary(4, 2, 2, 2, 1, 0, 0)},
	} {
		t.Run("stage tag "+stage.name, func(t *testing.T) {
			b := wantCodecRoundTrip(t, stage.a)
			if b[36] != stage.want {
				t.Fatalf("stage byte = %d, want %d", b[36], stage.want)
			}
		})
	}
	failureHashAbsent := wantCodecRoundTrip(t, modelOrdinary(3, 1, 2, 1, 1, 0, 0))
	t.Run("failure hash absent", func(t *testing.T) {
		if !bytes.Equal(failureHashAbsent[351:353], mustCodecHex(t, "0100")) {
			t.Fatalf("failure kind/hash option = %x", failureHashAbsent[351:353])
		}
	})
	for _, slot := range []struct {
		name   string
		base   []byte
		offset int
		values []byte
	}{
		{"version", rows[0].b, 0, []byte{0, 2, 255}},
		{"active profile", rows[0].b, 1, []byte{0, 3, 255}},
		{"phase", rows[0].b, 34, []byte{0, 5, 255}},
		{"lifecycle", rows[0].b, 35, []byte{0, 3, 255}},
		{"cleanup GENERATION kind", prune, 37, []byte{0, 5, 255}},
		{"cleanup BLOCKS kind", prune, 46, []byte{0, 5, 255}},
		{"cleanup UNDO kind", prune, 79, []byte{0, 5, 255}},
		{"cleanup SIDE kind", prune, 112, []byte{0, 5, 255}},
		{"outer pending option", rows[0].b, 36, []byte{2, 255}},
		{"outer invalid option", rows[0].b, 37, []byte{2, 255}},
		{"outer selected option", rows[0].b, 38, []byte{2, 255}},
		{"outer detached option", rows[0].b, 39, []byte{2, 255}},
		{"outer pending option present", rows[2].b, 70, []byte{2, 255}},
		{"outer invalid option present", rows[3].b, 231, []byte{2, 255}},
		{"outer selected option present", rows[1].b, 147, []byte{2, 255}},
		{"outer detached option present", rows[2].b, 74, []byte{2, 255}},
		{"ordinary cursor option", ordinary, 37, []byte{2, 255}},
		{"ordinary captured option", ordinary, 242, []byte{2, 255}},
		{"ordinary cleanup option", ordinary, 349, []byte{2, 255}},
		{"ordinary failure option", ordinary, 384, []byte{2, 255}},
		{"failure hash option", ordinary, 386, []byte{2, 255}},
		{"ordinary cursor option absent", rows[5].b, 37, []byte{2, 255}},
		{"ordinary captured option absent", rows[5].b, 122, []byte{2, 255}},
		{"ordinary cleanup option absent", rows[5].b, 123, []byte{2, 255}},
		{"ordinary failure option absent", rows[5].b, 124, []byte{2, 255}},
		{"failure hash option absent", failureHashAbsent, 352, []byte{2, 255}},
		{"replay target profile", replay, 36, []byte{0, 3, 255}},
		{"replay cursor", replay, 189, []byte{0, 3, 255}},
		{"ordinary stage", ordinary, 36, []byte{0, 5, 255}},
		{"failure kind", ordinary, 385, []byte{0, 5, 255}},
		{"pending profile", rows[2].b, 71, []byte{0, 3, 255}},
	} {
		for _, value := range slot.values {
			t.Run(slot.name+"="+strconv.Itoa(int(value)), func(t *testing.T) {
				b := append([]byte(nil), slot.base...)
				b[slot.offset] = value
				wantCodecDecodeError(t, b)
			})
		}
	}
}

func TestStorageAuthorityV1CodecFraming(t *testing.T) {
	wantCodecDecodeError(t, nil)
	for _, row := range codecLiteralCases(t) {
		t.Run(row.name+"-prefixes", func(t *testing.T) {
			for n := range len(row.b) {
				t.Run(strconv.Itoa(n), func(t *testing.T) { wantCodecDecodeError(t, row.b[:n]) })
			}
		})
	}
	none := codecLiteralCases(t)[0].b
	wantCodecDecodeError(t, append(append([]byte(nil), none...), 0))
	wantCodecDecodeError(t, append(append([]byte(nil), none...), none...))
	for _, offset := range []int{36, 37, 38, 39} {
		b := append([]byte(nil), none...)
		b[offset] = 1
		wantCodecDecodeError(t, b[:offset+1])
	}
}

func codecSemanticInvalidCases() []authorityCase {
	return []authorityCase{
		{"wrong replay genesis hash", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.BlockHash = modelHash(99) })},
		{"wrong replay tip hash", edit(modelReplay(2), func(a *StorageAuthorityV1) { a.Replay.Cursor.Height, a.Replay.Cursor.BlockHash = 2, modelHash(99) })},
		{"forbidden phase payload", edit(modelBase(1, 1, 13681), func(a *StorageAuthorityV1) { a.Cleanup = modelCleanup() })},
		{"forbidden optional owner product", edit(modelPrune(true), func(a *StorageAuthorityV1) { a.NextGenerationID, a.SelectedSide = 3, modelSide(2, 0, 1, 1, 1) })},
		{"wrong generation relation", edit(modelBase(1, 0, 0), func(a *StorageAuthorityV1) { a.NextGenerationID = 1 })},
		{"noncanonical cleanup order", edit(modelPrune(false), func(a *StorageAuthorityV1) { a.Cleanup.Spans = append(a.Cleanup.Spans, a.Cleanup.Spans[0]) })},
		{"detached sum mismatch", edit(modelDetachedAuthority(), func(a *StorageAuthorityV1) { a.DetachedSuffix.LogicalBytes++ })},
		{"detached entry count mismatch", edit(modelDetachedAuthority(), func(a *StorageAuthorityV1) { a.DetachedSuffix.EntryCount++ })},
		{"invalid list direction", edit(modelOrdinary(2, 0, 2, 0, 1, 0, 0), func(a *StorageAuthorityV1) {
			a.Ordinary.NewSuffix[1].Height, a.Ordinary.CapturedSelectedSide.TipHeight, a.Ordinary.CapturedSelectedSide.RowCount = 1, 1, 1
			a.Ordinary.Target = a.Ordinary.NewSuffix[1]
		})},
		{"duplicate list hash", edit(modelOrdinary(2, 0, 2, 0, 1, 0, 0), func(a *StorageAuthorityV1) {
			a.Ordinary.NewSuffix[1].BlockHash = a.Ordinary.NewSuffix[0].BlockHash
			a.Ordinary.Target.BlockHash, a.Ordinary.CapturedSelectedSide.TipHash = a.Ordinary.NewSuffix[1].BlockHash, a.Ordinary.NewSuffix[1].BlockHash
		})},
		{"terminal rollback cursor", modelOrdinary(3, 0, 2, 0, 1, 0, 0)},
		{"failure hash contradiction", edit(modelOrdinary(3, 1, 2, 1, 1, 0, 0), func(a *StorageAuthorityV1) {
			h := a.Ordinary.NewSuffix[0].BlockHash
			a.Ordinary.RecordedFailure = &RecordedFailureV1{2, &h, []byte{1}, []byte{2}}
		})},
	}
}

func TestStorageAuthorityV1CodecSemanticValidation(t *testing.T) {
	invalid, expected := codecSemanticInvalidCases(), codecSemanticInvalidCases()
	for index, row := range invalid {
		t.Run("encode "+row.name, func(t *testing.T) {
			got, err := row.a.Encode()
			if got != nil || !exactErr(err) || !reflect.DeepEqual(row.a, expected[index].a) {
				t.Fatalf("Encode invalid = %x, %v; input mutated", got, err)
			}
		})
	}
	rows := codecLiteralCases(t)
	nextEqual := append([]byte(nil), rows[0].b...)
	binary.BigEndian.PutUint64(nextEqual[26:], 1)
	wrongGenesis := append([]byte(nil), rows[3].b...)
	for i := 190; i < 198; i++ {
		wrongGenesis[i] = 0
	}
	wrongTip := append([]byte(nil), rows[3].b...)
	binary.BigEndian.PutUint64(wrongTip[190:], 2)
	cleanupOrder := append([]byte(nil), rows[1].b...)
	span := append([]byte(nil), cleanupOrder[46:79]...)
	copy(cleanupOrder[46:79], cleanupOrder[79:112])
	copy(cleanupOrder[79:112], span)
	detachedSum := append([]byte(nil), rows[2].b...)
	binary.BigEndian.PutUint64(detachedSum[167:], 2)
	detachedCount := append([]byte(nil), rows[2].b...)
	binary.BigEndian.PutUint16(detachedCount[165:], 2)
	stablePending := append([]byte(nil), rows[2].b...)
	stablePending[35] = 1
	noneRecovery := append([]byte(nil), rows[0].b...)
	noneRecovery[35] = 2
	terminal := append([]byte(nil), rows[4].b...)
	terminal = append(terminal[:350], terminal[384:]...)
	terminal[349] = 0
	terminal = append(terminal[:120], terminal[160:]...)
	binary.BigEndian.PutUint16(terminal[118:], 0)
	binary.BigEndian.PutUint64(terminal[2:], 0)
	binary.BigEndian.PutUint64(terminal[10:], 13680)
	failureHash := append([]byte(nil), rows[4].b...)
	failureHash[385] = 2
	wrongDirection := append([]byte(nil), rows[4].b...)
	for _, offset := range []int{78, 202, 259} {
		binary.BigEndian.PutUint64(wrongDirection[offset:], 15120)
	}
	binary.BigEndian.PutUint16(wrongDirection[339:], 1)
	duplicateHash := append([]byte(nil), rows[4].b...)
	for _, offset := range []int{86, 210, 267, 387} {
		copy(duplicateHash[offset:offset+32], duplicateHash[170:202])
	}
	for _, row := range []struct {
		name string
		b    []byte
	}{
		{"wrong generation relation", nextEqual},
		{"wrong replay genesis hash", wrongGenesis},
		{"wrong replay tip hash", wrongTip},
		{"noncanonical cleanup order", cleanupOrder},
		{"detached sum mismatch", detachedSum},
		{"detached entry count mismatch", detachedCount},
		{"forbidden optional owner product", stablePending},
		{"forbidden state payload", noneRecovery},
		{"terminal rollback cursor", terminal},
		{"failure hash contradiction", failureHash},
		{"invalid list direction", wrongDirection},
		{"duplicate list hash", duplicateHash},
	} {
		t.Run("decode "+row.name, func(t *testing.T) { wantCodecDecodeError(t, row.b) })
	}
}

func modelDetachedAuthority() StorageAuthorityV1 {
	a := modelPrune(false)
	a.DetachedSuffix = modelDetached(1, 1)
	return a
}

func TestStorageAuthorityV1CodecBounds(t *testing.T) {
	for n := range 40 {
		t.Run("length "+strconv.Itoa(n), func(t *testing.T) { wantCodecDecodeError(t, make([]byte, n)) })
	}
	rows := codecLiteralCases(t)
	for _, value := range []byte{0, 5} {
		t.Run("cleanup count "+strconv.Itoa(int(value)), func(t *testing.T) {
			b := append([]byte(nil), rows[1].b...)
			b[36] = value
			wantCodecDecodeError(t, b)
		})
	}
	for _, count := range []struct {
		name   string
		offset int
	}{{"old count 1441", 118}, {"new count 1441", 160}} {
		t.Run(count.name, func(t *testing.T) {
			b := append([]byte(nil), rows[4].b...)
			binary.BigEndian.PutUint16(b[count.offset:], 1441)
			wantCodecDecodeError(t, b)
		})
	}
	for _, value := range []uint16{0, 1441} {
		t.Run("detached count "+strconv.Itoa(int(value)), func(t *testing.T) {
			b := append([]byte(nil), rows[2].b...)
			binary.BigEndian.PutUint16(b[75:], value)
			wantCodecDecodeError(t, b)
		})
	}
	for _, count := range []struct {
		name   string
		a      StorageAuthorityV1
		offset int
	}{
		{"old framed 1441", modelOrdinary(1, 1440, 0, 2000, 1, 0, 561), 78},
		{"new framed 1441", modelOrdinary(2, 0, 1440, 0, 1, 0, 0), 80},
		{"detached framed 1441", modelDetached1440(), 74},
	} {
		t.Run(count.name, func(t *testing.T) {
			b := wantCodecRoundTrip(t, count.a)
			binary.BigEndian.PutUint16(b[count.offset:], 1441)
			wantCodecDecodeError(t, b)
		})
	}
	for _, row := range []struct {
		name string
		b    []byte
	}{
		{"old count insufficient", rows[4].b[:159]},
		{"new count insufficient", rows[4].b[:201]},
		{"detached count insufficient", rows[2].b[:124]},
		{"cleanup count insufficient", rows[2].b[:45]},
	} {
		t.Run(row.name, func(t *testing.T) { wantCodecDecodeError(t, row.b) })
	}
	shortBlob := append([]byte(nil), rows[3].b[:276]...)
	binary.BigEndian.PutUint32(shortBlob[272:], ^uint32(0))
	t.Run("blob uint32 max short", func(t *testing.T) { wantCodecDecodeError(t, shortBlob) })
	t.Run("cleanup GENERATION 9-byte span", func(t *testing.T) {
		a := modelPrune(false)
		a.NextGenerationID = 3
		a.Cleanup = &CleanupV1{Spans: []CleanupSpanV1{{Kind: 1, GenerationID: 2}}}
		if b := wantCodecRoundTrip(t, a); len(b) != 50 {
			t.Fatalf("record size = %d, want 50", len(b))
		}
	})
	t.Run("cleanup ranged 33-byte span", func(t *testing.T) {
		if b := wantCodecRoundTrip(t, modelPrune(false)); len(b) != 74 {
			t.Fatalf("record size = %d, want 74", len(b))
		}
	})
	runCodecCases(t, []authorityCase{
		{"detached count 1", modelDetachedAuthority()},
		{"old suffix count 1440", modelOrdinary(1, 1440, 0, 2000, 1, 0, 561)},
		{"new suffix count 1440", modelOrdinary(2, 0, 1440, 0, 1, 0, 0)},
		{"detached count 1440", modelDetached1440()},
		{"archive maximum U", modelBase(2, 0, 4_294_965_856)},
		{"pruned maximum B/U", modelBase(1, 4_294_952_176, 4_294_965_856)},
	})
	maxGeneration := modelBase(1, 0, 0)
	maxGeneration.ActiveGenerationID, maxGeneration.NextGenerationID = ^uint64(0)-1, ^uint64(0)
	maxGenerationBytes := wantCodecRoundTrip(t, maxGeneration)
	if !bytes.Equal(maxGenerationBytes[18:34], mustCodecHex(t, "fffffffffffffffeffffffffffffffff")) {
		t.Fatalf("maximum generation bytes = %x", maxGenerationBytes[18:34])
	}
	maxWork := modelReplay(1)
	maxWork.Replay.Target.CumulativeChainwork = modelWork(true)
	maxWorkBytes := wantCodecRoundTrip(t, maxWork)
	wantWork := make([]byte, 40)
	wantWork[3] = 1
	if !bytes.Equal(maxWorkBytes[149:189], wantWork) {
		t.Fatalf("2^288 chainwork bytes = %x", maxWorkBytes[149:189])
	}
	selected := modelBase(1, 0, 0)
	selected.NextGenerationID, selected.SelectedSide = 3, modelSide(2, 0, 1, 1, 1)
	appliedReplay := rows[3].a
	appliedReplay.ExcludedInvalidBranch = nil
	for _, row := range []struct {
		name     string
		baseSize int
		a        StorageAuthorityV1
	}{
		{"cleanup phase", 74, modelPrune(false)},
		{"replay phase", 194, modelReplay(1)},
		{"replay APPLIED phase", 234, appliedReplay},
		{"ordinary phase", 129, modelOrdinary(1, 1, 0, 1, 1, 0, 0)},
		{"ordinary full options", 436, rows[4].a},
		{"selected option", 146, selected},
		{"detached option", 174, modelDetachedAuthority()},
		{"pending and detached options", 175, rows[2].a},
	} {
		t.Run(row.name+" exact cap", func(t *testing.T) {
			payload := MaxMetadataBytes - row.baseSize - 44
			row.a.ExcludedInvalidBranch = &InvalidBranchV1{7, modelHash(72), make([]byte, payload)}
			if b := wantCodecRoundTrip(t, row.a); len(b) != MaxMetadataBytes {
				t.Fatalf("size = %d", len(b))
			}
			row.a.ExcludedInvalidBranch.ExactConsensusError = make([]byte, payload+1)
			if got, err := row.a.Encode(); got != nil || !exactErr(err) {
				t.Fatalf("cap+1 Encode = len %d, %v", len(got), err)
			}
		})
	}
	exact := modelBase(1, 0, 0)
	exact.ExcludedInvalidBranch = &InvalidBranchV1{7, modelHash(72), make([]byte, 1_048_492)}
	b := wantCodecRoundTrip(t, exact)
	if len(b) != 1_048_576 {
		t.Fatalf("exact cap size = %d", len(b))
	}
	over := modelBase(1, 0, 0)
	over.ExcludedInvalidBranch = &InvalidBranchV1{7, modelHash(72), bytes.Repeat([]byte{0x80}, 1_048_493)}
	expectedOver := modelBase(1, 0, 0)
	expectedOver.ExcludedInvalidBranch = &InvalidBranchV1{7, modelHash(72), bytes.Repeat([]byte{0x80}, 1_048_493)}
	if ValidateStorageAuthorityV1(over) != nil {
		t.Fatal("oversized witness must remain scalar-valid")
	}
	got, err := over.Encode()
	if got != nil || !exactErr(err) || !reflect.DeepEqual(over, expectedOver) {
		t.Fatalf("cap+1 Encode = %x, %v; input mutated=%v", got, err, !reflect.DeepEqual(over, expectedOver))
	}
	manual := append(append([]byte(nil), b...), 0)
	binary.BigEndian.PutUint32(manual[78:], 1_048_493)
	wantCodecDecodeError(t, manual)
}

func modelDetached1440() StorageAuthorityV1 {
	a := modelPrune(false)
	a.DetachedSuffix = modelDetached(1440, 1)
	return a
}

func TestStorageAuthorityV1CodecOwnership(t *testing.T) {
	rows := codecLiteralCases(t)
	a := rows[4].a
	before := codecLiteralCases(t)[4].a
	one, err := a.Encode()
	if err != nil || !reflect.DeepEqual(a, before) {
		t.Fatalf("Encode error/mutation = %v/%v", err, !reflect.DeepEqual(a, before))
	}
	two, err := a.Encode()
	if err != nil || !bytes.Equal(one, two) {
		t.Fatalf("second Encode = %v, equal=%v", err, bytes.Equal(one, two))
	}
	one[0] ^= 0xff
	if one[0] == two[0] {
		t.Fatal("encoded results share storage")
	}
	for _, boundary := range []struct {
		name   string
		mutate func(*StorageAuthorityV1)
	}{
		{"opaque blob", func(a *StorageAuthorityV1) { a.Ordinary.RecordedFailure.ExactResult[0] ^= 0xff }},
		{"point list", func(a *StorageAuthorityV1) { a.Ordinary.OldSuffix[0].BlockHash[0] ^= 0xff }},
		{"cursor pointer", func(a *StorageAuthorityV1) { a.Ordinary.Cursor.BlockHash[0] ^= 0xff }},
		{"cleanup span slice", func(a *StorageAuthorityV1) { a.Ordinary.CarriedCleanup.Spans[0].NextHeight++ }},
		{"failure hash pointer", func(a *StorageAuthorityV1) { a.Ordinary.RecordedFailure.FailedBlockHash[0] ^= 0xff }},
	} {
		t.Run("encode snapshot "+boundary.name, func(t *testing.T) {
			a := codecLiteralCases(t)[4].a
			encoded, err := a.Encode()
			if err != nil {
				t.Fatal(err)
			}
			boundary.mutate(&a)
			if !bytes.Equal(encoded, codecLiteralCases(t)[4].b) {
				t.Fatal("encoded result retained caller storage")
			}
		})
	}
	input := append([]byte(nil), two...)
	inputBefore := append([]byte(nil), input...)
	decoded, err := DecodeStorageAuthorityV1(input)
	if err != nil || !bytes.Equal(input, inputBefore) {
		t.Fatalf("Decode error/input mutation = %v/%v", err, !bytes.Equal(input, inputBefore))
	}
	if !reflect.DeepEqual(decoded, rows[4].a) {
		t.Fatal("Decode result mismatch")
	}
	input[423] ^= 0xff
	if !bytes.Equal(decoded.Ordinary.RecordedFailure.ExactResult, []byte{0, 0x31, 0xff}) {
		t.Fatal("decoded result aliases input")
	}
	for _, boundary := range []struct {
		name   string
		row    int
		mutate func(*StorageAuthorityV1)
	}{
		{"ExactResult", 4, func(a *StorageAuthorityV1) { a.Ordinary.RecordedFailure.ExactResult[0] ^= 0xff }},
		{"Evidence", 4, func(a *StorageAuthorityV1) { a.Ordinary.RecordedFailure.Evidence[0] ^= 0xff }},
		{"old suffix", 4, func(a *StorageAuthorityV1) { a.Ordinary.OldSuffix[0].BlockHash[0] ^= 0xff }},
		{"new suffix", 4, func(a *StorageAuthorityV1) { a.Ordinary.NewSuffix[0].BlockHash[0] ^= 0xff }},
		{"cursor pointer", 4, func(a *StorageAuthorityV1) { a.Ordinary.Cursor.BlockHash[0] ^= 0xff }},
		{"captured side pointer", 4, func(a *StorageAuthorityV1) { a.Ordinary.CapturedSelectedSide.TipHash[0] ^= 0xff }},
		{"cleanup span slice", 4, func(a *StorageAuthorityV1) { a.Ordinary.CarriedCleanup.Spans[0].NextHeight++ }},
		{"failure hash pointer", 4, func(a *StorageAuthorityV1) { a.Ordinary.RecordedFailure.FailedBlockHash[0] ^= 0xff }},
		{"invalid error blob", 3, func(a *StorageAuthorityV1) { a.ExcludedInvalidBranch.ExactConsensusError[0] ^= 0xff }},
		{"detached entry slice", 2, func(a *StorageAuthorityV1) { a.DetachedSuffix.Entries[0].Hash[0] ^= 0xff }},
	} {
		t.Run(boundary.name, func(t *testing.T) {
			first, err := DecodeStorageAuthorityV1(rows[boundary.row].b)
			if err != nil {
				t.Fatal(err)
			}
			second, err := DecodeStorageAuthorityV1(rows[boundary.row].b)
			if err != nil {
				t.Fatal(err)
			}
			boundary.mutate(&first)
			if reflect.DeepEqual(first, second) || !reflect.DeepEqual(second, rows[boundary.row].a) {
				t.Fatal("independent decoded result changed")
			}
		})
	}
	siblings, err := DecodeStorageAuthorityV1(rows[4].b)
	if err != nil {
		t.Fatal(err)
	}
	siblings.Ordinary.RecordedFailure.ExactResult[0] ^= 0xff
	if !bytes.Equal(siblings.Ordinary.RecordedFailure.Evidence, []byte{0x80, 0x41}) {
		t.Fatal("decoded result/evidence blobs share storage")
	}
	t.Run("equal opaque sibling ownership", func(t *testing.T) {
		shared := []byte{0x80}
		a := modelOrdinary(3, 1, 2, 1, 1, 0, 0)
		a.Ordinary.RecordedFailure.ExactResult, a.Ordinary.RecordedFailure.Evidence = shared, shared
		decoded, err := DecodeStorageAuthorityV1(wantCodecRoundTrip(t, a))
		if err != nil {
			t.Fatal(err)
		}
		decoded.Ordinary.RecordedFailure.ExactResult[0] ^= 0xff
		if decoded.Ordinary.RecordedFailure.Evidence[0] != 0x80 {
			t.Fatal("equal decoded result/evidence blobs share storage")
		}
	})
	for _, oldEmpty := range []bool{false, true} {
		empty := modelOrdinary(2, 0, 2, 0, 1, 0, 0)
		if oldEmpty {
			empty.Ordinary.OldSuffix = []AuthorityPointV1{}
		} else {
			empty.Ordinary.OldSuffix = nil
		}
		b, err := empty.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeStorageAuthorityV1(b)
		if err != nil || decoded.Ordinary.OldSuffix != nil {
			t.Fatalf("zero OldSuffix normalization = %#v, %v", decoded.Ordinary.OldSuffix, err)
		}
	}
	for _, newEmpty := range []bool{false, true} {
		empty := modelOrdinary(1, 1, 0, 1, 1, 0, 0)
		if newEmpty {
			empty.Ordinary.NewSuffix = []AuthorityPointV1{}
		} else {
			empty.Ordinary.NewSuffix = nil
		}
		b, err := empty.Encode()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeStorageAuthorityV1(b)
		if err != nil || decoded.Ordinary.NewSuffix != nil {
			t.Fatalf("zero NewSuffix normalization = %#v, %v", decoded.Ordinary.NewSuffix, err)
		}
	}
	wantCodecDecodeError(t, input[:100])
}
