package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"math"
	"testing"
)

func configForTest() ConfigV1 {
	return ConfigV1{Lower: 256, Now: 512, Upper: 1024, Growth: 256, Shrink: 512, PageSize: 256, MaxReaders: 1}
}

func TestConfigV1ExactRoundTripAndRejection(t *testing.T) {
	literalConfig := ConfigV1{Lower: 0x100, Now: 0x1_0200, Upper: 0x1_020300, Growth: 0x400, Shrink: 0x5_0600, PageSize: 0x100, MaxReaders: 0x1234}
	literal := []byte{
		0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 2, 0,
		0, 0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0,
		0, 0, 0, 0, 0, 5, 6, 0, 0, 0, 1, 0, 0, 0, 0x12, 0x34,
	}
	encoded, err := literalConfig.Encode()
	decoded, decErr := DecodeConfigV1(literal)
	if err != nil || decErr != nil || !bytes.Equal(encoded, literal) || decoded != literalConfig {
		t.Fatalf("literal config mismatch: %x %#v %v %v", encoded, decoded, err, decErr)
	}
	maximum := ConfigV1{Lower: math.MaxInt64 - 65_535, Now: math.MaxInt64 - 65_535, Upper: math.MaxInt64 - 65_535, Growth: 65_536, Shrink: 131_072, PageSize: 65_536, MaxReaders: 32_767}
	for _, want := range []ConfigV1{configForTest(), maximum} {
		b, err := want.Encode()
		got, decErr := DecodeConfigV1(b)
		if err != nil || decErr != nil || got != want || len(b) != 48 {
			t.Fatalf("config round trip: %#v %x %v %v", got, b, err, decErr)
		}
	}
	geometryBad := []struct {
		name string
		set  func(*ConfigV1)
	}{{"zero lower", func(c *ConfigV1) { c.Lower = 0 }}, {"zero now", func(c *ConfigV1) { c.Now = 0 }}, {"zero upper", func(c *ConfigV1) { c.Upper = 0 }}, {"zero growth", func(c *ConfigV1) { c.Growth = 0 }}, {"zero shrink", func(c *ConfigV1) { c.Shrink = 0 }}, {"over lower", func(c *ConfigV1) { c.Lower = uint64(math.MaxInt64) + 1 }}, {"over now", func(c *ConfigV1) { c.Now = uint64(math.MaxInt64) + 1 }}, {"over upper", func(c *ConfigV1) { c.Upper = uint64(math.MaxInt64) + 1 }}, {"over growth", func(c *ConfigV1) { c.Growth = uint64(math.MaxInt64) + 1 }}, {"over shrink", func(c *ConfigV1) { c.Shrink = uint64(math.MaxInt64) + 1 }}}
	for _, tc := range geometryBad {
		c := configForTest()
		tc.set(&c)
		if c.validGeometry() || acceptsConfig(c) {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	bad := []struct {
		name string
		set  func(*ConfigV1)
	}{{"lower order", func(c *ConfigV1) { c.Lower = 768 }}, {"now order", func(c *ConfigV1) { c.Now = 2048 }}, {"upper order", func(c *ConfigV1) { c.Upper = 256 }}, {"shrink order", func(c *ConfigV1) { c.Shrink = c.Growth }}, {"alignment", func(c *ConfigV1) { c.Lower++ }}, {"zero page size", func(c *ConfigV1) { c.PageSize = 0 }}, {"small page size", func(c *ConfigV1) { c.PageSize = 128 }}, {"non-power page size", func(c *ConfigV1) { c.PageSize = 768 }}, {"large page size", func(c *ConfigV1) { c.PageSize = 65_537 }}, {"zero readers", func(c *ConfigV1) { c.MaxReaders = 0 }}, {"large readers", func(c *ConfigV1) { c.MaxReaders = 32_768 }}}
	for _, tc := range bad {
		c := configForTest()
		tc.set(&c)
		if acceptsConfig(c) {
			t.Fatalf("%s accepted", tc.name)
		}
	}
	valid, _ := configForTest().Encode()
	for _, raw := range [][]byte{valid[:47], append(append([]byte(nil), valid...), 0)} {
		if _, err := DecodeConfigV1(raw); err == nil {
			t.Fatal("alternate config width accepted")
		}
	}
	swapped := append([]byte(nil), valid...)
	copy(swapped[0:8], valid[8:16])
	copy(swapped[8:16], valid[0:8])
	if _, err := DecodeConfigV1(swapped); err == nil {
		t.Fatal("field order mutation accepted")
	}
}

func TestDBIClosureAndKeys(t *testing.T) {
	wantNames := []string{"meta-v1", "utxo-v1", "canonical-v1", "headers-v1", "blocks-v1", "undo-v1", "staged-v1"}
	for i, d := range SchemaV1DBIs() {
		if d.Name != wantNames[i] || d.Rank != uint8(i) || d.Flags != 0 || ValidateDBI(d) != nil {
			t.Fatalf("DBI %d mismatch: %#v", i, d)
		}
	}
	for _, d := range []DBI{{Name: "meta-v2"}, {Name: "meta-v1", Rank: 1}, {Name: "meta-v1", Flags: 1}, {Rank: 7}} {
		if ValidateDBI(d) == nil {
			t.Fatalf("unknown DBI accepted: %#v", d)
		}
	}
	var h [32]byte
	h[0] = 1
	for _, tc := range []struct {
		rank uint8
		key  []byte
	}{
		{0, []byte{0}},
		{0, []byte{1}},
		{0, []byte{2}},
		{0, append([]byte{0x10}, be64(1)...)},
		{1, mustUTXOKey(t, 1, h, 0xff)},
		{2, mustHeightKey(t, 1, 0xff)},
		{2, mustHeightKey(t, 1, 0x100)},
		{3, h[:]},
		{4, h[:]},
		{5, UndoManifestKey(h)},
		{5, UndoEntryKey(h, h, 1, 2, 3)},
		{6, mustHeightKey(t, 1, 2)},
	} {
		if !validKey(tc.rank, tc.key) {
			t.Fatalf("valid key rank %d rejected", tc.rank)
		}
	}
	if bytes.Compare(mustHeightKey(t, 1, 0xff), mustHeightKey(t, 1, 0x100)) >= 0 {
		t.Fatal("big-endian height ordering wrong")
	}
	txid := [32]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f}
	wantUTXOKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x11, 0x22, 0x33, 0x44}
	gotUTXOKey := mustUTXOKey(t, 0x0102030405060708, txid, 0x11223344)
	gotHeightKey := mustHeightKey(t, 0x0102030405060708, 0x1112131415161718)
	if !bytes.Equal(gotUTXOKey, wantUTXOKey) || !bytes.Equal(gotHeightKey, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}) {
		t.Fatal("literal image key mismatch")
	}
	if bytes.Compare(mustUTXOKey(t, 1, txid, 0xff), mustUTXOKey(t, 1, txid, 0x100)) >= 0 {
		t.Fatal("big-endian vout ordering wrong")
	}
	for _, tc := range []struct {
		rank uint8
		key  []byte
	}{{0, []byte{3}}, {0, append([]byte{0x10}, make([]byte, 8)...)}, {1, make([]byte, 44)}, {2, make([]byte, 16)}, {3, make([]byte, 31)}, {5, append(UndoManifestKey(h), 0)}, {5, append(h[:], 2)}, {6, make([]byte, 15)}, {7, nil}} {
		if validKey(tc.rank, tc.key) {
			t.Fatalf("bad key rank %d accepted", tc.rank)
		}
	}
}

func TestMetadataValuesAndOwnership(t *testing.T) {
	version := SchemaVersionValue()
	config, _ := configForTest().Encode()
	counters := LogicalCounterValue(0x0102030405060708, 0x1112131415161718)
	bytesCount, entries, counterErr := DecodeLogicalCounterValue(counters)
	if !bytes.Equal(version, []byte{0, 0, 0, 1}) || DecodeSchemaVersionValue(version) != nil || !bytes.Equal(counters, []byte{1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}) || counterErr != nil || bytesCount != 0x0102030405060708 || entries != 0x1112131415161718 {
		t.Fatal("semantic metadata codecs mismatch")
	}
	ownedVersion, ownedCounters := SchemaVersionValue(), LogicalCounterValue(bytesCount, entries)
	version[0], counters[0] = 9, 9
	if ownedVersion[0] != 0 || ownedCounters[0] != 1 {
		t.Fatal("semantic metadata encoder reused result bytes")
	}
	version, counters = ownedVersion, ownedCounters
	for kind, in := range map[byte][]byte{0: version, 1: config, 2: {}, 0x10: counters} {
		got, err := MetaValue(kind, in)
		if err != nil || !bytes.Equal(got, in) {
			t.Fatalf("meta kind %x rejected", kind)
		}
		if kind == 2 && got == nil {
			t.Fatal("present-empty metadata collapsed to absent")
		}
		if len(in) > 0 {
			in[0] ^= 0xff
			if got[0] == in[0] {
				t.Fatal("metadata borrowed caller bytes")
			}
		}
	}
	maximum := make([]byte, MaxMetadataBytes)
	if got, err := MetaValue(2, maximum); err != nil || len(got) != MaxMetadataBytes {
		t.Fatal("maximum metadata rejected")
	}
	for _, tc := range []struct {
		kind  byte
		value []byte
	}{{0, []byte{0, 0, 0, 2}}, {0, make([]byte, 3)}, {0, []byte{0, 0, 0, 1, 0}}, {1, make([]byte, 48)}, {2, make([]byte, MaxMetadataBytes+1)}, {0x10, make([]byte, 15)}, {0x10, make([]byte, 17)}, {3, nil}} {
		if _, err := MetaValue(tc.kind, tc.value); err == nil {
			t.Fatalf("bad meta %x accepted", tc.kind)
		}
	}
	if k, _ := MetaKey(2, 0); !bytes.Equal(k, []byte{2}) {
		t.Fatal("global metadata key mismatch")
	}
	if _, err := MetaKey(2, 1); err == nil {
		t.Fatal("global key accepted image prefix")
	}
	if _, err := MetaKey(0x10, 0); err == nil {
		t.Fatal("image key accepted zero image")
	}
	if key, err := MetaKey(0x10, 0x0102030405060708); err != nil || !bytes.Equal(key, []byte{0x10, 1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("literal counter key mismatch")
	}
}

func TestUTXOCompactSizeBoundariesAndOwnership(t *testing.T) {
	literal := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 3, 0xaa, 0xbb, 0xcc, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 1}
	wantLiteral := UTXOValue{Value: 0x0807060504030201, CovenantType: 0x0a09, CovenantData: []byte{0xaa, 0xbb, 0xcc}, CreationHeight: 0x1817161514131211, Coinbase: true}
	encoded, err := wantLiteral.Encode()
	decoded, decErr := DecodeUTXOValue(literal)
	if err != nil || decErr != nil || !bytes.Equal(encoded, literal) || decoded.Value != wantLiteral.Value || decoded.CovenantType != wantLiteral.CovenantType || !bytes.Equal(decoded.CovenantData, wantLiteral.CovenantData) || decoded.CreationHeight != wantLiteral.CreationHeight || !decoded.Coinbase {
		t.Fatalf("literal UTXO mismatch: %x %#v %v %v", encoded, decoded, err, decErr)
	}
	nonCoinbaseLiteral := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 3, 0xaa, 0xbb, 0xcc, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0}
	wantLiteral.Coinbase = false
	encoded, err = wantLiteral.Encode()
	decoded, decErr = DecodeUTXOValue(nonCoinbaseLiteral)
	if err != nil || decErr != nil || !bytes.Equal(encoded, nonCoinbaseLiteral) || decoded.Value != wantLiteral.Value || decoded.CovenantType != wantLiteral.CovenantType || !bytes.Equal(decoded.CovenantData, wantLiteral.CovenantData) || decoded.CreationHeight != wantLiteral.CreationHeight || decoded.Coinbase {
		t.Fatalf("literal non-coinbase UTXO mismatch: %x %#v %v %v", encoded, decoded, err, decErr)
	}
	cases := []struct {
		n      int
		prefix []byte
	}{{0, []byte{0}}, {252, []byte{252}}, {253, []byte{0xfd, 0xfd, 0}}, {65_535, []byte{0xfd, 0xff, 0xff}}, {65_536, []byte{0xfe, 0, 0, 1, 0}}}
	for _, tc := range cases {
		data := bytes.Repeat([]byte{7}, tc.n)
		want := UTXOValue{Value: 9, CovenantType: 10, CovenantData: data, CreationHeight: 11, Coinbase: true}
		b, err := want.Encode()
		got, decErr := DecodeUTXOValue(b)
		if err != nil || decErr != nil || !bytes.Equal(b[10:10+len(tc.prefix)], tc.prefix) || got.Value != want.Value || got.CovenantType != want.CovenantType || got.CreationHeight != want.CreationHeight || !got.Coinbase || !bytes.Equal(got.CovenantData, data) {
			t.Fatalf("UTXO n=%d round trip failed", tc.n)
		}
		if tc.n > 0 {
			data[0] = 8
			b[10+len(tc.prefix)] = 9
			if got.CovenantData[0] != 7 {
				t.Fatalf("UTXO n=%d borrowed bytes", tc.n)
			}
		}
	}
	zero, _ := (UTXOValue{}).Encode()
	bad := [][]byte{zero[:19], append(append([]byte(nil), zero...), 0), append([]byte(nil), zero...)}
	bad[2][len(bad[2])-1] = 2
	nonminimal := append([]byte(nil), zero[:10]...)
	nonminimal = append(nonminimal, 0xfd, 0, 0)
	nonminimal = append(nonminimal, zero[11:]...)
	bad = append(bad, nonminimal, append(append([]byte(nil), zero[:10]...), 0xfd), append(append([]byte(nil), zero[:10]...), 0xff))
	nonminimalFE := append(append(make([]byte, 10), 0xfe, 0xff, 0xff, 0, 0), make([]byte, 65_535+9)...)
	overboundFE := append(append(make([]byte, 10), 0xfe, 1, 0, 1, 0), make([]byte, 65_537+9)...)
	bad = append(bad, nonminimalFE, overboundFE)
	for _, prefix := range [][]byte{{0xfd}, {0xfd, 1}, {0xfe}, {0xfe, 1}, {0xfe, 1, 2}, {0xfe, 1, 2, 3}} {
		if _, _, ok := readCompactSize(prefix); ok {
			t.Fatalf("truncated CompactSize accepted: %x", prefix)
		}
	}
	for i, b := range bad {
		if _, err := DecodeUTXOValue(b); err == nil {
			t.Fatalf("bad UTXO %d accepted", i)
		}
	}
	if _, err := (UTXOValue{CovenantData: make([]byte, MaxCovenantBytes+1)}).Encode(); err == nil {
		t.Fatal("oversize UTXO encoded")
	}
}

func TestChainHashAndUndoRows(t *testing.T) {
	b := [32]byte{2}
	chainBlock := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	parent := [32]byte{33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}
	work := [40]byte{65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104}
	wantChain := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104}
	if chain := ChainValue(chainBlock, parent, work); !bytes.Equal(chain, wantChain) {
		t.Fatal("uint320 chain value layout mismatch")
	}
	header := bytes.Repeat([]byte{5}, 116)
	hash := sha3.Sum256(header)
	block := append(append([]byte(nil), header...), 6)
	for _, tc := range []struct {
		rank  uint8
		value []byte
	}{{3, header}, {4, block}} {
		got, err := HashBoundValue(hash, tc.value, tc.rank == 4)
		if err != nil || !bytes.Equal(got, tc.value) {
			t.Fatal("hash-bound value rejected")
		}
		tc.value[0] ^= 1
		if got[0] == tc.value[0] {
			t.Fatal("hash-bound value borrowed caller bytes")
		}
	}
	if _, err := HashBoundValue(b, header, false); err == nil {
		t.Fatal("substituted header key accepted")
	}
	if _, err := HashBoundValue(hash, append(header, 0), false); err == nil {
		t.Fatal("long header accepted")
	}
	if _, err := HashBoundValue(hash, header[:115], true); err == nil {
		t.Fatal("short block accepted")
	}
	maximumBlock := make([]byte, MaxBlockBytes)
	copy(maximumBlock, bytes.Repeat([]byte{5}, 116))
	if got, err := HashBoundValue(hash, maximumBlock, true); err != nil || len(got) != MaxBlockBytes {
		t.Fatal("maximum block rejected")
	}
	if _, err := HashBoundValue(hash, make([]byte, MaxBlockBytes+1), true); err == nil {
		t.Fatal("oversize block accepted")
	}
	manifestKey := UndoManifestKey(chainBlock)
	wantManifestKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0}
	manifest := UndoManifestValue(0x0102030405060708, [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}, 0x11121314, 0x21222324)
	wantManifest := []byte{1, 1, 2, 3, 4, 5, 6, 7, 8, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24}
	badManifestVersion := []byte{2, 1, 2, 3, 4, 5, 6, 7, 8, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22, 0x23, 0x24}
	entryKey := UndoEntryKey(chainBlock, parent, 0x01020304, 0x05060708, 0x090a0b0c)
	wantEntryKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 1, 1, 2, 3, 4, 5, 6, 7, 8, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 9, 10, 11, 12}
	utxo, _ := (UTXOValue{}).Encode()
	if !bytes.Equal(manifestKey, wantManifestKey) || !bytes.Equal(manifest, wantManifest) || !bytes.Equal(entryKey, wantEntryKey) || ValidateRow(schemaDBIs[5], manifestKey, manifest) != nil || ValidateRow(schemaDBIs[5], entryKey, utxo) != nil {
		t.Fatal("undo exact forms rejected")
	}
	for _, tc := range []struct{ key, value []byte }{{append(manifestKey, 0), manifest}, {manifestKey, append(manifest, 0)}, {manifestKey, badManifestVersion}, {append(hash[:], 2), manifest}, {entryKey, append(utxo, 0)}} {
		if ValidateRow(schemaDBIs[5], tc.key, tc.value) == nil {
			t.Fatal("malformed undo accepted")
		}
	}
}

func TestValidateEveryDBIRow(t *testing.T) {
	var hash [32]byte
	header := make([]byte, 116)
	hash = sha3.Sum256(header)
	config, _ := configForTest().Encode()
	version := []byte{0, 0, 0, 1}
	utxo, _ := (UTXOValue{}).Encode()
	rows := []struct {
		d          DBI
		key, value []byte
	}{
		{schemaDBIs[0], []byte{0}, version},
		{schemaDBIs[0], []byte{1}, config},
		{schemaDBIs[0], []byte{2}, []byte{}},
		{schemaDBIs[0], append([]byte{0x10}, be64(1)...), make([]byte, 16)},
		{schemaDBIs[1], mustUTXOKey(t, 1, hash, 0), utxo},
		{schemaDBIs[2], mustHeightKey(t, 1, 0), make([]byte, 104)},
		{schemaDBIs[3], hash[:], header},
		{schemaDBIs[4], hash[:], header},
		{schemaDBIs[6], mustHeightKey(t, 1, 0), make([]byte, 104)},
	}
	for i, row := range rows {
		if err := ValidateRow(row.d, row.key, row.value); err != nil {
			t.Fatalf("row %d rejected", i)
		}
	}
	for i, row := range rows {
		mutated := append([]byte(nil), row.key...)
		mutated = append(mutated, 0)
		if ValidateRow(row.d, mutated, row.value) == nil {
			t.Fatalf("row %d trailing key accepted", i)
		}
	}
	if ValidateRow(DBI{Name: "unknown"}, nil, nil) == nil {
		t.Fatal("unknown DBI dispatched")
	}
	if ValidateRow(schemaDBIs[0], []byte{0}, []byte{0, 0, 0, 2}) == nil || ValidateRow(schemaDBIs[0], append([]byte{0x10}, be64(1)...), make([]byte, 15)) == nil {
		t.Fatal("semantic metadata validation bypassed")
	}
	if ValidateRow(schemaDBIs[2], mustHeightKey(t, 1, 0), make([]byte, 103)) == nil || ValidateRow(schemaDBIs[6], mustHeightKey(t, 1, 0), make([]byte, 105)) == nil {
		t.Fatal("chain value width mutation accepted")
	}
}

func acceptsConfig(c ConfigV1) bool {
	if _, err := c.Encode(); err == nil {
		return true
	}
	_, err := DecodeConfigV1(configBytes(c))
	return err == nil
}

func configBytes(c ConfigV1) []byte {
	b := make([]byte, 48)
	for i, n := range [...]uint64{c.Lower, c.Now, c.Upper, c.Growth, c.Shrink} {
		binary.BigEndian.PutUint64(b[i*8:], n)
	}
	binary.BigEndian.PutUint32(b[40:], c.PageSize)
	binary.BigEndian.PutUint32(b[44:], c.MaxReaders)
	return b
}

func be64(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func mustUTXOKey(t *testing.T, image uint64, txid [32]byte, vout uint32) []byte {
	t.Helper()
	b, err := UTXOKey(image, txid, vout)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHeightKey(t *testing.T, image, height uint64) []byte {
	t.Helper()
	b, err := HeightKey(image, height)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestConstructorsRejectZeroImage(t *testing.T) {
	if _, err := UTXOKey(0, [32]byte{}, 0); err == nil {
		t.Fatal("zero-image UTXO accepted")
	}
	if _, err := HeightKey(0, 0); err == nil {
		t.Fatal("zero-image height accepted")
	}
	key, _ := UTXOKey(1, [32]byte{}, 0)
	key[0] = 9
	want, _ := UTXOKey(1, [32]byte{}, 0)
	if bytes.Equal(key, want) {
		t.Fatal("constructor did not own result")
	}
}
