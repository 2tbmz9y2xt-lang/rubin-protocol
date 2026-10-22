package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func treeInputSnapshot(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func treeLeaf(key [36]byte) TreeNodeIDV1 {
	return TreeNodeIDV1{Kind: 1, Depth: 288, RoutingKey: key}
}

func treeBranch(depth uint16, prefix [36]byte) TreeNodeIDV1 {
	return TreeNodeIDV1{Kind: 2, Depth: depth, Prefix: prefix}
}

func treeKeyLiteral(t *testing.T, upper, code string) []byte {
	t.Helper()
	return mustCodecHex(t, "0102030405060708"+upper+code)
}

func TestTreeFamilies(t *testing.T) {
	want := [9]DBI{
		{"meta-v1", 0, 0},
		{"utxo-v1", 1, 0},
		{"canonical-v1", 2, 0},
		{"headers-v1", 3, 0},
		{"blocks-v1", 4, 0},
		{"undo-v1", 5, 0},
		{"staged-v1", 6, 0},
		{"canonical-owner-v1", 7, 0},
		{"tree-node-v1", 8, 0},
	}
	if got := TreeSchemaV1DBIs(); got != want {
		t.Fatalf("tree families = %#v", got)
	}
	if got := SchemaV2DBIs(); !reflect.DeepEqual(got[:], want[:8]) {
		t.Fatalf("historical families = %#v", got)
	}
	for _, d := range want {
		if err := TreeValidateDBI(d); err != nil {
			t.Fatalf("descriptor %d: %v", d.Rank, err)
		}
		for _, bad := range []DBI{{d.Name + "x", d.Rank, 0}, {d.Name, d.Rank, 1}, {d.Name, 255, 0}} {
			if err := TreeValidateDBI(bad); !exactErr(err) {
				t.Fatalf("forged descriptor = %v", err)
			}
			if err := ValidateTreeRow(bad, nil, nil); !exactErr(err) {
				t.Fatalf("forged row descriptor = %v", err)
			}
		}
	}
	one, two := TreeSchemaVersionValue(), TreeSchemaVersionValue()
	if !bytes.Equal(one, []byte{0, 0, 0, 3}) || !bytes.Equal(SchemaVersionValue(), []byte{0, 0, 0, 2}) {
		t.Fatal("tree/historical version bytes")
	}
	one[3] = 9
	if two[3] != 3 {
		t.Fatal("version outputs alias")
	}
	descriptors := TreeSchemaV1DBIs()
	descriptors[0].Name = "changed"
	if TreeSchemaV1DBIs()[0].Name != "meta-v1" {
		t.Fatal("descriptor output changed inventory")
	}
}

func TestTreeNodeCanonicalKey(t *testing.T) {
	for _, row := range []struct {
		depth               uint16
		prefix, upper, code string
	}{
		{0, strings.Repeat("00", 36), strings.Repeat("ff", 36), "0120"},
		{7, "fe" + strings.Repeat("00", 35), strings.Repeat("ff", 36), "0119"},
		{8, "a7" + strings.Repeat("00", 35), "a7" + strings.Repeat("ff", 35), "0118"},
		{9, "a780" + strings.Repeat("00", 34), "a7" + strings.Repeat("ff", 35), "0117"},
		{255, strings.Repeat("55", 31) + "5400000000", strings.Repeat("55", 31) + "55ffffffff", "0021"},
		{256, strings.Repeat("55", 32) + "00000000", strings.Repeat("55", 32) + "ffffffff", "0020"},
		{287, strings.Repeat("55", 35) + "54", strings.Repeat("55", 36), "0001"},
	} {
		t.Run(fmt.Sprint(row.depth), func(t *testing.T) {
			var prefix [36]byte
			copy(prefix[:], mustCodecHex(t, row.prefix))
			id, literal := treeBranch(row.depth, prefix), treeKeyLiteral(t, row.upper, row.code)
			got, err := TreeNodeKey(0x0102030405060708, id)
			if err != nil || !bytes.Equal(got, literal) {
				t.Fatalf("tree node canonical key = %x, %v; want %x", got, err, literal)
			}
			g, decoded, err := DecodeTreeNodeKey(literal)
			if err != nil || g != 0x0102030405060708 || decoded != id {
				t.Fatalf("decoded canonical key = %x, %#v, %v", g, decoded, err)
			}
			bad := bytes.Clone(literal)
			bad[43] ^= 1
			wantTreeKeyError(t, bad)
		})
	}
	for _, key := range [][36]byte{{}, {0xff, 0x80, 0x01}} {
		id := treeLeaf(key)
		want := append(mustCodecHex(t, "ffffffffffffffff"), key[:]...)
		want = append(want, 0, 0)
		got, err := TreeNodeKey(^uint64(0), id)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("leaf exact key = %x, %v", got, err)
		}
		g, decoded, err := DecodeTreeNodeKey(want)
		if err != nil || g != ^uint64(0) || decoded != id {
			t.Fatalf("leaf decoded key = %d, %#v, %v", g, decoded, err)
		}
	}
}

func wantTreeKeyError(t *testing.T, input []byte) {
	t.Helper()
	before := bytes.Clone(input)
	g, id, err := DecodeTreeNodeKey(input)
	if g != 0 || id != (TreeNodeIDV1{}) || !exactErr(err) || !bytes.Equal(input, before) {
		t.Fatalf("node key refusal = %d, %#v, %v; input changed", g, id, err)
	}
}

func TestTreeNodeIDRefusal(t *testing.T) {
	for _, id := range []TreeNodeIDV1{
		{},
		{Kind: 3},
		{Kind: 255},
		{Kind: 1, Depth: 287},
		{Kind: 1, Depth: 288, Prefix: [36]byte{1}},
		{Kind: 2, Depth: 288},
		{Kind: 2, Depth: 65535},
		{Kind: 2, RoutingKey: [36]byte{1}},
		{Kind: 2, Depth: 7, Prefix: [36]byte{1}},
	} {
		before := id
		if got, err := TreeNodeKey(1, id); got != nil || !exactErr(err) || id != before {
			t.Fatalf("node ID encode refusal = %x, %v", got, err)
		}
		if got, err := (TreeNodeV1{}).Encode(id); got != nil || !exactErr(err) {
			t.Fatalf("node value invalid ID = %x, %v", got, err)
		}
		wantTreeNodeError(t, id, nil)
	}
	if b, err := TreeNodeKey(0, treeLeaf([36]byte{})); b != nil || !exactErr(err) {
		t.Fatalf("zero generation = %x, %v", b, err)
	}
	literal := treeKeyLiteral(t, strings.Repeat("ff", 36), "0120")
	for _, bad := range [][]byte{nil, literal[:45], append(bytes.Clone(literal), 0), make([]byte, 46)} {
		wantTreeKeyError(t, bad)
	}
	for _, code := range []uint16{289, 65535} {
		bad := bytes.Clone(literal)
		binary.BigEndian.PutUint16(bad[44:], code)
		wantTreeKeyError(t, bad)
	}
}

// The expected identity order is explicit. Subsets preserve it even when every
// represented parent or either child is missing; no present links are used.
func TestTreePostorder(t *testing.T) {
	var full [36]byte
	for i := range full {
		full[i] = 0xff
	}
	prefix287 := full
	prefix287[35] = 0xfe
	prefix256 := full
	copy(prefix256[32:], []byte{0, 0, 0, 0})
	order := []TreeNodeIDV1{
		treeLeaf([36]byte{}), treeLeaf([36]byte{0x7f}), treeBranch(1, [36]byte{}),
		treeLeaf(full), treeBranch(287, prefix287), treeBranch(256, prefix256),
		treeBranch(1, [36]byte{0x80}), treeBranch(0, [36]byte{}),
	}
	for mask := 1; mask < 1<<len(order); mask++ {
		var want []TreeNodeIDV1
		var keys [][]byte
		for i, id := range order {
			if mask&(1<<i) == 0 {
				continue
			}
			key, err := TreeNodeKey(9, id)
			if err != nil {
				t.Fatal(err)
			}
			want, keys = append(want, id), append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
		for i, key := range keys {
			g, id, err := DecodeTreeNodeKey(key)
			if err != nil || g != 9 || id != want[i] {
				t.Fatalf("tree postorder mask=%x at=%d got=%#v want=%#v err=%v", mask, i, id, want[i], err)
			}
		}
	}
}

func treeChildLiteral(t *testing.T, side, kind byte) (TreeNodeIDV1, []byte) {
	t.Helper()
	if kind == 1 {
		key := [36]byte{side << 7}
		return treeLeaf(key), append(append([]byte(nil), key[:]...), 0, 0)
	}
	prefix := [36]byte{side << 7}
	upper := "7f" + strings.Repeat("ff", 35)
	if side == 1 {
		upper = strings.Repeat("ff", 36)
	}
	return treeBranch(1, prefix), mustCodecHex(t, upper+"011f")
}

func wantTreeNodeError(t *testing.T, id TreeNodeIDV1, input []byte) {
	t.Helper()
	before := bytes.Clone(input)
	got, err := DecodeTreeNodeValue(id, input)
	if !reflect.DeepEqual(got, TreeNodeV1{}) || !exactErr(err) || !bytes.Equal(input, before) {
		t.Fatalf("node value refusal = %#v, %v; input changed", got, err)
	}
}

func TestTreeNodeValues(t *testing.T) {
	parent := treeBranch(0, [36]byte{})
	for _, zeroKind := range []byte{1, 2} {
		for _, oneKind := range []byte{1, 2} {
			t.Run(fmt.Sprintf("%d+%d", zeroKind, oneKind), func(t *testing.T) {
				zero, zeroBytes := treeChildLiteral(t, 0, zeroKind)
				one, oneBytes := treeChildLiteral(t, 1, oneKind)
				node := TreeNodeV1{Zero: &TreeChildV1{zero, modelHash(31)}, One: &TreeChildV1{one, modelHash(32)}}
				literal := append(bytes.Clone(zeroBytes), mustCodecHex(t, codecZeros(62)+"1f")...)
				literal = append(literal, oneBytes...)
				literal = append(literal, mustCodecHex(t, codecZeros(62)+"20")...)
				got, err := node.Encode(parent)
				if err != nil || !bytes.Equal(got, literal) {
					t.Fatalf("branch value = %x, %v; want %x", got, err, literal)
				}
				decoded, err := DecodeTreeNodeValue(parent, literal)
				if err != nil || !reflect.DeepEqual(decoded, node) {
					t.Fatalf("branch decode = %#v, %v", decoded, err)
				}
				node.Zero.Digest[31] = 99
				literal[38] = 99
				if got[69] != 31 || decoded.Zero.Digest[0] != 0 || decoded.One.Digest[31] != 32 {
					t.Fatal("node encoded/decoded isolation")
				}
				decoded.Zero.Digest[0] = 77
				if decoded.One.Digest[0] != 0 {
					t.Fatal("child pointers alias")
				}
			})
		}
	}
	leaf, literal := treeLeaf([36]byte{}), bytes.Repeat([]byte{0x73}, 32)
	got, err := (TreeNodeV1{LeafDigest: [32]byte{0x73}}).Encode(leaf)
	if err != nil || len(got) != 32 || got[0] != 0x73 || !bytes.Equal(got[1:], make([]byte, 31)) {
		t.Fatalf("leaf value = %x, %v", got, err)
	}
	decoded, err := DecodeTreeNodeValue(leaf, literal)
	if err != nil || !bytes.Equal(decoded.LeafDigest[:], literal) {
		t.Fatalf("leaf decode = %#v, %v", decoded, err)
	}
	literal[0] = 0
	if decoded.LeafDigest[0] != 0x73 {
		t.Fatal("leaf decode aliases source")
	}
}

func TestTreeChildRelation(t *testing.T) {
	parent := treeBranch(8, [36]byte{0x80})
	valid := TreeNodeV1{Zero: &TreeChildV1{ID: treeLeaf([36]byte{0x80})}, One: &TreeChildV1{ID: treeLeaf([36]byte{0x80, 0x80})}}
	for _, row := range []mutationCase[TreeNodeV1]{
		{"missing zero", func(n *TreeNodeV1) { n.Zero = nil }},
		{"missing one", func(n *TreeNodeV1) { n.One = nil }},
		{"both missing", func(n *TreeNodeV1) { n.Zero, n.One = nil, nil }},
		{"leaf sibling digest", func(n *TreeNodeV1) { n.LeafDigest[0] = 1 }},
		{"parent zero", func(n *TreeNodeV1) { n.Zero.ID = parent }},
		{"same depth one", func(n *TreeNodeV1) { n.One.ID = treeBranch(8, [36]byte{0x81}) }},
		{"shallower zero", func(n *TreeNodeV1) { n.Zero.ID = treeBranch(7, [36]byte{0x80}) }},
		{"wrong zero side", func(n *TreeNodeV1) { n.Zero.ID = treeLeaf([36]byte{0x80, 0x80}) }},
		{"wrong one side", func(n *TreeNodeV1) { n.One.ID = treeLeaf([36]byte{0x80}) }},
		{"wrong zero prefix", func(n *TreeNodeV1) { n.Zero.ID = treeLeaf([36]byte{0x40}) }},
		{"wrong one prefix", func(n *TreeNodeV1) { n.One.ID = treeLeaf([36]byte{0x40, 0x80}) }},
		{"unknown zero kind", func(n *TreeNodeV1) { n.Zero.ID.Kind = 3 }},
		{"unknown one kind", func(n *TreeNodeV1) { n.One.ID.Kind = 0 }},
		{"duplicate children", func(n *TreeNodeV1) { n.One.ID = n.Zero.ID }},
	} {
		t.Run(row.name, func(t *testing.T) {
			n := TreeNodeV1{Zero: &TreeChildV1{ID: valid.Zero.ID}, One: &TreeChildV1{ID: valid.One.ID}}
			row.mutate(&n)
			before := treeInputSnapshot(t, n)
			if b, err := n.Encode(parent); b != nil || !exactErr(err) || !bytes.Equal(before, treeInputSnapshot(t, n)) {
				t.Fatalf("tree child relation encode = %x, %v", b, err)
			}
		})
	}
	base := make([]byte, 140)
	base[0], base[70], base[71] = 0x80, 0x80, 0x80
	if got, err := DecodeTreeNodeValue(parent, base); err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatalf("valid child relation sibling = %#v, %v", got, err)
	}
	for _, bad := range [][]byte{nil, base[:70], base[:139], append(bytes.Clone(base), 0), append(bytes.Clone(base), make([]byte, 70)...)} {
		wantTreeNodeError(t, parent, bad)
	}
	for _, row := range []struct {
		name   string
		offset int
		suffix []byte
	}{
		{"zero wrong side", 0, append([]byte{0x80, 0x80}, make([]byte, 36)...)},
		{"one wrong side", 70, append([]byte{0x80}, make([]byte, 37)...)},
		{"zero wrong prefix", 0, append([]byte{0x40}, make([]byte, 37)...)},
		{"one wrong prefix", 70, append([]byte{0x40, 0x80}, make([]byte, 36)...)},
		{"parent reference", 0, mustCodecHex(t, "80"+strings.Repeat("ff", 35)+"0118")},
		{"shallower reference", 70, mustCodecHex(t, "81"+strings.Repeat("ff", 35)+"0119")},
		{"unknown reference kind", 0, mustCodecHex(t, strings.Repeat("ff", 36)+"0121")},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := bytes.Clone(base)
			copy(bad[row.offset:], row.suffix)
			wantTreeNodeError(t, parent, bad)
		})
	}
	leaf := treeLeaf([36]byte{})
	for _, n := range []TreeNodeV1{{Zero: &TreeChildV1{}}, {One: &TreeChildV1{}}, {Zero: &TreeChildV1{}, One: &TreeChildV1{}}} {
		if b, err := n.Encode(leaf); b != nil || !exactErr(err) {
			t.Fatalf("leaf extra sibling = %x, %v", b, err)
		}
	}
	wantTreeNodeError(t, leaf, make([]byte, 31))
	wantTreeNodeError(t, leaf, make([]byte, 33))
}

func TestTreeFull148Admission(t *testing.T) {
	header := make([]byte, 148)
	for i := range header {
		header[i] = byte(i)
	}
	key := sha3.Sum256(header)
	old := sha3.Sum256(header[:116])
	for _, rank := range []uint8{3, 4} {
		dbi := DBI{[]string{"headers-v1", "blocks-v1"}[rank-3], rank, 0}
		for _, width := range []int{147, 148, 149, 68000157, 68000158} {
			t.Run(fmt.Sprintf("rank%d/%d", rank, width), func(t *testing.T) {
				input := make([]byte, width)
				copy(input, header)
				want := width == 148 || rank == 4 && (width == 149 || width == 68000157)
				var expected error
				if !want {
					expected = errSchema
				}
				wantTreeLiteral(t, dbi, key[:], input, expected)
				if err := ValidateTreeRow(dbi, key[:], input); (err == nil) != want || err != nil && !exactErr(err) {
					t.Fatalf("tree full148 admission = %v; want valid=%v", err, want)
				}
				if !bytes.Equal(input[:min(width, 148)], header[:min(width, 148)]) {
					t.Fatal("admission changed input")
				}
			})
		}
		changed := bytes.Clone(header)
		changed[147] ^= 1
		for _, wrong := range [][32]byte{key, old, {}} {
			wantTreeLiteral(t, dbi, wrong[:], changed, errSchema)
			if err := ValidateTreeRow(dbi, wrong[:], changed); !exactErr(err) {
				t.Fatalf("tree full148 wrong key = %v", err)
			}
		}
		rekeyed := sha3.Sum256(changed)
		wantTreeLiteral(t, dbi, rekeyed[:], changed, nil)
		if err := ValidateTreeRow(dbi, rekeyed[:], changed); err != nil {
			t.Fatalf("tree full148 rekey = %v", err)
		}
	}
	if err := ValidateTreeRow(DBI{"blocks-v1", 9, 0}, key[:], header); !exactErr(err) {
		t.Fatalf("unknown rank fell through = %v", err)
	}
}

func wantTreeLiteral(t *testing.T, dbi DBI, key, input []byte, expected error) {
	t.Helper()
	keyBefore, before := bytes.Clone(key), bytes.Clone(input)
	var got error
	mismatch := false
	allocations := testing.AllocsPerRun(1, func() {
		got = ValidateTreeRow(dbi, key, input)
		mismatch = mismatch || expected == nil && got != nil || expected != nil && !exactErr(got)
	})
	if mismatch {
		t.Fatalf("tree literal result = %v; want %v", got, expected)
	}
	if allocations != 0 {
		t.Fatalf("tree literal allocations = %v; want 0", allocations)
	}
	if !bytes.Equal(key, keyBefore) || !bytes.Equal(input, before) {
		t.Fatal("tree literal changed input")
	}
}

func TestTreeMetaRows(t *testing.T) {
	meta := DBI{"meta-v1", 0, 0}
	config := mustCodecHex(t, "000000000000010000000000000002000000000000000400000000000000010000000000000002000000010000000001")
	authority := treeEnvelopeLiteral(codecLiteralCases(t)[0].b, 0, 0, nil)
	binary.BigEndian.PutUint64(authority[22+26:], 20)
	evidence := treeEvidenceLiteral(t)
	hash := sha3.Sum256(evidence)
	nodeKey := treeKeyLiteral(t, strings.Repeat("00", 36), "0000")
	generation := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	utxo := make([]byte, 20)
	utxoKey := append(bytes.Clone(generation), make([]byte, 36)...)
	for _, row := range []struct {
		size   int
		prefix []byte
	}{{0, []byte{0}}, {1, []byte{1}}, {252, []byte{252}}, {253, []byte{253, 253, 0}}, {65535, []byte{253, 255, 255}}, {65536, []byte{254, 0, 0, 1, 0}}} {
		size := row.size
		for _, coinbase := range []byte{0, 1} {
			t.Run(fmt.Sprintf("UTXO%d/coinbase%d", size, coinbase), func(t *testing.T) {
				// Independently pinned CompactSize widths and little-endian payload.
				literal := append(make([]byte, 10), row.prefix...)
				literal = append(literal, bytes.Repeat([]byte{0x73}, size)...)
				literal = append(literal, make([]byte, 8)...)
				literal = append(literal, coinbase)
				dbi := DBI{"utxo-v1", 1, 0}
				wantTreeLiteral(t, dbi, utxoKey, literal, nil)
				decoded, err := DecodeUTXOValue(literal)
				if err != nil || len(decoded.CovenantData) != size || (size == 0 && decoded.CovenantData != nil) || decoded.Coinbase != (coinbase == 1) {
					t.Fatalf("public UTXO owned shape = %#v, %v", decoded, err)
				}
				for _, bad := range [][]byte{literal[:len(literal)-1], append(bytes.Clone(literal), 0)} {
					wantTreeLiteral(t, dbi, utxoKey, bad, errSchema)
					if got, err := DecodeUTXOValue(bad); !reflect.DeepEqual(got, UTXOValue{}) || !exactErr(err) {
						t.Fatalf("public UTXO zero result = %#v, %v", got, err)
					}
				}
				literal[len(literal)-1] = 2
				wantTreeLiteral(t, dbi, utxoKey, literal, errSchema)
			})
		}
	}
	for _, bad := range [][]byte{make([]byte, 19), make([]byte, 65561), append(make([]byte, 10), 253), append(append(make([]byte, 10), 253, 1, 0), make([]byte, 10)...), append(append(make([]byte, 10), 1), make([]byte, 9)...), append(append(make([]byte, 10), 0), make([]byte, 10)...)} {
		wantTreeLiteral(t, DBI{"utxo-v1", 1, 0}, utxoKey, bad, errSchema)
		if got, err := DecodeUTXOValue(bad); !reflect.DeepEqual(got, UTXOValue{}) || !exactErr(err) {
			t.Fatalf("public UTXO zero result = %#v, %v", got, err)
		}
	}
	manifest := make([]byte, 33)
	manifest[0] = 1
	entryKey := make([]byte, 77)
	entryKey[32] = 1
	rows := []struct {
		name       string
		dbi        DBI
		key, value []byte
	}{
		{"version", meta, []byte{0}, []byte{0, 0, 0, 3}},
		{"config", meta, []byte{1}, config},
		{"authority", meta, []byte{2}, authority},
		{"database", meta, []byte{3}, append(make([]byte, 31), 1)},
		{"counter", meta, mustCodecHex(t, "100102030405060708"), make([]byte, 16)},
		{"root", meta, mustCodecHex(t, "110102030405060708"), treeRootLiteral(t, false)},
		{"evidence", meta, append([]byte{0x12}, hash[:]...), evidence},
		{"UTXO", DBI{"utxo-v1", 1, 0}, append(bytes.Clone(generation), make([]byte, 36)...), utxo},
		{"canonical", DBI{"canonical-v1", 2, 0}, append(bytes.Clone(generation), make([]byte, 8)...), make([]byte, 104)},
		{"undo manifest", DBI{"undo-v1", 5, 0}, make([]byte, 33), manifest},
		{"undo entry", DBI{"undo-v1", 5, 0}, entryKey, utxo},
		{"staged", DBI{"staged-v1", 6, 0}, append(bytes.Clone(generation), make([]byte, 8)...), make([]byte, 104)},
		{"canonical owner", DBI{"canonical-owner-v1", 7, 0}, append(bytes.Clone(generation), make([]byte, 32)...), make([]byte, 8)},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			keyBefore, valueBefore := bytes.Clone(row.key), bytes.Clone(row.value)
			if row.dbi.Rank >= 1 && row.dbi.Rank <= 7 && row.name != "undo entry" || row.name == "authority" || row.name == "root" || row.name == "counter" {
				wantTreeLiteral(t, row.dbi, row.key, row.value, nil)
			}
			if err := ValidateTreeRow(row.dbi, row.key, row.value); err != nil {
				t.Fatalf("tree meta %s = %v", row.name, err)
			}
			if !bytes.Equal(row.key, keyBefore) || !bytes.Equal(row.value, valueBefore) {
				t.Fatal("meta row changed input")
			}
			for _, bad := range [][]byte{nil, row.value[:len(row.value)-1], append(bytes.Clone(row.value), 0)} {
				if err := ValidateTreeRow(row.dbi, row.key, bad); !exactErr(err) {
					t.Fatalf("meta %s wrong value width = %v", row.name, err)
				}
			}
			for _, badKey := range [][]byte{nil, append(bytes.Clone(row.key), 0), {0xff}} {
				if err := ValidateTreeRow(row.dbi, badKey, row.value); !exactErr(err) {
					t.Fatalf("meta %s wrong key width/tag = %v", row.name, err)
				}
			}
		})
	}
	for _, key := range [][]byte{{4}, {0x10}, {0x11}, {0x12}, make([]byte, 9), make([]byte, 33), {3, 0}} {
		if err := ValidateTreeRow(meta, key, make([]byte, 32)); !exactErr(err) {
			t.Fatalf("closed meta key = %x: %v", key, err)
		}
	}
	for _, tag := range []byte{0x10, 0x11} {
		if err := ValidateTreeRow(meta, append([]byte{tag}, make([]byte, 8)...), make([]byte, 16)); !exactErr(err) {
			t.Fatalf("zero generation meta key = %v", err)
		}
	}
	if err := ValidateTreeRow(meta, []byte{3}, make([]byte, 32)); !exactErr(err) {
		t.Fatalf("zero database = %v", err)
	}
	if err := ValidateTreeRow(meta, []byte{0}, []byte{0, 0, 0, 2}); !exactErr(err) {
		t.Fatalf("historical version admitted = %v", err)
	}
	wrongKey := append([]byte{0x12}, hash[:]...)
	wrongKey[1] ^= 1
	if err := ValidateTreeRow(meta, wrongKey, evidence); !exactErr(err) {
		t.Fatalf("evidence key hash mismatch = %v", err)
	}
	changedOrigin := bytes.Clone(evidence)
	changedOrigin[32] = 7
	if err := ValidateTreeRow(meta, append([]byte{0x12}, hash[:]...), changedOrigin); !exactErr(err) {
		t.Fatalf("changed original origin under old key = %v", err)
	}
	changedHash := sha3.Sum256(changedOrigin)
	if err := ValidateTreeRow(meta, append([]byte{0x12}, changedHash[:]...), changedOrigin); err != nil {
		t.Fatalf("new origin/new content key = %v", err)
	}
	if err := ValidateTreeRow(DBI{"tree-node-v1", 8, 0}, nodeKey, make([]byte, 32)); err != nil {
		t.Fatalf("tree node row = %v", err)
	}
	if err := ValidateTreeRow(DBI{"tree-node-v1", 8, 0}, nodeKey, make([]byte, 33)); !exactErr(err) {
		t.Fatalf("tree node invalid value = %v", err)
	}
}
