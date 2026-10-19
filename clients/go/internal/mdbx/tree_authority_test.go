package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func treeEmptyDigest(t *testing.T) [32]byte {
	t.Helper()
	// ROOT §2.6's independently spelled D_EMPTY bytes, not a production constant.
	return sha3.Sum256(mustCodecHex(t, "525542494e5f5554584f5f545245455f563100"))
}

func treeRootFixture(t *testing.T, applied bool) RootBindingV1 {
	t.Helper()
	r := RootBindingV1{
		DatabaseID: modelHash(1), CommitmentVersion: 1,
		ChainID: modelHash(2), GenesisHash: modelHash(3), RootDigest: treeEmptyDigest(t),
		Assurance: TreeAssuranceV1{Kind: 1},
	}
	if applied {
		r.Endpoint = TreeEndpointV1{Kind: 1, BlockHash: modelHash(4), CumulativeChainwork: modelWork(false)}
	}
	return r
}

func treeRootLiteral(t *testing.T, applied bool) []byte {
	t.Helper()
	b := mustCodecHex(t, "01"+codecZeros(62)+"01"+"01"+codecZeros(62)+"02"+codecZeros(62)+"03")
	if applied {
		b = append(b, mustCodecHex(t, "01"+"00000000"+codecZeros(62)+"04"+codecZeros(78)+"01")...)
	} else {
		b = append(b, 0)
	}
	digest := treeEmptyDigest(t)
	return append(append(b, digest[:]...), 0, 1)
}

func treeImportFixture() *TreeImportReferenceV1 {
	return &TreeImportReferenceV1{modelHash(6), 7, 8, 1, modelHash(9)}
}

func treeImportLiteral(t *testing.T, role byte) []byte {
	t.Helper()
	b := mustCodecHex(t, codecZeros(62)+"06"+"0000000000000007"+"0000000000000008")
	b = append(b, role)
	return append(b, mustCodecHex(t, codecZeros(62)+"09")...)
}

func wantTreeRootError(t *testing.T, input []byte) {
	t.Helper()
	before := bytes.Clone(input)
	got, err := DecodeRootBindingV1(input)
	if !reflect.DeepEqual(got, RootBindingV1{}) || !exactErr(err) || !bytes.Equal(input, before) {
		t.Fatalf("root refusal = %#v, %v; input changed", got, err)
	}
}

func wantTreeRootEncodeError(t *testing.T, root RootBindingV1) {
	t.Helper()
	before := root
	if root.Top.Node != nil {
		id := *root.Top.Node
		before.Top.Node = &id
	}
	if root.Assurance.Import != nil {
		ref := *root.Assurance.Import
		before.Assurance.Import = &ref
	}
	got, err := root.Encode()
	if got != nil || !exactErr(err) || !reflect.DeepEqual(root, before) {
		t.Fatalf("root encode refusal = %x, %v; input changed", got, err)
	}
}

func TestTreeRootLiterals(t *testing.T) {
	for _, applied := range []bool{false, true} {
		root, literal := treeRootFixture(t, applied), treeRootLiteral(t, applied)
		got, err := root.Encode()
		if err != nil || !bytes.Equal(got, literal) {
			t.Fatalf("root literal applied=%v = %x, %v; want %x", applied, got, err, literal)
		}
		decoded, err := DecodeRootBindingV1(literal)
		if err != nil || !reflect.DeepEqual(decoded, root) {
			t.Fatalf("root literal decode = %#v, %v", decoded, err)
		}
		for n := range len(literal) {
			wantTreeRootError(t, literal[:n])
		}
		wantTreeRootError(t, append(bytes.Clone(literal), 0))
	}
	for _, top := range []byte{1, 2} {
		for _, role := range []byte{1, 2} {
			root := treeRootFixture(t, true)
			id, suffix := treeChildLiteral(t, 1, top)
			originalDepth := id.Depth
			root.Top = TreeTopV1{TreeTopKindV1(top), &id}
			root.Assurance = TreeAssuranceV1{2, treeImportFixture()}
			root.Assurance.Import.OriginalRole = TreeOriginalRoleV1(role)
			literal := treeRootLiteral(t, true)
			literal = append(bytes.Clone(literal[:207]), top)
			literal = append(literal, suffix...)
			literal = append(literal, 2)
			literal = append(literal, treeImportLiteral(t, role)...)
			encoded, err := root.Encode()
			if err != nil || len(encoded) != 328 || !bytes.Equal(encoded, literal) {
				t.Fatalf("root top/assurance literal = %x, %v", encoded, err)
			}
			decoded, err := DecodeRootBindingV1(literal)
			if err != nil || !reflect.DeepEqual(decoded, root) {
				t.Fatalf("root top/assurance decode = %#v, %v", decoded, err)
			}
			second, err := DecodeRootBindingV1(literal)
			if err != nil {
				t.Fatal(err)
			}
			for n := 209; n < 328; n++ {
				wantTreeRootError(t, literal[:n])
			}
			literal[1], literal[208], literal[247] = 99, 99, 99
			if decoded.DatabaseID != modelHash(1) || *decoded.Top.Node != id || *decoded.Assurance.Import != *root.Assurance.Import {
				t.Fatal("tree decoded isolation: fixed fields or nested pointers")
			}
			second.Top.Node.Depth = 42
			second.Assurance.Import.OriginalCurrentID = 43
			if decoded.Top.Node.Depth != originalDepth || decoded.Assurance.Import.OriginalCurrentID != 7 {
				t.Fatal("independently decoded root targets alias")
			}
			root.DatabaseID = modelHash(99)
			root.Assurance.Import.OriginalCurrentID = 88
			root.Top.Node.Depth = 88
			if encoded[32] != 1 || encoded[286] != 7 || decoded.Assurance.Import.OriginalCurrentID != 7 || decoded.Top.Node.Depth != originalDepth {
				t.Fatal("root input/output or independent nested targets alias")
			}
		}
	}
}

func TestTreeEndpointShape(t *testing.T) {
	for _, row := range []mutationCase[RootBindingV1]{
		{"unknown endpoint", func(r *RootBindingV1) { r.Endpoint.Kind = 2 }},
		{"PRE height", func(r *RootBindingV1) { r.Endpoint.Height = 1 }},
		{"PRE hash", func(r *RootBindingV1) { r.Endpoint.BlockHash[0] = 1 }},
		{"PRE work", func(r *RootBindingV1) { r.Endpoint.CumulativeChainwork[39] = 1 }},
		{"PRE nonempty top", func(r *RootBindingV1) { id := treeLeaf([36]byte{}); r.Top = TreeTopV1{1, &id} }},
		{"PRE wrong empty root", func(r *RootBindingV1) { r.RootDigest[0] ^= 1 }},
		{"zero database", func(r *RootBindingV1) { r.DatabaseID = [32]byte{} }},
		{"unknown commitment", func(r *RootBindingV1) { r.CommitmentVersion = 2 }},
		{"zero commitment", func(r *RootBindingV1) { r.CommitmentVersion = 0 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := treeRootFixture(t, false)
			row.mutate(&r)
			wantTreeRootEncodeError(t, r)
		})
	}
	for _, row := range []mutationCase[RootBindingV1]{
		{"height overflow", func(r *RootBindingV1) { r.Endpoint.Height = 0x100000000 }},
		{"zero work", func(r *RootBindingV1) { r.Endpoint.CumulativeChainwork = [40]byte{} }},
		{"work 2^288+1", func(r *RootBindingV1) { r.Endpoint.CumulativeChainwork = modelWork(true); r.Endpoint.CumulativeChainwork[39] = 1 }},
		{"work upper bytes", func(r *RootBindingV1) { r.Endpoint.CumulativeChainwork[0] = 1 }},
		{"work upper digit", func(r *RootBindingV1) { r.Endpoint.CumulativeChainwork[3] = 2 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := treeRootFixture(t, true)
			row.mutate(&r)
			wantTreeRootEncodeError(t, r)
		})
	}
	r := treeRootFixture(t, true)
	r.Endpoint.Height, r.Endpoint.CumulativeChainwork = 0xffffffff, modelWork(true)
	encoded, err := r.Encode()
	if err != nil || !bytes.Equal(encoded[99:103], []byte{255, 255, 255, 255}) || !bytes.Equal(encoded[135:175], append([]byte{0, 0, 0, 1}, make([]byte, 36)...)) {
		t.Fatalf("endpoint upper bound = %x, %v", encoded, err)
	}
	decoded, err := DecodeRootBindingV1(encoded)
	if err != nil || decoded.Endpoint != r.Endpoint {
		t.Fatalf("endpoint upper decode = %#v, %v", decoded.Endpoint, err)
	}
	for _, row := range []struct {
		name string
		offset int
		value byte
	}{
		{"format zero", 0, 0}, {"format unknown", 0, 2}, {"database zero", 32, 0},
		{"commitment zero", 33, 0}, {"commitment unknown", 33, 2},
		{"endpoint unknown", 98, 2}, {"top unknown", 207, 3}, {"assurance zero", 208, 0}, {"assurance unknown", 208, 3},
		{"work overflow", 138, 2},
	} {
		t.Run(row.name, func(t *testing.T) {
			b := bytes.Clone(encoded)
			b[row.offset] = row.value
			wantTreeRootError(t, b)
		})
	}
	zeroWork := bytes.Clone(treeRootLiteral(t, true))
	zeroWork[174] = 0
	wantTreeRootError(t, zeroWork)
	badPre := bytes.Clone(treeRootLiteral(t, false))
	badPre[99] ^= 1
	wantTreeRootError(t, badPre)
	// Unknown endpoint with a truncated sibling cannot produce a partial result.
	badPre[98] = 255
	wantTreeRootError(t, badPre)
}

func TestTreeTopAssuranceShape(t *testing.T) {
	for _, row := range []mutationCase[RootBindingV1]{
		{"top unknown", func(r *RootBindingV1) { r.Top.Kind = 3 }},
		{"EMPTY extra payload", func(r *RootBindingV1) { id := treeLeaf([36]byte{}); r.Top.Node = &id }},
		{"LEAF missing payload", func(r *RootBindingV1) { r.Top.Kind = 1 }},
		{"BRANCH missing payload", func(r *RootBindingV1) { r.Top.Kind = 2 }},
		{"LEAF branch payload", func(r *RootBindingV1) { id := treeBranch(0, [36]byte{}); r.Top = TreeTopV1{1, &id} }},
		{"BRANCH leaf payload", func(r *RootBindingV1) { id := treeLeaf([36]byte{}); r.Top = TreeTopV1{2, &id} }},
		{"LEAF invalid ID", func(r *RootBindingV1) { id := treeLeaf([36]byte{}); id.Depth = 0; r.Top = TreeTopV1{1, &id} }},
		{"assurance zero", func(r *RootBindingV1) { r.Assurance.Kind = 0 }},
		{"assurance unknown", func(r *RootBindingV1) { r.Assurance.Kind = 3 }},
		{"FULL extra reference", func(r *RootBindingV1) { r.Assurance.Import = treeImportFixture() }},
		{"import missing reference", func(r *RootBindingV1) { r.Assurance.Kind = 2 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := treeRootFixture(t, true)
			row.mutate(&r)
			wantTreeRootEncodeError(t, r)
		})
	}
	for _, row := range []mutationCase[TreeImportReferenceV1]{
		{"origin database zero", func(r *TreeImportReferenceV1) { r.OriginalDatabaseID = [32]byte{} }},
		{"origin CURRENT zero", func(r *TreeImportReferenceV1) { r.OriginalCurrentID = 0 }},
		{"origin LAG zero", func(r *TreeImportReferenceV1) { r.OriginalLagID = 0 }},
		{"origin pair equal", func(r *TreeImportReferenceV1) { r.OriginalLagID = r.OriginalCurrentID }},
		{"origin role zero", func(r *TreeImportReferenceV1) { r.OriginalRole = 0 }},
		{"origin role unknown", func(r *TreeImportReferenceV1) { r.OriginalRole = 3 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := treeRootFixture(t, true)
			r.Assurance = TreeAssuranceV1{2, treeImportFixture()}
			row.mutate(r.Assurance.Import)
			wantTreeRootEncodeError(t, r)
		})
	}
	base := treeRootLiteral(t, true)
	for _, tag := range []byte{0, 3, 255} {
		bad := bytes.Clone(base)
		bad[208] = tag
		wantTreeRootError(t, bad)
	}
	extraTop := append(bytes.Clone(base[:207]), 0)
	extraTop = append(extraTop, make([]byte, 38)...)
	extraTop = append(extraTop, 1)
	wantTreeRootError(t, extraTop)
	for _, tag := range []byte{1, 2} {
		missing := bytes.Clone(base)
		missing[207] = tag
		wantTreeRootError(t, missing)
	}
	fullExtra := append(bytes.Clone(base), treeImportLiteral(t, 1)...)
	wantTreeRootError(t, fullExtra)
	importMissing := bytes.Clone(base)
	importMissing[208] = 2
	wantTreeRootError(t, importMissing)
	imported := append(bytes.Clone(base[:208]), 2)
	imported = append(imported, treeImportLiteral(t, 1)...)
	for _, row := range []struct {
		name string
		offset int
		value byte
	}{
		{"database", 240, 0}, {"CURRENT", 248, 0}, {"LAG", 256, 0},
		{"same pair", 256, 7}, {"role zero", 257, 0}, {"role unknown", 257, 3},
	} {
		t.Run("import decode "+row.name, func(t *testing.T) {
			bad := bytes.Clone(imported)
			bad[row.offset] = row.value
			wantTreeRootError(t, bad)
		})
	}
	wantTreeRootError(t, make([]byte, 132))
	wantTreeRootError(t, make([]byte, 329))
}

func treeEvidenceFixture() TreeEvidenceV1 {
	return TreeEvidenceV1{modelHash(6), 7, 8, []byte{0xde, 0xad, 0xbe}}
}

func treeEvidenceLiteral(t *testing.T) []byte {
	t.Helper()
	return mustCodecHex(t, "01"+codecZeros(62)+"06"+"0000000000000007"+"0000000000000008"+"00000003deadbe")
}

func wantTreeEvidenceError(t *testing.T, input []byte) {
	t.Helper()
	before := bytes.Clone(input)
	got, err := DecodeTreeEvidenceV1(input)
	if !reflect.DeepEqual(got, TreeEvidenceV1{}) || !exactErr(err) || !bytes.Equal(input, before) {
		t.Fatalf("evidence refusal = %#v, %v; input changed", got, err)
	}
}

func TestTreeEvidenceLiteralIsolation(t *testing.T) {
	evidence, literal := treeEvidenceFixture(), treeEvidenceLiteral(t)
	encoded, err := evidence.Encode()
	if err != nil || !bytes.Equal(encoded, literal) {
		t.Fatalf("evidence literal = %x, %v", encoded, err)
	}
	decoded, err := DecodeTreeEvidenceV1(literal)
	if err != nil || !reflect.DeepEqual(decoded, evidence) {
		t.Fatalf("evidence decode = %#v, %v", decoded, err)
	}
	evidence.Payload[0], literal[53] = 1, 2
	if encoded[53] != 0xde || decoded.Payload[0] != 0xde {
		t.Fatal("tree decoded isolation: evidence payload")
	}
	second, err := DecodeTreeEvidenceV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Payload[1] = 1
	if second.Payload[1] != 0xad {
		t.Fatal("evidence decoded outputs alias")
	}
	for n := range len(encoded) {
		wantTreeEvidenceError(t, encoded[:n])
	}
	wantTreeEvidenceError(t, append(bytes.Clone(encoded), 0))
	for _, row := range []struct {
		name string
		offset int
		value byte
	}{
		{"format zero", 0, 0}, {"format unknown", 0, 2}, {"database zero", 32, 0},
		{"CURRENT zero", 40, 0}, {"LAG zero", 48, 0}, {"pair equal", 48, 7},
		{"length zero", 52, 0}, {"length short", 52, 2}, {"length long", 52, 4}, {"length overflow", 49, 255},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := bytes.Clone(encoded)
			bad[row.offset] = row.value
			wantTreeEvidenceError(t, bad)
		})
	}
	for _, row := range []mutationCase[TreeEvidenceV1]{
		{"database zero", func(e *TreeEvidenceV1) { e.OriginalDatabaseID = [32]byte{} }},
		{"CURRENT zero", func(e *TreeEvidenceV1) { e.OriginalCurrentID = 0 }},
		{"LAG zero", func(e *TreeEvidenceV1) { e.OriginalLagID = 0 }},
		{"pair equal", func(e *TreeEvidenceV1) { e.OriginalLagID = e.OriginalCurrentID }},
		{"nil payload", func(e *TreeEvidenceV1) { e.Payload = nil }},
		{"empty payload", func(e *TreeEvidenceV1) { e.Payload = []byte{} }},
		{"oversize payload", func(e *TreeEvidenceV1) { e.Payload = make([]byte, 1048524) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			e := treeEvidenceFixture()
			row.mutate(&e)
			before := e
			before.Payload = bytes.Clone(e.Payload)
			if b, err := e.Encode(); b != nil || !exactErr(err) || !reflect.DeepEqual(e, before) {
				t.Fatalf("evidence encode refusal = %x, %v", b, err)
			}
		})
	}
	maximum := treeEvidenceFixture()
	maximum.Payload = make([]byte, 1048523)
	b, err := maximum.Encode()
	if err != nil || len(b) != 1048576 || !bytes.Equal(b[49:53], []byte{0, 15, 255, 203}) {
		t.Fatalf("evidence maximum = len%d, %v", len(b), err)
	}
	got, err := DecodeTreeEvidenceV1(b)
	if err != nil || len(got.Payload) != 1048523 {
		t.Fatalf("evidence maximum decode = len%d, %v", len(got.Payload), err)
	}
	wantTreeEvidenceError(t, append(b, 0))
}

func treeAuthorityFixture(a StorageAuthorityV1) TreeAuthorityV1 {
	a.NextGenerationID = 20
	tree := TreeAuthorityV1{Authority: a, LagGenerationID: 10}
	if a.Phase == 3 {
		tree.SourceKind, tree.TargetLagGenerationID = 1, 11
	}
	return tree
}

func treeEnvelopeLiteral(inner []byte, source, status byte, payload []byte) []byte {
	// Independent test framing pins every outer scalar width/order, including the
	// absent target LAG outside REPLAY. Inner fixtures have separate literal owners.
	b := []byte{1, source, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0}
	if source != 0 {
		b[17] = 11
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(inner)))
	b = append(b, inner...)
	b = append(b, status)
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	return append(b, payload...)
}

func wantTreeAuthority(t *testing.T, tree TreeAuthorityV1) []byte {
	t.Helper()
	encoded, err := tree.Encode()
	if err != nil {
		t.Fatalf("tree authority encode: %v; %#v", err, tree)
	}
	decoded, err := DecodeTreeAuthorityV1(encoded)
	if err != nil || !reflect.DeepEqual(decoded, tree) {
		t.Fatalf("tree authority decode = %#v, %v; want %#v", decoded, err, tree)
	}
	return encoded
}

func wantTreeAuthorityDecodeError(t *testing.T, input []byte) {
	t.Helper()
	before := bytes.Clone(input)
	got, err := DecodeTreeAuthorityV1(input)
	if !reflect.DeepEqual(got, TreeAuthorityV1{}) || !exactErr(err) || !bytes.Equal(input, before) {
		t.Fatalf("authority refusal = %#v, %v; input changed", got, err)
	}
}

func wantTreeAuthorityEncodeError(t *testing.T, tree TreeAuthorityV1) {
	t.Helper()
	before := treeInputSnapshot(t, tree)
	if got, err := tree.Encode(); got != nil || !exactErr(err) || !bytes.Equal(before, treeInputSnapshot(t, tree)) {
		t.Fatalf("authority encode refusal = %x, %v; input changed", got, err)
	}
}

func TestTreeAuthorityLiterals(t *testing.T) {
	for _, row := range codecLiteralCases(t) {
		t.Run(row.name, func(t *testing.T) {
			tree := treeAuthorityFixture(row.a)
			inner := bytes.Clone(row.b)
			binary.BigEndian.PutUint64(inner[26:], 20)
			literal := treeEnvelopeLiteral(inner, byte(tree.SourceKind), 0, nil)
			if got := wantTreeAuthority(t, tree); !bytes.Equal(got, literal) {
				t.Fatalf("tree authority literal = %x; want %x", got, literal)
			}
			for n := range len(literal) {
				wantTreeAuthorityDecodeError(t, literal[:n])
			}
			wantTreeAuthorityDecodeError(t, append(bytes.Clone(literal), 0))
		})
	}
	for _, cursor := range []byte{1, 2} {
		wantTreeAuthority(t, treeAuthorityFixture(modelReplay(cursor)))
	}
	base := treeAuthorityFixture(modelReplay(1))
	base.SourceKind, base.Authority.Replay.Cursor = 2, ReplayCursorV1{}
	inner, err := modelReplay(1).Encode()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(inner[26:], 20)
	inner[189] = 0
	for _, status := range []byte{1, 2} {
		t.Run(fmt.Sprintf("IMAGE%d", status), func(t *testing.T) {
			tree := base
			tree.Progress = TreeProgressV1{TreeProgressKindV1(status), []byte{0x80, 0x41}}
			literal := treeEnvelopeLiteral(inner, 2, status, []byte{0x80, 0x41})
			if got := wantTreeAuthority(t, tree); !bytes.Equal(got, literal) {
				t.Fatalf("IMAGE zero-cursor literal = %x; want %x", got, literal)
			}
			// The historical public decoder cannot inherit the zero IMAGE cursor.
			if a, err := DecodeStorageAuthorityV1(inner); !exactErr(err) || !reflect.DeepEqual(a, StorageAuthorityV1{}) {
				t.Fatalf("historical IMAGE cursor = %#v, %v", a, err)
			}
		})
	}
}

func TestTreeAuthorityFiveSpans(t *testing.T) {
	row := codecLiteralCases(t)[1]
	tree := treeAuthorityFixture(row.a)
	spans := tree.Authority.Cleanup.Spans
	tree.Authority.Cleanup.Spans = append([]CleanupSpanV1{spans[0], {Kind: 1, GenerationID: 4}}, spans[1:]...)
	inner := bytes.Clone(row.b)
	binary.BigEndian.PutUint64(inner[26:], 20)
	inner[36] = 5
	inner = append(append(bytes.Clone(inner[:46]), mustCodecHex(t, "010000000000000004")...), inner[46:]...)
	literal := treeEnvelopeLiteral(inner, 0, 0, nil)
	if got := wantTreeAuthority(t, tree); !bytes.Equal(got, literal) {
		t.Fatalf("five-span literal = %x; want %x", got, literal)
	}
	if a, err := DecodeStorageAuthorityV1(inner); !exactErr(err) || !reflect.DeepEqual(a, StorageAuthorityV1{}) {
		t.Fatalf("historical five-span decode = %#v, %v", a, err)
	}
	if b, err := tree.Authority.Encode(); b != nil || !exactErr(err) {
		t.Fatalf("historical five-span encode = %x, %v", b, err)
	}
	for _, row := range []struct {
		name string
		ids []uint64
	}{
		{"two ascending", []uint64{3, 4}}, {"one obsolete", []uint64{3}},
		{"duplicate", []uint64{3, 3}}, {"descending", []uint64{4, 3}},
		{"three obsolete", []uint64{3, 4, 5}}, {"zero", []uint64{0}},
		{"equal next", []uint64{20}}, {"above next", []uint64{21}},
		{"current", []uint64{1}}, {"live LAG", []uint64{10}},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := modelPrune(false)
			a.Cleanup = &CleanupV1{}
			for _, id := range row.ids {
				a.Cleanup.Spans = append(a.Cleanup.Spans, CleanupSpanV1{Kind: 1, GenerationID: id})
			}
			candidate := treeAuthorityFixture(a)
			if row.name == "two ascending" || row.name == "one obsolete" {
				wantTreeAuthority(t, candidate)
			} else {
				wantTreeAuthorityEncodeError(t, candidate)
			}
		})
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[36] = 0 }, func(b []byte) { b[36] = 6 },
		func(b []byte) { b[54] = 3 }, func(b []byte) { b[45], b[54] = 4, 3 },
		func(b []byte) { b[54] = 20 }, func(b []byte) { b[54] = 10 },
		func(b []byte) { b[55] = 5 },
	} {
		bad := bytes.Clone(inner)
		mutate(bad)
		wantTreeAuthorityDecodeError(t, treeEnvelopeLiteral(bad, 0, 0, nil))
	}
	wantTreeAuthorityDecodeError(t, treeEnvelopeLiteral(inner[:54], 0, 0, nil))
}

func TestTreeAuthorityRoles(t *testing.T) {
	for _, row := range []mutationCase[TreeAuthorityV1]{
		{"CURRENT zero", func(a *TreeAuthorityV1) { a.Authority.ActiveGenerationID = 0 }},
		{"CURRENT at next", func(a *TreeAuthorityV1) { a.Authority.ActiveGenerationID = 20 }},
		{"LAG missing", func(a *TreeAuthorityV1) { a.LagGenerationID = 0 }},
		{"LAG equals CURRENT", func(a *TreeAuthorityV1) { a.LagGenerationID = 1 }},
		{"LAG equals next", func(a *TreeAuthorityV1) { a.LagGenerationID = 20 }},
		{"LAG exceeds next", func(a *TreeAuthorityV1) { a.LagGenerationID = 21 }},
		{"target CURRENT zero", func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 0 }},
		{"target CURRENT equals CURRENT", func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 1 }},
		{"target CURRENT equals LAG", func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 10 }},
		{"target CURRENT at next", func(a *TreeAuthorityV1) { a.Authority.Replay.TargetGenerationID = 20 }},
		{"target LAG missing", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 0 }},
		{"target LAG equals CURRENT", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 1 }},
		{"target LAG equals LAG", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 10 }},
		{"target LAG equals target CURRENT", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 2 }},
		{"target LAG at next", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 20 }},
		{"target LAG exceeds next", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 21 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			tree := treeAuthorityFixture(modelReplay(1))
			row.mutate(&tree)
			wantTreeAuthorityEncodeError(t, tree)
		})
	}
	base := wantTreeAuthority(t, treeAuthorityFixture(modelReplay(1)))
	for _, row := range []struct {
		name string
		offset int
		values []uint64
	}{
		{"LAG", 2, []uint64{0, 1, 2, 11, 20, 21}},
		{"target LAG", 10, []uint64{0, 1, 2, 10, 20, 21}},
		{"CURRENT", 40, []uint64{0, 2, 10, 11, 20, 21}},
		{"target CURRENT", 59, []uint64{0, 1, 10, 11, 20, 21}},
	} {
		for _, value := range row.values {
			t.Run(fmt.Sprintf("decode %s%d", row.name, value), func(t *testing.T) {
				b := bytes.Clone(base)
				binary.BigEndian.PutUint64(b[row.offset:], value)
				wantTreeAuthorityDecodeError(t, b)
			})
		}
	}
}

func TestTreeLiveLagOwnerExclusion(t *testing.T) {
	// Each otherwise-valid owner is tested separately. In particular a single
	// obsolete=10 span cannot be rejected by two-span ordering, and SIDE=10 has
	// no selected-side mismatch. Both distinguish the live-LAG exclusion itself.
	for _, owner := range []string{"GENERATION", "SIDE", "selected", "carried GENERATION", "carried SIDE", "captured selected"} {
		for _, generation := range []uint64{3, 10, 1} {
			t.Run(fmt.Sprintf("%s=%d", owner, generation), func(t *testing.T) {
				a := modelPrune(false)
				switch owner {
				case "GENERATION":
					a.Cleanup = &CleanupV1{[]CleanupSpanV1{{Kind: 1, GenerationID: generation}}}
				case "SIDE":
					a.Cleanup = &CleanupV1{[]CleanupSpanV1{{Kind: 4, GenerationID: generation}}}
				case "selected":
					a = modelBase(1, 0, 0)
					a.SelectedSide = modelSide(generation, 0, 1, 1, 1)
				case "carried GENERATION":
					a = modelOrdinary(1, 1, 1, 1, 1, 0, 0)
					a.Ordinary.CarriedCleanup = &CleanupV1{[]CleanupSpanV1{{Kind: 1, GenerationID: generation}}}
				case "carried SIDE":
					a = modelOrdinary(1, 1, 1, 1, 1, 0, 0)
					a.Ordinary.CapturedSelectedSide.GenerationID = generation
					a.Ordinary.CarriedCleanup = &CleanupV1{[]CleanupSpanV1{{Kind: 4, GenerationID: generation, FirstHeight: 0, LastHeight: 0, NextHeight: 0}}}
				case "captured selected":
					a = modelOrdinary(1, 1, 1, 1, 1, 0, 0)
					a.Ordinary.CapturedSelectedSide.GenerationID = generation
				}
				tree := treeAuthorityFixture(a)
				if generation == 3 {
					wantTreeAuthority(t, tree)
				} else {
					wantTreeAuthorityEncodeError(t, tree)
					if generation == 10 {
						inner, err := tree.Authority.Encode()
						if err != nil {
							t.Fatalf("live LAG witness fails an unrelated historical rule: %v", err)
						}
						wantTreeAuthorityDecodeError(t, treeEnvelopeLiteral(inner, 0, 0, nil))
					}
				}
			})
		}
	}
}

func TestTreeProgressShape(t *testing.T) {
	for _, source := range []byte{0, 1, 2, 3, 255} {
		for _, status := range []byte{0, 1, 2, 3, 255} {
			for _, hasPayload := range []bool{false, true} {
				t.Run(fmt.Sprintf("source%d/status%d/payload%v", source, status, hasPayload), func(t *testing.T) {
					tree := treeAuthorityFixture(modelReplay(1))
					tree.SourceKind, tree.Progress.Kind = TreeSourceKindV1(source), TreeProgressKindV1(status)
					if source == 2 {
						tree.Authority.Replay.Cursor = ReplayCursorV1{}
					}
					if hasPayload {
						tree.Progress.Payload = []byte{0x80}
					}
					valid := source == 1 && status == 0 && !hasPayload || source == 2 && (status == 1 || status == 2) && hasPayload
					if valid {
						wantTreeAuthority(t, tree)
					} else {
						wantTreeAuthorityEncodeError(t, tree)
					}
				})
			}
		}
	}
	for _, row := range []mutationCase[TreeAuthorityV1]{
		{"NONE target LAG", func(a *TreeAuthorityV1) { a.TargetLagGenerationID = 11 }},
		{"NONE replay sibling", func(a *TreeAuthorityV1) { a.Authority.Replay = modelReplay(1).Replay }},
		{"NONE progress sibling", func(a *TreeAuthorityV1) { a.Progress.Payload = []byte{1} }},
		{"NONE PARTIAL sibling", func(a *TreeAuthorityV1) { a.Progress.Kind = 1 }},
		{"NONE COMPLETE sibling", func(a *TreeAuthorityV1) { a.Progress.Kind = 2 }},
		{"NONE genesis source", func(a *TreeAuthorityV1) { a.SourceKind = 1 }},
		{"NONE IMAGE source", func(a *TreeAuthorityV1) { a.SourceKind = 2 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := treeAuthorityFixture(modelBase(1, 0, 0))
			row.mutate(&a)
			wantTreeAuthorityEncodeError(t, a)
		})
	}
	for _, cursor := range []ReplayCursorV1{{Kind: 1}, {Kind: 2, BlockHash: modelHash(12)}, {Height: 1}, {BlockHash: modelHash(1)}, {Kind: 3}} {
		tree := treeAuthorityFixture(modelReplay(1))
		tree.SourceKind, tree.Progress = 2, TreeProgressV1{1, []byte{0x80}}
		tree.Authority.Replay.Cursor = cursor
		wantTreeAuthorityEncodeError(t, tree)
	}
	genesis := treeAuthorityFixture(modelReplay(1))
	genesis.Authority.Replay.Cursor = ReplayCursorV1{}
	wantTreeAuthorityEncodeError(t, genesis)
	for _, status := range []byte{1, 2} {
		tree := treeAuthorityFixture(modelReplay(1))
		tree.SourceKind, tree.Progress = 2, TreeProgressV1{TreeProgressKindV1(status), []byte{}}
		tree.Authority.Replay.Cursor = ReplayCursorV1{}
		wantTreeAuthorityEncodeError(t, tree)
	}
	image := treeAuthorityFixture(modelReplay(1))
	image.SourceKind, image.Progress = 2, TreeProgressV1{1, []byte{0x80}}
	image.Authority.Replay.Cursor = ReplayCursorV1{}
	b := wantTreeAuthority(t, image)
	for _, row := range []struct {
		name string
		offset int
		value byte
	}{
		{"format unknown", 0, 2}, {"source unknown", 1, 3}, {"source NONE in replay", 1, 0},
		{"GENESIS with checkpoint", 1, 1}, {"IMAGE legacy PRE", 211, 1}, {"IMAGE legacy APPLIED", 211, 2}, {"cursor unknown", 211, 3},
		{"status NONE", 216, 0}, {"status unknown", 216, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := bytes.Clone(b)
			bad[row.offset] = row.value
			wantTreeAuthorityDecodeError(t, bad)
		})
	}
}

func TestTreeDescriptor148Bound(t *testing.T) {
	for _, owner := range []string{"selected", "captured selected", "detached"} {
		for _, count := range []uint16{1, 2} {
			for _, maximum := range []uint64{68000125, 68000126, 68000157, 68000158} {
				t.Run(fmt.Sprintf("%s/%d/%d", owner, count, maximum), func(t *testing.T) {
					a := modelBase(1, 0, 0)
					switch owner {
					case "selected":
						a.SelectedSide = modelSide(2, 0, uint64(count), count, uint64(count)*maximum)
					case "captured selected":
						a = modelOrdinary(2, 0, int(count), 0, 1, 0, 0)
						if count == 1 {
							a = modelOrdinary(1, 1, 1, 1, 1, 0, 0)
						}
						a.Ordinary.CapturedSelectedSide.LogicalBytes = uint64(count) * maximum
					case "detached":
						a = modelPrune(false)
						a.DetachedSuffix = modelDetached(int(count), maximum)
					}
					tree := treeAuthorityFixture(a)
					if maximum <= 68000157 {
						wantTreeAuthority(t, tree)
					} else {
						wantTreeAuthorityEncodeError(t, tree)
					}
					legacy, legacyErr := tree.Authority.Encode()
					if maximum == 68000125 {
						if legacyErr != nil {
							t.Fatalf("historical maximum refused: %v", legacyErr)
						}
					} else if legacy != nil || !exactErr(legacyErr) {
						t.Fatalf("historical domain widened: %x, %v", legacy, legacyErr)
					}
				})
			}
		}
	}
	// The exact aggregate sibling differs by one byte, rather than a whole row.
	for _, owner := range []string{"selected", "captured selected"} {
		a := modelBase(1, 0, 0)
		if owner == "selected" {
			a.SelectedSide = modelSide(2, 0, 2, 2, 136000314)
		} else {
			a = modelOrdinary(2, 0, 2, 0, 1, 0, 0)
			a.Ordinary.CapturedSelectedSide.LogicalBytes = 136000314
		}
		tree := treeAuthorityFixture(a)
		b := wantTreeAuthority(t, tree)
		// selected logical bytes are the last8 of the descriptor. The trailing
		// outer options/envelope fields are fixed and checked by literal tests.
		offset := 22 + 36 + 3 + 98
		if owner == "captured selected" {
			// Header36 + ordinary stage/cursor2 + target40 + oldcount2 +
			// newcount2 + two points80 + captured-option1 + descriptor98.
			offset = 22 + 36 + 2 + 40 + 2 + 2 + 80 + 1 + 98
		}
		if binary.BigEndian.Uint64(b[offset:]) != 136000314 {
			t.Fatalf("%s aggregate literal not present", owner)
		}
		bad := bytes.Clone(b)
		binary.BigEndian.PutUint64(bad[offset:], 136000315)
		wantTreeAuthorityDecodeError(t, bad)
		if owner == "selected" {
			tree.Authority.SelectedSide.LogicalBytes++
		} else {
			tree.Authority.Ordinary.CapturedSelectedSide.LogicalBytes++
		}
		wantTreeAuthorityEncodeError(t, tree)
	}
}

func TestTreeAuthorityBoundsIsolation(t *testing.T) {
	image := treeAuthorityFixture(modelReplay(1))
	image.SourceKind, image.Authority.Replay.Cursor = 2, ReplayCursorV1{}
	image.Progress = TreeProgressV1{1, []byte{0x80, 0x41}}
	b := wantTreeAuthority(t, image)
	decoded, err := DecodeTreeAuthorityV1(b)
	if err != nil {
		t.Fatal(err)
	}
	image.Progress.Payload[0] = 1
	if b[len(b)-2] != 0x80 {
		t.Fatal("encoded progress retained input")
	}
	b[len(b)-1] = 2
	if decoded.Progress.Payload[0] != 0x80 || decoded.Progress.Payload[1] != 0x41 {
		t.Fatal("tree decoded isolation: progress")
	}
	second, err := DecodeTreeAuthorityV1(wantTreeAuthority(t, image))
	if err != nil {
		t.Fatal(err)
	}
	decoded.Progress.Payload[0] = 9
	if second.Progress.Payload[0] != 1 {
		t.Fatal("progress outputs alias")
	}
	// Replay inner194 plus outer27 leaves exactly1048355 opaque bytes.
	image.Progress.Payload = make([]byte, 1048355)
	maximum := wantTreeAuthority(t, image)
	if len(maximum) != 1048576 || binary.BigEndian.Uint32(maximum[217:]) != 1048355 {
		t.Fatalf("authority maximum = %d", len(maximum))
	}
	image.Progress.Payload = make([]byte, 1048356)
	wantTreeAuthorityEncodeError(t, image)
	wantTreeAuthorityDecodeError(t, append(bytes.Clone(maximum), 0))
	for _, row := range []struct {
		name string
		offset int
		value uint32
	}{
		{"authority zero", 18, 0}, {"authority short", 18, 39},
		{"authority overflow", 18, 0xffffffff}, {"authority overlaps progress", 18, 195},
		{"progress missing", 217, 0}, {"progress short", 217, 1048354},
		{"progress long", 217, 1048356}, {"progress overflow", 217, 0xffffffff},
	} {
		t.Run(row.name, func(t *testing.T) {
			bad := bytes.Clone(maximum)
			binary.BigEndian.PutUint32(bad[row.offset:], row.value)
			wantTreeAuthorityDecodeError(t, bad)
		})
	}
	wantTreeAuthorityDecodeError(t, nil)
	wantTreeAuthorityDecodeError(t, make([]byte, 66))
	// Nested authority length may itself fit metadata while outer27 must not.
	none := treeAuthorityFixture(modelBase(1, 0, 0))
	none.Authority.ExcludedInvalidBranch = &InvalidBranchV1{FirstInvalidHeight: 1, ExactConsensusError: make([]byte, 1048492)}
	wantTreeAuthorityEncodeError(t, none)
	// Outer scalar refusal wins even when the nested cleanup count is malformed.
	bad := bytes.Clone(maximum)
	bad[1], bad[22+34], bad[216] = 255, 2, 255
	wantTreeAuthorityDecodeError(t, bad)
}

func TestTreeAuthorityNestedIsolation(t *testing.T) {
	for _, row := range codecLiteralCases(t) {
		t.Run(row.name, func(t *testing.T) {
			tree := treeAuthorityFixture(row.a)
			encoded := wantTreeAuthority(t, tree)
			before := bytes.Clone(encoded)
			first, err := DecodeTreeAuthorityV1(encoded)
			if err != nil {
				t.Fatal(err)
			}
			second, err := DecodeTreeAuthorityV1(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if first.Authority.Cleanup != nil {
				first.Authority.Cleanup.Spans[0].GenerationID = 99
			}
			if first.Authority.Replay != nil {
				first.Authority.Replay.Target.ChainID[0] = 99
			}
			if first.Authority.Ordinary != nil {
				o := first.Authority.Ordinary
				o.NewSuffix[0].BlockHash[0], o.OldSuffix[0].BlockHash[0] = 99, 98
				o.CapturedSelectedSide.TipHash[0] = 97
				if o.Cursor != nil {
					o.Cursor.BlockHash[0] = 96
				}
				if o.CarriedCleanup != nil {
					o.CarriedCleanup.Spans[0].GenerationID = 95
				}
				if o.RecordedFailure != nil {
					o.RecordedFailure.ExactResult[0], o.RecordedFailure.Evidence[0] = 94, 93
					o.RecordedFailure.FailedBlockHash[0] = 92
				}
			}
			if first.Authority.ExcludedInvalidBranch != nil {
				first.Authority.ExcludedInvalidBranch.ExactConsensusError[0] = 91
			}
			if first.Authority.DetachedSuffix != nil {
				first.Authority.DetachedSuffix.Entries[0].Hash[0] = 90
			}
			if !reflect.DeepEqual(second, tree) || !bytes.Equal(encoded, before) {
				t.Fatal("nested tree authority decoded targets alias sibling/input")
			}
			encoded[22] = 9
			if second.Authority.Version != 1 {
				t.Fatal("tree authority input aliases result")
			}
		})
	}
}

func TestTreeDetached148DecodeBound(t *testing.T) {
	for _, count := range []int{1, 2} {
		a := modelPrune(false)
		a.DetachedSuffix = modelDetached(count, 68000157)
		b := wantTreeAuthority(t, treeAuthorityFixture(a))
		for index := range count {
			bad := bytes.Clone(b)
			// Outer22 + header36 + cleanup34 + four option bytes +
			// count2 + entry height8/hash32 place the first length at138.
			binary.BigEndian.PutUint64(bad[138+48*index:], 68000158)
			binary.BigEndian.PutUint64(bad[140+48*count:], uint64(count)*68000157+1)
			wantTreeAuthorityDecodeError(t, bad)
		}
	}
}

func TestTreeRootIdentityProvenance(t *testing.T) {
	root := treeRootFixture(t, true)
	root.Assurance = TreeAssuranceV1{2, treeImportFixture()}
	original, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	root.DatabaseID = modelHash(99)
	copied, err := root.Encode()
	if err != nil || bytes.Equal(original, copied) || !bytes.Equal(original[175:], copied[175:]) || !bytes.Equal(copied[209:], treeImportLiteral(t, 1)) {
		t.Fatalf("destination identity rewrote original provenance = %x, %v", copied, err)
	}
	for _, generation := range []byte{1, 2} {
		key := []byte{0x11, 0, 0, 0, 0, 0, 0, 0, generation}
		if err := ValidateTreeRow(DBI{"meta-v1", 0, 0}, key, copied); err != nil {
			t.Fatalf("distinct generation root binding = %v", err)
		}
	}
	root.Assurance.Import.OriginalRole = 2
	lag, err := root.Encode()
	if err != nil || bytes.Equal(lag, copied) || lag[257] != 2 || !bytes.Equal(lag[209:257], copied[209:257]) || !bytes.Equal(lag[258:], copied[258:]) {
		t.Fatalf("equal digest roles collapsed = %x, %v", lag, err)
	}
	root.Assurance.Import.OriginalCurrentID = 9
	otherPair, err := root.Encode()
	if err != nil || bytes.Equal(otherPair, lag) || !bytes.Equal(otherPair[175:207], lag[175:207]) {
		t.Fatalf("equal digest pair identities collapsed = %x, %v", otherPair, err)
	}
}

func TestTreeTopDecodeKind(t *testing.T) {
	for _, kind := range []byte{1, 2} {
		id, suffix := treeChildLiteral(t, 1, kind)
		root := treeRootFixture(t, true)
		root.Top = TreeTopV1{TreeTopKindV1(kind), &id}
		literal := append(bytes.Clone(treeRootLiteral(t, true)[:207]), kind)
		literal = append(literal, suffix...)
		literal = append(literal, 1)
		if got, err := DecodeRootBindingV1(literal); err != nil || !reflect.DeepEqual(got, root) {
			t.Fatalf("valid top kind sibling = %#v, %v", got, err)
		}
		literal[207] = 3 - kind
		wantTreeRootError(t, literal)
	}
}
