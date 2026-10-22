package mdbx

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
)

type TreeNodeKindV1 uint8

const (
	TreeNodeLeafV1   TreeNodeKindV1 = 1
	TreeNodeBranchV1 TreeNodeKindV1 = 2
)

type TreeNodeIDV1 struct {
	Kind       TreeNodeKindV1
	RoutingKey [36]byte
	Depth      uint16
	Prefix     [36]byte
}

type TreeChildV1 struct {
	ID     TreeNodeIDV1
	Digest [32]byte
}

type TreeNodeV1 struct {
	LeafDigest [32]byte
	Zero, One  *TreeChildV1
}

// TreeSchemaV1DBIs returns the dormant tree schema's closed descriptor values.
func TreeSchemaV1DBIs() [9]DBI {
	var out [9]DBI
	copy(out[:], schemaDBIs[:])
	out[8] = DBI{Name: "tree-node-v1", Rank: 8}
	return out
}

func TreeSchemaVersionValue() []byte { return []byte{0, 0, 0, 3} }

func TreeValidateDBI(d DBI) error {
	if d.Rank >= 9 || d != TreeSchemaV1DBIs()[d.Rank] {
		return errSchema
	}
	return nil
}

func treeMask(key [36]byte, depth uint16, suffix bool) [36]byte {
	for bit := int(depth); bit < 288; bit++ {
		mask := byte(1 << (7 - bit%8))
		key[bit/8] &^= mask
		if suffix {
			key[bit/8] |= mask
		}
	}
	return key
}

func validTreeNodeID(id TreeNodeIDV1) bool {
	switch id.Kind {
	case TreeNodeLeafV1:
		return id.Depth == 288 && id.Prefix == ([36]byte{})
	case TreeNodeBranchV1:
		return id.Depth < 288 && id.RoutingKey == ([36]byte{}) && treeMask(id.Prefix, id.Depth, false) == id.Prefix
	default:
		return false
	}
}

// TreeNodeKey orders established identities in zero-first postorder without
// consulting links or presence. Equal upper bounds put greater depth first.
func TreeNodeKey(g uint64, id TreeNodeIDV1) ([]byte, error) {
	if g == 0 || !validTreeNodeID(id) {
		return nil, errSchema
	}
	out := binary.BigEndian.AppendUint64(make([]byte, 0, 46), g)
	upper, code := id.RoutingKey, uint16(0)
	if id.Kind == TreeNodeBranchV1 {
		upper, code = treeMask(id.Prefix, id.Depth, true), 288-id.Depth
	}
	out = append(out, upper[:]...)
	return binary.BigEndian.AppendUint16(out, code), nil
}

func DecodeTreeNodeKey(b []byte) (uint64, TreeNodeIDV1, error) {
	if len(b) != 46 || binary.BigEndian.Uint64(b) == 0 {
		return 0, TreeNodeIDV1{}, errSchema
	}
	var upper [36]byte
	copy(upper[:], b[8:44])
	code := binary.BigEndian.Uint16(b[44:])
	id := TreeNodeIDV1{Kind: TreeNodeLeafV1, Depth: 288, RoutingKey: upper}
	if code > 288 {
		return 0, TreeNodeIDV1{}, errSchema
	}
	if code != 0 {
		id = TreeNodeIDV1{Kind: TreeNodeBranchV1, Depth: 288 - code, Prefix: treeMask(upper, 288-code, false)}
		if treeMask(id.Prefix, id.Depth, true) != upper {
			return 0, TreeNodeIDV1{}, errSchema
		}
	}
	return binary.BigEndian.Uint64(b), id, nil
}

func treeChildFits(parent, child TreeNodeIDV1, side byte) bool {
	if !validTreeNodeID(child) || child.Depth <= parent.Depth {
		return false
	}
	key := child.RoutingKey
	if child.Kind == TreeNodeBranchV1 {
		key = child.Prefix
	}
	return treeMask(key, parent.Depth, false) == parent.Prefix && (key[parent.Depth/8]>>(7-parent.Depth%8))&1 == side
}

func validTreeNode(id TreeNodeIDV1, node TreeNodeV1) bool {
	if !validTreeNodeID(id) {
		return false
	}
	if id.Kind == TreeNodeLeafV1 {
		return node.Zero == nil && node.One == nil
	}
	if node.Zero == nil || node.One == nil || node.LeafDigest != ([32]byte{}) {
		return false
	}
	return treeChildFits(id, node.Zero.ID, 0) && treeChildFits(id, node.One.ID, 1)
}

func (node TreeNodeV1) Encode(id TreeNodeIDV1) ([]byte, error) {
	if !validTreeNode(id, node) {
		return nil, errSchema
	}
	if id.Kind == TreeNodeLeafV1 {
		return append([]byte(nil), node.LeafDigest[:]...), nil
	}
	out := make([]byte, 0, 140)
	for _, child := range [2]*TreeChildV1{node.Zero, node.One} {
		key, _ := TreeNodeKey(1, child.ID)
		out = append(out, key[8:]...)
		out = append(out, child.Digest[:]...)
	}
	return out, nil
}

func decodeTreeSuffix(b []byte) (TreeNodeIDV1, error) {
	if len(b) != 38 {
		return TreeNodeIDV1{}, errSchema
	}
	var key [46]byte
	key[7] = 1
	copy(key[8:], b)
	_, id, err := DecodeTreeNodeKey(key[:])
	return id, err
}

func DecodeTreeNodeValue(id TreeNodeIDV1, b []byte) (TreeNodeV1, error) {
	var node TreeNodeV1
	if !validTreeNodeID(id) {
		return node, errSchema
	}
	if id.Kind == TreeNodeLeafV1 {
		if len(b) != 32 {
			return node, errSchema
		}
		copy(node.LeafDigest[:], b)
		return node, nil
	}
	if len(b) != 140 {
		return node, errSchema
	}
	zero, err := decodeTreeSuffix(b[:38])
	if err != nil {
		return node, errSchema
	}
	one, err := decodeTreeSuffix(b[70:108])
	if err != nil {
		return node, errSchema
	}
	node.Zero, node.One = &TreeChildV1{ID: zero}, &TreeChildV1{ID: one}
	copy(node.Zero.Digest[:], b[38:70])
	copy(node.One.Digest[:], b[108:])
	if !validTreeNode(id, node) {
		return TreeNodeV1{}, errSchema
	}
	return node, nil
}

func treeValidKey(rank uint8, key []byte) bool {
	switch rank {
	case 0:
		return treeValidMetaKey(key)
	case 8:
		_, _, err := DecodeTreeNodeKey(key)
		return err == nil
	default:
		return validKey(rank, key)
	}
}

func treeValidMetaKey(key []byte) bool {
	switch len(key) {
	case 1:
		return key[0] <= 3
	case 9:
		return all(anyTrue(key[0] == 0x10, key[0] == 0x11), binary.BigEndian.Uint64(key[1:]) != 0)
	case 33:
		return key[0] == 0x12
	default:
		return false
	}
}

// ValidateTreeRow admits only local representation, not complete tree health,
// history assurance, IMAGE authentication or transaction validity.
func ValidateTreeRow(d DBI, key, value []byte) error {
	if TreeValidateDBI(d) != nil || !treeValidKey(d.Rank, key) {
		return errSchema
	}
	switch d.Rank {
	case 0:
		return treeMetaValue(key, value)
	case 1:
		_, err := decodeUTXOValue(value)
		return err
	case 3, 4:
		var hash [32]byte
		copy(hash[:], key)
		return validateInitial148Value(hash, value, d.Rank == 4)
	case 8:
		_, id, _ := DecodeTreeNodeKey(key)
		_, err := DecodeTreeNodeValue(id, value)
		return err
	default:
		return validateValue(d.Rank, key, value)
	}
}

func treeMetaValue(key, value []byte) error {
	switch key[0] {
	case 0:
		if !bytes.Equal(value, []byte{0, 0, 0, 3}) {
			return errSchema
		}
	case 2:
		return inspectTreeAuthorityV1(value)
	case 3:
		if !all(len(value) == 32, !bytes.Equal(value, make([]byte, 32))) {
			return errSchema
		}
	case 0x11:
		return inspectRootBindingV1(value)
	case 0x12:
		return validateTreeEvidenceRow(key[1:], value)
	default:
		return validateMetaValue(key[0], value)
	}
	return nil
}

func validateTreeEvidenceRow(key, value []byte) error {
	if _, err := DecodeTreeEvidenceV1(value); err != nil {
		return err
	}
	hash := sha3.Sum256(value)
	if !bytes.Equal(key, hash[:]) {
		return errSchema
	}
	return nil
}
