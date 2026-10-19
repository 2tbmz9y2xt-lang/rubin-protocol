package consensus

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"sort"
)

type utxoImageProof struct {
	exposed        []UTXOImageEntry
	left, right    []UTXOImageEdge
	hasPredecessor bool
}

// VerifyUTXOImageChunk requires prior caller correlation and finite proof
// admission. Success authenticates a local interval relative to echoed Root;
// entry semantics, anchor eligibility and import effects remain caller-owned.
func VerifyUTXOImageChunk(reply UTXOImageReply) (UTXOImageRange, bool, string) {
	if !reply.valid || string(reply.command[:]) != utxoImageChunkCommand {
		return UTXOImageRange{}, false, ""
	}
	proof := utxoImageProofFields(reply.payload)
	if !utxoImageOrdered(proof.exposed) || !utxoImageStart(proof, reply.query.StartKey) {
		return UTXOImageRange{}, false, "image_range"
	}
	root, ok := utxoImageProofRoot(proof)
	if !ok || root != reply.query.Root {
		return UTXOImageRange{}, false, "image_range"
	}
	if !utxoImageCover(proof, reply.query.StartKey) {
		return UTXOImageRange{}, false, "image_range"
	}
	return utxoImageOwnedRange(proof), true, ""
}

// The immutable private payload has already passed the complete scalar scan.
// Locate the flag without retaining descriptors, then allocate exactly t rows.
func utxoImageProofFields(payload []byte) utxoImageProof {
	flagOffset := 120
	_ = utxoImageScanEntries(payload, &flagOffset)
	shift := uint32(payload[flagOffset])
	n := binary.LittleEndian.Uint32(payload[120:124])
	proof := utxoImageProof{
		exposed: make([]UTXOImageEntry, n+shift), hasPredecessor: shift == 1,
	}
	off := 124
	for i := range n {
		proof.exposed[i+shift], _ = utxoImageReadEntry(payload, &off)
	}
	off++
	if proof.hasPredecessor {
		proof.exposed[0], _ = utxoImageReadEntry(payload, &off)
	}
	proof.left = utxoImageProofEdges(payload, &off)
	proof.right = utxoImageProofEdges(payload, &off)
	return proof
}

func utxoImageProofEdges(payload []byte, off *int) []UTXOImageEdge {
	n := binary.LittleEndian.Uint16(payload[*off : *off+2])
	*off += 2
	if n == 0 {
		return nil
	}
	edges := make([]UTXOImageEdge, n)
	for i := range n {
		edges[i].Depth = binary.BigEndian.Uint16(payload[*off : *off+2])
		copy(edges[i].Hash[:], payload[*off+2:*off+34])
		*off += 34
	}
	return edges
}

func utxoImageOrdered(entries []UTXOImageEntry) bool {
	for i := 1; i < len(entries); i++ {
		previous := canonicalUTXORoutingKey(entries[i-1].Outpoint)
		current := canonicalUTXORoutingKey(entries[i].Outpoint)
		if bytes.Compare(previous[:], current[:]) >= 0 {
			return false
		}
	}
	return true
}

func utxoImageStart(proof utxoImageProof, start [36]byte) bool {
	if len(proof.exposed) == 0 {
		return true
	}
	first := canonicalUTXORoutingKey(proof.exposed[0].Outpoint)
	if !proof.hasPredecessor {
		return bytes.Compare(first[:], start[:]) >= 0
	}
	if bytes.Compare(first[:], start[:]) >= 0 {
		return false
	}
	if len(proof.exposed) > 1 {
		returned := canonicalUTXORoutingKey(proof.exposed[1].Outpoint)
		return bytes.Compare(returned[:], start[:]) > 0
	}
	return true
}

func utxoImageProofRoot(proof utxoImageProof) ([32]byte, bool) {
	if len(proof.exposed) == 0 {
		if len(proof.left)+len(proof.right) != 0 {
			return [32]byte{}, false
		}
		return sha3.Sum256([]byte(canonicalUTXOEmptyDomain)), true
	}
	return utxoImageReconstruct(proof.exposed, proof.left, proof.right, -1)
}

func utxoImageEdgeDepth(edges []UTXOImageEdge) uint16 {
	if len(edges) == 0 {
		return 288
	}
	return edges[0].Depth
}

func utxoImageNextDepth(internal uint16, left, right []UTXOImageEdge) (uint16, bool) {
	ld, rd := utxoImageEdgeDepth(left), utxoImageEdgeDepth(right)
	d := min(internal, ld, rd)
	if d == 288 {
		return d, true
	}
	matches := 0
	for _, candidate := range [3]uint16{internal, ld, rd} {
		if candidate == d {
			matches++
		}
	}
	return d, matches == 1
}

// Each call owns a nonempty consecutive subset and all its applicable items.
// Consuming slices by value preserves the original retained right frontier.
func utxoImageReconstruct(entries []UTXOImageEntry, left, right []UTXOImageEdge, parent int) ([32]byte, bool) {
	first := canonicalUTXORoutingKey(entries[0].Outpoint)
	last := canonicalUTXORoutingKey(entries[len(entries)-1].Outpoint)
	internal := canonicalUTXOFirstDifferingBit(first, last)
	d, ok := utxoImageNextDepth(internal, left, right)
	if !ok {
		return [32]byte{}, false
	}
	if d == 288 {
		return canonicalUTXOLeafHash(entries[0].Outpoint, entries[0].Entry), true
	}
	if int(d) <= parent {
		return [32]byte{}, false
	}
	switch {
	case d == internal:
		return utxoImageInternal(entries, left, right, d)
	case d == utxoImageEdgeDepth(left):
		return utxoImageLeft(entries, left, right, d)
	default:
		return utxoImageRight(entries, left, right, d)
	}
}

func utxoImageInternal(entries []UTXOImageEntry, left, right []UTXOImageEdge, d uint16) ([32]byte, bool) {
	split := sort.Search(len(entries), func(i int) bool {
		key := canonicalUTXORoutingKey(entries[i].Outpoint)
		return key[d/8]&(0x80>>uint(d%8)) != 0
	})
	if split == 0 || split == len(entries) {
		return [32]byte{}, false
	}
	zero, ok := utxoImageReconstruct(entries[:split], left, nil, int(d))
	if !ok {
		return [32]byte{}, false
	}
	one, ok := utxoImageReconstruct(entries[split:], nil, right, int(d))
	if !ok {
		return [32]byte{}, false
	}
	key := canonicalUTXORoutingKey(entries[0].Outpoint)
	return canonicalUTXOBranchHash(d, key, zero, one), true
}

func utxoImageLeft(entries []UTXOImageEntry, left, right []UTXOImageEdge, d uint16) ([32]byte, bool) {
	key := canonicalUTXORoutingKey(entries[0].Outpoint)
	// The strictly smaller candidate than internal depth proves a shared prefix.
	if key[d/8]&(0x80>>uint(d%8)) == 0 {
		return [32]byte{}, false
	}
	opaque := left[0].Hash
	child, ok := utxoImageReconstruct(entries, left[1:], right, int(d))
	if !ok {
		return [32]byte{}, false
	}
	return canonicalUTXOBranchHash(d, key, opaque, child), true
}

func utxoImageRight(entries []UTXOImageEntry, left, right []UTXOImageEdge, d uint16) ([32]byte, bool) {
	key := canonicalUTXORoutingKey(entries[len(entries)-1].Outpoint)
	if key[d/8]&(0x80>>uint(d%8)) != 0 {
		return [32]byte{}, false
	}
	opaque := right[0].Hash
	right = right[1:]
	child, ok := utxoImageReconstruct(entries, left, right, int(d))
	if !ok {
		return [32]byte{}, false
	}
	return canonicalUTXOBranchHash(d, key, child, opaque), true
}

func utxoImageCover(proof utxoImageProof, start [36]byte) bool {
	if proof.hasPredecessor {
		return len(proof.exposed) != 1 || len(proof.right) == 0
	}
	if len(proof.exposed) == 0 {
		return true
	}
	first := canonicalUTXORoutingKey(proof.exposed[0].Outpoint)
	return first == start || len(proof.left) == 0
}

func utxoImageOwnedRange(proof utxoImageProof) UTXOImageRange {
	// Descriptors and edge arrays were allocated afresh for this call. Transfer
	// them only after success, cloning borrowed data in place to stay within t/e.
	for i := range proof.exposed {
		proof.exposed[i].Entry = cloneUtxoEntry(proof.exposed[i].Entry)
	}
	out := UTXOImageRange{
		Terminal: len(proof.right) == 0, RightEdge: proof.right,
	}
	start := 0
	if proof.hasPredecessor {
		out.Predecessor, start = &proof.exposed[0], 1
	}
	if len(proof.exposed) > start {
		out.Entries = proof.exposed[start:]
	}
	return out
}

// UTXOImageSuccessor adds one to the full unsigned 36-byte big-endian key.
// All-ff has no successor and returns zero,false without a scheduling effect.
func UTXOImageSuccessor(key [36]byte) ([36]byte, bool) {
	for i := len(key) - 1; i >= 0; i-- {
		key[i]++
		if key[i] != 0 {
			return key, true
		}
	}
	return [36]byte{}, false
}
