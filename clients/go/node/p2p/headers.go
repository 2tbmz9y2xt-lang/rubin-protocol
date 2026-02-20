package p2p

import (
	"encoding/binary"
	"fmt"

	"rubin.dev/node/consensus"
)

const (
	MaxHeadersPerMsg    = 2_000
	MaxLocatorHashes    = 64
	BlockHeaderBytesLen = 116
)

type GetHeadersPayload struct {
	Version      uint32
	BlockLocator [][32]byte
	HashStop     [32]byte // zero => up to MaxHeadersPerMsg
}

func EncodeGetHeadersPayload(p GetHeadersPayload) ([]byte, error) {
	if len(p.BlockLocator) == 0 || len(p.BlockLocator) > MaxLocatorHashes {
		return nil, fmt.Errorf("p2p: getheaders: invalid locator length")
	}
	out := make([]byte, 0, 4+9+len(p.BlockLocator)*32+32)
	var ver [4]byte
	binary.LittleEndian.PutUint32(ver[:], p.Version)
	out = append(out, ver[:]...)
	out = append(out, encodeCompactSize(uint64(len(p.BlockLocator)))...)
	for _, h := range p.BlockLocator {
		out = append(out, h[:]...)
	}
	out = append(out, p.HashStop[:]...)
	return out, nil
}

func DecodeGetHeadersPayload(b []byte) (*GetHeadersPayload, error) {
	if len(b) < 4+1+32+32 {
		return nil, fmt.Errorf("p2p: getheaders: short payload")
	}
	ver := binary.LittleEndian.Uint32(b[:4])
	hashCountU64, used, err := readCompactSize(b[4:])
	if err != nil {
		return nil, err
	}
	if hashCountU64 < 1 || hashCountU64 > MaxLocatorHashes {
		return nil, fmt.Errorf("p2p: getheaders: invalid hash_count")
	}
	hashCount := int(hashCountU64)
	need := 4 + used + hashCount*32 + 32
	if len(b) != need {
		return nil, fmt.Errorf("p2p: getheaders: length mismatch")
	}
	loc := make([][32]byte, 0, hashCount)
	off := 4 + used
	for i := 0; i < hashCount; i++ {
		var h [32]byte
		copy(h[:], b[off:off+32])
		loc = append(loc, h)
		off += 32
	}
	var stop [32]byte
	copy(stop[:], b[off:off+32])
	return &GetHeadersPayload{
		Version:      ver,
		BlockLocator: loc,
		HashStop:     stop,
	}, nil
}

func EncodeHeadersPayload(headers []consensus.BlockHeader) ([]byte, error) {
	if len(headers) > MaxHeadersPerMsg {
		return nil, fmt.Errorf("p2p: headers: too many headers")
	}
	out := make([]byte, 0, 9+len(headers)*BlockHeaderBytesLen)
	out = append(out, encodeCompactSize(uint64(len(headers)))...)
	for _, h := range headers {
		out = append(out, consensus.BlockHeaderBytes(h)...)
	}
	return out, nil
}

func DecodeHeadersPayload(b []byte) ([]consensus.BlockHeader, error) {
	countU64, used, err := readCompactSize(b)
	if err != nil {
		return nil, err
	}
	if countU64 > MaxHeadersPerMsg {
		return nil, fmt.Errorf("p2p: headers: count exceeds MaxHeadersPerMsg")
	}
	count := int(countU64)
	off := used
	need := used + count*BlockHeaderBytesLen
	if len(b) != need {
		return nil, fmt.Errorf("p2p: headers: length mismatch")
	}
	out := make([]consensus.BlockHeader, 0, count)
	for i := 0; i < count; i++ {
		chunk := b[off : off+BlockHeaderBytesLen]
		h, err := consensus.ParseBlockHeaderBytes(chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
		off += BlockHeaderBytesLen
	}
	return out, nil
}

// BuildBlockLocatorHeights implements the normative locator algorithm from the P2P spec.
// Result is a list of heights (tip->genesis) with at most MaxLocatorHashes entries.
func BuildBlockLocatorHeights(tipHeight uint64) []uint64 {
	heights := make([]uint64, 0, MaxLocatorHashes)

	// First 12: step 1 (including tip itself).
	for i := uint64(0); i < 12 && len(heights) < MaxLocatorHashes; i++ {
		if tipHeight < i {
			break
		}
		heights = append(heights, tipHeight-i)
	}

	// Then exponential offsets (spec §5.2 worked example): 14, 18, 26, 42, 74, ...
	// Implemented as a running offset with a doubling step.
	var step uint64 = 4
	var offset uint64 = 14
	for len(heights) < MaxLocatorHashes {
		if tipHeight < offset {
			break
		}
		heights = append(heights, tipHeight-offset)
		if step > (1 << 62) {
			break
		}
		offset += step
		step *= 2
	}

	// Ensure genesis is included (within the MaxLocatorHashes cap).
	if len(heights) == 0 || heights[len(heights)-1] != 0 {
		if len(heights) < MaxLocatorHashes {
			heights = append(heights, 0)
		} else {
			heights[len(heights)-1] = 0
		}
	}

	return heights
}
