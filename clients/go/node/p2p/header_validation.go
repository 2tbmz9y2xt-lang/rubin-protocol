package p2p

import (
	"bytes"
	"fmt"

	"rubin.dev/node/consensus"
	"rubin.dev/node/crypto"
)

// ValidateHeadersProfile applies the P2P header-chain validation profile from the P2P spec (§5.5):
// - linkage (prev hash)
// - expected target (when ancestry is available)
// - PoW: hash < target
// - timestamp: MTP and MAX_FUTURE_DRIFT (when ancestry is available)
//
// This is policy (P2P) validation but must stay consistent with the consensus header checks used by
// node import/apply paths.
func ValidateHeadersProfile(
	p crypto.CryptoProvider,
	headers []consensus.BlockHeader,
	ctx consensus.BlockValidationContext,
) error {
	if p == nil {
		return fmt.Errorf("p2p: headers: nil crypto provider")
	}
	if len(headers) == 0 {
		return nil
	}

	anc := append([]consensus.BlockHeader(nil), ctx.AncestorHeaders...)
	height := ctx.Height

	var prevHash [32]byte
	var havePrev bool
	if height > 0 && len(anc) > 0 {
		h, err := consensus.BlockHeaderHash(p, anc[len(anc)-1])
		if err != nil {
			return err
		}
		prevHash = h
		havePrev = true
	}

	for i := range headers {
		hdr := headers[i]
		if havePrev {
			if hdr.PrevBlockHash != prevHash {
				return fmt.Errorf(consensus.BLOCK_ERR_LINKAGE_INVALID)
			}
		}

		// Target/timestamp checks require ancestry context. If this stream begins at unknown parent,
		// we validate PoW only and leave target/timestamp to later full sync once ancestry is known.
		if height > 0 && len(anc) > 0 {
			exp, err := consensus.BlockExpectedTarget(anc, height, hdr.Target)
			if err != nil {
				return err
			}
			if !bytes.Equal(hdr.Target[:], exp[:]) {
				return fmt.Errorf(consensus.BLOCK_ERR_TARGET_INVALID)
			}

			medianTs, err := consensus.MedianPastTimestamp(anc, height)
			if err != nil {
				return err
			}
			if hdr.Timestamp <= medianTs {
				return fmt.Errorf(consensus.BLOCK_ERR_TIMESTAMP_OLD)
			}
			if ctx.LocalTimeSet && hdr.Timestamp > ctx.LocalTime+consensus.MAX_FUTURE_DRIFT {
				// Spec: do not immediately ban for future timestamps; callers may defer.
				return fmt.Errorf(consensus.BLOCK_ERR_TIMESTAMP_FUTURE)
			}
		}

		hash, err := consensus.BlockHeaderHash(p, hdr)
		if err != nil {
			return err
		}
		if bytes.Compare(hash[:], hdr.Target[:]) >= 0 {
			return fmt.Errorf(consensus.BLOCK_ERR_POW_INVALID)
		}

		prevHash = hash
		havePrev = true
		anc = append(anc, hdr)
		height++
	}

	return nil
}
