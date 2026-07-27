package node

import (
	"errors"
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var (
	errTargetHistoryMissing = errors.New("target schedule history unavailable")
	errTargetHistoryCorrupt = errors.New("target schedule history corrupt")
	errTargetHeightInvalid  = errors.New("target schedule height invalid")
	errTargetRetarget       = errors.New("target schedule retarget failed")
	errTargetLocalIO        = errors.New("target schedule local I/O")
)

type targetHeaderReader func([32]byte) ([]byte, error)

func expectedTargetForCandidateWithReader(read targetHeaderReader, parentHash [32]byte, candidateHeight uint64) ([32]byte, error) {
	var zero [32]byte
	if candidateHeight == 0 {
		return zero, errTargetHeightInvalid
	}
	if candidateHeight%uint64(consensus.WINDOW_SIZE) != 0 {
		return selectedParentTarget(read, parentHash)
	}

	window := int(consensus.WINDOW_SIZE)
	timestamps := make([]uint64, window)
	visited := make(map[[32]byte]struct{}, window)
	current := parentHash
	var targetOld [32]byte
	for i := 0; i < window; i++ {
		header, err := readTargetScheduleHeader(read, current, i == 0, i+1 < window, visited)
		if err != nil {
			return zero, err
		}
		if i == 0 {
			targetOld = header.Target
		}
		timestamps[window-1-i] = header.Timestamp
		current = header.PrevBlockHash
	}
	target, err := consensus.RetargetV1Clamped(targetOld, timestamps)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", errTargetRetarget, err)
	}
	return target, nil
}

func readTargetScheduleHeader(read targetHeaderReader, lookup [32]byte, immediate, needParent bool, visited map[[32]byte]struct{}) (consensus.BlockHeader, error) {
	var zero consensus.BlockHeader
	if _, ok := visited[lookup]; ok {
		return zero, fmt.Errorf("%w: repeated lookup hash", errTargetHistoryCorrupt)
	}
	visited[lookup] = struct{}{}
	header, raw, err := readParsedTargetHeader(read, lookup, immediate)
	if err != nil {
		return zero, err
	}
	if _, ok := visited[header.PrevBlockHash]; ok {
		return zero, fmt.Errorf("%w: repeated lookup hash", errTargetHistoryCorrupt)
	}
	if err := verifyTargetHeaderHash(raw, lookup); err != nil {
		return zero, err
	}
	if needParent && header.PrevBlockHash == ([32]byte{}) {
		return zero, fmt.Errorf("%w: zero ancestor before complete window", errTargetHistoryMissing)
	}
	return header, nil
}

func selectedParentTarget(read targetHeaderReader, parentHash [32]byte) ([32]byte, error) {
	header, raw, err := readParsedTargetHeader(read, parentHash, true)
	if err != nil {
		return [32]byte{}, err
	}
	if err := verifyTargetHeaderHash(raw, parentHash); err != nil {
		return [32]byte{}, err
	}
	return header.Target, nil
}

func readParsedTargetHeader(read targetHeaderReader, lookup [32]byte, immediate bool) (consensus.BlockHeader, []byte, error) {
	raw, err := read(lookup)
	if err != nil {
		return consensus.BlockHeader{}, nil, targetScheduleReadError(err, immediate)
	}
	header, err := consensus.ParseBlockHeaderBytes(raw)
	if err != nil {
		return consensus.BlockHeader{}, nil, fmt.Errorf("%w: malformed header: %w", errTargetHistoryCorrupt, err)
	}
	return header, raw, nil
}

func targetScheduleReadError(err error, immediate bool) error {
	if errors.Is(err, os.ErrNotExist) {
		if immediate {
			return ErrParentNotFound
		}
		return fmt.Errorf("%w: ancestor header not found", errTargetHistoryMissing)
	}
	return fmt.Errorf("%w: header read: %w", errTargetLocalIO, err)
}

func verifyTargetHeaderHash(raw []byte, lookup [32]byte) error {
	hash, err := consensus.BlockHash(raw)
	if err != nil {
		return fmt.Errorf("%w: header hash: %w", errTargetHistoryCorrupt, err)
	}
	if hash != lookup {
		return fmt.Errorf("%w: lookup hash mismatch", errTargetHistoryCorrupt)
	}
	return nil
}

func expectedTargetForCandidate(store *BlockStore, parentHash [32]byte, candidateHeight uint64) ([32]byte, error) {
	return expectedTargetForCandidateWithReader(store.GetHeaderByHash, parentHash, candidateHeight)
}

func (s *SyncEngine) expectedTargetForCandidate(parentHash [32]byte, candidateHeight uint64) ([32]byte, error) {
	if s == nil {
		return expectedTargetForCandidate(nil, parentHash, candidateHeight)
	}
	return expectedTargetForCandidate(s.blockStore, parentHash, candidateHeight)
}
