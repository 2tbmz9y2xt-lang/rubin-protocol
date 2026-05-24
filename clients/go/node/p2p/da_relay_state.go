package p2p

import (
	"errors"
	"sync"
)

const (
	daOrphanPoolSizeBytes          uint64 = 64 << 20
	daOrphanPoolPerPeerMaxBytes    uint64 = 4 << 20
	daOrphanPoolPerDAIDMaxBytes    uint64 = 8 << 20
	daOrphanCommitOverheadMaxBytes uint64 = 8 << 20
	daOrphanTTLBlocks              uint64 = 3
	daMempoolPinnedPayloadMaxBytes uint64 = 96_000_000
)

type daRelaySetState uint8

const (
	daRelayStateOrphanChunks daRelaySetState = iota
	daRelayStateStagedCommit
	daRelayStateCompleteSet
)

type daRelayCaps struct {
	orphanPoolBytes           uint64
	orphanPoolPerPeerBytes    uint64
	orphanPoolPerDAIDBytes    uint64
	orphanCommitOverheadBytes uint64
	orphanTTLBlocks           uint64
	pinnedPayloadBytes        uint64
}

func defaultDARelayCaps() daRelayCaps {
	return daRelayCaps{
		orphanPoolBytes:           daOrphanPoolSizeBytes,
		orphanPoolPerPeerBytes:    daOrphanPoolPerPeerMaxBytes,
		orphanPoolPerDAIDBytes:    daOrphanPoolPerDAIDMaxBytes,
		orphanCommitOverheadBytes: daOrphanCommitOverheadMaxBytes,
		orphanTTLBlocks:           daOrphanTTLBlocks,
		pinnedPayloadBytes:        daMempoolPinnedPayloadMaxBytes,
	}
}

func (c daRelayCaps) validate() error {
	if err := c.validatePositiveCaps(); err != nil {
		return err
	}
	return c.validateRelativeCaps()
}

func (c daRelayCaps) validatePositiveCaps() error {
	if c.orphanPoolBytes == 0 {
		return errors.New("da orphan pool cap is zero")
	}
	if c.orphanPoolPerPeerBytes == 0 {
		return errors.New("da orphan pool per-peer cap is zero")
	}
	if c.orphanPoolPerDAIDBytes == 0 {
		return errors.New("da orphan pool per-da_id cap is zero")
	}
	if c.orphanCommitOverheadBytes == 0 {
		return errors.New("da orphan commit overhead cap is zero")
	}
	if c.orphanTTLBlocks == 0 {
		return errors.New("da orphan ttl is zero")
	}
	if c.pinnedPayloadBytes == 0 {
		return errors.New("da pinned payload cap is zero")
	}
	return nil
}

func (c daRelayCaps) validateRelativeCaps() error {
	if c.orphanPoolPerPeerBytes > c.orphanPoolBytes {
		return errors.New("da orphan pool per-peer cap exceeds global cap")
	}
	if c.orphanPoolPerDAIDBytes > c.orphanPoolBytes {
		return errors.New("da orphan pool per-da_id cap exceeds global cap")
	}
	if c.orphanCommitOverheadBytes > c.orphanPoolBytes {
		return errors.New("da orphan commit overhead cap exceeds global cap")
	}
	return nil
}

type daRelaySetRecord struct {
	daID         [32]byte
	state        daRelaySetState
	receivedTime uint64
	payloadBytes uint64
	wireBytes    uint64
	totalFee     uint64
}

type daRelayState struct {
	mu                        sync.Mutex
	caps                      daRelayCaps
	nextReceivedTime          uint64
	orphanBytes               uint64
	orphanBytesByPeer         map[string]uint64
	orphanBytesByDAID         map[[32]byte]uint64
	orphanCommitOverheadBytes uint64
	pinnedPayloadBytes        uint64
	sets                      map[[32]byte]daRelaySetRecord
}

func newDARelayState(caps daRelayCaps) (*daRelayState, error) {
	if err := caps.validate(); err != nil {
		return nil, err
	}
	return &daRelayState{
		caps:              caps,
		orphanBytesByPeer: map[string]uint64{},
		orphanBytesByDAID: map[[32]byte]uint64{},
		sets:              make(map[[32]byte]daRelaySetRecord),
	}, nil
}

func (s *daRelayState) nextMonotonicReceivedTime() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.nextReceivedTime++
	return s.nextReceivedTime
}
