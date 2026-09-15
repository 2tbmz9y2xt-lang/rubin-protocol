package p2p

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"io"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// readInboundBlockPayload reads one block or cmpctblock payload under a single checked
// byte lease. Success returns the exact payload plus the live lease its caller now owns;
// every other exit returns no payload and no lease, and reports the read or checksum error
// ahead of any local capacity result (RUBIN_L1_P2P_AUX.md Section 2). Its caller supplies
// a non-nil reader and a header already validated by readFrameHeader. Stream position per
// exit: a precheck refusal reads nothing, a capacity refusal and a checksum error consume
// the declared payload, a non-capacity refusal stops after the fixed prefix, and a read
// error stops mid-frame.
func readInboundBlockPayload(r io.Reader, header frameHeader, budget *inboundBlockBudget) ([]byte, *inboundBlockLease, error) {
	charge, err := inboundBlockPrechecks(header, budget)
	if err != nil {
		return nil, nil, err
	}
	var storage [consensus.BLOCK_HEADER_BYTES]byte
	prefixLen, err := readInboundBlockPrefix(r, header.Size, &storage)
	if err != nil {
		return nil, nil, err
	}
	prefix := storage[:prefixLen]
	lease, err := budget.TryReserveOrSubscribe(charge)
	if err != nil {
		var capacity inboundBlockBudgetError
		if !errors.As(err, &capacity) || capacity.resource != inboundBudgetCapacityResource {
			return nil, nil, err
		}
		return nil, nil, discardRefusedInboundBlockPayload(r, header, prefix, capacity)
	}
	return readInboundBlockBody(r, header, prefix, lease)
}

// inboundBlockPrechecks answers with the byte charge this frame costs, refusing an
// unsupported command first, then a size above that command's cap, then a missing budget.
// Every refusal here precedes the first payload byte (RUBIN_L1_P2P_AUX.md Section 2.1).
func inboundBlockPrechecks(header frameHeader, budget *inboundBlockBudget) (uint64, error) {
	charge, err := inboundBlockCharge(header.Command, uint64(header.Size))
	if err != nil {
		return 0, err
	}
	if header.Size > inboundBlockPayloadCap(header.Command) {
		return 0, commandPayloadCapError{command: header.Command}
	}
	if budget == nil {
		return 0, errNilInboundBlockBudget
	}
	return charge, nil
}

// inboundBlockPayloadCap returns the cap its existing owner gives one of the two commands
// this reader accepts; every other command caps at zero, so any nonzero size exceeds it
// (RUBIN_COMPACT_BLOCKS.md Section 1).
func inboundBlockPayloadCap(command string) uint32 {
	switch command {
	case messageBlock:
		return variablePostHandshakePayloadCap(command, 0, 0)
	case messageCmpctBlock:
		return compactRelayPayloadCap(command)
	}
	return 0
}

// readInboundBlockPrefix stores the first min(size, 116) payload bytes in storage and
// reports how many it stored, without any size-dependent allocation. Unlike
// readPayloadPrefix, whose io.ReadFull drops an error co-returned with a full buffer, this
// loop keeps that error unless those bytes complete the whole declared payload.
func readInboundBlockPrefix(r io.Reader, size uint32, storage *[consensus.BLOCK_HEADER_BYTES]byte) (int, error) {
	want := len(storage)
	if size < uint32(want) {
		want = int(size)
	}
	read := 0
	for read < want {
		n, err := r.Read(storage[read:want])
		read += n
		if err == nil {
			continue
		}
		if read == int(size) {
			break
		}
		return read, payloadReadError(size, 0, read, err)
	}
	return read, nil
}

// readInboundBlockBody replays the prefix ahead of the live reader and returns the exact
// payload with the lease still held; every other exit, a panic from the reader included,
// releases that lease exactly once.
func readInboundBlockBody(r io.Reader, header frameHeader, prefix []byte, lease *inboundBlockLease) ([]byte, *inboundBlockLease, error) {
	kept := false
	defer func() {
		if !kept {
			lease.Release()
		}
	}()
	payload, err := readPayloadWithChecksum(io.MultiReader(bytes.NewReader(prefix), r), header.Size, header.Checksum)
	if err != nil {
		return nil, nil, err
	}
	kept = true
	return payload, lease, nil
}

// discardRefusedInboundBlockPayload drains the rest of the declared payload through one
// fixed scratch buffer, keeping the existing absolute 32768-byte read boundaries, and
// returns the captured refusal only once the envelope checksum matches. A complete header
// adds its identity to that refusal; a shorter payload adds none.
func discardRefusedInboundBlockPayload(r io.Reader, header frameHeader, prefix []byte, refusal inboundBlockBudgetError) error {
	hasher := sha3.New256()
	// hash.Hash.Write never reports an error (its stdlib contract).
	_, _ = hasher.Write(prefix)
	var scratch [streamReadChunkBytes]byte
	for received := len(prefix); received < int(header.Size); {
		window := inboundBlockDiscardWindow(received, int(header.Size))
		n, err := io.ReadFull(r, scratch[:window])
		if err != nil {
			return payloadReadError(header.Size, received, n, err)
		}
		_, _ = hasher.Write(scratch[:window])
		received += window
	}
	sum := hasher.Sum(nil)
	if [4]byte{sum[0], sum[1], sum[2], sum[3]} != header.Checksum {
		return errors.New("invalid envelope checksum")
	}
	if h, err := consensus.BlockHash(prefix); err == nil {
		refusal.hash, refusal.hashOK = h, true
	}
	return refusal
}

// inboundBlockDiscardWindow returns the read length that ends at the next absolute
// 32768-byte payload boundary, or at the declared size.
func inboundBlockDiscardWindow(received, size int) int {
	remaining := size - received
	if step := streamReadChunkBytes - received%streamReadChunkBytes; step < remaining {
		return step
	}
	return remaining
}
