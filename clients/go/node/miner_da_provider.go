package node

// CompleteDASetProvider exposes relay-complete DA set candidates to miner code.
type CompleteDASetProvider interface {
	CompleteDASetCandidates(maxPayloadBytes uint64) []CompleteDASetCandidate
}

// CompleteDASetCandidate is an immutable miner-facing COMPLETE_SET snapshot.
type CompleteDASetCandidate struct {
	DAID         [32]byte
	PayloadBytes uint64
	CommitTx     []byte
	Chunks       []CompleteDASetChunkCandidate
}

// CompleteDASetChunkCandidate carries one DA_CHUNK_TX snapshot in chunk_index order.
type CompleteDASetChunkCandidate struct {
	Index uint16
	Tx    []byte
}
