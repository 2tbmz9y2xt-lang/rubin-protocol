package node

// CompleteDASetProvider exposes caller-owned COMPLETE_SET DA relay snapshots.
type CompleteDASetProvider interface {
	CompleteDASetCandidates(maxPayloadBytes uint64) []CompleteDASetCandidate
}

// CompleteDASetCandidate is a caller-owned snapshot of one relay-complete DA set.
type CompleteDASetCandidate struct {
	DAID         [32]byte
	PayloadBytes uint64
	CommitTx     []byte
	Chunks       []CompleteDASetChunkCandidate
}

// CompleteDASetChunkCandidate is a caller-owned DA chunk transaction snapshot.
type CompleteDASetChunkCandidate struct {
	Index uint16
	Tx    []byte
}
