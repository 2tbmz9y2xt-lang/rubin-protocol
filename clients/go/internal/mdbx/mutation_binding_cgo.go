//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

// MutationBindingV1 is the opaque process-local lineage of one active Reader:
// its Store instance identity and the mutation epoch captured when the Reader
// was created. It proves lineage only (RUBIN_COMPACT_BLOCKS.md Section 10), never
// a quantity, a delta or that a commit happened. The zero value is never reusable.
type MutationBindingV1 struct {
	instance uint64
	epoch    uint64
	reusable bool
}

// MutationBindingV1 returns the Reader's captured binding without native access.
// An inactive, nil, copied or expired Reader returns the zero binding and the
// same refusal Reader.Get returns; an active non-cacheable Reader returns a
// non-reusable binding and nil.
func (r *Reader) MutationBindingV1() (MutationBindingV1, error) {
	if !r.usable() {
		return MutationBindingV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	return MutationBindingV1{instance: r.lineageID, epoch: r.lineageEpoch, reusable: r.lineageReusable}, nil
}

// EqualForReuse is true only when both bindings are reusable and name the same
// Store instance and the same mutation epoch.
func (b MutationBindingV1) EqualForReuse(other MutationBindingV1) bool {
	return b.reusable && other.reusable && b.instance == other.instance && b.epoch == other.epoch
}

// AfterOneCommitAttemptV1 returns the binding expected after exactly one more
// native commit attempt on the same instance, or (zero, false) for a
// non-reusable binding or one at the maximum epoch. It performs no Store action
// and does not prove that an attempt happened or that its delta is known.
func (b MutationBindingV1) AfterOneCommitAttemptV1() (MutationBindingV1, bool) {
	if !b.reusable || b.epoch == ^uint64(0) {
		return MutationBindingV1{}, false
	}
	return MutationBindingV1{instance: b.instance, epoch: b.epoch + 1, reusable: true}, true
}
