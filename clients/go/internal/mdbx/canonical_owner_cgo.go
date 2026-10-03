//go:build cgo && (darwin || linux) && (amd64 || arm64)

package mdbx

/*
#cgo CFLAGS: -std=c11
#include "../../../../third_party/libmdbx/mdbx.h"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

// canonicalSide is one access path of the canonical index for the pairing rule (RUBIN_MEMPOOL_POLICY.md Section
// 6.4.1.2 and 6.4.1.3): canonical-v1 (rank 2, 104-byte value whose leading 32 bytes name the block hash) or
// canonical-owner-v1 (rank 7, 8-byte value naming the height). A row of one side names its partner key
// generation || value[:field]; the partner names it back when the partner value's leading len(key)-8 bytes equal key[8:].
type canonicalSide struct {
	rank, partner       uint8
	width, partnerWidth C.size_t
	field               int
}

// canonicalSides lists the forward side (rules N1 and O1) before the owner side (rules N2 and O2).
var canonicalSides = [...]canonicalSide{{rank: 2, partner: 7, width: 104, partnerWidth: 8, field: 32}, {rank: 7, partner: 2, width: 8, partnerWidth: 104, field: 8}}

func canonicalPairingError() error {
	return adapterError(operationUpdate, EngineInvalidInput, codeEINVAL, "unpaired canonical owner mutation", nil)
}

// updateNativePairedImages captures every target's OLD image and every OLD_VALUE_REF source exactly as
// updateNativeImages does, then applies updateNativePairing before any OLD/write snapshot comparison runs.
func updateNativePairedImages(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation) ([]updateImage, []updateReference, error) {
	targets, references, err := updateNativeImages(old, dbis, plan)
	if err != nil {
		return nil, nil, err
	}
	err = updateNativePairing(old, dbis, plan, targets)
	if err != nil {
		return nil, nil, err
	}
	return targets, references, nil
}

// updateNativePairing keeps canonical-v1 and canonical-owner-v1 bijective across one admitted plan. N1: a forward literal
// (g,h)->x needs an owner literal target (g,x)->h. N2: an owner literal (g,x)->h needs a forward literal target (g,h)
// naming x. O1: a forward target whose OLD value is exactly 104 bytes naming x, and whose NEW value is absent or names
// another hash, needs an owner target (g,x) whenever the OLD owner (g,x) is exactly 8 bytes holding h. O2: an owner
// target whose OLD value is exactly 8 bytes holding h, and whose NEW value is absent or holds another height, needs a
// forward target (g,h) whenever the OLD forward (g,h) is exactly 104 bytes naming x. A partner that is itself a target
// satisfies O1/O2 without a read; any other partner is one exact OLD point read. An OLD image of another width or an
// unpaired OLD partner creates no obligation, so orphan and malformed rows stay disposable. Rules run in the order N1,
// N2, O1, O2, each over targets in plan order; the first violation returns the direct InvalidInput refusal and a
// failed partner read returns its unchanged native error. A plan without a rank-2 or rank-7 target reads nothing and
// allocates nothing; a partner read allocates one 40- or 16-byte key. Borrowed OLD bytes are read only while old is live.
func updateNativePairing(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, targets []updateImage) error {
	for _, side := range canonicalSides {
		if !canonicalNewPaired(plan, side) {
			return canonicalPairingError()
		}
	}
	for _, side := range canonicalSides {
		err := canonicalOldPaired(old, dbis, plan, targets, side)
		if err != nil {
			return err
		}
	}
	return nil
}

// canonicalNewPaired is N1 for the forward side and N2 for the owner side.
func canonicalNewPaired(plan []ownedMutation, side canonicalSide) bool {
	var partner [40]byte
	for _, m := range plan {
		if m.dbi.Rank != side.rank || m.after != AfterLiteral {
			continue
		}
		j := canonicalTargetIndex(plan, side.partner, canonicalPartnerKey(&partner, m.key, m.literal[:side.field]))
		if j < 0 || plan[j].after != AfterLiteral || !bytes.Equal(plan[j].literal[:len(m.key)-8], m.key[8:]) {
			return false
		}
	}
	return true
}

// canonicalOldPaired is O1 for the forward side and O2 for the owner side.
func canonicalOldPaired(old *C.MDBX_txn, dbis [8]C.MDBX_dbi, plan []ownedMutation, targets []updateImage, side canonicalSide) error {
	var partner [40]byte
	for i, m := range plan {
		field, obligated := canonicalOldField(m, targets[i], side)
		if !obligated {
			continue
		}
		key := canonicalPartnerKey(&partner, m.key, field)
		if canonicalTargetIndex(plan, side.partner, key) >= 0 {
			continue
		}
		image, err := updateNativeImage(old, dbis[side.partner], bytes.Clone(key))
		if err != nil {
			return err
		}
		if canonicalImageNames(image, side.partnerWidth, m.key) {
			return canonicalPairingError()
		}
	}
	return nil
}

// canonicalOldField returns the leading OLD field of a target of this side whose OLD value has the side's exact width,
// and reports whether the planned NEW value is absent or names another partner. The width is checked before slicing.
func canonicalOldField(m ownedMutation, image updateImage, side canonicalSide) ([]byte, bool) {
	if m.dbi.Rank != side.rank || len(m.key) != 48-side.field || !image.present || image.length != side.width {
		return nil, false
	}
	field := unsafe.Slice((*byte)(image.bytes), side.field)
	return field, m.after != AfterLiteral || !bytes.Equal(m.literal[:side.field], field)
}

// canonicalImageNames reports whether an OLD partner image is present, has the partner's exact width and names key back.
func canonicalImageNames(image updateImage, width C.size_t, key []byte) bool {
	if !image.present || image.length != width {
		return false
	}
	return bytes.Equal(unsafe.Slice((*byte)(image.bytes), len(key)-8), key[8:])
}

// canonicalPartnerKey writes generation || field into buf and returns that 40- or 16-byte view.
func canonicalPartnerKey(buf *[40]byte, key, field []byte) []byte {
	copy(buf[:8], key[:8])
	return buf[:8+copy(buf[8:], field)]
}

// canonicalTargetIndex returns the plan index of the (rank, key) target or -1; the admitted plan is strictly ordered by
// (DBI.Rank, key) and an admitted rank names exactly one DBI.
func canonicalTargetIndex(plan []ownedMutation, rank uint8, key []byte) int {
	low, high := 0, len(plan)
	for low < high {
		middle := low + (high-low)/2
		if updateKeyOrdered(plan[middle].dbi.Rank, plan[middle].key, rank, key) {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low < len(plan) && plan[low].dbi.Rank == rank && bytes.Equal(plan[low].key, key) {
		return low
	}
	return -1
}

// CanonicalOwnerResultV1 is one keyed CanonicalOwnerV1 observation (RUBIN_MEMPOOL_POLICY.md Section 6.4.1.3). Owned
// reports that canonical-owner-v1 holds Height for the queried hash and that canonical-v1 at that height is a
// structurally legal entry naming it; Entry is then that exact 104-byte entry. Rows lists the rows the observation
// consulted in (DBI.Rank, key) order: the owner row alone when Owned is false, the forward row then the owner row when
// Owned is true. Entry and every Rows key are fresh allocations the caller owns.
type CanonicalOwnerResultV1 struct {
	Height uint64
	Owned  bool
	Entry  []byte
	Rows   []ConsultedRow
}

// CanonicalOwnerV1 resolves (generation, hash) through the keyed owner row and at most one forward read, in this order:
// an unusable Reader returns InvalidInput "Reader is not active"; a Reader whose Store handle holds no canonical-owner
// verification returns InvalidInput "canonical owner index is not verified" with no read, no recorded failure and a
// still-usable Reader; the owner row is read with Get, so generation zero returns Get's invalid-key refusal and a
// native, shape or width failure returns the object Get recorded; an absent owner row is Owned false with Rows holding
// the owner row; a present height is followed by Get of canonical-v1 (generation, height) with the same failure rule;
// an absent forward entry, one naming another hash, or one whose 40-byte work (offsets 64..103) is outside
// 0 < work <= 2^288 records Integrity "canonical owner index inconsistency" as this Reader's failure and returns that
// same object, never Owned false; if the Reader expired or was disarmed by another failure meanwhile, nothing is recorded
// and "Reader is not active" is returned. Verification exists on a Store handle only after the successful Create
// publication or BootstrapStorageV1's exact-empty census; Open never establishes it. Each call allocates at most a
// 40-byte owner key, a 16-byte forward key, Get copies of 8 and 104 bytes and one Rows array of two rows; consumers
// charge those buffers to their reservation.
func (r *Reader) CanonicalOwnerV1(generation uint64, hash [32]byte) (CanonicalOwnerResultV1, error) {
	if !r.usable() {
		return CanonicalOwnerResultV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "Reader is not active", nil)
	}
	if !r.ownerVerified {
		return CanonicalOwnerResultV1{}, adapterError(operationGet, EngineInvalidInput, codeEINVAL, "canonical owner index is not verified", nil)
	}
	owner := ConsultedRow{DBI: schemaDBIs[7], Key: make([]byte, 40)}
	binary.BigEndian.PutUint64(owner.Key, generation)
	copy(owner.Key[8:], hash[:])
	value, present, err := r.Get(owner.DBI, owner.Key)
	if err != nil {
		return CanonicalOwnerResultV1{}, err
	}
	if !present {
		return CanonicalOwnerResultV1{Rows: []ConsultedRow{owner}}, nil
	}
	return r.canonicalOwnerEntry(owner, generation, binary.BigEndian.Uint64(value), hash)
}

// canonicalOwnerEntry reads the forward entry a present owner row selects and decides Owned or the recorded inconsistency.
func (r *Reader) canonicalOwnerEntry(owner ConsultedRow, generation, height uint64, hash [32]byte) (CanonicalOwnerResultV1, error) {
	forward := ConsultedRow{DBI: schemaDBIs[2], Key: make([]byte, 16)}
	binary.BigEndian.PutUint64(forward.Key, generation)
	binary.BigEndian.PutUint64(forward.Key[8:], height)
	entry, present, err := r.Get(forward.DBI, forward.Key)
	if err != nil {
		return CanonicalOwnerResultV1{}, err
	}
	if !present || !bytes.Equal(entry[:32], hash[:]) || !validWork([40]byte(entry[64:104])) {
		return CanonicalOwnerResultV1{}, bootstrapFailure(r, integrityError(operationGet, "canonical owner index inconsistency", nil))
	}
	return CanonicalOwnerResultV1{Height: height, Owned: true, Entry: entry, Rows: []ConsultedRow{forward, owner}}, nil
}
