// Package exclusionjournal retains independently durable original evidence bytes.
package exclusionjournal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

// Source refusals preserve the actual caller and retained-file owners.
var (
	ErrIntegrityV1   = errors.New("source: integrity")
	ErrUnavailableV1 = errors.New("source: unavailable")
	ErrCapacityV1    = errors.New("source: capacity")
	ErrIdentityV1    = errors.New("source: identity")
	ErrBusyV1        = errors.New("source: busy")
)

type (
	CaptureClassV1 uint8
	PartKindV1     uint8
)

// Capture classes select a closed ordered part set.
const (
	RejectionV1 CaptureClassV1 = iota + 1
	AcceptanceV1
	RecoveryCoreImpossibleV1
)

// Part kinds carry opaque original evidence, never a qualified journal decision.
const (
	BoundBodyV1 PartKindV1 = iota + 1
	ObservedResultV1
	HistoricalContextV1
	OriginalAssuranceV1
	ParentPathV1
	AcceptedPrefixV1
	AcquiredBlockBytesV1
	ExpectedHeaderPathV1
	AcquisitionPositionV1
)

// SourcePartSpecV1 fixes a part kind and its exact admitted byte length.
type SourcePartSpecV1 struct {
	Kind   PartKindV1
	Length uint64
}

// SourceManifestV1 fixes original identity, class, acquired-byte digest and ordered census.
type SourceManifestV1 struct {
	Identity, AcquiredDigest [32]byte
	Class                    CaptureClassV1
	Parts                    []SourcePartSpecV1
}

// SourceLimitsV1 are positive finite ceilings over the shared retained-source census and each operation.
type SourceLimitsV1 struct {
	Bytes, Files, Scans, RAM, Headers, Descriptors, Overhead uint64
}

// SourceOwnerV1 binds source operations to one actual Store instance and its protected directory.
type SourceOwnerV1 struct {
	store  *policycontrol.Store
	dir    string
	id     policycontrol.Identity
	info   os.FileInfo
	parent os.FileInfo
	limits SourceLimitsV1
	busy   atomic.Bool
	ops    sourceFS
	debt   *sourceDebt
}

// PreparedSourceV1 owns qualified durable backing; it is no journal reference or transfer permission.
type PreparedSourceV1 struct {
	owner    *SourceOwnerV1
	manifest SourceManifestV1
	name     string
	released bool
}

const (
	sourceDirectory = "source-captures-v1"
	scratchBytes    = 64 * 1024
	bundleHeader    = 4 + 97 + 32 + 32 + 1 + 1
)

// NewSourceOwnerV1 admits the protected child and finite census under one reusable owner, including its cleanup debt.
func NewSourceOwnerV1(store *policycontrol.Store, expected policycontrol.Identity, limits SourceLimitsV1, account OperationAccountV1) (*SourceOwnerV1, error) {
	b, err := store.BorrowSourceAuthorityV1()
	if err != nil {
		return nil, err
	}
	defer b.ReleaseV1()
	dir, id, err := b.BindingV1()
	if err != nil || id != expected {
		return nil, ErrIdentityV1
	}
	if !limits.valid() || account == nil {
		return nil, ErrCapacityV1
	}
	o := &SourceOwnerV1{store: store, dir: dir, id: id, limits: limits, ops: realSourceFS}
	err = account.WithReservation(limits.WorkingBytesV1(), func() error {
		parent, openErr := os.OpenRoot(filepath.Dir(dir))
		if openErr != nil {
			return ErrIdentityV1
		}
		o.parent, err = parent.Lstat(filepath.Join(".", filepath.Base(dir)))
		_ = parent.Close()
		if err != nil {
			return ErrIdentityV1
		}
		return o.openSourceRoot()
	})
	if err != nil {
		return nil, err
	}
	return o, nil
}

// valid rejects absent and effectively unbounded resource ceilings.
func (l SourceLimitsV1) valid() bool {
	for _, n := range []uint64{l.Bytes, l.Files, l.Scans, l.RAM, l.Headers, l.Descriptors, l.Overhead} {
		if n == 0 || n >= math.MaxInt64 {
			return false
		}
	}
	if l.Scans > uint64(math.MaxInt-scratchBytes-4096)/512 {
		return false
	}
	return l.Descriptors >= 4 && l.Files < l.Scans && l.RAM >= l.WorkingBytesV1()
}

// WorkingBytesV1 bounds copy scratch, directory metadata and constant operation/borrow state.
func (l SourceLimitsV1) WorkingBytesV1() uint64 { return scratchBytes + 4096 + l.Scans*512 }

// operation protects authority and funding through the last callback and cleanup without a P mutex.
func (o *SourceOwnerV1) operation(account OperationAccountV1, use func() error) error {
	if o == nil {
		return ErrIdentityV1
	}
	b, err := o.store.BorrowSourceAuthorityV1()
	if err != nil {
		return err
	}
	defer b.ReleaseV1()
	dir, id, err := b.BindingV1()
	if err != nil || id != o.id || filepath.Clean(dir) != o.dir {
		return ErrIdentityV1
	}
	switch {
	case account == nil, !o.limits.valid():
		return ErrCapacityV1
	}
	if !o.busy.CompareAndSwap(false, true) {
		return ErrBusyV1
	}
	defer o.busy.Store(false)
	return account.WithReservation(o.limits.WorkingBytesV1(), use)
}

// kinds selects the exact required and forbidden part domain.
func (m SourceManifestV1) kinds() []PartKindV1 {
	switch m.Class {
	case RejectionV1, AcceptanceV1:
		return []PartKindV1{BoundBodyV1, ObservedResultV1, HistoricalContextV1, OriginalAssuranceV1, ParentPathV1, AcceptedPrefixV1}
	case RecoveryCoreImpossibleV1:
		return []PartKindV1{AcquiredBlockBytesV1, ExpectedHeaderPathV1, HistoricalContextV1, OriginalAssuranceV1, AcquisitionPositionV1}
	}
	return nil
}

// SizeV1 validates the closed manifest and returns its exact encoded length before allocation.
func (m SourceManifestV1) SizeV1() (uint64, error) {
	kinds := m.kinds()
	if kinds == nil || len(m.Parts) != len(kinds) || m.Identity == [32]byte{} {
		return 0, ErrIntegrityV1
	}
	if (m.Class == RecoveryCoreImpossibleV1) != (m.AcquiredDigest != [32]byte{}) {
		return 0, ErrIntegrityV1
	}
	total := uint64(bundleHeader + 32)
	for i, p := range m.Parts {
		if !p.fits(kinds[i], total) {
			return 0, ErrIntegrityV1
		}
		total += 9 + p.Length
	}
	return total, nil
}

// fits checks the field domain and remaining signed-offset range before addition.
func (p SourcePartSpecV1) fits(kind PartKindV1, total uint64) bool {
	if p.Kind != kind || (p.Length == 0 && p.Kind != AcceptedPrefixV1) {
		return false
	}
	return total <= math.MaxInt64-9 && p.Length <= math.MaxInt64-total-9
}

// header encodes each fixed-width field explicitly, independent of Go struct layout.
func (m SourceManifestV1) header(id policycontrol.Identity) []byte {
	b := make([]byte, 0, bundleHeader+9*len(m.Parts))
	b = append(b, 'S', 'C', 'V', 1)
	b = append(b, id.InstallationID[:]...)
	b = append(b, id.ChainID[:]...)
	b = append(b, id.GenesisHash[:]...)
	b = append(b, byte(id.Profile))
	b = append(b, m.Identity[:]...)
	b = append(b, m.AcquiredDigest[:]...)
	b = append(b, byte(m.Class), 0)
	for _, part := range m.Parts {
		b[bundleHeader-1]++
		b = append(b, byte(part.Kind))
		b = binary.LittleEndian.AppendUint64(b, part.Length)
	}
	return b
}

// name includes capture class and the acquired bytes digest without treating either as evidence.
func (m SourceManifestV1) name(id policycontrol.Identity) string {
	digest := sha256.Sum256(m.header(id)[:bundleHeader])
	return hex.EncodeToString(digest[:])
}

// LimitsV1 returns finite immutable ceilings for source adapters.
func (o *SourceOwnerV1) LimitsV1() SourceLimitsV1 {
	if o == nil {
		return SourceLimitsV1{}
	}
	return o.limits
}
