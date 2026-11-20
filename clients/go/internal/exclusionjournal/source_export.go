package exclusionjournal

import (
	"cmp"
	"io"
	"math"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// SourceExporterV1 delivers the exact manifest once, in order, within WithBackingV1.
type SourceExporterV1 func(operation *SourceOperationV1, visit func(SourcePartV1) error) error

// SourceOperationV1 bounds synchronous source backing on the live operation account; a nil, zero or expired operation refuses with ErrUnavailableV1.
type SourceOperationV1 struct{ cursor *exportCursor }

// SourceOriginV1 names a complete nonempty allocation or a planned allocation of at most math.MaxInt bytes.
type SourceOriginV1 struct {
	Bytes        []byte
	PlannedBytes uint64
}

// SourceViewV1 binds an exact part range to its origin. Origin -1 denotes an empty part without backing.
type SourceViewV1 struct {
	Origin         int
	Offset, Length uint64
}

// SourcePartV1 exposes one bounded ReadAt until its visitor returns.
type SourcePartV1 struct {
	Kind   PartKindV1
	Length uint64
	ReadAt func([]byte, int64) (int, error)
}

type partScope struct {
	mu      sync.Mutex
	closing atomic.Bool
	part    SourcePartV1
}

func (s *partScope) read(dst []byte, offset int64) (int, error) {
	if s.closing.Load() {
		return 0, ErrUnavailableV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return 0, ErrUnavailableV1
	}
	if offset < 0 || offset > int64(min(s.part.Length, math.MaxInt64))-int64(len(dst)) {
		return 0, ErrIntegrityV1
	}
	return s.part.ReadAt(dst, offset)
}

func (s *partScope) expire() {
	s.closing.Store(true)
	s.mu.Lock()
	s.part = SourcePartV1{}
	s.mu.Unlock()
}

func visitPart(part SourcePartV1, visit func(SourcePartV1) error) error {
	s := &partScope{part: part}
	defer s.expire()
	return visit(SourcePartV1{Kind: part.Kind, Length: part.Length, ReadAt: s.read})
}

func backingBytes(m SourceManifestV1, origins []SourceOriginV1, views []SourceViewV1) (uint64, error) {
	if len(origins) > 9 || len(views) != len(m.Parts) {
		return 0, ErrIntegrityV1
	}
	for i, view := range views {
		if !view.fits(origins, m.Parts[i].Length) {
			return 0, ErrIntegrityV1
		}
	}
	var total uint64
	for index, origin := range origins {
		length := origin.length()
		if !origin.valid(origins[:index]) {
			return 0, ErrIntegrityV1
		}
		if length > math.MaxUint64-total {
			return 0, ErrCapacityV1
		}
		total += length
	}
	return total, nil
}

func (v SourceViewV1) fits(origins []SourceOriginV1, expected uint64) bool {
	if v.Origin < 0 || v.Origin >= len(origins) {
		return expected == 0 && v == (SourceViewV1{Origin: -1})
	}
	length := origins[v.Origin].length()
	return v.Length == expected && v.Offset <= length && v.Length <= length-v.Offset
}

func (o SourceOriginV1) length() uint64 { return max(uint64(len(o.Bytes)), o.PlannedBytes) }

func (o SourceOriginV1) valid(previous []SourceOriginV1) bool {
	if o.PlannedBytes != 0 {
		return o.Bytes == nil && o.PlannedBytes <= math.MaxInt
	}
	start := uint64(reflect.ValueOf(o.Bytes).Pointer())
	length := uint64(len(o.Bytes))
	return length != 0 && len(o.Bytes) == cap(o.Bytes) && length <= math.MaxUint64-start && !slices.ContainsFunc(previous, func(origin SourceOriginV1) bool {
		other := uint64(reflect.ValueOf(origin.Bytes).Pointer())
		return start < other+uint64(len(origin.Bytes)) && other < start+length
	})
}

type exportCursor struct {
	lifetime     sync.RWMutex
	mu, delivery sync.Mutex
	*exportState
}

type exportState struct {
	manifest SourceManifestV1
	account  *mdbx.OperationAccount
	limits   SourceLimitsV1
	visit    func(SourcePartV1) error
	used     bool
	active   atomic.Bool
	failure  error
	panicked any
}

// pin keeps the backing state alive until the caller releases the lifetime read lock.
func (op *SourceOperationV1) pin() *exportCursor {
	if op == nil || op.cursor == nil || !op.cursor.lifetime.TryRLock() {
		return nil
	}
	c := op.cursor
	if c.exportState == nil {
		c.lifetime.RUnlock()
		return nil
	}
	return c
}

// LimitsV1 returns the active source ceilings, or ErrUnavailableV1 after expiry.
func (op *SourceOperationV1) LimitsV1() (SourceLimitsV1, error) {
	c := op.pin()
	if c == nil {
		return SourceLimitsV1{}, ErrUnavailableV1
	}
	defer c.lifetime.RUnlock()
	return c.limits, nil
}

// WithBackingV1 admits one synchronous delivery from bounded, disjoint allocations before calling use.
func (op *SourceOperationV1) WithBackingV1(origins []SourceOriginV1, views []SourceViewV1, use func() error) error {
	c := op.pin()
	if c == nil {
		return ErrUnavailableV1
	}
	defer c.lifetime.RUnlock()
	var charge uint64
	err := c.update(func(s *exportState) error {
		if s.used || use == nil {
			return ErrIntegrityV1
		}
		s.used = true
		var err error
		charge, err = backingBytes(s.manifest, origins, views)
		if charge > s.limits.RAM-s.limits.WorkingBytesV1()-s.limits.retainedRAM() {
			return ErrCapacityV1
		}
		return err
	})
	if err != nil {
		return err
	}
	return c.settle(c.account.WithReservation(charge, func() error {
		c.active.Store(true)
		defer func() {
			c.delivery.Lock()
			c.active.Store(false)
			c.delivery.Unlock()
		}()
		return use()
	}))
}

// update changes a live cursor only while it has no recorded failure.
func (c *exportCursor) update(change func(*exportState) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.exportState == nil:
		return ErrUnavailableV1
	case c.failure == nil:
		c.failure = change(c.exportState)
	}
	return c.failure
}

func (c *exportCursor) settle(err error) error {
	return c.update(func(*exportState) error { return err })
}

func (o *SourceOwnerV1) export(account *mdbx.OperationAccount, m SourceManifestV1, producer SourceExporterV1, visit func(SourcePartV1) error) (result error) {
	if producer == nil || visit == nil {
		return ErrIntegrityV1
	}
	cursor := &exportCursor{exportState: &exportState{manifest: m, account: account, limits: o.limits, visit: visit}}
	defer cursor.finish(&result)
	return producer(&SourceOperationV1{cursor}, cursor.part)
}

func (c *exportCursor) part(part SourcePartV1) error {
	if !c.delivery.TryLock() {
		return c.settle(ErrIntegrityV1)
	}
	defer c.delivery.Unlock()
	var visit func(SourcePartV1) error
	err := c.update(func(s *exportState) error {
		parts := s.manifest.Parts
		if !s.active.Load() || len(parts) == 0 || part.ReadAt == nil || parts[0] != (SourcePartSpecV1{Kind: part.Kind, Length: part.Length}) {
			return ErrIntegrityV1
		}
		visit, s.manifest.Parts = s.visit, parts[1:]
		return nil
	})
	if err != nil {
		return err
	}
	return c.settle(visitPart(part, func(scoped SourcePartV1) error {
		defer c.preservePanic()
		return c.settle(visit(scoped))
	}))
}

func (c *exportCursor) preservePanic() {
	if value := recover(); value != nil {
		c.mu.Lock()
		c.panicked = value
		c.failure = cmp.Or(c.failure, ErrIntegrityV1)
		c.mu.Unlock()
		panic(value) //nolint:forbidigo // Propagate the original visitor panic.
	}
}

// finish drains admitted backing, settles the first failure and invalidates the cursor.
func (c *exportCursor) finish(result *error) {
	c.lifetime.Lock()
	defer c.lifetime.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.exportState
	c.exportState = nil
	*result = cmp.Or(s.failure, *result)
	if *result == nil && len(s.manifest.Parts) != 0 {
		*result = ErrIntegrityV1
	}
	if s.panicked != nil {
		panic(s.panicked) //nolint:forbidigo // Propagate the original visitor panic.
	}
}

// WithSourceExportV1 holds source authority during export and expires readers and callbacks on exit.
func (o *SourceOwnerV1) WithSourceExportV1(account *mdbx.OperationAccount, m SourceManifestV1, producer SourceExporterV1, visit func(SourcePartV1) error) error {
	return o.withManifest(account, m, false, func(_ *sourceRoot, admitted SourceManifestV1, _ uint64) error {
		return o.export(account, admitted, producer, visit)
	})
}

func (o *SourceOwnerV1) withManifest(account *mdbx.OperationAccount, m SourceManifestV1, preparing bool, use func(*sourceRoot, SourceManifestV1, uint64) error) error {
	return o.operation(account, func() error {
		size, err := m.SizeV1()
		if err != nil {
			return err
		}
		if preparing && o.release != nil {
			return ErrBusyV1
		}
		if !o.manifestFits(m, size) {
			return ErrCapacityV1
		}
		m.Parts = slices.Clone(m.Parts)
		return o.withRoot(o.bindRoot, func(r *sourceRoot) error { return use(r, m, size) })
	})
}

func (o *SourceOwnerV1) manifestFits(m SourceManifestV1, size uint64) bool {
	return size <= o.limits.Bytes && uint64(len(m.Parts))*3+o.limits.Files*2+2 <= o.limits.Scans
}

func copyPart(part SourcePartV1, dst io.Writer, scratch []byte) error {
	for offset := uint64(0); offset < part.Length; {
		n := min(uint64(len(scratch)), part.Length-offset)
		chunk := scratch[:n]
		if err := readPartAt(part, chunk, offset); err != nil {
			return err
		}
		if _, err := dst.Write(chunk); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

// readPartAt accepts a full final read accompanied by EOF.
func readPartAt(part SourcePartV1, dst []byte, offset uint64) error {
	n, err := part.ReadAt(dst, int64(min(offset, math.MaxInt64)))
	if n != len(dst) || err != nil && (err != io.EOF || uint64(n) != part.Length-offset) {
		return ErrIntegrityV1
	}
	return nil
}
