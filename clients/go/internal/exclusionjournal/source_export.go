package exclusionjournal

import (
	"io"
	"math"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// SourceExporterV1 visits each original immutable part synchronously, in manifest order.
type SourceExporterV1 func(operation *SourceOperationV1, visit func(SourcePartV1) error) error

// SourceOperationV1 bounds synchronous source backing on the live operation account.
type SourceOperationV1 struct{ cursor *exportCursor }

// SourceOriginV1 describes either a complete immutable allocation or the exact size of a new allocation after admission.
type SourceOriginV1 struct {
	Bytes        []byte
	PlannedBytes uint64
}

// SourceViewV1 names a range in an origin. Origin -1 names an empty part.
type SourceViewV1 struct {
	Origin         int
	Offset, Length uint64
}

// SourcePartV1 is an exact bounded part. ReadAt is valid only during its visitor call.
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
	if v.Length != expected {
		return false
	}
	if v.Origin == -1 {
		return v == SourceViewV1{Origin: -1}
	}
	if v.Origin < 0 || v.Origin >= len(origins) {
		return false
	}
	length := origins[v.Origin].length()
	return v.Offset <= length && v.Length <= length-v.Offset
}

func (o SourceOriginV1) length() uint64 { return max(uint64(len(o.Bytes)), o.PlannedBytes) }

func (o SourceOriginV1) valid(previous []SourceOriginV1) bool {
	if o.PlannedBytes != 0 {
		return o.Bytes == nil && o.PlannedBytes <= math.MaxInt
	}
	start := uint64(reflect.ValueOf(o.Bytes).Pointer())
	length := uint64(len(o.Bytes))
	return length != 0 && len(o.Bytes) == cap(o.Bytes) && length <= math.MaxUint64-start && !overlapsOrigin(start, start+length, previous)
}

func overlapsOrigin(start, end uint64, origins []SourceOriginV1) bool {
	for _, origin := range origins {
		other := uint64(reflect.ValueOf(origin.Bytes).Pointer())
		if start < other+uint64(len(origin.Bytes)) && other < end {
			return true
		}
	}
	return false
}

type exportCursor struct {
	mu       sync.Mutex
	delivery sync.Mutex
	manifest SourceManifestV1
	account  *mdbx.OperationAccount
	limits   SourceLimitsV1
	visit    func(SourcePartV1) error
	done     chan struct{}
	active   bool
	sealed   bool
	next     int
	failure  error
	panicked any
}

// LimitsV1 returns the active source ceilings or refuses after expiry.
func (op *SourceOperationV1) LimitsV1() (SourceLimitsV1, error) {
	if op == nil || op.cursor == nil {
		return SourceLimitsV1{}, ErrUnavailableV1
	}
	c := op.cursor
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sealed {
		return SourceLimitsV1{}, ErrUnavailableV1
	}
	return c.limits, nil
}

// WithBackingV1 funds one synchronous delivery from complete disjoint immutable allocations with exact part views.
func (op *SourceOperationV1) WithBackingV1(origins []SourceOriginV1, views []SourceViewV1, use func() error) error {
	if op == nil || op.cursor == nil {
		return ErrUnavailableV1
	}
	c := op.cursor
	charge, err := c.beginBacking(origins, views, use)
	if err != nil {
		return err
	}
	defer close(c.done)
	err = c.account.WithReservation(charge, func() error {
		c.mu.Lock()
		c.active = true
		c.mu.Unlock()
		defer func() {
			c.delivery.Lock()
			defer c.delivery.Unlock()
			c.mu.Lock()
			c.active = false
			c.mu.Unlock()
		}()
		return use()
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fail(err)
}

func (c *exportCursor) beginBacking(origins []SourceOriginV1, views []SourceViewV1, use func() error) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.sealed:
		return 0, ErrUnavailableV1
	case c.failure != nil:
		return 0, c.failure
	case c.done != nil, use == nil:
		return 0, c.fail(ErrIntegrityV1)
	}
	charge, err := backingBytes(c.manifest, origins, views)
	if err == nil && charge > c.limits.RAM-c.limits.WorkingBytesV1()-c.limits.retainedRAM() {
		err = ErrCapacityV1
	}
	if err != nil {
		return 0, c.fail(err)
	}
	c.done = make(chan struct{})
	return charge, nil
}

func (c *exportCursor) fail(err error) error {
	if c.failure == nil {
		c.failure = err
	}
	return c.failure
}

func (o *SourceOwnerV1) export(account *mdbx.OperationAccount, m SourceManifestV1, producer SourceExporterV1, visit func(SourcePartV1) error) error {
	if producer == nil || visit == nil {
		return ErrIntegrityV1
	}
	cursor := &exportCursor{manifest: m, account: account, limits: o.limits, visit: visit}
	defer cursor.expire()
	return cursor.result(producer(&SourceOperationV1{cursor}, cursor.part))
}

func (c *exportCursor) part(part SourcePartV1) error {
	if !c.delivery.TryLock() {
		return c.partResult(ErrIntegrityV1)
	}
	defer c.delivery.Unlock()
	visit, err := c.acceptPart(part)
	if err != nil {
		return err
	}
	err = visitPart(part, func(scoped SourcePartV1) error {
		defer c.preservePanic()
		return c.partResult(visit(scoped))
	})
	return c.partResult(err)
}

// preservePanic keeps the visitor's panic observable if the producer recovers it.
func (c *exportCursor) preservePanic() {
	if value := recover(); value != nil {
		c.mu.Lock()
		c.panicked = value
		_ = c.fail(ErrIntegrityV1)
		c.mu.Unlock()
		panic(value) //nolint:forbidigo // Propagate the original visitor panic.
	}
}

func (c *exportCursor) partResult(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visit == nil {
		return ErrUnavailableV1
	}
	return c.fail(err)
}

func (c *exportCursor) acceptPart(part SourcePartV1) (func(SourcePartV1) error, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.visit == nil {
		return nil, ErrUnavailableV1
	}
	if c.failure != nil {
		return nil, c.failure
	}
	if !c.active || c.next >= len(c.manifest.Parts) || part.ReadAt == nil {
		return nil, c.fail(ErrIntegrityV1)
	}
	actual := SourcePartSpecV1{Kind: part.Kind, Length: part.Length}
	if actual != c.manifest.Parts[c.next] {
		return nil, c.fail(ErrIntegrityV1)
	}
	c.next++
	return c.visit, nil
}

func (c *exportCursor) result(err error) error {
	c.waitBacking()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.panicked != nil {
		panic(c.panicked) //nolint:forbidigo // Propagate the original visitor panic.
	}
	if c.failure != nil {
		return c.failure
	}
	if err != nil {
		return err
	}
	if c.next != len(c.manifest.Parts) {
		return ErrIntegrityV1
	}
	return nil
}

func (c *exportCursor) expire() {
	c.waitBacking()
	c.mu.Lock()
	c.visit = nil
	c.account = nil
	c.manifest = SourceManifestV1{}
	c.failure = nil
	c.panicked = nil
	c.next = 0
	c.mu.Unlock()
}

func (c *exportCursor) waitBacking() {
	c.mu.Lock()
	c.sealed = true
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
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
		r, err := o.root(false)
		if err != nil {
			return err
		}
		defer r.Close()
		return use(r, m, size)
	})
}

func (o *SourceOwnerV1) manifestFits(m SourceManifestV1, size uint64) bool {
	return size <= o.limits.Bytes && uint64(len(m.Parts))*3+o.limits.Files*2+2 <= o.limits.Scans
}

func copyPart(part SourcePartV1, dst io.Writer, scratch []byte) error {
	for offset := uint64(0); offset < part.Length; {
		n := min(uint64(len(scratch)), part.Length-offset)
		chunk := scratch[:n]
		read, err := part.ReadAt(chunk, int64(offset))
		if read != len(chunk) || err != nil {
			return ErrIntegrityV1
		}
		if _, err := dst.Write(chunk); err != nil {
			return err
		}
		offset += n
	}
	return nil
}
