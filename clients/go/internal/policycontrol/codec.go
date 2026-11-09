// Package policycontrol is the dormant installation/network policy control P of
// RUBIN_MEMPOOL_POLICY.md Section 6.4.1.8: one immutably identified journal changed
// only by exclusive atomic durable transactions with a checked sequence and one
// last receipt. Its file layout is client-local; decode accepts exactly what encode produces.
package policycontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
)

// Profile is the client-local storage profile token; ProfileV1 is the one supported.
type Profile uint8

const ProfileV1 Profile = 1

// Identity is the immutable installation/network identity and profile of P.
type Identity struct {
	InstallationID, ChainID, GenesisHash [32]byte
	Profile                              Profile
}

func (id Identity) valid() bool {
	var z [32]byte
	return id.InstallationID != z && id.ChainID != z && id.GenesisHash != z && id.Profile == ProfileV1
}

type OwnerKind uint8

const (
	OwnerlessControl OwnerKind = iota + 1
	OwnerOrdinaryRecovery
	OwnerH1
	OwnerGenericManual
	OwnerOrdinaryRestoration
	OwnerPendingNativeDisposition
)

type OpClass uint8

const (
	ClassControl OpClass = iota + 1
	ClassReserveArm
	ClassCapture
	ClassPromoteTransfer
	ClassRelease
	ClassReconciliationBatch
	ClassCompoundControl
)

type Owner struct {
	Kind   OwnerKind
	Epoch  uint64
	Intent []byte
}

type Cursors struct{ Before, After uint64 }

// Receipt is the one last-commit receipt: no history and no proof of any affected row.
type Receipt struct {
	Predecessor, Successor uint64
	Operation              [32]byte
	Owner                  Owner
	Class                  OpClass
	Ordinal                uint64
	Cursors                *Cursors // nil: no batch participated (distinct from zero)
}

type IncidentState uint8

const (
	StateObserved IncidentState = iota + 1
	StateIntent
	StateAutoBlocked
)

// ReplaySource is the explicit admitted source; GENESIS_REPLAY is its only value.
type ReplaySource uint8

const SourceGenesisReplay ReplaySource = 1

// Diagnosis is the immutable first-invalid B, error, source and original L/T provenance.
type Diagnosis struct {
	Height                 uint64
	Hash                   [32]byte
	Error, Source, Trigger []byte
}

// Admission is the exact intent of an INTENT or AUTO_BLOCKED incident.
type Admission struct {
	Old, Destination []byte
	Source           ReplaySource
	Profile          Profile
	Ownership        []byte
}

type Incident struct {
	Diagnosis Diagnosis
	Attempted bool
	State     IncidentState
	Admission *Admission // nil exactly when State is StateObserved
}

type RowKind uint8

const (
	KindOriginalRejection RowKind = iota + 1
	KindRecoveryCoreImpossible
	KindContext
	KindCorrectiveAcceptance
	KindReservation
	KindAudit
	KindDisposition
	KindWorkingReservation
)

// Row is one journal member; payload semantics belong to the journal producer.
type Row struct {
	Kind     RowKind
	Key      []byte
	Sequence uint64
	Payload  []byte
}

// Logical bounds (Section 6.4.1.4) and client-local physical ceilings.
const (
	MaxLastingSlots   = 65536
	MaxContexts       = 1024
	MaxReservations   = 65536 // client-local; reservations count in neither logical bound
	MaxKeyBytes       = 64
	MaxPayloadBytes   = 512
	MaxFieldBytes     = 1024
	MaxIntentBytes    = 256
	MaxIncidentHeight = 4294967295

	magic         = "RBNPCTL\x01"
	maxRows       = MaxLastingSlots + MaxContexts + MaxReservations + 1
	minRowBytes   = 1 + 2 + 8 + 2
	maxImageBytes = 1<<16 + maxRows*(minRowBytes+MaxKeyBytes+MaxPayloadBytes)
)

var (
	ErrMissingControl   = errors.New("policycontrol: missing policy control")           // absent P, no positive proof used
	ErrIntegrity        = errors.New("policycontrol: policy control integrity failure") // malformed or mismatched P
	ErrIdentityMismatch = errors.New("policycontrol: policy control identity mismatch")
	ErrUnreadable       = errors.New("policycontrol: policy control unreadable") // path, lock or bytes unqualified
	ErrRefused          = errors.New("policycontrol: refused before effects")
	ErrBusy             = errors.New("policycontrol: concurrency refusal") // the immediate concurrency result
	ErrUnresolved       = errors.New("policycontrol: attempted transaction unresolved")
	ErrStaleLocalPlan   = errors.New("policycontrol: STALE_LOCAL_PLAN") // OLD retained; qualify afresh
	ErrContradiction    = errors.New("policycontrol: incident control contradiction")
	ErrNoRequest        = errors.New("policycontrol: no latch request")
	ErrFinished         = errors.New("policycontrol: transaction finished")
	ErrClosed           = errors.New("policycontrol: store closed")
)

type control struct {
	sequence                uint64 // committing P sequence of the control record; 0 only while initial
	initialSync, hasAttempt bool
	incident                *Incident
}

type state struct {
	id      Identity
	seq     uint64
	receipt *Receipt
	ctl     control
	rows    map[string]Row
}

func rowID(kind RowKind, key []byte) string { return string(append([]byte{byte(kind)}, key...)) }

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return bytes.Clone(b)
}

func operationID(id Identity, successor uint64) [32]byte {
	b := append([]byte("rubin/policycontrol/operation/v1"), id.InstallationID[:]...)
	b = append(append(append(b, id.ChainID[:]...), id.GenesisHash[:]...), byte(id.Profile))
	return sha256.Sum256(binary.BigEndian.AppendUint64(b, successor))
}

func (c control) initial() bool {
	return c.sequence == 0 && !c.initialSync && !c.hasAttempt && c.incident == nil
}

func (c control) clone() control {
	c.incident = c.incident.clone()
	return c
}

func (c control) equal(o control) bool {
	return c.initialSync == o.initialSync && c.hasAttempt == o.hasAttempt && bytes.Equal(incidentBytes(c.incident), incidentBytes(o.incident))
}

func (in *Incident) clone() *Incident {
	if in == nil {
		return nil
	}
	out := *in
	d := &out.Diagnosis
	d.Error, d.Source, d.Trigger = clone(d.Error), clone(d.Source), clone(d.Trigger)
	if a := in.Admission; a != nil {
		out.Admission = &Admission{clone(a.Old), clone(a.Destination), a.Source, a.Profile, clone(a.Ownership)}
	}
	return &out
}

func badField(b []byte) bool   { return len(b) == 0 || len(b) > MaxFieldBytes }
func fields(bs ...[]byte) bool { return !slices.ContainsFunc(bs, badField) }

func refused(what string) error { return fmt.Errorf("%w: %s", ErrRefused, what) }

func validDiagnosis(d Diagnosis) error {
	if d.Height > MaxIncidentHeight || !fields(d.Error, d.Source, d.Trigger) {
		return refused("incident diagnosis outside its domain")
	}
	return nil
}

func validAdmission(a *Admission) error {
	if a == nil || !fields(a.Old, a.Destination, a.Ownership) || bytes.Equal(a.Old, a.Destination) ||
		a.Source != SourceGenesisReplay || a.Profile != ProfileV1 {
		return refused("incident admission outside its domain")
	}
	return nil
}

func (st IncidentState) admitted() bool { return st == StateIntent || st == StateAutoBlocked }

func validateIncident(in *Incident, hasAttempt bool) error {
	if err := validDiagnosis(in.Diagnosis); err != nil {
		return err
	}
	if in.Attempted && !hasAttempt {
		return errors.New("attempted incident without has_attempt")
	}
	switch {
	case in.State == StateObserved && in.Admission == nil:
		return nil
	case in.State.admitted() && in.Attempted:
		return validAdmission(in.Admission)
	}
	return errors.New("incident state, attempted bit or destination outside its domain")
}

func (o Owner) ownedAt(seq uint64) bool {
	return o.Epoch != 0 && o.Epoch <= seq && len(o.Intent) != 0 && len(o.Intent) <= MaxIntentBytes
}

func validateReceiptOwner(o Owner, seq uint64) error {
	switch {
	case o.Kind < OwnerlessControl || o.Kind > OwnerPendingNativeDisposition:
		return errors.New("unknown owner kind")
	case o.Kind == OwnerlessControl && (o.Epoch != seq || len(o.Intent) != 0):
		return errors.New("ownerless control receipt needs epoch n+1 and empty intent")
	case o.Kind != OwnerlessControl && !o.ownedAt(seq):
		return errors.New("owned receipt epoch or intent outside its domain")
	}
	return nil
}

func validateReceiptOperation(r *Receipt) error {
	switch {
	case r.Class < ClassControl || r.Class > ClassCompoundControl:
		return errors.New("unknown operation class")
	case (r.Class == ClassReconciliationBatch) != (r.Cursors != nil) && r.Class != ClassCompoundControl:
		return errors.New("cursor presence disagrees with batch participation")
	case r.Class == ClassCompoundControl && r.Ordinal != 0:
		return errors.New("compound control receipt needs ordinal 0")
	}
	return nil
}

func validateReceipt(id Identity, seq uint64, r *Receipt) error {
	if r.Successor != seq || r.Predecessor != seq-1 || r.Operation != operationID(id, seq) {
		return errors.New("receipt is not bound to this journal and successor")
	}
	if err := validateReceiptOwner(r.Owner, seq); err != nil {
		return err
	}
	return validateReceiptOperation(r)
}

var rowBound = map[RowKind]int{KindContext: 1, KindReservation: 2, KindWorkingReservation: 3}

// countRows returns lasting slots, contexts, reservations and working reservations.
func countRows(rows map[string]Row) (n [4]int) {
	for _, r := range rows {
		n[rowBound[r.Kind]]++
	}
	return n
}

func validateControl(st *state) error {
	if st.ctl.sequence > st.seq || (st.ctl.sequence == 0) != st.ctl.initial() {
		return errors.New("control committing sequence outside its domain")
	}
	if st.ctl.incident == nil {
		return nil
	}
	return validateIncident(st.ctl.incident, st.ctl.hasAttempt)
}

func (r Row) domainValid(seq uint64) bool {
	return r.Kind >= KindOriginalRejection && r.Kind <= KindWorkingReservation && len(r.Key) <= MaxKeyBytes &&
		len(r.Payload) <= MaxPayloadBytes && r.Sequence != 0 && r.Sequence <= seq
}

func validateRows(st *state) error {
	for id, r := range st.rows {
		if !r.domainValid(st.seq) || id != rowID(r.Kind, r.Key) {
			return errors.New("journal row outside its domain")
		}
	}
	if n := countRows(st.rows); n[0] > MaxLastingSlots || n[1] > MaxContexts || n[2] > MaxReservations || n[3] > 1 {
		return errors.New("journal membership exceeds its bounds")
	}
	return nil
}

func (st *state) initialEmpty() bool {
	return st.receipt == nil && st.ctl.initial() && len(st.rows) == 0
}

func validateState(st *state) error {
	if !st.id.valid() {
		return errors.New("identity or profile outside its domain")
	}
	if st.seq == 0 {
		if !st.initialEmpty() {
			return errors.New("sequence 0 must hold the initial empty state")
		}
		return nil
	}
	if st.receipt == nil {
		return errors.New("missing receipt")
	}
	if err := validateReceipt(st.id, st.seq, st.receipt); err != nil {
		return err
	}
	if err := validateControl(st); err != nil {
		return err
	}
	return validateRows(st)
}

// coder appends when encoding and strictly consumes when decoding, checking each
// length against its ceiling and the remaining input before allocating.
type coder struct {
	dec bool
	b   []byte
	err error
}

func (c *coder) fail(msg string) {
	if c.err == nil {
		c.err = errors.New(msg)
	}
}

func (c *coder) raw(vs ...[]byte) {
	for _, v := range vs {
		switch {
		case !c.dec:
			c.b = append(c.b, v...)
		case len(v) > len(c.b):
			c.fail("truncated image")
		case c.err == nil:
			copy(v, c.b)
			c.b = c.b[len(v):]
		}
	}
}

func (c *coder) u8s(vs ...*uint8) {
	for _, v := range vs {
		buf := []byte{*v}
		if c.raw(buf); c.dec {
			*v = buf[0]
		}
	}
}

func (c *coder) u64s(vs ...*uint64) {
	for _, v := range vs {
		buf := binary.BigEndian.AppendUint64(nil, *v)
		if c.raw(buf); c.dec {
			*v = binary.BigEndian.Uint64(buf)
		}
	}
}

func (c *coder) flag(v bool) bool {
	u := uint8(0)
	if v {
		u = 1
	}
	if c.u8s(&u); u > 1 {
		c.fail("non-canonical boolean or presence tag")
	}
	return u == 1 && c.err == nil
}

func (c *coder) bools(vs ...*bool) {
	for _, v := range vs {
		if f := c.flag(*v); c.dec {
			*v = f
		}
	}
}

func (c *coder) field(limit int, v *[]byte) {
	n := len(*v)
	if n > math.MaxUint16 || (!c.dec && n > limit) {
		c.fail("field above its ceiling")
		return
	}
	buf := binary.BigEndian.AppendUint16(nil, uint16(n))
	c.raw(buf)
	if !c.dec {
		c.b = append(c.b, *v...)
		return
	}
	if n = int(binary.BigEndian.Uint16(buf)); n > limit || n > len(c.b) {
		c.fail("length above its ceiling or the remaining input")
	} else if c.err == nil {
		*v, c.b = clone(c.b[:n]), c.b[n:]
	}
}

func (c *coder) bytes(limit int, vs ...*[]byte) {
	for _, v := range vs {
		c.field(limit, v)
	}
}

func present[T any](c *coder, p **T) bool {
	if !c.flag(*p != nil) {
		return false
	}
	if *p == nil {
		*p = new(T)
	}
	return true
}

func (c *coder) incident(p **Incident) {
	if !present(c, p) {
		return
	}
	in, d := *p, &(*p).Diagnosis
	c.u64s(&d.Height)
	c.raw(d.Hash[:])
	c.bytes(MaxFieldBytes, &d.Error, &d.Source, &d.Trigger)
	c.bools(&in.Attempted)
	c.u8s((*uint8)(&in.State))
	if present(c, &in.Admission) {
		a := in.Admission
		c.bytes(MaxFieldBytes, &a.Old, &a.Destination)
		c.u8s((*uint8)(&a.Source), (*uint8)(&a.Profile))
		c.bytes(MaxFieldBytes, &a.Ownership)
	}
}

func (c *coder) image(st *state) {
	m := []byte(magic)
	if c.raw(m); string(m) != magic {
		c.fail("bad magic")
	}
	c.raw(st.id.InstallationID[:], st.id.ChainID[:], st.id.GenesisHash[:])
	c.u8s((*uint8)(&st.id.Profile))
	c.u64s(&st.seq)
	if present(c, &st.receipt) {
		r := st.receipt
		c.u64s(&r.Predecessor, &r.Successor)
		c.raw(r.Operation[:])
		c.u8s((*uint8)(&r.Owner.Kind))
		c.u64s(&r.Owner.Epoch)
		c.bytes(MaxIntentBytes, &r.Owner.Intent)
		c.u8s((*uint8)(&r.Class))
		c.u64s(&r.Ordinal)
		if present(c, &r.Cursors) {
			c.u64s(&r.Cursors.Before, &r.Cursors.After)
		}
	}
	c.u64s(&st.ctl.sequence)
	c.bools(&st.ctl.initialSync, &st.ctl.hasAttempt)
	c.incident(&st.ctl.incident)
	c.rows(st)
}

func (c *coder) rowCount(st *state, ids []string) uint64 {
	n := uint64(len(ids))
	if c.u64s(&n); c.dec && (n > maxRows || n*minRowBytes > uint64(len(c.b))) {
		c.fail("row count above its ceiling or the remaining input")
	}
	if c.dec && c.err == nil {
		st.rows = make(map[string]Row, n)
	}
	return n
}

func (c *coder) decodedRow(st *state, r Row, prev string) string {
	if c.err != nil {
		return prev
	}
	id := rowID(r.Kind, r.Key)
	if prev != "" && id <= prev {
		c.fail("rows not strictly ordered by kind and key")
	}
	st.rows[id] = r
	return id
}

func (c *coder) rows(st *state) {
	ids := sortedRowIDs(st.rows)
	n := c.rowCount(st, ids)
	for i, prev := uint64(0), ""; c.err == nil && i < n; i++ {
		var r Row
		if !c.dec {
			r = st.rows[ids[i]]
		}
		c.u8s((*uint8)(&r.Kind))
		c.bytes(MaxKeyBytes, &r.Key)
		c.u64s(&r.Sequence)
		c.bytes(MaxPayloadBytes, &r.Payload)
		if c.dec {
			prev = c.decodedRow(st, r, prev)
		}
	}
}

func sortedRowIDs(rows map[string]Row) []string { return slices.Sorted(maps.Keys(rows)) }

// encode returns the canonical image, or nil when a field exceeds its ceiling.
func encode(st *state) []byte {
	c := &coder{}
	if c.image(st); c.err != nil {
		return nil
	}
	return c.b
}

func incidentBytes(in *Incident) []byte {
	c := &coder{}
	c.incident(&in)
	return c.b
}

// decode strictly parses one canonical P image; every failure wraps only ErrIntegrity.
func decode(b []byte) (*state, error) {
	c, st := &coder{dec: true, b: b}, &state{}
	if c.image(st); len(c.b) != 0 {
		c.fail("trailing bytes")
	}
	if c.err == nil {
		c.err = validateState(st)
	}
	if c.err != nil {
		return nil, fmt.Errorf("%w: %s", ErrIntegrity, c.err.Error())
	}
	return st, nil
}
