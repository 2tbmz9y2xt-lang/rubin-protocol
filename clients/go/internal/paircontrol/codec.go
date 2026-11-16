// Package paircontrol owns dormant installation-local outer intent and retirement data.
package paircontrol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path"
	"strings"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/policycontrol"
)

const maxImageV1 = 16384

const (
	maxLocationV1 = 768
	maxBasenameV1 = 255
)

// IdentityV1 binds the aggregate to P's installation/network and a caller-qualified root.
type IdentityV1 struct {
	policycontrol.Identity
	DatabaseRoot string
}

// DatabaseLocationV1 stores an absolute location (1) or root-relative basename (2).
type DatabaseLocationV1 struct {
	Form       uint8
	Location   string
	DatabaseID [32]byte
}

// PairBindingV1 is identity data, not native pair qualification.
type PairBindingV1 struct {
	Database                                            DatabaseLocationV1
	CurrentGeneration, LagGeneration, AuthoritySequence uint64
}

// ReferenceV1 copies opaque producer-owned backing identity, without acquiring its lifetime.
type ReferenceV1 struct {
	OwnerID [32]byte
	Opaque  []byte
}

// RetirementV1 preserves the unavailable original pair and its original result.
type RetirementV1 struct {
	Old    PairBindingV1
	Reason uint8
	Result ReferenceV1
}

// H1BindingV1 preserves the complete original semantic admission and its P observation.
type H1BindingV1 struct {
	OwnerEpoch, ObservedPSequence uint64
	OwnerIntent                   [32]byte
	Diagnosis                     policycontrol.Diagnosis
	Admission                     policycontrol.Admission
}

// IntentV1 is one exact replacement request; origins 1/2/3 mean ECONOMY/RETAINED_OLD/H1.
type IntentV1 struct {
	ID                                       [32]byte
	Origin, Source, LAG                      uint8
	Destination                              DatabaseLocationV1
	Old                                      *PairBindingV1
	SourceRef                                ReferenceV1
	ComparandRef, AssuranceRef, LAGSourceRef *ReferenceV1
	H1Binding                                *H1BindingV1
}

// RecordV1 is an owned snapshot; selector 1/2/3 means FIRST_INSTALL_NONE/SELECTED/RETIRED.
type RecordV1 struct {
	Identity IdentityV1
	Sequence uint64
	Selector uint8
	Selected *PairBindingV1
	Retired  *RetirementV1
	Intent   *IntentV1
}

var errShapeV1 = errors.New("paircontrol: invalid closed value")

// absoluteV1 validates a bounded canonical POSIX path without resolving it.
func absoluteV1(s string) bool {
	return len(s) > 0 && len(s) <= maxLocationV1 && path.IsAbs(s) && path.Clean(s) == s && !strings.ContainsRune(s, 0)
}

// identityValidV1 checks stored identity data without comparing an ambient installation.
func identityValidV1(id IdentityV1) bool {
	return id.InstallationID != [32]byte{} && id.ChainID != [32]byte{} && id.GenesisHash != [32]byte{} && id.Profile == 1 && absoluteV1(id.DatabaseRoot)
}

// locationValidV1 owns the closed form/path/database-ID domain.
func locationValidV1(v DatabaseLocationV1) bool {
	switch v.Form {
	case 1:
		return v.DatabaseID != [32]byte{} && absoluteV1(v.Location)
	case 2:
		return v.DatabaseID != [32]byte{} && basenameV1(v.Location)
	default:
		return false
	}
}

// basenameV1 validates the bounded single root-relative component domain.
func basenameV1(s string) bool {
	return len(s) > 0 && len(s) <= maxBasenameV1 && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00") && path.Clean(s) == s
}

// EncodeDatabaseLocationV1 produces the canonical private location leaf.
func EncodeDatabaseLocationV1(v DatabaseLocationV1) ([]byte, error) {
	if !locationValidV1(v) {
		return nil, errShapeV1
	}
	c := wireV1{}
	c.location(&v)
	return c.b, c.err
}

// DecodeDatabaseLocationV1 accepts exactly one complete canonical leaf and owns its backing.
func DecodeDatabaseLocationV1(b []byte) (DatabaseLocationV1, error) {
	v := DatabaseLocationV1{}
	if len(b) > 803 {
		return v, errShapeV1
	}
	c := wireV1{b: b, reading: true}
	c.location(&v)
	if !locationValidV1(v) {
		c.err = errShapeV1
	}
	return v, c.finish()
}

// EncodeH1OwnershipV1 binds the actual semantic admitting epoch and nonzero intent.
func EncodeH1OwnershipV1(epoch uint64, intent [32]byte) ([]byte, error) {
	if epoch == 0 || intent == [32]byte{} {
		return nil, errShapeV1
	}
	b := make([]byte, 40)
	binary.BigEndian.PutUint64(b, epoch)
	copy(b[8:], intent[:])
	return b, nil
}

// wireV1 walks one finite grammar in either direction; every variable field is bounded before copying.
type wireV1 struct {
	b          []byte
	at         int
	reading    bool
	validating bool
	err        error
}

// fixed copies one fixed-width field or visits it during preflight.
func (c *wireV1) fixed(v []byte) {
	if c.err != nil {
		return
	}
	if !c.reading {
		if !c.validating {
			c.b = append(c.b, v...)
		}
		return
	}
	if len(v) > len(c.b)-c.at {
		c.err = errShapeV1
		return
	}
	copy(v, c.b[c.at:c.at+len(v)])
	c.at += len(v)
}

// tag rejects an unknown discriminator before its payload is visited.
func (c *wireV1) tag(v *uint8, low, high uint8) {
	b := []byte{*v}
	c.fixed(b)
	if c.reading {
		*v = b[0]
	}
	if *v < low || *v > high {
		c.err = errShapeV1
	}
}

// number owns the exact unsigned 64-bit big-endian representation.
func (c *wireV1) number(v *uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], *v)
	c.fixed(b[:])
	if c.reading {
		*v = binary.BigEndian.Uint64(b[:])
	}
}

// field checks width and availability before allocating or copying variable data.
func (c *wireV1) field(v *[]byte, limit int) {
	if c.err != nil {
		return
	}
	if !c.reading && !fieldSizeV1(len(*v), limit) {
		c.err = errShapeV1
		return
	}
	var b [2]byte
	var width uint16
	width, c.err = fieldWidthV1(len(*v))
	binary.BigEndian.PutUint16(b[:], width)
	c.fixed(b[:])
	if c.err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(b[:]))
	if !fieldSizeV1(n, limit) {
		c.err = errShapeV1
		return
	}
	if c.reading {
		if n > len(c.b)-c.at {
			c.err = errShapeV1
			return
		}
		*v = make([]byte, n)
	}
	c.fixed(*v)
}

// fieldSizeV1 owns the nonempty bounded field domain before narrowing or allocation.
func fieldSizeV1(n, limit int) bool {
	return n > 0 && n <= limit
}

// fieldWidthV1 checks only the representation bound before narrowing a field length.
func fieldWidthV1(n int) (uint16, error) {
	if n < 0 || n > 65535 {
		return 0, errShapeV1
	}
	return uint16(n), nil
}

// location walks a bounded leaf using the form-specific length ceiling.
func (c *wireV1) location(v *DatabaseLocationV1) {
	if !c.reading && !locationValidV1(*v) {
		c.err = errShapeV1
		return
	}
	c.tag(&v.Form, 1, 2)
	if c.err != nil {
		return
	}
	n := maxLocationV1
	if v.Form == 2 {
		n = maxBasenameV1
	}
	b := []byte(v.Location)
	c.field(&b, n)
	if c.reading {
		v.Location = string(b)
	}
	c.fixed(v.DatabaseID[:])
	if !locationValidV1(*v) {
		c.err = errShapeV1
	}
}

// pair preserves observed authority data while rejecting invalid generation identities.
func (c *wireV1) pair(v *PairBindingV1) {
	c.location(&v.Database)
	c.number(&v.CurrentGeneration)
	c.number(&v.LagGeneration)
	c.number(&v.AuthoritySequence)
	if v.CurrentGeneration == 0 || v.LagGeneration == 0 || v.CurrentGeneration == v.LagGeneration {
		c.err = errShapeV1
	}
}

// reference copies an exact nonempty reference without acquiring any source lifetime.
func (c *wireV1) reference(v *ReferenceV1) {
	c.fixed(v.OwnerID[:])
	c.field(&v.Opaque, 1024)
	if v.OwnerID == [32]byte{} {
		c.err = errShapeV1
	}
}

// optionalReference owns the closed zero-or-one reference framing.
func (c *wireV1) optionalReference(v **ReferenceV1) {
	p := uint8(0)
	if *v != nil {
		p = 1
	}
	c.tag(&p, 0, 1)
	if c.err != nil || p == 0 {
		return
	}
	if c.reading {
		*v = &ReferenceV1{}
	}
	c.reference(*v)
}

// h1 preserves complete historical P binding data without invoking P operations.
func (c *wireV1) h1(v *H1BindingV1) {
	d, a := &v.Diagnosis, &v.Admission
	c.number(&d.Height)
	c.fixed(d.Hash[:])
	c.number(&v.OwnerEpoch)
	c.fixed(v.OwnerIntent[:])
	c.number(&v.ObservedPSequence)
	c.field(&d.Error, 1024)
	c.field(&d.Source, 1024)
	c.field(&d.Trigger, 1024)
	c.field(&a.Old, 803)
	c.field(&a.Destination, 803)
	source, profile := uint8(a.Source), uint8(a.Profile)
	c.tag(&source, 1, 1)
	c.tag(&profile, 1, 1)
	if c.reading {
		a.Source, a.Profile = policycontrol.ReplaySource(source), policycontrol.Profile(profile)
	}
	c.field(&a.Ownership, 40)
	owner, err := EncodeH1OwnershipV1(v.OwnerEpoch, v.OwnerIntent)
	if err != nil || !bytes.Equal(owner, a.Ownership) || d.Height > 4294967295 {
		c.err = errShapeV1
	}
}

// intent visits the sole replacement payload in its frozen field order.
func (c *wireV1) intent(v *IntentV1) {
	c.fixed(v.ID[:])
	c.tag(&v.Origin, 1, 3)
	c.tag(&v.Source, 1, 2)
	c.tag(&v.LAG, 1, 3)
	if c.err != nil {
		return
	}
	c.location(&v.Destination)
	c.requiredPair(&v.Old)
	c.reference(&v.SourceRef)
	c.optionalReference(&v.ComparandRef)
	c.optionalReference(&v.AssuranceRef)
	c.optionalReference(&v.LAGSourceRef)
	c.optionalH1(&v.H1Binding)
	if !intentShapeV1(v) {
		c.err = errShapeV1
	}
}

// requiredPair owns the intent's mandatory OLD presence and payload.
func (c *wireV1) requiredPair(v **PairBindingV1) {
	p := uint8(0)
	if *v != nil {
		p = 1
	}
	c.tag(&p, 1, 1)
	if c.err != nil {
		return
	}
	if c.reading {
		*v = &PairBindingV1{}
	}
	c.pair(*v)
}

// optionalH1 owns only the zero-or-one H1 payload framing.
func (c *wireV1) optionalH1(v **H1BindingV1) {
	p := uint8(0)
	if *v != nil {
		p = 1
	}
	c.tag(&p, 0, 1)
	if c.err != nil || p == 0 {
		return
	}
	if c.reading {
		*v = &H1BindingV1{}
	}
	c.h1(*v)
}

// intentShapeV1 checks mandatory siblings and delegates the origin-specific relation.
func intentShapeV1(v *IntentV1) bool {
	if v.ID == [32]byte{} || v.Old == nil || v.ComparandRef == nil || v.Destination.Form != 2 {
		return false
	}
	if v.Destination.DatabaseID == v.Old.Database.DatabaseID {
		return false
	}
	if v.Origin == 3 {
		return h1ShapeV1(v)
	}
	if v.H1Binding != nil {
		return false
	}
	return operatorShapeV1(v)
}

// operatorShapeV1 owns the two source-specific LAG/reference combinations.
func operatorShapeV1(v *IntentV1) bool {
	if v.Source == 1 {
		return v.AssuranceRef == nil && replayLAGV1(v)
	}
	return v.Source == 2 && v.LAG == 3 && v.AssuranceRef != nil && v.LAGSourceRef == nil
}

// replayLAGV1 binds replay's rebuilt/reused LAG to its sole permitted reference.
func replayLAGV1(v *IntentV1) bool {
	switch v.LAG {
	case 1:
		return v.LAGSourceRef == nil
	case 2:
		return v.LAGSourceRef != nil
	default:
		return false
	}
}

// h1ShapeV1 compares original admission leaves to the exact OLD/destination data.
func h1ShapeV1(v *IntentV1) bool {
	if !h1ModeV1(v) {
		return false
	}
	old, e1 := EncodeDatabaseLocationV1(v.Old.Database)
	dest, e2 := EncodeDatabaseLocationV1(v.Destination)
	return e1 == nil && e2 == nil && bytes.Equal(old, v.H1Binding.Admission.Old) && bytes.Equal(dest, v.H1Binding.Admission.Destination)
}

// h1ModeV1 owns H1's exact source/LAG and required/forbidden siblings.
func h1ModeV1(v *IntentV1) bool {
	return v.Source == 1 && v.LAG == 1 && v.H1Binding != nil && v.AssuranceRef == nil && v.LAGSourceRef == nil
}

// selector dispatches only the payload owned by its recognized tag.
func (c *wireV1) selector(v *RecordV1) {
	c.tag(&v.Selector, 1, 3)
	if c.err != nil {
		return
	}
	switch v.Selector {
	case 1:
		if v.Selected != nil || v.Retired != nil {
			c.err = errShapeV1
		}
	case 2:
		c.selected(v)
	case 3:
		c.retired(v)
	}
}

// selected owns the selector's exclusive live-pair payload.
func (c *wireV1) selected(v *RecordV1) {
	if c.reading {
		v.Selected = &PairBindingV1{}
	}
	if v.Selected == nil || v.Retired != nil {
		c.err = errShapeV1
		return
	}
	c.pair(v.Selected)
}

// retired owns the selector's exclusive historical pair/reason/result payload.
func (c *wireV1) retired(v *RecordV1) {
	if c.reading {
		v.Retired = &RetirementV1{}
	}
	if v.Retired == nil || v.Selected != nil {
		c.err = errShapeV1
		return
	}
	c.pair(&v.Retired.Old)
	c.tag(&v.Retired.Reason, 1, 3)
	if c.err == nil {
		c.reference(&v.Retired.Result)
	}
}

// header owns the fixed magic, identity and sequence prefix.
func (c *wireV1) header(v *RecordV1) {
	if !c.reading && !identityValidV1(v.Identity) {
		c.err = errShapeV1
		return
	}
	magic := []byte{0x52, 0x42, 0x4e, 0x4f, 0x55, 0x54, 1, 0}
	c.fixed(magic)
	if !bytes.Equal(magic, []byte("RBNOUT\x01\x00")) {
		c.err = errShapeV1
		return
	}
	id := &v.Identity
	c.fixed(id.InstallationID[:])
	c.fixed(id.ChainID[:])
	c.fixed(id.GenesisHash[:])
	p := uint8(id.Profile)
	c.tag(&p, 1, 1)
	if c.reading {
		id.Profile = policycontrol.Profile(p)
	}
	b := []byte(id.DatabaseRoot)
	c.field(&b, maxLocationV1)
	if c.reading {
		id.DatabaseRoot = string(b)
	}
	c.number(&v.Sequence)
}

// record visits the selector and optional intent after the common header.
func (c *wireV1) record(v *RecordV1) {
	c.header(v)
	c.selector(v)
	p := uint8(0)
	if v.Intent != nil {
		p = 1
	}
	c.tag(&p, 0, 1)
	if p == 1 && c.err == nil {
		if c.reading {
			v.Intent = &IntentV1{}
		}
		c.intent(v.Intent)
	}
	if c.err == nil && !recordShapeV1(v) {
		c.err = errShapeV1
	}
}

// recordShapeV1 binds an intent to exact selected/retired OLD without granting service.
func recordShapeV1(v *RecordV1) bool {
	if !identityValidV1(v.Identity) {
		return false
	}
	if v.Intent == nil {
		return true
	}
	if v.Selector == 1 {
		return false
	}
	old := v.Selected
	if v.Selector == 3 {
		old = &v.Retired.Old
		if !retirementOriginV1(v.Retired.Reason, v.Intent.Origin) {
			return false
		}
	}
	return old != nil && v.Intent.Old != nil && *old == *v.Intent.Old
}

// retirementOriginV1 keeps retirement reasons independent of origin numbers.
func retirementOriginV1(reason, origin uint8) bool {
	return reason == 3 || reason == 1 && origin == 1 || reason == 2 && origin == 3
}

// finish rejects trailing bytes and preserves the single unwrapped shape sentinel.
func (c *wireV1) finish() error {
	if len(c.b) > maxImageV1 || c.reading && c.at != len(c.b) {
		return errShapeV1
	}
	return c.err
}

// encodeV1 validates the entire closed value before producing owned image bytes.
func encodeV1(v RecordV1) ([]byte, error) {
	preflight := wireV1{validating: true}
	preflight.record(&v)
	if preflight.err != nil {
		return nil, preflight.err
	}
	c := wireV1{}
	c.record(&v)
	return c.b, c.finish()
}

// decodeV1 bounds the complete image before allocating detached variable fields.
func decodeV1(b []byte) (RecordV1, error) {
	v := RecordV1{}
	if len(b) > maxImageV1 {
		return v, errShapeV1
	}
	c := wireV1{b: b, reading: true}
	c.record(&v)
	return v, c.finish()
}
