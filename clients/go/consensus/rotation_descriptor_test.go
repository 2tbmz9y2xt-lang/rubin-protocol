package consensus

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func assertNativeSuiteIDs(t *testing.T, got *NativeSuiteSet, want []uint8) {
	t.Helper()
	gotIDs := got.SuiteIDs()
	if !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("suite IDs mismatch: got %v want %v", gotIDs, want)
	}
}

func TestCryptoRotationDescriptor_Validate(t *testing.T) {
	// Build a registry with two suites for testing.
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}

	valid := CryptoRotationDescriptor{
		Name:         "test-rotation",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 100,
		SpendHeight:  200,
	}
	if err := valid.Validate(reg); err != nil {
		t.Fatalf("expected valid: %v", err)
	}

	// With sunset.
	withSunset := valid
	withSunset.SunsetHeight = 300
	if err := withSunset.Validate(reg); err != nil {
		t.Fatalf("expected valid with sunset: %v", err)
	}

	cases := []struct {
		name    string
		mod     func(*CryptoRotationDescriptor)
		wantErr string
	}{
		{
			name:    "empty_name",
			mod:     func(d *CryptoRotationDescriptor) { d.Name = "" },
			wantErr: "name required",
		},
		{
			name:    "old_equals_new",
			mod:     func(d *CryptoRotationDescriptor) { d.NewSuiteID = d.OldSuiteID },
			wantErr: "must differ",
		},
		{
			name:    "old_not_registered",
			mod:     func(d *CryptoRotationDescriptor) { d.OldSuiteID = 0xFF },
			wantErr: "old suite 0xff not registered",
		},
		{
			name:    "new_not_registered",
			mod:     func(d *CryptoRotationDescriptor) { d.NewSuiteID = 0xFE },
			wantErr: "new suite 0xfe not registered",
		},
		{
			name:    "create_gte_spend",
			mod:     func(d *CryptoRotationDescriptor) { d.CreateHeight = d.SpendHeight },
			wantErr: "create_height",
		},
		{
			name:    "create_gt_spend",
			mod:     func(d *CryptoRotationDescriptor) { d.CreateHeight = d.SpendHeight + 1 },
			wantErr: "create_height",
		},
		{
			name: "sunset_lte_spend",
			mod: func(d *CryptoRotationDescriptor) {
				d.SunsetHeight = d.SpendHeight
			},
			wantErr: "sunset_height",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := valid
			tc.mod(&d)
			err := d.Validate(reg)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateRotationSet_Overlap(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			0x01: {SuiteID: 0x01, PubkeyLen: 2592, SigLen: 4627},
			0x02: {SuiteID: 0x02, PubkeyLen: 1024, SigLen: 512},
		},
	}

	// Non-overlapping: first completes before second starts.
	noOverlap := []CryptoRotationDescriptor{
		{Name: "rot-1", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 100, SpendHeight: 200},
		{Name: "rot-2", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 200, SpendHeight: 300},
	}
	if err := ValidateRotationSet(noOverlap, reg); err != nil {
		t.Fatalf("expected non-overlapping to pass: %v", err)
	}

	// Overlapping: second starts before first finishes.
	overlap := []CryptoRotationDescriptor{
		{Name: "rot-A", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 100, SpendHeight: 250},
		{Name: "rot-B", OldSuiteID: 0x01, NewSuiteID: 0x02, CreateHeight: 200, SpendHeight: 350},
	}
	err := ValidateRotationSet(overlap, reg)
	if err == nil {
		t.Fatalf("expected overlap error")
	}
	if !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("error %q does not contain 'overlapping'", err.Error())
	}
}

func TestDescriptorRotationProvider_CreateSuites(t *testing.T) {
	d := CryptoRotationDescriptor{
		Name:         "test",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 100,
		SpendHeight:  200,
		SunsetHeight: 300,
	}
	p := DescriptorRotationProvider{Descriptor: d}

	// Before H1: only old.
	s := p.NativeCreateSuites(50)
	if !s.Contains(0x01) || s.Contains(0x02) {
		t.Fatalf("before H1: expected only old suite")
	}

	// At H1: both.
	s = p.NativeCreateSuites(100)
	if !s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("at H1: expected both suites")
	}

	// Between H1 and H2: both.
	s = p.NativeCreateSuites(150)
	if !s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("between H1 and H2: expected both suites")
	}

	// At H2: only new (create cutoff per spec §6 Phase 2).
	s = p.NativeCreateSuites(200)
	if s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("at H2: expected only new suite (create cutoff)")
	}

	// At H4: still only new.
	s = p.NativeCreateSuites(300)
	if s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("at H4: expected only new suite")
	}
}

func TestDescriptorRotationProvider_SpendSuites(t *testing.T) {
	d := CryptoRotationDescriptor{
		Name:         "test",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 100,
		SpendHeight:  200,
		SunsetHeight: 400,
	}
	p := DescriptorRotationProvider{Descriptor: d}

	// Before H1: only old.
	s := p.NativeSpendSuites(50)
	if !s.Contains(0x01) || s.Contains(0x02) {
		t.Fatalf("before H1: expected only old suite for spend")
	}

	// At H1: both (new suite enters spend set at activation).
	s = p.NativeSpendSuites(100)
	if !s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("at H1: expected both suites for spend")
	}

	// Between H1 and H4: both.
	s = p.NativeSpendSuites(250)
	if !s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("between H1 and H4: expected both suites for spend")
	}

	// At H4: only new (sunset per spec §6 Phase 4).
	s = p.NativeSpendSuites(400)
	if s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("at H4: expected only new suite for spend (sunset)")
	}

	// After H4: only new.
	s = p.NativeSpendSuites(999)
	if s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("after H4: expected only new suite for spend")
	}
}

func TestDescriptorRotationProvider_NoSunset(t *testing.T) {
	d := CryptoRotationDescriptor{
		Name:         "no-sunset",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 100,
		SpendHeight:  200,
		SunsetHeight: 0, // no sunset
	}
	p := DescriptorRotationProvider{Descriptor: d}

	// At a very high height without sunset, create returns only new (H2 create cutoff still applies).
	s := p.NativeCreateSuites(999999)
	if s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("no sunset, high height: expected only new suite for create (H2 cutoff)")
	}

	// But spend returns both (no H4 sunset means old never removed from spend).
	s = p.NativeSpendSuites(999999)
	if !s.Contains(0x01) || !s.Contains(0x02) {
		t.Fatalf("no sunset: expected both suites for spend at high height")
	}
}

func TestDescriptorRotationProvider_PhaseBoundaries(t *testing.T) {
	d := CryptoRotationDescriptor{
		Name:         "phase-boundaries",
		OldSuiteID:   0x01,
		NewSuiteID:   0x02,
		CreateHeight: 100,
		SpendHeight:  200,
		SunsetHeight: 300,
	}
	p := DescriptorRotationProvider{Descriptor: d}

	cases := []struct {
		name       string
		height     uint64
		wantCreate []uint8
		wantSpend  []uint8
	}{
		{name: "before_h1", height: 99, wantCreate: []uint8{0x01}, wantSpend: []uint8{0x01}},
		{name: "at_h1", height: 100, wantCreate: []uint8{0x01, 0x02}, wantSpend: []uint8{0x01, 0x02}},
		{name: "before_h2", height: 199, wantCreate: []uint8{0x01, 0x02}, wantSpend: []uint8{0x01, 0x02}},
		{name: "at_h2", height: 200, wantCreate: []uint8{0x02}, wantSpend: []uint8{0x01, 0x02}},
		{name: "before_h4", height: 299, wantCreate: []uint8{0x02}, wantSpend: []uint8{0x01, 0x02}},
		{name: "at_h4", height: 300, wantCreate: []uint8{0x02}, wantSpend: []uint8{0x02}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertNativeSuiteIDs(t, p.NativeCreateSuites(tc.height), tc.wantCreate)
			assertNativeSuiteIDs(t, p.NativeSpendSuites(tc.height), tc.wantSpend)
		})
	}
}

func TestDescriptorRotationProvider_DegenerateIdenticalSuitesDedup(t *testing.T) {
	p := DescriptorRotationProvider{
		Descriptor: CryptoRotationDescriptor{
			Name:         "degenerate-identical",
			OldSuiteID:   0x01,
			NewSuiteID:   0x01,
			CreateHeight: 100,
			SpendHeight:  200,
			SunsetHeight: 300,
		},
	}

	for _, height := range []uint64{0, 100, 200, 300, 999} {
		t.Run(fmt.Sprintf("height_%d", height), func(t *testing.T) {
			assertNativeSuiteIDs(t, p.NativeCreateSuites(height), []uint8{0x01})
			assertNativeSuiteIDs(t, p.NativeSpendSuites(height), []uint8{0x01})
		})
	}
}

func TestDescriptorNativeSuiteSet_FailsClosedOnUnexpectedCardinality(t *testing.T) {
	s := descriptorNativeSuiteSet(0x01, 0x02, 0x03)
	if s == nil {
		t.Fatalf("unexpected nil set")
	}
	assertNativeSuiteIDs(t, s, nil)
}

func TestCryptoRotationDescriptor_NilRegistry(t *testing.T) {
	// With nil registry, should fall back to DefaultSuiteRegistry (ML-DSA-87 only).
	d := CryptoRotationDescriptor{
		Name:         "test",
		OldSuiteID:   SUITE_ID_ML_DSA_87,
		NewSuiteID:   0x42,
		CreateHeight: 100,
		SpendHeight:  200,
	}
	err := d.Validate(nil)
	if err == nil {
		t.Fatalf("expected error: 0x42 not in default registry")
	}
	if !strings.Contains(err.Error(), "new suite 0x42 not registered") {
		t.Fatalf("unexpected error: %v", err)
	}
}
