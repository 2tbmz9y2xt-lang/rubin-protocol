package consensus

import (
	"testing"
)

// ---------------------------------------------------------------------------
// SuiteRegistry tests
// ---------------------------------------------------------------------------

func TestDefaultSuiteRegistry_LookupMLDSA87(t *testing.T) {
	reg := DefaultSuiteRegistry()
	p, ok := reg.Lookup(SUITE_ID_ML_DSA_87)
	if !ok {
		t.Fatal("ML-DSA-87 should be registered in default registry")
	}
	if p.SuiteID != SUITE_ID_ML_DSA_87 {
		t.Errorf("SuiteID = %d, want %d", p.SuiteID, SUITE_ID_ML_DSA_87)
	}
	if p.PubkeyLen != ML_DSA_87_PUBKEY_BYTES {
		t.Errorf("PubkeyLen = %d, want %d", p.PubkeyLen, ML_DSA_87_PUBKEY_BYTES)
	}
	if p.SigLen != ML_DSA_87_SIG_BYTES {
		t.Errorf("SigLen = %d, want %d", p.SigLen, ML_DSA_87_SIG_BYTES)
	}
	if p.VerifyCost != VERIFY_COST_ML_DSA_87 {
		t.Errorf("VerifyCost = %d, want %d", p.VerifyCost, VERIFY_COST_ML_DSA_87)
	}
	if p.OpenSSLAlg != "ML-DSA-87" {
		t.Errorf("OpenSSLAlg = %q, want %q", p.OpenSSLAlg, "ML-DSA-87")
	}
}

func TestDefaultSuiteRegistry_LookupUnknown(t *testing.T) {
	reg := DefaultSuiteRegistry()
	_, ok := reg.Lookup(0xFF)
	if ok {
		t.Fatal("unknown suite should not be found")
	}
}

func TestDefaultSuiteRegistry_LookupSentinel(t *testing.T) {
	reg := DefaultSuiteRegistry()
	_, ok := reg.Lookup(SUITE_ID_SENTINEL)
	if ok {
		t.Fatal("SENTINEL should not be registered")
	}
}

func TestSuiteRegistry_IsRegistered(t *testing.T) {
	reg := DefaultSuiteRegistry()
	if !reg.IsRegistered(SUITE_ID_ML_DSA_87) {
		t.Error("ML-DSA-87 should be registered")
	}
	if reg.IsRegistered(0xFF) {
		t.Error("0xFF should not be registered")
	}
	if reg.IsRegistered(SUITE_ID_SENTINEL) {
		t.Error("SENTINEL should not be registered")
	}
}

func TestSuiteRegistry_NilSafe(t *testing.T) {
	var reg *SuiteRegistry
	_, ok := reg.Lookup(SUITE_ID_ML_DSA_87)
	if ok {
		t.Error("nil registry Lookup should return false")
	}
	if reg.IsRegistered(SUITE_ID_ML_DSA_87) {
		t.Error("nil registry IsRegistered should return false")
	}
}

// ---------------------------------------------------------------------------
// NativeSuiteSet tests
// ---------------------------------------------------------------------------

func TestNativeSuiteSet_Contains(t *testing.T) {
	s := NewNativeSuiteSet(SUITE_ID_ML_DSA_87)
	if !s.Contains(SUITE_ID_ML_DSA_87) {
		t.Error("set should contain ML-DSA-87")
	}
	if s.Contains(0xFF) {
		t.Error("set should not contain 0xFF")
	}
	if s.Contains(SUITE_ID_SENTINEL) {
		t.Error("set should not contain SENTINEL")
	}
}

func TestNativeSuiteSet_Len(t *testing.T) {
	s := NewNativeSuiteSet(SUITE_ID_ML_DSA_87, 0x02, 0x03)
	if s.Len() != 3 {
		t.Errorf("Len = %d, want 3", s.Len())
	}
}

func TestNativeSuiteSet_SuiteIDs_Sorted(t *testing.T) {
	s := NewNativeSuiteSet(0x03, SUITE_ID_ML_DSA_87, 0x02)
	ids := s.SuiteIDs()
	if len(ids) != 3 {
		t.Fatalf("len = %d, want 3", len(ids))
	}
	if ids[0] != SUITE_ID_ML_DSA_87 || ids[1] != 0x02 || ids[2] != 0x03 {
		t.Errorf("SuiteIDs = %v, want [1 2 3]", ids)
	}
}

func TestNativeSuiteSet_Empty(t *testing.T) {
	s := NewNativeSuiteSet()
	if s.Contains(SUITE_ID_ML_DSA_87) {
		t.Error("empty set should not contain anything")
	}
	if s.Len() != 0 {
		t.Error("empty set Len should be 0")
	}
	if s.SuiteIDs() != nil {
		t.Error("empty set SuiteIDs should be nil")
	}
}

func TestNativeSuiteSet_NilSafe(t *testing.T) {
	var s *NativeSuiteSet
	if s.Contains(SUITE_ID_ML_DSA_87) {
		t.Error("nil set Contains should return false")
	}
	if s.Len() != 0 {
		t.Error("nil set Len should be 0")
	}
	if s.SuiteIDs() != nil {
		t.Error("nil set SuiteIDs should be nil")
	}
}

func TestNativeSuiteSet_Dedup(t *testing.T) {
	s := NewNativeSuiteSet(SUITE_ID_ML_DSA_87, SUITE_ID_ML_DSA_87, SUITE_ID_ML_DSA_87)
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (dedup)", s.Len())
	}
}

// ---------------------------------------------------------------------------
// RotationProvider tests
// ---------------------------------------------------------------------------

func TestDefaultRotationProvider_CreateSuites(t *testing.T) {
	var rp DefaultRotationProvider
	for _, h := range []uint64{0, 1, 100, 1_000_000} {
		s := rp.NativeCreateSuites(h)
		if !s.Contains(SUITE_ID_ML_DSA_87) {
			t.Errorf("height %d: NativeCreateSuites should contain ML-DSA-87", h)
		}
		if s.Len() != 1 {
			t.Errorf("height %d: NativeCreateSuites.Len = %d, want 1", h, s.Len())
		}
	}
}

func TestDefaultRotationProvider_SpendSuites(t *testing.T) {
	var rp DefaultRotationProvider
	for _, h := range []uint64{0, 1, 100, 1_000_000} {
		s := rp.NativeSpendSuites(h)
		if !s.Contains(SUITE_ID_ML_DSA_87) {
			t.Errorf("height %d: NativeSpendSuites should contain ML-DSA-87", h)
		}
		if s.Len() != 1 {
			t.Errorf("height %d: NativeSpendSuites.Len = %d, want 1", h, s.Len())
		}
	}
}

func TestDefaultRotationProvider_SpendSuites_NoSentinel(t *testing.T) {
	var rp DefaultRotationProvider
	s := rp.NativeSpendSuites(100)
	if s.Contains(SUITE_ID_SENTINEL) {
		t.Error("NativeSpendSuites should not contain SENTINEL")
	}
}

func TestDefaultRotationProvider_CreateSuites_NoUnknown(t *testing.T) {
	var rp DefaultRotationProvider
	s := rp.NativeCreateSuites(100)
	if s.Contains(0xFF) {
		t.Error("NativeCreateSuites should not contain unknown suite")
	}
}

// ---------------------------------------------------------------------------
// Custom RotationProvider (simulates future rotation)
// ---------------------------------------------------------------------------

type mockRotationProvider struct {
	h2 uint64 // height at which new suite becomes spend-valid
}

func (m *mockRotationProvider) NativeCreateSuites(height uint64) *NativeSuiteSet {
	return NewNativeSuiteSet(SUITE_ID_ML_DSA_87)
}

func (m *mockRotationProvider) NativeSpendSuites(height uint64) *NativeSuiteSet {
	if height >= m.h2 {
		return NewNativeSuiteSet(SUITE_ID_ML_DSA_87, 0x02)
	}
	return NewNativeSuiteSet(SUITE_ID_ML_DSA_87)
}

func TestMockRotationProvider_TransitionAtH2(t *testing.T) {
	rp := &mockRotationProvider{h2: 1000}

	// Before H2: only ML-DSA-87
	s := rp.NativeSpendSuites(999)
	if s.Len() != 1 {
		t.Errorf("pre-H2: Len = %d, want 1", s.Len())
	}
	if !s.Contains(SUITE_ID_ML_DSA_87) {
		t.Error("pre-H2: should contain ML-DSA-87")
	}
	if s.Contains(0x02) {
		t.Error("pre-H2: should not contain 0x02")
	}

	// At H2: ML-DSA-87 + new suite
	s = rp.NativeSpendSuites(1000)
	if s.Len() != 2 {
		t.Errorf("at-H2: Len = %d, want 2", s.Len())
	}
	if !s.Contains(0x02) {
		t.Error("at-H2: should contain 0x02")
	}

	// After H2
	s = rp.NativeSpendSuites(2000)
	if s.Len() != 2 {
		t.Errorf("post-H2: Len = %d, want 2", s.Len())
	}
}

func TestSuiteRegistry_MultiSuite(t *testing.T) {
	reg := &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			SUITE_ID_ML_DSA_87: {
				SuiteID:    SUITE_ID_ML_DSA_87,
				PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
				SigLen:     ML_DSA_87_SIG_BYTES,
				VerifyCost: VERIFY_COST_ML_DSA_87,
				OpenSSLAlg: "ML-DSA-87",
			},
			0x02: {
				SuiteID:    0x02,
				PubkeyLen:  1312,
				SigLen:     2420,
				VerifyCost: 4,
				OpenSSLAlg: "ML-DSA-65",
			},
		},
	}

	p1, ok := reg.Lookup(SUITE_ID_ML_DSA_87)
	if !ok || p1.VerifyCost != VERIFY_COST_ML_DSA_87 {
		t.Error("ML-DSA-87 lookup failed")
	}
	p2, ok := reg.Lookup(0x02)
	if !ok || p2.VerifyCost != 4 {
		t.Error("0x02 lookup failed")
	}
	_, ok = reg.Lookup(0x03)
	if ok {
		t.Error("0x03 should not exist")
	}
}
