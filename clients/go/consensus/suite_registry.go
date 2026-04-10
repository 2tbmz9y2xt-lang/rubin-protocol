package consensus

// SuiteParams holds the consensus parameters for a single signature suite.
// These are used by verify_sig dispatch, weight calculation, and spend validators
// to handle suite-specific logic without hardcoding constants.
type SuiteParams struct {
	SuiteID    uint8
	PubkeyLen  int
	SigLen     int    // crypto sig length (without sighash byte)
	VerifyCost uint64 // weight units per signature verification
	AlgName    string // semantic algorithm identity for live verifier binding
}

// SuiteRegistry maps suite IDs to their consensus parameters.
// It is the single source of truth for per-suite constants, replacing
// scattered hardcoded ML_DSA_87_* constants in verify_sig, weight, and
// spend validation paths.
type SuiteRegistry struct {
	suites map[uint8]SuiteParams
}

// NewSuiteRegistryFromParams builds a registry from an explicit list of suites.
// This is intended for conformance tooling and tests that need suites beyond
// the default pre-rotation registry.
//
// NOTE: The returned registry is independent from any caller slices/maps.
func NewSuiteRegistryFromParams(params []SuiteParams) *SuiteRegistry {
	suites := make(map[uint8]SuiteParams, len(params))
	for _, p := range params {
		suites[p.SuiteID] = p
	}
	return &SuiteRegistry{suites: suites}
}

// DefaultSuiteRegistry returns the registry containing all currently defined
// native signature suites. Pre-rotation, this is ML-DSA-87 only.
func DefaultSuiteRegistry() *SuiteRegistry {
	return &SuiteRegistry{
		suites: map[uint8]SuiteParams{
			SUITE_ID_ML_DSA_87: {
				SuiteID:    SUITE_ID_ML_DSA_87,
				PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
				SigLen:     ML_DSA_87_SIG_BYTES,
				VerifyCost: VERIFY_COST_ML_DSA_87,
				AlgName:    "ML-DSA-87",
			},
		},
	}
}

// IsCanonicalDefaultLiveManifest reports whether the registry still matches the
// current chain-instance live manifest contract: exactly one ML-DSA-87 entry
// with the canonical lengths, verify cost, and algorithm identity.
func (r *SuiteRegistry) IsCanonicalDefaultLiveManifest() bool {
	if r == nil || len(r.suites) != 1 {
		return false
	}
	params, ok := r.Lookup(SUITE_ID_ML_DSA_87)
	if !ok {
		return false
	}
	return params.SuiteID == SUITE_ID_ML_DSA_87 &&
		params.PubkeyLen == ML_DSA_87_PUBKEY_BYTES &&
		params.SigLen == ML_DSA_87_SIG_BYTES &&
		params.VerifyCost == VERIFY_COST_ML_DSA_87 &&
		params.AlgName == "ML-DSA-87"
}

// Lookup returns the parameters for suiteID, or (zero, false) if not registered.
func (r *SuiteRegistry) Lookup(suiteID uint8) (SuiteParams, bool) {
	if r == nil {
		return SuiteParams{}, false
	}
	p, ok := r.suites[suiteID]
	return p, ok
}

// IsRegistered returns true if the suite is known to the registry.
func (r *SuiteRegistry) IsRegistered(suiteID uint8) bool {
	if r == nil {
		return false
	}
	_, ok := r.suites[suiteID]
	return ok
}

// NativeSuiteSet is a set of suite IDs that are valid for native covenant
// operations at a given block height. Create-side and spend-side have separate
// sets because during a rotation transition period, new suites may be valid
// for creation before they become valid for spending (or vice versa).
type NativeSuiteSet struct {
	suites map[uint8]struct{}
}

// Contains returns true if suiteID is in the set.
func (s *NativeSuiteSet) Contains(suiteID uint8) bool {
	if s == nil {
		return false
	}
	_, ok := s.suites[suiteID]
	return ok
}

// Len returns the number of suites in the set.
func (s *NativeSuiteSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.suites)
}

// SuiteIDs returns the suite IDs in the set as a sorted slice.
func (s *NativeSuiteSet) SuiteIDs() []uint8 {
	if s == nil || len(s.suites) == 0 {
		return nil
	}
	ids := make([]uint8, 0, len(s.suites))
	for id := range s.suites {
		ids = append(ids, id)
	}
	// Sort for determinism.
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
	return ids
}

// NewNativeSuiteSet constructs a NativeSuiteSet from a list of suite IDs.
func NewNativeSuiteSet(ids ...uint8) *NativeSuiteSet {
	m := make(map[uint8]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return &NativeSuiteSet{suites: m}
}

// Clone returns a deep copy of the suite set so callers cannot mutate shared state.
func (s *NativeSuiteSet) Clone() *NativeSuiteSet {
	if s == nil {
		return nil
	}
	m := make(map[uint8]struct{}, len(s.suites))
	for id := range s.suites {
		m[id] = struct{}{}
	}
	return &NativeSuiteSet{suites: m}
}

// RotationProvider determines which signature suites are valid for native
// covenant creation and spending at a given block height. This is the
// injection point for rotation deployment descriptors.
//
// Pre-rotation, the default implementation returns {ML_DSA_87} for both
// create and spend at all heights.
type RotationProvider interface {
	// NativeCreateSuites returns the set of suites valid for creating
	// native covenant outputs at the given block height.
	NativeCreateSuites(height uint64) *NativeSuiteSet

	// NativeSpendSuites returns the set of suites valid for spending
	// native covenant outputs at the given block height.
	NativeSpendSuites(height uint64) *NativeSuiteSet
}

// DefaultRotationProvider returns a RotationProvider that always reports
// {ML_DSA_87} as the only native suite for both create and spend.
// This is the pre-rotation behavior.
type DefaultRotationProvider struct{}

var defaultNativeSuiteSet = NewNativeSuiteSet(SUITE_ID_ML_DSA_87)

// NativeCreateSuites implements RotationProvider.
func (DefaultRotationProvider) NativeCreateSuites(_ uint64) *NativeSuiteSet {
	return defaultNativeSuiteSet.Clone()
}

// NativeSpendSuites implements RotationProvider.
func (DefaultRotationProvider) NativeSpendSuites(_ uint64) *NativeSuiteSet {
	return defaultNativeSuiteSet.Clone()
}
