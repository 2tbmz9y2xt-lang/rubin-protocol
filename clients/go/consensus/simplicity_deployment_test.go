package consensus

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// bytes32 returns a [32]byte filled with b (test fixtures).
func bytes32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// goldenDescriptor is the fully-specified sample whose anchor/set-anchor are pinned
// below; every field is a fixed literal so the golden hex is reproducible.
func goldenDescriptor(activationHeight uint64) SimplicityDeploymentDescriptor {
	return SimplicityDeploymentDescriptor{
		ChainID:             bytes32(0x11),
		ActivationHeight:    activationHeight,
		SimplicityVersion:   7,
		WitnessABIVersion:   1,
		ErrorMapVersion:     3,
		JetsRegistryHash:    bytes32(0x22),
		CostModelHash:       bytes32(0x33),
		ProgramEncodingHash: bytes32(0x44),
		ContextSchemaHash:   bytes32(0x55),
	}
}

// Golden hex computed INDEPENDENTLY (Python sha3_256 over the hand-assembled
// preimage), not by the code under test, so a field-order/endianness bug in
// simplicityDeploymentBytesV1 surfaces as a mismatch (§23.2.4).
func TestSimplicityDeploymentGoldenVectors(t *testing.T) {
	d := goldenDescriptor(1000)
	if got := len(simplicityDeploymentBytesV1(d)); got != 238 {
		t.Fatalf("preimage length = %d, want 238 (26 tag + 212 fields)", got)
	}
	anchor := simplicityDeploymentAnchorV1(d)
	if got := hex.EncodeToString(anchor[:]); got != "54b3f2564f184cab0d9b7926c93f666e0965f4933801d4730012b04e85172a99" {
		t.Fatalf("simplicity_deployment_anchor_v1 = %s", got)
	}
	set := []SimplicityDeploymentDescriptor{goldenDescriptor(1000), goldenDescriptor(2000)}
	setAnchor, err := SimplicityDeploymentSetAnchor(bytes32(0x11), set)
	if err != nil {
		t.Fatalf("set anchor: %v", err)
	}
	if got := hex.EncodeToString(setAnchor[:]); got != "2c82bbbf5bba8afdc827454501fa3cc72ab7b2f1c64125aeaea8d77a9c45d70d" {
		t.Fatalf("simplicity_deployment_set_anchor_v1 = %s", got)
	}
	// Dropping a published descriptor changes the anchor (commits publication, not validity).
	if partial, _ := SimplicityDeploymentSetAnchor(bytes32(0x11), set[:1]); partial == setAnchor {
		t.Fatal("set anchor must differ when a published descriptor is dropped")
	}
}

// liveValidDescriptor builds a VALID descriptor for chainID at activationHeight.
func liveValidDescriptor(chainID [32]byte, activationHeight uint64) SimplicityDeploymentDescriptor {
	a := liveArtifactHashes()
	return SimplicityDeploymentDescriptor{
		ChainID:             chainID,
		ActivationHeight:    activationHeight,
		WitnessABIVersion:   1,
		JetsRegistryHash:    a.jetsRegistry,
		CostModelHash:       a.costModel,
		ProgramEncodingHash: a.programEncoding,
		ContextSchemaHash:   a.contextSchema,
	}
}

// selectOver computes the published-set anchor for set and runs surface selection.
func selectOver(t *testing.T, chainID [32]byte, height uint64, set []SimplicityDeploymentDescriptor) (*VerifiedSimplicitySurface, error) {
	t.Helper()
	anchor, err := SimplicityDeploymentSetAnchor(chainID, set)
	if err != nil {
		return nil, err
	}
	return selectGoverningSurface(set, anchor, chainID, height, liveArtifactHashes())
}

func TestSelectGoverningSurface_ValidityAndSelection(t *testing.T) {
	chain := bytes32(0xAB)
	other := bytes32(0xCD)

	badJets := liveValidDescriptor(chain, 10)
	badJets.JetsRegistryHash = bytes32(0x01)
	badCost := liveValidDescriptor(chain, 10)
	badCost.CostModelHash = bytes32(0x01)
	badProg := liveValidDescriptor(chain, 10)
	badProg.ProgramEncodingHash = bytes32(0x01)
	badCtx := liveValidDescriptor(chain, 10)
	badCtx.ContextSchemaHash = bytes32(0x01)
	badWitness := liveValidDescriptor(chain, 10)
	badWitness.WitnessABIVersion = 2
	badDA := liveValidDescriptor(chain, 10)
	badDA.DAReferenceSchemaHash = bytes32(0x01)
	crossChain := liveValidDescriptor(other, 10)
	informative := liveValidDescriptor(chain, 10)
	informative.SimplicityVersion = 0xDEADBEEF
	informative.ErrorMapVersion = 0x1234

	// Two distinct valid descriptors at the same activation_height (differ via an informative field).
	tieA := liveValidDescriptor(chain, 10)
	tieB := liveValidDescriptor(chain, 10)
	tieB.SimplicityVersion = 99

	cases := []struct {
		name   string
		height uint64
		set    []SimplicityDeploymentDescriptor
		active bool
		wantAH uint64 // governing activation_height when active
	}{
		{"pre-height inactive", 9, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10)}, false, 0},
		{"valid active at H", 10, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10)}, true, 10},
		{"wrong jets_registry_hash", 10, []SimplicityDeploymentDescriptor{badJets}, false, 0},
		{"wrong cost_model_hash", 10, []SimplicityDeploymentDescriptor{badCost}, false, 0},
		{"wrong program_encoding_hash", 10, []SimplicityDeploymentDescriptor{badProg}, false, 0},
		{"wrong context_schema_hash", 10, []SimplicityDeploymentDescriptor{badCtx}, false, 0},
		{"witness_abi_version != 1", 10, []SimplicityDeploymentDescriptor{badWitness}, false, 0},
		{"da_reference_schema_hash != 0", 10, []SimplicityDeploymentDescriptor{badDA}, false, 0},
		{"chain_id mismatch", 10, []SimplicityDeploymentDescriptor{crossChain}, false, 0},
		{"informative fields arbitrary still active", 10, []SimplicityDeploymentDescriptor{informative}, true, 10},
		{"two valid same height => both ignored", 10, []SimplicityDeploymentDescriptor{tieA, tieB}, false, 0},
		{"tie at query height ignored, prior lower valid governs", 10, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 5), tieA, tieB}, true, 5},
		{"valid + invalid same height => valid governs", 10, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10), crossChain}, true, 10},
		{"later descriptor replaces earlier (query high)", 20, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10), liveValidDescriptor(chain, 20)}, true, 20},
		{"earlier governs before replacement (query low)", 15, []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10), liveValidDescriptor(chain, 20)}, true, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			surface, err := selectOver(t, chain, tc.height, tc.set)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.active {
				if surface == nil {
					t.Fatal("expected an active governing surface, got nil")
				}
				if surface.ActivationHeight != tc.wantAH {
					t.Fatalf("governing activation_height = %d, want %d", surface.ActivationHeight, tc.wantAH)
				}
			} else if surface != nil {
				t.Fatalf("expected no active surface, got activation_height %d", surface.ActivationHeight)
			}
		})
	}
}

func TestSelectGoverningSurface_UnverifiableSet(t *testing.T) {
	chain := bytes32(0xAB)
	set := []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10)}

	anchor, err := SimplicityDeploymentSetAnchor(chain, set)
	if err != nil {
		t.Fatal(err)
	}
	// Clause (b): a previously-ACTIVE surface at height 10, then UNKNOWN (set-anchor
	// mismatch) must yield NO surface — the stateless gate never replaces or
	// deactivates a caller-held governing surface.
	if s, _ := selectGoverningSurface(set, anchor, chain, 10, liveArtifactHashes()); s == nil {
		t.Fatal("precondition: expected a previously-ACTIVE surface")
	}
	if s, err := selectGoverningSurface(set, bytes32(0xFF), chain, 10, liveArtifactHashes()); err == nil || s != nil {
		t.Fatalf("UNKNOWN must yield no surface, got s=%v err=%v", s, err)
	}

	// Duplicate anchor (same descriptor published twice) => invalid set (error).
	dup := []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10), liveValidDescriptor(chain, 10)}
	if _, err := SimplicityDeploymentSetAnchor(chain, dup); err == nil {
		t.Fatal("expected duplicate-anchor invalid-set error")
	}
}

// stubDeploymentProvider is a raw-I/O provider stub for the gate-level disposition tests.
type stubDeploymentProvider struct {
	set       []SimplicityDeploymentDescriptor
	setAnchor [32]byte
	ok        bool
	err       error
}

func (s stubDeploymentProvider) PublishedSimplicityDeployments() ([]SimplicityDeploymentDescriptor, [32]byte, bool, error) {
	return s.set, s.setAnchor, s.ok, s.err
}

func TestValidateCoreSimplicityDeploymentActive_Dispositions(t *testing.T) {
	chain := bytes32(0xAB)
	valid := []SimplicityDeploymentDescriptor{liveValidDescriptor(chain, 10)}
	validAnchor, err := SimplicityDeploymentSetAnchor(chain, valid)
	if err != nil {
		t.Fatalf("set anchor: %v", err)
	}

	assertReason := func(t *testing.T, err error, substr string) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected error containing %q, got nil", substr)
		}
		if !strings.Contains(err.Error(), substr) {
			t.Fatalf("error = %q, want substring %q", err.Error(), substr)
		}
	}

	// nil provider => not active (compat).
	assertReason(t, validateCoreSimplicityDeploymentActive(chain, 10, nil), "deployment not active")

	// provider I/O error => distinct "lookup failure" (RUB-604-pinned string), NOT
	// collapsed into "not active".
	ioErr := stubDeploymentProvider{ok: false, err: errTestLookup}
	assertReason(t, validateCoreSimplicityDeploymentActive(chain, 10, ioErr), "deployment lookup failure")

	// ok=false (set unobtainable / partial knowledge) => UNKNOWN => not active, and
	// must NOT return a governing surface on partial knowledge.
	unknown := stubDeploymentProvider{set: valid, setAnchor: validAnchor, ok: false}
	assertReason(t, validateCoreSimplicityDeploymentActive(chain, 10, unknown), "deployment not active")

	// set-anchor mismatch => not active (UNKNOWN), previously-active surface unchanged.
	mismatch := stubDeploymentProvider{set: valid, setAnchor: bytes32(0xFF), ok: true}
	assertReason(t, validateCoreSimplicityDeploymentActive(chain, 10, mismatch), "deployment not active")

	// Verified active set => passes the gate (no error).
	active := stubDeploymentProvider{set: valid, setAnchor: validAnchor, ok: true}
	if err := validateCoreSimplicityDeploymentActive(chain, 10, active); err != nil {
		t.Fatalf("expected active gate to pass, got %v", err)
	}
	// Below activation height => not active.
	assertReason(t, validateCoreSimplicityDeploymentActive(chain, 9, active), "deployment not active")
}

var errTestLookup = errors.New("simulated lookup i/o")

// A descriptor-bearing provider satisfies the interface; a bare bool method no
// longer does (compile-time enforcement that a bare-bool provider cannot satisfy
// activation readiness).
var (
	_ SimplicityDeploymentProvider = stubDeploymentProvider{}
	_ SimplicityDeploymentProvider = testRotationProvider{}
)
