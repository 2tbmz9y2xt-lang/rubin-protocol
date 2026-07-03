package consensus

import (
	"bytes"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus/simplicity"
)

// CANONICAL §23.2.4 CORE_SIMPLICITY deployment-descriptor activation surface: a
// deployment activates through a descriptor committing the full execution surface
// (10 fields) plus a set-level anchor over every PUBLISHED descriptor. ACTIVE
// status is validated from that set, never a bare height bool.

// Domain-separation tags (ASCII, no length prefix); byte lengths pinned by tests.
var (
	simplicityDeployTag    = []byte("RUBIN-SIMPLICITY-DEPLOY-v1")
	simplicityDeploySetTag = []byte("RUBIN-SIMPLICITY-DEPLOY-SET-v1")
)

// SimplicityDeploymentDescriptor is a §23.2.4 deployment descriptor: the committed
// field set in canonical order (see inline notes for informative-only fields).
type SimplicityDeploymentDescriptor struct {
	ChainID               [32]byte
	ActivationHeight      uint64
	SimplicityVersion     uint32 // informative — never gates validity
	WitnessABIVersion     uint32 // v1 MUST be 1
	ErrorMapVersion       uint32 // informative — never gates validity
	JetsRegistryHash      [32]byte
	CostModelHash         [32]byte
	ProgramEncodingHash   [32]byte
	ContextSchemaHash     [32]byte
	DAReferenceSchemaHash [32]byte // reserved in v1 — MUST be 32 zero bytes
}

// VerifiedSimplicitySurface is the execution surface a verified governing descriptor exposes.
type VerifiedSimplicitySurface struct {
	ActivationHeight    uint64
	JetsRegistryHash    [32]byte
	CostModelHash       [32]byte
	ProgramEncodingHash [32]byte
	ContextSchemaHash   [32]byte
}

// simplicityArtifactHashes bundles the committed artifact hashes a descriptor must match.
type simplicityArtifactHashes struct {
	jetsRegistry    [32]byte
	costModel       [32]byte
	programEncoding [32]byte
	contextSchema   [32]byte
}

// liveArtifactHashes returns the current v1 artifact hashes from the simplicity package.
func liveArtifactHashes() simplicityArtifactHashes {
	return simplicityArtifactHashes{
		jetsRegistry:    simplicity.JetsRegistryHash(),
		costModel:       simplicity.CostModelHash(),
		programEncoding: simplicity.ProgramEncodingHash(),
		contextSchema:   simplicity.ContextSchemaHash(),
	}
}

// simplicityDeploymentBytesV1 builds the canonical SimplicityDeploymentBytes_v1
// preimage: the domain tag followed by the ten fields in canonical order.
func simplicityDeploymentBytesV1(d SimplicityDeploymentDescriptor) []byte {
	// 238-byte preimage: 26-byte tag + 212 bytes of fields (32+8+4+4+4+32*5).
	out := make([]byte, 0, 238)
	out = append(out, simplicityDeployTag...)
	out = append(out, d.ChainID[:]...)
	out = AppendU64le(out, d.ActivationHeight)
	out = AppendU32le(out, d.SimplicityVersion)
	out = AppendU32le(out, d.WitnessABIVersion)
	out = AppendU32le(out, d.ErrorMapVersion)
	out = append(out, d.JetsRegistryHash[:]...)
	out = append(out, d.CostModelHash[:]...)
	out = append(out, d.ProgramEncodingHash[:]...)
	out = append(out, d.ContextSchemaHash[:]...)
	out = append(out, d.DAReferenceSchemaHash[:]...)
	return out
}

// simplicityDeploymentAnchorV1 = SHA3-256(SimplicityDeploymentBytes_v1(D)).
func simplicityDeploymentAnchorV1(d SimplicityDeploymentDescriptor) [32]byte {
	return sha3_256(simplicityDeploymentBytesV1(d))
}

// simplicityDeploymentSetAnchorV1 commits publication (validity-agnostic) over
// the anchors of ALL published descriptors, sorted strictly ascending bytewise.
// A duplicate anchor is an invalid set and returns an error.
func simplicityDeploymentSetAnchorV1(chainID [32]byte, anchors [][32]byte) ([32]byte, error) {
	sorted := make([][32]byte, len(anchors))
	copy(sorted, anchors)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if bytes.Compare(sorted[i-1][:], sorted[i][:]) >= 0 { // duplicate => invalid set
			return [32]byte{}, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY duplicate deployment anchor")
		}
	}
	out := make([]byte, 0, len(simplicityDeploySetTag)+32+9+32*len(sorted))
	out = append(out, simplicityDeploySetTag...)
	out = append(out, chainID[:]...)
	out = AppendCompactSize(out, uint64(len(sorted)))
	for i := range sorted {
		out = append(out, sorted[i][:]...)
	}
	return sha3_256(out), nil
}

// SimplicityDeploymentSetAnchor computes the published-set anchor over the
// descriptors' anchors (sorted bytewise). Exported for provider implementations.
func SimplicityDeploymentSetAnchor(chainID [32]byte, descriptors []SimplicityDeploymentDescriptor) ([32]byte, error) {
	anchors := make([][32]byte, len(descriptors))
	for i := range descriptors {
		anchors[i] = simplicityDeploymentAnchorV1(descriptors[i])
	}
	return simplicityDeploymentSetAnchorV1(chainID, anchors)
}

// LiveSimplicityDeploymentDescriptor builds the valid v1 descriptor committing the
// current execution surface for chainID at height 0. Used by node/genesis shims
// that force CORE_SIMPLICITY active for pre-activation well-formedness checks.
func LiveSimplicityDeploymentDescriptor(chainID [32]byte) SimplicityDeploymentDescriptor {
	a := liveArtifactHashes()
	return SimplicityDeploymentDescriptor{
		ChainID:             chainID,
		ActivationHeight:    0,
		WitnessABIVersion:   1,
		JetsRegistryHash:    a.jetsRegistry,
		CostModelHash:       a.costModel,
		ProgramEncodingHash: a.programEncoding,
		ContextSchemaHash:   a.contextSchema,
	}
}
