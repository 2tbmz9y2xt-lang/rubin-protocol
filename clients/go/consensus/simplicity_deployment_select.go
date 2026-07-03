package consensus

// descriptorFieldsValid: valid v1 descriptor for the chain — chain_id match,
// witness_abi_version==1, da_reference zero, four artifact hashes match (versions informative).
func descriptorFieldsValid(d SimplicityDeploymentDescriptor, chainID [32]byte, artifacts simplicityArtifactHashes) bool {
	if d.ChainID != chainID {
		return false
	}
	if d.WitnessABIVersion != 1 {
		return false
	}
	if d.DAReferenceSchemaHash != ([32]byte{}) {
		return false
	}
	return d.JetsRegistryHash == artifacts.jetsRegistry &&
		d.CostModelHash == artifacts.costModel &&
		d.ProgramEncodingHash == artifacts.programEncoding &&
		d.ContextSchemaHash == artifacts.contextSchema
}

// selectGoverningSurface verifies the COMPLETE published set (incl. invalid
// descriptors) against setAnchor FIRST, then ignores invalid ones and returns the
// surface governing at height (§23.2.4 ordering). A set-anchor mismatch/duplicate
// is UNKNOWN => error (never activate/replace on partial knowledge); a verified
// set with no governing descriptor returns (nil, nil) = inactive.
func selectGoverningSurface(
	descriptors []SimplicityDeploymentDescriptor,
	setAnchor [32]byte,
	chainID [32]byte,
	height uint64,
	artifacts simplicityArtifactHashes,
) (*VerifiedSimplicitySurface, error) {
	computed, err := SimplicityDeploymentSetAnchor(chainID, descriptors)
	if err != nil {
		return nil, err
	}
	if computed != setAnchor {
		return nil, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_SIMPLICITY deployment set anchor mismatch")
	}
	governing := governingDescriptor(validDescriptorSubset(descriptors, chainID, artifacts), height)
	if governing == nil {
		return nil, nil
	}
	return &VerifiedSimplicitySurface{
		ActivationHeight:    governing.ActivationHeight,
		JetsRegistryHash:    governing.JetsRegistryHash,
		CostModelHash:       governing.CostModelHash,
		ProgramEncodingHash: governing.ProgramEncodingHash,
		ContextSchemaHash:   governing.ContextSchemaHash,
	}, nil
}

// validDescriptorSubset returns the valid descriptors, derived AFTER set-anchor
// verification (validity-agnostic ordering).
func validDescriptorSubset(descriptors []SimplicityDeploymentDescriptor, chainID [32]byte, artifacts simplicityArtifactHashes) []SimplicityDeploymentDescriptor {
	valid := make([]SimplicityDeploymentDescriptor, 0, len(descriptors))
	for i := range descriptors {
		if descriptorFieldsValid(descriptors[i], chainID, artifacts) {
			valid = append(valid, descriptors[i])
		}
	}
	return valid
}

// governingDescriptor returns the highest-activation_height valid descriptor at
// or below height, skipping activation_height ties (both ignored). Selection
// iterates the ordered slice, so the chosen descriptor is deterministic; the map
// is used only for order-independent tie counting (how many valid descriptors
// share each activation_height) and never drives selection order.
func governingDescriptor(valid []SimplicityDeploymentDescriptor, height uint64) *SimplicityDeploymentDescriptor {
	heightCounts := make(map[uint64]int, len(valid))
	for i := range valid {
		heightCounts[valid[i].ActivationHeight]++
	}
	var governing *SimplicityDeploymentDescriptor
	for i := range valid {
		d := valid[i]
		if heightCounts[d.ActivationHeight] > 1 || d.ActivationHeight > height {
			continue
		}
		if governing == nil || d.ActivationHeight > governing.ActivationHeight {
			governing = &valid[i]
		}
	}
	return governing
}
