package mdbx

func validSelectedFor(s *SelectedSideV1, tree bool) bool {
	if s.F >= s.TipHeight || s.TipHeight > maxAuthorityHeight {
		return false
	}
	// Full form row_count=min(C,1440); the sole one-slot form is C>=1440, row_count=1439 (RUBIN_MEMPOOL_POLICY.md 6.4.1.3).
	c := s.TipHeight - s.F
	if s.GenerationID == 0 || !validWork(s.CumulativeChainwork) {
		return false
	}
	return all(anyTrue(uint64(s.RowCount) == min(c, 1440), all(c >= 1440, s.RowCount == 1439)),
		s.LogicalBytes >= uint64(s.RowCount),
		s.LogicalBytes <= uint64(s.RowCount)*authorityBlockMaximum(tree))
}

func validSpan(s CleanupSpanV1) bool {
	if s.GenerationID == 0 {
		return false
	}
	switch s.Kind {
	case CleanupSpanGenerationV1:
		return all(s.FirstHeight == 0, s.LastHeight == 0, s.NextHeight == 0)
	case CleanupSpanBlocksV1, CleanupSpanUndoV1, CleanupSpanSideV1:
		return all(s.FirstHeight <= s.NextHeight, s.NextHeight <= s.LastHeight, s.LastHeight <= maxAuthorityHeight)
	}
	return false
}

func validCleanupFor(spans authoritySpans, tree bool) bool {
	if spans.len() < 1 {
		return false
	}
	previous := CleanupSpanKindV1(0)
	var generation uint64
	generations := 0
	for i := 0; i < spans.len(); i++ {
		span := spans.at(i)
		if !validSpan(span) || !validSpanOrder(span, previous, generation, tree) {
			return false
		}
		previous = span.Kind
		if span.Kind == CleanupSpanGenerationV1 {
			generation = span.GenerationID
			generations++
			if generations > 2 {
				return false
			}
		}
	}
	return true
}

func validReplayFor(v *ReplayV1, tree bool) bool {
	if !validProfile(v.TargetProfile) || !validWork(v.Target.CumulativeChainwork) {
		return false
	}
	if !all(v.TargetGenerationID != 0, v.Target.TipHeight >= 1, v.Target.TipHeight <= maxAuthorityHeight) {
		return false
	}
	if tree && v.Cursor == (ReplayCursorV1{}) {
		return true
	}
	switch v.Cursor.Kind {
	case ReplayCursorPreGenesisV1:
		return all(v.Cursor.Height == 0, v.Cursor.BlockHash == ([32]byte{}))
	case ReplayCursorAppliedV1:
		return all(v.Cursor.Height <= v.Target.TipHeight,
			anyTrue(v.Cursor.Height != 0, v.Cursor.BlockHash == v.Target.GenesisHash),
			anyTrue(v.Cursor.Height != v.Target.TipHeight, v.Cursor.BlockHash == v.Target.TipHash))
	}
	return false
}

func validDetachedFor(d *DetachedSuffixV1, entries authorityDetached, tree bool) bool {
	if !all(entries.len() >= 1, entries.len() <= 1440, int(d.EntryCount) == entries.len()) {
		return false
	}
	sum := uint64(0)
	for i := 0; i < entries.len(); i++ {
		entry := entries.at(i)
		if !all(entry.Height <= maxAuthorityHeight, entry.BlockBytesLen >= 1,
			entry.BlockBytesLen <= authorityBlockMaximum(tree), !entries.hasHash(entry.Hash, i)) {
			return false
		}
		if i > 0 && !validPointStep(entries.at(i-1).Height, entry.Height, true) {
			return false
		}
		sum += entry.BlockBytesLen
	}
	first := entries.at(0)
	return all(d.Cursor == (AuthorityPointV1{Height: first.Height, BlockHash: first.Hash}), d.LogicalBytes == sum)
}

func validDescriptors(a StorageAuthorityV1) bool {
	return validDescriptorsFor(projectAuthority(a, nil), false)
}

func validDescriptorsFor(a authorityValidation, tree bool) bool {
	if a.SelectedSide != nil && !validSelectedFor(a.SelectedSide, tree) {
		return false
	}
	if a.DetachedSuffix != nil && !validDetachedFor(a.DetachedSuffix, a.detached, tree) {
		return false
	}
	branch := a.ExcludedInvalidBranch
	return branch == nil || branch.FirstInvalidHeight <= maxAuthorityHeight && validConsensusErrorToken(branch.ExactConsensusError)
}

// validConsensusErrorToken accepts the exact error codes in RUBIN_L1_CANONICAL.md Section 13.
func validConsensusErrorToken(token []byte) bool {
	switch string(token) {
	case "TX_ERR_PARSE", "TX_ERR_VALUE_CONSERVATION", "TX_ERR_TX_NONCE_INVALID",
		"TX_ERR_SEQUENCE_INVALID", "TX_ERR_NONCE_REPLAY", "TX_ERR_SIG_INVALID",
		"TX_ERR_SIG_ALG_INVALID", "TX_ERR_SIGHASH_TYPE_INVALID", "TX_ERR_SIG_NONCANONICAL",
		"TX_ERR_TIMELOCK_NOT_MET", "TX_ERR_WITNESS_OVERFLOW", "TX_ERR_COVENANT_TYPE_INVALID",
		"TX_ERR_VAULT_MALFORMED", "TX_ERR_VAULT_PARAMS_INVALID", "TX_ERR_VAULT_KEYS_NOT_CANONICAL",
		"TX_ERR_VAULT_WHITELIST_NOT_CANONICAL", "TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN", "TX_ERR_VAULT_OWNER_AUTH_REQUIRED",
		"TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN", "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN", "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED",
		"TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE", "TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE", "TX_ERR_SIMPLICITY_CMR_MISMATCH",
		"TX_ERR_SIMPLICITY_DECODE", "TX_ERR_SIMPLICITY_JET_DISALLOWED", "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED",
		"TX_ERR_SIMPLICITY_REJECTED", "TX_ERR_MISSING_UTXO", "TX_ERR_COINBASE_IMMATURE",
		"BLOCK_ERR_LINKAGE_INVALID", "BLOCK_ERR_MERKLE_INVALID", "BLOCK_ERR_WITNESS_COMMITMENT",
		"BLOCK_ERR_POW_INVALID", "BLOCK_ERR_TARGET_INVALID", "BLOCK_ERR_TIMESTAMP_OLD",
		"BLOCK_ERR_TIMESTAMP_FUTURE", "BLOCK_ERR_COINBASE_INVALID", "BLOCK_ERR_SUBSIDY_EXCEEDED",
		"BLOCK_ERR_STATE_CAP_EXCEEDED", "BLOCK_ERR_STATE_GROWTH_EXCEEDED", "BLOCK_ERR_UTXO_ROOT_MISMATCH",
		"BLOCK_ERR_WEIGHT_EXCEEDED", "BLOCK_ERR_ANCHOR_BYTES_EXCEEDED", "BLOCK_ERR_DA_INCOMPLETE",
		"BLOCK_ERR_DA_CHUNK_HASH_INVALID", "BLOCK_ERR_DA_SET_INVALID", "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID",
		"BLOCK_ERR_DA_BATCH_EXCEEDED", "BLOCK_ERR_PARSE":
		return true
	}
	return false
}

func authorityBlockMaximum(tree bool) uint64 {
	if tree {
		return Initial148MaxBlockBytes
	}
	return MaxBlockBytes
}

func cleanupSpanMaximum(tree bool) int {
	if tree {
		return 5
	}
	return 4
}

func validSpanOrder(span CleanupSpanV1, previous CleanupSpanKindV1, generation uint64, tree bool) bool {
	if tree && span.Kind == CleanupSpanGenerationV1 && previous == span.Kind {
		return generation != 0 && generation < span.GenerationID
	}
	return span.Kind > previous
}
