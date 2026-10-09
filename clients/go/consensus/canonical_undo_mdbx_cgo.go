//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// canonicalUndoFamilyV1 consumes the original qualified source, borrowing the
// same-image observations and target keys. The caller keeps those keys immutable
// through comparison and native ownership capture; this owner never reads OLD.
func canonicalUndoFamilyV1(generation, height, txCount uint64, hash *[32]byte, generated *Uint128, logical []mdbx.Mutation, observed map[Outpoint]logicalMDBXRowObservation, spent *blockSpentInputSource) ([]mdbx.Mutation, error) {
	if spent != nil {
		defer spent.discard()
	}
	if !canonicalUndoInput(generation, height, txCount, hash, generated, spent) {
		return nil, localLogicalStateFailure("invalid canonical undo input")
	}
	count := canonicalUndoCount(spent)
	var supply [16]byte
	binary.BigEndian.PutUint64(supply[:8], generated.Hi)
	binary.BigEndian.PutUint64(supply[8:], generated.Lo)
	rows := make([]mdbx.Mutation, 1, count+1)
	// The masks are identity on the original scalar and qualified compact-source domains.
	rows[0] = mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[5], Key: mdbx.UndoManifestKey(*hash), AfterKind: mdbx.AfterLiteral, Literal: mdbx.UndoManifestValue(height, supply, uint32(txCount&0xffffffff), uint32(count&0xffffffff))}
	if spent != nil {
		for tuple, ok := spent.next(); ok; tuple, ok = spent.next() {
			row, err := canonicalUndoEntry(generation, hash, tuple, logical, observed)
			if err != nil {
				return nil, err
			}
			rows = append(rows, row)
		}
	}
	if len(rows)-1 != count {
		return nil, localLogicalStateFailure("undo source count differs")
	}
	return rows, nil
}

func canonicalUndoInput(generation, height, txCount uint64, hash *[32]byte, generated *Uint128, spent *blockSpentInputSource) bool {
	if !canonicalUndoScalars(generation, height, txCount, hash, generated) {
		return false
	}
	if height == 0 {
		return spent == nil && txCount == 1 && *generated == (Uint128{})
	}
	return canonicalUndoSource(txCount, spent)
}

func canonicalUndoScalars(generation, height, txCount uint64, hash *[32]byte, generated *Uint128) bool {
	return generation != 0 && height <= 0xffffffff && txCount != 0 && txCount <= 0xffffffff && hash != nil && generated != nil
}

func canonicalUndoSource(txCount uint64, spent *blockSpentInputSource) bool {
	if spent == nil {
		return false
	}
	return spent.raw != nil && spent.count == txCount && spent.nextTx == 1 && spent.current == nil && spent.inputIndex == 0 && spent.txIndex == 0
}

func canonicalUndoCount(spent *blockSpentInputSource) int {
	if spent == nil {
		return 0
	}
	count := 0
	for _, length := range spent.spent {
		if length > 0 {
			count++
		}
	}
	return count
}

func canonicalUndoEntry(generation uint64, hash *[32]byte, tuple blockSpentInput, logical []mdbx.Mutation, observed map[Outpoint]logicalMDBXRowObservation) (mdbx.Mutation, error) {
	if err := canonicalUndoObservation(tuple, observed[tuple.outpoint]); err != nil {
		return mdbx.Mutation{}, err
	}
	key, _ := mdbx.UTXOKey(generation, tuple.outpoint.Txid, tuple.outpoint.Vout)
	target := canonicalUndoTarget(logical, key)
	if target == nil || !target.BeforePresent {
		return mdbx.Mutation{}, localLogicalStateFailure("undo source is not a removed target row")
	}
	if target.AfterKind != mdbx.AfterAbsent && target.AfterKind != mdbx.AfterLiteral {
		return mdbx.Mutation{}, localLogicalStateFailure("undo source is not a removed target row")
	}
	return mdbx.Mutation{DBI: mdbx.SchemaV2DBIs()[5], Key: mdbx.UndoEntryKey(*hash, tuple.outpoint.Txid, tuple.txIndex, tuple.inputIndex, tuple.outpoint.Vout), AfterKind: mdbx.AfterOldValueRef, RefDBI: target.DBI, RefKey: target.Key}, nil
}

func canonicalUndoObservation(tuple blockSpentInput, observation logicalMDBXRowObservation) error {
	if tuple.logicalEntryLength < 56 || tuple.logicalEntryLength > 65596 {
		return localLogicalStateFailure("undo logical length outside domain")
	}
	if !observation.present || observation.entryBytes != uint64(tuple.logicalEntryLength) {
		return localLogicalStateFailure("undo source length differs from observed target")
	}
	return nil
}

// Search the original ordered plan; a reference aliases its actual target key.
func canonicalUndoTarget(logical []mdbx.Mutation, key []byte) *mdbx.Mutation {
	i := sort.Search(len(logical), func(i int) bool {
		row := &logical[i]
		return row.DBI.Rank > 1 || row.DBI.Rank == 1 && bytes.Compare(row.Key, key) >= 0
	})
	if i == len(logical) {
		return nil
	}
	row := &logical[i]
	if row.DBI.Rank != 1 || !bytes.Equal(row.Key, key) {
		return nil
	}
	return row
}

// canonicalUndoFamilyEqualV1 requires the active original Reader and a complete
// canonical immutable expected family. Physical OLD spans have their actual
// native widths, independently of expected/ref widths, through visitor expiry.
func canonicalUndoFamilyEqualV1(reader *mdbx.Reader, hash *[32]byte, expected []mdbx.Mutation) (bool, error) {
	count := 0
	err := reader.VisitLargeImageV1(mdbx.LargeImageSelectorV1{Kind: mdbx.LargeImageUndoFamilyV1, Hash: *hash}, func(row mdbx.LargeImageRowV1) error {
		if count == len(expected) || !bytes.Equal(row.Key(), expected[count].Key) {
			return selectedSideDefect("undo family has an unexpected member")
		}
		if err := canonicalUndoRowEqual(reader, row, &expected[count]); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	if count != len(expected) {
		return false, selectedSideDefect("undo family is incomplete")
	}
	return true, nil
}

func canonicalUndoRowEqual(reader *mdbx.Reader, row mdbx.LargeImageRowV1, expected *mdbx.Mutation) error {
	value := expected.Literal
	if expected.AfterKind == mdbx.AfterOldValueRef {
		var present bool
		var err error
		value, present, err = reader.Get(expected.RefDBI, expected.RefKey)
		if err != nil {
			return err
		}
		if !present {
			return selectedSideDefect("undo source absent")
		}
	}
	if !row.Present() || row.Length() != uint64(len(value)) {
		return selectedSideDefect("undo value length differs")
	}
	return canonicalUndoBytesEqual(row, value)
}

func canonicalUndoBytesEqual(row mdbx.LargeImageRowV1, value []byte) error {
	var scratch [65536]byte
	for offset := 0; offset < len(value); {
		window := min(len(scratch), len(value)-offset)
		n, err := row.ReadAt(scratch[:window], uint64(offset))
		if err != nil {
			return err
		}
		if n != window || !bytes.Equal(scratch[:window], value[offset:offset+window]) {
			return selectedSideDefect("undo value differs")
		}
		offset += window
	}
	return nil
}
