//go:build cgo && (darwin || linux) && (amd64 || arm64)

package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/internal/mdbx"
)

// ReplayStartupDecisionV1 describes the dormant startup diagnostic action.
type ReplayStartupDecisionV1 uint8

const (
	ReplayStartupNoActionV1        ReplayStartupDecisionV1 = 0
	ReplayStartupVerifiedV1        ReplayStartupDecisionV1 = 1
	ReplayStartupRetryV1           ReplayStartupDecisionV1 = 2
	ReplayStartupCloseQuarantineV1 ReplayStartupDecisionV1 = 3
)

// ReplayStartupOutcomeV1 preserves the exact readonly native-final error.
// CanonicalTruth is always OLD; this operation performs no durable writes.
type ReplayStartupOutcomeV1 struct {
	Verified       bool
	Decision       ReplayStartupDecisionV1
	Result         string
	CanonicalTruth string
	Err            error
}

var (
	errInvalidStartupNetworkContext = errors.New("invalid startup network context")
	startupJoinType                 = reflect.TypeOf(errors.Join(errInvalidStartupNetworkContext))
)

type replayStartupCheck struct {
	chainID, genesisHash       [32]byte
	readResource               string
	observedErr                error
	observedResult             string
	completedCanonicalPositive bool
}

type startupIndexTipV1 struct {
	Present bool
	Height  uint64
	Hash    [32]byte
	Work    [40]byte
}

// VerifyPersistedReplayStartupMDBX verifies current active and the entire committed
// replay target in one snapshot before the native owner publishes permission.
// It is a dormant REPLAY-only operation, not public startup or recovery execution.
func VerifyPersistedReplayStartupMDBX(store *mdbx.Store, reservations *mdbx.OperationReservationOwner, chainID, genesisHash [32]byte) ReplayStartupOutcomeV1 {
	out := ReplayStartupOutcomeV1{CanonicalTruth: "OLD"}
	if chainID == ([32]byte{}) || genesisHash == ([32]byte{}) {
		out.Err = errInvalidStartupNetworkContext
		return out
	}
	if store == nil {
		out.Err = store.View(nil)
		return out
	}
	c := replayStartupCheck{chainID: chainID, genesisHash: genesisHash}
	ran := false
	out.Err = reservations.WithReservation(4096, func() error {
		ran = true
		raw := store.StartupVerifyCanonicalV1(c.verify)
		out = startupOutcome(raw, c.projectResult(raw))
		return raw
	})
	if !ran && mdbx.IsOperationReservationCapacity(out.Err) {
		out.Decision = ReplayStartupRetryV1
		out.Result = "LOCAL_RESOURCE_UNAVAILABLE(storage_capacity)"
	}
	return out
}

func startupOutcome(raw error, result string) ReplayStartupOutcomeV1 {
	out := ReplayStartupOutcomeV1{CanonicalTruth: "OLD", Err: raw, Result: result}
	switch {
	case raw == nil:
		out.Verified, out.Decision = true, ReplayStartupVerifiedV1
	case result == "TERMINAL_STORE_INTEGRITY(canonical)":
		out.Decision = ReplayStartupCloseQuarantineV1
	case result != "" && result != "TERMINAL_LOCAL_INVARIANT(evidence)":
		out.Decision = ReplayStartupRetryV1
	}
	return out
}

func (c *replayStartupCheck) positive(message string) error {
	err := errors.New(message)
	c.observedErr, c.observedResult = err, "TERMINAL_STORE_INTEGRITY(canonical)"
	c.completedCanonicalPositive = true
	return err
}

func (c *replayStartupCheck) observed(err error) error {
	if err == nil {
		c.readResource = ""
		return nil
	}
	c.observedErr = err
	c.observedResult = ClassifySelectedSideFailureMDBX(err, mdbx.UpdateStagePrewrite, c.readResource, nil, "")
	if c.observedResult == "TERMINAL_STORE_INTEGRITY(canonical)" {
		c.completedCanonicalPositive = true
	}
	return err
}

func (c *replayStartupCheck) verify(r *mdbx.Reader) (mdbx.StartupCanonicalCompletionV1, error) {
	a, err := c.authority(r)
	if err != nil {
		return mdbx.StartupCanonicalNotCompleteV1, err
	}
	tip, err := c.index(r, a.ActiveGenerationID, nil)
	if err != nil {
		return mdbx.StartupCanonicalNotCompleteV1, err
	}
	b, u := startupBounds(&tip, a.ActiveProfile)
	if a.B != b || a.U != u {
		return mdbx.StartupCanonicalNotCompleteV1, c.positive("startup active bounds mismatch")
	}
	tip = startupIndexTipV1{}
	if _, err = c.index(r, a.Replay.TargetGenerationID, a.Replay); err != nil {
		return mdbx.StartupCanonicalNotCompleteV1, err
	}
	return mdbx.StartupCanonicalActiveAndReplayCompleteV1, nil
}

// Authority admission owns full decode, exact exclusion, phase, and immutable
// network agreement in that order, before any canonical data observation.
func (c *replayStartupCheck) authority(r *mdbx.Reader) (mdbx.StorageAuthorityV1, error) {
	a, err := r.ReadStorageAuthorityV1()
	if err != nil {
		return mdbx.StorageAuthorityV1{}, c.observed(err)
	}
	if a.ExcludedInvalidBranch != nil && !startupExclusionToken(a.ExcludedInvalidBranch.ExactConsensusError) {
		return mdbx.StorageAuthorityV1{}, c.positive("invalid startup exclusion token")
	}
	if a.Phase != mdbx.StoragePhaseReplayV1 {
		err = &mdbx.EngineError{Class: mdbx.EngineInvalidInput, Operation: "view", Code: 22, Diagnostic: "persisted authority is not REPLAY"}
		return mdbx.StorageAuthorityV1{}, c.observed(err)
	}
	if a.Replay.Target.ChainID != c.chainID || a.Replay.Target.GenesisHash != c.genesisHash {
		return mdbx.StorageAuthorityV1{}, c.positive("startup replay network identity mismatch")
	}
	return a, nil
}

func startupBounds(tip *startupIndexTipV1, profile mdbx.StorageProfileV1) (b, u uint64) {
	if !tip.Present {
		return 0, 0
	}
	if tip.Height >= 1440 {
		u = tip.Height - 1439
	}
	if profile == mdbx.StorageProfilePrunedV1 && tip.Height >= 15120 {
		b = tip.Height - 15119
	}
	return b, u
}

func startupReadResource(replay *mdbx.ReplayV1) string {
	if replay != nil {
		return "LOCAL_RESOURCE_UNAVAILABLE(recovery_artifact)"
	}
	return "LOCAL_RESOURCE_UNAVAILABLE(canonical_artifact_read)"
}

func (c *replayStartupCheck) pull(r *mdbx.Reader, rank uint8, generation uint64, after []byte, resource string) (mdbx.PrefixRow, bool, error) {
	c.readResource = resource
	row, found, err := r.StartupCanonicalNextV1(mdbx.SchemaV2DBIs()[rank], generation, after)
	return row, found, c.observed(err)
}

func (c *replayStartupCheck) get(r *mdbx.Reader, rank uint8, key []byte, resource string) ([]byte, bool, error) {
	c.readResource = resource
	value, found, err := r.Get(mdbx.SchemaV2DBIs()[rank], key)
	return value, found, c.observed(err)
}

func (c *replayStartupCheck) index(r *mdbx.Reader, generation uint64, replay *mdbx.ReplayV1) (startupIndexTipV1, error) {
	var tip startupIndexTipV1
	var after []byte
	resource := startupReadResource(replay)
	for {
		row, found, err := c.pull(r, 2, generation, after, resource)
		if err != nil {
			return startupIndexTipV1{}, err
		}
		if !found {
			break
		}
		if err := c.forward(r, row, &tip, replay, resource); err != nil {
			return startupIndexTipV1{}, err
		}
		after = row.Key
	}
	if err := c.inverse(r, generation, resource); err != nil {
		return startupIndexTipV1{}, err
	}
	if err := c.cursor(&tip, replay); err != nil {
		return startupIndexTipV1{}, err
	}
	return tip, nil
}

func (c *replayStartupCheck) forward(r *mdbx.Reader, row mdbx.PrefixRow, previous *startupIndexTipV1, replay *mdbx.ReplayV1, resource string) error {
	height := binary.BigEndian.Uint64(row.Key[8:])
	if err := c.height(height, previous, replay); err != nil {
		return err
	}
	hash := [32]byte(row.Value[:32])
	header, present, err := c.get(r, 3, hash[:], resource)
	if err != nil {
		return err
	}
	if !present {
		return c.positive("startup required header is absent")
	}
	work, err := c.header(row.Value, header, hash, previous)
	if err != nil {
		return err
	}
	var key [40]byte
	copy(key[:8], row.Key[:8])
	copy(key[8:], hash[:])
	inverse, present, err := c.get(r, 7, key[:], resource)
	if err != nil {
		return err
	}
	if !present || binary.BigEndian.Uint64(inverse) != height {
		return c.positive("startup inverse height mismatch")
	}
	// Old rolling facts have reached their last consumer. Replace them only
	// after this row's header/work and exact inverse probe have completed.
	*previous = startupIndexTipV1{Present: true, Height: height, Hash: hash, Work: work}
	return nil
}

func (c *replayStartupCheck) height(height uint64, previous *startupIndexTipV1, replay *mdbx.ReplayV1) error {
	expected := uint64(0)
	if previous.Present {
		expected = previous.Height + 1
	}
	if height > 0xffffffff || height != expected {
		return c.positive("startup canonical height mismatch")
	}
	if replay != nil {
		if replay.Cursor.Kind == mdbx.ReplayCursorPreGenesisV1 || height > replay.Cursor.Height {
			return c.positive("startup target extends beyond cursor")
		}
	}
	return nil
}

func (c *replayStartupCheck) header(entry, raw []byte, hash [32]byte, previous *startupIndexTipV1) ([40]byte, error) {
	h, err := ParseBlockHeaderBytes(raw)
	if err != nil {
		return [40]byte{}, c.positive("startup required header malformed")
	}
	actual, err := BlockHash(raw)
	if err != nil || actual != hash {
		return [40]byte{}, c.positive("startup header identity mismatch")
	}
	if !previous.Present && hash != c.genesisHash {
		return [40]byte{}, c.positive("startup genesis identity mismatch")
	}
	if h.PrevBlockHash != previous.Hash || !bytes.Equal(entry[32:64], h.PrevBlockHash[:]) {
		return [40]byte{}, c.positive("startup parent mismatch")
	}
	return c.work(entry[64:104], h.Target, &previous.Work)
}

func (c *replayStartupCheck) work(stored []byte, target [32]byte, previous *[40]byte) ([40]byte, error) {
	work, err := WorkFromTarget(target)
	if err != nil {
		return [40]byte{}, c.positive("startup header target mismatch")
	}
	work.Add(work, new(big.Int).SetBytes(previous[:]))
	// The only accepted 289-bit value is the inclusive upper endpoint 2^288.
	if work.BitLen() > 289 || work.BitLen() == 289 && work.TrailingZeroBits() != 288 {
		return [40]byte{}, c.positive("startup cumulative work outside domain")
	}
	var sum [40]byte
	work.FillBytes(sum[:])
	if !bytes.Equal(stored, sum[:]) {
		return [40]byte{}, c.positive("startup cumulative work mismatch")
	}
	return sum, nil
}

func (c *replayStartupCheck) inverse(r *mdbx.Reader, generation uint64, resource string) error {
	var after []byte
	for {
		row, found, err := c.pull(r, 7, generation, after, resource)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if err := c.inverseRow(r, generation, row, resource); err != nil {
			return err
		}
		after = row.Key
	}
}

func (c *replayStartupCheck) inverseRow(r *mdbx.Reader, generation uint64, row mdbx.PrefixRow, resource string) error {
	height := binary.BigEndian.Uint64(row.Value)
	if height > 0xffffffff {
		return c.positive("startup inverse height outside domain")
	}
	var key [16]byte
	binary.BigEndian.PutUint64(key[:8], generation)
	binary.BigEndian.PutUint64(key[8:], height)
	forward, present, err := c.get(r, 2, key[:], resource)
	if err != nil {
		return err
	}
	if !present || !bytes.Equal(forward[:32], row.Key[8:]) {
		return c.positive("startup extra or disagreeing inverse")
	}
	return nil
}

func (c *replayStartupCheck) cursor(tip *startupIndexTipV1, replay *mdbx.ReplayV1) error {
	if replay == nil {
		return nil
	}
	if replay.Cursor.Kind == mdbx.ReplayCursorPreGenesisV1 {
		if tip.Present {
			return c.positive("startup PRE_GENESIS target is not empty")
		}
		return nil
	}
	if !tip.Present || tip.Height != replay.Cursor.Height || tip.Hash != replay.Cursor.BlockHash {
		return c.positive("startup replay cursor mismatch")
	}
	return c.targetTip(tip, &replay.Target)
}

func (c *replayStartupCheck) targetTip(tip *startupIndexTipV1, target *mdbx.RecoveryTargetV1) error {
	if tip.Height == target.TipHeight && (tip.Hash != target.TipHash || tip.Work != target.CumulativeChainwork) {
		return c.positive("startup replay target tip mismatch")
	}
	return nil
}

func startupExclusionToken(token []byte) bool {
	switch string(token) {
	case "CONSENSUS_INVALID(TX_ERR_PARSE)", "CONSENSUS_INVALID(TX_ERR_VALUE_CONSERVATION)", "CONSENSUS_INVALID(TX_ERR_TX_NONCE_INVALID)", "CONSENSUS_INVALID(TX_ERR_SEQUENCE_INVALID)", "CONSENSUS_INVALID(TX_ERR_NONCE_REPLAY)", "CONSENSUS_INVALID(TX_ERR_SIG_INVALID)", "CONSENSUS_INVALID(TX_ERR_SIG_ALG_INVALID)", "CONSENSUS_INVALID(TX_ERR_SIGHASH_TYPE_INVALID)", "CONSENSUS_INVALID(TX_ERR_SIG_NONCANONICAL)", "CONSENSUS_INVALID(TX_ERR_TIMELOCK_NOT_MET)", "CONSENSUS_INVALID(TX_ERR_WITNESS_OVERFLOW)", "CONSENSUS_INVALID(TX_ERR_COVENANT_TYPE_INVALID)", "CONSENSUS_INVALID(TX_ERR_VAULT_MALFORMED)", "CONSENSUS_INVALID(TX_ERR_VAULT_PARAMS_INVALID)", "CONSENSUS_INVALID(TX_ERR_VAULT_KEYS_NOT_CANONICAL)", "CONSENSUS_INVALID(TX_ERR_VAULT_WHITELIST_NOT_CANONICAL)", "CONSENSUS_INVALID(TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN)", "CONSENSUS_INVALID(TX_ERR_VAULT_OWNER_AUTH_REQUIRED)", "CONSENSUS_INVALID(TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN)", "CONSENSUS_INVALID(TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN)", "CONSENSUS_INVALID(TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_PROGRAM_TOO_LARGE)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_ENVELOPE_TOO_LARGE)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_CMR_MISMATCH)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_DECODE)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_JET_DISALLOWED)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_BUDGET_EXCEEDED)", "CONSENSUS_INVALID(TX_ERR_SIMPLICITY_REJECTED)", "CONSENSUS_INVALID(TX_ERR_MISSING_UTXO)", "CONSENSUS_INVALID(TX_ERR_COINBASE_IMMATURE)",
		"CONSENSUS_INVALID(BLOCK_ERR_LINKAGE_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_MERKLE_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_WITNESS_COMMITMENT)", "CONSENSUS_INVALID(BLOCK_ERR_POW_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_TARGET_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_TIMESTAMP_OLD)", "CONSENSUS_INVALID(BLOCK_ERR_TIMESTAMP_FUTURE)", "CONSENSUS_INVALID(BLOCK_ERR_COINBASE_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_SUBSIDY_EXCEEDED)", "CONSENSUS_INVALID(BLOCK_ERR_STATE_CAP_EXCEEDED)", "CONSENSUS_INVALID(BLOCK_ERR_WEIGHT_EXCEEDED)", "CONSENSUS_INVALID(BLOCK_ERR_ANCHOR_BYTES_EXCEEDED)", "CONSENSUS_INVALID(BLOCK_ERR_DA_INCOMPLETE)", "CONSENSUS_INVALID(BLOCK_ERR_DA_CHUNK_HASH_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_DA_SET_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID)", "CONSENSUS_INVALID(BLOCK_ERR_DA_BATCH_EXCEEDED)", "CONSENSUS_INVALID(BLOCK_ERR_PARSE)":
		return true
	}
	return false
}

func (c *replayStartupCheck) projectResult(raw error) string {
	if c.completedCanonicalPositive {
		return "TERMINAL_STORE_INTEGRITY(canonical)"
	}
	var pending [4]error
	pending[0] = raw
	count, first := 1, ""
	for count != 0 {
		count--
		part := pending[count]
		pending[count] = nil
		if startupNilError(part) {
			continue
		}
		next, children := c.projectLeaf(part)
		if startupTerminal(next) {
			return next
		}
		if first == "" {
			first = next
		}
		if len(children) > len(pending)-count {
			return "TERMINAL_LOCAL_INVARIANT(evidence)"
		}
		for i := len(children) - 1; i >= 0; i-- {
			pending[count], count = children[i], count+1
		}
	}
	return first
}

// A bound application leaf and native diagnostic Cause remain opaque. Only the
// native close/BUSY PRIMARY-composition edge enters the finite pending stack.
func (c *replayStartupCheck) projectLeaf(part error) (string, []error) {
	// Identity and direct dynamic type are this producer's closed provenance
	// boundary; generic errors.Is/As traversal would admit foreign applications.
	if any(part) == any(c.observedErr) {
		return c.observedResult, nil
	}
	if reflect.TypeOf(part) == startupJoinType {
		join, ok := any(part).(interface{ Unwrap() []error })
		if !ok {
			return "TERMINAL_LOCAL_INVARIANT(evidence)", nil
		}
		return "", join.Unwrap()
	}
	e, ok := any(part).(*mdbx.EngineError)
	if !ok {
		return "TERMINAL_LOCAL_INVARIANT(evidence)", nil
	}
	next := ClassifySelectedSideFailureMDBX(e, mdbx.UpdateStagePrewrite, "", nil, "")
	if e.Operation == "close" && e.Code == -30778 && e.Cause != nil {
		return next, []error{e.Cause}
	}
	return next, nil
}

func startupTerminal(result string) bool {
	return result == "TERMINAL_STORE_INTEGRITY(canonical)" || result == "TERMINAL_LOCAL_INVARIANT(evidence)"
}

func startupNilError(err error) bool {
	if err == nil {
		return true
	}
	v := reflect.ValueOf(err)
	kind := v.Kind()
	switch {
	case kind == reflect.Chan, kind == reflect.Func, kind == reflect.Interface, kind == reflect.Map, kind == reflect.Pointer, kind == reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
