//go:build rubin_da_observer

package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var reorgRefusalIDs = []string{"REORG_TERMINAL_PERSISTENCE_NEW_NO_OWNER", "REORG_FAILED_TRANSITION_NO_OWNER"}

type reorgRefusalInput struct {
	Source   string `json:"source_context"`
	Policy   string `json:"policy_context"`
	Chain    string `json:"chain_context"`
	Prestate string `json:"prestate"`
	Scenario string `json:"reorg_scenario"`
	Control  string `json:"transition_control"`
}

type reorgRefusalBlock struct {
	Ref       string          `json:"block_ref"`
	Height    uint64          `json:"height"`
	Hex       string          `json:"block_hex"`
	Hash      string          `json:"block_hash"`
	Parent    string          `json:"parent_hash"`
	Target    json.RawMessage `json:"target"`
	Timestamp json.RawMessage `json:"timestamp"`
	TxOrder   json.RawMessage `json:"tx_order"`
}

type reorgRefusalCall struct {
	Phase string   `json:"phase"`
	Ref   string   `json:"block_ref"`
	Times []uint64 `json:"prev_timestamps"`
}

type reorgRefusalFixture struct {
	Source struct {
		Source     string `json:"source"`
		Entrypoint string `json:"entrypoint"`
	}
	Policy struct {
		Fee        uint64          `json:"current_mempool_min_fee_rate"`
		DAFee      uint64          `json:"min_da_fee_rate"`
		RelayValue json.RawMessage `json:"min_relay_output_value"`
		Size       uint64          `json:"effective_da_mempool_size"`
		Count      uint64          `json:"complete_set_max_count"`
		Payload    uint64          `json:"pinned_payload_max"`
		TTL        uint64          `json:"orphan_ttl_blocks"`
	}
	Chain struct {
		ID              string          `json:"chain_id"`
		Height          uint64          `json:"height"`
		AdmissionHeight json.RawMessage `json:"admission_height"`
		Tip             string          `json:"tip_hash"`
		UTXOs           json.RawMessage `json:"utxos"`
		Prefix          struct {
			Blocks []reorgRefusalBlock `json:"blocks"`
			Index  []struct {
				Hash   string `json:"block_hash"`
				Ref    string `json:"block_ref"`
				Height uint64 `json:"height"`
			} `json:"canonical_index"`
			Height     uint64          `json:"tip_height"`
			Tip        string          `json:"tip_hash"`
			Target     json.RawMessage `json:"tip_target"`
			Work       json.RawMessage `json:"chain_work"`
			Generated  json.RawMessage `json:"already_generated"`
			Derivation json.RawMessage `json:"required_utxo_derivation"`
			UTXOs      json.RawMessage `json:"required_utxos"`
			Config     struct {
				ID     string `json:"chain_id"`
				Target string `json:"expected_target"`
			} `json:"public_engine_config"`
		} `json:"canonical_prefix"`
	}
	Scenario struct {
		Prefix  string `json:"canonical_prefix_ref"`
		Binding struct {
			Phase  string `json:"phase"`
			Policy string `json:"policy_context"`
		} `json:"mempool_binding"`
		Old          []reorgRefusalBlock `json:"old_branch"`
		Win          []reorgRefusalBlock `json:"winning_branch"`
		Calls        []reorgRefusalCall  `json:"public_calls"`
		Disconnected json.RawMessage     `json:"disconnected_order"`
	}
	Prestate struct {
		Records  []any `json:"record_image"`
		Locators []any `json:"locator_image"`
		Claims   []any `json:"claim_image"`
		Orphans  struct {
			Global   uint64 `json:"global_bytes"`
			IDs      []any  `json:"per_da_id"`
			Overhead uint64 `json:"commit_overhead_bytes"`
			Quotas   []any  `json:"per_quota"`
		} `json:"orphan_accounting"`
		Counters struct {
			Staged   uint64 `json:"staged_retained_bytes"`
			Complete uint64 `json:"complete_retained_bytes"`
			Count    uint64 `json:"complete_set_count"`
			Payload  uint64 `json:"complete_payload_bytes"`
			Sequence uint64 `json:"accepted_sequence"`
		} `json:"retained_counters"`
	}
}

func reorgRefusalRows(raw []byte) ([]daNodeObserverCase, reorgRefusalFixture, error) {
	var corpus daNodeObserverCorpus
	var fixture reorgRefusalFixture
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return nil, fixture, err
	}
	var inputs map[string]map[string]json.RawMessage
	if err := json.Unmarshal(corpus.InputFixtures, &inputs); err != nil {
		return nil, fixture, err
	}
	for _, item := range []struct {
		group, key string
		dst        any
	}{
		{"source_contexts", "DETACHED_REORG", &fixture.Source},
		{"policy_contexts", "ACCEPT_DA", &fixture.Policy},
		{"chain_contexts", "CHAIN_100", &fixture.Chain},
		{"prestates", "EMPTY_DA", &fixture.Prestate},
		{"reorg_scenarios", "DA_ONLY_LITERAL_REJECT", &fixture.Scenario},
	} {
		if err := decodeDANodeObserverInput(inputs[item.group][item.key], item.dst); err != nil {
			return nil, fixture, fmt.Errorf("reorg fixture %s: %w", item.key, err)
		}
	}
	rows := make([]daNodeObserverCase, 0, 2)
	for ordinal, rawCase := range corpus.Cases {
		var row daNodeObserverCase
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rawCase, &row); err != nil {
			return nil, fixture, err
		}
		if err := json.Unmarshal(row.Input, &fields); err != nil {
			return nil, fixture, err
		}
		if _, owned := fields["transition_control"]; !owned {
			continue
		}
		if len(rows) >= 2 || row.ID != reorgRefusalIDs[len(rows)] || ordinal != 19+len(rows) {
			return nil, fixture, fmt.Errorf("reorg census: unexpected owned row %s at %d", row.ID, ordinal)
		}
		rows = append(rows, row)
	}
	if len(rows) != 2 {
		return nil, fixture, fmt.Errorf("reorg census: expected two owned rows")
	}
	return rows, fixture, nil
}

func reorgRefusalInputChecked(raw json.RawMessage) (reorgRefusalInput, error) {
	var input reorgRefusalInput
	if err := decodeDANodeObserverInput(raw, &input); err != nil {
		return input, err
	}
	for _, field := range []struct{ name, got, want string }{
		{"source_context", input.Source, "DETACHED_REORG"},
		{"policy_context", input.Policy, "ACCEPT_DA"},
		{"chain_context", input.Chain, "CHAIN_100"},
		{"prestate", input.Prestate, "EMPTY_DA"},
		{"reorg_scenario", input.Scenario, "DA_ONLY_LITERAL_REJECT"},
	} {
		if field.got != field.want {
			return input, fmt.Errorf("reorg input %s", field.name)
		}
	}
	if input.Control != "TERMINAL_PERSISTENCE_NEW" && input.Control != "LOCAL_PERSISTENCE_ERROR_PRECOMMIT_VERIFIED_WRITE" {
		return input, fmt.Errorf("reorg input transition_control")
	}
	return input, nil
}

func reorgRefusalDAPremise(block *consensus.ParsedBlock) error {
	if len(block.Txs) < 2 {
		return fmt.Errorf("reorg disconnected block: no DA rows")
	}
	for _, tx := range block.Txs[1:] {
		if tx.TxKind != 1 && tx.TxKind != 2 {
			return fmt.Errorf("reorg disconnected block: standard row")
		}
	}
	return nil
}

func reorgRefusalBlocks(f reorgRefusalFixture) ([][]byte, []string, error) {
	prefix, scenario := f.Chain.Prefix, f.Scenario
	if len(prefix.Blocks) != 101 || len(scenario.Old) != 1 || len(scenario.Win) != 2 || len(scenario.Calls) != 104 {
		return nil, nil, fmt.Errorf("reorg fixture block/call counts")
	}
	for _, field := range []struct{ name, got, want string }{
		{"source", f.Source.Source, "DETACHED_REORG"},
		{"entrypoint", f.Source.Entrypoint, "SyncEngine.ApplyBlockWithReorg"},
		{"chain_id", f.Chain.ID, daNodeObserverHexID(devnetGenesisChainID)},
		{"public_engine_config.chain_id", prefix.Config.ID, daNodeObserverHexID(devnetGenesisChainID)},
		{"public_engine_config.expected_target", prefix.Config.Target, daNodeObserverHexID(consensus.POW_LIMIT)},
		{"canonical_prefix_ref", scenario.Prefix, "CHAIN_100"},
		{"mempool_binding.phase", scenario.Binding.Phase, "AFTER_CANONICAL_PREFIX"},
		{"mempool_binding.policy_context", scenario.Binding.Policy, "ACCEPT_DA"},
	} {
		if field.got != field.want {
			return nil, nil, fmt.Errorf("reorg fixture %s", field.name)
		}
	}
	blocks := append(slices.Clone(prefix.Blocks), scenario.Old...)
	blocks = append(blocks, scenario.Win...)
	data, hashes := make([][]byte, len(blocks)), make([]string, len(blocks))
	heights := make(map[string]uint64)
	for i, block := range blocks {
		raw, err := hex.DecodeString(block.Hex)
		if err != nil {
			return nil, nil, fmt.Errorf("reorg block_hex %s: %w", block.Ref, err)
		}
		parsed, err := consensus.ParseBlockBytes(raw)
		if err != nil {
			return nil, nil, err
		}
		hash, err := consensus.BlockHash(parsed.HeaderBytes)
		if err != nil || daNodeObserverHexID(hash) != block.Hash {
			return nil, nil, fmt.Errorf("reorg block_hash %s", block.Ref)
		}
		if daNodeObserverHexID(parsed.Header.PrevBlockHash) != block.Parent {
			return nil, nil, fmt.Errorf("reorg parent_hash %s", block.Ref)
		}
		parentHeight, parentExists := heights[block.Parent]
		if (i == 0 && block.Height != 0) || (i != 0 && (!parentExists || block.Height != parentHeight+1)) {
			return nil, nil, fmt.Errorf("reorg height %s", block.Ref)
		}
		if i == 0 && hash != devnetGenesisBlockHash {
			return nil, nil, fmt.Errorf("reorg genesis hash")
		}
		phase := "CANONICAL_PREFIX"
		if i == 101 {
			phase = "OLD_BRANCH"
			if err := reorgRefusalDAPremise(parsed); err != nil {
				return nil, nil, err
			}
		} else if i > 101 {
			phase = "WINNING_BRANCH"
		}
		if scenario.Calls[i].Ref != block.Ref || scenario.Calls[i].Phase != phase {
			return nil, nil, fmt.Errorf("reorg public_calls %d", i)
		}
		data[i], hashes[i], heights[block.Hash] = raw, daNodeObserverHexID(hash), block.Height
	}
	if blocks[101].Ref != "DA_ONLY_OLD_101" || blocks[102].Ref != "DA_ONLY_WIN_101" || blocks[103].Ref != "DA_ONLY_WIN_102" {
		return nil, nil, fmt.Errorf("reorg branch block_ref")
	}
	if len(prefix.Index) != 101 {
		return nil, nil, fmt.Errorf("reorg canonical_index count")
	}
	for i, entry := range prefix.Index {
		if entry.Hash != hashes[i] || entry.Ref != blocks[i].Ref || entry.Height != blocks[i].Height {
			return nil, nil, fmt.Errorf("reorg canonical_index %d", i)
		}
	}
	return data, hashes, nil
}

type reorgRefusalSnapshot struct {
	Counts                 DAObserverOwnerCounts
	StandardCalls, DACalls uint64
	Image                  DAObserverStateImage
	TxIDs                  [][32]byte
	UsedBytes              int
	AdmissionSeq, Fee      uint64
	StandardMap, DAMap     any // Keep both original maps alive while comparing their identities.
	OwnerTip               PendingOutpointTip
	Generation, HighWater  uint64
	Transition             bool
	Durable, Published     []string
	Tip                    canonicalTipScalars
	View                   chainStateView
	Digest                 [32]byte
}

func readReorgRefusal(e *SyncEngine, mp *Mempool, relay *DARelayState, daCalls *atomic.Uint64, post bool) (reorgRefusalSnapshot, error) {
	var out reorgRefusalSnapshot
	owner := mp.PendingOutpointOwner()
	out.Counts = DAObserverReadOwnerCounts(owner)
	counts := mp.AdmissionCounts()
	out.StandardCalls = counts.Accepted + counts.Conflict + counts.Rejected + counts.Unavailable
	out.DACalls = daCalls.Load()
	if !post {
		out.TxIDs = mp.AllTxIDs()
		slices.SortFunc(out.TxIDs, compareDAObserverID)
	}
	relay.mu.Lock()
	owner.mu.Lock()
	out.Image = observerImageLocked(relay, owner).Image
	var err error
	if post {
		_, err = validateCanonicalDARetainedSnapshot(relay, owner)
	}
	owner.mu.Unlock()
	relay.mu.Unlock()
	if err != nil {
		return out, err
	}
	if post {
		out.TxIDs = mp.AllTxIDs()
		slices.SortFunc(out.TxIDs, compareDAObserverID)
	}
	index, _, err := loadBlockStoreIndex(e.blockStore.indexPath)
	if err != nil {
		return out, err
	}
	out.Durable = index.Canonical
	if post {
		out.Tip = chainTipScalarsOf(e.chainState)
		out.Published, err = decodeCanonicalIndexSequence(e.blockStore.visibleIndexBytes())
		if err != nil {
			return out, err
		}
	}
	relay.mu.Lock()
	owner.mu.Lock()
	out.OwnerTip, out.Generation, out.HighWater, out.Transition = owner.stableTip, owner.generation, owner.tokenHighWater, owner.inTransition
	owner.mu.Unlock()
	relay.mu.Unlock()
	mp.mu.RLock()
	out.StandardMap, out.UsedBytes, out.AdmissionSeq, out.Fee = mp.relations.forward, mp.usedBytes, mp.lastAdmissionSeq, mp.currentMinFeeRate
	mp.mu.RUnlock()
	relay.mu.Lock()
	out.DAMap = relay.sets
	relay.mu.Unlock()
	out.View, out.Digest = e.chainState.view(), e.chainState.StateDigest()
	return out, err
}

type reorgRefusalFault struct {
	Path, Control string
	Planned       []string
	Cause         error
	Saved         func(string, []byte, os.FileMode) error
	Calls         int
	Failure       error
}

func (f *reorgRefusalFault) write(path string, raw []byte, mode os.FileMode) error {
	if path != f.Path {
		return f.Saved(path, raw, mode)
	}
	f.Calls++
	sequence, err := decodeCanonicalIndexSequence(raw)
	if f.Calls != 1 || err != nil || !slices.Equal(sequence, f.Planned) {
		f.Failure = fmt.Errorf("reorg control: intercept count or planned index")
		return f.Failure
	}
	stage := atomicWriteBeforeNamespaceCommit
	if f.Control == "TERMINAL_PERSISTENCE_NEW" {
		if err := f.Saved(path, raw, mode); err != nil {
			f.Failure = fmt.Errorf("reorg control: saved write: %w", err)
			return err
		}
		stage = atomicWriteAfterNamespaceCommit
	}
	return newAtomicWriteError(stage, path, atomicWriteOverwrite, f.Cause)
}

type reorgRefusalObservation struct {
	Before, After reorgRefusalSnapshot
	Old, New      []string
	Summary       *ChainStateConnectSummary
	Err, Cause    error
	IndexPath     string
	Latched       bool
}

func (f *reorgRefusalFault) check() error {
	if f.Calls != 1 || f.Failure != nil {
		return fmt.Errorf("reorg control not applied: count=%d failure=%v", f.Calls, f.Failure)
	}
	return nil
}

func observeReorgRefusal(row daNodeObserverCase, f reorgRefusalFixture, dir string, armed, beforeWrite bool) (reorgRefusalObservation, error) {
	var out reorgRefusalObservation
	input, err := reorgRefusalInputChecked(row.Input)
	if err != nil {
		return out, err
	}
	blocks, hashes, err := reorgRefusalBlocks(f)
	if err != nil {
		return out, err
	}
	store, err := CreateBlockStore(BlockStorePath(dir))
	if err != nil {
		return out, err
	}
	target := consensus.POW_LIMIT
	engine, err := NewSyncEngine(NewChainState(), store, DefaultSyncConfig(&target, devnetGenesisChainID, ChainStatePath(dir)))
	if err != nil {
		return out, err
	}
	var mp *Mempool
	var relay *DARelayState
	var daCalls atomic.Uint64
	for i, raw := range blocks[:len(blocks)-1] {
		if _, err := engine.ApplyBlockWithReorg(raw, f.Scenario.Calls[i].Times); err != nil {
			return out, fmt.Errorf("reorg replay %d: %w", i, err)
		}
		if i == 100 {
			tip := chainTipScalarsOf(engine.chainState)
			if tip.height != f.Chain.Height || daNodeObserverHexID(tip.tipHash) != f.Chain.Tip ||
				tip.height != f.Chain.Prefix.Height || daNodeObserverHexID(tip.tipHash) != f.Chain.Prefix.Tip {
				return out, fmt.Errorf("reorg prefix tip")
			}
			index, _, err := loadBlockStoreIndex(store.indexPath)
			if err != nil || !slices.Equal(index.Canonical, hashes[:101]) {
				return out, fmt.Errorf("reorg durable prefix: %v", err)
			}
			config := DefaultMempoolConfig()
			config.MinDaFeeRate = f.Policy.DAFee
			mp, err = NewMempoolWithConfig(engine.chainState, store, devnetGenesisChainID, config)
			if err != nil {
				return out, err
			}
			engine.SetMempool(mp)
			relay = engine.DARelayState()
			if relay == nil {
				return out, fmt.Errorf("reorg relay binding")
			}
			_, err = engine.ClaimDARelayState(relay, func(raw []byte) (func(bool), error) {
				_, err := relay.AdmitDA(raw, DetachedReorgDAProvenance())
				return nil, err
			})
			if err != nil {
				return out, err
			}
			DAObserverSetAdmitObserver(relay, func(DAObserverAdmitCall) { daCalls.Add(1) })
			size, err := engine.EffectiveDAMempoolSize()
			if err != nil {
				return out, err
			}
			for _, field := range []struct {
				name      string
				got, want uint64
			}{
				{"current_mempool_min_fee_rate", mp.CurrentMinFeeRateSnapshot(), f.Policy.Fee},
				{"min_da_fee_rate", mp.policySnapshot().MinDaFeeRate, f.Policy.DAFee},
				{"effective_da_mempool_size", uint64(size), f.Policy.Size},
				{"complete_set_max_count", DAObserverCompleteSetMaxCount(), f.Policy.Count},
				{"pinned_payload_max", relay.caps.pinnedPayloadBytes, f.Policy.Payload},
				{"orphan_ttl_blocks", relay.caps.orphanTTLBlocks, f.Policy.TTL},
			} {
				if field.got != field.want {
					return out, fmt.Errorf("reorg policy %s", field.name)
				}
			}
		} else if i >= 101 {
			tip := chainTipScalarsOf(engine.chainState)
			if tip.height != 101 || daNodeObserverHexID(tip.tipHash) != hashes[101] {
				return out, fmt.Errorf("reorg old/prefix winning tip")
			}
		}
	}
	out.Old = slices.Clone(hashes[:102])
	out.New = append(slices.Clone(hashes[:101]), hashes[102:]...)
	out.Before, err = readReorgRefusal(engine, mp, relay, &daCalls, false)
	if err != nil || !slices.Equal(out.Before.Durable, out.Old) {
		return out, fmt.Errorf("reorg pre-call durable identity: %v", err)
	}
	prestate, err := reorgRefusalStateImage(out.Before.Image)
	wantPrestate, marshalErr := json.Marshal(f.Prestate)
	gotPrestate, encodeErr := json.Marshal(prestate)
	var want, got any
	if err != nil || marshalErr != nil || encodeErr != nil || json.Unmarshal(wantPrestate, &want) != nil ||
		json.Unmarshal(gotPrestate, &got) != nil || !reflect.DeepEqual(want, got) {
		return out, fmt.Errorf("reorg EMPTY_DA prestate")
	}
	out.IndexPath, out.Cause = store.indexPath, errors.New("reorg observer injected index failure")
	fault := reorgRefusalFault{Path: out.IndexPath, Control: input.Control, Planned: out.New, Cause: out.Cause, Saved: writeFileAtomicFn}
	if beforeWrite {
		fault.Control = "LOCAL_PERSISTENCE_ERROR_PRECOMMIT_VERIFIED_WRITE"
	}
	func() {
		defer func() { writeFileAtomicFn = fault.Saved }()
		if armed {
			writeFileAtomicFn = fault.write
		}
		out.Summary, out.Err = engine.ApplyBlockWithReorg(blocks[103], f.Scenario.Calls[103].Times)
	}()
	if armed {
		if err := fault.check(); err != nil {
			return out, err
		}
	}
	out.After, err = readReorgRefusal(engine, mp, relay, &daCalls, true)
	if err != nil {
		return out, err
	}
	var probe *TxAdmitError
	if !errors.As(mp.AddTx(nil), &probe) || (probe.Kind != TxAdmitUnavailable && probe.Kind != TxAdmitRejected) {
		return out, fmt.Errorf("reorg next-admission probe")
	}
	out.Latched = probe.Kind == TxAdmitUnavailable
	return out, nil
}

func collectReorgRefusal(raw []byte, dir, path string) ([]byte, error) {
	rows, fixture, err := reorgRefusalRows(raw)
	if err != nil {
		return nil, err
	}
	out := daNodeObserverOutput{FormatVersion: 1, Cases: make([]daNodeObserverOutCase, 0, 2)}
	for i, row := range rows {
		rowDir := filepath.Join(dir, fmt.Sprint(i))
		if err := os.Mkdir(rowDir, 0o700); err != nil {
			return nil, err
		}
		observed, err := observeReorgRefusal(row, fixture, rowDir, true, false)
		if err != nil {
			return nil, err
		}
		actual, err := projectReorgRefusal(row.ID, observed)
		if err != nil {
			return nil, err
		}
		out.Cases = append(out.Cases, daNodeObserverOutCase{ID: row.ID, Actual: actual})
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return writeDANodeObserverShard(append(encoded, '\n'), path)
}

func TestDAAdmissionObserverNodeReorgRefusal(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "reorg corpus: %v", err)
	_, err = collectReorgRefusal(raw, t.TempDir(), os.Getenv("RUBIN_DA_NODE_REORG_REFUSAL_ACTUAL_OUT"))
	require(t, err == nil, "reorg collection: %v", err)
}

func TestDAAdmissionObserverNodeReorgRefusalIsolation(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "reorg corpus: %v", err)
	first, err := collectReorgRefusal(raw, t.TempDir(), "")
	require(t, err == nil, "reorg isolation baseline: %v", err)
	poison, err := poisonDANodeObserverExpectations(raw)
	require(t, err == nil, "reorg isolation poison: %v", err)
	second, err := collectReorgRefusal(poison, t.TempDir(), "")
	require(t, err == nil && bytes.Equal(first, second), "reorg isolation: actual changed: %v", err)
	invalid := mutateDANodeObserverInput(t, raw, reorgRefusalIDs[1], func(input map[string]json.RawMessage) error {
		input["transition_control"] = json.RawMessage(`"UNKNOWN"`)
		return nil
	})
	for _, existing := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "actual.json")
		if existing {
			require(t, os.WriteFile(path, []byte("sentinel"), 0o600) == nil, "reorg sentinel setup")
		}
		_, err = collectReorgRefusal(invalid, t.TempDir(), path)
		require(t, err != nil && err.Error() == "reorg input transition_control", "reorg second-row refusal: %v", err)
		contents, err := os.ReadFile(path)
		if existing {
			require(t, err == nil && string(contents) == "sentinel", "reorg failed output rewrite: %q %v", contents, err)
		} else {
			require(t, errors.Is(err, os.ErrNotExist), "reorg partial output: %v", err)
		}
	}
}

func TestDAAdmissionObserverNodeReorgRefusalReachability(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "reorg corpus: %v", err)
	rows, f, err := reorgRefusalRows(raw)
	require(t, err == nil, "reorg fixtures: %v", err)
	counterfactual, err := observeReorgRefusal(rows[0], f, t.TempDir(), true, true)
	require(t, err == nil, "reorg unchanged-control counterfactual: %v", err)
	actual, err := projectReorgRefusal(rows[0].ID, counterfactual)
	require(t, err == nil && actual["transition_result"] == "LOCAL_PERSISTENCE_ERROR(precommit)" && actual["commit_truth"] == "OLD",
		"reorg unchanged-control result/truth: %v %v", actual, err)
	for _, component := range []string{"canonical", "standard", "da", "claims"} {
		require(t, actual["published_image"].(map[string]any)[component] == "OLD", "reorg unchanged-control publication %s", component)
	}
	for _, terminal := range []bool{false, true} {
		for _, row := range rows {
			input, err := reorgRefusalInputChecked(row.Input)
			require(t, err == nil, "reorg input: %v", err)
			input.Control = "LOCAL_PERSISTENCE_ERROR_PRECOMMIT_VERIFIED_WRITE"
			label, result := "OLD", "LOCAL_PERSISTENCE_ERROR(precommit)"
			if terminal {
				input.Control, label, result = "TERMINAL_PERSISTENCE_NEW", "NEW", "TERMINAL_PERSISTENCE(new)"
			}
			row.Input, err = json.Marshal(input)
			require(t, err == nil, "reorg input encode: %v", err)
			o, err := observeReorgRefusal(row, f, t.TempDir(), true, false)
			require(t, err == nil, "reorg control reachability: %v", err)
			actual, err := projectReorgRefusal(row.ID, o)
			require(t, err == nil && actual["transition_result"] == result && actual["commit_truth"] == label, "reorg control truth: %v %v", actual, err)
			for _, component := range []string{"canonical", "standard", "da", "claims"} {
				require(t, actual["published_image"].(map[string]any)[component] == label, "reorg control publication %s", component)
			}
		}
	}
	o, err := observeReorgRefusal(rows[0], f, t.TempDir(), false, false)
	require(t, err == nil, "reorg disarmed: %v", err)
	result, err := reorgRefusalResult(o)
	require(t, err == nil && result == "ACCEPTED" && slices.Equal(o.After.Durable, o.New), "reorg disarmed accepted/new: %v", err)
	require(t, o.After.DACalls-o.Before.DACalls == 2 && o.After.Counts.ReserveCalls-o.Before.Counts.ReserveCalls == 1 &&
		o.After.Counts.ReservationsAcquired-o.Before.Counts.ReservationsAcquired == 1 &&
		o.After.Counts.Finalizations-o.Before.Counts.Finalizations == 1 && len(o.After.Image.Records) == 1 && o.After.Image.StagedBytes == 7566,
		"reorg disarmed owner/image counters")
	_, err = projectReorgRefusal(rows[0].ID, o)
	require(t, err != nil && err.Error() == "reorg requeue_rows: owner invocation", "reorg disarmed refusal: %v", err)
}

func syntheticReorgRefusal() reorgRefusalObservation {
	old, first, last := [32]byte{1}, [32]byte{2}, [32]byte{3}
	o := reorgRefusalObservation{
		Old:       []string{daNodeObserverHexID(old)},
		New:       []string{daNodeObserverHexID(first), daNodeObserverHexID(last)},
		IndexPath: "canonical-index",
		Cause:     errors.New("synthetic index fault"),
		Latched:   true,
		Summary: &ChainStateConnectSummary{
			BlockHeight:            102,
			BlockHash:              last,
			UtxoCount:              17,
			CanonicalAppliedBlocks: []CanonicalAppliedBlock{{Hash: first}, {Hash: last}},
		},
	}
	o.Before = reorgRefusalSnapshot{
		Counts:        DAObserverOwnerCounts{ReserveCalls: 21, ReservationsAcquired: 22, Finalizations: 23, CandidateReleases: 24},
		StandardCalls: 31,
		DACalls:       32,
		Image: DAObserverStateImage{
			OrphanBytes:               41,
			OrphanCommitOverheadBytes: 42,
			StagedBytes:               43,
			CompleteBytes:             44,
			CompleteCount:             45,
			PinnedPayloadBytes:        46,
			NextReceivedTime:          47,
		},
		StandardMap: map[string]int{},
		DAMap:       map[string]int{},
		Generation:  51,
		HighWater:   61,
		OwnerTip:    PendingOutpointTip{HasTip: true, Height: 101, Hash: old},
		Tip:         canonicalTipScalars{hasTip: true, height: 101, tipHash: old},
		View:        chainStateView{hasTip: true, height: 101, tipHash: old, utxoCount: 18},
		Durable:     o.Old,
		Published:   o.Old,
	}
	o.After = o.Before
	o.After.Counts = DAObserverOwnerCounts{ReserveCalls: 121, ReservationsAcquired: 222, Finalizations: 323, CandidateReleases: 424}
	o.After.Generation, o.After.Transition = 52, true
	o.After.StandardMap, o.After.DAMap = map[string]int{}, map[string]int{}
	o.After.OwnerTip = PendingOutpointTip{HasTip: true, Height: 102, Hash: last}
	o.After.Tip = canonicalTipScalars{hasTip: true, height: 102, tipHash: last}
	o.After.View = chainStateView{hasTip: true, height: 102, tipHash: last, utxoCount: 17}
	o.After.Durable, o.After.Published = o.New, o.New
	o.Err = newAtomicWriteError(atomicWriteAfterNamespaceCommit, o.IndexPath, atomicWriteOverwrite, o.Cause)
	return o
}

func reorgRefusalDistinct(o reorgRefusalObservation) error {
	seen := map[uint64]string{}
	for _, sample := range []reorgRefusalSnapshot{o.Before, o.After} {
		values := map[string]uint64{
			"ReserveCalls":              sample.Counts.ReserveCalls,
			"ReservationsAcquired":      sample.Counts.ReservationsAcquired,
			"Finalizations":             sample.Counts.Finalizations,
			"CandidateReleases":         sample.Counts.CandidateReleases,
			"StandardCalls":             sample.StandardCalls,
			"DACalls":                   sample.DACalls,
			"OrphanBytes":               sample.Image.OrphanBytes,
			"OrphanCommitOverheadBytes": sample.Image.OrphanCommitOverheadBytes,
			"StagedBytes":               sample.Image.StagedBytes,
			"CompleteBytes":             sample.Image.CompleteBytes,
			"CompleteCount":             sample.Image.CompleteCount,
			"PinnedPayloadBytes":        sample.Image.PinnedPayloadBytes,
			"NextReceivedTime":          sample.Image.NextReceivedTime,
		}
		for name, value := range values {
			if previous, found := seen[value]; value != 0 && found && previous != name {
				return fmt.Errorf("reorg distinct sources: %s and %s", previous, name)
			}
			seen[value] = name
		}
	}
	return nil
}

func TestDAAdmissionObserverNodeReorgRefusalProjection(t *testing.T) {
	o := syntheticReorgRefusal()
	require(t, reorgRefusalDistinct(o) == nil, "reorg distinct synthetic sources")
	actual, err := projectReorgRefusal(reorgRefusalIDs[0], o)
	require(t, err == nil, "reorg synthetic projection: %v", err)
	const terminal = `{"transition_result":"TERMINAL_PERSISTENCE(new)","commit_truth":"NEW","requeue_rows":[],"fallback_owner":null,"retry_scheduled":false,"published_image":{"canonical":"NEW","standard":"NEW","da":"NEW","claims":"NEW"},"state_image":{"record_image":[],"locator_image":[],"claim_image":[],"orphan_accounting":{"global_bytes":41,"per_da_id":[],"commit_overhead_bytes":42,"per_quota":[]},"retained_counters":{"staged_retained_bytes":43,"complete_retained_bytes":44,"complete_set_count":45,"complete_payload_bytes":46,"accepted_sequence":47}},"owner":{"admission_entrypoint":{"domain":"NONE","invocations":0},"pending_outpoint":{"reserve_calls":100,"reservations_acquired":200,"finalizations":300,"exact_releases":400}}}`
	t.Run("terminal", func(t *testing.T) {
		stateAssertJSON(t, actual, terminal)
	})
	old := o
	old.Summary, old.Latched = nil, false
	old.After = old.Before
	old.After.Generation++
	old.Err = newAtomicWriteError(atomicWriteBeforeNamespaceCommit, old.IndexPath, atomicWriteOverwrite, old.Cause)
	actual, err = projectReorgRefusal(reorgRefusalIDs[1], old)
	require(t, err == nil, "reorg old projection: %v", err)
	const precommit = `{"transition_result":"LOCAL_PERSISTENCE_ERROR(precommit)","commit_truth":"OLD","requeue_rows":[],"published_image":{"canonical":"OLD","standard":"OLD","da":"OLD","claims":"OLD"},"state_image":{"record_image":[],"locator_image":[],"claim_image":[],"orphan_accounting":{"global_bytes":41,"per_da_id":[],"commit_overhead_bytes":42,"per_quota":[]},"retained_counters":{"staged_retained_bytes":43,"complete_retained_bytes":44,"complete_set_count":45,"complete_payload_bytes":46,"accepted_sequence":47}},"owner":{"admission_entrypoint":{"domain":"NONE","invocations":0},"pending_outpoint":{"reserve_calls":0,"reservations_acquired":0,"finalizations":0,"exact_releases":0}}}`
	t.Run("precommit", func(t *testing.T) {
		stateAssertJSON(t, actual, precommit)
	})
	for _, sample := range []reorgRefusalObservation{o, old} {
		sample.After.Durable = sample.Old
		truth, canonical := "OLD", "NEW"
		if sample.Summary == nil {
			sample.After.Durable, truth, canonical = sample.New, "NEW", "OLD"
		}
		actual, err := projectReorgRefusal(reorgRefusalIDs[0], sample)
		require(t, err == nil && actual["commit_truth"] == truth && actual["published_image"].(map[string]any)["canonical"] == canonical,
			"reorg independent durable/published sources: %v %v", actual, err)
	}
	for _, component := range []string{"standard", "da", "claims"} {
		sample := o
		switch component {
		case "standard":
			sample.After.StandardMap = sample.Before.StandardMap
		case "da":
			sample.After.DAMap = sample.Before.DAMap
		case "claims":
			sample.After.OwnerTip = sample.Before.OwnerTip
		}
		actual, err := projectReorgRefusal(reorgRefusalIDs[0], sample)
		require(t, err == nil && actual["published_image"].(map[string]any)[component] == "OLD", "reorg independent %s witness: %v", component, err)
	}
	collision := o
	collision.After.Image.OrphanBytes = collision.After.Image.StagedBytes
	err = reorgRefusalDistinct(collision)
	require(t, err != nil && strings.Contains(err.Error(), "OrphanBytes") && strings.Contains(err.Error(), "StagedBytes"), "reorg distinct guard: %v", err)
}

func reorgRefusalResult(o reorgRefusalObservation) (string, error) {
	if o.Summary != nil {
		s := o.Summary
		if len(o.New) < 2 || s.BlockHeight != 102 || daNodeObserverHexID(s.BlockHash) != o.New[len(o.New)-1] ||
			len(s.CanonicalAppliedBlocks) != 2 || daNodeObserverHexID(s.CanonicalAppliedBlocks[0].Hash) != o.New[len(o.New)-2] ||
			daNodeObserverHexID(s.CanonicalAppliedBlocks[1].Hash) != o.New[len(o.New)-1] {
			return "", fmt.Errorf("reorg result: summary planned tip")
		}
		if o.Err == nil && !o.Latched {
			return "ACCEPTED", nil
		}
	}
	var atomicErr *atomicWriteError
	if !errors.As(o.Err, &atomicErr) || atomicErr == nil || atomicErr.destination != o.IndexPath || !errors.Is(o.Err, o.Cause) {
		return "", fmt.Errorf("reorg result: error provenance")
	}
	if o.Summary != nil && o.Latched && atomicErr.stage == atomicWriteAfterNamespaceCommit {
		return "TERMINAL_PERSISTENCE(new)", nil
	}
	if o.Summary == nil && !o.Latched && atomicErr.stage == atomicWriteBeforeNamespaceCommit {
		return "LOCAL_PERSISTENCE_ERROR(precommit)", nil
	}
	return "", fmt.Errorf("reorg result: summary/error/latch/stage combination")
}

func reorgRefusalStateImage(image DAObserverStateImage) (map[string]any, error) {
	for _, source := range []struct {
		name  string
		count int
	}{
		{"record_image", len(image.Records)},
		{"locator_image", len(image.Locators)},
		{"claim_image", len(image.Claims)},
		{"outpoint_rows", len(image.OutpointRows)},
		{"per_da_id", len(image.OrphanBytesByDAID)},
		{"per_quota", len(image.OrphanBytesByPeerQuotaKey)},
	} {
		if source.count != 0 {
			return nil, fmt.Errorf("reorg state_image: nonempty %s", source.name)
		}
	}
	return map[string]any{
		"record_image":  []any{},
		"locator_image": []any{},
		"claim_image":   []any{},
		"orphan_accounting": map[string]any{
			"global_bytes":          image.OrphanBytes,
			"per_da_id":             []any{},
			"commit_overhead_bytes": image.OrphanCommitOverheadBytes,
			"per_quota":             []any{},
		},
		"retained_counters": map[string]any{
			"staged_retained_bytes":   image.StagedBytes,
			"complete_retained_bytes": image.CompleteBytes,
			"complete_set_count":      image.CompleteCount,
			"complete_payload_bytes":  image.PinnedPayloadBytes,
			"accepted_sequence":       image.NextReceivedTime,
		},
	}, nil
}

func reorgRefusalCanonical(o reorgRefusalObservation) (string, error) {
	a := o.After
	if o.Summary != nil && a.Tip.hasTip && a.Tip.height == 102 &&
		daNodeObserverHexID(a.Tip.tipHash) == o.New[len(o.New)-1] && slices.Equal(a.Published, o.New) &&
		a.View.hasTip && a.View.height == 102 && a.View.tipHash == a.Tip.tipHash && uint64(a.View.utxoCount) == o.Summary.UtxoCount {
		return "NEW", nil
	}
	if a.Tip.hasTip && a.Tip.height == 101 && daNodeObserverHexID(a.Tip.tipHash) == o.Old[len(o.Old)-1] &&
		slices.Equal(a.Published, o.Old) && a.View == o.Before.View && a.Digest == o.Before.Digest {
		return "OLD", nil
	}
	return "", fmt.Errorf("reorg published_image.canonical")
}

func reorgRefusalComponents(o reorgRefusalObservation) (map[string]any, error) {
	b, a := o.Before, o.After
	if !slices.Equal(b.TxIDs, a.TxIDs) || b.UsedBytes != a.UsedBytes || b.AdmissionSeq != a.AdmissionSeq || b.Fee != a.Fee {
		return nil, fmt.Errorf("reorg published_image.standard content")
	}
	bImage, aImage := b.Image, a.Image
	bImage.RecordRevisionHighWater, aImage.RecordRevisionHighWater = 0, 0
	bImage.Claims, bImage.OutpointRows, aImage.Claims, aImage.OutpointRows = nil, nil, nil, nil
	if !reflect.DeepEqual(bImage, aImage) {
		return nil, fmt.Errorf("reorg published_image.da content")
	}
	if !reflect.DeepEqual(b.Image.Claims, a.Image.Claims) || !reflect.DeepEqual(b.Image.OutpointRows, a.Image.OutpointRows) {
		return nil, fmt.Errorf("reorg published_image.claims content")
	}
	labels := map[string]any{"standard": "OLD", "da": "OLD", "claims": "OLD"}
	if reflect.ValueOf(b.StandardMap).Pointer() != reflect.ValueOf(a.StandardMap).Pointer() {
		labels["standard"] = "NEW"
	}
	if reflect.ValueOf(b.DAMap).Pointer() != reflect.ValueOf(a.DAMap).Pointer() {
		labels["da"] = "NEW"
	}
	if a.OwnerTip.HasTip && a.OwnerTip.Height == 102 && daNodeObserverHexID(a.OwnerTip.Hash) == o.New[len(o.New)-1] {
		labels["claims"] = "NEW"
	} else if a.OwnerTip != b.OwnerTip || !a.OwnerTip.HasTip || a.OwnerTip.Height != 101 || daNodeObserverHexID(a.OwnerTip.Hash) != o.Old[len(o.Old)-1] {
		return nil, fmt.Errorf("reorg published_image.claims witness")
	}
	return labels, nil
}

func projectReorgRefusal(id string, o reorgRefusalObservation) (map[string]any, error) {
	result, err := reorgRefusalResult(o)
	if err != nil {
		return nil, err
	}
	truth := ""
	if slices.Equal(o.After.Durable, o.New) {
		truth = "NEW"
	} else if slices.Equal(o.After.Durable, o.Old) {
		truth = "OLD"
	} else {
		return nil, fmt.Errorf("reorg commit_truth")
	}
	b, a := o.Before, o.After
	if a.StandardCalls < b.StandardCalls || a.DACalls < b.DACalls {
		return nil, fmt.Errorf("reorg owner invocation negative delta")
	}
	s, d := a.StandardCalls-b.StandardCalls, a.DACalls-b.DACalls
	if s != 0 && d != 0 {
		return nil, fmt.Errorf("reorg owner invocation both domains")
	}
	if s != 0 || d != 0 {
		return nil, fmt.Errorf("reorg requeue_rows: owner invocation")
	}
	if a.Generation <= b.Generation || a.Generation-b.Generation != 1 {
		return nil, fmt.Errorf("reorg owner generation")
	}
	if a.HighWater != b.HighWater {
		return nil, fmt.Errorf("reorg owner high-water")
	}
	if a.Transition != o.Latched {
		return nil, fmt.Errorf("reorg owner transition/probe")
	}
	canonical, err := reorgRefusalCanonical(o)
	if err != nil {
		return nil, err
	}
	labels, err := reorgRefusalComponents(o)
	if err != nil {
		return nil, err
	}
	labels["canonical"] = canonical
	image, err := reorgRefusalStateImage(a.Image)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]any)
	for _, field := range []struct {
		name          string
		before, after uint64
	}{
		{"reserve_calls", b.Counts.ReserveCalls, a.Counts.ReserveCalls},
		{"reservations_acquired", b.Counts.ReservationsAcquired, a.Counts.ReservationsAcquired},
		{"finalizations", b.Counts.Finalizations, a.Counts.Finalizations},
		{"exact_releases", b.Counts.CandidateReleases, a.Counts.CandidateReleases},
	} {
		if field.after < field.before {
			return nil, fmt.Errorf("reorg owner pending_outpoint negative %s", field.name)
		}
		counts[field.name] = field.after - field.before
	}
	out := map[string]any{
		"transition_result": result,
		"commit_truth":      truth,
		"requeue_rows":      []any{},
		"published_image":   labels,
		"state_image":       image,
		"owner": map[string]any{
			"admission_entrypoint": map[string]any{"domain": "NONE", "invocations": s + d},
			"pending_outpoint":     counts,
		},
	}
	if id == reorgRefusalIDs[0] {
		out["fallback_owner"], out["retry_scheduled"] = nil, false
	}
	return out, nil
}

func TestDAAdmissionObserverNodeReorgRefusalCensus(t *testing.T) {
	corpus, _, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "reorg corpus: %v", err)
	for _, variant := range []string{"missing", "duplicate", "reordered", "unknown", "third owned row"} {
		t.Run(variant, func(t *testing.T) {
			candidate := corpus
			candidate.Cases = slices.Clone(corpus.Cases)
			want := "reorg census: expected two owned rows"
			switch variant {
			case "missing":
				candidate.Cases = slicesDeleteCase(t, candidate.Cases, reorgRefusalIDs[1])
			case "duplicate":
				candidate.Cases[20] = candidate.Cases[19]
				want = "reorg census: unexpected owned row REORG_TERMINAL_PERSISTENCE_NEW_NO_OWNER at 20"
			case "reordered":
				candidate.Cases = swapDANodeObserverCases(t, candidate.Cases, reorgRefusalIDs[0], reorgRefusalIDs[1])
				want = "reorg census: unexpected owned row REORG_FAILED_TRANSITION_NO_OWNER at 19"
			case "unknown":
				candidate.Cases = renameDANodeObserverCase(t, candidate.Cases, reorgRefusalIDs[0], "UNKNOWN")
				want = "reorg census: unexpected owned row UNKNOWN at 19"
			case "third owned row":
				var row daNodeObserverCase
				require(t, json.Unmarshal(candidate.Cases[0], &row) == nil, "reorg third row decode")
				var owned daNodeObserverCase
				require(t, json.Unmarshal(candidate.Cases[19], &owned) == nil, "reorg owned input decode")
				row.Input = bytes.Clone(owned.Input)
				candidate.Cases[0], err = json.Marshal(row)
				require(t, err == nil, "reorg third row encode: %v", err)
				want = fmt.Sprintf("reorg census: unexpected owned row %s at 0", row.ID)
			}
			encoded, err := json.Marshal(candidate)
			require(t, err == nil, "reorg census encode: %v", err)
			_, _, err = reorgRefusalRows(encoded)
			require(t, err != nil && err.Error() == want, "reorg census %s: %v", variant, err)
		})
	}
}

func TestDAAdmissionObserverNodeReorgRefusalNonempty(t *testing.T) {
	for _, field := range []string{"Records", "Locators", "Claims", "OutpointRows", "OrphanBytesByDAID", "OrphanBytesByPeerQuotaKey"} {
		o := syntheticReorgRefusal()
		var want string
		switch field {
		case "Records":
			o.Before.Image.Records = []DAObserverRecord{{}}
			want = "record_image"
		case "Locators":
			o.Before.Image.Locators = []DAObserverLocator{{}}
			want = "locator_image"
		case "Claims":
			o.Before.Image.Claims = []DAObserverClaim{{}}
			want = "claim_image"
		case "OutpointRows":
			o.Before.Image.OutpointRows = []DAObserverOutpointRow{{}}
			want = "outpoint_rows"
		case "OrphanBytesByDAID":
			o.Before.Image.OrphanBytesByDAID = []DAObserverIDBytes{{}}
			want = "per_da_id"
		case "OrphanBytesByPeerQuotaKey":
			o.Before.Image.OrphanBytesByPeerQuotaKey = []DAObserverKeyBytes{{}}
			want = "per_quota"
		}
		o.After.Image = o.Before.Image
		_, err := projectReorgRefusal(reorgRefusalIDs[0], o)
		require(t, err != nil && err.Error() == "reorg state_image: nonempty "+want, "reorg nonempty %s: %v", field, err)
	}
	o := syntheticReorgRefusal()
	o.After.Image.Claims = []DAObserverClaim{{}}
	o.After.OwnerTip = o.Before.OwnerTip
	_, err := projectReorgRefusal(reorgRefusalIDs[0], o)
	require(t, err != nil && err.Error() == "reorg published_image.claims content", "reorg claims content: %v", err)
}

func TestDAAdmissionObserverNodeReorgRefusalFault(t *testing.T) {
	savedError := errors.New("non-index saved write")
	passed := false
	passthrough := reorgRefusalFault{
		Path: "index",
		Saved: func(path string, raw []byte, mode os.FileMode) error {
			passed = path == "other" && string(raw) == "bytes" && mode == 0o600
			return savedError
		},
	}
	returned := passthrough.write("other", []byte("bytes"), 0o600)
	require(t, passed && returned == savedError && passthrough.Calls == 0, "reorg non-index saved write forwarding")
	unapplied := reorgRefusalFault{}
	err := unapplied.check()
	require(t, err != nil && err.Error() == "reorg control not applied: count=0 failure=<nil>", "reorg no intercept: %v", err)
	for _, variant := range []string{"second intercept", "nonplanned bytes", "saved write failure"} {
		cause := errors.New("saved write failure")
		fault := reorgRefusalFault{
			Path:    "index",
			Control: "TERMINAL_PERSISTENCE_NEW",
			Planned: []string{strings.Repeat("01", 32)},
			Cause:   errors.New("injected failure"),
			Saved:   func(string, []byte, os.FileMode) error { return nil },
		}
		encoded, err := encodeBlockStoreIndex(blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: fault.Planned})
		require(t, err == nil, "reorg seam planned index encode: %v", err)
		want := "reorg control: intercept count or planned index"
		switch variant {
		case "second intercept":
			fault.Calls = 1
		case "nonplanned bytes":
			encoded, err = encodeBlockStoreIndex(blockStoreIndexDisk{Version: blockStoreIndexVersion, Canonical: []string{strings.Repeat("02", 32)}})
			require(t, err == nil, "reorg seam other index encode: %v", err)
		case "saved write failure":
			fault.Saved = func(string, []byte, os.FileMode) error { return cause }
			want = "reorg control: saved write: saved write failure"
		}
		returned := fault.write("index", encoded, 0o600)
		require(t, fault.Failure != nil && fault.Failure.Error() == want, "reorg seam %s: %v", variant, fault.Failure)
		if variant == "saved write failure" {
			require(t, returned == cause, "reorg saved write error identity")
		}
	}
}

func TestDAAdmissionObserverNodeReorgRefusalIntegrity(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	require(t, err == nil, "reorg corpus: %v", err)
	rows, original, err := reorgRefusalRows(raw)
	require(t, err == nil, "reorg fixtures: %v", err)
	for _, owner := range []struct{ group, key string }{
		{"source_contexts", "DETACHED_REORG"},
		{"policy_contexts", "ACCEPT_DA"},
		{"chain_contexts", "CHAIN_100"},
		{"prestates", "EMPTY_DA"},
		{"reorg_scenarios", "DA_ONLY_LITERAL_REJECT"},
	} {
		var corpus map[string]json.RawMessage
		require(t, json.Unmarshal(raw, &corpus) == nil, "reorg strict corpus decode")
		var fixtures map[string]map[string]json.RawMessage
		require(t, json.Unmarshal(corpus["input_fixtures"], &fixtures) == nil, "reorg strict fixtures decode")
		var object map[string]json.RawMessage
		require(t, json.Unmarshal(fixtures[owner.group][owner.key], &object) == nil, "reorg strict object decode")
		object["unexpected"] = json.RawMessage(`0`)
		fixtures[owner.group][owner.key], err = json.Marshal(object)
		require(t, err == nil, "reorg strict object encode: %v", err)
		corpus["input_fixtures"], err = json.Marshal(fixtures)
		require(t, err == nil, "reorg strict fixtures encode: %v", err)
		encoded, err := json.Marshal(corpus)
		require(t, err == nil, "reorg strict corpus encode: %v", err)
		_, _, err = reorgRefusalRows(encoded)
		require(t, err != nil && err.Error() == "reorg fixture "+owner.key+": observer input: json: unknown field \"unexpected\"",
			"reorg strict fixture %s: %v", owner.key, err)
	}
	configured := original
	configured.Policy.DAFee = 97
	_, err = observeReorgRefusal(rows[0], configured, t.TempDir(), true, false)
	require(t, err == nil, "reorg nondefault DA fee configuration/readback: %v", err)
	oldRaw, err := hex.DecodeString(original.Scenario.Old[0].Hex)
	require(t, err == nil, "reorg premise bytes: %v", err)
	parsed, err := consensus.ParseBlockBytes(oldRaw)
	require(t, err == nil, "reorg premise parse: %v", err)
	coinbaseOnly := *parsed
	coinbaseOnly.Txs = parsed.Txs[:1]
	err = reorgRefusalDAPremise(&coinbaseOnly)
	require(t, err != nil && err.Error() == "reorg disconnected block: no DA rows", "reorg coinbase-only premise: %v", err)
	standard := *parsed
	standard.Txs = slices.Clone(parsed.Txs)
	tx := *standard.Txs[1]
	tx.TxKind = 0
	standard.Txs[1] = &tx
	err = reorgRefusalDAPremise(&standard)
	require(t, err != nil && err.Error() == "reorg disconnected block: standard row", "reorg standard-row premise: %v", err)
	encoded, err := json.Marshal(original)
	require(t, err == nil, "reorg genesis copy encode: %v", err)
	var genesis reorgRefusalFixture
	require(t, json.Unmarshal(encoded, &genesis) == nil, "reorg genesis copy decode")
	rebound := make(map[string]string)
	for _, branch := range [][]reorgRefusalBlock{genesis.Chain.Prefix.Blocks, genesis.Scenario.Old, genesis.Scenario.Win} {
		for i := range branch {
			block := &branch[i]
			raw, err := hex.DecodeString(block.Hex)
			require(t, err == nil, "reorg genesis block decode: %v", err)
			if block.Height == 0 {
				raw[consensus.BLOCK_HEADER_BYTES-1] ^= 1
			} else {
				block.Parent = rebound[block.Parent]
				parent, err := hex.DecodeString(block.Parent)
				require(t, err == nil, "reorg genesis parent decode: %v", err)
				copy(raw[4:36], parent)
			}
			hash, err := consensus.BlockHash(raw[:consensus.BLOCK_HEADER_BYTES])
			require(t, err == nil, "reorg genesis hash: %v", err)
			rebound[block.Hash] = daNodeObserverHexID(hash)
			block.Hash, block.Hex = daNodeObserverHexID(hash), hex.EncodeToString(raw)
		}
	}
	for i := range genesis.Chain.Prefix.Index {
		genesis.Chain.Prefix.Index[i].Hash = rebound[genesis.Chain.Prefix.Index[i].Hash]
	}
	genesis.Chain.Tip, genesis.Chain.Prefix.Tip = rebound[genesis.Chain.Tip], rebound[genesis.Chain.Prefix.Tip]
	_, _, err = reorgRefusalBlocks(genesis)
	require(t, err != nil && err.Error() == "reorg genesis hash", "reorg nondevnet genesis: %v", err)
	for _, field := range []string{
		"source_context",
		"policy_context",
		"chain_context",
		"prestate",
		"reorg_scenario",
		"transition_control",
	} {
		for _, variant := range []string{"unknown", "missing", "extra"} {
			var input map[string]any
			require(t, json.Unmarshal(rows[0].Input, &input) == nil, "reorg input decode")
			want := "reorg input " + field
			switch variant {
			case "unknown":
				input[field] = "UNKNOWN"
			case "missing":
				delete(input, field)
			case "extra":
				input[field+"_extra"] = "UNKNOWN"
				want = "observer input: json: unknown field \"" + field + "_extra\""
			}
			encoded, err := json.Marshal(input)
			require(t, err == nil, "reorg input encode: %v", err)
			_, err = reorgRefusalInputChecked(encoded)
			require(t, err != nil && err.Error() == want, "reorg closed input %s/%s: %v", field, variant, err)
		}
	}
	for _, test := range []struct {
		name string
		edit func(*reorgRefusalFixture)
		want string
	}{
		{
			"public_calls phase",
			func(f *reorgRefusalFixture) { f.Scenario.Calls[103].Phase = "OLD_BRANCH" },
			"reorg public_calls 103",
		},
		{
			"source fixture",
			func(f *reorgRefusalFixture) { f.Source.Source = "UNKNOWN" },
			"reorg fixture source",
		},
		{
			"entrypoint fixture",
			func(f *reorgRefusalFixture) { f.Source.Entrypoint = "UNKNOWN" },
			"reorg fixture entrypoint",
		},
		{
			"prefix reference",
			func(f *reorgRefusalFixture) { f.Scenario.Prefix = "UNKNOWN" },
			"reorg fixture canonical_prefix_ref",
		},
		{
			"canonical index hash",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Index[100].Hash = strings.Repeat("00", 32) },
			"reorg canonical_index 100",
		},
		{
			"canonical index ref",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Index[100].Ref = "UNKNOWN" },
			"reorg canonical_index 100",
		},
		{
			"prefix tip hash",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Tip = strings.Repeat("00", 32) },
			"reorg prefix tip",
		},
		{
			"chain height",
			func(f *reorgRefusalFixture) { f.Chain.Height++ },
			"reorg prefix tip",
		},
		{
			"chain tip hash",
			func(f *reorgRefusalFixture) { f.Chain.Tip = strings.Repeat("00", 32) },
			"reorg prefix tip",
		},
		{
			"public_calls ref",
			func(f *reorgRefusalFixture) { f.Scenario.Calls[103].Ref = "DA_ONLY_WIN_101" },
			"reorg public_calls 103",
		},
		{
			"block hash",
			func(f *reorgRefusalFixture) { f.Scenario.Win[1].Hash = strings.Repeat("00", 32) },
			"reorg block_hash DA_ONLY_WIN_102",
		},
		{
			"block parent",
			func(f *reorgRefusalFixture) { f.Scenario.Win[1].Parent = strings.Repeat("00", 32) },
			"reorg parent_hash DA_ONLY_WIN_102",
		},
		{
			"block height",
			func(f *reorgRefusalFixture) { f.Scenario.Win[1].Height++ },
			"reorg height DA_ONLY_WIN_102",
		},
		{
			"chain id",
			func(f *reorgRefusalFixture) { f.Chain.ID = strings.Repeat("00", 32) },
			"reorg fixture chain_id",
		},
		{
			"engine chain id",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Config.ID = strings.Repeat("00", 32) },
			"reorg fixture public_engine_config.chain_id",
		},
		{
			"engine target",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Config.Target = strings.Repeat("00", 32) },
			"reorg fixture public_engine_config.expected_target",
		},
		{
			"binding phase",
			func(f *reorgRefusalFixture) { f.Scenario.Binding.Phase = "BEFORE_CANONICAL_PREFIX" },
			"reorg fixture mempool_binding.phase",
		},
		{
			"binding policy",
			func(f *reorgRefusalFixture) { f.Scenario.Binding.Policy = "UNKNOWN" },
			"reorg fixture mempool_binding.policy_context",
		},
		{
			"canonical index",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Index[100].Height++ },
			"reorg canonical_index 100",
		},
		{
			"prefix tip",
			func(f *reorgRefusalFixture) { f.Chain.Prefix.Height++ },
			"reorg prefix tip",
		},
		{
			"mempool fee",
			func(f *reorgRefusalFixture) { f.Policy.Fee++ },
			"reorg policy current_mempool_min_fee_rate",
		},
		{
			"DA fee readback",
			func(f *reorgRefusalFixture) { f.Policy.DAFee = 0 },
			"reorg policy min_da_fee_rate",
		},
		{
			"effective size",
			func(f *reorgRefusalFixture) { f.Policy.Size++ },
			"reorg policy effective_da_mempool_size",
		},
		{
			"complete count",
			func(f *reorgRefusalFixture) { f.Policy.Count++ },
			"reorg policy complete_set_max_count",
		},
		{
			"pinned payload",
			func(f *reorgRefusalFixture) { f.Policy.Payload++ },
			"reorg policy pinned_payload_max",
		},
		{
			"orphan ttl",
			func(f *reorgRefusalFixture) { f.Policy.TTL++ },
			"reorg policy orphan_ttl_blocks",
		},
		{
			"EMPTY_DA prestate",
			func(f *reorgRefusalFixture) { f.Prestate.Counters.Staged++ },
			"reorg EMPTY_DA prestate",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(original)
			require(t, err == nil, "reorg fixture copy encode: %v", err)
			var fixture reorgRefusalFixture
			require(t, json.Unmarshal(encoded, &fixture) == nil, "reorg fixture copy decode")
			test.edit(&fixture)
			_, err = observeReorgRefusal(rows[0], fixture, t.TempDir(), true, false)
			require(t, err != nil && err.Error() == test.want, "reorg integrity %s: %v", test.name, err)
		})
	}
}

func TestDAAdmissionObserverNodeReorgRefusalProjectionRefusals(t *testing.T) {
	for _, old := range []bool{false, true} {
		for _, field := range []string{"tip presence", "tip height", "tip hash", "store", "view presence", "view height", "view hash", "UTXO count", "generated", "digest"} {
			if !old && (field == "generated" || field == "digest") {
				continue
			}
			o := syntheticReorgRefusal()
			if old {
				o.Summary, o.Latched = nil, false
				o.After = o.Before
				o.After.Generation++
				o.Err = newAtomicWriteError(atomicWriteBeforeNamespaceCommit, o.IndexPath, atomicWriteOverwrite, o.Cause)
			}
			switch field {
			case "tip presence":
				o.After.Tip.hasTip = false
			case "tip height":
				o.After.Tip.height++
			case "tip hash":
				o.After.Tip.tipHash = [32]byte{9}
				if !old {
					o.After.View.tipHash = o.After.Tip.tipHash
				}
			case "store":
				o.After.Published = []string{"other"}
			case "view presence":
				o.After.View.hasTip = false
			case "view height":
				o.After.View.height++
			case "view hash":
				o.After.View.tipHash = [32]byte{9}
			case "UTXO count":
				o.After.View.utxoCount++
			case "generated":
				o.After.View.alreadyGenerated = consensus.Uint128FromU64(1)
			case "digest":
				o.After.Digest = [32]byte{9}
			}
			_, err := projectReorgRefusal(reorgRefusalIDs[0], o)
			require(t, err != nil && err.Error() == "reorg published_image.canonical", "reorg canonical old=%t %s: %v", old, field, err)
		}
	}
	for _, field := range []string{"txids", "admission sequence", "fee", "orphan bytes", "overhead", "complete bytes", "complete count", "payload", "received sequence", "records", "locators", "per DA ID", "per quota", "outpoints"} {
		o := syntheticReorgRefusal()
		want := "reorg published_image.da content"
		switch field {
		case "txids":
			o.After.TxIDs, want = [][32]byte{{9}}, "reorg published_image.standard content"
		case "admission sequence":
			o.After.AdmissionSeq, want = 1, "reorg published_image.standard content"
		case "fee":
			o.After.Fee, want = 1, "reorg published_image.standard content"
		case "orphan bytes":
			o.After.Image.OrphanBytes++
		case "overhead":
			o.After.Image.OrphanCommitOverheadBytes++
		case "complete bytes":
			o.After.Image.CompleteBytes++
		case "complete count":
			o.After.Image.CompleteCount++
		case "payload":
			o.After.Image.PinnedPayloadBytes++
		case "received sequence":
			o.After.Image.NextReceivedTime++
		case "records":
			o.After.Image.Records = []DAObserverRecord{{}}
		case "locators":
			o.After.Image.Locators = []DAObserverLocator{{}}
		case "per DA ID":
			o.After.Image.OrphanBytesByDAID = []DAObserverIDBytes{{}}
		case "per quota":
			o.After.Image.OrphanBytesByPeerQuotaKey = []DAObserverKeyBytes{{}}
		case "outpoints":
			o.After.Image.OutpointRows, want = []DAObserverOutpointRow{{}}, "reorg published_image.claims content"
		}
		o.After.StandardMap, o.After.DAMap, o.After.OwnerTip = o.Before.StandardMap, o.Before.DAMap, o.Before.OwnerTip
		_, err := projectReorgRefusal(reorgRefusalIDs[0], o)
		require(t, err != nil && err.Error() == want, "reorg component content %s: %v", field, err)
	}
	for _, summary := range []bool{false, true} {
		for _, latched := range []bool{false, true} {
			for _, stage := range []string{"nil", "untagged", "before", "after"} {
				o := syntheticReorgRefusal()
				o.Latched = latched
				if !summary {
					o.Summary = nil
				}
				switch stage {
				case "nil":
					o.Err = nil
				case "untagged":
					o.Err = o.Cause
				case "before":
					o.Err = newAtomicWriteError(atomicWriteBeforeNamespaceCommit, o.IndexPath, atomicWriteOverwrite, o.Cause)
				}
				result, err := reorgRefusalResult(o)
				switch {
				case summary && !latched && stage == "nil":
					require(t, err == nil && result == "ACCEPTED", "reorg classification accepted: %v", err)
				case summary && latched && stage == "after":
					require(t, err == nil && result == "TERMINAL_PERSISTENCE(new)", "reorg classification terminal: %v", err)
				case !summary && !latched && stage == "before":
					require(t, err == nil && result == "LOCAL_PERSISTENCE_ERROR(precommit)", "reorg classification precommit: %v", err)
				default:
					want := "reorg result: summary/error/latch/stage combination"
					if stage == "nil" || stage == "untagged" {
						want = "reorg result: error provenance"
					}
					require(t, err != nil && err.Error() == want, "reorg classification %t/%t/%s: %v", summary, latched, stage, err)
				}
			}
		}
	}
	for _, test := range []struct {
		name string
		edit func(*reorgRefusalObservation)
		want string
	}{
		{
			"summary error open",
			func(o *reorgRefusalObservation) { o.Latched = false },
			"reorg result: summary/error/latch/stage combination",
		},
		{
			"nil summary untagged",
			func(o *reorgRefusalObservation) {
				o.Summary = nil
				o.Err = o.Cause
			},
			"reorg result: error provenance",
		},
		{
			"nil summary after namespace",
			func(o *reorgRefusalObservation) { o.Summary = nil },
			"reorg result: summary/error/latch/stage combination",
		},
		{
			"accepted wrong summary",
			func(o *reorgRefusalObservation) {
				o.Err, o.Latched = nil, false
				o.Summary.BlockHeight++
			},
			"reorg result: summary planned tip",
		},
		{
			"summary wrong tip hash",
			func(o *reorgRefusalObservation) { o.Summary.BlockHash = [32]byte{9} },
			"reorg result: summary planned tip",
		},
		{
			"summary wrong applied count",
			func(o *reorgRefusalObservation) {
				o.Summary.CanonicalAppliedBlocks = o.Summary.CanonicalAppliedBlocks[:1]
			},
			"reorg result: summary planned tip",
		},
		{
			"summary wrong first applied hash",
			func(o *reorgRefusalObservation) { o.Summary.CanonicalAppliedBlocks[0].Hash = [32]byte{9} },
			"reorg result: summary planned tip",
		},
		{
			"summary wrong last applied hash",
			func(o *reorgRefusalObservation) { o.Summary.CanonicalAppliedBlocks[1].Hash = [32]byte{9} },
			"reorg result: summary planned tip",
		},
		{
			"wrong destination",
			func(o *reorgRefusalObservation) { o.IndexPath = "other-index" },
			"reorg result: error provenance",
		},
		{
			"wrong cause",
			func(o *reorgRefusalObservation) { o.Cause = errors.New("different cause") },
			"reorg result: error provenance",
		},
		{
			"standard only",
			func(o *reorgRefusalObservation) { o.After.StandardCalls++ },
			"reorg requeue_rows: owner invocation",
		},
		{
			"DA only",
			func(o *reorgRefusalObservation) { o.After.DACalls++ },
			"reorg requeue_rows: owner invocation",
		},
		{
			"both domains",
			func(o *reorgRefusalObservation) {
				o.After.StandardCalls++
				o.After.DACalls++
			},
			"reorg owner invocation both domains",
		},
		{
			"negative standard",
			func(o *reorgRefusalObservation) { o.After.StandardCalls-- },
			"reorg owner invocation negative delta",
		},
		{
			"negative DA",
			func(o *reorgRefusalObservation) { o.After.DACalls-- },
			"reorg owner invocation negative delta",
		},
		{
			"generation",
			func(o *reorgRefusalObservation) { o.After.Generation++ },
			"reorg owner generation",
		},
		{
			"generation wraparound",
			func(o *reorgRefusalObservation) {
				o.Before.Generation, o.After.Generation = ^uint64(0), 0
			},
			"reorg owner generation",
		},
		{
			"high water",
			func(o *reorgRefusalObservation) { o.After.HighWater++ },
			"reorg owner high-water",
		},
		{
			"transition probe",
			func(o *reorgRefusalObservation) { o.After.Transition = false },
			"reorg owner transition/probe",
		},
		{
			"standard content",
			func(o *reorgRefusalObservation) {
				o.After.UsedBytes++
				o.After.StandardMap = o.Before.StandardMap
			},
			"reorg published_image.standard content",
		},
		{
			"DA content",
			func(o *reorgRefusalObservation) {
				o.After.Image.StagedBytes++
				o.After.DAMap = o.Before.DAMap
			},
			"reorg published_image.da content",
		},
		{
			"reserve delta",
			func(o *reorgRefusalObservation) { o.After.Counts.ReserveCalls = 0 },
			"reorg owner pending_outpoint negative reserve_calls",
		},
		{
			"acquired delta",
			func(o *reorgRefusalObservation) { o.After.Counts.ReservationsAcquired = 0 },
			"reorg owner pending_outpoint negative reservations_acquired",
		},
		{
			"finalizations delta",
			func(o *reorgRefusalObservation) { o.After.Counts.Finalizations = 0 },
			"reorg owner pending_outpoint negative finalizations",
		},
		{
			"releases delta",
			func(o *reorgRefusalObservation) { o.After.Counts.CandidateReleases = 0 },
			"reorg owner pending_outpoint negative exact_releases",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := syntheticReorgRefusal()
			test.edit(&o)
			_, err := projectReorgRefusal(reorgRefusalIDs[0], o)
			require(t, err != nil && err.Error() == test.want, "reorg projection refusal %s: %v", test.name, err)
		})
	}
}
