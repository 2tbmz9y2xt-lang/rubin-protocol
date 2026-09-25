//go:build rubin_da_observer

package node

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

var daNodeObserverIDs = []string{
	"CAP_SET_COUNT_BELOW",
	"CAP_SET_COUNT_EQUAL",
	"CAP_SET_COUNT_ABOVE",
	"CAP_RETAINED_BYTES_BELOW",
	"CAP_RETAINED_BYTES_EQUAL",
	"CAP_RETAINED_BYTES_ABOVE",
	"CAP_DUAL_BOUNDARY",
	"CAP_VICTIM_MIN_RETENTION",
	"CAP_VICTIM_LEX_TIE",
	"CAP_MINIMAL_PREFIX",
	"CAP_CANDIDATE_WINS_EQUALITY_REJECT",
	"CAP_PAYLOAD_BELOW",
	"CAP_PAYLOAD_EQUAL",
	"CAP_PAYLOAD_ABOVE",
}

type daNodeObserverCorpus struct {
	FormatVersion int               `json:"format_version"`
	InputFixtures json.RawMessage   `json:"input_fixtures"`
	Cases         []json.RawMessage `json:"cases"`
}

type daNodeObserverCase struct {
	ID    string          `json:"id"`
	Input json.RawMessage `json:"input"`
}

type daNodeObserverOutput struct {
	FormatVersion int                      `json:"format_version"`
	Cases         []daNodeObserverOutCase `json:"cases"`
}

type daNodeObserverOutCase struct {
	ID     string         `json:"id"`
	Actual map[string]any `json:"actual"`
}

func daNodeObserverCorpusPath() string {
	if path := os.Getenv("RUBIN_DA_NODE_CORPUS"); path != "" {
		return path
	}
	return filepath.Join("..", "..", "..", "conformance", "fixtures", "protocol", "da_admission_expected_v1.json")
}

func loadDANodeObserverCorpus(path string) (daNodeObserverCorpus, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return daNodeObserverCorpus{}, nil, err
	}
	var corpus daNodeObserverCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return daNodeObserverCorpus{}, nil, fmt.Errorf("observer input corpus: %w", err)
	}
	if corpus.FormatVersion != 1 || len(corpus.Cases) == 0 || len(corpus.InputFixtures) == 0 {
		return daNodeObserverCorpus{}, nil, fmt.Errorf("observer input corpus: unsupported format or missing inputs")
	}
	return corpus, raw, nil
}

func decodeDANodeObserverInput(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("observer input: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("observer input: trailing JSON value")
	}
	return nil
}

type daNodePlannerInput struct {
	ExecutionBoundary      string `json:"execution_boundary"`
	CaseOrdinal            *uint64 `json:"case_ordinal"`
	EffectiveDAMempoolSize string `json:"effective_da_mempool_size"`
	CompleteSetMaxCount    uint64 `json:"complete_set_max_count"`
	PinnedPayloadMax       string `json:"pinned_payload_max"`
	LogicalPrestate        struct {
		ResidentClasses []struct {
			ClassOrdinal        *uint64 `json:"class_ordinal"`
			ResidentCount       uint64 `json:"resident_count"`
			DAIDRange struct {
				First string `json:"first"`
				Last  string `json:"last"`
			} `json:"da_id_range"`
			ResidentOrdinalRange struct {
				First *uint64 `json:"first"`
				Last  *uint64 `json:"last"`
			} `json:"resident_ordinal_range"`
			TotalFee               string `json:"total_fee"`
			TotalFeeLast           string `json:"total_fee_last"`
			TotalFeeStep           string `json:"total_fee_step"`
			TotalBytes             string `json:"total_bytes"`
			PayloadBytes           string `json:"payload_bytes"`
			ReceivedSequenceFirst  string `json:"received_sequence_first"`
			ReceivedSequenceLast   string `json:"received_sequence_last"`
			ReceivedSequenceStep   string `json:"received_sequence_step"`
		} `json:"resident_classes"`
		RetainedCounters struct {
			StagedRetainedBytes   string `json:"staged_retained_bytes"`
			CompleteRetainedBytes string `json:"complete_retained_bytes"`
			CompleteSetCount      uint64 `json:"complete_set_count"`
			CompletePayloadBytes  string `json:"complete_payload_bytes"`
		} `json:"retained_counters"`
		IdentityMapping struct {
			DAID string `json:"da_id"`
		} `json:"identity_mapping"`
	} `json:"logical_prestate"`
	Candidate struct {
		ClassOrdinal              *uint64 `json:"class_ordinal"`
		ResidentOrdinal           *uint64 `json:"resident_ordinal"`
		DAID                      string `json:"da_id"`
		TotalFee                  string `json:"total_fee"`
		TotalBytes                string `json:"total_bytes"`
		PayloadBytes              string `json:"payload_bytes"`
		ReceivedSequence          string `json:"received_sequence"`
		CandidatePriorStagedCharge string `json:"candidate_prior_staged_charge"`
	} `json:"candidate"`
	PreVictimProjection json.RawMessage `json:"pre_victim_projection"`
	ComparatorWitness   json.RawMessage `json:"comparator_witness"`
	TieWitness          json.RawMessage `json:"tie_witness"`
	EqualityWitness     json.RawMessage `json:"equality_witness"`
}

func parseDANodeObserverUint(label, value string) (uint64, error) {
	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("observer input %s: %w", label, err)
	}
	return v, nil
}

func parseDANodeObserverU128(label, value string) (consensus.Uint128, error) {
	v, ok := new(big.Int).SetString(value, 10)
	if !ok || v.Sign() < 0 || v.BitLen() > 128 {
		return consensus.Uint128{}, fmt.Errorf("observer input %s: invalid u128", label)
	}
	lo := v.Uint64()
	hi := new(big.Int).Rsh(new(big.Int).Set(v), 64).Uint64()
	return consensus.Uint128{Hi: hi, Lo: lo}, nil
}

func daNodeObserverIdentity(caseOrdinal, classOrdinal, residentOrdinal uint64) [32]byte {
	var id [32]byte
	id[0] = 0x52
	binary.BigEndian.PutUint64(id[8:16], caseOrdinal)
	binary.BigEndian.PutUint64(id[16:24], classOrdinal)
	binary.BigEndian.PutUint64(id[24:32], residentOrdinal)
	return id
}

func daNodeObserverHexID(id [32]byte) string { return hex.EncodeToString(id[:]) }

func cloneDANodePlannerInput(in daCompleteCapacityInput) daCompleteCapacityInput {
	copy := in
	copy.residents = append([]daCompleteCapacitySet(nil), in.residents...)
	return copy
}

func daNodeObserverExpandPlanner(id string, in daNodePlannerInput) (daCompleteCapacityInput, error) {
	var out daCompleteCapacityInput
	if in.ExecutionBoundary != "CAPACITY_PLANNER_PRECONDITION" || len(in.LogicalPrestate.ResidentClasses) == 0 || in.LogicalPrestate.IdentityMapping.DAID != "0x52 || seven 0x00 bytes || u64be(case_ordinal) || u64be(class_ordinal) || u64be(resident_ordinal)" {
		return out, fmt.Errorf("observer input %s: invalid planner shape", id)
	}
	if in.CaseOrdinal == nil || in.Candidate.ClassOrdinal == nil || in.Candidate.ResidentOrdinal == nil {
		return out, fmt.Errorf("observer input %s: missing required identity ordinal", id)
	}
	caseOrdinal := *in.CaseOrdinal
	var err error
	if out.byteCap, err = parseDANodeObserverUint("effective_da_mempool_size", in.EffectiveDAMempoolSize); err != nil {
		return out, err
	}
	payloadCap, err := parseDANodeObserverUint("pinned_payload_max", in.PinnedPayloadMax)
	if err != nil || payloadCap != daMempoolPinnedPayloadMaxBytes || in.CompleteSetMaxCount != daCompleteSetMaxCount {
		return out, fmt.Errorf("observer input %s: unsupported planner bounds", id)
	}
	if out.stagedBytes, err = parseDANodeObserverUint("staged_retained_bytes", in.LogicalPrestate.RetainedCounters.StagedRetainedBytes); err != nil {
		return out, err
	}
	if out.completeBytes, err = parseDANodeObserverUint("complete_retained_bytes", in.LogicalPrestate.RetainedCounters.CompleteRetainedBytes); err != nil {
		return out, err
	}
	if out.completePayload, err = parseDANodeObserverUint("complete_payload_bytes", in.LogicalPrestate.RetainedCounters.CompletePayloadBytes); err != nil {
		return out, err
	}
	out.completeCount = in.LogicalPrestate.RetainedCounters.CompleteSetCount
	if out.completeCount > daCompleteSetMaxCount {
		return out, fmt.Errorf("observer input %s: resident count exceeds construction bound", id)
	}
	if in.Candidate.DAID == "" {
		return out, fmt.Errorf("observer input %s: missing candidate identity", id)
	}
	candidateID, err := hex.DecodeString(in.Candidate.DAID)
	if err != nil || len(candidateID) != 32 {
		return out, fmt.Errorf("observer input %s: candidate identity is not 32 bytes", id)
	}
	candidateIDValue := daNodeObserverIdentity(caseOrdinal, *in.Candidate.ClassOrdinal, *in.Candidate.ResidentOrdinal)
	if !bytes.Equal(candidateID, candidateIDValue[:]) {
		return out, fmt.Errorf("observer input %s: candidate identity does not match its supplied ordinals", id)
	}
	out.candidate.id = candidateIDValue
	if out.candidate.fee, err = parseDANodeObserverU128("candidate.total_fee", in.Candidate.TotalFee); err != nil {
		return out, err
	}
	if out.candidate.totalBytes, err = parseDANodeObserverUint("candidate.total_bytes", in.Candidate.TotalBytes); err != nil {
		return out, err
	}
	if out.candidate.payloadBytes, err = parseDANodeObserverUint("candidate.payload_bytes", in.Candidate.PayloadBytes); err != nil {
		return out, err
	}
	if out.candidate.receivedSequence, err = parseDANodeObserverUint("candidate.received_sequence", in.Candidate.ReceivedSequence); err != nil {
		return out, err
	}
	if out.priorCredit, err = parseDANodeObserverUint("candidate_prior_staged_charge", in.Candidate.CandidatePriorStagedCharge); err != nil {
		return out, err
	}
	ids := make(map[[32]byte]struct{})
	for _, row := range in.LogicalPrestate.ResidentClasses {
		if row.ClassOrdinal == nil || row.ResidentOrdinalRange.First == nil || row.ResidentOrdinalRange.Last == nil {
			return out, fmt.Errorf("observer input %s: missing required resident ordinal", id)
		}
		firstOrdinal, lastOrdinal := *row.ResidentOrdinalRange.First, *row.ResidentOrdinalRange.Last
		if row.ResidentCount == 0 { return out, fmt.Errorf("observer input %s: invalid resident count", id) }
		if uint64(len(out.residents)) > daCompleteSetMaxCount || row.ResidentCount > daCompleteSetMaxCount-uint64(len(out.residents)) {
			return out, fmt.Errorf("observer input %s: resident count exceeds construction bound", id)
		}
		if lastOrdinal < firstOrdinal || lastOrdinal-firstOrdinal != row.ResidentCount-1 { return out, fmt.Errorf("observer input %s: invalid resident range", id) }
		fee, err := parseDANodeObserverU128("resident.total_fee", row.TotalFee)
		if err != nil { return out, err }
		feeStep := new(big.Int)
		if row.TotalFeeStep != "" {
			if _, ok := feeStep.SetString(row.TotalFeeStep, 10); !ok || feeStep.Sign() < 0 || feeStep.BitLen() > 128 { return out, fmt.Errorf("observer input %s: invalid resident fee step", id) }
		}
		seqFirst, err := parseDANodeObserverUint("resident.received_sequence_first", row.ReceivedSequenceFirst)
		if err != nil { return out, err }
		seqStep := uint64(0)
		if row.ReceivedSequenceStep != "" {
			seqStep, err = parseDANodeObserverUint("resident.received_sequence_step", row.ReceivedSequenceStep)
			if err != nil { return out, err }
		}
		bytes, err := parseDANodeObserverUint("resident.total_bytes", row.TotalBytes)
		if err != nil { return out, err }
		payload, err := parseDANodeObserverUint("resident.payload_bytes", row.PayloadBytes)
		if err != nil { return out, err }
		firstID := daNodeObserverHexID(daNodeObserverIdentity(caseOrdinal, *row.ClassOrdinal, firstOrdinal))
		lastID := daNodeObserverHexID(daNodeObserverIdentity(caseOrdinal, *row.ClassOrdinal, lastOrdinal))
		if row.DAIDRange.First != firstID || row.DAIDRange.Last != lastID {
			return out, fmt.Errorf("observer input %s: resident identity range mismatch", id)
		}
		for ordinal := uint64(0); ordinal < row.ResidentCount; ordinal++ {
			if seqStep != 0 && ordinal > (^uint64(0)-seqFirst)/seqStep { return out, fmt.Errorf("observer input %s: resident sequence overflow", id) }
			residentFee := new(big.Int).Add(new(big.Int).SetBytes(feeBytes(fee)), new(big.Int).Mul(feeStep, new(big.Int).SetUint64(ordinal)))
			if residentFee.BitLen() > 128 { return out, fmt.Errorf("observer input %s: resident fee overflow", id) }
			feeValue, err := parseDANodeObserverU128("resident fee", residentFee.String())
			if err != nil {
				return out, err
			}
			seq := seqFirst + ordinal*seqStep
			residentID := daNodeObserverIdentity(caseOrdinal, *row.ClassOrdinal, firstOrdinal+ordinal)
			if _, ok := ids[residentID]; ok || residentID == out.candidate.id { return out, fmt.Errorf("observer input %s: duplicate planner identity", id) }
			ids[residentID] = struct{}{}
			out.residents = append(out.residents, daCompleteCapacitySet{id: residentID, fee: feeValue, totalBytes: bytes, payloadBytes: payload, receivedSequence: seq})
		}
		if row.TotalFeeLast != "" && len(out.residents) > 0 {
			last, err := parseDANodeObserverU128("resident.total_fee_last", row.TotalFeeLast)
			if err != nil { return out, err }
			if out.residents[len(out.residents)-1].fee != last { return out, fmt.Errorf("observer input %s: resident fee endpoint mismatch", id) }
		}
		if row.ReceivedSequenceLast != "" && len(out.residents) > 0 {
			last, err := parseDANodeObserverUint("resident.received_sequence_last", row.ReceivedSequenceLast)
			if err != nil { return out, err }
			if out.residents[len(out.residents)-1].receivedSequence != last { return out, fmt.Errorf("observer input %s: resident sequence endpoint mismatch", id) }
		}
	}
	return out, nil
}

func feeBytes(v consensus.Uint128) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], v.Hi)
	binary.BigEndian.PutUint64(b[8:], v.Lo)
	return b
}

func observeDANodePlanner(id string, raw json.RawMessage) (map[string]any, error) {
	var input daNodePlannerInput
	if err := decodeDANodeObserverInput(raw, &input); err != nil { return nil, err }
	in, err := daNodeObserverExpandPlanner(id, input)
	if err != nil { return nil, err }
	before := cloneDANodePlannerInput(in)
	plan, err := planDACompleteCapacity(in)
	if err != nil { return nil, fmt.Errorf("observer input %s: planner: %w", id, err) }
	return projectDANodePlanner(plan, reflect.DeepEqual(before, in)), nil
}

func projectDANodePlanner(plan daCompleteCapacityPlan, inputUnchanged bool) map[string]any {
	victims := make([]string, len(plan.victims))
	for i, victim := range plan.victims { victims[i] = daNodeObserverHexID(victim) }
	actual := map[string]any{
		"capacity_plan": map[string]any{"accepted": plan.accepted, "victim_da_ids": victims},
		"input_unchanged": inputUnchanged,
	}
	if plan.accepted {
		actual["projected_counters"] = map[string]any{
			"shared_bytes": strconv.FormatUint(plan.sharedBytes, 10),
			"complete_set_count": plan.completeCount,
			"payload_bytes": strconv.FormatUint(plan.payloadBytes, 10),
		}
	}
	return actual
}

func requireDANodeObserverCaseOrder(cases []daNodeObserverCase) error {
	if len(cases) != len(daNodeObserverIDs) { return fmt.Errorf("observer census: found %d assigned cases, want %d", len(cases), len(daNodeObserverIDs)) }
	for i, want := range daNodeObserverIDs {
		if cases[i].ID != want { return fmt.Errorf("observer census: case %d is %q, want %q", i, cases[i].ID, want) }
		if len(cases[i].Input) == 0 || bytes.Equal(cases[i].Input, []byte("null")) { return fmt.Errorf("observer input %s: missing input", want) }
	}
	return nil
}

func collectDANodeObserverPlanner(c daNodeObserverCase) (daNodeObserverOutCase, error) {
	actual, err := observeDANodePlanner(c.ID, c.Input)
	if err != nil { return daNodeObserverOutCase{}, err }
	return daNodeObserverOutCase{ID: c.ID, Actual: actual}, nil
}

func TestDAAdmissionObserverNodeProjection(t *testing.T) {
	var first, second [32]byte
	first[31], second[31] = 1, 2
	plan := daCompleteCapacityPlan{
		accepted: true, victims: [][32]byte{first, second}, sharedBytes: 123, completeCount: 7, payloadBytes: 89,
	}
	accepted := projectDANodePlanner(plan, true)
	wantAccepted := map[string]any{
		"capacity_plan": map[string]any{
			"accepted": true,
			"victim_da_ids": []string{
				"0000000000000000000000000000000000000000000000000000000000000001",
				"0000000000000000000000000000000000000000000000000000000000000002",
			},
		},
		"input_unchanged": true,
		"projected_counters": map[string]any{"shared_bytes": "123", "complete_set_count": uint64(7), "payload_bytes": "89"},
	}
	if !reflect.DeepEqual(accepted, wantAccepted) { t.Fatalf("observer projection accepted=%v", accepted) }
	refused := projectDANodePlanner(daCompleteCapacityPlan{
		sharedBytes: 456, completeCount: 11, payloadBytes: 12,
	}, false)
	wantRefused := map[string]any{
		"capacity_plan": map[string]any{"accepted": false, "victim_da_ids": []string{}},
		"input_unchanged": false,
	}
	if !reflect.DeepEqual(refused, wantRefused) { t.Fatalf("observer projection refusal=%v", refused) }
	plan.victims[0][31] = 9
	if accepted["capacity_plan"].(map[string]any)["victim_da_ids"].([]string)[0] != wantAccepted["capacity_plan"].(map[string]any)["victim_da_ids"].([]string)[0] {
		t.Fatal("observer alias: actual projection aliases the returned planner victim slice")
	}
}

func TestDAAdmissionObserverNodeAlias(t *testing.T) {
	input := daCompleteCapacityInput{residents: []daCompleteCapacitySet{{id: [32]byte{1}, fee: consensus.Uint128{Hi: 2, Lo: 3}, totalBytes: 4, payloadBytes: 5, receivedSequence: 6}}}
	saved := cloneDANodePlannerInput(input)
	input.residents[0].id[0] = 9
	if saved.residents[0].id[0] != 1 { t.Fatal("observer alias: source mutation changed saved resident copy") }
	saved.residents[0].fee.Lo = 8
	if input.residents[0].fee.Lo != 3 { t.Fatal("observer alias: copy mutation changed source resident") }
}

func poisonDANodeObserverExpectations(raw []byte) ([]byte, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil { return nil, err }
	var cases []json.RawMessage
	if err := json.Unmarshal(root["cases"], &cases); err != nil { return nil, err }
	poison := json.RawMessage(`{"poison":true}`)
	expectCount := 0
	annotationCounts := map[string]int{"pre_victim_projection": 0, "comparator_witness": 0, "tie_witness": 0, "equality_witness": 0}
	for i, item := range cases {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(item, &row); err != nil { return nil, err }
		if _, ok := row["expect"]; ok {
			row["expect"] = poison
			expectCount++
		}
		var id string
		if err := json.Unmarshal(row["id"], &id); err != nil { return nil, err }
		if assignedDANodeObserverIndex(id) >= 0 {
			var input map[string]json.RawMessage
			if err := json.Unmarshal(row["input"], &input); err != nil { return nil, err }
			for field := range annotationCounts {
				if _, ok := input[field]; ok { input[field] = poison; annotationCounts[field]++ }
			}
			encodedInput, err := json.Marshal(input)
			if err != nil { return nil, err }
			row["input"] = encodedInput
		}
		encodedRow, err := json.Marshal(row)
		if err != nil { return nil, err }
		cases[i] = encodedRow
	}
	if expectCount == 0 { return nil, fmt.Errorf("observer expected isolation: corpus has no expect fields") }
	for field, count := range annotationCounts {
		if count == 0 { return nil, fmt.Errorf("observer expected isolation: annotation %s absent", field) }
	}
	encodedCases, err := json.Marshal(cases)
	if err != nil { return nil, err }
	root["cases"] = encodedCases
	for _, receipt := range []string{"forward_receipt", "reverse_receipt"} {
		if len(root[receipt]) == 0 { return nil, fmt.Errorf("observer expected isolation: missing %s", receipt) }
		poisonedReceipt, err := json.Marshal("poison-" + receipt)
		if err != nil { return nil, err }
		root[receipt] = poisonedReceipt
	}
	return json.Marshal(root)
}

func TestDAAdmissionObserverNodeExpectedIsolation(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	if err != nil { t.Fatalf("observer expected isolation input: %v", err) }
	before, err := collectDANodeObserver(raw)
	if err != nil { t.Fatalf("observer expected isolation baseline: %v", err) }
	poisoned, err := poisonDANodeObserverExpectations(raw)
	if err != nil { t.Fatal(err) }
	after, err := collectDANodeObserver(poisoned)
	if err != nil { t.Fatalf("observer expected isolation poisoned collection: %v", err) }
	if !bytes.Equal(before, after) { t.Fatal("observer expected isolation: expected/receipt/annotation mutation changed actual bytes") }
}

func mutateDANodeObserverInput(t *testing.T, raw []byte, caseID string, mutate func(map[string]json.RawMessage) error) []byte {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil { t.Fatal(err) }
	var cases []json.RawMessage
	if err := json.Unmarshal(root["cases"], &cases); err != nil { t.Fatal(err) }
	found := 0
	for i, item := range cases {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(item, &row); err != nil { t.Fatal(err) }
		var id string
		if err := json.Unmarshal(row["id"], &id); err != nil { t.Fatal(err) }
		if id != caseID { continue }
		var input map[string]json.RawMessage
		if err := json.Unmarshal(row["input"], &input); err != nil { t.Fatal(err) }
		if err := mutate(input); err != nil { t.Fatal(err) }
		encodedInput, err := json.Marshal(input)
		if err != nil { t.Fatal(err) }
		row["input"] = encodedInput
		cases[i], err = json.Marshal(row)
		if err != nil { t.Fatal(err) }
		found++
	}
	if found != 1 { t.Fatalf("observer census: mutation target %s count=%d", caseID, found) }
	encodedCases, err := json.Marshal(cases)
	if err != nil { t.Fatal(err) }
	root["cases"] = encodedCases
	mutated, err := json.Marshal(root)
	if err != nil { t.Fatal(err) }
	return mutated
}

func observerActualBytes(t *testing.T, output daNodeObserverOutput, id string) []byte {
	t.Helper()
	for _, row := range output.Cases {
		if row.ID == id {
			encoded, err := json.Marshal(row.Actual)
			if err != nil { t.Fatal(err) }
			return encoded
		}
	}
	t.Fatalf("observer census: output missing %s", id)
	return nil
}

func TestDAAdmissionObserverNodeInputReachability(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	if err != nil { t.Fatalf("observer input reachability corpus: %v", err) }
	baseBytes, err := collectDANodeObserver(raw)
	if err != nil { t.Fatalf("observer input reachability baseline: %v", err) }
	var base daNodeObserverOutput
	if err := json.Unmarshal(baseBytes, &base); err != nil { t.Fatal(err) }
	for _, id := range daNodeObserverIDs {
		plan := base.Cases[assignedDANodeObserverIndex(id)].Actual["capacity_plan"].(map[string]any)
		if id != "CAP_CANDIDATE_WINS_EQUALITY_REJECT" && plan["accepted"] != true { t.Fatalf("observer input reachability %s: frozen plan was not accepted", id) }
		mutated := mutateDANodeObserverInput(t, raw, id, func(input map[string]json.RawMessage) error {
			var candidate map[string]json.RawMessage
			if err := json.Unmarshal(input["candidate"], &candidate); err != nil { return err }
			field := "total_bytes"
			if id == "CAP_CANDIDATE_WINS_EQUALITY_REJECT" { field = "total_fee" }
			var decimal string
			if err := json.Unmarshal(candidate[field], &decimal); err != nil { return fmt.Errorf("observer input reachability %s: %w", id, err) }
			value, err := strconv.ParseUint(decimal, 10, 64)
			if err != nil || value == ^uint64(0) { return fmt.Errorf("observer input reachability %s: candidate increment overflows", id) }
			candidate[field], err = json.Marshal(strconv.FormatUint(value+1, 10))
			if err != nil { return err }
			input["candidate"], err = json.Marshal(candidate)
			return err
		})
		changedBytes, err := collectDANodeObserver(mutated)
		if err != nil { t.Fatalf("observer input reachability %s: %v", id, err) }
		var changed daNodeObserverOutput
		if err := json.Unmarshal(changedBytes, &changed); err != nil { t.Fatal(err) }
		if bytes.Equal(observerActualBytes(t, base, id), observerActualBytes(t, changed, id)) { t.Fatalf("observer input reachability %s: actual row unchanged", id) }
	}
}

func requireDANodeObserverInputFailure(t *testing.T, raw []byte, id, label, diagnostic string, mutate func(map[string]json.RawMessage) error) {
	t.Helper()
	changed := mutateDANodeObserverInput(t, raw, id, mutate)
	_, err := collectDANodeObserver(changed)
	matched := err != nil && strings.Contains(err.Error(), diagnostic)
	if diagnostic == "resident sequence overflow" || diagnostic == "resident fee overflow" || diagnostic == "resident identity range mismatch" || diagnostic == "resident count exceeds construction bound" {
		matched = err != nil && strings.HasSuffix(err.Error(), diagnostic)
	}
	if !matched {
		t.Fatalf("observer input %s: error=%v", label, err)
	}
}

func mutateDANodeObserverCaseList(t *testing.T, raw []byte, mutate func([]json.RawMessage) []json.RawMessage) []byte {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil { t.Fatal(err) }
	var cases []json.RawMessage
	if err := json.Unmarshal(root["cases"], &cases); err != nil { t.Fatal(err) }
	encoded, err := json.Marshal(mutate(cases))
	if err != nil { t.Fatal(err) }
	root["cases"] = encoded
	changed, err := json.Marshal(root)
	if err != nil { t.Fatal(err) }
	return changed
}

func TestDAAdmissionObserverNodeIntegrity(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	if err != nil { t.Fatalf("observer integrity corpus: %v", err) }
	unchanged := bytes.Clone(raw)
	if _, err := collectDANodeObserver(raw); err != nil { t.Fatalf("observer integrity baseline: %v", err) }
	if !bytes.Equal(raw, unchanged) { t.Fatal("observer alias: collection changed source corpus bytes") }
	for label, changed := range map[string][]byte{
		"missing": mutateDANodeObserverCaseList(t, raw, func(cases []json.RawMessage) []json.RawMessage {
			return slicesDeleteCase(t, cases, daNodeObserverIDs[0])
		}),
		"duplicate": mutateDANodeObserverCaseList(t, raw, func(cases []json.RawMessage) []json.RawMessage {
			return append(cases, findDANodeObserverCase(t, cases, daNodeObserverIDs[0]))
		}),
		"unknown": mutateDANodeObserverCaseList(t, raw, func(cases []json.RawMessage) []json.RawMessage {
			return renameDANodeObserverCase(t, cases, daNodeObserverIDs[0], "CAP_UNKNOWN")
		}),
		"reordered": mutateDANodeObserverCaseList(t, raw, func(cases []json.RawMessage) []json.RawMessage {
			return swapDANodeObserverCases(t, cases, daNodeObserverIDs[0], daNodeObserverIDs[1])
		}),
	} {
		if _, err := collectDANodeObserver(changed); err == nil || !strings.Contains(err.Error(), "observer census") { t.Fatalf("observer census %s error=%v", label, err) }
	}
	candidateField := func(field string, value json.RawMessage) func(map[string]json.RawMessage) error {
		return func(input map[string]json.RawMessage) error {
			return editDANodeObserverNested(input, "candidate", func(candidate map[string]json.RawMessage) error {
				candidate[field] = value
				return nil
			})
		}
	}
	mutations := []struct {
		label, id, diagnostic string
		edit func(map[string]json.RawMessage) error
	}{
		{"missing case ordinal", "CAP_RETAINED_BYTES_BELOW", "missing required identity ordinal", func(in map[string]json.RawMessage) error { delete(in, "case_ordinal"); return nil }},
		{"missing candidate class ordinal", "CAP_RETAINED_BYTES_BELOW", "missing required identity ordinal", func(in map[string]json.RawMessage) error { return editDANodeObserverNested(in, "candidate", func(v map[string]json.RawMessage) error { delete(v, "class_ordinal"); return nil }) }},
		{"missing resident ordinal", "CAP_RETAINED_BYTES_BELOW", "missing required identity ordinal", func(in map[string]json.RawMessage) error { return editDANodeObserverNested(in, "candidate", func(v map[string]json.RawMessage) error { delete(v, "resident_ordinal"); return nil }) }},
		{"missing resident class ordinal", "CAP_RETAINED_BYTES_BELOW", "missing required resident ordinal", func(in map[string]json.RawMessage) error { return editDANodeObserverResident(in, 0, func(v map[string]json.RawMessage) error { delete(v, "class_ordinal"); return nil }) }},
		{"missing range first ordinal", "CAP_RETAINED_BYTES_BELOW", "missing required resident ordinal", func(in map[string]json.RawMessage) error { return editDANodeObserverResident(in, 0, func(v map[string]json.RawMessage) error { return editDANodeObserverNested(v, "resident_ordinal_range", func(r map[string]json.RawMessage) error { delete(r, "first"); return nil }) }) }},
		{"unknown owned field", "CAP_RETAINED_BYTES_BELOW", "unknown field", candidateField("unknown", json.RawMessage(`1`))},
		{"u64 width", "CAP_RETAINED_BYTES_BELOW", "candidate.total_bytes", candidateField("total_bytes", json.RawMessage(`"18446744073709551616"`))},
		{"u128 width", "CAP_RETAINED_BYTES_BELOW", "candidate.total_fee", candidateField("total_fee", json.RawMessage(`"340282366920938463463374607431768211456"`))},
		{"capacity width", "CAP_RETAINED_BYTES_BELOW", "effective_da_mempool_size", func(in map[string]json.RawMessage) error { in["effective_da_mempool_size"] = json.RawMessage(`"18446744073709551616"`); return nil }},
		{"complete set bound", "CAP_RETAINED_BYTES_BELOW", "unsupported planner bounds", func(in map[string]json.RawMessage) error { in["complete_set_max_count"] = json.RawMessage(`65535`); return nil }},
		{"pinned payload bound", "CAP_RETAINED_BYTES_BELOW", "unsupported planner bounds", func(in map[string]json.RawMessage) error { in["pinned_payload_max"] = json.RawMessage(`"95999999"`); return nil }},
		{"hex width", "CAP_RETAINED_BYTES_BELOW", "candidate identity is not 32 bytes", candidateField("da_id", json.RawMessage(`"00"`))},
		{"candidate identity", "CAP_RETAINED_BYTES_BELOW", "candidate identity does not match", candidateField("da_id", json.RawMessage(`"5000000000000000000000000000001f000000000000ffff0000000000000000"`))},
		{"missing resident range", "CAP_RETAINED_BYTES_BELOW", "missing required resident ordinal", removeDANodeObserverResidentRange},
		{"identity mapping", "CAP_RETAINED_BYTES_BELOW", "invalid planner shape", identityMappingDANodeObserverMutation},
		{"range endpoint", "CAP_RETAINED_BYTES_BELOW", "resident identity range mismatch", rangeEndpointDANodeObserverMutation},
		{"sequence progression overflow", "CAP_SET_COUNT_BELOW", "resident sequence overflow", func(in map[string]json.RawMessage) error { return editDANodeObserverResident(in, 0, func(r map[string]json.RawMessage) error { r["received_sequence_first"] = json.RawMessage(`"18446744073709551615"`); r["received_sequence_step"] = json.RawMessage(`"1"`); return nil }) }},
		{"fee progression overflow", "CAP_SET_COUNT_BELOW", "resident fee overflow", func(in map[string]json.RawMessage) error { return editDANodeObserverResident(in, 0, func(r map[string]json.RawMessage) error { r["total_fee"] = json.RawMessage(`"340282366920938463463374607431768211455"`); r["total_fee_step"] = json.RawMessage(`"1"`); return nil }) }},
		{"resident bound", "CAP_SET_COUNT_BELOW", "resident count exceeds construction bound", residentBoundDANodeObserverMutation},
		{"duplicate identity", "CAP_RETAINED_BYTES_BELOW", "duplicate planner identity", duplicateDANodeObserverResident},
	}
	for _, mutation := range mutations {
		requireDANodeObserverInputFailure(t, raw, mutation.id, mutation.label, mutation.diagnostic, mutation.edit)
	}
}

func editDANodeObserverNested(input map[string]json.RawMessage, field string, edit func(map[string]json.RawMessage) error) error {
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(input[field], &nested); err != nil { return err }
	if err := edit(nested); err != nil { return err }
	encoded, err := json.Marshal(nested)
	if err != nil { return err }
	input[field] = encoded
	return nil
}

func editDANodeObserverResident(input map[string]json.RawMessage, index int, edit func(map[string]json.RawMessage) error) error {
	return editDANodeObserverNested(input, "logical_prestate", func(logical map[string]json.RawMessage) error {
		var residents []json.RawMessage
		if err := json.Unmarshal(logical["resident_classes"], &residents); err != nil { return err }
		if index < 0 || index >= len(residents) { return fmt.Errorf("resident index %d out of range", index) }
		var resident map[string]json.RawMessage
		if err := json.Unmarshal(residents[index], &resident); err != nil { return err }
		if err := edit(resident); err != nil { return err }
		encoded, err := json.Marshal(resident)
		if err != nil { return err }
		residents[index] = encoded
		encoded, err = json.Marshal(residents)
		if err != nil { return err }
		logical["resident_classes"] = encoded
		return err
	})
}

func removeDANodeObserverResidentRange(input map[string]json.RawMessage) error {
	return editDANodeObserverResident(input, 0, func(resident map[string]json.RawMessage) error {
		delete(resident, "resident_ordinal_range")
		return nil
	})
}

func rangeEndpointDANodeObserverMutation(input map[string]json.RawMessage) error {
	var planner daNodePlannerInput
	encodedInput, err := json.Marshal(input)
	if err != nil { return err }
	if err := json.Unmarshal(encodedInput, &planner); err != nil { return err }
	if planner.CaseOrdinal == nil || len(planner.LogicalPrestate.ResidentClasses) == 0 || planner.LogicalPrestate.ResidentClasses[0].ClassOrdinal == nil || planner.LogicalPrestate.ResidentClasses[0].ResidentOrdinalRange.First == nil { return fmt.Errorf("observer input range mutation: missing ordinals") }
	first := *planner.LogicalPrestate.ResidentClasses[0].ResidentOrdinalRange.First
	if first == ^uint64(0) { return fmt.Errorf("observer input range mutation: ordinal overflow") }
	wrongLast := daNodeObserverHexID(daNodeObserverIdentity(*planner.CaseOrdinal, *planner.LogicalPrestate.ResidentClasses[0].ClassOrdinal, first+1))
	return editDANodeObserverResident(input, 0, func(resident map[string]json.RawMessage) error {
		return editDANodeObserverNested(resident, "da_id_range", func(ids map[string]json.RawMessage) error {
			encoded, err := json.Marshal(wrongLast)
			if err == nil { ids["last"] = encoded }
			return err
		})
	})
}

func residentBoundDANodeObserverMutation(input map[string]json.RawMessage) error {
	var planner daNodePlannerInput
	encodedInput, err := json.Marshal(input)
	if err != nil { return err }
	if err := json.Unmarshal(encodedInput, &planner); err != nil { return err }
	if planner.CaseOrdinal == nil || len(planner.LogicalPrestate.ResidentClasses) == 0 || planner.LogicalPrestate.ResidentClasses[0].ClassOrdinal == nil || planner.LogicalPrestate.ResidentClasses[0].ResidentOrdinalRange.First == nil { return fmt.Errorf("observer input bound mutation: missing ordinals") }
	first := *planner.LogicalPrestate.ResidentClasses[0].ResidentOrdinalRange.First
	if first > ^uint64(0)-65536 { return fmt.Errorf("observer input bound mutation: ordinal overflow") }
	last := first + 65536
	lastID := daNodeObserverHexID(daNodeObserverIdentity(*planner.CaseOrdinal, *planner.LogicalPrestate.ResidentClasses[0].ClassOrdinal, last))
	return editDANodeObserverResident(input, 0, func(resident map[string]json.RawMessage) error {
		count, err := json.Marshal(uint64(65537))
		if err != nil { return err }
		resident["resident_count"] = count
		if err := editDANodeObserverNested(resident, "resident_ordinal_range", func(r map[string]json.RawMessage) error {
			raw, err := json.Marshal(last)
			if err == nil { r["last"] = raw }
			return err
		}); err != nil { return err }
		return editDANodeObserverNested(resident, "da_id_range", func(r map[string]json.RawMessage) error {
			raw, err := json.Marshal(lastID)
			if err == nil { r["last"] = raw }
			return err
		})
	})
}

func identityMappingDANodeObserverMutation(input map[string]json.RawMessage) error {
	return editDANodeObserverNested(input, "logical_prestate", func(logical map[string]json.RawMessage) error {
		return editDANodeObserverNested(logical, "identity_mapping", func(mapping map[string]json.RawMessage) error {
			mapping["da_id"] = json.RawMessage(`"unsupported"`)
			return nil
		})
	})
}

func duplicateDANodeObserverResident(input map[string]json.RawMessage) error {
	return editDANodeObserverNested(input, "logical_prestate", func(logical map[string]json.RawMessage) error {
		var residents []json.RawMessage
		if err := json.Unmarshal(logical["resident_classes"], &residents); err != nil { return err }
		if len(residents) == 0 { return fmt.Errorf("no resident class to duplicate") }
		encoded, err := json.Marshal(append(residents, json.RawMessage(bytes.Clone(residents[0]))))
		if err != nil { return err }
		logical["resident_classes"] = encoded
		return nil
	})
}

func observerCaseID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var row struct { ID string `json:"id"` }
	if err := json.Unmarshal(raw, &row); err != nil { t.Fatalf("observer census case: %v", err) }
	return row.ID
}

func findDANodeObserverCase(t *testing.T, cases []json.RawMessage, id string) json.RawMessage {
	t.Helper()
	for _, row := range cases { if observerCaseID(t, row) == id { return bytes.Clone(row) } }
	t.Fatalf("observer census: missing case %s", id)
	return nil
}

func slicesDeleteCase(t *testing.T, cases []json.RawMessage, id string) []json.RawMessage {
	t.Helper()
	for i, row := range cases {
		if observerCaseID(t, row) == id { return append(cases[:i], cases[i+1:]...) }
	}
	return cases
}

func renameDANodeObserverCase(t *testing.T, cases []json.RawMessage, from, to string) []json.RawMessage {
	t.Helper()
	for i, raw := range cases {
		if observerCaseID(t, raw) != from { continue }
		var row map[string]json.RawMessage
		if err := json.Unmarshal(raw, &row); err != nil { t.Fatal(err) }
		encodedID, err := json.Marshal(to)
		if err != nil { t.Fatal(err) }
		row["id"] = encodedID
		cases[i], err = json.Marshal(row)
		if err != nil { t.Fatal(err) }
		return cases
	}
	t.Fatalf("observer census: missing case %s", from)
	return cases
}

func swapDANodeObserverCases(t *testing.T, cases []json.RawMessage, first, second string) []json.RawMessage {
	t.Helper()
	firstIndex, secondIndex := -1, -1
	for i, raw := range cases {
		switch observerCaseID(t, raw) {
		case first: firstIndex = i
		case second: secondIndex = i
		}
	}
	if firstIndex < 0 || secondIndex < 0 { t.Fatalf("observer census: missing cases %s/%s", first, second) }
	cases[firstIndex], cases[secondIndex] = cases[secondIndex], cases[firstIndex]
	return cases
}

func assignedDANodeObserverIndex(id string) int {
	for i, assigned := range daNodeObserverIDs {
		if id == assigned { return i }
	}
	return -1
}

func selectDANodeObserverCases(corpus daNodeObserverCorpus) ([]daNodeObserverCase, error) {
	selected := make([]daNodeObserverCase, 0, len(daNodeObserverIDs))
	for _, raw := range corpus.Cases {
		var row daNodeObserverCase
		if err := json.Unmarshal(raw, &row); err != nil { return nil, fmt.Errorf("observer census: invalid case: %w", err) }
		index := assignedDANodeObserverIndex(row.ID)
		if index < 0 {
			var input map[string]json.RawMessage
			if len(row.Input) != 0 && !bytes.Equal(row.Input, []byte("null")) {
				if err := json.Unmarshal(row.Input, &input); err != nil {
					return nil, fmt.Errorf("observer census: cannot classify unassigned case input: %w", err)
				}
			}
			var boundary string
			if value := input["execution_boundary"]; len(value) != 0 {
				if err := json.Unmarshal(value, &boundary); err != nil {
					return nil, fmt.Errorf("observer census: invalid unassigned case boundary: %w", err)
				}
			}
			if boundary == "CAPACITY_PLANNER_PRECONDITION" {
				return nil, fmt.Errorf("observer census: unknown owned case %q", row.ID)
			}
			continue
		}
		if index != len(selected) { return nil, fmt.Errorf("observer census: duplicate or out-of-order case %q", row.ID) }
		if len(row.Input) == 0 || bytes.Equal(row.Input, []byte("null")) { return nil, fmt.Errorf("observer input %s: missing input", row.ID) }
		selected = append(selected, row)
	}
	if err := requireDANodeObserverCaseOrder(selected); err != nil { return nil, err }
	return selected, nil
}

func collectDANodeObserver(raw []byte) ([]byte, error) {
	var corpus daNodeObserverCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil { return nil, fmt.Errorf("observer input corpus: %w", err) }
	if corpus.FormatVersion != 1 || len(corpus.InputFixtures) == 0 { return nil, fmt.Errorf("observer input corpus: missing versioned inputs") }
	cases, err := selectDANodeObserverCases(corpus)
	if err != nil { return nil, err }
	out := daNodeObserverOutput{FormatVersion: 1, Cases: make([]daNodeObserverOutCase, 0, len(cases))}
	for _, c := range cases {
		observed, err := collectDANodeObserverPlanner(c)
		if err != nil { return nil, err }
		if observed.ID != c.ID || observed.Actual == nil { return nil, fmt.Errorf("observer input %s: incomplete actual record", c.ID) }
		out.Cases = append(out.Cases, observed)
	}
	encoded, err := json.Marshal(out)
	if err != nil { return nil, fmt.Errorf("observer output: %w", err) }
	return append(encoded, '\n'), nil
}

func TestDAAdmissionObserverNode(t *testing.T) {
	_, raw, err := loadDANodeObserverCorpus(daNodeObserverCorpusPath())
	if err != nil { t.Fatalf("observer input corpus: %v", err) }
	actual, err := collectDANodeObserver(raw)
	if err != nil { t.Fatal(err) }
	var output daNodeObserverOutput
	if err := json.Unmarshal(actual, &output); err != nil { t.Fatalf("observer output: %v", err) }
	if output.FormatVersion != 1 || len(output.Cases) != len(daNodeObserverIDs) { t.Fatalf("observer census: output version=%d cases=%d", output.FormatVersion, len(output.Cases)) }
	if path := os.Getenv("RUBIN_DA_NODE_ACTUAL_OUT"); path != "" {
		if err := os.WriteFile(path, actual, 0o600); err != nil { t.Fatalf("observer output write: %v", err) }
	}
}
