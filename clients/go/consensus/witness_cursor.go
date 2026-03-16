package consensus

// InputWitnessAssignment records the per-input witness slice boundaries
// within tx.Witness. Start is inclusive, End is exclusive.
// Slots is the number of witness items consumed by this input.
type InputWitnessAssignment struct {
	Start int // inclusive offset into tx.Witness
	End   int // exclusive offset into tx.Witness
	Slots int // number of witness items (End - Start)
}

// ComputeWitnessAssignments deterministically computes per-input witness
// slice boundaries for a non-coinbase transaction. The function implements
// the canonical sequential cursor model: for each input, WitnessSlots()
// determines the number of witness items consumed; the cursor advances
// by that amount.
//
// resolvedInputs must be in input order and must have the same length as
// tx.Inputs. Each entry provides the CovenantType and CovenantData needed
// to compute witness slot counts.
//
// On success, returns one InputWitnessAssignment per input and the total
// number of witness slots consumed. The caller must separately verify that
// the total equals len(tx.Witness) if full-consumption semantics are required.
//
// Returns an error if:
//   - resolvedInputs length mismatches tx.Inputs
//   - WitnessSlots returns an error or non-positive count
//   - the cursor would exceed len(tx.Witness) (witness underflow)
func ComputeWitnessAssignments(
	tx *Tx,
	resolvedInputs []UtxoEntry,
) ([]InputWitnessAssignment, int, error) {
	if len(resolvedInputs) != len(tx.Inputs) {
		return nil, 0, txerr(TX_ERR_PARSE, "resolvedInputs length mismatch")
	}

	assignments := make([]InputWitnessAssignment, len(tx.Inputs))
	cursor := 0

	for i, entry := range resolvedInputs {
		slots, err := WitnessSlots(entry.CovenantType, entry.CovenantData)
		if err != nil {
			return nil, 0, err
		}
		if slots <= 0 {
			return nil, 0, txerr(TX_ERR_PARSE, "invalid witness slots")
		}
		if cursor+slots > len(tx.Witness) {
			return nil, 0, txerr(TX_ERR_PARSE, "witness underflow")
		}
		assignments[i] = InputWitnessAssignment{
			Start: cursor,
			End:   cursor + slots,
			Slots: slots,
		}
		cursor += slots
	}

	return assignments, cursor, nil
}
