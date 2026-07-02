package simplicity

type EvalHost interface {
	Charge(cost uint64) error
	Cost() uint64
	ReadIntrinsic(ContextIntrinsic) (IntrinsicResult, error)
}

type ContextIntrinsic struct {
	ID, Index       uint16
	Name, Signature string
}

type IntrinsicResult struct{ Accepted bool }

func LookupContextIntrinsic(id uint16) (ContextIntrinsic, bool) {
	row, ok := contextIntrinsicByID[id]
	return row, ok
}

func ContextSchemaHash() [32]byte { return contextSchemaHashValue }

func contextIntrinsicRowsByID(rows []ContextIntrinsic) map[uint16]ContextIntrinsic {
	out := make(map[uint16]ContextIntrinsic, len(rows))
	for _, row := range rows {
		out[row.ID] = row
	}
	return out
}

func evaluateJetWithHost(result EvalResult, host EvalHost) (EvalResult, error) {
	err := host.Charge(result.Cost)
	result.Cost = host.Cost()
	if err != nil {
		return result, err
	}
	if !result.Accepted {
		return result, &Error{Code: ErrRejected}
	}
	return result, nil
}

func evaluateJetWithLocalMeter(result EvalResult) (EvalResult, error) {
	var meter meter
	err := meter.charge(result.Cost)
	result.Cost = meter.cost
	if err != nil {
		return result, err
	}
	if !result.Accepted {
		return result, &Error{Code: ErrRejected}
	}
	return result, nil
}

func (p Program) evaluateStepProgram(opts EvalOptions) (EvalResult, error) {
	if opts.Host != nil {
		return evaluateStepsWithHost(p.evalSteps, opts.Host)
	}
	return evaluateSteps(p.evalSteps)
}

func (p Program) evaluateIntrinsics(opts EvalOptions) (EvalResult, error) {
	if opts.Host == nil {
		return EvalResult{}, &Error{Code: ErrDecode}
	}
	if p.evalSteps > 0 {
		if err := chargeSteps(opts.Host, p.evalSteps); err != nil {
			return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, err
		}
	}
	for _, intrinsic := range p.intrinsics {
		if opts.Host.Cost() >= MaxExecCost {
			return EvalResult{Accepted: true, Cost: MaxExecCost}, &Error{Code: ErrBudgetExceeded}
		}
		result, err := opts.Host.ReadIntrinsic(intrinsic)
		if err != nil {
			return EvalResult{Accepted: result.Accepted, Cost: opts.Host.Cost()}, err
		}
	}
	return EvalResult{Accepted: true, Cost: opts.Host.Cost()}, nil
}

func evaluateStepsWithHost(steps uint64, host EvalHost) (EvalResult, error) {
	err := chargeSteps(host, steps)
	return EvalResult{Accepted: true, Cost: host.Cost()}, err
}

func chargeSteps(host EvalHost, steps uint64) error {
	if StepCost == 0 || steps == 0 {
		return nil
	}
	if steps > MaxExecCost/StepCost {
		if err := host.Charge(MaxExecCost); err != nil {
			return err
		}
		return &Error{Code: ErrBudgetExceeded}
	}
	return host.Charge(steps * StepCost)
}

var contextSchemaHashValue = hex32("e832db3008c355262420c63168c1c9787a69aac31d15a50a640f0301d8410150")
var contextIntrinsicByID = contextIntrinsicRowsByID(contextIntrinsicRows)
var contextChainIDRow = contextIntrinsicByID[0x0100]

var contextIntrinsicRows = []ContextIntrinsic{
	{ID: 0x0100, Name: "ctx_chain_id", Signature: "unit -> bytes32"},
	{ID: 0x0101, Name: "ctx_height", Signature: "unit -> u64"},
	{ID: 0x0102, Name: "ctx_tx_kind", Signature: "unit -> u8"},
	{ID: 0x0103, Name: "ctx_tx_nonce", Signature: "unit -> u64"},
	{ID: 0x0104, Name: "ctx_locktime", Signature: "unit -> u32"},
	{ID: 0x0105, Name: "ctx_input_count", Signature: "unit -> u16"},
	{ID: 0x0106, Name: "ctx_output_count", Signature: "unit -> u16"},
	{ID: 0x0107, Name: "ctx_total_in", Signature: "unit -> u128"},
	{ID: 0x0108, Name: "ctx_total_out", Signature: "unit -> u128"},
	{ID: 0x0110, Name: "ctx_self_input_index", Signature: "unit -> u16"},
	{ID: 0x0111, Name: "ctx_self_value", Signature: "unit -> u64"},
	{ID: 0x0112, Name: "ctx_self_state", Signature: "unit -> bytes"},
	{ID: 0x0113, Name: "ctx_self_program_cmr", Signature: "unit -> bytes32"},
	{ID: 0x0114, Name: "ctx_self_sighash_type", Signature: "unit -> u8"},
	{ID: 0x0115, Name: "ctx_self_digest32", Signature: "unit -> bytes32"},
	{ID: 0x0120, Name: "ctx_inputs_value", Signature: "u16 -> Either<unit, u64>"},
	{ID: 0x0121, Name: "ctx_inputs_covenant_type", Signature: "u16 -> Either<unit, u16>"},
	{ID: 0x0122, Name: "ctx_inputs_descriptor_hash", Signature: "u16 -> Either<unit, bytes32>"},
	{ID: 0x0128, Name: "ctx_outputs_value", Signature: "u16 -> Either<unit, u64>"},
	{ID: 0x0129, Name: "ctx_outputs_covenant_type", Signature: "u16 -> Either<unit, u16>"},
	{ID: 0x012a, Name: "ctx_outputs_descriptor_hash", Signature: "u16 -> Either<unit, bytes32>"},
	{ID: 0x0130, Name: "ctx_group_inputs_value", Signature: "u16 -> Either<unit, u64>"},
	{ID: 0x0131, Name: "ctx_group_inputs_state_bytes", Signature: "u16 -> Either<unit, bytes>"},
	{ID: 0x0138, Name: "ctx_group_outputs_value", Signature: "u16 -> Either<unit, u64>"},
	{ID: 0x0139, Name: "ctx_group_outputs_state_bytes", Signature: "u16 -> Either<unit, bytes>"},
	{ID: 0x0140, Name: "ctx_da_commit_da_id", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0141, Name: "ctx_da_commit_chunk_count", Signature: "unit -> Either<unit, u16>"},
	{ID: 0x0142, Name: "ctx_da_commit_retl_domain_id", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0143, Name: "ctx_da_commit_batch_number", Signature: "unit -> Either<unit, u64>"},
	{ID: 0x0144, Name: "ctx_da_commit_tx_data_root", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0145, Name: "ctx_da_commit_state_root", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0146, Name: "ctx_da_commit_withdrawals_root", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0150, Name: "ctx_da_chunk_da_id", Signature: "unit -> Either<unit, bytes32>"},
	{ID: 0x0151, Name: "ctx_da_chunk_chunk_index", Signature: "unit -> Either<unit, u16>"},
	{ID: 0x0152, Name: "ctx_da_chunk_chunk_hash", Signature: "unit -> Either<unit, bytes32>"},
}
