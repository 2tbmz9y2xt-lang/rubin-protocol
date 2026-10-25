package consensus

// ConnectBlockParallelSigVerify connects a block against an in-memory UTXO
// snapshot with parallel signature verification. This is an IBD-only
// optimization: all fast pre-checks (UTXO lookup, covenant parse, witness
// assignment, value conservation) are performed sequentially, while the
// expensive ML-DSA-87 signature verifications are collected into a
// SigCheckQueue and executed in parallel using a goroutine pool.
//
// Earlier produced transaction results are selected before a later transaction's
// synchronous failure or panic. Complete canonical transaction stage production
// remains a separate responsibility of the transaction engine.
//
// The workers parameter controls the goroutine pool size for signature
// verification. If workers <= 0, defaults to GOMAXPROCS.
func ConnectBlockParallelSigVerify(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	workers int,
) (*ConnectBlockBasicSummary, error) {
	return ConnectBlockParallelSigVerifyWithSuiteContext(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		state,
		chainID,
		nil, /*rotation*/
		nil, /*registry*/
		workers,
	)
}

func ConnectBlockParallelSigVerifyWithSuiteContext(
	blockBytes []byte,
	expectedPrevHash *[32]byte,
	expectedTarget *[32]byte,
	blockHeight uint64,
	prevTimestamps []uint64,
	state *InMemoryChainState,
	chainID [32]byte,
	rotation RotationProvider,
	registry *SuiteRegistry,
	workers int,
) (summary *ConnectBlockBasicSummary, err error) {
	alreadyGenerated, alreadyGeneratedU128, err := preflightInMemoryChainState(state)
	if err != nil {
		return nil, err
	}
	rot := rotation
	if rot == nil {
		rot = DefaultRotationProvider{}
	}
	reg := registry
	if reg == nil {
		reg = DefaultSuiteRegistry()
	}

	// Block-global checks first; non-coinbase semantics stay in transaction order below.
	pb, err := parseAndValidateBlockBasicForConnectWithContextAtHeight(
		blockBytes,
		expectedPrevHash,
		expectedTarget,
		blockHeight,
		prevTimestamps,
		chainID,
		rot,
	)
	if err != nil {
		return nil, err
	}
	if pb == nil || len(pb.Txs) == 0 || len(pb.Txids) != len(pb.Txs) {
		return nil, txerr(BLOCK_ERR_PARSE, "invalid parsed block")
	}

	blockMTP := pb.Header.Timestamp
	if median, ok, err := medianTimePast(blockHeight, prevTimestamps); err != nil {
		return nil, err
	} else if ok {
		blockMTP = median
	}
	// Clone UTXO set upfront to prevent aliasing state.Utxos. Without this,
	// coinbase-only blocks (no non-coinbase txs) would insert coinbase outputs
	// directly into state.Utxos before all fallible checks complete, leaving
	// the caller's state partially mutated on error paths.
	workUtxos := cloneUtxoSet(state.Utxos)
	if err := applyInMemoryCoinbaseOutputs(pb, workUtxos, blockHeight, chainID, rot); err != nil {
		return nil, err
	}

	// Create a single sig check queue for the entire block (rotation-aware so Flush uses verifySigWithRegistry).
	sigQueue := NewSigCheckQueue(workers).WithRegistry(reg)

	defer sigQueue.rollbackTo(sigCheckQueueMark{})
	completed := false
	defer func() {
		if completed {
			if err != nil {
				if earlier := sigQueue.settleRange(sigCheckQueueMark{}, sigQueue.mark()); earlier != nil {
					err = earlier
				}
			}
			return
		}
		laterPanic := recover()
		if earlier := sigQueue.settleRange(sigCheckQueueMark{}, sigQueue.mark()); earlier != nil {
			summary, err = nil, earlier
			return
		}
		panic(laterPanic) //nolint:forbidigo // RUB-721: preserve the later raw panic after the earlier interval succeeds.
	}()

	summary, err = func() (*ConnectBlockBasicSummary, error) {
		// Apply all non-coinbase transactions with deferred sig verification.
		var sumFees Uint128
		seenNonces := make(map[uint64]struct{}, len(pb.Txs))
		for i := 1; i < len(pb.Txs); i++ {
			tx := pb.Txs[i]
			txid := pb.Txids[i]
			if err := validateNonCoinbaseBlockTx(tx, seenNonces); err != nil {
				return nil, err
			}

			nextUtxos, s, err := applyNonCoinbaseTxBasicUpdateWithMTPQ(
				tx,
				txid,
				workUtxos,
				blockHeight,
				pb.Header.Timestamp,
				blockMTP,
				chainID,
				sigQueue,
				rot,
				reg,
			)
			if err != nil {
				return nil, err
			}
			workUtxos = nextUtxos
			var ok bool
			sumFees, ok = sumFees.CheckedAdd(s.Fee)
			if !ok {
				return nil, txerr(BLOCK_ERR_PARSE, "sum_fees overflow")
			}
		}

		// Record task count before flushing (Flush clears the queue).
		sigTaskCount := uint64(sigQueue.Len()) // #nosec G115 -- Len() is non-negative and used only for bookkeeping.

		// Flush the signature queue: verify all collected signatures in parallel.
		// Returns the first error by submission order (deterministic within the
		// deferred-sig model).
		if err := sigQueue.Flush(); err != nil {
			return nil, err
		}
		workerPanics := sigQueue.Panics()

		// Enforce coinbase bound using locally computed fees.
		if err := validateCoinbaseValueBound(pb, blockHeight, alreadyGenerated, sumFees); err != nil {
			return nil, err
		}

		// Update already_generated(h) -> already_generated(h+1) only after every
		// earlier block, transaction, signature, and coinbase check has passed.
		alreadyGeneratedN1, err := checkedAdvanceAlreadyGenerated(blockHeight, alreadyGeneratedU128, alreadyGenerated)
		if err != nil {
			return nil, err
		}

		return commitInMemoryConnectSummary(
			state,
			workUtxos,
			alreadyGeneratedU128,
			alreadyGeneratedN1,
			sumFees,
			sigTaskCount,
			workerPanics,
		), nil
	}()
	completed = true
	return
}

// applyNonCoinbaseTxBasicUpdateWithMTPQ is the queue-aware
// wrapper around applyNonCoinbaseTxBasicWorkQ. The SigCheckQueue is used for
// deferred signature verification.
func applyNonCoinbaseTxBasicUpdateWithMTPQ(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	_ uint64,
	blockMTP uint64,
	chainID [32]byte,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (map[Outpoint]UtxoEntry, *UtxoApplySummary, error) {
	work, fee, err := applyNonCoinbaseTxBasicWorkQ(tx, txid, utxoSet, height, blockMTP, chainID, sigQueue, rotation, registry)
	if err != nil {
		return nil, nil, err
	}
	return work, &UtxoApplySummary{
		Fee:       fee,
		UtxoCount: uint64(len(work)),
	}, nil
}

// applyNonCoinbaseTxBasicWorkQ is the queue-aware variant of
// applyNonCoinbaseTxBasicWork: the same stage owner (utxo_basic_stages.go)
// runs every stage, and S4 pushes signature checks to sigQueue instead of
// verifying them inline.
//
// An earlier queued result of this transaction precedes any later synchronous
// failure or panic of the same transaction. Queue ownership is
// transaction-atomic: an error rolls back only tasks appended by this call to
// its entry mark, while success retains them in submission order.
func applyNonCoinbaseTxBasicWorkQ(
	tx *Tx,
	txid [32]byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockMTP uint64,
	chainID [32]byte,
	sigQueue *SigCheckQueue,
	rotation RotationProvider,
	registry *SuiteRegistry,
) (result map[Outpoint]UtxoEntry, resultFee Uint128, err error) {
	entryMark := sigQueue.mark()
	completed := false
	defer func() {
		if !completed || err != nil {
			sigQueue.rollbackTo(entryMark)
		}
	}()
	defer func() {
		if completed {
			if err != nil {
				if earlier := sigQueue.settleRange(entryMark, sigQueue.mark()); earlier != nil {
					err = earlier
				}
			}
			return
		}
		laterPanic := recover()
		if earlier := sigQueue.settleRange(entryMark, sigQueue.mark()); earlier != nil {
			result, resultFee, err = nil, Uint128{}, earlier
			return
		}
		panic(laterPanic) //nolint:forbidigo // RUB-721: preserve the later raw panic after the earlier interval succeeds.
	}()

	// Private work map so the delta never aliases the caller's map.
	work := make(map[Outpoint]UtxoEntry, len(utxoSet))
	for k, v := range utxoSet {
		work[k] = v
	}
	result, resultFee, err = (&nonCoinbaseApplyContext{
		tx:       tx,
		txid:     txid,
		work:     work,
		height:   height,
		blockMTP: blockMTP,
		chainID:  chainID,
		rotation: rotation,
		registry: registry,
		sigQueue: sigQueue,
	}).apply()
	completed = true
	return
}
