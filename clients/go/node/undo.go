package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

type BlockUndo struct {
	BlockHeight              uint64
	PreviousAlreadyGenerated uint64
	Txs                      []TxUndo
}

type TxUndo struct {
	Spent []SpentUndo
}

type SpentUndo struct {
	Outpoint consensus.Outpoint
	Entry    consensus.UtxoEntry
}

type ChainStateDisconnectSummary struct {
	DisconnectedHeight uint64
	BlockHash          [32]byte
	NewHeight          uint64
	NewTipHash         [32]byte
	HasTip             bool
	AlreadyGenerated   uint64
	UtxoCount          uint64
}

type blockUndoDisk struct {
	BlockHeight              uint64       `json:"block_height"`
	PreviousAlreadyGenerated uint64       `json:"previous_already_generated"`
	Txs                      []txUndoDisk `json:"txs"`
}

type txUndoDisk struct {
	Spent []spentUndoDisk `json:"spent"`
}

type spentUndoDisk struct {
	Txid              string `json:"txid"`
	Vout              uint32 `json:"vout"`
	Value             uint64 `json:"value"`
	CovenantType      uint16 `json:"covenant_type"`
	CovenantData      string `json:"covenant_data"`
	CreationHeight    uint64 `json:"creation_height"`
	CreatedByCoinbase bool   `json:"created_by_coinbase"`
}

func buildBlockUndo(prevState *ChainState, pb *consensus.ParsedBlock, blockHeight uint64) (*BlockUndo, error) {
	if prevState == nil {
		return nil, errors.New("nil previous chainstate")
	}
	if pb == nil {
		return nil, errors.New("nil parsed block")
	}
	if len(pb.Txs) != len(pb.Txids) {
		return nil, errors.New("parsed block txid length mismatch")
	}

	work := copyUtxoSet(prevState.Utxos)
	txUndos, err := buildTxUndos(work, pb, blockHeight)
	if err != nil {
		return nil, err
	}
	return &BlockUndo{
		BlockHeight:              blockHeight,
		PreviousAlreadyGenerated: prevState.AlreadyGenerated,
		Txs:                      txUndos,
	}, nil
}

// buildTxUndos iterates transactions and builds undo entries.
func buildTxUndos(work map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, blockHeight uint64) ([]TxUndo, error) {
	txUndos := make([]TxUndo, len(pb.Txs))
	for i := 0; i < len(pb.Txs); i++ {
		tx := pb.Txs[i]
		if tx == nil {
			return nil, fmt.Errorf("nil tx at index %d", i)
		}
		spent, err := spendUndoInputs(work, tx, i)
		if err != nil {
			return nil, err
		}
		addUndoCreatedOutputs(work, pb.Txids[i], tx, blockHeight, i == 0)
		txUndos[i] = TxUndo{Spent: spent}
	}
	return txUndos, nil
}

func spendUndoInputs(work map[consensus.Outpoint]consensus.UtxoEntry, tx *consensus.Tx, txIndex int) ([]SpentUndo, error) {
	spent := make([]SpentUndo, 0, len(tx.Inputs))
	if txIndex == 0 {
		return spent, nil
	}
	for _, in := range tx.Inputs {
		op := consensus.Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
		entry, ok := work[op]
		if !ok {
			return nil, fmt.Errorf("undo missing utxo for %x:%d", op.Txid, op.Vout)
		}
		spent = append(spent, SpentUndo{Outpoint: op, Entry: copyUtxoEntry(entry)})
		delete(work, op)
	}
	return spent, nil
}

func addUndoCreatedOutputs(work map[consensus.Outpoint]consensus.UtxoEntry, txid [32]byte, tx *consensus.Tx, blockHeight uint64, coinbase bool) {
	for outputIndex, out := range tx.Outputs {
		if out.CovenantType != consensus.COV_TYPE_ANCHOR && out.CovenantType != consensus.COV_TYPE_DA_COMMIT {
			work[consensus.Outpoint{Txid: txid, Vout: uint32(outputIndex)}] = consensus.UtxoEntry{
				Value:             out.Value,
				CovenantType:      out.CovenantType,
				CovenantData:      append([]byte(nil), out.CovenantData...),
				CreationHeight:    blockHeight,
				CreatedByCoinbase: coinbase,
			}
		}
	}
}

func (s *ChainState) DisconnectBlock(blockBytes []byte, undo *BlockUndo) (*ChainStateDisconnectSummary, error) {
	if s == nil {
		return nil, errors.New("nil chainstate")
	}
	s.admissionMu.Lock()
	defer s.admissionMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.HasTip {
		return nil, errors.New("chainstate has no tip")
	}
	if undo == nil {
		return nil, errors.New("nil block undo")
	}

	pb, blockHash, err := parseAndValidateDisconnectBlock(blockBytes, undo, s.TipHash, s.Height)
	if err != nil {
		return nil, err
	}

	work := copyUtxoSet(s.Utxos)
	if err := applyDisconnectUndo(work, pb, undo); err != nil {
		return nil, err
	}

	s.Utxos = work
	s.AlreadyGenerated = undo.PreviousAlreadyGenerated
	if s.Height == 0 {
		s.HasTip = false
		s.Height = 0
		s.TipHash = [32]byte{}
	} else {
		s.Height--
		s.TipHash = pb.Header.PrevBlockHash
		s.HasTip = true
	}

	return &ChainStateDisconnectSummary{
		DisconnectedHeight: undo.BlockHeight,
		BlockHash:          blockHash,
		NewHeight:          s.Height,
		NewTipHash:         s.TipHash,
		HasTip:             s.HasTip,
		AlreadyGenerated:   s.AlreadyGenerated,
		UtxoCount:          uint64(len(s.Utxos)),
	}, nil
}

// parseAndValidateDisconnectBlock parses block bytes and validates undo against chain state.
func parseAndValidateDisconnectBlock(blockBytes []byte, undo *BlockUndo, tipHash [32]byte, height uint64) (*consensus.ParsedBlock, [32]byte, error) {
	pb, blockHash, err := parseDisconnectBlock(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(undo.Txs) != len(pb.Txs) {
		return nil, [32]byte{}, errors.New("undo tx count mismatch")
	}
	if tipHash != blockHash {
		return nil, [32]byte{}, errors.New("disconnect block is not current tip")
	}
	if height != undo.BlockHeight {
		return nil, [32]byte{}, fmt.Errorf("disconnect height mismatch: chainstate=%d undo=%d", height, undo.BlockHeight)
	}
	return pb, blockHash, nil
}

func parseDisconnectBlock(blockBytes []byte) (*consensus.ParsedBlock, [32]byte, error) {
	pb, err := consensus.ParseBlockBytes(blockBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	if len(pb.Txs) != len(pb.Txids) {
		return nil, [32]byte{}, errors.New("parsed block txid length mismatch")
	}
	blockHash, err := consensus.BlockHash(pb.HeaderBytes)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return pb, blockHash, nil
}

func (s *ChainState) validateDisconnectBlockLocked(pb *consensus.ParsedBlock, undo *BlockUndo, blockHash [32]byte) error {
	if len(undo.Txs) != len(pb.Txs) {
		return errors.New("undo tx count mismatch")
	}
	if s.TipHash != blockHash {
		return errors.New("disconnect block is not current tip")
	}
	if s.Height != undo.BlockHeight {
		return fmt.Errorf("disconnect height mismatch: chainstate=%d undo=%d", s.Height, undo.BlockHeight)
	}
	return nil
}

func applyDisconnectUndo(work map[consensus.Outpoint]consensus.UtxoEntry, pb *consensus.ParsedBlock, undo *BlockUndo) error {
	for txIndex := len(pb.Txs) - 1; txIndex >= 0; txIndex-- {
		for outputIndex, out := range pb.Txs[txIndex].Outputs {
			if out.CovenantType != consensus.COV_TYPE_ANCHOR && out.CovenantType != consensus.COV_TYPE_DA_COMMIT {
				delete(work, consensus.Outpoint{Txid: pb.Txids[txIndex], Vout: uint32(outputIndex)})
			}
		}
		for _, item := range undo.Txs[txIndex].Spent {
			if _, exists := work[item.Outpoint]; exists {
				return fmt.Errorf("undo restore collision for %x:%d", item.Outpoint.Txid, item.Outpoint.Vout)
			}
			work[item.Outpoint] = copyUtxoEntry(item.Entry)
		}
	}
	return nil
}

func marshalBlockUndo(undo *BlockUndo) ([]byte, error) {
	disk, err := blockUndoToDisk(undo)
	if err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode undo: %w", err)
	}
	return append(raw, '\n'), nil
}

func unmarshalBlockUndo(raw []byte) (*BlockUndo, error) {
	var disk blockUndoDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return nil, fmt.Errorf("decode undo: %w", err)
	}
	return blockUndoFromDisk(disk)
}

func blockUndoToDisk(undo *BlockUndo) (blockUndoDisk, error) {
	if undo == nil {
		return blockUndoDisk{}, errors.New("nil block undo")
	}
	txs := make([]txUndoDisk, 0, len(undo.Txs))
	for _, txUndo := range undo.Txs {
		spent := make([]spentUndoDisk, 0, len(txUndo.Spent))
		for _, input := range txUndo.Spent {
			spent = append(spent, spentUndoDisk{
				Txid:              hex.EncodeToString(input.Outpoint.Txid[:]),
				Vout:              input.Outpoint.Vout,
				Value:             input.Entry.Value,
				CovenantType:      input.Entry.CovenantType,
				CovenantData:      hex.EncodeToString(input.Entry.CovenantData),
				CreationHeight:    input.Entry.CreationHeight,
				CreatedByCoinbase: input.Entry.CreatedByCoinbase,
			})
		}
		txs = append(txs, txUndoDisk{Spent: spent})
	}
	return blockUndoDisk{
		BlockHeight:              undo.BlockHeight,
		PreviousAlreadyGenerated: undo.PreviousAlreadyGenerated,
		Txs:                      txs,
	}, nil
}

func blockUndoFromDisk(disk blockUndoDisk) (*BlockUndo, error) {
	txs := make([]TxUndo, 0, len(disk.Txs))
	for txIndex, txUndo := range disk.Txs {
		spent := make([]SpentUndo, 0, len(txUndo.Spent))
		for spentIndex, input := range txUndo.Spent {
			txid, err := parseHex32(fmt.Sprintf("undo[%d].spent[%d].txid", txIndex, spentIndex), input.Txid)
			if err != nil {
				return nil, err
			}
			covData, err := parseHex(fmt.Sprintf("undo[%d].spent[%d].covenant_data", txIndex, spentIndex), input.CovenantData)
			if err != nil {
				return nil, err
			}
			spent = append(spent, SpentUndo{
				Outpoint: consensus.Outpoint{
					Txid: txid,
					Vout: input.Vout,
				},
				Entry: consensus.UtxoEntry{
					Value:             input.Value,
					CovenantType:      input.CovenantType,
					CovenantData:      covData,
					CreationHeight:    input.CreationHeight,
					CreatedByCoinbase: input.CreatedByCoinbase,
				},
			})
		}
		txs = append(txs, TxUndo{Spent: spent})
	}
	return &BlockUndo{
		BlockHeight:              disk.BlockHeight,
		PreviousAlreadyGenerated: disk.PreviousAlreadyGenerated,
		Txs:                      txs,
	}, nil
}
