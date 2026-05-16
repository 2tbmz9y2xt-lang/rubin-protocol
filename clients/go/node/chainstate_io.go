package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func stateToDisk(s *ChainState) (chainStateDisk, error) {
	if s == nil {
		return chainStateDisk{}, errors.New("nil chainstate")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	utxos := make([]utxoDiskEntry, 0, len(s.Utxos))
	for op, entry := range s.Utxos {
		utxos = append(utxos, utxoDiskEntry{
			Txid:              hex.EncodeToString(op.Txid[:]),
			Vout:              op.Vout,
			Value:             entry.Value,
			CovenantType:      entry.CovenantType,
			CovenantData:      hex.EncodeToString(entry.CovenantData),
			CreationHeight:    entry.CreationHeight,
			CreatedByCoinbase: entry.CreatedByCoinbase,
		})
	}
	sort.Slice(utxos, func(i, j int) bool {
		if utxos[i].Txid != utxos[j].Txid {
			return utxos[i].Txid < utxos[j].Txid
		}
		return utxos[i].Vout < utxos[j].Vout
	})

	return chainStateDisk{
		Version:          chainStateDiskVersion,
		HasTip:           s.HasTip,
		Height:           s.Height,
		TipHash:          hex.EncodeToString(s.TipHash[:]),
		AlreadyGenerated: s.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}

func chainStateFromDisk(disk chainStateDisk) (*ChainState, error) {
	if disk.Version != chainStateDiskVersion {
		return nil, fmt.Errorf("unsupported chainstate version: %d", disk.Version)
	}

	tipHash, err := parseHex32("tip_hash", disk.TipHash)
	if err != nil {
		return nil, err
	}
	utxos := make(map[consensus.Outpoint]consensus.UtxoEntry, len(disk.Utxos))
	for _, item := range disk.Utxos {
		txid, err := parseHex32("utxo.txid", item.Txid)
		if err != nil {
			return nil, err
		}
		covData, err := parseHex("utxo.covenant_data", item.CovenantData)
		if err != nil {
			return nil, err
		}
		op := consensus.Outpoint{
			Txid: txid,
			Vout: item.Vout,
		}
		if _, exists := utxos[op]; exists {
			return nil, fmt.Errorf("duplicate utxo outpoint: %s:%d", item.Txid, item.Vout)
		}
		utxos[op] = consensus.UtxoEntry{
			Value:             item.Value,
			CovenantType:      item.CovenantType,
			CovenantData:      covData,
			CreationHeight:    item.CreationHeight,
			CreatedByCoinbase: item.CreatedByCoinbase,
		}
	}
	return &ChainState{
		HasTip:           disk.HasTip,
		Height:           disk.Height,
		TipHash:          tipHash,
		AlreadyGenerated: disk.AlreadyGenerated,
		Utxos:            utxos,
	}, nil
}
