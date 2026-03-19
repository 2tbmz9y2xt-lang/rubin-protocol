package consensus

import (
	"bytes"
	"fmt"
)

// DigestSigner signs 32-byte sighash digests for ML-DSA witness construction.
type DigestSigner interface {
	PubkeyBytes() []byte
	SignDigest32([32]byte) ([]byte, error)
}

type CheckedTransaction struct {
	Tx             *Tx
	Bytes          []byte
	TxID           [32]byte
	WTxID          [32]byte
	Fee            uint64
	Weight         uint64
	DaBytes        uint64
	SerializedSize int
}

func P2PKCovenantDataForPubkey(pub []byte) []byte {
	keyID := sha3_256(pub)
	out := make([]byte, MAX_P2PK_COVENANT_DATA)
	out[0] = SUITE_ID_ML_DSA_87
	copy(out[1:], keyID[:])
	return out
}

func CheckTransaction(
	txBytes []byte,
	utxoSet map[Outpoint]UtxoEntry,
	height uint64,
	blockMTP uint64,
	chainID [32]byte,
) (*CheckedTransaction, error) {
	tx, txid, wtxid, consumed, err := ParseTx(txBytes)
	if err != nil {
		return nil, err
	}
	if consumed != len(txBytes) {
		return nil, txerr(TX_ERR_PARSE, "trailing bytes after canonical tx")
	}

	weight, daBytes, _, err := TxWeightAndStats(tx)
	if err != nil {
		return nil, err
	}
	workUtxos := cloneUtxoSet(utxoSet)
	_, fee, err := applyNonCoinbaseTxBasicWork(
		tx,
		txid,
		workUtxos,
		height,
		blockMTP,
		chainID,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &CheckedTransaction{
		Tx:             tx,
		Bytes:          append([]byte(nil), txBytes...),
		TxID:           txid,
		WTxID:          wtxid,
		Fee:            fee,
		Weight:         weight,
		DaBytes:        daBytes,
		SerializedSize: len(txBytes),
	}, nil
}

// SignTransaction currently supports ML-DSA CORE_P2PK inputs only.
func SignTransaction(tx *Tx, utxoSet map[Outpoint]UtxoEntry, chainID [32]byte, signer DigestSigner) error {
	if tx == nil {
		return txerr(TX_ERR_PARSE, "nil tx")
	}
	if len(tx.Inputs) == 0 {
		return txerr(TX_ERR_PARSE, "non-coinbase must have at least one input")
	}
	if signer == nil {
		return fmt.Errorf("nil signer")
	}
	pub, keyID, err := signerBinding(signer)
	if err != nil {
		return err
	}
	sighashCache, err := NewSighashV1PrehashCache(tx)
	if err != nil {
		return err
	}

	witness := make([]WitnessItem, 0, len(tx.Inputs))
	for i, in := range tx.Inputs {
		entry, err := signableP2PKEntry(utxoSet, in, keyID)
		if err != nil {
			return err
		}
		witnessItem, err := signWitnessItem(tx, uint32(i), entry.Value, chainID, sighashCache, signer, pub)
		if err != nil {
			return err
		}
		witness = append(witness, witnessItem)
	}

	tx.Witness = witness
	return nil
}

func signerBinding(signer DigestSigner) ([]byte, [32]byte, error) {
	pub := signer.PubkeyBytes()
	if len(pub) != ML_DSA_87_PUBKEY_BYTES {
		return nil, [32]byte{}, txerr(TX_ERR_SIG_NONCANONICAL, "non-canonical ML-DSA public key length")
	}
	return pub, sha3_256(pub), nil
}

func signableP2PKEntry(utxoSet map[Outpoint]UtxoEntry, in TxInput, keyID [32]byte) (UtxoEntry, error) {
	op := Outpoint{Txid: in.PrevTxid, Vout: in.PrevVout}
	entry, ok := utxoSet[op]
	if !ok {
		return UtxoEntry{}, txerr(TX_ERR_MISSING_UTXO, "utxo not found")
	}
	if entry.CovenantType != COV_TYPE_P2PK {
		return UtxoEntry{}, fmt.Errorf("unsupported covenant type for signing: 0x%04x", entry.CovenantType)
	}
	if len(entry.CovenantData) != MAX_P2PK_COVENANT_DATA || entry.CovenantData[0] != SUITE_ID_ML_DSA_87 {
		return UtxoEntry{}, txerr(TX_ERR_COVENANT_TYPE_INVALID, "CORE_P2PK covenant_data invalid")
	}
	if !bytes.Equal(entry.CovenantData[1:33], keyID[:]) {
		return UtxoEntry{}, txerr(TX_ERR_SIG_INVALID, "signer key binding mismatch")
	}
	return entry, nil
}

func signWitnessItem(
	tx *Tx,
	inputIndex uint32,
	inputValue uint64,
	chainID [32]byte,
	cache *SighashV1PrehashCache,
	signer DigestSigner,
	pub []byte,
) (WitnessItem, error) {
	var digest [32]byte
	var err error
	if cache != nil {
		digest, err = SighashV1DigestWithCache(cache, inputIndex, inputValue, chainID, SIGHASH_ALL)
	} else {
		digest, err = SighashV1DigestWithType(tx, inputIndex, inputValue, chainID, SIGHASH_ALL)
	}
	if err != nil {
		return WitnessItem{}, err
	}
	signature, err := signer.SignDigest32(digest)
	if err != nil {
		return WitnessItem{}, err
	}
	signature = append(signature, SIGHASH_ALL)
	return WitnessItem{
		SuiteID:   SUITE_ID_ML_DSA_87,
		Pubkey:    append([]byte(nil), pub...),
		Signature: signature,
	}, nil
}
