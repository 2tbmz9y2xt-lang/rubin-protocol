package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

// This generator updates a small set of conformance fixtures to use *real* ML-DSA
// witness signatures (OpenSSL backend) so that spend-path crypto verification is
// exercised end-to-end.
//
// It intentionally mutates only the vectors that previously used a dummy suite_id=0
// witness item and now fail with TX_ERR_SIG_ALG_INVALID after Q-R006.

func runGeneratorCLI() {
	repoRoot, err := repoRootFromGoModule()
	if err != nil {
		fatalf("repo root: %v", err)
	}

	// Key material (generated once per run, then baked into fixtures).
	ownerKP := mustKeypair("owner")
	defer ownerKP.Close()
	slhKP := mustSLHKeypair("slh")
	defer slhKP.Close()
	vaultKP := mustKeypair("vault")
	defer vaultKP.Close()
	sponsorKP := mustKeypair("sponsor")
	defer sponsorKP.Close()
	destKP := mustKeypair("dest")
	defer destKP.Close()
	dest2KP := mustKeypair("dest2")
	defer dest2KP.Close()
	multisigKP := mustKeypair("multisig")
	defer multisigKP.Close()
	htlcClaimKP := mustKeypair("htlc-claim")
	defer htlcClaimKP.Close()
	htlcRefundKP := mustKeypair("htlc-refund")
	defer htlcRefundKP.Close()

	zeroChainID := [32]byte{}

	// CV-UTXO-BASIC updates.
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-UTXO-BASIC.json")
		f := mustLoadFixture(path)

		updateP2PKVector(f, "CV-U-05", zeroChainID, ownerKP, 100, 101) // sum_out > sum_in
		updateP2PKVector(f, "CV-U-06", zeroChainID, ownerKP, 100, 90)  // fee=10
		updateP2PKVectorSLH(f, "CV-U-16", zeroChainID, slhKP, 100, 90) // fee=10, post-activation OK

		updateMultisigVector1of1(f, "CV-U-09", zeroChainID, multisigKP, 100, 90) // fee=10

		updateVaultSpendVectorsUTXO(
			f,
			zeroChainID,
			ownerKP,
			vaultKP,
			destKP,
			dest2KP,
			100, // vault_value
			10,  // owner_fee_input_value
		)

		mustWriteFixture(path, f)
	}

	// CV-VAULT updates.
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-VAULT.json")
		f := mustLoadFixture(path)

		updateVaultCreateVectors(
			f,
			zeroChainID,
			ownerKP,
			sponsorKP, // used as "non-owner" for negative case
			vaultKP,
			destKP,
			100, // input_value
			90,  // vault_output_value (fee=10)
		)

		updateVaultSpendVectorsVaultFixture(
			f,
			zeroChainID,
			ownerKP,
			sponsorKP,
			vaultKP,
			destKP,
			dest2KP,
			100, // vault_value
			10,  // owner_fee_input_value
			10,  // sponsor_input_value
		)

		mustWriteFixture(path, f)
	}

	// CV-HTLC updates (single vector that needs real signature witness).
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-HTLC.json")
		f := mustLoadFixture(path)
		updateHTLCVector(f, "CV-HTLC-13", zeroChainID, htlcClaimKP, htlcRefundKP, destKP)
		mustWriteFixture(path, f)
	}

	// CV-SUBSIDY updates (block-level coinbase bound; requires valid non-coinbase sig).
	{
		path := filepath.Join(repoRoot, "conformance/fixtures/CV-SUBSIDY.json")
		f := mustLoadFixture(path)
		updateSubsidyBlocks(f, zeroChainID, ownerKP, destKP)
		mustWriteFixture(path, f)
	}

	fmt.Println("ok: updated fixtures with real ML-DSA + SLH signatures")
}

type fixtureFile struct {
	Gate    string           `json:"gate"`
	Vectors []map[string]any `json:"vectors"`
}

type digestSigner interface {
	PubkeyBytes() []byte
	SignDigest32([32]byte) ([]byte, error)
}

func mustLoadFixture(path string) *fixtureFile {
	b, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		fatalf("parse %s: %v", path, err)
	}
	return &f
}

func mustWriteFixture(path string, f *fixtureFile) {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		fatalf("marshal %s: %v", path, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func findVector(f *fixtureFile, id string) map[string]any {
	for _, v := range f.Vectors {
		if v["id"] == id {
			return v
		}
	}
	fatalf("missing vector id=%s", id)
	return nil
}

func mustKeypair(label string) *consensus.MLDSA87Keypair {
	kp, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		fatalf("keygen %s: %v", label, err)
	}
	return kp
}

func mustSLHKeypair(label string) *consensus.SLHDSASHAKE256fKeypair {
	kp, err := consensus.NewSLHDSASHAKE256fKeypair()
	if err != nil {
		fatalf("keygen %s: %v", label, err)
	}
	return kp
}

func sha3_256(b []byte) [32]byte { return sha3.Sum256(b) }

func keyIDForPub(pub []byte) [32]byte { return sha3_256(pub) }

func p2pkCovenantDataWithSuite(suiteID byte, pub []byte) []byte {
	kid := keyIDForPub(pub)
	out := make([]byte, 0, consensus.MAX_P2PK_COVENANT_DATA)
	out = append(out, suiteID)
	out = append(out, kid[:]...)
	return out
}

func p2pkCovenantData(pub []byte) []byte {
	return p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)
}

func multisigCovenantData1of1(pub []byte) []byte {
	kid := keyIDForPub(pub)
	out := make([]byte, 0, 34)
	out = append(out, 0x01) // threshold
	out = append(out, 0x01) // key_count
	out = append(out, kid[:]...)
	return out
}

func vaultCovenantData(ownerLockID [32]byte, vaultKeyID [32]byte, whitelist [32]byte) []byte {
	out := make([]byte, 0, 32+1+1+32+2+32)
	out = append(out, ownerLockID[:]...)
	out = append(out, 0x01) // threshold
	out = append(out, 0x01) // key_count
	out = append(out, vaultKeyID[:]...)
	var wc [2]byte
	binary.LittleEndian.PutUint16(wc[:], 1)
	out = append(out, wc[:]...)
	out = append(out, whitelist[:]...)
	return out
}

func txBytes(tx *consensus.Tx) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}
	var b []byte
	b = appendU32le(b, tx.Version)
	b = append(b, tx.TxKind)
	b = appendU64le(b, tx.TxNonce)
	b = appendCompactSize(b, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		b = append(b, in.PrevTxid[:]...)
		b = appendU32le(b, in.PrevVout)
		b = appendCompactSize(b, uint64(len(in.ScriptSig)))
		b = append(b, in.ScriptSig...)
		b = appendU32le(b, in.Sequence)
	}
	b = appendCompactSize(b, uint64(len(tx.Outputs)))
	for _, o := range tx.Outputs {
		b = appendU64le(b, o.Value)
		b = appendU16le(b, o.CovenantType)
		b = appendCompactSize(b, uint64(len(o.CovenantData)))
		b = append(b, o.CovenantData...)
	}
	b = appendU32le(b, tx.Locktime)
	b = appendCompactSize(b, uint64(len(tx.Witness)))
	for _, w := range tx.Witness {
		b = append(b, w.SuiteID)
		b = appendCompactSize(b, uint64(len(w.Pubkey)))
		b = append(b, w.Pubkey...)
		b = appendCompactSize(b, uint64(len(w.Signature)))
		b = append(b, w.Signature...)
	}
	// da_payload_len + payload
	b = appendCompactSize(b, uint64(len(tx.DaPayload)))
	b = append(b, tx.DaPayload...)
	return b, nil
}

func updateSingleInputSignedVector(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	suiteID byte,
	inCov []byte,
	outCov []byte,
	inValue uint64,
	outValue uint64,
	signer digestSigner,
) {
	v := findVector(f, id)
	pub := signer.PubkeyBytes()

	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo, got %d", id, len(utxos))
	}
	utxos[0]["covenant_data"] = hex.EncodeToString(inCov)

	prevTxid := mustHex32(utxos[0]["txid"].(string))
	prevVout := uint32(utxos[0]["vout"].(float64))

	tx := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevTxid, PrevVout: prevVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		Locktime: 0,
	}

	d, err := consensus.SighashV1Digest(tx, 0, inValue, chainID)
	if err != nil {
		fatalf("%s: sighash: %v", id, err)
	}
	sig, err := signer.SignDigest32(d)
	if err != nil {
		fatalf("%s: sign: %v", id, err)
	}
	tx.Witness = []consensus.WitnessItem{{SuiteID: suiteID, Pubkey: pub, Signature: sig}}

	b := mustTxBytes(tx)
	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
}

func updateP2PKVector(f *fixtureFile, id string, chainID [32]byte, signer *consensus.MLDSA87Keypair, inValue uint64, outValue uint64) {
	pub := signer.PubkeyBytes()
	cov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_ML_DSA_87, pub)
	updateSingleInputSignedVector(
		f,
		id,
		chainID,
		consensus.SUITE_ID_ML_DSA_87,
		cov,
		cov,
		inValue,
		outValue,
		signer,
	)
}

func updateP2PKVectorSLH(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	signer *consensus.SLHDSASHAKE256fKeypair,
	inValue uint64,
	outValue uint64,
) {
	pub := signer.PubkeyBytes()
	cov := p2pkCovenantDataWithSuite(consensus.SUITE_ID_SLH_DSA_SHAKE_256F, pub)
	updateSingleInputSignedVector(
		f,
		id,
		chainID,
		consensus.SUITE_ID_SLH_DSA_SHAKE_256F,
		cov,
		cov,
		inValue,
		outValue,
		signer,
	)
}

func updateMultisigVector1of1(f *fixtureFile, id string, chainID [32]byte, signer *consensus.MLDSA87Keypair, inValue uint64, outValue uint64) {
	pub := signer.PubkeyBytes()
	inCov := multisigCovenantData1of1(pub)
	outCov := p2pkCovenantData(pub) // any valid output
	updateSingleInputSignedVector(
		f,
		id,
		chainID,
		consensus.SUITE_ID_ML_DSA_87,
		inCov,
		outCov,
		inValue,
		outValue,
		signer,
	)
}

func updateVaultSpendVectorsUTXO(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP *consensus.MLDSA87Keypair,
	vaultKP *consensus.MLDSA87Keypair,
	destKP *consensus.MLDSA87Keypair,
	dest2KP *consensus.MLDSA87Keypair,
	vaultValue uint64,
	ownerFeeInValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultPub := vaultKP.PubkeyBytes()
	vaultKeyID := keyIDForPub(vaultPub)

	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// Helper to build/patch one vector with (outValue, destCovData).
	build := func(id string, outValue uint64, outCov []byte) {
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 2 {
			fatalf("%s: want 2 utxos", id)
		}
		// vault input first
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[0]["covenant_type"] = float64(consensus.COV_TYPE_VAULT)
		// owner fee input second
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)
		utxos[1]["covenant_type"] = float64(consensus.COV_TYPE_P2PK)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		vout0 := uint32(utxos[0]["vout"].(float64))
		vout1 := uint32(utxos[1]["vout"].(float64))

		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: outValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
			Locktime: 0,
		}

		d0, err := consensus.SighashV1Digest(tx, 0, vaultValue, chainID)
		if err != nil {
			fatalf("%s: sighash0: %v", id, err)
		}
		vaultSig, err := vaultKP.SignDigest32(d0)
		if err != nil {
			fatalf("%s: vault sign: %v", id, err)
		}
		d1, err := consensus.SighashV1Digest(tx, 1, ownerFeeInValue, chainID)
		if err != nil {
			fatalf("%s: sighash1: %v", id, err)
		}
		ownerSig, err := ownerKP.SignDigest32(d1)
		if err != nil {
			fatalf("%s: owner sign: %v", id, err)
		}
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: vaultPub, Signature: vaultSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
		}

		b := mustTxBytes(tx)

		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// CV-U-10: vault funds fee -> reject value conservation.
	build("CV-U-10", 95, destCov)
	// CV-U-11: vault preserved exactly; owner funds fee.
	build("CV-U-11", vaultValue, destCov)
	// CV-U-12: output not whitelisted.
	build("CV-U-12", vaultValue, p2pkCovenantData(dest2KP.PubkeyBytes()))
	// CV-U-13: owner top-up; sum_out > sum_in_vault.
	build("CV-U-13", 105, destCov)
}

func updateVaultCreateVectors(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP *consensus.MLDSA87Keypair,
	nonOwnerKP *consensus.MLDSA87Keypair,
	vaultKP *consensus.MLDSA87Keypair,
	destKP *consensus.MLDSA87Keypair,
	inValue uint64,
	vaultOutValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultKeyID := keyIDForPub(vaultKP.PubkeyBytes())
	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// Negative: input is non-owner; creates vault output with ownerLockID -> missing owner auth.
	{
		id := "VAULT-CREATE-01"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 1 {
			fatalf("%s: want 1 utxo", id)
		}
		nonOwnerPub := nonOwnerKP.PubkeyBytes()
		nonOwnerCov := p2pkCovenantData(nonOwnerPub)
		utxos[0]["covenant_data"] = hex.EncodeToString(nonOwnerCov)
		utxos[0]["value"] = float64(inValue)

		prev := mustHex32(utxos[0]["txid"].(string))
		vout := uint32(utxos[0]["vout"].(float64))
		tx := &consensus.Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  1,
			Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
			Outputs:  []consensus.TxOutput{{Value: vaultOutValue, CovenantType: consensus.COV_TYPE_VAULT, CovenantData: vaultCov}},
			Locktime: 0,
		}
		d, err := consensus.SighashV1Digest(tx, 0, inValue, chainID)
		if err != nil {
			fatalf("%s: sighash: %v", id, err)
		}
		sig, err := nonOwnerKP.SignDigest32(d)
		if err != nil {
			fatalf("%s: sign: %v", id, err)
		}
		tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: nonOwnerPub, Signature: sig}}
		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// Positive: input is owner-authorized; creates vault output.
	{
		id := "VAULT-CREATE-02"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 1 {
			fatalf("%s: want 1 utxo", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[0]["value"] = float64(inValue)

		prev := mustHex32(utxos[0]["txid"].(string))
		vout := uint32(utxos[0]["vout"].(float64))
		tx := &consensus.Tx{
			Version:  1,
			TxKind:   0x00,
			TxNonce:  1,
			Inputs:   []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
			Outputs:  []consensus.TxOutput{{Value: vaultOutValue, CovenantType: consensus.COV_TYPE_VAULT, CovenantData: vaultCov}},
			Locktime: 0,
		}
		d, err := consensus.SighashV1Digest(tx, 0, inValue, chainID)
		if err != nil {
			fatalf("%s: sighash: %v", id, err)
		}
		sig, err := ownerKP.SignDigest32(d)
		if err != nil {
			fatalf("%s: sign: %v", id, err)
		}
		tx.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: sig}}
		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}
}

func updateVaultSpendVectorsVaultFixture(
	f *fixtureFile,
	chainID [32]byte,
	ownerKP *consensus.MLDSA87Keypair,
	sponsorKP *consensus.MLDSA87Keypair,
	vaultKP *consensus.MLDSA87Keypair,
	destKP *consensus.MLDSA87Keypair,
	dest2KP *consensus.MLDSA87Keypair,
	vaultValue uint64,
	ownerFeeInValue uint64,
	sponsorInValue uint64,
) {
	ownerPub := ownerKP.PubkeyBytes()
	ownerInCov := p2pkCovenantData(ownerPub)
	ownerLockID := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, ownerInCov))

	vaultPub := vaultKP.PubkeyBytes()
	vaultKeyID := keyIDForPub(vaultPub)
	destCov := p2pkCovenantData(destKP.PubkeyBytes())
	destDescHash := sha3_256(consensus.OutputDescriptorBytes(consensus.COV_TYPE_P2PK, destCov))
	vaultCov := vaultCovenantData(ownerLockID, vaultKeyID, destDescHash)

	// VAULT-SPEND-02: include a non-owner P2PK input (valid sig) to trigger sponsorship forbidden.
	{
		id := "VAULT-SPEND-02"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 3 {
			fatalf("%s: want 3 utxos", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)

		sponsorPub := sponsorKP.PubkeyBytes()
		sponsorCov := p2pkCovenantData(sponsorPub)
		utxos[2]["covenant_data"] = hex.EncodeToString(sponsorCov)
		utxos[2]["value"] = float64(sponsorInValue)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		prev2 := mustHex32(utxos[2]["txid"].(string))
		vout0 := uint32(utxos[0]["vout"].(float64))
		vout1 := uint32(utxos[1]["vout"].(float64))
		vout2 := uint32(utxos[2]["vout"].(float64))

		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev2, PrevVout: vout2, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: vaultValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: destCov}},
			Locktime: 0,
		}

		// Witness cursor: vault(1) + owner(1) + sponsor(1) = 3 witness items.
		// For this vector, vault threshold is checked *after* sponsorship, so we can keep the vault witness as sentinel (smaller).
		d1, err := consensus.SighashV1Digest(tx, 1, ownerFeeInValue, chainID)
		if err != nil {
			fatalf("%s: sighash owner: %v", id, err)
		}
		ownerSig, err := ownerKP.SignDigest32(d1)
		if err != nil {
			fatalf("%s: sign owner: %v", id, err)
		}
		d2, err := consensus.SighashV1Digest(tx, 2, sponsorInValue, chainID)
		if err != nil {
			fatalf("%s: sighash sponsor: %v", id, err)
		}
		sponsorSig, err := sponsorKP.SignDigest32(d2)
		if err != nil {
			fatalf("%s: sign sponsor: %v", id, err)
		}
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: nil, Signature: nil},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: sponsorPub, Signature: sponsorSig},
		}

		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}

	// VAULT-SPEND-04: output not whitelisted (must pass vault threshold first).
	{
		id := "VAULT-SPEND-04"
		v := findVector(f, id)
		utxos := anyToSliceMap(v["utxos"])
		if len(utxos) != 2 {
			fatalf("%s: want 2 utxos", id)
		}
		utxos[0]["covenant_data"] = hex.EncodeToString(vaultCov)
		utxos[0]["value"] = float64(vaultValue)
		utxos[1]["covenant_data"] = hex.EncodeToString(ownerInCov)
		utxos[1]["value"] = float64(ownerFeeInValue)

		prev0 := mustHex32(utxos[0]["txid"].(string))
		prev1 := mustHex32(utxos[1]["txid"].(string))
		vout0 := uint32(utxos[0]["vout"].(float64))
		vout1 := uint32(utxos[1]["vout"].(float64))

		nonWL := p2pkCovenantData(dest2KP.PubkeyBytes())
		tx := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 1,
			Inputs: []consensus.TxInput{
				{PrevTxid: prev0, PrevVout: vout0, ScriptSig: nil, Sequence: 0},
				{PrevTxid: prev1, PrevVout: vout1, ScriptSig: nil, Sequence: 0},
			},
			Outputs:  []consensus.TxOutput{{Value: vaultValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: nonWL}},
			Locktime: 0,
		}

		d0, err := consensus.SighashV1Digest(tx, 0, vaultValue, chainID)
		if err != nil {
			fatalf("%s: sighash0: %v", id, err)
		}
		vaultSig, err := vaultKP.SignDigest32(d0)
		if err != nil {
			fatalf("%s: vault sign: %v", id, err)
		}
		d1, err := consensus.SighashV1Digest(tx, 1, ownerFeeInValue, chainID)
		if err != nil {
			fatalf("%s: sighash1: %v", id, err)
		}
		ownerSig, err := ownerKP.SignDigest32(d1)
		if err != nil {
			fatalf("%s: owner sign: %v", id, err)
		}
		tx.Witness = []consensus.WitnessItem{
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: vaultPub, Signature: vaultSig},
			{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: ownerPub, Signature: ownerSig},
		}

		b := mustTxBytes(tx)
		v["tx_hex"] = hex.EncodeToString(b)
		v["utxos"] = utxos
	}
}

func updateHTLCVector(
	f *fixtureFile,
	id string,
	chainID [32]byte,
	claimKP *consensus.MLDSA87Keypair,
	refundKP *consensus.MLDSA87Keypair,
	destKP *consensus.MLDSA87Keypair,
) {
	v := findVector(f, id)
	utxos := anyToSliceMap(v["utxos"])
	if len(utxos) != 1 {
		fatalf("%s: want 1 utxo", id)
	}

	claimPub := claimKP.PubkeyBytes()
	refundPub := refundKP.PubkeyBytes()
	claimKeyID := keyIDForPub(claimPub)
	refundKeyID := keyIDForPub(refundPub)

	preimage := []byte("rubin-htlc-claim-preimage")
	hash := sha3_256(preimage)

	lockMode := byte(consensus.LOCK_MODE_TIMESTAMP)
	lockValue := uint64(2500) // must be > 0, but claim path doesn't enforce it further.

	htlcCov := make([]byte, 0, consensus.MAX_HTLC_COVENANT_DATA)
	htlcCov = append(htlcCov, hash[:]...)
	htlcCov = append(htlcCov, lockMode)
	var lv [8]byte
	binary.LittleEndian.PutUint64(lv[:], lockValue)
	htlcCov = append(htlcCov, lv[:]...)
	htlcCov = append(htlcCov, claimKeyID[:]...)
	htlcCov = append(htlcCov, refundKeyID[:]...)
	if len(htlcCov) != consensus.MAX_HTLC_COVENANT_DATA {
		fatalf("%s: bad htlc cov len=%d", id, len(htlcCov))
	}

	utxos[0]["covenant_data"] = hex.EncodeToString(htlcCov)
	utxos[0]["covenant_type"] = float64(consensus.COV_TYPE_HTLC)
	utxos[0]["value"] = float64(100)

	prev := mustHex32(utxos[0]["txid"].(string))
	vout := uint32(utxos[0]["vout"].(float64))

	outCov := p2pkCovenantData(destKP.PubkeyBytes())
	tx := &consensus.Tx{
		Version: 1,
		TxKind:  0x00,
		TxNonce: 1,
		Inputs:  []consensus.TxInput{{PrevTxid: prev, PrevVout: vout, ScriptSig: nil, Sequence: 0}},
		Outputs: []consensus.TxOutput{{Value: 90, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		// Keep locktime=0 for non-coinbase.
		Locktime: 0,
	}

	d, err := consensus.SighashV1Digest(tx, 0, 100, chainID)
	if err != nil {
		fatalf("%s: sighash: %v", id, err)
	}
	sig, err := claimKP.SignDigest32(d)
	if err != nil {
		fatalf("%s: sign: %v", id, err)
	}

	// Witness items for HTLC input:
	//  - path selector (sentinel): pubkey=key_id (32), signature=claim payload
	//  - crypto signature (ML-DSA): pubkey + signature
	var selSig []byte
	selSig = append(selSig, 0x00) // pathID=claim
	var preLen [2]byte
	binary.LittleEndian.PutUint16(preLen[:], uint16(len(preimage)))
	selSig = append(selSig, preLen[:]...)
	selSig = append(selSig, preimage...)

	tx.Witness = []consensus.WitnessItem{
		{SuiteID: consensus.SUITE_ID_SENTINEL, Pubkey: claimKeyID[:], Signature: selSig},
		{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: claimPub, Signature: sig},
	}

	b := mustTxBytes(tx)

	v["tx_hex"] = hex.EncodeToString(b)
	v["utxos"] = utxos
}

func updateSubsidyBlocks(
	f *fixtureFile,
	chainID [32]byte,
	spendKP *consensus.MLDSA87Keypair,
	coinbaseDestKP *consensus.MLDSA87Keypair,
) {
	// Both vectors use the same header prev hash/target in the fixtures.
	sub1 := findVector(f, "CV-SUB-01")
	sub2 := findVector(f, "CV-SUB-02")

	blockHeight := uint64(1)
	alreadyGenerated := uint64(0)
	sumFees := uint64(10)
	subsidy := consensus.BlockSubsidy(blockHeight, alreadyGenerated)

	spendPub := spendKP.PubkeyBytes()
	spendInCov := p2pkCovenantData(spendPub)
	spendUTXO := anyToSliceMap(sub1["utxos"])
	if len(spendUTXO) != 1 {
		fatalf("CV-SUB-01: want 1 utxo")
	}
	spendUTXO[0]["covenant_data"] = hex.EncodeToString(spendInCov)

	prevSpend := mustHex32(spendUTXO[0]["txid"].(string))
	prevSpendVout := uint32(spendUTXO[0]["vout"].(float64))

	// Build the non-coinbase tx: 100 -> 90 (fee=10).
	outCov := p2pkCovenantData(coinbaseDestKP.PubkeyBytes())
	nonCoinbase := &consensus.Tx{
		Version:  1,
		TxKind:   0x00,
		TxNonce:  1,
		Inputs:   []consensus.TxInput{{PrevTxid: prevSpend, PrevVout: prevSpendVout, ScriptSig: nil, Sequence: 0}},
		Outputs:  []consensus.TxOutput{{Value: 90, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: outCov}},
		Locktime: 0,
	}
	d, err := consensus.SighashV1Digest(nonCoinbase, 0, 100, chainID)
	if err != nil {
		fatalf("subsidy: sighash: %v", err)
	}
	sig, err := spendKP.SignDigest32(d)
	if err != nil {
		fatalf("subsidy: sign: %v", err)
	}
	nonCoinbase.Witness = []consensus.WitnessItem{{SuiteID: consensus.SUITE_ID_ML_DSA_87, Pubkey: spendPub, Signature: sig}}
	nonCoinbaseBytes := mustTxBytes(nonCoinbase)

	// Coinbase destination output covenant data can be any valid P2PK (no sig required).
	cbDestCov := p2pkCovenantData(coinbaseDestKP.PubkeyBytes())

	buildBlock := func(coinbaseValue uint64) string {
		coinbase := &consensus.Tx{
			Version: 1,
			TxKind:  0x00,
			TxNonce: 0,
			Inputs: []consensus.TxInput{{
				PrevTxid:  [32]byte{},
				PrevVout:  ^uint32(0),
				ScriptSig: nil,
				Sequence:  ^uint32(0),
			}},
			Outputs: []consensus.TxOutput{
				{Value: coinbaseValue, CovenantType: consensus.COV_TYPE_P2PK, CovenantData: cbDestCov},
				{Value: 0, CovenantType: consensus.COV_TYPE_ANCHOR, CovenantData: bytes.Repeat([]byte{0x00}, 32)}, // placeholder
			},
			Locktime:  uint32(blockHeight),
			Witness:   nil,
			DaPayload: nil,
		}

		// Compute witness commitment from wtxids (coinbase + non-coinbase).
		coinbaseBytes := mustTxBytes(coinbase)
		_, _, cbWtxid, n, err := consensus.ParseTx(coinbaseBytes)
		if err != nil || n != len(coinbaseBytes) {
			fatalf("subsidy: parse coinbase: err=%v consumed=%d", err, n)
		}
		_, _, ncWtxid, n, err := consensus.ParseTx(nonCoinbaseBytes)
		if err != nil || n != len(nonCoinbaseBytes) {
			fatalf("subsidy: parse non-coinbase: err=%v consumed=%d", err, n)
		}
		wroot, err := consensus.WitnessMerkleRootWtxids([][32]byte{cbWtxid, ncWtxid})
		if err != nil {
			fatalf("subsidy: witness root: %v", err)
		}
		wc := consensus.WitnessCommitmentHash(wroot)
		coinbase.Outputs[1].CovenantData = wc[:]
		coinbaseBytes = mustTxBytes(coinbase)

		_, cbTxid, _, n, err := consensus.ParseTx(coinbaseBytes)
		if err != nil || n != len(coinbaseBytes) {
			fatalf("subsidy: parse coinbase(2): err=%v consumed=%d", err, n)
		}
		_, ncTxid, _, n, err := consensus.ParseTx(nonCoinbaseBytes)
		if err != nil || n != len(nonCoinbaseBytes) {
			fatalf("subsidy: parse non-coinbase(2): err=%v consumed=%d", err, n)
		}
		merkle, err := consensus.MerkleRootTxids([][32]byte{cbTxid, ncTxid})
		if err != nil {
			fatalf("subsidy: merkle root: %v", err)
		}

		prevHash := mustHex32(sub1["expected_prev_hash"].(string))
		header := make([]byte, 0, consensus.BLOCK_HEADER_BYTES)
		header = appendU32le(header, 1)
		header = append(header, prevHash[:]...)
		header = append(header, merkle[:]...)
		header = appendU64le(header, 123) // timestamp (matches prior fixture style)
		header = append(header, bytes.Repeat([]byte{0xff}, 32)...)
		header = appendU64le(header, 123) // nonce
		if len(header) != consensus.BLOCK_HEADER_BYTES {
			fatalf("subsidy: header len=%d", len(header))
		}

		var block []byte
		block = append(block, header...)
		block = appendCompactSize(block, 2)
		block = append(block, coinbaseBytes...)
		block = append(block, nonCoinbaseBytes...)

		if _, err := consensus.ValidateBlockBasicWithContextAtHeight(block, nil, nil, blockHeight, nil); err != nil {
			fatalf("subsidy: generated block fails basic validation: %v", err)
		}

		return hex.EncodeToString(block)
	}

	sub1["block_hex"] = buildBlock(subsidy + sumFees)
	sub1["utxos"] = spendUTXO
	sub1["already_generated"] = float64(alreadyGenerated)

	sub2["block_hex"] = buildBlock(subsidy + sumFees + 1)
	sub2["utxos"] = spendUTXO
	sub2["already_generated"] = float64(alreadyGenerated)
}

func mustTxBytes(tx *consensus.Tx) []byte {
	b, err := txBytes(tx)
	if err != nil {
		fatalf("txBytes: %v", err)
	}
	if _, _, _, n, err := consensus.ParseTx(b); err != nil || n != len(b) {
		fatalf("txBytes sanity: err=%v consumed=%d len=%d", err, n, len(b))
	}
	return b
}

func anyToSliceMap(v any) []map[string]any {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		// json.Unmarshal uses []any, not []map. Handle already-converted.
		if m2, ok2 := v.([]map[string]any); ok2 {
			return m2
		}
		fatalf("unexpected list type %T", v)
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			fatalf("unexpected item type %T", item)
		}
		out = append(out, m)
	}
	return out
}

func mustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		fatalf("bad hex32: %q", s)
	}
	copy(out[:], b)
	return out
}

func repoRootFromGoModule() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// We run under clients/go; repo root is two levels up from that module root.
	// Be strict: ensure go.mod exists in cwd or parent chain.
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// module root is dir; repo root is two parents.
			return filepath.Clean(filepath.Join(dir, "../..")), nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			break
		}
		dir = next
	}
	return "", fmt.Errorf("could not locate go.mod from %s", wd)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "fatal: "+format+"\n", args...)
	os.Exit(1)
}

// --- minimal CompactSize + little-endian encoders (mirrors consensus encoding) ---

func appendU16le(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU32le(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendU64le(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendCompactSize(b []byte, v uint64) []byte {
	switch {
	case v < 0xfd:
		return append(b, byte(v))
	case v <= 0xffff:
		b = append(b, 0xfd)
		return appendU16le(b, uint16(v))
	case v <= 0xffffffff:
		b = append(b, 0xfe)
		return appendU32le(b, uint32(v))
	default:
		b = append(b, 0xff)
		return appendU64le(b, v)
	}
}

// Ensure whitelist/keys ordering is canonical for any future extension.
func sortedUnique32(xs [][32]byte) [][32]byte {
	sort.Slice(xs, func(i, j int) bool {
		return bytes.Compare(xs[i][:], xs[j][:]) < 0
	})
	out := make([][32]byte, 0, len(xs))
	var last *[32]byte
	for i := range xs {
		if last != nil && *last == xs[i] {
			continue
		}
		x := xs[i]
		out = append(out, x)
		last = &x
	}
	return out
}
