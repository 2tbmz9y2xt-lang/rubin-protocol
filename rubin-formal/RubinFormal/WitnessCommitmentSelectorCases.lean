import RubinFormal.BlockBasicV1
import RubinFormal.BlockBasicCheckV1
import RubinFormal.Hex
import RubinFormal.Conformance.CVBlockBasicVectors

/-!
Compile-time test cases for the Section 10.4.1 selector of the block-basic model.
These are finite executed examples, not registered coverage; a false expectation
fails `lake build` at its own theorem. The commitment is the literal CORE_ANCHOR
data of fixture CV-B-01; it holds for every one-transaction block because the
coinbase slot of the witness tree is fixed to zero bytes.
-/

namespace RubinFormal.WitnessCommitmentSelectorCases

open RubinFormal
open RubinFormal.BlockBasicV1

private def hx (s : String) : Bytes := (decodeHex? s).getD ByteArray.empty

private def commit : Bytes :=
  hx "b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a8"
private def otherA : Bytes :=
  hx "b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071a9"
private def otherB : Bytes :=
  hx "b716a4b7f4c0fab665298ab9b8199b601ab9fa7e0a27f0713383f34cf37071aa"
private def prev : Bytes :=
  hx "1111111111111111111111111111111111111111111111111111111111111111"
private def target : Bytes :=
  hx "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
private def wrongRoot : Bytes :=
  hx "2222222222222222222222222222222222222222222222222222222222222222"

private def out (value : UInt8) (covType : Nat) (data : Bytes) : Bytes :=
  RubinFormal.bytes #[value, 0, 0, 0, 0, 0, 0, 0, UInt8.ofNat (covType % 256),
    UInt8.ofNat (covType / 256), UInt8.ofNat data.size] ++ data

private def anchor (data : Bytes) : Bytes := out 0 2 data
private def good : Bytes := anchor commit
private def anchor31 : Bytes := anchor (commit.extract 0 31)
private def anchor33 : Bytes := anchor (commit ++ RubinFormal.bytes #[0])
private def otherType : Bytes := out 0 0 commit
/-- CORE_DA_COMMIT (0x0103), which the model groups with CORE_ANCHOR for byte accounting. -/
private def daCommitType : Bytes := out 0 0x0103 commit
/-- An unassigned type sharing the low byte of CORE_ANCHOR. -/
private def sameLowByteType : Bytes := out 0 0x0202 commit

private def txHead : Bytes :=
  hx ("01000000" ++ "00" ++ "0000000000000000" ++ "01"
    ++ "0000000000000000000000000000000000000000000000000000000000000000"
    ++ "ffffffff" ++ "00" ++ "ffffffff")
private def txTail : Bytes := hx "000000000000"

private def coinbase (outs : List Bytes) : Bytes :=
  txHead ++ RubinFormal.bytes #[UInt8.ofNat outs.length]
    ++ outs.foldl (· ++ ·) ByteArray.empty ++ txTail

private def blockWithRoot (root : Bytes) (outs : List Bytes) : Bytes :=
  headerBytes
      { version := 1, prevHash := prev, merkleRoot := root,
        timestamp := 1, target := target, nonce := 7 }
    ++ RubinFormal.bytes #[1] ++ coinbase outs

/-- Only the header Merkle root, an input to the stage under test, uses the model. -/
private def block (outs : List Bytes) : Bytes :=
  let root :=
    match parseTxFromCursor { bs := coinbase outs, off := 0 } with
    | .ok (_, txid, _, _, _) => (merkleRootTxids [txid]).toOption.getD ByteArray.empty
    | .error _ => ByteArray.empty
  blockWithRoot root outs

private def atBasic (b : Bytes) : Except String Unit :=
  validateBlockBasic b (some prev) (some target)
private def atCheck (b : Bytes) : Except String Unit :=
  BlockBasicCheckV1.validateBlockBasicCheck b (some prev) (some target) 0 [0]
private def atCheckOld (b : Bytes) : Except String Unit :=
  BlockBasicCheckV1.validateBlockBasicCheck b (some prev) (some target) 0 [1]

private def isOk {α : Type} : Except String α → Bool
  | .ok _ => true
  | .error _ => false
private def errIs {α : Type} (s : String) : Except String α → Bool
  | .ok _ => false
  | .error e => e == s
private def witnessErr {α : Type} : Except String α → Bool :=
  errIs "BLOCK_ERR_WITNESS_COMMITMENT"

/-- `checkWitnessCommitment` on the parsed F01 singleton with its coinbase bytes replaced. -/
private def checkWithCoinbase (tx : Bytes) : Except String Unit :=
  match parseBlock (block [good]) with
  | .ok pb => checkWitnessCommitment { pb with coinbaseTx := tx }
  | .error e => .error e

private def truncatedCoinbase : Bytes :=
  let tx := coinbase [good]
  tx.extract 0 (tx.size - 20)
private def nonMinimalLenCoinbase : Bytes :=
  txHead ++ RubinFormal.bytes #[1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0xfd, 32, 0] ++ commit ++ txTail

/-- A qualifying matching output followed by a second output the selector cannot read:
a selector that tolerates the failure would hold a count of one and accept. -/
private def goodThen (defect : Bytes) : Bytes :=
  txHead ++ RubinFormal.bytes #[2] ++ good ++ defect

private def valuePrefix : Bytes := RubinFormal.bytes #[0, 0, 0, 0, 0, 0, 0, 0]
private def typedPrefix : Bytes := valuePrefix ++ RubinFormal.bytes #[0, 0]

private def truncatedValue : Bytes := goodThen (RubinFormal.bytes #[0, 0, 0])
private def truncatedType : Bytes := goodThen (valuePrefix ++ RubinFormal.bytes #[0])
private def truncatedLen : Bytes := goodThen (typedPrefix ++ RubinFormal.bytes #[0xfd, 32])
private def truncatedData : Bytes :=
  goodThen (typedPrefix ++ RubinFormal.bytes #[32] ++ commit.extract 0 5)
private def nonMinimalLenSecond : Bytes :=
  goodThen (typedPrefix ++ RubinFormal.bytes #[0xfd, 32, 0] ++ commit) ++ txTail

private def fixtureIs (id : String) (b : Bytes) : Bool :=
  match Conformance.cvBlockBasicVectors.find? (fun v => v.id == id) with
  | none => false
  | some v =>
      match decodeHex? v.blockHex with
      | none => false
      | some fixture => fixture == b

-- F01: accepted singletons; neighbours outside the count, before and after it.
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_value_zero_at_basic : isOk (atBasic (block [good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_value_zero_at_check : isOk (atCheck (block [good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 5 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_value_nonzero_at_basic : isOk (atBasic (block [out 5 2 commit])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 5 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_value_nonzero_at_check : isOk (atCheck (block [out 5 2 commit])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output of 31-byte data returns ok. -/
theorem f01_good_then_len31_at_basic : isOk (atBasic (block [good, anchor31])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output of 31-byte data returns ok. -/
theorem f01_good_then_len31_at_check : isOk (atCheck (block [good, anchor31])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 31-byte data, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_len31_then_good_at_basic : isOk (atBasic (block [anchor31, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 31-byte data, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_len31_then_good_at_check : isOk (atCheck (block [anchor31, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment returns ok. -/
theorem f01_good_then_len33_at_basic : isOk (atBasic (block [good, anchor33])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment returns ok. -/
theorem f01_good_then_len33_at_check : isOk (atCheck (block [good, anchor33])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_len33_then_good_at_basic : isOk (atBasic (block [anchor33, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_len33_then_good_at_check : isOk (atCheck (block [anchor33, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_other_type_at_basic : isOk (atBasic (block [good, otherType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_other_type_at_check : isOk (atCheck (block [good, otherType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_other_type_then_good_at_basic : isOk (atBasic (block [otherType, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_other_type_then_good_at_check : isOk (atCheck (block [otherType, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0x0103 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_da_commit_at_basic : isOk (atBasic (block [good, daCommitType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0x0103 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_da_commit_at_check : isOk (atCheck (block [good, daCommitType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0x0103 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_da_commit_then_good_at_basic : isOk (atBasic (block [daCommitType, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0x0103 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_da_commit_then_good_at_check : isOk (atCheck (block [daCommitType, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0x0202 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_same_low_byte_at_basic : isOk (atBasic (block [good, sameLowByteType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0x0202 output whose 32-byte data equals the commitment returns ok. -/
theorem f01_good_then_same_low_byte_at_check : isOk (atCheck (block [good, sameLowByteType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0x0202 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_same_low_byte_then_good_at_basic : isOk (atBasic (block [sameLowByteType, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0x0202 output whose 32-byte data equals the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f01_same_low_byte_then_good_at_check : isOk (atCheck (block [sameLowByteType, good])) = true := by native_decide

-- F02: every other qualifying count or sole-data shape refuses with the witness error.
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds no outputs returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_no_output_at_basic : witnessErr (atBasic (block [])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds no outputs returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_no_output_at_check : witnessErr (atCheck (block [])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_other_type_at_basic : witnessErr (atBasic (block [otherType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_other_type_at_check : witnessErr (atCheck (block [otherType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0x0103 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_da_commit_at_basic : witnessErr (atBasic (block [daCommitType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0x0103 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_da_commit_at_check : witnessErr (atCheck (block [daCommitType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a covenant-type-0x0202 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_same_low_byte_at_basic : witnessErr (atBasic (block [sameLowByteType])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a covenant-type-0x0202 output whose 32-byte data equals the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_same_low_byte_at_check : witnessErr (atCheck (block [sameLowByteType])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 31-byte data returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_len31_at_basic : witnessErr (atBasic (block [anchor31])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 31-byte data returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_len31_at_check : witnessErr (atCheck (block [anchor31])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_len33_at_basic : witnessErr (atBasic (block [anchor33])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output of 33-byte data whose first 32 bytes equal the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_sole_len33_at_check : witnessErr (atCheck (block [anchor33])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_one_byte_different_at_basic : witnessErr (atBasic (block [anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_one_byte_different_at_check : witnessErr (atCheck (block [anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_equal_equal_at_basic : witnessErr (atBasic (block [good, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_equal_equal_at_check : witnessErr (atCheck (block [good, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_equal_distinct_at_basic : witnessErr (atBasic (block [good, anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_equal_distinct_at_check : witnessErr (atCheck (block [good, anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_distinct_equal_at_basic : witnessErr (atBasic (block [anchor otherA, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_distinct_equal_at_check : witnessErr (atCheck (block [anchor otherA, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then a second distinct CORE_ANCHOR output whose 32-byte data differs from the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_distinct_distinct_at_basic : witnessErr (atBasic (block [anchor otherA, anchor otherB])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then a second distinct CORE_ANCHOR output whose 32-byte data differs from the commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_distinct_distinct_at_check : witnessErr (atCheck (block [anchor otherA, anchor otherB])) = true := by native_decide
/-- Finite case: at `validateBlockBasic`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then a second distinct CORE_ANCHOR output whose 32-byte data differs from the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_three_last_equal_at_basic : witnessErr (atBasic (block [anchor otherA, anchor otherB, good])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block whose coinbase holds a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte, then a second distinct CORE_ANCHOR output whose 32-byte data differs from the commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f02_three_last_equal_at_check : witnessErr (atCheck (block [anchor otherA, anchor otherB, good])) = true := by native_decide

-- F03: selector read failures have no success path.
/-- Finite control: `checkWitnessCommitment` on the parsed singleton block with its coinbase bytes replaced by a coinbase holding one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns ok. -/
theorem f03_control_unreplaced_coinbase_accepted : isOk (checkWithCoinbase (coinbase [good])) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes truncated inside the data of its sole output returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_truncated_at_selector : witnessErr (findCoinbaseAnchorCommitment truncatedCoinbase) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes truncated inside the data of its sole output returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_truncated_at_check_witness : witnessErr (checkWithCoinbase truncatedCoinbase) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes whose sole output encodes covenant_data_len 32 non-minimally returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_non_minimal_len_at_selector : witnessErr (findCoinbaseAnchorCommitment nonMinimalLenCoinbase) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes whose sole output encodes covenant_data_len 32 non-minimally returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_non_minimal_len_at_check_witness : witnessErr (checkWithCoinbase nonMinimalLenCoinbase) = true := by native_decide
/-- Finite control: `checkWitnessCommitment` on the parsed singleton block with its coinbase bytes replaced by a coinbase holding one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a covenant-type-0 output whose 32-byte data equals the commitment returns ok. -/
theorem f03_control_good_then_other_type_accepted : isOk (checkWithCoinbase (coinbase [good, otherType])) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes with a qualifying matching output and then a second output truncated inside its value returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_value_at_selector : witnessErr (findCoinbaseAnchorCommitment truncatedValue) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes with a qualifying matching output and then a second output truncated inside its value returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_value_at_check_witness : witnessErr (checkWithCoinbase truncatedValue) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant type returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_type_at_selector : witnessErr (findCoinbaseAnchorCommitment truncatedType) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant type returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_type_at_check_witness : witnessErr (checkWithCoinbase truncatedType) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant_data_len returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_len_at_selector : witnessErr (findCoinbaseAnchorCommitment truncatedLen) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant_data_len returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_len_at_check_witness : witnessErr (checkWithCoinbase truncatedLen) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant data returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_data_at_selector : witnessErr (findCoinbaseAnchorCommitment truncatedData) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes with a qualifying matching output and then a second output truncated inside its covenant data returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_data_at_check_witness : witnessErr (checkWithCoinbase truncatedData) = true := by native_decide
/-- Finite case: `findCoinbaseAnchorCommitment` on coinbase bytes with a qualifying matching output and then a second output encoding covenant_data_len 32 non-minimally returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_non_minimal_len_at_selector : witnessErr (findCoinbaseAnchorCommitment nonMinimalLenSecond) = true := by native_decide
/-- Finite case: `checkWitnessCommitment` on the parsed singleton block with its coinbase replaced by coinbase bytes with a qualifying matching output and then a second output encoding covenant_data_len 32 non-minimally returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f03_second_output_non_minimal_len_at_check_witness : witnessErr (checkWithCoinbase nonMinimalLenSecond) = true := by native_decide

-- F04: stage order around the witness stage.
/-- Finite case: at `validateBlockBasic`, a one-transaction block with a wrong header Merkle root whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_MERKLE_INVALID`. -/
theorem f04_wrong_root_pair_at_basic : errIs "BLOCK_ERR_MERKLE_INVALID" (atBasic (blockWithRoot wrongRoot [good, anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck`, a one-transaction block with a wrong header Merkle root whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_MERKLE_INVALID`. -/
theorem f04_wrong_root_pair_at_check : errIs "BLOCK_ERR_MERKLE_INVALID" (atCheck (blockWithRoot wrongRoot [good, anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck` with previous timestamps `[1]` and header timestamp 1, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then a CORE_ANCHOR output whose 32-byte data differs from the commitment in the last byte returns exactly `BLOCK_ERR_WITNESS_COMMITMENT`. -/
theorem f04_old_timestamp_pair_at_check : witnessErr (atCheckOld (block [good, anchor otherA])) = true := by native_decide
/-- Finite case: at `validateBlockBasicCheck` with previous timestamps `[1]` and header timestamp 1, a one-transaction block whose coinbase holds one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment returns exactly `BLOCK_ERR_TIMESTAMP_OLD`. -/
theorem f04_old_timestamp_singleton_at_check : errIs "BLOCK_ERR_TIMESTAMP_OLD" (atCheckOld (block [good])) = true := by native_decide

-- F07: the builder reproduces the fixture bytes from the inputs used above.
/-- Finite case: the case builder given one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment reproduces the `block_hex` bytes of fixture CV-B-01. -/
theorem f07_builder_matches_cv_b_01 : fixtureIs "CV-B-01" (block [good]) = true := by native_decide
/-- Finite case: the case builder given no outputs reproduces the `block_hex` bytes of fixture CV-B-07. -/
theorem f07_builder_matches_cv_b_07 : fixtureIs "CV-B-07" (block []) = true := by native_decide
/-- Finite case: the case builder given one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment, then one CORE_ANCHOR output of value 0 with 32-byte data equal to the CV-B-01 commitment reproduces the `block_hex` bytes of fixture CV-B-08. -/
theorem f07_builder_matches_cv_b_08 : fixtureIs "CV-B-08" (block [good, good]) = true := by native_decide

end RubinFormal.WitnessCommitmentSelectorCases
