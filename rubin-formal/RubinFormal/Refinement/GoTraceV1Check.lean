import Std
import RubinFormal.Hex
import RubinFormal.TxParseV2
import RubinFormal.SighashV1
import RubinFormal.PowV1
import RubinFormal.TxWeightV2
import RubinFormal.UtxoBasicV1
import RubinFormal.BlockBasicV1
import RubinFormal.Refinement.GoTraceV1

import RubinFormal.Conformance.CVParseVectors
import RubinFormal.Conformance.CVSighashVectors
import RubinFormal.Conformance.CVPowVectors
import RubinFormal.Conformance.CVUtxoBasicVectors
import RubinFormal.Conformance.CVBlockBasicVectors

set_option maxHeartbeats 10000000
set_option maxRecDepth 50000

namespace RubinFormal.Refinement

open RubinFormal
open TxV2
open RubinFormal.SighashV1
open RubinFormal.PowV1
open RubinFormal.TxWeightV2
open RubinFormal.UtxoBasicV1
open RubinFormal.BlockBasicV1

private def findById? (id : String) (xs : List α) (getId : α → String) : Option α :=
  xs.find? (fun x => getId x == id)

private def decodeHexOpt? (s : Option String) : Option Bytes :=
  s.bind RubinFormal.decodeHex?

private def checkParse (o : ParseOut) : Bool :=
  match findById? o.id RubinFormal.Conformance.cvParseVectors (fun v => v.id) with
  -- Vector not in Lean model scope (toy-model phase0): skip rather than fail.
  -- Ensures refinement only fails when the model has a prediction that disagrees with Go.
  | none => true
  | some v =>
      match RubinFormal.decodeHex? v.txHex with
      | none => false
      | some tx =>
          let r := TxV2.parseTx tx
          if o.ok then
            match r.txid, r.wtxid, RubinFormal.decodeHex? o.txidHex, RubinFormal.decodeHex? o.wtxidHex with
            | some txid, some wtxid, some etxid, some ewtxid =>
                r.ok == true &&
                txid == etxid &&
                wtxid == ewtxid &&
                -- consumed is only asserted on ok-path (Go parser reports bytes-consumed)
                tx.size == o.consumed
            | _, _, _, _ => false
          else
            match r.err with
            | none => false
            | some e => r.ok == false && e.toString == o.err

private def checkSighash (o : SighashOut) : Bool :=
  match findById? o.id RubinFormal.Conformance.cvSighashVectors (fun v => v.id) with
  | none => false
  | some v =>
      match RubinFormal.decodeHex? v.txHex, RubinFormal.decodeHex? v.chainIdHex, RubinFormal.decodeHex? o.digestHex with
      | some tx, some chainId, some exp =>
          match SighashV1.digestV1 tx chainId v.inputIndex v.inputValue with
          | .ok d => o.ok && d == exp
          | .error e => (!o.ok) && e == o.err
      | _, _, _ => false

private def bytesEqHex (got : Bytes) (hexStr : Option String) : Bool :=
  match hexStr with
  | none => false
  | some hs =>
      match RubinFormal.decodeHex? hs with
      | none => false
      | some exp => got == exp

private def toPowWindowPattern (p : RubinFormal.Conformance.WindowPattern) : PowV1.WindowPattern :=
  { windowSize := p.windowSize, start := p.start, step := p.step, lastJump := p.lastJump }

private def powOpToString (op : RubinFormal.Conformance.CVPowOp) : String :=
  match op with
  | .retarget_v1 => "retarget_v1"
  | .block_hash => "block_hash"
  | .pow_check => "pow_check"

private def checkPow (o : PowOut) : Bool :=
  match findById? o.id RubinFormal.Conformance.cvPowVectors (fun v => v.id) with
  | none => false
  | some v =>
      if o.op != powOpToString v.op then
        false
      else if v.op == .retarget_v1 then
        match RubinFormal.decodeHexOpt? v.targetOldHex, v.timestampFirst, v.timestampLast with
        | some tOld, some tsF, some tsL =>
            match PowV1.retargetV1 tOld tsF tsL (v.windowPattern.map toPowWindowPattern) with
            | .ok out =>
                o.ok && bytesEqHex out o.targetNewHex
            | .error e =>
                (!o.ok) && (e == o.err)
        | _, _, _ => false
      else if v.op == .block_hash then
        match RubinFormal.decodeHexOpt? v.headerHex with
        | some hb =>
            let bh := PowV1.blockHash hb
            o.ok && bytesEqHex bh o.blockHashHex
        | none => false
      else if v.op == .pow_check then
        match RubinFormal.decodeHexOpt? v.headerHex, RubinFormal.decodeHexOpt? v.targetHex with
        | some hb, some tgt =>
            match PowV1.powCheck hb tgt with
            | .ok _ => o.ok
            | .error e => (!o.ok) && (e == o.err)
        | _, _ => false
      else
        false

private def toUtxoPairs? (us : List RubinFormal.Conformance.CVUtxoEntry) : Option (List (Outpoint × UtxoEntry)) :=
  us.mapM (fun u => do
    let txid <- RubinFormal.decodeHex? u.txidHex
    let cd <- RubinFormal.decodeHex? u.covenantDataHex
    pure
      (
        { txid := txid, vout := u.vout },
        {
          value := u.value
          covenantType := u.covenantType
          covenantData := cd
          creationHeight := u.creationHeight
          createdByCoinbase := u.createdByCoinbase
        }
      ))

private def checkUtxoBasic (o : UtxoBasicOut) : Bool :=
  match findById? o.id RubinFormal.Conformance.cvUtxoBasicVectors (fun v => v.id) with
  | none => false
  | some v =>
      match RubinFormal.decodeHex? v.txHex, toUtxoPairs? v.utxos with
      | some tx, some utxos =>
          let chainId : Bytes := RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)
          match applyNonCoinbaseTxBasic tx utxos v.height v.blockTimestamp chainId with
          | .ok (fee, utxoCount) =>
              o.ok && (o.fee == some fee) && (o.utxoCount == some utxoCount)
          | .error e =>
              (!o.ok) && (o.err == e)
      | _, _ => false

private def blockSummary? (blockBytes : Bytes) : Except String (Bytes × Nat × Nat) := do
  let pb ← BlockBasicV1.parseBlock blockBytes
  -- block hash is over header bytes
  let bh := PowV1.blockHash (BlockBasicV1.headerBytes pb.header)
  let mut sumW : Nat := 0
  let mut sumDa : Nat := 0
  for tx in pb.txs do
    match TxWeightV2.txWeightAndStats tx with
    | .ok st =>
        sumW := sumW + st.weight
        sumDa := sumDa + st.daBytes
    | .error _ =>
        throw "TX_ERR_PARSE"
  pure (bh, sumW, sumDa)

private def checkBlockBasic (o : BlockBasicOut) : Bool :=
  match findById? o.id RubinFormal.Conformance.cvBlockBasicVectors (fun v => v.id) with
  | none => false
  | some v =>
      match RubinFormal.decodeHex? v.blockHex with
      | none => false
      | some blockBytes =>
          let ph := decodeHexOpt? v.expectedPrevHashHex
          let tgt := decodeHexOpt? v.expectedTargetHex
          match BlockBasicV1.validateBlockBasic blockBytes ph tgt with
          | .ok _ =>
              if !o.ok then
                false
              else
                match blockSummary? blockBytes with
                | .error _ => false
                | .ok (bh, sumW, sumDa) =>
                    bytesEqHex bh o.blockHashHex &&
                    o.sumWeight == some sumW &&
                    o.sumDa == some sumDa
          | .error e =>
              (!o.ok) && (o.err == e)

def allGoTraceV1Ok : Bool :=
  parseOuts.all checkParse &&
  sighashOuts.all checkSighash &&
  powOuts.all checkPow &&
  utxoBasicOuts.all checkUtxoBasic &&
  blockBasicOuts.all checkBlockBasic

def firstGoTraceV1Mismatch : Option String :=
  let mk (gate : String) (id : String) : Option String := some (gate ++ ":" ++ id)
  match parseOuts.find? (fun o => !checkParse o) with
  | some o => mk "CV-PARSE" o.id
  | none =>
      match sighashOuts.find? (fun o => !checkSighash o) with
      | some o => mk "CV-SIGHASH" o.id
      | none =>
          match powOuts.find? (fun o => !checkPow o) with
          | some o => mk "CV-POW" (o.id ++ "/" ++ o.op)
          | none =>
              match utxoBasicOuts.find? (fun o => !checkUtxoBasic o) with
              | some o => mk "CV-UTXO-BASIC" o.id
              | none =>
                  match blockBasicOuts.find? (fun o => !checkBlockBasic o) with
                  | some o => mk "CV-BLOCK-BASIC" o.id
                  | none => none

end RubinFormal.Refinement
