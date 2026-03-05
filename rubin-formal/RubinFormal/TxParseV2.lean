import Std
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.DaCoreV1

namespace RubinFormal

open Wire

namespace TxV2

-- Consensus constants (subset, from CANONICAL §2/§5).
def MAX_TX_INPUTS : Nat := 1024
def MAX_TX_OUTPUTS : Nat := 1024
def MAX_SCRIPT_SIG_BYTES : Nat := 32
def MAX_WITNESS_ITEMS : Nat := 1024
def MAX_WITNESS_BYTES_PER_TX : Nat := 100000
-- Wire-level hard cap (CANONICAL §5.3).
def MAX_COVENANT_DATA_PER_OUTPUT : Nat := 65536

def SUITE_ID_SENTINEL : Nat := 0x00
def SUITE_ID_ML_DSA_87 : Nat := 0x01

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627

def MAX_HTLC_PREIMAGE_BYTES : Nat := 256

@[inline] def fail (e : TxErr) : ParseResult :=
  { ok := false, err := some e, txid := none, wtxid := none }

def requireMinimal (minimal : Bool) : Option Unit :=
  if minimal then some () else none

def parseInputs (c : Cursor) (n : Nat) : Option Cursor := do
  let mut cur := c
  for _ in [0:n] do
    -- prev_txid (32) + prev_vout (4)
    let (_, cur1) ← cur.getBytes? 32
    let (_, cur2) ← cur1.getBytes? 4
    -- script_sig_len
    let (ssLen, cur3, minimal) ← cur2.getCompactSize?
    let _ ← requireMinimal minimal
    if ssLen > MAX_SCRIPT_SIG_BYTES then
      none
    let (_, cur4) ← cur3.getBytes? ssLen
    -- sequence (4)
    let (_, cur5) ← cur4.getBytes? 4
    cur := cur5
  pure cur

def parseOutputs (c : Cursor) (n : Nat) : Option Cursor := do
  let mut cur := c
  for _ in [0:n] do
    -- value (8) + covenant_type (2)
    let (_, cur1) ← cur.getBytes? 8
    let (_, cur2) ← cur1.getBytes? 2
    -- covenant_data_len
    let (cdLen, cur3, minimal) ← cur2.getCompactSize?
    let _ ← requireMinimal minimal
    if cdLen > MAX_COVENANT_DATA_PER_OUTPUT then
      none
    let (_, cur4) ← cur3.getBytes? cdLen
    cur := cur4
  pure cur

def parseWitnessItem (c : Cursor) : Option (Cursor × Option TxErr) := do
  let (suite, c1) ← c.getU8?
  let suiteID := suite.toNat
  let (pubLen, c2, minimal1) ← c1.getCompactSize?
  let _ ← requireMinimal minimal1
  let (_pub, c3) ← c2.getBytes? pubLen
  let (sigLen, c4, minimal2) ← c3.getCompactSize?
  let _ ← requireMinimal minimal2
  let (sig, c5) ← c4.getBytes? sigLen

  -- Non-sentinel suites require at least 1 byte of signature (sighash_type).
  if suiteID != SUITE_ID_SENTINEL && sigLen == 0 then
    none
  else
  -- Canonicalization rules (CANONICAL §5.4).
  if suiteID == SUITE_ID_SENTINEL then
    if pubLen == 0 && sigLen == 0 then
      pure (c5, none)
    else if pubLen == 32 then
      if sigLen == 1 then
        if sig.size == 1 && sig.get! 0 == 0x01 then
          pure (c5, none)
        else
          none
      else if sigLen >= 3 then
        if sig.size >= 3 && sig.get! 0 == 0x00 then
          let preLen := Wire.u16le? (sig.get! 1) (sig.get! 2)
          if preLen >= 1 && preLen <= MAX_HTLC_PREIMAGE_BYTES && sigLen == 3 + preLen then
            pure (c5, none)
          else
            none
        else
          none
      else
        none
    else
      none
  else if suiteID == SUITE_ID_ML_DSA_87 then
    -- Wire canonical size includes the trailing sighash_type byte (+1).
    if pubLen == ML_DSA_87_PUBKEY_BYTES && sigLen == ML_DSA_87_SIG_BYTES + 1 then
      pure (c5, none)
    else
      pure (c5, some .sigNoncanonical)
  else
    -- Unknown suites are accepted at parse stage (CANONICAL §12.2 / CV-SIG-05).
    -- Semantic suite authorization is enforced at the spend path.
    pure (c5, none)

-- Per-item short-circuit: matches Go behaviour where overflow and canonical checks
-- happen after each item rather than at the end.  The first error encountered wins.
def parseWitnessSection (c : Cursor) : Option (Cursor × TxErr × Nat × Nat) := do
  let startOff := c.off
  let (wCount, c1, minimal) ← c.getCompactSize?
  let _ ← requireMinimal minimal
  if wCount > MAX_WITNESS_ITEMS then
    pure (c1, .witnessOverflow, startOff, c1.off)
  else
    let rec loop (cur : Cursor) (remaining : Nat) (earlyErr : Option TxErr)
        : Option (Cursor × TxErr × Nat × Nat) := do
      match remaining with
      | 0 =>
          let endOff := cur.off
          let err := earlyErr.getD .parse
          pure (cur, err, startOff, endOff)
      | Nat.succ rem =>
          -- If a hard error was already seen, we still need to consume the remaining
          -- witness bytes to reach the correct cursor position for subsequent parsing.
          let (cur', e) ← parseWitnessItem cur
          -- Per-item cumulative witness byte check (Go checks after each item).
          let cumBytes := cur'.off - startOff
          let earlyErr' :=
            if earlyErr.isSome then earlyErr
            else if cumBytes > MAX_WITNESS_BYTES_PER_TX then some .witnessOverflow
            else match e with
              | some err => some err
              | none => none
          loop cur' rem earlyErr'
    loop c1 wCount none

def parseTx (tx : Bytes) : ParseResult :=
  let c0 : Cursor := { bs := tx, off := 0 }
  match c0.getU32le? with
  | none => fail .parse
  | some (_version, c1) =>
    match c1.getU8? with
    | none => fail .parse
    | some (txKindB, c2) =>
      let txKind := txKindB.toNat
      if !(txKind == 0x00 || txKind == 0x01 || txKind == 0x02) then
        fail .parse
      else
        match c2.getU64le? with
        | none => fail .parse
        | some (_nonce, c3) =>
          match c3.getCompactSize? with
          | none => fail .parse
          | some (inCount, c4, minIn) =>
            if !minIn then fail .parse else
            if inCount > MAX_TX_INPUTS then fail .parse else
            match parseInputs c4 inCount with
            | none => fail .parse
            | some c5 =>
              match c5.getCompactSize? with
              | none => fail .parse
              | some (outCount, c6, minOut) =>
                if !minOut then fail .parse else
                if outCount > MAX_TX_OUTPUTS then fail .parse else
                match parseOutputs c6 outCount with
                | none => fail .parse
                | some c7 =>
                  -- locktime
                  match c7.getU32le? with
                  | none => fail .parse
                  | some (_locktime, c8) =>
                    match DaCoreV1.parseDaCoreFields txKind c8 with
                    | none => fail .parse
                    | some cDa =>
                      let coreEnd := cDa.off

                    -- witness
                    match parseWitnessSection cDa with
                    | none => fail .parse
                    | some (cW, wErr, _wStart, _wEnd) =>
                      -- Per-item error priority (Go bails on first per-item error):
                      -- overflow and canonical checks happen per item inside
                      -- parseWitnessSection; wErr captures the first one encountered.
                      if wErr == .witnessOverflow then
                        fail .witnessOverflow
                      else if wErr == .sigAlgInvalid then
                        fail .sigAlgInvalid
                      else if wErr == .sigNoncanonical then
                        fail .sigNoncanonical
                      else
                        -- da_payload_len + payload
                        match cW.getCompactSize? with
                        | none => fail .parse
                        | some (daLen, c9, minDa) =>
                          if !minDa then fail .parse else
                          match c9.getBytes? daLen with
                          | none => fail .parse
                          | some (_payload, c10) =>
                            if c10.off != tx.size then
                              fail .parse
                            else if txKind == 0x00 && daLen != 0 then
                              fail .parse
                            else if txKind == 0x01 && daLen > DaCoreV1.MAX_DA_MANIFEST_BYTES_PER_TX then
                              fail .parse
                            else if txKind == 0x02 && (daLen < 1 || daLen > DaCoreV1.CHUNK_BYTES) then
                              fail .parse
                            else
                              let core := tx.extract 0 coreEnd
                              let txid := SHA3.sha3_256 core
                              let wtxid := SHA3.sha3_256 tx
                              { ok := true, err := none, txid := some txid, wtxid := some wtxid }

end TxV2
end RubinFormal
