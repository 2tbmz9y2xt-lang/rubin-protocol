import Std
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2

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
def SUITE_ID_SLH_DSA_SHAKE_256F : Nat := 0x02

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627
def SLH_DSA_SHAKE_256F_PUBKEY_BYTES : Nat := 64
def MAX_SLH_DSA_SIG_BYTES : Nat := 49856

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
    if pubLen == ML_DSA_87_PUBKEY_BYTES && sigLen == ML_DSA_87_SIG_BYTES then
      pure (c5, none)
    else
      pure (c5, some .sigNoncanonical)
  else if suiteID == SUITE_ID_SLH_DSA_SHAKE_256F then
    if pubLen == SLH_DSA_SHAKE_256F_PUBKEY_BYTES && sigLen > 0 && sigLen <= MAX_SLH_DSA_SIG_BYTES then
      pure (c5, none)
    else
      pure (c5, some .sigNoncanonical)
  else
    pure (c5, some .sigAlgInvalid)

def parseWitnessSection (c : Cursor) : Option (Cursor × TxErr × Nat × Nat) := do
  let startOff := c.off
  let (wCount, c1, minimal) ← c.getCompactSize?
  let _ ← requireMinimal minimal
  if wCount > MAX_WITNESS_ITEMS then
    pure (c1, .witnessOverflow, startOff, c1.off)
  else
    let mut cur := c1
    let mut anySigAlgInvalid : Bool := false
    let mut anySigNoncanonical : Bool := false
    for _ in [0:wCount] do
      let (cur', e) ← parseWitnessItem cur
      cur := cur'
      match e with
      | none => ()
      | some .sigAlgInvalid => anySigAlgInvalid := true
      | some .sigNoncanonical => anySigNoncanonical := true
      | some .witnessOverflow => () -- not produced here
      | some .parse => () -- not produced here
    let endOff := cur.off
    let err :=
      if anySigAlgInvalid then .sigAlgInvalid
      else if anySigNoncanonical then .sigNoncanonical
      else .parse
    pure (cur, err, startOff, endOff)

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
                    -- DaCoreFields: for parse vectors we only require structural presence for kind=0x00.
                    let coreEnd := c8.off

                    -- witness
                    match parseWitnessSection c8 with
                    | none => fail .parse
                    | some (cW, wErr, wStart, wEnd) =>
                      let witBytes := wEnd - wStart
                      if witBytes > MAX_WITNESS_BYTES_PER_TX then
                        fail .witnessOverflow
                      else if wErr == .witnessOverflow then
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
                            else
                              let core := tx.extract 0 coreEnd
                              let txid := SHA3.sha3_256 core
                              let wtxid := SHA3.sha3_256 tx
                              { ok := true, err := none, txid := some txid, wtxid := some wtxid }

end TxV2
end RubinFormal
