import RubinFormal.ByteWireV2

namespace RubinFormal

open Wire

namespace DaCoreV1

def MAX_DA_MANIFEST_BYTES_PER_TX : Nat := 65536
def CHUNK_BYTES : Nat := 524288
def MAX_DA_CHUNK_COUNT : Nat := 61

def requireMinimal (minimal : Bool) : Option Unit :=
  if minimal then some () else none

def parseDaCoreFieldsWithBytes (txKind : Nat) (c : Cursor) : Option (Cursor × Nat) := do
  let start := c.off
  if txKind == 0x00 then
    pure (c, 0)
  else if txKind == 0x01 then
    let (_, c1) ← c.getBytes? 32 -- da_id
    let (ccRaw, c2) ← c1.getBytes? 2 -- chunk_count
    let chunkCount := Wire.u16le? (ccRaw.get! 0) (ccRaw.get! 1)
    if chunkCount < 1 || chunkCount > MAX_DA_CHUNK_COUNT then
      none
    let (_, c3) ← c2.getBytes? 32 -- retl_domain_id
    let (_, c4) ← c3.getBytes? 8 -- batch_number
    let (_, c5) ← c4.getBytes? 32 -- tx_data_root
    let (_, c6) ← c5.getBytes? 32 -- state_root
    let (_, c7) ← c6.getBytes? 32 -- withdrawals_root
    let (_, c8) ← c7.getBytes? 1 -- batch_sig_suite
    let (sigLen, c9, minimal) ← c8.getCompactSize?
    let _ ← requireMinimal minimal
    if sigLen > MAX_DA_MANIFEST_BYTES_PER_TX then
      none
    let (_, c10) ← c9.getBytes? sigLen
    pure (c10, c10.off - start)
  else if txKind == 0x02 then
    let (_, c1) ← c.getBytes? 32 -- da_id
    let (idxRaw, c2) ← c1.getBytes? 2 -- chunk_index
    let chunkIndex := Wire.u16le? (idxRaw.get! 0) (idxRaw.get! 1)
    if chunkIndex >= MAX_DA_CHUNK_COUNT then
      none
    let (_, c3) ← c2.getBytes? 32 -- chunk_hash
    pure (c3, c3.off - start)
  else
    none

def parseDaCoreFields (txKind : Nat) (c : Cursor) : Option Cursor := do
  let (cur, _) ← parseDaCoreFieldsWithBytes txKind c
  pure cur

end DaCoreV1

end RubinFormal
