use crate::error::{ErrorCode, TxError};
use crate::wire_read::Reader;

pub fn read_compact_size(r: &mut Reader<'_>) -> Result<(u64, usize), TxError> {
    let start = r.offset();
    let tag = r.read_u8()?;

    let (v, minimal_ok) = match tag {
        0x00..=0xfc => (tag as u64, true),
        0xfd => {
            let v = r.read_u16_le()? as u64;
            (v, v >= 0xfd)
        }
        0xfe => {
            let v = r.read_u32_le()? as u64;
            (v, v > 0xffff)
        }
        0xff => {
            let v = r.read_u64_le()?;
            (v, v > 0xffff_ffff)
        }
    };

    if !minimal_ok {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "non-minimal CompactSize",
        ));
    }

    Ok((v, r.offset() - start))
}

pub fn read_compact_size_bytes(b: &[u8]) -> Result<(u64, usize), TxError> {
    let mut r = Reader::new(b);
    read_compact_size(&mut r)
}

pub fn encode_compact_size(n: u64, out: &mut Vec<u8>) {
    match n {
        0x00..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// Kani bounded model checking proofs
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod verification {
    use super::*;

    /// For any u64 value, encode → decode must roundtrip to the same value
    /// and consume exactly the number of bytes produced.
    #[kani::proof]
    fn verify_compact_size_roundtrip() {
        let n: u64 = kani::any();
        let mut buf = Vec::new();
        encode_compact_size(n, &mut buf);

        let (decoded, consumed) = read_compact_size_bytes(&buf).unwrap();
        assert_eq!(decoded, n);
        assert_eq!(consumed, buf.len());
    }

    /// encode_compact_size always produces minimal encoding (no wasted bytes).
    #[kani::proof]
    fn verify_compact_size_encoding_is_minimal() {
        let n: u64 = kani::any();
        let mut buf = Vec::new();
        encode_compact_size(n, &mut buf);

        let expected_len = match n {
            0x00..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x1_0000..=0xffff_ffff => 5,
            _ => 9,
        };
        assert_eq!(buf.len(), expected_len);
    }

    /// Decoding any 9-byte buffer never panics (returns Ok or Err, no UB).
    #[kani::proof]
    fn verify_compact_size_decode_no_panic() {
        let buf: [u8; 9] = kani::any();
        let _ = read_compact_size_bytes(&buf);
    }
}
