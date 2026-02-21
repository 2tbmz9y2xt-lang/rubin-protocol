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
