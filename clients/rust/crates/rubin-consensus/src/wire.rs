use crate::compact_size_decode;

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.remaining() < len {
            return Err("parse: truncated".into());
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..start + len])
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_exact(1)?[0])
    }

    pub(crate) fn read_u16le(&mut self) -> Result<u16, String> {
        let b = self.read_exact(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn read_u32le(&mut self) -> Result<u32, String> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn read_u64le(&mut self) -> Result<u64, String> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub(crate) fn read_compact_size(&mut self) -> Result<u64, String> {
        let (n, consumed) = compact_size_decode(&self.bytes[self.pos..])?;
        self.pos += consumed;
        Ok(n)
    }
}
