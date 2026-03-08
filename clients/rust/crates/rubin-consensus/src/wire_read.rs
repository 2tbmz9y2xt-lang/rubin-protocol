use crate::error::{ErrorCode, TxError};

pub struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, off: 0 }
    }

    pub fn offset(&self) -> usize {
        self.off
    }

    fn checked_end(&self, n: usize, eof_msg: &'static str) -> Result<usize, TxError> {
        self.off
            .checked_add(n)
            .filter(|end| *end <= self.b.len())
            .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, eof_msg))
    }

    pub fn read_u8(&mut self) -> Result<u8, TxError> {
        let end = self.checked_end(1, "unexpected EOF (u8)")?;
        let v = self.b[self.off];
        self.off = end;
        Ok(v)
    }

    pub fn read_u16_le(&mut self) -> Result<u16, TxError> {
        let end = self.checked_end(2, "unexpected EOF (u16le)")?;
        let v = u16::from_le_bytes(self.b[self.off..end].try_into().unwrap());
        self.off = end;
        Ok(v)
    }

    pub fn read_u32_le(&mut self) -> Result<u32, TxError> {
        let end = self.checked_end(4, "unexpected EOF (u32le)")?;
        let v = u32::from_le_bytes(self.b[self.off..end].try_into().unwrap());
        self.off = end;
        Ok(v)
    }

    pub fn read_u64_le(&mut self) -> Result<u64, TxError> {
        let end = self.checked_end(8, "unexpected EOF (u64le)")?;
        let v = u64::from_le_bytes(self.b[self.off..end].try_into().unwrap());
        self.off = end;
        Ok(v)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        let end = self.checked_end(n, "unexpected EOF (bytes)")?;
        let v = &self.b[self.off..end];
        self.off = end;
        Ok(v)
    }
}
