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

    pub fn read_u8(&mut self) -> Result<u8, TxError> {
        if self.off + 1 > self.b.len() {
            return Err(TxError::new(ErrorCode::TxErrParse, "unexpected EOF (u8)"));
        }
        let v = self.b[self.off];
        self.off += 1;
        Ok(v)
    }

    pub fn read_u16_le(&mut self) -> Result<u16, TxError> {
        if self.off + 2 > self.b.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "unexpected EOF (u16le)",
            ));
        }
        let v = u16::from_le_bytes(self.b[self.off..self.off + 2].try_into().unwrap());
        self.off += 2;
        Ok(v)
    }

    pub fn read_u32_le(&mut self) -> Result<u32, TxError> {
        if self.off + 4 > self.b.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "unexpected EOF (u32le)",
            ));
        }
        let v = u32::from_le_bytes(self.b[self.off..self.off + 4].try_into().unwrap());
        self.off += 4;
        Ok(v)
    }

    pub fn read_u64_le(&mut self) -> Result<u64, TxError> {
        if self.off + 8 > self.b.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "unexpected EOF (u64le)",
            ));
        }
        let v = u64::from_le_bytes(self.b[self.off..self.off + 8].try_into().unwrap());
        self.off += 8;
        Ok(v)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], TxError> {
        if self.off + n > self.b.len() {
            return Err(TxError::new(
                ErrorCode::TxErrParse,
                "unexpected EOF (bytes)",
            ));
        }
        let v = &self.b[self.off..self.off + n];
        self.off += n;
        Ok(v)
    }
}
