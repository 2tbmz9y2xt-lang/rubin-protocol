use crate::compact_size_decode;

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a new Cursor over the given byte slice with the read position initialized to 0.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = b"abc";
    /// let cur = Cursor::new(bytes);
    /// assert_eq!(cur.remaining(), 3);
    /// ```
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Reports the number of unread bytes left in the cursor.
    ///
    /// Returns the count of bytes remaining to be read; yields `0` if the cursor is at or beyond the end of the slice.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut c = crate::wire::Cursor::new(&[1u8, 2, 3]);
    /// assert_eq!(c.remaining(), 3);
    /// let _ = c.read_exact(2).unwrap();
    /// assert_eq!(c.remaining(), 1);
    /// ```
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Reads exactly `len` bytes from the cursor and advances the read position.
    ///
    /// On success returns a slice containing the next `len` bytes and advances `self.pos` by `len`.
    /// On failure returns `Err("parse: truncated")` when fewer than `len` bytes remain.
    ///
    /// # Examples
    ///
    /// ```
    /// let data = b"\x01\x02\x03\x04";
    /// let mut cur = crate::wire::Cursor::new(data);
    /// let s = cur.read_exact(2).unwrap();
    /// assert_eq!(s, b"\x01\x02");
    /// assert_eq!(cur.remaining(), 2);
    /// ```
    pub(crate) fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.remaining() < len {
            return Err("parse: truncated".into());
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..start + len])
    }

    /// Reads a single byte from the cursor and advances the cursor position by one.
    ///
    /// Returns the byte read as a `u8`. Returns an `Err(String)` with message `"parse: truncated"` if there are no remaining bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut c = Cursor::new(&[0x12u8]);
    /// let b = c.read_u8().unwrap();
    /// assert_eq!(b, 0x12);
    /// ```
    pub(crate) fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_exact(1)?[0])
    }

    /// Reads a 16-bit unsigned integer encoded in little-endian from the cursor and advances the position by two bytes.
    ///
    /// # Returns
    ///
    /// `u16` parsed from the next two bytes, or an `Err(String)` with `"parse: truncated"` if there are fewer than two unread bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut c = Cursor::new(&[0x34, 0x12]);
    /// assert_eq!(c.read_u16le().unwrap(), 0x1234);
    /// ```
    pub(crate) fn read_u16le(&mut self) -> Result<u16, String> {
        let b = self.read_exact(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Reads the next four bytes and interprets them as a little-endian `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut cur = Cursor::new(&[0x78, 0x56, 0x34, 0x12]);
    /// let v = cur.read_u32le().unwrap();
    /// assert_eq!(v, 0x12345678);
    /// ```
    pub(crate) fn read_u32le(&mut self) -> Result<u32, String> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads an unsigned 64-bit integer from the current cursor position using little-endian byte order.
    ///
    /// # Returns
    /// The `u64` value formed from the next 8 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let bytes = [1u8, 0, 0, 0, 0, 0, 0, 0];
    /// let mut cur = Cursor::new(&bytes);
    /// assert_eq!(cur.read_u64le().unwrap(), 1u64);
    /// ```
    pub(crate) fn read_u64le(&mut self) -> Result<u64, String> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Decodes a Bitcoin-style compact size integer at the cursor and advances the cursor by the number of bytes consumed.
    ///
    /// Returns the decoded integer on success, or an error string if decoding fails (for example, due to truncation or invalid encoding).
    ///
    /// # Examples
    ///
    /// ```
    /// let mut c = Cursor::new(&[0xFD, 0x01, 0x00]); // compact-size for 1 (0xFD followed by u16 little-endian)
    /// let n = c.read_compact_size().unwrap();
    /// assert_eq!(n, 1);
    /// ```
    pub(crate) fn read_compact_size(&mut self) -> Result<u64, String> {
        let (n, consumed) = compact_size_decode(&self.bytes[self.pos..])?;
        self.pos += consumed;
        Ok(n)
    }
}
