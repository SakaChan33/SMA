use crate::error::ParseError;

pub struct ByteReader<'a> {
    data: &'a [u8],
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    // Borrow `len` bytes at `offset`, bounds-checked (checked_add guards against
    // an offset+len that overflows usize; slice::get returns None if out of range).
    pub fn bytes(&self, offset: usize, len: usize) -> Result<&'a [u8], ParseError> {
        let end = offset
            .checked_add(len)
            .ok_or(ParseError::TooShort { offset, needed: len, have: self.data.len() })?;
        self.data
            .get(offset..end)
            .ok_or(ParseError::TooShort { offset, needed: len, have: self.data.len() })
    }

    pub fn u16_le(&self, offset: usize) -> Result<u16, ParseError> {
        let b = self.bytes(offset, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32_le(&self, offset: usize) -> Result<u32, ParseError> {
        let b = self.bytes(offset, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64_le(&self, offset: usize) -> Result<u64, ParseError> {
        let b = self.bytes(offset, 8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}
