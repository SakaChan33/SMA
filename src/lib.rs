pub mod binary;
pub mod cfg;
pub mod elf;
pub mod entropy;
pub mod error;
pub mod hexdump;
pub mod imports;
pub mod json;
pub mod pe;
pub mod reader;
pub mod rules;
pub mod strings;

use binary::Binary;
use error::ParseError;

pub fn parse(data: &[u8]) -> Result<Binary, ParseError> {
    if data.starts_with(b"MZ") {
        pe::parse(data)
    } else if data.starts_with(&elf::ELF_MAGIC) {
        elf::parse(data)
    } else {
        Err(ParseError::UnknownFormat)
    }
}
