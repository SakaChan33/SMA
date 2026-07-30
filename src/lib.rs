pub mod binary;
pub mod cfg;
pub mod cli;
pub mod elf;
pub mod entropy;
pub mod error;
pub mod exports;
pub mod functions;
pub mod hexdump;
pub mod imports;
pub mod json;
pub mod limits;
pub mod packers;
pub mod pe;
pub mod reader;
pub mod report;
pub mod rules;
pub mod strings;
pub mod symbols;

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
