use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    // Wanted `needed` bytes at `offset`, but the file only has `have` bytes.
    // Almost every truncated/malformed input ends here instead of panicking.
    TooShort { offset: usize, needed: usize, have: usize },
    // The file did not start with the "MZ" DOS magic.
    BadDosMagic,
    // e_lfanew did not point at the "PE\0\0" signature.
    BadPeSignature,
    // Optional-header magic was neither PE32 (0x10b) nor PE32+ (0x20b).
    UnknownOptionalMagic(u16),
    // The file did not start with the "\x7fELF" magic.
    BadElfMagic,
    // ELF class byte was neither 1 (32-bit) nor 2 (64-bit).
    UnsupportedElfClass(u8),
    // Big-endian ELF -- out of scope for our little-endian reader.
    UnsupportedElfEndian,
    // The leading bytes matched no format we recognize (not "MZ" or "\x7fELF").
    UnknownFormat,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { offset, needed, have } => write!(
                f,
                "buffer too short: need {needed} byte(s) at offset {offset:#x}, but file is only {have} bytes"
            ),
            ParseError::BadDosMagic => write!(f, "not a PE file: missing 'MZ' magic"),
            ParseError::BadPeSignature => write!(f, "not a PE file: missing 'PE\\0\\0' signature"),
            ParseError::UnknownOptionalMagic(m) => write!(f, "unknown optional-header magic: {m:#06x}"),
            ParseError::BadElfMagic => write!(f, "not an ELF file: missing '\\x7fELF' magic"),
            ParseError::UnsupportedElfClass(c) => write!(f, "unsupported ELF class byte: {c} (want 1=32-bit or 2=64-bit)"),
            ParseError::UnsupportedElfEndian => write!(f, "big-endian ELF is not supported"),
            ParseError::UnknownFormat => write!(f, "unrecognized file format (not PE 'MZ' or ELF '\\x7fELF')"),
        }
    }
}

impl std::error::Error for ParseError {}
