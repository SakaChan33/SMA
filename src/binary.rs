use crate::strings::StringScan;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pe,
    Elf,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Pe => write!(f, "PE (Windows)"),
            Format::Elf => write!(f, "ELF (Linux/Unix)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Import {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_addr: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub entropy: f64,
}

impl Section {
    pub const HIGH_ENTROPY: f64 = 7.0;

    pub fn is_readable(&self) -> bool {
        self.readable
    }
    pub fn is_writable(&self) -> bool {
        self.writable
    }
    pub fn is_executable(&self) -> bool {
        self.executable
    }
    pub fn is_writable_and_executable(&self) -> bool {
        self.writable && self.executable
    }

    pub fn is_high_entropy(&self) -> bool {
        self.entropy >= Self::HIGH_ENTROPY
    }

    pub fn is_likely_packed(&self) -> bool {
        self.executable && self.is_high_entropy()
    }

    pub fn on_disk_bytes<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        clamped_slice(file, self.file_offset, self.file_size)
    }
}

#[derive(Debug, Clone)]
pub struct Binary {
    pub format: Format,
    pub arch: &'static str,
    pub bits: u8,
    pub kind: &'static str,
    pub attributes: Vec<String>,
    pub entry_point: u64,
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub strings: StringScan,
}

impl Binary {
    pub fn packed_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_likely_packed()).collect()
    }

    pub fn total_imported_functions(&self) -> usize {
        self.imports.iter().map(|i| i.functions.len()).sum()
    }
}

pub fn entropy_label(entropy: f64) -> &'static str {
    if entropy >= 7.5 {
        "packed/encrypted?"
    } else if entropy >= 7.0 {
        "compressed?"
    } else if entropy >= 5.0 {
        "code/data"
    } else if entropy >= 1.0 {
        "structured"
    } else {
        "uniform/empty"
    }
}

pub(crate) fn clamped_slice(data: &[u8], offset: u64, size: u64) -> &[u8] {
    let start = (offset as usize).min(data.len());
    let end = start.saturating_add(size as usize).min(data.len());
    &data[start..end]
}
