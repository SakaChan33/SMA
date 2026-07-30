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
pub struct ImportedFn {
    pub name: String,
    // Where the loader writes this function's real address: the import address
    // table slot. Code calls the API *through* this slot, so it is the link
    // between "this binary imports VirtualAlloc" and "the function at 0x24c0
    // calls VirtualAlloc". None when we can't place it (ELF dynamic symbols --
    // that would need relocation parsing we don't do).
    pub iat_rva: Option<u64>,
    // Imported by number rather than by name; `name` is then "#42".
    pub ordinal: Option<u16>,
}

impl ImportedFn {
    // A function known by name only, with no tracked slot.
    pub fn named(name: impl Into<String>) -> Self {
        Self { name: name.into(), iat_rva: None, ordinal: None }
    }
}

#[derive(Debug, Clone)]
pub struct Import {
    pub dll: String,
    pub functions: Vec<ImportedFn>,
}

impl Import {
    // Just the function names. Callers that only match or display names go
    // through this, so the richer per-function record stays behind one API.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.functions.iter().map(|f| f.name.as_str())
    }
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

// A function this binary offers to others. Both formats have these, so it lives
// on the neutral model.
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub rva: u64,
    pub ordinal: u16,
    // A forwarded export doesn't point at code here -- it names a function in
    // another DLL ("NTDLL.RtlAllocateHeap"). Malware uses this to proxy a real
    // library while intercepting a few functions.
    pub forwarder: Option<String>,
}

// Bytes past the end of the last section: not described by any header, not
// loaded into memory, and a favourite hiding place for a second-stage payload
// or an installer's archive. Any format can have one.
#[derive(Debug, Clone)]
pub struct Overlay {
    pub file_offset: u64,
    pub size: u64,
    pub entropy: f64,
}

// PE-only metadata. Deliberately an Option on `Binary` rather than nullable
// fields on the neutral model: a subsystem, an Authenticode signature and TLS
// callbacks are PE concepts, and pretending ELF has them would weaken the
// format abstraction rather than serve it.
#[derive(Debug, Clone, Default)]
pub struct PeMeta {
    // COFF TimeDateStamp. 0 means stripped.
    pub timestamp: u32,
    // Built with /Brepro, so `timestamp` is a content hash rather than a date
    // and must not be read as one.
    pub reproducible_build: bool,
    pub subsystem: &'static str,
    // Mitigations opted into at link time: ASLR, DEP, CFG, ...
    pub dll_characteristics: Vec<&'static str>,
    // A .NET assembly: the native code here is a thin loader stub and the real
    // logic is managed IL, so native disassembly is the wrong lens entirely.
    pub is_dotnet: bool,
    // An Authenticode certificate is present. Presence only -- we do not verify
    // the chain, and a signature proves nothing about intent.
    pub signed: bool,
    pub has_resources: bool,
    // Code that runs before the entry point.
    pub tls_callbacks: Vec<u64>,
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
    pub exports: Vec<Export>,
    pub overlay: Option<Overlay>,
    pub pe_meta: Option<PeMeta>,
    pub strings: StringScan,
}

impl Binary {
    pub fn packed_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.is_likely_packed()).collect()
    }

    pub fn total_imported_functions(&self) -> usize {
        self.imports.iter().map(|i| i.functions.len()).sum()
    }

    // The section containing a virtual address (PE: RVA; ELF: vaddr), by the
    // address's place in the *loaded* image.
    pub fn section_at(&self, va: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            let size = s.virtual_size.max(s.file_size);
            size > 0 && va >= s.virtual_addr && va < s.virtual_addr + size
        })
    }

    // Map a virtual address to a file offset. Returns None when the address is
    // in no section, or lands in the part of a section that has no bytes on disk
    // (.bss, or a virtual size larger than the raw size -- which is exactly what
    // a packer's unpack buffer looks like).
    pub fn va_to_file_offset(&self, va: u64) -> Option<usize> {
        let s = self.section_at(va)?;
        let delta = va - s.virtual_addr;
        if delta >= s.file_size {
            return None;
        }
        Some((s.file_offset + delta) as usize)
    }

    // Code that runs before the entry point. Empty for formats that have no
    // such concept.
    pub fn tls_callbacks(&self) -> &[u64] {
        self.pe_meta.as_ref().map(|m| m.tls_callbacks.as_slice()).unwrap_or(&[])
    }

    pub fn is_dotnet(&self) -> bool {
        self.pe_meta.as_ref().is_some_and(|m| m.is_dotnet)
    }

    // Packers this file's section names suggest. A name convention only -- see
    // `packers` for why that is both useful and trivially defeated.
    pub fn packer_hints(&self) -> Vec<&'static str> {
        crate::packers::identify(&self.sections)
    }
}

// Bytes past the end of every section. Computed rather than parsed: the last
// section's raw end is where the described file stops, and anything after it is
// undescribed.
//
// `signature` is the PE certificate table's (file offset, size), which must be
// excluded. An Authenticode signature is also stored past the last section and
// is also high-entropy, so counting it as an overlay would report an
// "encrypted appended payload" on every signed binary on the system -- a false
// positive severe enough to discredit the finding when it is real.
pub fn find_overlay(
    file: &[u8],
    sections: &[Section],
    signature: Option<(u64, u64)>,
) -> Option<Overlay> {
    let described_end = sections
        .iter()
        .filter(|s| s.file_size > 0)
        .map(|s| s.file_offset.saturating_add(s.file_size))
        .max()
        .unwrap_or(0);

    let start = described_end as usize;
    if start == 0 || start >= file.len() {
        return None;
    }

    // The signature is appended last, so it bounds the top of any real overlay.
    let mut end = file.len();
    if let Some((sig_offset, sig_size)) = signature {
        if sig_size > 0 && sig_offset as usize >= start {
            end = end.min(sig_offset as usize);
        }
    }
    if start >= end {
        return None;
    }

    let bytes = &file[start..end];
    Some(Overlay {
        file_offset: described_end,
        size: bytes.len() as u64,
        entropy: crate::entropy::shannon_entropy(bytes),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(file_offset: u64, file_size: u64) -> Section {
        Section {
            name: ".text".into(),
            virtual_addr: 0x1000,
            virtual_size: file_size,
            file_offset,
            file_size,
            readable: true,
            writable: false,
            executable: true,
            entropy: 0.0,
        }
    }

    #[test]
    fn no_overlay_when_the_file_ends_at_the_last_section() {
        let file = vec![0u8; 0x600];
        assert!(find_overlay(&file, &[sec(0x200, 0x400)], None).is_none());
    }

    #[test]
    fn appended_bytes_are_an_overlay() {
        let mut file = vec![0u8; 0x600];
        file.extend_from_slice(&[0xAA; 0x100]);
        let ov = find_overlay(&file, &[sec(0x200, 0x400)], None).expect("overlay");
        assert_eq!(ov.file_offset, 0x600);
        assert_eq!(ov.size, 0x100);
    }

    #[test]
    fn a_signature_is_not_an_overlay() {
        // The regression this guards: an Authenticode signature also lives past
        // the last section and is also high-entropy, so counting it would report
        // an "encrypted appended payload" on every signed binary in System32.
        let mut file = vec![0u8; 0x600];
        file.extend_from_slice(&[0xAA; 0x100]); // the certificate table
        assert!(find_overlay(&file, &[sec(0x200, 0x400)], Some((0x600, 0x100))).is_none());
    }

    #[test]
    fn data_before_a_signature_is_still_an_overlay() {
        let mut file = vec![0u8; 0x600];
        file.extend_from_slice(&[0xBB; 0x80]); // real appended data
        file.extend_from_slice(&[0xAA; 0x100]); // then the signature
        let ov = find_overlay(&file, &[sec(0x200, 0x400)], Some((0x680, 0x100))).expect("overlay");
        assert_eq!(ov.file_offset, 0x600);
        assert_eq!(ov.size, 0x80, "the signature must not be counted");
    }

    #[test]
    fn va_maps_to_a_file_offset_only_where_bytes_exist() {
        let mut s = sec(0x200, 0x400);
        s.virtual_size = 0x1000; // larger in memory than on disk
        let bin = Binary {
            format: Format::Pe,
            arch: "x86-64 (AMD64)",
            bits: 64,
            kind: "executable",
            attributes: vec![],
            entry_point: 0x1000,
            image_base: 0,
            sections: vec![s],
            imports: vec![],
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        };
        assert_eq!(bin.va_to_file_offset(0x1000), Some(0x200));
        assert_eq!(bin.va_to_file_offset(0x1100), Some(0x300));
        // Inside the section virtually, but past its bytes on disk: a packer's
        // unpack buffer looks exactly like this.
        assert_eq!(bin.va_to_file_offset(0x1500), None);
        assert_eq!(bin.va_to_file_offset(0x9999), None);
    }
}
