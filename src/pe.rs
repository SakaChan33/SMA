use crate::binary::{clamped_slice, find_overlay, Binary, Format, PeMeta, Section};
use crate::entropy::shannon_entropy;
use crate::error::ParseError;
use crate::exports::{parse_exports, parse_tls_callbacks};
use crate::imports::parse_imports;
use crate::reader::ByteReader;

const DOS_MAGIC: u16 = 0x5A4D;
const E_LFANEW_OFFSET: usize = 0x3C;
const PE_SIGNATURE: u32 = 0x00004550;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_ENTRY_SIZE: usize = 40;
const OPT_MAGIC_PE32: u16 = 0x10b;
const OPT_MAGIC_PE32_PLUS: u16 = 0x20b;

const MEM_EXECUTE: u32 = 0x2000_0000;
const MEM_READ: u32 = 0x4000_0000;
const MEM_WRITE: u32 = 0x8000_0000;

// Data directory indices (each entry is an RVA + a size).
const DATA_DIR_ENTRY_SIZE: usize = 8;
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_CERTIFICATE: usize = 4;
const DIR_DEBUG: usize = 6;
const DIR_TLS: usize = 9;
const DIR_CLR: usize = 14;

// IMAGE_DEBUG_DIRECTORY: 28 bytes, with Type at +12.
const DEBUG_ENTRY_SIZE: usize = 28;
const IMAGE_DEBUG_TYPE_REPRO: u32 = 16;

pub fn parse(data: &[u8]) -> Result<Binary, ParseError> {
    let reader = ByteReader::new(data);

    if reader.u16_le(0)? != DOS_MAGIC {
        return Err(ParseError::BadDosMagic);
    }
    let e_lfanew = reader.u32_le(E_LFANEW_OFFSET)? as usize;

    if reader.u32_le(e_lfanew)? != PE_SIGNATURE {
        return Err(ParseError::BadPeSignature);
    }

    let coff = e_lfanew + 4;
    let machine = reader.u16_le(coff)?;
    let number_of_sections = reader.u16_le(coff + 2)?;
    let size_of_optional_header = reader.u16_le(coff + 16)? as usize;
    let characteristics = reader.u16_le(coff + 18)?;

    let opt = coff + COFF_HEADER_SIZE;
    let magic = reader.u16_le(opt)?;
    let is_pe32_plus = match magic {
        OPT_MAGIC_PE32 => false,
        OPT_MAGIC_PE32_PLUS => true,
        other => return Err(ParseError::UnknownOptionalMagic(other)),
    };
    let entry_point = reader.u32_le(opt + 16)? as u64;
    let image_base = if is_pe32_plus {
        reader.u64_le(opt + 24)?
    } else {
        reader.u32_le(opt + 28)? as u64
    };

    let section_table = opt + size_of_optional_header;
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for i in 0..number_of_sections as usize {
        let base = section_table + i * SECTION_ENTRY_SIZE;
        let name = section_name(reader.bytes(base, 8)?);
        let virtual_size = reader.u32_le(base + 8)? as u64;
        let virtual_addr = reader.u32_le(base + 12)? as u64;
        let file_size = reader.u32_le(base + 16)? as u64;
        let file_offset = reader.u32_le(base + 20)? as u64;
        let ch = reader.u32_le(base + 36)?;

        let entropy = shannon_entropy(clamped_slice(data, file_offset, file_size));

        sections.push(Section {
            name,
            virtual_addr,
            virtual_size,
            file_offset,
            file_size,
            readable: ch & MEM_READ != 0,
            writable: ch & MEM_WRITE != 0,
            executable: ch & MEM_EXECUTE != 0,
            entropy,
        });
    }

    // Data directories describe the optional structures: imports, exports, TLS,
    // resources, the certificate, the CLR header. `NumberOfRvaAndSizes` bounds
    // the array -- reading past it would decode section-table bytes as a
    // directory entry and invent structures that aren't there.
    let (dir_count_off, data_directories) =
        if is_pe32_plus { (opt + 108, opt + 112) } else { (opt + 92, opt + 96) };
    let dir_count = reader.u32_le(dir_count_off).unwrap_or(0) as usize;
    let dir = |index: usize| -> (u32, u32) {
        if index >= dir_count {
            return (0, 0);
        }
        let at = data_directories + index * DATA_DIR_ENTRY_SIZE;
        (reader.u32_le(at).unwrap_or(0), reader.u32_le(at + 4).unwrap_or(0))
    };

    let (export_rva, export_size) = dir(DIR_EXPORT);
    let (import_rva, _) = dir(DIR_IMPORT);
    let (resource_rva, _) = dir(DIR_RESOURCE);
    let (certificate_rva, certificate_size) = dir(DIR_CERTIFICATE);
    let (debug_rva, debug_size) = dir(DIR_DEBUG);
    let (tls_rva, _) = dir(DIR_TLS);
    let (clr_rva, _) = dir(DIR_CLR);

    let imports = parse_imports(data, &sections, is_pe32_plus, import_rva);
    let exports = parse_exports(data, &sections, export_rva, export_size);
    let tls_callbacks = parse_tls_callbacks(data, &sections, is_pe32_plus, tls_rva, image_base);

    let pe_meta = PeMeta {
        timestamp: reader.u32_le(coff + 4).unwrap_or(0),
        reproducible_build: has_repro_marker(&reader, &sections, debug_rva, debug_size),
        subsystem: subsystem_name(reader.u16_le(opt + 68).unwrap_or(0)),
        dll_characteristics: dll_characteristics_attrs(reader.u16_le(opt + 70).unwrap_or(0)),
        is_dotnet: clr_rva != 0,
        // The certificate directory is the one entry whose "RVA" is really a
        // file offset, since a signature lives outside the loaded image. We only
        // record presence: verifying a chain is a different project, and a valid
        // signature says nothing about intent anyway (signing keys get stolen).
        signed: certificate_rva != 0 && certificate_size != 0,
        has_resources: resource_rva != 0,
        tls_callbacks,
    };

    // The certificate table is the one directory whose "RVA" is a file offset.
    let signature = (certificate_rva != 0 && certificate_size != 0)
        .then_some((certificate_rva as u64, certificate_size as u64));
    let overlay = find_overlay(data, &sections, signature);
    let strings = crate::strings::scan(data, 5);

    Ok(Binary {
        format: Format::Pe,
        arch: machine_name(machine),
        bits: if is_pe32_plus { 64 } else { 32 },
        kind: if characteristics & 0x2000 != 0 { "DLL" } else { "executable" },
        attributes: characteristics_attrs(characteristics),
        entry_point,
        image_base,
        sections,
        imports,
        exports,
        overlay,
        pe_meta: Some(pe_meta),
        strings,
    })
}

// A reproducible build (link /Brepro) replaces TimeDateStamp with a hash of the
// binary's contents, so the field stops being a date entirely. It announces
// itself with a debug directory entry of type REPRO -- which is the honest way
// to detect this, rather than guessing from whether the decoded date looks odd.
// Every modern Windows system binary is built this way, so without this check
// the report confidently states a build date decades in the future.
fn has_repro_marker(reader: &ByteReader, sections: &[Section], rva: u32, size: u32) -> bool {
    if rva == 0 || size < DEBUG_ENTRY_SIZE as u32 {
        return false;
    }
    let base = match crate::imports::rva_to_offset(sections, rva) {
        Some(o) => o,
        None => return false,
    };
    let count = (size as usize / DEBUG_ENTRY_SIZE).min(64);
    (0..count).any(|i| {
        reader.u32_le(base + i * DEBUG_ENTRY_SIZE + 12).unwrap_or(0) == IMAGE_DEBUG_TYPE_REPRO
    })
}

fn subsystem_name(s: u16) -> &'static str {
    match s {
        1 => "native (driver / no subsystem)",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "unknown",
    }
}

// Exploit mitigations the linker opted into. Their *absence* on a modern binary
// is the interesting reading: a 2020s executable without ASLR or DEP was either
// built with unusual flags or had its header rewritten.
fn dll_characteristics_attrs(c: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if c & 0x0020 != 0 { v.push("HIGH_ENTROPY_VA"); }
    if c & 0x0040 != 0 { v.push("ASLR"); }
    if c & 0x0080 != 0 { v.push("FORCE_INTEGRITY"); }
    if c & 0x0100 != 0 { v.push("DEP"); }
    if c & 0x0400 != 0 { v.push("NO_SEH"); }
    if c & 0x1000 != 0 { v.push("APPCONTAINER"); }
    if c & 0x2000 != 0 { v.push("WDM_DRIVER"); }
    if c & 0x4000 != 0 { v.push("CFG"); }
    if c & 0x8000 != 0 { v.push("TERMINAL_SERVER_AWARE"); }
    v
}

fn section_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86 (I386)",
        0x8664 => "x86-64 (AMD64)",
        0xaa64 => "ARM64",
        0x01c0 | 0x01c4 => "ARM",
        _ => "unknown",
    }
}

fn characteristics_attrs(c: u16) -> Vec<String> {
    let mut v = Vec::new();
    if c & 0x0002 != 0 { v.push("EXECUTABLE_IMAGE".into()); }
    if c & 0x2000 != 0 { v.push("DLL".into()); }
    if c & 0x0020 != 0 { v.push("LARGE_ADDRESS_AWARE".into()); }
    if c & 0x0100 != 0 { v.push("32BIT_MACHINE".into()); }
    if c & 0x0001 != 0 { v.push("RELOCS_STRIPPED".into()); }
    v
}
