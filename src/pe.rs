use crate::binary::{clamped_slice, Binary, Format, Section};
use crate::entropy::shannon_entropy;
use crate::error::ParseError;
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

    let data_directories = if is_pe32_plus { opt + 112 } else { opt + 96 };
    let import_dir_rva = reader.u32_le(data_directories + 8).unwrap_or(0);
    let imports = parse_imports(data, &sections, is_pe32_plus, import_dir_rva);

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
        strings,
    })
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
