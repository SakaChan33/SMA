use crate::binary::{clamped_slice, Binary, Format, Import, Section};
use crate::entropy::shannon_entropy;
use crate::error::ParseError;
use crate::imports::read_cstr;
use crate::reader::ByteReader;

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const EI_CLASS: usize = 4; // 1 = 32-bit, 2 = 64-bit
const EI_DATA: usize = 5; // 1 = little-endian, 2 = big-endian

// Section header types.
const SHT_SYMTAB: u32 = 2;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOBITS: u32 = 8; // .bss: occupies memory but no file bytes
const SHT_DYNSYM: u32 = 11;

// Section flags.
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2; // occupies memory during execution (=> readable)
const SHF_EXECINSTR: u64 = 0x4;

// Dynamic-table tags.
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1; // value = offset into .dynstr for a needed library name

// A raw section header as read from disk (fields common to 32- and 64-bit).
struct Shdr {
    name_off: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

// Parse the ELF header, sections, dynamic imports and strings into `Binary`.
pub fn parse(data: &[u8]) -> Result<Binary, ParseError> {
    let r = ByteReader::new(data);

    // e_ident: magic, class (32/64), data (endianness).
    if r.bytes(0, 4)? != ELF_MAGIC {
        return Err(ParseError::BadElfMagic);
    }
    let class = *data.get(EI_CLASS).ok_or(ParseError::TooShort {
        offset: EI_CLASS,
        needed: 1,
        have: data.len(),
    })?;
    let is64 = match class {
        1 => false,
        2 => true,
        other => return Err(ParseError::UnsupportedElfClass(other)),
    };
    // Our ByteReader is little-endian; big-endian ELF (rare -- some MIPS/SPARC)
    // is out of scope, so fail cleanly rather than silently misread every field.
    if *data.get(EI_DATA).unwrap_or(&1) == 2 {
        return Err(ParseError::UnsupportedElfEndian);
    }

    let e_type = r.u16_le(16)?;
    let e_machine = r.u16_le(18)?;

    // Header fields whose offsets differ between the 32- and 64-bit layouts.
    let (e_entry, e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is64 {
        (
            r.u64_le(24)?,
            r.u64_le(40)? as usize,
            r.u16_le(58)? as usize,
            r.u16_le(60)? as usize,
            r.u16_le(62)? as usize,
        )
    } else {
        (
            r.u32_le(24)? as u64,
            r.u32_le(32)? as usize,
            r.u16_le(46)? as usize,
            r.u16_le(48)? as usize,
            r.u16_le(50)? as usize,
        )
    };

    // Read the section headers. A read that falls off the end just stops the walk.
    let mut shdrs: Vec<Shdr> = Vec::with_capacity(e_shnum.min(4096));
    for i in 0..e_shnum.min(65536) {
        match read_shdr(&r, e_shoff + i * e_shentsize, is64) {
            Ok(s) => shdrs.push(s),
            Err(_) => break,
        }
    }

    // The section-header string table (index e_shstrndx) names every section.
    let shstr_off = shdrs.get(e_shstrndx).map(|s| s.offset as usize).unwrap_or(0);

    let mut sections = Vec::with_capacity(shdrs.len());
    for s in &shdrs {
        let name = if shstr_off != 0 {
            read_cstr(data, shstr_off + s.name_off as usize)
        } else {
            String::new()
        };
        // .bss (SHT_NOBITS) occupies memory but has no bytes on disk.
        let file_size = if s.sh_type == SHT_NOBITS { 0 } else { s.size };
        let entropy = shannon_entropy(clamped_slice(data, s.offset, file_size));
        sections.push(Section {
            name,
            virtual_addr: s.addr,
            virtual_size: s.size,
            file_offset: s.offset,
            file_size,
            readable: s.flags & SHF_ALLOC != 0, // ELF has no read bit; ALLOC => in memory
            writable: s.flags & SHF_WRITE != 0,
            executable: s.flags & SHF_EXECINSTR != 0,
            entropy,
        });
    }

    let imports = parse_dynamic_imports(data, &shdrs, is64);

    // Human notes: object kind, dynamic-vs-static, stripped.
    let mut attributes = Vec::new();
    if e_type == 1 {
        attributes.push("relocatable object".into());
    } else if e_type == 3 {
        attributes.push("PIE / shared object".into());
    }
    let dynamic = shdrs.iter().any(|s| s.sh_type == SHT_DYNAMIC);
    attributes.push(if dynamic { "dynamically linked".into() } else { "statically linked".into() });
    if !shdrs.iter().any(|s| s.sh_type == SHT_SYMTAB) {
        attributes.push("stripped (no .symtab)".into());
    }

    // ELF has no single image-base field (0 for PIE). Approximate it with the
    // lowest nonzero load address among allocated sections.
    let image_base = sections
        .iter()
        .filter(|s| s.readable && s.virtual_addr != 0)
        .map(|s| s.virtual_addr)
        .min()
        .unwrap_or(0);

    let strings = crate::strings::scan(data, 5);

    Ok(Binary {
        format: Format::Elf,
        arch: machine_name(e_machine),
        bits: if is64 { 64 } else { 32 },
        kind: elf_kind(e_type),
        attributes,
        entry_point: e_entry,
        image_base,
        sections,
        imports,
        strings,
    })
}

fn read_shdr(r: &ByteReader, base: usize, is64: bool) -> Result<Shdr, ParseError> {
    if is64 {
        Ok(Shdr {
            name_off: r.u32_le(base)?,
            sh_type: r.u32_le(base + 4)?,
            flags: r.u64_le(base + 8)?,
            addr: r.u64_le(base + 16)?,
            offset: r.u64_le(base + 24)?,
            size: r.u64_le(base + 32)?,
            link: r.u32_le(base + 40)?,
            entsize: r.u64_le(base + 56)?,
        })
    } else {
        Ok(Shdr {
            name_off: r.u32_le(base)?,
            sh_type: r.u32_le(base + 4)?,
            flags: r.u32_le(base + 8)? as u64,
            addr: r.u32_le(base + 12)? as u64,
            offset: r.u32_le(base + 16)? as u64,
            size: r.u32_le(base + 20)? as u64,
            link: r.u32_le(base + 24)?,
            entsize: r.u32_le(base + 36)? as u64,
        })
    }
}

// Imports = needed shared libraries (DT_NEEDED) + undefined dynamic symbols.
// We resolve names through the .dynstr string table that each table's sh_link
// points at, using only file offsets (no RVA translation needed).
fn parse_dynamic_imports(data: &[u8], shdrs: &[Shdr], is64: bool) -> Vec<Import> {
    let r = ByteReader::new(data);
    let mut imports = Vec::new();

    // Needed libraries, from the .dynamic table.
    if let Some(dynamic) = shdrs.iter().find(|s| s.sh_type == SHT_DYNAMIC) {
        if let Some(strtab) = shdrs.get(dynamic.link as usize) {
            let entsize = if dynamic.entsize > 0 {
                dynamic.entsize as usize
            } else if is64 {
                16
            } else {
                8
            };
            let count = (dynamic.size as usize) / entsize.max(1);
            for i in 0..count.min(65536) {
                let base = dynamic.offset as usize + i * entsize;
                let (tag, val) = if is64 {
                    (r.u64_le(base).unwrap_or(DT_NULL), r.u64_le(base + 8).unwrap_or(0))
                } else {
                    (r.u32_le(base).unwrap_or(0) as u64, r.u32_le(base + 4).unwrap_or(0) as u64)
                };
                if tag == DT_NULL {
                    break;
                }
                if tag == DT_NEEDED {
                    let name = read_cstr(data, strtab.offset as usize + val as usize);
                    if !name.is_empty() {
                        imports.push(Import { dll: name, functions: Vec::new() });
                    }
                }
            }
        }
    }

    // Undefined dynamic symbols (st_shndx == SHN_UNDEF) are imported functions.
    if let Some(dynsym) = shdrs.iter().find(|s| s.sh_type == SHT_DYNSYM) {
        if let Some(strtab) = shdrs.get(dynsym.link as usize) {
            let symsize = if dynsym.entsize > 0 {
                dynsym.entsize as usize
            } else if is64 {
                24
            } else {
                16
            };
            let count = (dynsym.size as usize) / symsize.max(1);
            let mut funcs = Vec::new();
            for i in 0..count.min(500_000) {
                let base = dynsym.offset as usize + i * symsize;
                // st_name is first in both layouts; st_shndx sits at +6 (64-bit)
                // or +14 (32-bit).
                let name_off = r.u32_le(base).unwrap_or(0);
                let shndx = if is64 {
                    r.u16_le(base + 6).unwrap_or(0)
                } else {
                    r.u16_le(base + 14).unwrap_or(0)
                };
                if shndx == 0 && name_off != 0 {
                    let name = read_cstr(data, strtab.offset as usize + name_off as usize);
                    if !name.is_empty() {
                        funcs.push(name);
                    }
                }
            }
            if !funcs.is_empty() {
                imports.push(Import { dll: "(imported symbols)".into(), functions: funcs });
            }
        }
    }

    imports
}

fn machine_name(m: u16) -> &'static str {
    match m {
        3 => "x86 (I386)",
        40 => "ARM",
        62 => "x86-64 (AMD64)",
        183 => "ARM64 (AArch64)",
        243 => "RISC-V",
        21 => "PowerPC64",
        _ => "unknown",
    }
}

fn elf_kind(t: u16) -> &'static str {
    match t {
        1 => "relocatable object",
        2 => "executable",
        3 => "shared object / PIE",
        4 => "core dump",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal but valid 64-bit little-endian ELF: header + a section
    // string table + one ".text" section flagged alloc+exec. Enough to exercise
    // the header decode, section walk, name resolution, and R/W/X mapping.
    fn minimal_elf() -> Vec<u8> {
        let mut f = vec![0u8; 0x200];
        // e_ident
        f[0..4].copy_from_slice(&ELF_MAGIC);
        f[EI_CLASS] = 2; // 64-bit
        f[EI_DATA] = 1; // little-endian
        // e_type = ET_EXEC (2), e_machine = x86-64 (62)
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_entry = 0x401000
        f[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // e_shoff = 0x80, e_shentsize = 64, e_shnum = 3, e_shstrndx = 2
        f[40..48].copy_from_slice(&0x80u64.to_le_bytes());
        f[58..60].copy_from_slice(&64u16.to_le_bytes());
        f[60..62].copy_from_slice(&3u16.to_le_bytes());
        f[62..64].copy_from_slice(&2u16.to_le_bytes());

        // .shstrtab contents at file offset 0x180: "\0.text\0.shstrtab\0"
        let shstr = b"\0.text\0.shstrtab\0";
        f[0x180..0x180 + shstr.len()].copy_from_slice(shstr);

        let write_shdr = |f: &mut [u8], idx: usize, name_off: u32, sh_type: u32,
                          flags: u64, addr: u64, offset: u64, size: u64| {
            let b = 0x80 + idx * 64;
            f[b..b + 4].copy_from_slice(&name_off.to_le_bytes());
            f[b + 4..b + 8].copy_from_slice(&sh_type.to_le_bytes());
            f[b + 8..b + 16].copy_from_slice(&flags.to_le_bytes());
            f[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
            f[b + 24..b + 32].copy_from_slice(&offset.to_le_bytes());
            f[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
        };
        // [0] null section, [1] .text (name_off 1, PROGBITS, ALLOC|EXEC), [2] .shstrtab
        write_shdr(&mut f, 1, 1, 1, SHF_ALLOC | SHF_EXECINSTR, 0x401000, 0x100, 0x10);
        write_shdr(&mut f, 2, 7, 3, 0, 0, 0x180, shstr.len() as u64);
        f
    }

    #[test]
    fn parses_header_and_text_section() {
        let bin = parse(&minimal_elf()).unwrap();
        assert_eq!(bin.bits, 64);
        assert_eq!(bin.arch, "x86-64 (AMD64)");
        assert_eq!(bin.entry_point, 0x401000);
        let text = bin.sections.iter().find(|s| s.name == ".text").expect(".text");
        assert!(text.is_executable() && text.is_readable() && !text.is_writable());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut f = minimal_elf();
        f[1] = b'X'; // corrupt the magic
        assert!(matches!(parse(&f), Err(ParseError::BadElfMagic)));
    }
}
