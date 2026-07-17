use crate::binary::{Import, Section};
use crate::reader::ByteReader;

pub fn rva_to_offset(sections: &[Section], rva: u32) -> Option<usize> {
    let rva = rva as u64;
    for s in sections {
        let start = s.virtual_addr;
        let size = s.virtual_size.max(s.file_size);
        if rva >= start && rva < start + size {
            return Some((s.file_offset + (rva - start)) as usize);
        }
    }
    None
}

// Read a NUL-terminated ASCII string at a file offset, bounds-checked and capped
// so a missing terminator can't run away. Shared with the ELF parser.
pub(crate) fn read_cstr(data: &[u8], offset: usize) -> String {
    let limit = offset.saturating_add(256).min(data.len());
    let mut end = offset.min(data.len());
    while end < limit && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(data.get(offset..end).unwrap_or(&[])).into_owned()
}

const DESCRIPTOR_SIZE: usize = 20;
const ORDINAL_FLAG_32: u64 = 0x8000_0000; // bit 31 set => imported by number, not name
const ORDINAL_FLAG_64: u64 = 0x8000_0000_0000_0000; // bit 63 for PE32+

// Parse the whole import table. Best-effort and bounds-safe: any malformed
// pointer just stops that part of the walk instead of failing the whole parse.
pub fn parse_imports(
    data: &[u8],
    sections: &[Section],
    is_pe32_plus: bool,
    import_dir_rva: u32,
) -> Vec<Import> {
    let mut imports = Vec::new();
    if import_dir_rva == 0 {
        return imports; // no import directory (e.g. a statically-linked binary)
    }
    let reader = ByteReader::new(data);
    let table = match rva_to_offset(sections, import_dir_rva) {
        Some(o) => o,
        None => return imports,
    };

    // Walk descriptors until an all-zero one. The cap guards a malformed table.
    for i in 0..1024 {
        let d = table + i * DESCRIPTOR_SIZE;
        let original_first_thunk = reader.u32_le(d).unwrap_or(0);
        let name_rva = reader.u32_le(d + 12).unwrap_or(0);
        let first_thunk = reader.u32_le(d + 16).unwrap_or(0);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break; // end-of-table marker
        }

        // A valid descriptor's Name always resolves to a string inside a section.
        // If it doesn't, we've walked off the real table into garbage -- stop
        // rather than emit junk imports.
        let dll = match rva_to_offset(sections, name_rva) {
            Some(o) => read_cstr(data, o),
            None => break,
        };

        // The thunk array lists the functions. Prefer the Import Name Table
        // (OriginalFirstThunk); fall back to the IAT (FirstThunk) if it's 0.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let functions = read_thunks(data, sections, is_pe32_plus, thunk_rva);

        imports.push(Import { dll, functions });
    }

    imports
}

// Walk one DLL's thunk array, collecting function names (or "#ordinal").
fn read_thunks(data: &[u8], sections: &[Section], is_pe32_plus: bool, thunk_rva: u32) -> Vec<String> {
    let mut functions = Vec::new();
    let reader = ByteReader::new(data);
    let mut off = match rva_to_offset(sections, thunk_rva) {
        Some(o) => o,
        None => return functions,
    };

    for _ in 0..8192 {
        // Each entry is 8 bytes on PE32+, 4 on PE32; a zero entry ends the list.
        let raw = if is_pe32_plus {
            reader.u64_le(off).unwrap_or(0)
        } else {
            reader.u32_le(off).unwrap_or(0) as u64
        };
        if raw == 0 {
            break;
        }

        let ordinal_flag = if is_pe32_plus { ORDINAL_FLAG_64 } else { ORDINAL_FLAG_32 };
        if raw & ordinal_flag != 0 {
            // Imported by ordinal number instead of by name.
            functions.push(format!("#{}", raw & 0xffff));
        } else if let Some(hint_name) = rva_to_offset(sections, (raw & 0x7fff_ffff) as u32) {
            // Points at IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name string.
            functions.push(read_cstr(data, hint_name + 2));
        }

        off += if is_pe32_plus { 8 } else { 4 };
    }

    functions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::Section;

    fn sec(va: u64, vsize: u64, ptr: u64, rsize: u64) -> Section {
        Section {
            name: "s".into(),
            virtual_addr: va,
            virtual_size: vsize,
            file_offset: ptr,
            file_size: rsize,
            readable: false,
            writable: false,
            executable: false,
            entropy: 0.0,
        }
    }

    #[test]
    fn rva_maps_into_the_right_section() {
        // Section loads at RVA 0x1000, its bytes are at file offset 0x400.
        let sections = vec![sec(0x1000, 0x500, 0x400, 0x600)];
        assert_eq!(rva_to_offset(&sections, 0x1000), Some(0x400)); // start
        assert_eq!(rva_to_offset(&sections, 0x1100), Some(0x500)); // +0x100
        assert_eq!(rva_to_offset(&sections, 0x9999), None); // outside every section
    }

    #[test]
    fn read_cstr_stops_at_nul() {
        let data = b"kernel32.dll\0garbage";
        assert_eq!(read_cstr(data, 0), "kernel32.dll");
    }
}
