use crate::binary::{Import, ImportedFn, Section};
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

        // Two parallel arrays describe the same functions. The Import Name Table
        // (OriginalFirstThunk) keeps the names; the Import Address Table
        // (FirstThunk) is what the loader overwrites with real addresses, and so
        // is what compiled code actually calls through. Read names from the INT
        // when it exists, but always compute slot addresses from the IAT --
        // getting this backwards is why a call target can't be named.
        let name_thunk = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        let functions = read_thunks(data, sections, is_pe32_plus, name_thunk, first_thunk);

        imports.push(Import { dll, functions });
    }

    imports
}

// Walk one DLL's thunk array, collecting each function's name (or "#ordinal")
// together with the IAT slot the loader will fill in for it.
fn read_thunks(
    data: &[u8],
    sections: &[Section],
    is_pe32_plus: bool,
    name_thunk_rva: u32,
    iat_rva: u32,
) -> Vec<ImportedFn> {
    let mut functions = Vec::new();
    let reader = ByteReader::new(data);
    let entry_size = if is_pe32_plus { 8usize } else { 4 };
    let mut off = match rva_to_offset(sections, name_thunk_rva) {
        Some(o) => o,
        None => return functions,
    };

    // `i` must advance for every entry, including ones whose name we fail to
    // resolve: the slot address is positional, so skipping an index would
    // silently misalign every later function with the wrong slot.
    for i in 0..8192usize {
        // Each entry is 8 bytes on PE32+, 4 on PE32; a zero entry ends the list.
        let raw = if is_pe32_plus {
            reader.u64_le(off).unwrap_or(0)
        } else {
            reader.u32_le(off).unwrap_or(0) as u64
        };
        if raw == 0 {
            break;
        }

        // An all-zero FirstThunk means we have no IAT to point at.
        let slot = if iat_rva != 0 {
            Some(iat_rva as u64 + (i * entry_size) as u64)
        } else {
            None
        };

        let ordinal_flag = if is_pe32_plus { ORDINAL_FLAG_64 } else { ORDINAL_FLAG_32 };
        if raw & ordinal_flag != 0 {
            // Imported by ordinal number instead of by name.
            let n = (raw & 0xffff) as u16;
            functions.push(ImportedFn { name: format!("#{n}"), iat_rva: slot, ordinal: Some(n) });
        } else if let Some(hint_name) = rva_to_offset(sections, (raw & 0x7fff_ffff) as u32) {
            // Points at IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name string.
            let name = read_cstr(data, hint_name + 2);
            functions.push(ImportedFn { name, iat_rva: slot, ordinal: None });
        }

        off += entry_size;
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

    // One section mapping RVA 0x1000.. onto file offset 0.., so RVA = offset + 0x1000.
    fn flat_section() -> Vec<Section> {
        vec![sec(0x1000, 0x1000, 0, 0x1000)]
    }

    fn put32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    // An import directory with one DLL and two named functions. Names come from
    // the INT at `int_rva`; the IAT is at `iat_rva`.
    fn import_fixture(is_pe32_plus: bool, int_rva: u32, iat_rva: u32) -> Vec<u8> {
        let mut f = vec![0u8; 0x1000];
        // Descriptor at RVA 0x1000 (offset 0), then a zero terminator.
        put32(&mut f, 0, int_rva); // OriginalFirstThunk
        put32(&mut f, 12, 0x1900); // Name -> offset 0x900
        put32(&mut f, 16, iat_rva); // FirstThunk
        f[0x900..0x90c].copy_from_slice(b"KERNEL32.dll");

        // Thunks in the name table point at IMAGE_IMPORT_BY_NAME entries.
        let names = [(0x1700u32, "VirtualAlloc"), (0x1720u32, "ExitProcess")];
        let int_off = (int_rva - 0x1000) as usize;
        for (i, (rva, name)) in names.iter().enumerate() {
            let hint = (*rva - 0x1000) as usize;
            f[hint + 2..hint + 2 + name.len()].copy_from_slice(name.as_bytes());
            if is_pe32_plus {
                put64(&mut f, int_off + i * 8, *rva as u64);
            } else {
                put32(&mut f, int_off + i * 4, *rva);
            }
        }
        f
    }

    #[test]
    fn iat_slots_come_from_first_thunk_not_the_name_table() {
        // The regression this guards: reading slot addresses from whichever
        // array supplied the names. Names live in the INT (0x1400), but code
        // calls through the IAT (0x1500), so every slot must be based at 0x1500.
        let f = import_fixture(true, 0x1400, 0x1500);
        let imports = parse_imports(&f, &flat_section(), true, 0x1000);

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "KERNEL32.dll");
        let fns = &imports[0].functions;
        assert_eq!(fns.len(), 2);
        assert_eq!(fns[0].name, "VirtualAlloc");
        assert_eq!(fns[0].iat_rva, Some(0x1500));
        assert_eq!(fns[1].name, "ExitProcess");
        assert_eq!(fns[1].iat_rva, Some(0x1508)); // +8: PE32+ entries are 8 bytes
    }

    #[test]
    fn pe32_slots_advance_by_four() {
        let f = import_fixture(false, 0x1400, 0x1500);
        let imports = parse_imports(&f, &flat_section(), false, 0x1000);
        let fns = &imports[0].functions;
        assert_eq!(fns[0].iat_rva, Some(0x1500));
        assert_eq!(fns[1].iat_rva, Some(0x1504));
    }

    #[test]
    fn names_fall_back_to_the_iat_when_there_is_no_name_table() {
        // OriginalFirstThunk == 0: names must be read from the IAT, and the
        // slots still start at FirstThunk.
        let f = import_fixture(true, 0x1500, 0x1500);
        let mut g = f.clone();
        put32(&mut g, 0, 0); // OriginalFirstThunk = 0
        let imports = parse_imports(&g, &flat_section(), true, 0x1000);
        let fns = &imports[0].functions;
        assert_eq!(fns[0].name, "VirtualAlloc");
        assert_eq!(fns[0].iat_rva, Some(0x1500));
    }

    #[test]
    fn ordinal_imports_keep_their_slot_and_number() {
        let mut f = import_fixture(true, 0x1400, 0x1500);
        put64(&mut f, 0x400, ORDINAL_FLAG_64 | 42); // first INT entry -> ordinal 42
        let imports = parse_imports(&f, &flat_section(), true, 0x1000);
        let first = &imports[0].functions[0];
        assert_eq!(first.name, "#42");
        assert_eq!(first.ordinal, Some(42));
        assert_eq!(first.iat_rva, Some(0x1500));
    }
}
