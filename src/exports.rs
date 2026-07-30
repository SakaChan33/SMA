// PE export directory and TLS callbacks.
//
// Both answer "where does execution enter this image, other than the entry
// point?" -- which is exactly what a call-target sweep cannot tell you. An
// exported function is reachable by name from outside; a TLS callback runs
// *before* the entry point, which is why anti-debug checks and unpacking stubs
// get put there.
//
// Best-effort and bounds-safe, matching `imports`: a malformed pointer stops
// that part of the walk instead of failing the parse. Hostile input is the
// normal case here.

use crate::binary::{Export, Section};
use crate::imports::{read_cstr, rva_to_offset};
use crate::reader::ByteReader;

const MAX_EXPORTS: usize = 65_536;
const MAX_TLS_CALLBACKS: usize = 4_096;

// IMAGE_EXPORT_DIRECTORY field offsets.
const ORDINAL_BASE: usize = 16;
const NUMBER_OF_FUNCTIONS: usize = 20;
const NUMBER_OF_NAMES: usize = 24;
const ADDRESS_OF_FUNCTIONS: usize = 28;
const ADDRESS_OF_NAMES: usize = 32;
const ADDRESS_OF_NAME_ORDINALS: usize = 36;

pub fn parse_exports(
    data: &[u8],
    sections: &[Section],
    export_dir_rva: u32,
    export_dir_size: u32,
) -> Vec<Export> {
    let mut exports = Vec::new();
    if export_dir_rva == 0 {
        return exports;
    }
    let r = ByteReader::new(data);
    let dir = match rva_to_offset(sections, export_dir_rva) {
        Some(o) => o,
        None => return exports,
    };

    let ordinal_base = r.u32_le(dir + ORDINAL_BASE).unwrap_or(0);
    let n_funcs = r.u32_le(dir + NUMBER_OF_FUNCTIONS).unwrap_or(0) as usize;
    let n_names = r.u32_le(dir + NUMBER_OF_NAMES).unwrap_or(0) as usize;
    let funcs_rva = r.u32_le(dir + ADDRESS_OF_FUNCTIONS).unwrap_or(0);
    let names_rva = r.u32_le(dir + ADDRESS_OF_NAMES).unwrap_or(0);
    let ords_rva = r.u32_le(dir + ADDRESS_OF_NAME_ORDINALS).unwrap_or(0);

    let funcs_off = match rva_to_offset(sections, funcs_rva) {
        Some(o) => o,
        None => return exports,
    };

    // An export whose code RVA points back inside the export directory is not
    // code at all -- it is a forwarder string like "NTDLL.RtlAllocateHeap",
    // meaning calls get handed to another DLL. Proxy DLLs are built out of these.
    let dir_start = export_dir_rva as u64;
    let dir_end = dir_start + export_dir_size as u64;

    // Ordinal -> name, built from the parallel name/ordinal arrays. Exports
    // without a name entry are ordinal-only, which is legitimate but also a way
    // to make an export table less readable.
    let mut names_by_index: std::collections::BTreeMap<u16, String> = std::collections::BTreeMap::new();
    if let (Some(names_off), Some(ords_off)) =
        (rva_to_offset(sections, names_rva), rva_to_offset(sections, ords_rva))
    {
        for i in 0..n_names.min(MAX_EXPORTS) {
            let name_rva = match r.u32_le(names_off + i * 4) {
                Ok(v) => v,
                Err(_) => break,
            };
            let idx = match r.u16_le(ords_off + i * 2) {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Some(off) = rva_to_offset(sections, name_rva) {
                let name = read_cstr(data, off);
                if !name.is_empty() {
                    names_by_index.insert(idx, name);
                }
            }
        }
    }

    for i in 0..n_funcs.min(MAX_EXPORTS) {
        let rva = match r.u32_le(funcs_off + i * 4) {
            Ok(v) => v as u64,
            Err(_) => break,
        };
        if rva == 0 {
            continue; // an empty ordinal slot
        }
        let ordinal = (ordinal_base as usize + i).min(u16::MAX as usize) as u16;
        let forwarder = if rva >= dir_start && rva < dir_end {
            rva_to_offset(sections, rva as u32).map(|o| read_cstr(data, o)).filter(|s| !s.is_empty())
        } else {
            None
        };
        let name = names_by_index
            .get(&(i.min(u16::MAX as usize) as u16))
            .cloned()
            .unwrap_or_else(|| format!("#{ordinal}"));

        exports.push(Export { name, rva, ordinal, forwarder });
    }

    exports
}

// The TLS directory's callback array: function pointers run before the entry
// point, on every thread start. Stored as virtual addresses, so the image base
// comes back off to get RVAs consistent with everything else we print.
pub fn parse_tls_callbacks(
    data: &[u8],
    sections: &[Section],
    is_pe32_plus: bool,
    tls_dir_rva: u32,
    image_base: u64,
) -> Vec<u64> {
    let mut callbacks = Vec::new();
    if tls_dir_rva == 0 {
        return callbacks;
    }
    let r = ByteReader::new(data);
    let dir = match rva_to_offset(sections, tls_dir_rva) {
        Some(o) => o,
        None => return callbacks,
    };

    // AddressOfCallBacks: +24 in the 64-bit layout (four u64 fields before it),
    // +12 in the 32-bit one (three u32 fields).
    let ptr_size = if is_pe32_plus { 8usize } else { 4 };
    let field = if is_pe32_plus { 24 } else { 12 };
    let array_va = if is_pe32_plus {
        r.u64_le(dir + field).unwrap_or(0)
    } else {
        r.u32_le(dir + field).unwrap_or(0) as u64
    };
    if array_va == 0 {
        return callbacks;
    }
    let array_rva = match array_va.checked_sub(image_base) {
        Some(v) if v <= u32::MAX as u64 => v as u32,
        _ => return callbacks,
    };
    let mut off = match rva_to_offset(sections, array_rva) {
        Some(o) => o,
        None => return callbacks,
    };

    // NULL-terminated array of VAs.
    for _ in 0..MAX_TLS_CALLBACKS {
        let va = if is_pe32_plus {
            r.u64_le(off).unwrap_or(0)
        } else {
            r.u32_le(off).unwrap_or(0) as u64
        };
        if va == 0 {
            break;
        }
        if let Some(rva) = va.checked_sub(image_base) {
            callbacks.push(rva);
        }
        off += ptr_size;
    }

    callbacks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::Section;

    // One section mapping RVA 0x1000.. to file offset 0.., so RVA == offset + 0x1000.
    fn one_section() -> Vec<Section> {
        vec![Section {
            name: ".rdata".into(),
            virtual_addr: 0x1000,
            virtual_size: 0x1000,
            file_offset: 0,
            file_size: 0x1000,
            readable: true,
            writable: false,
            executable: false,
            entropy: 0.0,
        }]
    }

    fn put32(buf: &mut [u8], at: usize, v: u32) {
        buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put16(buf: &mut [u8], at: usize, v: u16) {
        buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    // Export directory at RVA 0x1000 (file offset 0) with one named export.
    fn export_fixture() -> Vec<u8> {
        let mut f = vec![0u8; 0x1000];
        put32(&mut f, ORDINAL_BASE, 1); // Base = 1
        put32(&mut f, NUMBER_OF_FUNCTIONS, 1);
        put32(&mut f, NUMBER_OF_NAMES, 1);
        put32(&mut f, ADDRESS_OF_FUNCTIONS, 0x1100);
        put32(&mut f, ADDRESS_OF_NAMES, 0x1200);
        put32(&mut f, ADDRESS_OF_NAME_ORDINALS, 0x1300);

        put32(&mut f, 0x100, 0x2500); // function[0] RVA -> real code
        put32(&mut f, 0x200, 0x1400); // name[0] RVA -> the string
        put16(&mut f, 0x300, 0); // nameOrdinal[0] -> function index 0
        f[0x400..0x407].copy_from_slice(b"Install");
        f
    }

    #[test]
    fn parses_a_named_export() {
        let f = export_fixture();
        let ex = parse_exports(&f, &one_section(), 0x1000, 0x400);
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0].name, "Install");
        assert_eq!(ex[0].rva, 0x2500);
        assert_eq!(ex[0].ordinal, 1);
        assert!(ex[0].forwarder.is_none());
    }

    #[test]
    fn an_rva_inside_the_directory_is_a_forwarder_not_code() {
        let mut f = export_fixture();
        // Point function[0] at a string inside the directory's own range.
        put32(&mut f, 0x100, 0x1500);
        f[0x500..0x519].copy_from_slice(b"NTDLL.RtlAllocateHeap\0\0\0\0"[..0x19].as_ref());

        let ex = parse_exports(&f, &one_section(), 0x1000, 0x600);
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0].forwarder.as_deref(), Some("NTDLL.RtlAllocateHeap"));
    }

    #[test]
    fn an_absent_export_directory_yields_nothing() {
        assert!(parse_exports(&[0u8; 64], &one_section(), 0, 0).is_empty());
    }

    #[test]
    fn empty_ordinal_slots_are_skipped() {
        let mut f = export_fixture();
        put32(&mut f, NUMBER_OF_FUNCTIONS, 3);
        // function[1] and function[2] stay zero => unused ordinals.
        let ex = parse_exports(&f, &one_section(), 0x1000, 0x400);
        assert_eq!(ex.len(), 1, "only the populated slot is an export");
    }

    #[test]
    fn tls_callbacks_are_read_as_rvas() {
        // TLS directory at RVA 0x1000 (offset 0). AddressOfCallBacks at +24 for
        // PE32+, pointing at VA 0x140001100 => RVA 0x1100 => file offset 0x100.
        let base = 0x140000000u64;
        let mut f = vec![0u8; 0x1000];
        f[24..32].copy_from_slice(&(base + 0x1100).to_le_bytes());
        f[0x100..0x108].copy_from_slice(&(base + 0x2000).to_le_bytes());
        f[0x108..0x110].copy_from_slice(&(base + 0x3000).to_le_bytes());
        // f[0x110..] stays zero => end of the array.

        let cbs = parse_tls_callbacks(&f, &one_section(), true, 0x1000, base);
        assert_eq!(cbs, vec![0x2000, 0x3000]);
    }

    #[test]
    fn an_absent_tls_directory_yields_nothing() {
        assert!(parse_tls_callbacks(&[0u8; 64], &one_section(), true, 0, 0).is_empty());
    }
}
