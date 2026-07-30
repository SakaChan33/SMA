use crate::binary::Binary;
use std::io::{self, Write};

const BYTES_PER_LINE: usize = 16;
const HEX: [u8; 16] = *b"0123456789abcdef";

// Where to start reading. Static triage wants a window -- the header region, the
// first bytes of a suspicious section, the code at an address the report just
// named -- not the whole file. (This tool used to dump every byte of every
// section; a 223 MB binary became ~1 GB of text that nobody read.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexWindow {
    // A virtual address: PE RVA, ELF vaddr. The same numbers every other view prints.
    At(u64),
    // The start of a named section.
    Section(String),
    // File offset 0 up to the first section's raw data.
    Headers,
}

// The header region ends where the first section's bytes begin.
pub fn header_region_end(file: &[u8], bin: &Binary) -> usize {
    bin.sections
        .iter()
        .map(|s| s.file_offset as usize)
        .filter(|&p| p > 0)
        .min()
        .unwrap_or(file.len())
        .min(file.len())
}

// Resolve a window to a (file offset, length) byte range, clamped to the file.
// Returns a human-facing explanation on failure rather than an io::Error, since
// every failure here is the user naming something that isn't there.
pub fn resolve_window(
    file: &[u8],
    bin: &Binary,
    window: &HexWindow,
    len: Option<usize>,
    default_len: usize,
) -> Result<(usize, usize), String> {
    let (start, natural_len) = match window {
        HexWindow::At(va) => {
            let off = bin.va_to_file_offset(*va).ok_or_else(|| {
                format!(
                    "no section maps address {va:#x} to bytes on disk\n\
                     (addresses are virtual: PE RVA, ELF vaddr -- the same ones scan and functions print)"
                )
            })?;
            (off, default_len)
        }
        HexWindow::Section(name) => {
            let sec = find_section(bin, name)?;
            if sec.file_size == 0 {
                return Err(format!(
                    "section '{}' has no bytes on disk (virtual size {:#x}, file size 0)",
                    sec.name, sec.virtual_size
                ));
            }
            (sec.file_offset as usize, default_len)
        }
        HexWindow::Headers => {
            let end = header_region_end(file, bin);
            (0, end)
        }
    };

    if start >= file.len() {
        return Err(format!(
            "that window starts at file offset {start:#x}, past the end of a {}-byte file",
            file.len()
        ));
    }
    let want = len.unwrap_or(natural_len);
    Ok((start, want.min(file.len() - start)))
}

// Exact name first, then case-insensitive -- PE section names are conventionally
// lowercase but packers are not (UPX0, MPRESS1).
fn find_section<'a>(bin: &'a Binary, name: &str) -> Result<&'a crate::binary::Section, String> {
    if let Some(s) = bin.sections.iter().find(|s| s.name == name) {
        return Ok(s);
    }
    if let Some(s) = bin.sections.iter().find(|s| s.name.eq_ignore_ascii_case(name)) {
        return Ok(s);
    }
    let available: Vec<&str> = bin
        .sections
        .iter()
        .map(|s| if s.name.is_empty() { "(unnamed)" } else { s.name.as_str() })
        .collect();
    Err(format!("no section named '{name}'. this file has: {}", available.join(", ")))
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

pub fn dump_to<W: Write>(out: &mut W, data: &[u8], base: usize) -> io::Result<()> {
    let mut line: Vec<u8> = Vec::with_capacity(80);

    for (row, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        line.clear();
        let addr = base + row * BYTES_PER_LINE;

        // Address column: 8 hex digits, most-significant nibble first. (File
        // offsets fit in 32 bits, so 8 digits is always enough here.)
        for shift in (0..8).rev() {
            line.push(HEX[(addr >> (shift * 4)) & 0xf]);
        }
        line.push(b' ');
        line.push(b' ');

        // Hex column. We always emit 16 slots (3 chars each) plus one gap after
        // the 8th, so the ASCII column lines up even on a short final row.
        for i in 0..BYTES_PER_LINE {
            if i == 8 {
                line.push(b' ');
            }
            match chunk.get(i) {
                Some(&b) => {
                    line.push(HEX[(b >> 4) as usize]);
                    line.push(HEX[(b & 0xf) as usize]);
                    line.push(b' ');
                }
                None => line.extend_from_slice(b"   "), // 3 spaces to match "xx "
            }
        }

        // ASCII column (only the bytes that actually exist on this row).
        line.extend_from_slice(b" |");
        for &b in chunk {
            line.push(if is_printable(b) { b } else { b'.' });
        }
        line.extend_from_slice(b"|\n");

        out.write_all(&line)?;
    }

    Ok(())
}

// Convenience wrapper that returns the dump as a String. For small buffers and
// tests; for large data prefer `dump_to` to avoid building one giant String.
pub fn dump(data: &[u8], base: usize) -> String {
    let mut buf = Vec::with_capacity(data.len().div_ceil(BYTES_PER_LINE) * 78);
    // Writing to a Vec cannot fail.
    dump_to(&mut buf, data, base).expect("in-memory write is infallible");
    String::from_utf8(buf).expect("hex dump is pure ASCII")
}

#[cfg(test)]
mod tests {
    use super::{dump, dump_to};

    #[test]
    fn formats_offset_hex_and_ascii() {
        let d = dump(b"MZ", 0);
        assert!(d.starts_with("00000000  4d 5a"), "got: {d}");
        assert!(d.contains("|MZ|"), "got: {d}");
    }

    #[test]
    fn dump_to_matches_dump() {
        // The streaming and convenience paths must produce identical output.
        let data: Vec<u8> = (0..50).collect();
        let mut streamed = Vec::new();
        dump_to(&mut streamed, &data, 0x1000).unwrap();
        assert_eq!(String::from_utf8(streamed).unwrap(), dump(&data, 0x1000));
    }

    #[test]
    fn base_offset_appears_in_address_column() {
        let d = dump(&[0x00], 0x400);
        assert!(d.starts_with("00000400  00"), "got: {d}");
    }

    #[test]
    fn non_printable_bytes_become_dots() {
        let d = dump(&[0x00, 0x41, 0xff], 0);
        assert!(d.contains("|.A.|"), "got: {d}");
    }

    #[test]
    fn wraps_every_16_bytes() {
        let data: Vec<u8> = (0..32).collect();
        let d = dump(&data, 0);
        // Two rows: addresses 0x00000000 and 0x00000010.
        assert!(d.contains("00000000  "));
        assert!(d.contains("00000010  "));
        assert_eq!(d.lines().count(), 2);
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(dump(&[], 0), "");
    }

    use super::{resolve_window, HexWindow};
    use crate::binary::{Binary, Format, Section};
    use crate::strings::StringScan;

    // Headers at 0..0x200, then .text loaded at RVA 0x1000 from file offset 0x200.
    fn fixture() -> (Vec<u8>, Binary) {
        let file = vec![0u8; 0x600];
        let bin = Binary {
            format: Format::Pe,
            arch: "x86-64 (AMD64)",
            bits: 64,
            kind: "executable",
            attributes: vec![],
            entry_point: 0x1000,
            image_base: 0,
            sections: vec![Section {
                name: ".text".into(),
                virtual_addr: 0x1000,
                virtual_size: 0x400,
                file_offset: 0x200,
                file_size: 0x400,
                readable: true,
                writable: false,
                executable: true,
                entropy: 0.0,
            }],
            imports: vec![],
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        };
        (file, bin)
    }

    #[test]
    fn an_address_window_resolves_through_the_section_table() {
        let (file, bin) = fixture();
        // RVA 0x1080 is 0x80 into .text, so file offset 0x280.
        assert_eq!(resolve_window(&file, &bin, &HexWindow::At(0x1080), None, 256).unwrap(), (0x280, 256));
    }

    #[test]
    fn a_window_is_clamped_to_the_end_of_the_file() {
        let (file, bin) = fixture();
        let (off, len) = resolve_window(&file, &bin, &HexWindow::At(0x1300), None, 0x400).unwrap();
        assert_eq!(off, 0x500);
        assert_eq!(len, 0x100, "must not read past the end of a 0x600-byte file");
    }

    #[test]
    fn the_header_window_stops_at_the_first_section() {
        let (file, bin) = fixture();
        assert_eq!(resolve_window(&file, &bin, &HexWindow::Headers, None, 256).unwrap(), (0, 0x200));
        // An explicit --len still narrows it.
        assert_eq!(resolve_window(&file, &bin, &HexWindow::Headers, Some(16), 256).unwrap(), (0, 16));
    }

    #[test]
    fn a_section_window_starts_at_its_bytes_and_matches_case_insensitively() {
        let (file, bin) = fixture();
        let by_name = resolve_window(&file, &bin, &HexWindow::Section(".text".into()), None, 64).unwrap();
        let by_case = resolve_window(&file, &bin, &HexWindow::Section(".TEXT".into()), None, 64).unwrap();
        assert_eq!(by_name, (0x200, 64));
        assert_eq!(by_case, by_name);
    }

    #[test]
    fn unknown_windows_explain_what_is_available() {
        let (file, bin) = fixture();
        let err = resolve_window(&file, &bin, &HexWindow::Section(".nope".into()), None, 64).unwrap_err();
        assert!(err.contains(".text"), "error should list real section names: {err}");

        let err = resolve_window(&file, &bin, &HexWindow::At(0x99999), None, 64).unwrap_err();
        assert!(err.contains("no section maps address"), "got: {err}");
    }
}
