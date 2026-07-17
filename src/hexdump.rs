use std::io::{self, Write};

const BYTES_PER_LINE: usize = 16;
const HEX: [u8; 16] = *b"0123456789abcdef";

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
}
