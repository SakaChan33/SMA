// The human-readable triage report -- what `sma scan` prints.
//
// Deliberately descriptive: it lists evidence and never synthesizes a verdict or
// a score. Deciding whether a binary is malicious is the analyst's job; this
// report's job is to be complete about what the bytes actually say, and (in the
// closing `limits` section) about what they refuse to say.

use crate::binary::{self, Binary, Format, Section};
use crate::limits;
use std::io::{self, Write};

const IOC_LIMIT: usize = 15;
const EXPORT_LIMIT: usize = 20;

pub fn write<W: Write>(w: &mut W, path: &str, file_len: usize, bin: &Binary) -> io::Result<()> {
    header(w, path, file_len, bin)?;
    metadata(w, bin)?;
    sections(w, bin)?;
    imports(w, bin)?;
    exports(w, bin)?;
    strings(w, bin)?;
    overlay(w, bin)?;
    writeln!(w)?;
    limits::write(w, &limits::assess(bin, None))?;
    Ok(())
}

// PE-specific structure: when it was built, how it wants to be loaded, what
// mitigations it opted into, and what runs before main.
fn metadata<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    let meta = match &bin.pe_meta {
        Some(m) => m,
        None => return Ok(()), // ELF: none of these fields exist
    };

    writeln!(w, "compiled       : {}", format_timestamp(meta.timestamp, meta.reproducible_build))?;
    writeln!(w, "subsystem      : {}", meta.subsystem)?;
    let mitigations = if meta.dll_characteristics.is_empty() {
        "none declared (unusual for a modern build)".to_string()
    } else {
        meta.dll_characteristics.join(", ")
    };
    writeln!(w, "mitigations    : {mitigations}")?;

    let mut notes: Vec<String> = Vec::new();
    if meta.is_dotnet {
        notes.push(".NET assembly (managed IL, not native code)".into());
    }
    // Presence only. We do not verify the chain, and a valid signature is not
    // evidence of good intent -- signing keys get stolen and abused.
    notes.push(if meta.signed {
        "embedded Authenticode signature present (not verified)".into()
    } else {
        // Absence is weak evidence: Windows system binaries are normally signed
        // by a separate catalog file, which leaves nothing embedded to find.
        "no embedded Authenticode signature (may still be catalog-signed)".into()
    });
    if meta.has_resources {
        notes.push("has resources".into());
    }
    if !meta.tls_callbacks.is_empty() {
        let addrs: Vec<String> = meta.tls_callbacks.iter().map(|a| format!("{a:#x}")).collect();
        notes.push(format!(
            "{} TLS callback(s) at {} -- these run BEFORE the entry point",
            meta.tls_callbacks.len(),
            addrs.join(", ")
        ));
    }
    for n in notes {
        writeln!(w, "                 {n}")?;
    }

    let hints = bin.packer_hints();
    if !hints.is_empty() {
        writeln!(w, "packer         : section names match {} (a naming convention, easily faked)", hints.join(" / "))?;
    }
    writeln!(w)
}

fn exports<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    if bin.exports.is_empty() {
        return Ok(());
    }
    let forwarded = bin.exports.iter().filter(|e| e.forwarder.is_some()).count();
    writeln!(
        w,
        "exports        : {} function(s){}",
        bin.exports.len(),
        if forwarded > 0 { format!(", {forwarded} forwarded to another library") } else { String::new() }
    )?;
    for e in bin.exports.iter().take(EXPORT_LIMIT) {
        match &e.forwarder {
            Some(f) => writeln!(w, "  {:<32} -> {f}  (forwarder)", e.name)?,
            None => writeln!(w, "  {:<32} {:#x}", e.name, e.rva)?,
        }
    }
    if bin.exports.len() > EXPORT_LIMIT {
        writeln!(w, "  ... {} more", bin.exports.len() - EXPORT_LIMIT)?;
    }
    writeln!(w)
}

fn overlay<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    writeln!(w)?;
    match &bin.overlay {
        // "Nothing unexplained" rather than "the file ends here": a signature
        // also lives past the last section, and it is accounted for, not absent.
        None => writeln!(w, "overlay        : none (no unexplained data past the last section)"),
        Some(ov) => {
            writeln!(
                w,
                "overlay        : {} byte(s) past the last section, at file offset {:#x}",
                ov.size, ov.file_offset
            )?;
            writeln!(
                w,
                "                 entropy {:.3} ({}) -- data no header describes and the loader \
                 never maps",
                ov.entropy,
                binary::entropy_label(ov.entropy)
            )
        }
    }
}

// COFF timestamps are seconds since the Unix epoch, rendered in UTC without a
// date crate. Whether the field is a date at all is decided by the REPRO debug
// marker rather than by whether the decoded year looks plausible, so the same
// input always produces the same output.
fn format_timestamp(ts: u32, reproducible: bool) -> String {
    if reproducible {
        return format!(
            "n/a - reproducible build, so this field is a content hash ({ts:#010x}), not a date"
        );
    }
    if ts == 0 {
        return "0 (stripped, deliberately or by the toolchain)".to_string();
    }
    let (y, m, d, hh, mm, ss) = civil_from_epoch(ts as i64);
    let stamp = format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02} UTC");
    // Nothing was built before PE existed, and a far-future date is a forged or
    // hashed field that carries no REPRO marker to explain itself.
    if !(1993..=2038).contains(&y) {
        return format!("{stamp}  <- implausible, so this field is faked or is not a date");
    }
    stamp
}

// Howard Hinnant's civil_from_days, plus the time of day.
fn civil_from_epoch(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
}

fn header<W: Write>(w: &mut W, path: &str, file_len: usize, bin: &Binary) -> io::Result<()> {
    // Entry point and load base mean slightly different things per format, so
    // label them accordingly rather than implying a false equivalence.
    let (entry_label, base_label) = match bin.format {
        Format::Pe => ("(RVA)", "(image base)"),
        Format::Elf => ("(virtual address)", "(load base, approx)"),
    };

    writeln!(w, "Binary Report")?;
    writeln!(w, "file           : {path} ({file_len} bytes)")?;
    writeln!(w, "format         : {}", bin.format)?;
    writeln!(w, "arch           : {} ({}-bit)", bin.arch, bin.bits)?;
    writeln!(w, "kind           : {}", bin.kind)?;
    if !bin.attributes.is_empty() {
        writeln!(w, "attributes     : {}", bin.attributes.join(", "))?;
    }
    writeln!(w, "entry point    : {:#x} {entry_label}", bin.entry_point)?;
    writeln!(w, "load base      : {:#x} {base_label}", bin.image_base)?;
    writeln!(w, "sections       : {}", bin.sections.len())?;
    writeln!(w)
}

fn sections<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    writeln!(
        w,
        "  {:<14} {:>7}  {:>10}  {:<5} {:<17} note",
        "name", "entropy", "filesize", "flags", "reading"
    )?;
    for s in &bin.sections {
        let mut note = String::new();
        if s.is_likely_packed() {
            note.push_str("<- PACKED? (exec + high entropy)");
        } else if s.is_writable_and_executable() {
            note.push_str("<- W+X");
        }
        let name = if s.name.is_empty() { "(unnamed)" } else { &s.name };
        writeln!(
            w,
            "  {:<14} {:>7.3}  {:>10}  {:<5} {:<17} {}",
            name,
            s.entropy,
            s.file_size,
            rwx(s),
            binary::entropy_label(s.entropy),
            note
        )?;
    }
    writeln!(w)?;

    // A finding, not an error: high entropy in executable memory is a reason to
    // look closer, and plenty of benign installers look exactly like this.
    let packed = bin.packed_sections();
    if packed.is_empty() {
        writeln!(w, "packing        : no packed sections detected")?;
    } else {
        let names: Vec<&str> = packed.iter().map(|s| s.name.as_str()).collect();
        writeln!(
            w,
            "packing        : WARNING - {} section(s) look packed: {}",
            packed.len(),
            names.join(", ")
        )?;
    }
    writeln!(w)
}

// The binary's own import table, in full.
//
// No dictionary decides what appears here, because no dictionary can: System32
// alone exports on the order of a hundred thousand functions across ~3,500
// DLLs, and any hand-written list of "interesting" ones is a filter whose gaps
// are invisible to the analyst. The import table is authoritative about what
// this program declared, so it is printed entire -- every library, every
// function, nothing sampled and nothing summarised.
//
// The one thing that can make it incomplete is the program hiding its own
// imports, and that is exactly what the `limits` section reports.
fn imports<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    let total = bin.total_imported_functions();
    let lib_word = if bin.format == Format::Pe { "DLL(s)" } else { "library/symbol group(s)" };
    writeln!(w, "imports        : {} {lib_word}, {total} function(s)", bin.imports.len())?;

    if bin.imports.is_empty() {
        writeln!(w, "                 nothing imported -- see 'limits' below")?;
        return writeln!(w);
    }

    writeln!(
        w,
        "                 listed in full, in import-table order. slot addresses are where the\n\
         \x20                loader writes each function, which is what code calls through."
    )?;
    for imp in &bin.imports {
        writeln!(w)?;
        writeln!(w, "  {} ({} function(s))", imp.dll, imp.functions.len())?;
        for f in &imp.functions {
            match f.iat_rva {
                Some(slot) => writeln!(w, "      {slot:#010x}  {}", f.name)?,
                None => writeln!(w, "                  {}", f.name)?,
            }
        }
    }
    writeln!(w)
}

fn strings<W: Write>(w: &mut W, bin: &Binary) -> io::Result<()> {
    writeln!(w, "strings        : {} ascii, {} wide", bin.strings.ascii_count, bin.strings.wide_count)?;
    if bin.strings.iocs.is_empty() {
        writeln!(w, "IOCs           : none extracted")?;
    } else {
        writeln!(w, "IOCs           : {} unique (showing up to {IOC_LIMIT})", bin.strings.iocs.len())?;
        for ioc in bin.strings.iocs.iter().take(IOC_LIMIT) {
            writeln!(w, "  [{:<8}] {}", ioc.kind, ioc.value)?;
        }
    }
    Ok(())
}

// R/W/X permission string for a section.
pub fn rwx(s: &Section) -> String {
    format!(
        "{}{}{}",
        if s.is_readable() { 'R' } else { '-' },
        if s.is_writable() { 'W' } else { '-' },
        if s.is_executable() { 'X' } else { '-' },
    )
}
