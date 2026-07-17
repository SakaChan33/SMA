// SMA - Static Malware Analysis
// Command: sma [MODE] <path-to-exe> [options]


use static_malware_analysis::binary::{self, Binary, Format, Section};
use static_malware_analysis::{cfg, hexdump, parse, rules};
use std::process::ExitCode;

// Which analysis to run. Scan is the default; the rest are planned milestones.
enum Mode {
    Scan,        // -s: static report (headers, entropy, imports, capabilities, IOCs)
    Disassemble, // -d: decode code sections into instructions        [planned: M7]
    Debug,       // -b: dynamic / debug analysis                      [planned: future]
}

fn print_help() {
    println!("sma - static malware analysis\n");
    println!("usage:");
    println!("  sma [MODE] <path-to-exe> [options]\n");
    println!("modes:");
    println!("  -s, --scan           static report: headers, entropy, imports,");
    println!("                       capabilities, strings/IOCs           (default)");
    println!("  -d, --disassemble    build a function's control-flow graph (CFG)");
    println!("  -b, --debug          dynamic / debug analysis                 [planned: future]\n");
    println!("scan options:");
    println!("  -f, --full           also print the COMPLETE hex of the headers and every");
    println!("                       section to stdout (massive for large files)");
    println!("      --dump-sections <dir>   write one file per section (specifics + FULL");
    println!("                              hex) plus a headers file into <dir>\n");
    println!("disassemble options:");
    println!("      --addr <hex>     function start address (default: the entry point)");
    println!("      --dot            emit Graphviz DOT instead of a text listing");
    println!("      --all            linear-disassemble EVERY executable section (whole");
    println!("                       program, any size) -- redirect to a file");
    println!("      --calls          list the program's call targets (RVA + call count);");
    println!("                       jump to any with --addr\n");
    println!("  -h, --help           show this help");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = Mode::Scan;
    let mut path: Option<String> = None;
    let mut dump_dir: Option<String> = None;
    let mut full = false;
    let mut addr: Option<u64> = None; // -d start address
    let mut dot = false; // -d DOT output
    let mut disasm_all = false; // -d --all: linear disassembly of every exec section
    let mut list_calls = false; // -d --calls: list the program's call targets

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "-s" | "--scan" => mode = Mode::Scan,
            "-d" | "--disassemble" => mode = Mode::Disassemble,
            "-b" | "--debug" => mode = Mode::Debug,
            "-f" | "--full" => full = true,
            "--dot" => dot = true,
            "--all" => disasm_all = true,
            "--calls" => list_calls = true,
            "--addr" => {
                i += 1;
                match args.get(i).map(|s| parse_hex(s)) {
                    Some(Some(v)) => addr = Some(v),
                    Some(None) => {
                        eprintln!("error: --addr wants a hex address like 0x1400 or 1400");
                        return ExitCode::FAILURE;
                    }
                    None => {
                        eprintln!("error: --addr needs a value");
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--dump-sections" => {
                i += 1;
                match args.get(i) {
                    Some(d) => dump_dir = Some(d.clone()),
                    None => {
                        eprintln!("error: --dump-sections needs a directory");
                        return ExitCode::FAILURE;
                    }
                }
            }
            p if !p.starts_with('-') && path.is_none() => path = Some(p.to_string()),
            other => eprintln!("warning: ignoring unrecognized argument '{other}'"),
        }
        i += 1;
    }

    let path = match path {
        Some(p) => p,
        None => {
            print_help();
            return ExitCode::FAILURE;
        }
    };

    // Debug mode isn't built yet: announce the plan honestly instead of pretending.
    // Exit code 2 = "recognized but not implemented" (distinct from parse error 1).
    if let Mode::Debug = mode {
        eprintln!("debug (-b) dynamic analysis is a planned future milestone.");
        eprintln!("this project is static-first by design; not yet implemented.");
        return ExitCode::from(2);
    }

    // Read the whole file. Every byte from here on is UNTRUSTED input.
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Sniff the format (PE vs ELF) and parse into the neutral model.
    let bin = match parse(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("parse error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match mode {
        Mode::Scan => {
            // stdout: the generalized report. With -f, also stream the complete
            // hex of the headers and every section after it.
            print_report(&path, &bytes, &bin);
            if full {
                if let Err(e) = print_full_hex(&bytes, &bin) {
                    // A broken pipe (e.g. piping into `head`) is normal, not an error.
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!("error: writing hex failed: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            if let Some(dir) = dump_dir {
                if let Err(e) = dump_sections(&path, &bytes, &bin, &dir) {
                    eprintln!("error: writing section dumps failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Mode::Disassemble => {
            let stdout = std::io::stdout();
            if list_calls {
                // --calls: list every function the program calls (RVA + count).
                let mut w = std::io::BufWriter::new(stdout.lock());
                match cfg::list_calls(&bytes, &bin, &mut w) {
                    Ok(_) => {
                        let _ = std::io::Write::flush(&mut w);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(e) => {
                        eprintln!("disassemble: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else if disasm_all {
                // --all: LINEAR disassembly of the whole program (every exec
                // section), streamed so any file size works. Redirect to a file.
                let mut w = std::io::BufWriter::new(stdout.lock());
                match cfg::disassemble_all(&bytes, &bin, &mut w) {
                    Ok(_) => {
                        let _ = std::io::Write::flush(&mut w);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(e) => {
                        eprintln!("disassemble: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                // Default: the control-flow graph of ONE function.
                let graph = match cfg::build(&bytes, &bin, addr) {
                    Ok(g) => g,
                    Err(msg) => {
                        eprintln!("disassemble: {msg}");
                        return ExitCode::FAILURE;
                    }
                };
                let mut w = stdout.lock();
                let res = if dot { graph.to_dot(&mut w) } else { graph.to_text(&mut w) };
                if let Err(e) = res {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!("disassemble: writing output failed: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
        Mode::Debug => unreachable!("handled above"),
    }
    ExitCode::SUCCESS
}

// Parse a hex address, with or without a leading "0x".
fn parse_hex(s: &str) -> Option<u64> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16).ok()
}

fn print_report(path: &str, file: &[u8], bin: &Binary) {
    // Entry point / load base mean slightly different things per format, so label
    // them accordingly (PE: RVA + exact image base; ELF: absolute vaddr + approx).
    let (entry_label, base_label) = match bin.format {
        Format::Pe => ("(RVA)", "(image base)"),
        Format::Elf => ("(virtual address)", "(load base, approx)"),
    };

    println!("Binary Report");
    println!("file           : {path} ({} bytes)", file.len());
    println!("format         : {}", bin.format);
    println!("arch           : {} ({}-bit)", bin.arch, bin.bits);
    println!("kind           : {}", bin.kind);
    if !bin.attributes.is_empty() {
        println!("attributes     : {}", bin.attributes.join(", "));
    }
    println!("entry point    : {:#x} {entry_label}", bin.entry_point);
    println!("load base      : {:#x} {base_label}", bin.image_base);
    println!("sections       : {}", bin.sections.len());
    println!();

    // M2: per-section entropy + packing assessment.
    println!("  {:<14} {:>7}  {:>10}  {:<5} {:<17} note", "name", "entropy", "filesize", "flags", "reading");
    for s in &bin.sections {
        let flags = format!(
            "{}{}{}",
            if s.is_readable() { 'R' } else { '-' },
            if s.is_writable() { 'W' } else { '-' },
            if s.is_executable() { 'X' } else { '-' },
        );
        let mut note = String::new();
        if s.is_likely_packed() {
            note.push_str("<- PACKED? (exec + high entropy)");
        } else if s.is_writable_and_executable() {
            note.push_str("<- W+X");
        }
        let name = if s.name.is_empty() { "(unnamed)" } else { &s.name };
        println!(
            "  {:<14} {:>7.3}  {:>10}  {:<5} {:<17} {}",
            name,
            s.entropy,
            s.file_size,
            flags,
            binary::entropy_label(s.entropy),
            note
        );
    }
    println!();

    // Overall packing verdict (the M2 "flag": a finding, not an error).
    let packed = bin.packed_sections();
    if packed.is_empty() {
        println!("packing        : no packed sections detected");
    } else {
        let names: Vec<&str> = packed.iter().map(|s| s.name.as_str()).collect();
        println!(
            "packing        : WARNING - {} section(s) look packed: {}",
            packed.len(),
            names.join(", ")
        );
    }
    println!();

    // M3: imported libraries + function names -- the program's declared capabilities.
    // (PE: DLLs + APIs; ELF: needed .so libraries + undefined dynamic symbols.)
    let total_funcs = bin.total_imported_functions();
    let lib_word = if bin.format == Format::Pe { "DLL(s)" } else { "library/symbol group(s)" };
    println!("imports        : {} {lib_word}, {total_funcs} function(s)", bin.imports.len());
    for imp in &bin.imports {
        let sample: Vec<&str> = imp.functions.iter().take(6).map(|s| s.as_str()).collect();
        let more = if imp.functions.len() > 6 { " ..." } else { "" };
        println!("  {:<20} ({:>4})  {}{}", imp.dll, imp.functions.len(), sample.join(", "), more);
    }
    println!();

    // M4: interpret the imports into capability findings. A rule fires only when a
    // dangerous COMBINATION of APIs is present, and each carries a severity --
    // because benign software uses most of these individually too.
    let findings = rules::assess_imports(&bin.imports);
    if findings.is_empty() {
        println!("capabilities   : none of the flagged categories detected");
    } else {
        let max = rules::max_severity(&findings).unwrap();
        println!("capabilities   : {} finding(s), highest severity {}", findings.len(), max);
        for f in &findings {
            let sample: Vec<&str> = f.matched.iter().take(4).map(|s| s.as_str()).collect();
            println!("  [{:<6}] {:<38} {}", f.severity, f.capability, sample.join(", "));
        }
    }

    // Cross-signal: few imports + a packed section => the imports are likely hidden.
    if !packed.is_empty() && total_funcs < 10 {
        println!("note           : only {total_funcs} import(s) + packed section(s) -> likely packed / imports hidden");
    }
    println!();

    // M5: embedded strings + extracted IOCs (indicators of compromise).
    println!("strings        : {} ascii, {} wide", bin.strings.ascii_count, bin.strings.wide_count);
    if bin.strings.iocs.is_empty() {
        println!("IOCs           : none extracted");
    } else {
        println!("IOCs           : {} unique (showing up to 15)", bin.strings.iocs.len());
        for ioc in bin.strings.iocs.iter().take(15) {
            println!("  [{:<8}] {}", ioc.kind, ioc.value);
        }
    }
}

fn header_region_end(file: &[u8], bin: &Binary) -> usize {
    bin.sections
        .iter()
        .map(|s| s.file_offset as usize)
        .filter(|&p| p > 0)
        .min()
        .unwrap_or(file.len())
        .min(file.len())
}

fn print_full_hex(file: &[u8], bin: &Binary) -> std::io::Result<()> {
    use std::io::{BufWriter, Write};
    let stdout = std::io::stdout();
    let mut w = BufWriter::new(stdout.lock());

    writeln!(w, "\n== Raw hex (full) ==")?;

    let first_data = header_region_end(file, bin);
    writeln!(w, "\n-- headers (file offset 0x0 .. {first_data:#x}) --")?;
    hexdump::dump_to(&mut w, &file[..first_data], 0)?;

    for s in &bin.sections {
        let raw = s.on_disk_bytes(file);
        if raw.is_empty() {
            writeln!(w, "\n-- {} (no on-disk bytes) --", s.name)?;
            continue;
        }
        let start = s.file_offset as usize;
        writeln!(
            w,
            "\n-- {} (file offset {:#x} .. {:#x}, {} bytes) --",
            s.name,
            start,
            start + raw.len(),
            raw.len()
        )?;
        hexdump::dump_to(&mut w, raw, start)?;
    }

    w.flush()
}

fn dump_sections(path: &str, file: &[u8], bin: &Binary, dir: &str) -> std::io::Result<()> {
    use std::io::{BufWriter, Write};
    let dir = dir.trim_end_matches(['/', '\\']); // avoid "output//file"
    std::fs::create_dir_all(dir)?;
    let base = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("image");

    // Headers file (small, always dumped in full).
    let first_data = header_region_end(file, bin);
    let headers_path = format!("{dir}/{base}.headers.txt");
    let mut w = BufWriter::new(std::fs::File::create(&headers_path)?);
    writeln!(w, "== Headers of {path} ==")?;
    writeln!(w, "region      : file offset 0x0 .. {first_data:#x} ({first_data} bytes)")?;
    writeln!(w, "sections    : {}\n", bin.sections.len())?;
    hexdump::dump_to(&mut w, &file[..first_data], 0)?;
    w.flush()?;
    eprintln!("wrote {headers_path} ({first_data} bytes)");

    // One file per section, each with the section's specifics then all its bytes.
    for (idx, s) in bin.sections.iter().enumerate() {
        let n = idx + 1;
        let fname = format!("{dir}/{base}.section-{n:02}-{}.txt", sanitize(&s.name));
        let raw = s.on_disk_bytes(file);

        let mut w = BufWriter::new(std::fs::File::create(&fname)?);
        writeln!(w, "== Section {n} of {}: {} ==", bin.sections.len(), s.name)?;
        writeln!(w, "file        : {path}")?;
        writeln!(w, "flags       : {}", rwx(s))?;
        writeln!(w, "entropy     : {:.3} ({})", s.entropy, binary::entropy_label(s.entropy))?;
        writeln!(w, "virtual size: {:#x} ({})", s.virtual_size, s.virtual_size)?;
        writeln!(w, "virtual addr: {:#x}", s.virtual_addr)?;
        writeln!(w, "file size   : {:#x} ({})", s.file_size, s.file_size)?;
        writeln!(w, "file offset : {:#x}", s.file_offset)?;
        writeln!(
            w,
            "packed?     : {}",
            if s.is_likely_packed() { "yes (executable + high entropy)" } else { "no" }
        )?;
        writeln!(w, "hex bytes   : {} (all)\n", raw.len())?;

        if raw.is_empty() {
            writeln!(w, "(no on-disk bytes)")?;
        } else {
            hexdump::dump_to(&mut w, raw, s.file_offset as usize)?;
        }
        w.flush()?;
        eprintln!("wrote {fname} ({} bytes of section data)", raw.len());
    }

    Ok(())
}

// R/W/X permission string for a section.
fn rwx(s: &Section) -> String {
    format!(
        "{}{}{}",
        if s.is_readable() { 'R' } else { '-' },
        if s.is_writable() { 'W' } else { '-' },
        if s.is_executable() { 'X' } else { '-' },
    )
}

fn sanitize(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() { "unnamed".to_string() } else { trimmed.to_string() }
}
