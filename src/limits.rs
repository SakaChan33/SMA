// What static analysis could not see in this sample.
//
// This is the section the removed `-b/--debug` mode was gesturing at. That mode
// promised dynamic analysis sma will never do; this one does something more
// useful and more honest -- it names, per sample, the specific thing the bytes
// refuse to reveal, the evidence for that conclusion, and which tool takes over.
//
// Deliberately NOT a verdict. Nothing here ranks suspicion or estimates
// maliciousness. A limit fires on structural evidence ("this section is
// executable and reads at 7.9 bits/byte, and only 4 imports are declared"), and
// a perfectly legitimate packed installer trips several of them. The reading is
// always "static analysis stops here", never "this is malware".

use crate::binary::Binary;
use std::io::{self, Write};

pub struct Limit {
    // What cannot be observed statically.
    pub obscured: &'static str,
    // Why we say so -- the specific measurement, not a generality.
    pub evidence: String,
    // Which technique answers it instead.
    pub next_step: &'static str,
}

// Few enough imports that the table cannot describe a real program's behaviour.
const SPARSE_IMPORTS: usize = 10;

// The shortest list of functions whose presence means the import table is
// incomplete *by construction*: everything reached through them is resolved at
// runtime and never appears in any header.
//
// This is deliberately not a capability taxonomy, and it must never grow into
// one. SMA lists the binary's own import table without consulting any
// dictionary, precisely so nothing can be filtered out by a gap in a table we
// maintain. These six names gate one sentence in this section -- they decide
// nothing about what the analyst is shown.
//
// Matched by prefix, so LoadLibraryExW and LoadLibraryW both count. That
// mattered: an earlier rules engine appended only "A"/"W" and so missed
// LoadLibraryExW, which is the spelling real code actually uses.
const API_RESOLVERS: &[&str] = &[
    "getprocaddress",
    "loadlibrary",
    "ldrgetprocedureaddress",
    "ldrloaddll",
    "dlsym",
    "dlopen",
];

// The resolvers this binary imports, named, or None.
fn imported_resolvers(bin: &Binary) -> Option<String> {
    let mut found: Vec<String> = Vec::new();
    for imp in &bin.imports {
        for name in imp.names() {
            let lower = name.to_ascii_lowercase();
            if API_RESOLVERS.iter().any(|r| lower.starts_with(r)) && !found.iter().any(|f| f == name)
            {
                found.push(name.to_string());
            }
        }
    }
    if found.is_empty() {
        return None;
    }
    found.sort();
    Some(found.join(", "))
}

pub fn assess(bin: &Binary, indirect_ratio: Option<(u64, u64)>) -> Vec<Limit> {
    let mut limits = Vec::new();
    let packed = bin.packed_sections();
    let total_imports = bin.total_imported_functions();

    // A .NET assembly first: it changes what every other reading means. The
    // native code is a loader stub, so "few imports" and "small .text" are
    // expected rather than evasive.
    if bin.is_dotnet() {
        limits.push(Limit {
            obscured: "the actual program logic",
            evidence: "the CLR data directory is present: this is a .NET assembly, and its real \
                       code is managed IL, not the native instructions sma disassembles"
                .to_string(),
            next_step: "decompile the IL with ILSpy or dnSpy -- native disassembly is the wrong lens here",
        });
    }

    // The classic pairing: code you cannot read, and an import table too small
    // to be real. Either alone is weak; together they say the imports are
    // resolved after unpacking.
    if !packed.is_empty() && total_imports < SPARSE_IMPORTS {
        let names: Vec<&str> = packed.iter().map(|s| s.name.as_str()).collect();
        limits.push(Limit {
            obscured: "the real import table",
            evidence: format!(
                "{} declared import(s) alongside packed section(s) [{}] -- too few to account for \
                 a working program, so the rest are resolved at runtime",
                total_imports,
                names.join(", ")
            ),
            next_step: "run to the original entry point, then dump the unpacked image from memory",
        });
    } else if !packed.is_empty() {
        let worst = packed
            .iter()
            .max_by(|a, b| a.entropy.total_cmp(&b.entropy))
            .expect("packed is non-empty");
        limits.push(Limit {
            obscured: "the instructions in the packed section(s)",
            evidence: format!(
                "'{}' is executable and reads at {:.2} bits/byte -- compressed or encrypted, not \
                 the code that ultimately runs",
                worst.name, worst.entropy
            ),
            next_step: "break after the unpacking stub and dump the section from memory",
        });
    }

    // A named packer tells you which tool to reach for.
    let hints = bin.packer_hints();
    if !hints.is_empty() {
        limits.push(Limit {
            obscured: "the original code",
            evidence: format!(
                "section names match {} -- note this is a naming convention, trivially renamed, so \
                 confirm it against the entropy reading above",
                hints.join(" / ")
            ),
            next_step: "unpack with the matching tool (e.g. `upx -d`), or dump at the original entry point",
        });
    }

    // Zero imports in something that isn't statically linked means the table was
    // stripped or is built at runtime.
    let statically_linked = bin.attributes.iter().any(|a| a.contains("statically linked"));
    if total_imports == 0 && !statically_linked {
        limits.push(Limit {
            obscured: "every API this program uses",
            evidence: "no imported functions were parsed, and this binary is not statically linked"
                .to_string(),
            next_step: "inspect the import address table in a debugger once the loader has filled it in",
        });
    }

    // Importing a resolver means the interesting API names may never appear in
    // the table at all. This is a statement about what the import listing can
    // show, not about whether the program is doing anything wrong with it --
    // every dynamically-linked program on the system imports these.
    if let Some(found) = imported_resolvers(bin) {
        limits.push(Limit {
            obscured: "any API resolved by name at runtime",
            evidence: format!(
                "{found} imported: whatever is reached through a resolver never appears in the \
                 import table, so the listing above is a floor, not a ceiling"
            ),
            next_step: "breakpoint the resolver and log the names it is asked for",
        });
    }

    // Entry point in memory the loader will write to, or that we cannot read at
    // all, means the first instruction we show is not the first that runs.
    if let Some(sec) = bin.section_at(bin.entry_point) {
        if sec.is_writable_and_executable() {
            limits.push(Limit {
                obscured: "the code at the entry point",
                evidence: format!(
                    "the entry point {:#x} sits in '{}', which is both writable and executable -- \
                     it can rewrite itself before the first instruction you'd read here runs",
                    bin.entry_point, sec.name
                ),
                next_step: "break at the entry point and read the instructions from memory",
            });
        }
    }
    if bin.va_to_file_offset(bin.entry_point).is_none() {
        limits.push(Limit {
            obscured: "the entry point itself",
            evidence: format!(
                "entry point {:#x} has no bytes on disk -- it lands in space that only exists once \
                 the image is loaded",
                bin.entry_point
            ),
            next_step: "let the loader map the image, then disassemble from memory",
        });
    }

    // Appended data: undescribed by any header, unloaded, and therefore invisible
    // to every structural check above.
    if let Some(ov) = &bin.overlay {
        if ov.entropy >= 7.0 {
            limits.push(Limit {
                obscured: "appended data past the last section",
                evidence: format!(
                    "{} byte(s) of overlay at file offset {:#x}, reading {:.2} bits/byte -- \
                     compressed or encrypted, and described by no header",
                    ov.size, ov.file_offset, ov.entropy
                ),
                next_step: "carve the overlay at that offset and analyze it as a file in its own right",
            });
        }
    }

    // If most calls have no static target, the call graph is a fraction of the
    // real one.
    if let Some((resolved, indirect)) = indirect_ratio {
        limits.extend(call_graph_limit(resolved, indirect));
    }

    limits
}

// Shared with `sma functions`, which is where these counts are actually
// measured. `resolved` covers calls to a known address or a named API.
pub fn call_graph_limit(resolved: u64, indirect: u64) -> Option<Limit> {
    if indirect <= resolved || indirect <= 20 {
        return None;
    }
    Some(Limit {
        obscured: "most of the call graph",
        evidence: format!(
            "{indirect} call site(s) computed at runtime against {resolved} resolvable -- the \
             majority of targets cannot be known without running the code (virtual dispatch, or \
             deliberate indirection)"
        ),
        next_step: "resolve the targets at runtime, or with a tool that does value analysis",
    })
}

pub fn write<W: Write>(w: &mut W, limits: &[Limit]) -> io::Result<()> {
    if limits.is_empty() {
        writeln!(w, "limits         : nothing detected that static analysis cannot reach")?;
        writeln!(
            w,
            "                 (this says the structure is readable, not that the file is safe)"
        )?;
        return Ok(());
    }

    writeln!(w, "limits         : {} thing(s) static analysis cannot resolve here", limits.len())?;
    for l in limits {
        writeln!(w, "  cannot see   : {}", l.obscured)?;
        writeln!(w, "    because    : {}", wrap(&l.evidence, 76, 17))?;
        writeln!(w, "    next step  : {}", l.next_step)?;
    }
    Ok(())
}

// Wrap on word boundaries, indenting continuation lines so the block reads as
// one field rather than running back to the margin.
fn wrap(text: &str, width: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::with_capacity(text.len() + 16);
    let mut line = 0usize;
    for word in text.split_whitespace() {
        if line > 0 && line + 1 + word.len() > width {
            out.push('\n');
            out.push_str(&pad);
            line = 0;
        } else if line > 0 {
            out.push(' ');
            line += 1;
        }
        out.push_str(word);
        line += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{Binary, Format, Import, ImportedFn, Overlay, PeMeta, Section};
    use crate::strings::StringScan;

    fn section(name: &str, entropy: f64, exec: bool, write: bool) -> Section {
        Section {
            name: name.into(),
            virtual_addr: 0x1000,
            virtual_size: 0x1000,
            file_offset: 0x400,
            file_size: 0x1000,
            readable: true,
            writable: write,
            executable: exec,
            entropy,
        }
    }

    fn binary(sections: Vec<Section>, imports: Vec<Import>) -> Binary {
        Binary {
            format: Format::Pe,
            arch: "x86-64 (AMD64)",
            bits: 64,
            kind: "executable",
            attributes: vec![],
            entry_point: 0x1000,
            image_base: 0x400000,
            sections,
            imports,
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        }
    }

    fn imports(names: &[&str]) -> Vec<Import> {
        vec![Import {
            dll: "kernel32.dll".into(),
            functions: names.iter().copied().map(ImportedFn::named).collect(),
        }]
    }

    #[test]
    fn packed_plus_sparse_imports_reports_hidden_imports() {
        let bin = binary(vec![section(".text", 7.8, true, false)], imports(&["ExitProcess"]));
        let limits = assess(&bin, None);
        assert!(
            limits.iter().any(|l| l.obscured.contains("import table")),
            "expected a hidden-import limit, got: {:?}",
            limits.iter().map(|l| l.obscured).collect::<Vec<_>>()
        );
        // The evidence must carry the actual numbers, not a generality.
        let l = limits.iter().find(|l| l.obscured.contains("import table")).unwrap();
        assert!(l.evidence.contains('1'), "evidence should cite the import count: {}", l.evidence);
        assert!(l.evidence.contains(".text"), "evidence should name the section: {}", l.evidence);
    }

    #[test]
    fn an_ordinary_binary_reports_no_limits() {
        let bin = binary(
            vec![section(".text", 6.1, true, false), section(".rdata", 4.5, false, false)],
            imports(&[
                "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "HeapAlloc", "HeapFree",
                "GetLastError", "SetFilePointer", "GetStdHandle", "ExitProcess", "GetModuleHandleW",
            ]),
        );
        assert!(assess(&bin, None).is_empty(), "clean binary should have no limits");
    }

    #[test]
    fn packed_alone_reports_unreadable_code_not_hidden_imports() {
        let many: Vec<&str> = vec![
            "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "HeapAlloc", "HeapFree",
            "GetLastError", "SetFilePointer", "GetStdHandle", "ExitProcess", "GetModuleHandleW",
        ];
        let bin = binary(vec![section(".text", 7.6, true, false)], imports(&many));
        let limits = assess(&bin, None);
        assert!(limits.iter().any(|l| l.obscured.contains("packed section")));
        assert!(!limits.iter().any(|l| l.obscured.contains("import table")));
    }

    #[test]
    fn runtime_resolution_is_reported_from_the_import_pair() {
        let bin = binary(
            vec![section(".text", 6.0, true, false)],
            imports(&["LoadLibraryW", "GetProcAddress", "CreateFileW", "ReadFile", "WriteFile",
                      "CloseHandle", "HeapAlloc", "HeapFree", "GetLastError", "ExitProcess",
                      "GetStdHandle"]),
        );
        let limits = assess(&bin, None);
        assert!(limits.iter().any(|l| l.obscured.contains("resolved by name at runtime")));
    }

    #[test]
    fn a_writable_executable_entry_point_is_flagged() {
        let bin = binary(vec![section(".text", 6.0, true, true)], imports(&["ExitProcess"; 11]));
        let limits = assess(&bin, None);
        assert!(limits.iter().any(|l| l.obscured.contains("code at the entry point")));
    }

    #[test]
    fn a_high_entropy_overlay_is_flagged_but_a_low_entropy_one_is_not() {
        let mut bin = binary(vec![section(".text", 6.0, true, false)], imports(&["ExitProcess"; 11]));
        bin.overlay = Some(Overlay { file_offset: 0x1400, size: 4096, entropy: 7.9 });
        assert!(assess(&bin, None).iter().any(|l| l.obscured.contains("appended data")));

        bin.overlay = Some(Overlay { file_offset: 0x1400, size: 4096, entropy: 3.2 });
        assert!(!assess(&bin, None).iter().any(|l| l.obscured.contains("appended data")));
    }

    #[test]
    fn dotnet_assemblies_are_called_out() {
        let mut bin = binary(vec![section(".text", 6.0, true, false)], imports(&["ExitProcess"; 11]));
        bin.pe_meta = Some(PeMeta { is_dotnet: true, ..PeMeta::default() });
        let limits = assess(&bin, None);
        assert!(limits.iter().any(|l| l.next_step.contains("ILSpy")));
    }

    #[test]
    fn indirect_heavy_call_graphs_are_reported() {
        let bin = binary(vec![section(".text", 6.0, true, false)], imports(&["ExitProcess"; 11]));
        assert!(assess(&bin, Some((10, 500))).iter().any(|l| l.obscured.contains("call graph")));
        // Direct-dominated, and small counts, stay quiet.
        assert!(!assess(&bin, Some((500, 10))).iter().any(|l| l.obscured.contains("call graph")));
        assert!(!assess(&bin, Some((1, 5))).iter().any(|l| l.obscured.contains("call graph")));
    }

    #[test]
    fn wrap_breaks_on_words_and_indents_continuations() {
        let out = wrap("aaa bbb ccc ddd", 7, 2);
        assert_eq!(out, "aaa bbb\n  ccc ddd");
        assert_eq!(wrap("", 10, 2), "");
    }
}
