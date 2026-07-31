use crate::binary::{Binary, Format};

// Escape a string for use inside a JSON string literal (RFC 8259).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// Quote + escape a string into a JSON string value.
fn q(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

// The same, for other modules that emit their own JSON views.
pub fn quote(s: &str) -> String {
    q(s)
}

// Join items into a JSON array body.
fn arr(items: Vec<String>) -> String {
    format!("[{}]", items.join(", "))
}

// Build the full JSON report for one analyzed binary. Numbers stay numeric
// (sizes, offsets, addresses, counts) so a consumer can threshold/compare them;
// entropy is a float; severities/kinds are strings.
pub fn report(path: &str, size: usize, bin: &Binary) -> String {
    let format = match bin.format {
        Format::Pe => "PE",
        Format::Elf => "ELF",
    };

    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!("  \"file\": {},\n", q(path)));
    s.push_str(&format!("  \"size\": {size},\n"));
    s.push_str(&format!("  \"format\": {},\n", q(format)));
    s.push_str(&format!("  \"arch\": {},\n", q(bin.arch)));
    s.push_str(&format!("  \"bits\": {},\n", bin.bits));
    s.push_str(&format!("  \"kind\": {},\n", q(bin.kind)));
    s.push_str(&format!("  \"attributes\": {},\n", arr(bin.attributes.iter().map(|a| q(a)).collect())));
    s.push_str(&format!("  \"entry_point\": {},\n", bin.entry_point));
    s.push_str(&format!("  \"image_base\": {},\n", bin.image_base));

    // Sections (one object per line).
    s.push_str("  \"sections\": [\n");
    for (i, sec) in bin.sections.iter().enumerate() {
        let comma = if i + 1 < bin.sections.len() { "," } else { "" };
        s.push_str(&format!(
            "    {{\"name\": {}, \"virtual_addr\": {}, \"virtual_size\": {}, \"file_offset\": {}, \"file_size\": {}, \"readable\": {}, \"writable\": {}, \"executable\": {}, \"entropy\": {:.3}, \"likely_packed\": {}}}{comma}\n",
            q(&sec.name),
            sec.virtual_addr,
            sec.virtual_size,
            sec.file_offset,
            sec.file_size,
            sec.readable,
            sec.writable,
            sec.executable,
            sec.entropy,
            sec.is_likely_packed(),
        ));
    }
    s.push_str("  ],\n");

    // Packing verdict.
    let packed: Vec<String> = bin.packed_sections().iter().map(|s| q(&s.name)).collect();
    s.push_str(&format!(
        "  \"packing\": {{\"packed\": {}, \"sections\": {}}},\n",
        !packed.is_empty(),
        arr(packed)
    ));

    // The import table in full, with each function's IAT slot so a consumer can
    // correlate a name with the address code calls through. Nothing is filtered
    // or sampled: this is the binary's own list.
    s.push_str("  \"imports\": [\n");
    for (i, imp) in bin.imports.iter().enumerate() {
        let comma = if i + 1 < bin.imports.len() { "," } else { "" };
        let funcs: Vec<String> = imp
            .functions
            .iter()
            .map(|f| {
                let slot = match f.iat_rva {
                    Some(rva) => rva.to_string(),
                    None => "null".to_string(),
                };
                let ord = match f.ordinal {
                    Some(o) => o.to_string(),
                    None => "null".to_string(),
                };
                format!("{{\"name\": {}, \"iat_rva\": {slot}, \"ordinal\": {ord}}}", q(&f.name))
            })
            .collect();
        s.push_str(&format!(
            "    {{\"dll\": {}, \"functions\": [{}]}}{comma}\n",
            q(&imp.dll),
            funcs.join(", ")
        ));
    }
    s.push_str("  ],\n");
    s.push_str(&format!(
        "  \"import_summary\": {{\"libraries\": {}, \"functions\": {}}},\n",
        bin.imports.len(),
        bin.total_imported_functions()
    ));


    // Strings + IOCs (M5).
    s.push_str(&format!(
        "  \"strings\": {{\"ascii\": {}, \"wide\": {}}},\n",
        bin.strings.ascii_count, bin.strings.wide_count
    ));
    s.push_str("  \"iocs\": [\n");
    for (i, ioc) in bin.strings.iocs.iter().enumerate() {
        let comma = if i + 1 < bin.strings.iocs.len() { "," } else { "" };
        s.push_str(&format!("    {{\"kind\": {}, \"value\": {}}}{comma}\n", q(&ioc.kind.to_string()), q(&ioc.value)));
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{Binary, Format, Section};
    use crate::strings::StringScan;

    #[test]
    fn escapes_special_chars() {
        assert_eq!(esc(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(esc("x\ty\n"), "x\\ty\\n");
        assert_eq!(esc("\u{0007}"), "\\u0007"); // a control char -> \u escape
    }

    fn tiny_binary() -> Binary {
        Binary {
            format: Format::Elf,
            arch: "x86-64 (AMD64)",
            bits: 64,
            kind: "executable",
            attributes: vec!["statically linked".into()],
            entry_point: 0x1000,
            image_base: 0,
            sections: vec![Section {
                name: ".text".into(),
                virtual_addr: 0x1000,
                virtual_size: 0x10,
                file_offset: 0x40,
                file_size: 0x10,
                readable: true,
                writable: false,
                executable: true,
                entropy: 6.5,
            }],
            imports: vec![],
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        }
    }

    #[test]
    fn report_has_expected_keys_and_shape() {
        let out = report("/bin/x", 123, &tiny_binary());
        for key in
            ["\"file\"", "\"format\"", "\"arch\"", "\"sections\"", "\"packing\"", "\"imports\"", "\"iocs\""]
        {
            assert!(out.contains(key), "missing {key} in:\n{out}");
        }
        assert!(out.contains("\"format\": \"ELF\""));
        assert!(out.contains("\"executable\": true"));
        // balanced braces/brackets is a cheap validity smoke test
        assert_eq!(out.matches('{').count(), out.matches('}').count());
        assert_eq!(out.matches('[').count(), out.matches(']').count());
    }

    #[test]
    fn no_capability_or_scoring_field_is_emitted() {
        // SMA lists; it does not grade. A consumer must not find a severity or
        // a category to sort by, because inventing one is the analyst's call.
        let out = report("/bin/x", 123, &tiny_binary());
        for gone in ["capabilit", "severity", "score", "api_index", "verdict"] {
            assert!(!out.contains(gone), "{gone} should not appear in:\n{out}");
        }
    }

    #[test]
    fn imports_carry_every_function_with_its_slot() {
        use crate::binary::{Import, ImportedFn};
        let mut bin = tiny_binary();
        bin.imports = vec![Import {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                ImportedFn { name: "VirtualAlloc".into(), iat_rva: Some(0x2000), ordinal: None },
                ImportedFn { name: "VirtualProtect".into(), iat_rva: Some(0x2008), ordinal: None },
                ImportedFn { name: "#42".into(), iat_rva: Some(0x2010), ordinal: Some(42) },
            ],
        }];
        let out = report("/bin/x", 123, &bin);
        assert!(out.contains("\"VirtualAlloc\""));
        assert!(out.contains("\"VirtualProtect\""), "nothing may be filtered out");
        assert!(out.contains("\"iat_rva\": 8192")); // 0x2000
        assert!(out.contains("\"ordinal\": 42"));
    }
}
