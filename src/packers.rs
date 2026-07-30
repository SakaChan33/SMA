// Packer identification from section names.
//
// Packers rename sections, and most never bother to hide it: UPX writes UPX0 and
// UPX1, MPRESS writes MPRESS1 and MPRESS2. Matching those names costs nothing
// and tells you what tool to reach for next.
//
// The limitation is the whole point, and worth being loud about: this is a
// *naming convention*, not a signature. `upx --compress-icons` still writes
// UPX0, but one pass of a section renamer defeats this check entirely, and
// nothing stops a benign program from calling a section UPX0. A hit here is a
// hypothesis to confirm -- the entropy reading and the import count are the
// evidence that either supports or kills it.

use crate::binary::Section;

// Every name here must be one that no ordinary toolchain emits. A false
// positive on a system binary would discredit every other reading in the
// report, so anything ambiguous is left out on purpose:
//
//   .pdata   x64 exception unwind data, present in nearly every 64-bit PE
//   .adata   claimed by both ASPack and Armadillo, and used benignly besides
//   .vmp0    listed only under VMProtect, though Themida can emit it too
const SIGNATURES: &[(&str, &[&str])] = &[
    ("UPX", &["UPX0", "UPX1", "UPX2", "UPX!"]),
    ("ASPack", &[".aspack"]),
    ("Themida / WinLicense", &[".themida", ".winlice"]),
    ("VMProtect", &[".vmp0", ".vmp1", ".vmp2"]),
    ("FSG", &["FSG!"]),
    ("PECompact", &["PEC2", "PECompact2"]),
    ("Petite", &[".petite"]),
    ("NsPack", &[".nsp0", ".nsp1", ".nsp2"]),
    ("MPRESS", &["MPRESS1", "MPRESS2"]),
    ("MEW", &[".MEW"]),
    ("Enigma", &[".enigma1", ".enigma2"]),
    ("Obsidium", &[".obsidium"]),
    ("Upack", &[".Upack", ".ByDwing"]),
];

// Every packer whose section-name convention this file matches. Usually empty or
// a single entry; more than one means the names overlap and none of them should
// be trusted without corroboration.
pub fn identify(sections: &[Section]) -> Vec<&'static str> {
    let mut hits: Vec<&'static str> = Vec::new();
    for (packer, names) in SIGNATURES {
        let matched = sections
            .iter()
            .any(|s| names.iter().any(|n| s.name.eq_ignore_ascii_case(n)));
        if matched && !hits.contains(packer) {
            hits.push(packer);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sections(names: &[&str]) -> Vec<Section> {
        names
            .iter()
            .map(|n| Section {
                name: (*n).to_string(),
                virtual_addr: 0,
                virtual_size: 0,
                file_offset: 0,
                file_size: 0,
                readable: true,
                writable: false,
                executable: false,
                entropy: 0.0,
            })
            .collect()
    }

    #[test]
    fn upx_sections_are_recognized() {
        assert_eq!(identify(&sections(&["UPX0", "UPX1", ".rsrc"])), vec!["UPX"]);
    }

    #[test]
    fn ordinary_sections_match_nothing() {
        // .pdata and .didat are standard in 64-bit PEs; a signature that fires
        // on notepad.exe would discredit every other reading in the report.
        assert!(identify(&sections(&[
            ".text", ".rdata", ".data", ".pdata", ".didat", ".rsrc", ".reloc", ".bss", ".tls",
            ".idata", ".edata", ".debug", ".adata", "fothk",
        ]))
        .is_empty());
    }

    #[test]
    fn every_signature_is_distinctive() {
        // No signature may collide with a name a normal toolchain emits.
        const ORDINARY: &[&str] = &[
            ".text", ".rdata", ".data", ".pdata", ".xdata", ".didat", ".rsrc", ".reloc", ".bss",
            ".tls", ".idata", ".edata", ".debug", ".adata", ".sdata", ".init", ".fini", ".got",
            ".plt", ".comment", ".eh_frame", ".symtab", ".strtab", ".shstrtab", ".dynsym",
        ];
        for (packer, names) in SIGNATURES {
            for n in *names {
                assert!(
                    !ORDINARY.iter().any(|o| o.eq_ignore_ascii_case(n)),
                    "{packer} claims '{n}', which is an ordinary section name"
                );
            }
        }
    }

    #[test]
    fn matching_ignores_case() {
        // Some builders lowercase the whole section table.
        assert_eq!(identify(&sections(&["upx0", "upx1"])), vec!["UPX"]);
    }

    #[test]
    fn each_packer_is_reported_once() {
        // UPX0 and UPX1 both match the same packer; it should not appear twice.
        assert_eq!(identify(&sections(&["UPX0", "UPX1", "UPX2"])).len(), 1);
    }
}
