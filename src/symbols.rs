use crate::binary::Binary;
use crate::cfg::x86_mode;
use capstone::prelude::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

// What a known address is, when it isn't an import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Label {
    // The image's entry point.
    Entry,
    // An exported function, by name.
    Export(String),
    // A TLS callback: runs *before* the entry point, which is why malware likes
    // putting anti-debug checks here.
    TlsCallback,
}

impl Label {
    pub fn text(&self) -> String {
        match self {
            Label::Entry => "[entry]".to_string(),
            Label::Export(n) => format!("[export: {n}]"),
            Label::TlsCallback => "[TLS callback]".to_string(),
        }
    }
}

pub struct Symbols<'a> {
    file: &'a [u8],
    bin: &'a Binary,
    // IAT slot RVA -> "KERNEL32!VirtualAlloc"
    imports: BTreeMap<u64, String>,
    // Code RVA -> what that address is.
    labels: BTreeMap<u64, Label>,
    // detail(true) so we can read a jmp's memory operand. Only ever used on the
    // handful of addresses that are call targets, never on a bulk sweep.
    cs: Option<Capstone>,
    // Call targets repeat constantly; decode each one once.
    cache: RefCell<HashMap<u64, Option<String>>>,
}

impl<'a> Symbols<'a> {
    pub fn build(file: &'a [u8], bin: &'a Binary) -> Self {
        let mut imports = BTreeMap::new();
        for imp in &bin.imports {
            let lib = trim_dll_suffix(&imp.dll);
            for f in &imp.functions {
                if let Some(slot) = f.iat_rva {
                    imports.insert(slot, format!("{lib}!{}", f.name));
                }
            }
        }

        let mut labels = BTreeMap::new();
        labels.insert(bin.entry_point, Label::Entry);
        for &cb in bin.tls_callbacks() {
            labels.insert(cb, Label::TlsCallback);
        }
        // Exports last: a named export is more informative than "entry", and if
        // an address is both, the name is what an analyst wants to see.
        for e in &bin.exports {
            if e.forwarder.is_none() {
                labels.insert(e.rva, Label::Export(e.name.clone()));
            }
        }

        let cs = x86_mode(bin).and_then(|mode| {
            Capstone::new()
                .x86()
                .mode(mode)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()
                .ok()
        });

        Symbols { file, bin, imports, labels, cs, cache: RefCell::new(HashMap::new()) }
    }

    pub fn label_at(&self, rva: u64) -> Option<&Label> {
        self.labels.get(&rva)
    }

    // What a call/jump actually reaches, from its operand text.
    //
    // Two forms both end at an API, and missing the second one loses most of a
    // modern Windows binary's API calls:
    //
    //   call 0x401234              -> a thunk, which jumps through an IAT slot
    //   call qword ptr [rip+0x2a5e] -> straight through the IAT slot, no thunk
    //
    // MSVC emits the second form for nearly every import. Treating it as
    // "indirect, target unknown" is technically true of the instruction and
    // useless in practice: the slot address is right there in the operand.
    pub fn classify_call(&self, ops: &str, next_rva: u64) -> CallTarget {
        if let Some(direct) = crate::cfg::parse_target(ops) {
            return match self.describe(direct) {
                Some(api) => CallTarget::Import(api),
                None => CallTarget::Code(direct),
            };
        }
        if let Some(slot) = parse_mem_operand(ops, next_rva, self.bin.image_base) {
            if let Some(api) = self.import_at(slot) {
                return CallTarget::Import(api.to_string());
            }
        }
        CallTarget::Unknown
    }

    // Is this address an import slot rather than code?
    pub fn import_at(&self, rva: u64) -> Option<&str> {
        self.imports.get(&rva).map(|s| s.as_str())
    }

    pub fn has_imports(&self) -> bool {
        !self.imports.is_empty()
    }

    // "KERNEL32!VirtualAlloc" for an address that reaches an import, directly or
    // through one thunk. None means the target is ordinary code (or something we
    // cannot follow statically, which is itself worth knowing).
    pub fn describe(&self, rva: u64) -> Option<String> {
        if let Some(direct) = self.imports.get(&rva) {
            return Some(direct.clone());
        }
        if let Some(hit) = self.cache.borrow().get(&rva) {
            return hit.clone();
        }
        let resolved = self.follow_thunk(rva).and_then(|slot| self.imports.get(&slot).cloned());
        self.cache.borrow_mut().insert(rva, resolved.clone());
        resolved
    }

    // Decode one instruction at `rva`; if it is an indirect jump through memory,
    // return the RVA it jumps through.
    fn follow_thunk(&self, rva: u64) -> Option<u64> {
        let cs = self.cs.as_ref()?;
        let off = self.bin.va_to_file_offset(rva)?;
        // A thunk is at most a handful of bytes; 16 is the x86 maximum
        // instruction length, so this never reads more than one instruction.
        let end = (off + 16).min(self.file.len());
        let insns = cs.disasm_count(self.file.get(off..end)?, rva, 1).ok()?;
        let insn = insns.iter().next()?;
        if insn.mnemonic() != Some("jmp") {
            return None;
        }

        let detail = cs.insn_detail(insn).ok()?;
        let arch = detail.arch_detail();
        let x86 = arch.x86()?;
        let op = x86.operands().next()?;
        let mem = match op.op_type {
            arch::x86::X86OperandType::Mem(m) => m,
            _ => return None,
        };

        let rip = RegId(arch::x86::X86Reg::X86_REG_RIP as RegIdInt);
        if mem.base() == rip {
            // RIP-relative (x86-64): the displacement is from the *next*
            // instruction, so the jump reads [end-of-this-instruction + disp].
            let next = rva + insn.bytes().len() as u64;
            checked_offset(next, mem.disp())
        } else if mem.base() == RegId(0) && mem.index() == RegId(0) {
            // Absolute (x86-32): the displacement is a virtual address, so drop
            // the image base to get back to an RVA.
            let va = mem.disp() as u64;
            va.checked_sub(self.bin.image_base)
        } else {
            // Indexed or register-based: a jump table or a computed target. Not
            // statically knowable, which is exactly the kind of gap `sma scan`
            // reports under `limits`.
            None
        }
    }
}

// What a call instruction reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTarget {
    // A known address inside the image.
    Code(u64),
    // An imported API, reached directly or through one thunk.
    Import(String),
    // Computed at runtime: `call rax`, `call [rbx+rcx*8]`. Statically unknowable,
    // and the honest answer is to say so.
    Unknown,
}

// Read the memory operand of a call/jump and return the RVA it reads through.
// Capstone's Intel syntax renders these as `qword ptr [rip + 0x2a5e]` (x86-64,
// relative to the *next* instruction) or `dword ptr [0x40a000]` (x86-32,
// an absolute virtual address).
fn parse_mem_operand(ops: &str, next_rva: u64, image_base: u64) -> Option<u64> {
    let open = ops.find('[')?;
    let close = ops[open..].find(']')? + open;
    let inner = ops.get(open + 1..close)?.trim();

    if let Some(rest) = inner.strip_prefix("rip") {
        let rest = rest.trim();
        if rest.is_empty() {
            return Some(next_rva);
        }
        let (negative, rest) = match rest.split_at(1) {
            ("+", r) => (false, r),
            ("-", r) => (true, r),
            _ => return None,
        };
        let disp = parse_number(rest.trim())?;
        return if negative { next_rva.checked_sub(disp) } else { next_rva.checked_add(disp) };
    }

    // No base register: the operand is an absolute address, so the image base
    // comes off to get an RVA. Anything else (a register, an index, a scale) is
    // computed at runtime and must not be guessed at.
    parse_number(inner)?.checked_sub(image_base)
}

fn parse_number(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse::<u64>().ok(),
    }
}

fn checked_offset(base: u64, disp: i64) -> Option<u64> {
    if disp >= 0 {
        base.checked_add(disp as u64)
    } else {
        base.checked_sub(disp.unsigned_abs())
    }
}

// "KERNEL32.dll" + "VirtualAlloc" -> "KERNEL32!VirtualAlloc". One spelling
// everywhere, so a name from the import table and a name from a resolved call
// site compare equal.
pub fn qualified_name(dll: &str, func: &str) -> String {
    format!("{}!{}", trim_dll_suffix(dll), func)
}

// "KERNEL32.dll" -> "KERNEL32", matching the DLL!API convention debuggers use.
fn trim_dll_suffix(dll: &str) -> &str {
    let bytes = dll.as_bytes();
    if bytes.len() > 4 && dll[bytes.len() - 4..].eq_ignore_ascii_case(".dll") {
        &dll[..bytes.len() - 4]
    } else {
        dll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{Binary, Format, Import, ImportedFn, Section};
    use crate::strings::StringScan;

    // One executable section holding `code` at `base`, plus one imported API
    // whose IAT slot sits at `iat_rva`.
    fn fixture(code: &[u8], base: u64, iat_rva: u64, image_base: u64) -> (Vec<u8>, Binary) {
        let sec = Section {
            name: ".text".into(),
            virtual_addr: base,
            virtual_size: code.len() as u64,
            file_offset: 0,
            file_size: code.len() as u64,
            readable: true,
            writable: false,
            executable: true,
            entropy: 0.0,
        };
        let bin = Binary {
            format: Format::Pe,
            arch: "x86-64 (AMD64)",
            bits: 64,
            kind: "executable",
            attributes: vec![],
            entry_point: base,
            image_base,
            sections: vec![sec],
            imports: vec![Import {
                dll: "KERNEL32.dll".into(),
                functions: vec![ImportedFn {
                    name: "VirtualAlloc".into(),
                    iat_rva: Some(iat_rva),
                    ordinal: None,
                }],
            }],
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        };
        (code.to_vec(), bin)
    }

    #[test]
    fn resolves_a_rip_relative_thunk() {
        // At 0x1000:  ff 25 fa 0f 00 00   jmp qword ptr [rip + 0xffa]
        // Next instruction is 0x1006, so the slot is 0x1006 + 0xffa = 0x2000.
        let code = [0xff, 0x25, 0xfa, 0x0f, 0x00, 0x00];
        let (file, mut bin) = fixture(&code, 0x1000, 0x2000, 0x140000000);
        // Widen the section so the IAT address is inside the image.
        bin.sections[0].virtual_size = 0x2000;

        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.describe(0x1000).as_deref(), Some("KERNEL32!VirtualAlloc"));
    }

    #[test]
    fn resolves_a_direct_slot_hit() {
        let (file, bin) = fixture(&[0x90], 0x1000, 0x2000, 0);
        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.describe(0x2000).as_deref(), Some("KERNEL32!VirtualAlloc"));
    }

    #[test]
    fn resolves_an_absolute_thunk_after_subtracting_image_base() {
        // 32-bit form: ff 25 00 20 40 00  jmp dword ptr [0x402000]
        // With image base 0x400000 that slot is RVA 0x2000.
        let code = [0xff, 0x25, 0x00, 0x20, 0x40, 0x00];
        let (file, mut bin) = fixture(&code, 0x1000, 0x2000, 0x400000);
        bin.arch = "x86 (I386)";
        bin.bits = 32;
        bin.sections[0].virtual_size = 0x2000;

        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.describe(0x1000).as_deref(), Some("KERNEL32!VirtualAlloc"));
    }

    #[test]
    fn ordinary_code_resolves_to_nothing() {
        // xor eax, eax; ret -- not a thunk.
        let code = [0x31, 0xc0, 0xc3];
        let (file, bin) = fixture(&code, 0x1000, 0x2000, 0);
        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.describe(0x1000), None);
    }

    #[test]
    fn indirect_register_jumps_are_not_guessed() {
        // jmp qword ptr [rax] -- a computed target we must not pretend to know.
        let code = [0xff, 0x20];
        let (file, bin) = fixture(&code, 0x1000, 0x2000, 0);
        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.describe(0x1000), None);
    }

    #[test]
    fn entry_point_is_labelled() {
        let (file, bin) = fixture(&[0x90], 0x1000, 0x2000, 0);
        let syms = Symbols::build(&file, &bin);
        assert_eq!(syms.label_at(0x1000), Some(&Label::Entry));
        assert_eq!(syms.label_at(0x1234), None);
    }

    #[test]
    fn dll_suffix_is_trimmed_case_insensitively() {
        assert_eq!(trim_dll_suffix("KERNEL32.dll"), "KERNEL32");
        assert_eq!(trim_dll_suffix("ADVAPI32.DLL"), "ADVAPI32");
        assert_eq!(trim_dll_suffix("libc.so.6"), "libc.so.6");
        assert_eq!(trim_dll_suffix(".dll"), ".dll"); // too short to be a suffix
    }
}
