use crate::binary::Binary;
use crate::symbols::{CallTarget, Symbols};
use capstone::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

// How a single instruction affects control flow.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Flow {
    Normal,   // falls through to the next instruction
    Call,     // calls a subroutine, then falls through (callee is another function)
    Return,   // ends the function path (ret)
    Jump,     // unconditional jmp: one successor (the target), or none if indirect
    CondJump, // conditional branch: two successors (target + fall-through)
}

struct Instr {
    addr: u64,
    size: u64,
    text: String,        // "mov rax, [rcx]"
    flow: Flow,
    target: Option<u64>, // direct branch/call target, when statically known
}

struct Block {
    start: u64,
    addrs: Vec<u64>,                // instruction addresses in order
    succ: Vec<(u64, &'static str)>, // (successor address, edge label)
}

pub struct Cfg {
    func: u64,
    instrs: BTreeMap<u64, Instr>,
    blocks: Vec<Block>,
}

const MAX_INSNS: usize = 50_000; // bound the walk on hostile/degenerate input

// Disassemble the function at `start` (default: the entry point) and build its CFG.
pub fn build(file: &[u8], bin: &Binary, start: Option<u64>) -> Result<Cfg, String> {
    let mode =
        x86_mode(bin).ok_or_else(|| format!("disassembly supports x86/x86-64 only (this is {})", bin.arch))?;

    let func = start.unwrap_or(bin.entry_point);

    // A declared entry point of 0 means the image has none: resource-only DLLs
    // and some .NET stubs look like this. Say so, rather than reporting the
    // generic "no section contains address 0x0" and leaving the user to work
    // out that the address came from us, not from them.
    if func == 0 && start.is_none() {
        return Err(
            "this image declares no entry point (RVA 0), so there is no default function to graph.\n\
             pick one with --addr, or run `sma functions` to list the addresses worth looking at"
                .to_string(),
        );
    }

    // Find the section holding the start address, and borrow its on-disk bytes.
    let sec = bin
        .sections
        .iter()
        .find(|s| {
            let size = s.virtual_size.max(s.file_size);
            s.virtual_addr <= func && func < s.virtual_addr + size
        })
        .ok_or_else(|| format!("no section contains address {func:#x}"))?;
    let sbytes = sec.on_disk_bytes(file);
    let sec_base = sec.virtual_addr;
    let sec_end = sec_base + sbytes.len() as u64;
    if !(sec_base..sec_end).contains(&func) {
        return Err(format!("address {func:#x} has no on-disk bytes to disassemble"));
    }

    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .map_err(|e| format!("capstone init failed: {e}"))?;

    // Phase 1 -- recursive descent: decode every reachable instruction of the
    // function by following each branch's successors.
    let mut instrs: BTreeMap<u64, Instr> = BTreeMap::new();
    let mut work: VecDeque<u64> = VecDeque::new();
    work.push_back(func);
    while let Some(addr) = work.pop_front() {
        if instrs.contains_key(&addr) || instrs.len() >= MAX_INSNS {
            continue;
        }
        if !(sec_base..sec_end).contains(&addr) {
            continue; // target outside this section (e.g. a tail call) -- don't follow
        }
        let ins = match decode_one(&cs, sbytes, sec_base, addr) {
            Some(i) => i,
            None => continue, // undecodable byte -- stop this path
        };
        let next = addr + ins.size;
        let succs: Vec<u64> = match ins.flow {
            Flow::Return => vec![],
            Flow::Jump => ins.target.into_iter().collect(),
            Flow::CondJump => {
                let mut v = vec![next];
                v.extend(ins.target);
                v
            }
            Flow::Normal | Flow::Call => vec![next],
        };
        instrs.insert(addr, ins);
        for s in succs {
            if (sec_base..sec_end).contains(&s) && !instrs.contains_key(&s) {
                work.push_back(s);
            }
        }
    }
    if instrs.is_empty() {
        return Err(format!("no decodable instructions at {func:#x}"));
    }

    // Phase 2 -- leaders: entry, every branch target, and the instruction after
    // any branch/jump/ret.
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    leaders.insert(func);
    for ins in instrs.values() {
        let next = ins.addr + ins.size;
        match ins.flow {
            Flow::Jump | Flow::CondJump => {
                if let Some(t) = ins.target {
                    leaders.insert(t);
                }
                leaders.insert(next);
            }
            Flow::Return => {
                leaders.insert(next);
            }
            _ => {}
        }
    }
    let starts: Vec<u64> = leaders.iter().copied().filter(|a| instrs.contains_key(a)).collect();
    let start_set: BTreeSet<u64> = starts.iter().copied().collect();

    // Phase 3 -- build the blocks and their out-edges.
    let mut blocks: Vec<Block> = Vec::new();
    for &start in &starts {
        let mut addrs = Vec::new();
        let mut cur = start;
        loop {
            let ins = &instrs[&cur];
            addrs.push(cur);
            let next = ins.addr + ins.size;
            if matches!(ins.flow, Flow::Return | Flow::Jump | Flow::CondJump) {
                break; // a control-flow instruction ends the block
            }
            if !instrs.contains_key(&next) || start_set.contains(&next) {
                break; // ran into the next block (or the end)
            }
            cur = next;
        }
        let last = &instrs[addrs.last().unwrap()];
        let next = last.addr + last.size;
        let succ: Vec<(u64, &'static str)> = match last.flow {
            Flow::Return => vec![],
            Flow::Jump => match last.target {
                Some(t) => vec![(t, "jmp")],
                None => vec![], // indirect jump -- target unknown statically
            },
            Flow::CondJump => {
                let mut v = vec![(next, "fall")];
                if let Some(t) = last.target {
                    v.push((t, "taken"));
                }
                v
            }
            Flow::Normal | Flow::Call => vec![(next, "")], // fell through to a leader
        };
        blocks.push(Block { start, addrs, succ });
    }

    Ok(Cfg { func, instrs, blocks })
}

// Pick the Capstone x86 mode for this binary (None if it isn't x86/x86-64).
pub(crate) fn x86_mode(bin: &Binary) -> Option<arch::x86::ArchMode> {
    if bin.arch.contains("x86-64") || bin.arch.contains("AMD64") {
        Some(arch::x86::ArchMode::Mode64)
    } else if bin.arch.contains("x86") || bin.arch.contains("I386") {
        Some(arch::x86::ArchMode::Mode32)
    } else {
        None
    }
}

// What `sma disasm` should cover.
#[derive(Debug, Default, Clone)]
pub struct DisasmOpts<'a> {
    // Start here instead of walking whole sections.
    pub addr: Option<u64>,
    // Stop after this many instructions. None = no limit.
    pub count: Option<usize>,
    // Restrict to one section by name.
    pub section: Option<&'a str>,
}

// `sma disasm`: LINEAR disassembly, top to bottom -- the whole program's code by
// default, not just one function. Streamed instruction-by-instruction (bounded
// memory) so any file size works, even a 172 MB `.text`. Undecodable bytes are
// emitted as `.byte (bad)` the way objdump does. Returns the instruction count.
//
// Linear sweeping is the honest-but-dumb strategy: it will happily decode data
// as instructions. `sma cfg` follows control flow instead and is what you want
// once you know which address matters.
pub fn disassemble<W: Write>(
    file: &[u8],
    bin: &Binary,
    w: &mut W,
    opts: &DisasmOpts,
    syms: Option<&Symbols>,
) -> io::Result<u64> {
    let mode = x86_mode(bin).ok_or_else(|| {
        io::Error::other(format!("disassembly supports x86/x86-64 only (this is {})", bin.arch))
    })?;
    let cs = new_capstone(mode)?;

    let mut total: u64 = 0;
    let limit = opts.count.unwrap_or(usize::MAX);

    // --addr narrows to one window inside whichever section holds the address.
    if let Some(start) = opts.addr {
        let sec = bin
            .section_at(start)
            .ok_or_else(|| io::Error::other(format!("no section contains address {start:#x}")))?;
        let bytes = sec.on_disk_bytes(file);
        let delta = (start - sec.virtual_addr) as usize;
        if delta >= bytes.len() {
            return Err(io::Error::other(format!(
                "address {start:#x} has no bytes on disk (it lands in the part of '{}' that only exists once loaded)",
                sec.name
            )));
        }
        let name = section_label(sec);
        writeln!(w, "== {name} from {start:#x} ==\n")?;
        total += sweep(&cs, &bytes[delta..], start, limit, w, syms)?;
        return Ok(total);
    }

    let wanted = |s: &&crate::binary::Section| -> bool {
        s.is_executable()
            && match opts.section {
                Some(n) => s.name == n || s.name.eq_ignore_ascii_case(n),
                None => true,
            }
    };

    let mut matched_any = false;
    for sec in bin.sections.iter().filter(wanted) {
        matched_any = true;
        let bytes = sec.on_disk_bytes(file);
        if bytes.is_empty() {
            continue;
        }
        let name = section_label(sec);
        writeln!(w, "\n== section {name}  (addr {:#x}, {} bytes) ==", sec.virtual_addr, bytes.len())?;
        let remaining = limit.saturating_sub(total as usize);
        if remaining == 0 {
            break;
        }
        total += sweep(&cs, bytes, sec.virtual_addr, remaining, w, syms)?;
    }

    if !matched_any {
        if let Some(n) = opts.section {
            return Err(io::Error::other(format!("no executable section named '{n}'")));
        }
        return Err(io::Error::other("this binary has no executable section with bytes on disk"));
    }
    Ok(total)
}

// Decode `bytes` starting at virtual address `base`, printing up to `limit`
// instructions. Batched so the whole section's instructions never sit in memory
// at once.
fn sweep<W: Write>(
    cs: &Capstone,
    bytes: &[u8],
    base: u64,
    limit: usize,
    w: &mut W,
    syms: Option<&Symbols>,
) -> io::Result<u64> {
    let mut count: u64 = 0;
    let mut off = 0usize;
    while off < bytes.len() && (count as usize) < limit {
        let addr = base + off as u64;
        let batch = 8192.min(limit - count as usize);
        let insns = cs
            .disasm_count(&bytes[off..], addr, batch)
            .map_err(|e| io::Error::other(format!("capstone: {e}")))?;
        if insns.is_empty() {
            // A byte we can't decode: data, padding, or a truncated tail.
            writeln!(w, "{addr:#012x}  {:02x}          .byte (bad)", bytes[off])?;
            off += 1;
            continue;
        }
        for insn in insns.iter() {
            let m = insn.mnemonic().unwrap_or("");
            let o = insn.op_str().unwrap_or("");
            let note = call_annotation(m, o, insn.address() + insn.bytes().len() as u64, syms);
            match (o.is_empty(), note) {
                (true, _) => writeln!(w, "{:#012x}  {m}", insn.address())?,
                (false, Some(n)) => writeln!(w, "{:#012x}  {m} {o}{n}", insn.address())?,
                (false, None) => writeln!(w, "{:#012x}  {m} {o}", insn.address())?,
            }
            off += insn.bytes().len();
            count += 1;
        }
    }
    Ok(count)
}

// `; KERNEL32!VirtualAlloc` for a call whose target resolves to an import.
// This is the difference between reading addresses and reading behaviour.
fn call_annotation(mnem: &str, ops: &str, next_rva: u64, syms: Option<&Symbols>) -> Option<String> {
    let syms = syms?;
    if !matches!(classify(mnem), Flow::Call | Flow::Jump) {
        return None;
    }
    match syms.classify_call(ops, next_rva) {
        CallTarget::Import(api) => Some(format!("        ; {api}")),
        CallTarget::Code(t) => syms.label_at(t).map(|l| format!("        ; {}", l.text())),
        CallTarget::Unknown => None,
    }
}

fn section_label(s: &crate::binary::Section) -> &str {
    if s.name.is_empty() {
        "(unnamed)"
    } else {
        &s.name
    }
}

pub(crate) fn new_capstone(mode: arch::x86::ArchMode) -> io::Result<Capstone> {
    Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .map_err(|e| io::Error::other(format!("capstone init failed: {e}")))
}

// Decode exactly one instruction at `addr` and classify its control flow.
fn decode_one(cs: &Capstone, sbytes: &[u8], sec_base: u64, addr: u64) -> Option<Instr> {
    let off = (addr - sec_base) as usize;
    if off >= sbytes.len() {
        return None;
    }
    let insns = cs.disasm_count(&sbytes[off..], addr, 1).ok()?;
    let insn = insns.iter().next()?;
    let mnem = insn.mnemonic().unwrap_or("");
    let ops = insn.op_str().unwrap_or("");
    let size = insn.bytes().len() as u64;
    if size == 0 {
        return None;
    }
    let flow = classify(mnem);
    let target = match flow {
        Flow::Jump | Flow::CondJump | Flow::Call => parse_target(ops),
        _ => None,
    };
    let text = if ops.is_empty() { mnem.to_string() } else { format!("{mnem} {ops}") };
    Some(Instr { addr, size, text, flow, target })
}

// Classify an x86 mnemonic. (All mnemonics starting with 'j' except "jmp" are
// conditional jumps; "loop*" branch conditionally too.)
pub(crate) fn classify(mnem: &str) -> Flow {
    if mnem == "ret" || mnem == "retn" || mnem == "retf" || mnem.starts_with("iret") {
        Flow::Return
    } else if mnem == "call" || mnem == "lcall" {
        Flow::Call
    } else if mnem == "jmp" || mnem == "ljmp" {
        Flow::Jump
    } else if mnem.starts_with('j') || mnem.starts_with("loop") {
        Flow::CondJump
    } else {
        Flow::Normal
    }
}

// A direct branch/call renders its target as a bare hex address in the operand
// string (e.g. "0x401020"); indirect ones (a register/memory) do not parse.
pub(crate) fn parse_target(ops: &str) -> Option<u64> {
    ops.trim().strip_prefix("0x").and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

impl Cfg {
    pub fn instruction_count(&self) -> usize {
        self.instrs.len()
    }
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    // Readable text listing: each block, its instructions, and its out-edges.
    // `syms` turns `call 0x401234` into `call 0x401234  ; KERNEL32!VirtualAlloc`,
    // which is the difference between reading addresses and reading behaviour.
    pub fn to_text<W: Write>(&self, w: &mut W, syms: Option<&Symbols>) -> io::Result<()> {
        let index: BTreeMap<u64, usize> =
            self.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let title = syms
            .and_then(|s| s.label_at(self.func))
            .map(|l| format!("  {}", l.text()))
            .unwrap_or_default();
        writeln!(
            w,
            "function {:#x}{title}  ({} instruction(s), {} basic block(s))\n",
            self.func,
            self.instrs.len(),
            self.blocks.len()
        )?;
        for (i, b) in self.blocks.iter().enumerate() {
            let tag = if b.start == self.func { "  (entry)" } else { "" };
            writeln!(w, "[block {i}] {:#x}{tag}", b.start)?;
            for &a in &b.addrs {
                let ins = &self.instrs[&a];
                match self.annotate(ins, syms) {
                    Some(note) => writeln!(w, "    {:#010x}  {:<38} ; {note}", a, ins.text)?,
                    None => writeln!(w, "    {:#010x}  {}", a, ins.text)?,
                }
            }
            if b.succ.is_empty() {
                writeln!(w, "    -> (end)")?;
            } else {
                let parts: Vec<String> = b
                    .succ
                    .iter()
                    .map(|(t, label)| {
                        let dest = match index.get(t) {
                            Some(j) => format!("block {j} ({t:#x})"),
                            None => format!("{t:#x} (external)"),
                        };
                        if label.is_empty() { format!("-> {dest}") } else { format!("-> {dest} [{label}]") }
                    })
                    .collect();
                writeln!(w, "    {}", parts.join("   "))?;
            }
            writeln!(w)?;
        }
        Ok(())
    }

    // An API name for a call/jump that reaches an import, or a label for one
    // that reaches a known function.
    fn annotate(&self, ins: &Instr, syms: Option<&Symbols>) -> Option<String> {
        let syms = syms?;
        if !matches!(ins.flow, Flow::Call | Flow::Jump) {
            return None;
        }
        let ops = ins.text.split_once(' ').map(|(_, o)| o).unwrap_or("");
        match syms.classify_call(ops, ins.addr + ins.size) {
            CallTarget::Import(api) => Some(api),
            CallTarget::Code(t) => syms.label_at(t).map(|l| l.text()),
            CallTarget::Unknown => None,
        }
    }

    // Graphviz DOT: one box per block (its disassembly), edges labeled. Render with
    //   sma cfg <file> --dot > f.dot && dot -Tpng f.dot -o f.png
    pub fn to_dot<W: Write>(&self, w: &mut W, syms: Option<&Symbols>) -> io::Result<()> {
        let starts: BTreeSet<u64> = self.blocks.iter().map(|b| b.start).collect();
        let title = syms
            .and_then(|s| s.label_at(self.func))
            .map(|l| format!("  {}", l.text()))
            .unwrap_or_default();
        writeln!(w, "digraph cfg {{")?;
        writeln!(w, "  labelloc=\"t\";")?;
        writeln!(w, "  label=\"CFG of function {:#x}{}\";", self.func, dot_escape(&title))?;
        writeln!(w, "  node [shape=box, fontname=\"monospace\", fontsize=10];")?;

        for b in &self.blocks {
            let mut label = format!("{:#x}\\l", b.start);
            for &a in &b.addrs {
                let ins = &self.instrs[&a];
                match self.annotate(ins, syms) {
                    Some(note) => label.push_str(&format!(
                        "{:#x}  {}  ; {}\\l",
                        a,
                        dot_escape(&ins.text),
                        dot_escape(&note)
                    )),
                    None => label.push_str(&format!("{:#x}  {}\\l", a, dot_escape(&ins.text))),
                }
            }
            // Highlight the entry block so the graph reads top-down.
            let style = if b.start == self.func { ", style=filled, fillcolor=\"#d0e0ff\"" } else { "" };
            writeln!(w, "  \"{:#x}\" [label=\"{label}\"{style}];", b.start)?;
        }
        for b in &self.blocks {
            for (t, lab) in &b.succ {
                let attrs = if lab.is_empty() { String::new() } else { format!(" [label=\"{lab}\"]") };
                if starts.contains(t) {
                    writeln!(w, "  \"{:#x}\" -> \"{t:#x}\"{attrs};", b.start)?;
                } else {
                    // Target outside this function (tail call / jump table): a stub node.
                    writeln!(w, "  \"ext_{t:#x}\" [shape=oval, style=dashed, label=\"{t:#x}\\n(external)\"];")?;
                    writeln!(w, "  \"{:#x}\" -> \"ext_{t:#x}\"{attrs};", b.start)?;
                }
            }
        }
        writeln!(w, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{Binary, Format, Section};
    use crate::strings::StringScan;

    // Wrap raw code bytes in a one-section x86-64 Binary loaded at `base`.
    fn code_binary(code: &[u8], base: u64) -> (Vec<u8>, Binary) {
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
            image_base: 0,
            sections: vec![sec],
            imports: vec![],
            exports: vec![],
            overlay: None,
            pe_meta: None,
            strings: StringScan::default(),
        };
        (code.to_vec(), bin)
    }

    #[test]
    fn conditional_branch_makes_three_blocks() {
        // test rcx,rcx | je +3 | mov al,1 | ret | mov al,0 | ret
        // A diamond with no join: entry splits into two ret-terminated blocks.
        let code = [0x48, 0x85, 0xc9, 0x74, 0x03, 0xb0, 0x01, 0xc3, 0xb0, 0x00, 0xc3];
        let (file, bin) = code_binary(&code, 0x1000);
        let g = build(&file, &bin, None).unwrap();

        assert_eq!(g.instruction_count(), 6); // test, je, mov, ret, mov, ret
        assert_eq!(g.block_count(), 3);

        // Entry block ends in a conditional jump => two successors.
        let entry = g.blocks.iter().find(|b| b.start == 0x1000).unwrap();
        assert_eq!(entry.succ.len(), 2);
        assert!(entry.succ.iter().any(|(t, _)| *t == 0x1008)); // taken target
        assert!(entry.succ.iter().any(|(t, _)| *t == 0x1005)); // fall-through

        // Both other blocks end in ret => no successors.
        for b in g.blocks.iter().filter(|b| b.start != 0x1000) {
            assert!(b.succ.is_empty());
        }
    }

    #[test]
    fn straight_line_is_one_block() {
        // xor eax,eax | ret
        let code = [0x31, 0xc0, 0xc3];
        let (file, bin) = code_binary(&code, 0x2000);
        let g = build(&file, &bin, None).unwrap();
        assert_eq!(g.block_count(), 1);
        assert_eq!(g.instruction_count(), 2);
    }
}
