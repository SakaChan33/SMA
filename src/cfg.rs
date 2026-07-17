use crate::binary::Binary;
use capstone::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

// How a single instruction affects control flow.
#[derive(Clone, Copy, PartialEq)]
enum Flow {
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
fn x86_mode(bin: &Binary) -> Option<arch::x86::ArchMode> {
    if bin.arch.contains("x86-64") || bin.arch.contains("AMD64") {
        Some(arch::x86::ArchMode::Mode64)
    } else if bin.arch.contains("x86") || bin.arch.contains("I386") {
        Some(arch::x86::ArchMode::Mode32)
    } else {
        None
    }
}

// `-d --all`: LINEAR disassembly of every executable section, top to bottom --
// the entire program's code, not just one function. Streamed instruction-by-
// instruction (bounded memory) so it works regardless of file size, even a
// 172 MB `.text`. Undecodable bytes are emitted as `.byte` and skipped, the way
// objdump prints `(bad)`. Returns the instruction count.
pub fn disassemble_all<W: Write>(file: &[u8], bin: &Binary, w: &mut W) -> io::Result<u64> {
    let mode = x86_mode(bin).ok_or_else(|| {
        io::Error::other(format!("disassembly supports x86/x86-64 only (this is {})", bin.arch))
    })?;
    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .map_err(|e| io::Error::other(format!("capstone init failed: {e}")))?;

    let mut count: u64 = 0;
    for sec in bin.sections.iter().filter(|s| s.is_executable()) {
        let bytes = sec.on_disk_bytes(file);
        if bytes.is_empty() {
            continue;
        }
        let base = sec.virtual_addr;
        let name = if sec.name.is_empty() { "(unnamed)" } else { &sec.name };
        writeln!(w, "\n== section {name}  (addr {base:#x}, {} bytes) ==", bytes.len())?;

        // Decode in batches so we never hold the whole section's instructions in
        // memory at once.
        let mut off = 0usize;
        while off < bytes.len() {
            let addr = base + off as u64;
            let insns = cs
                .disasm_count(&bytes[off..], addr, 8192)
                .map_err(|e| io::Error::other(format!("capstone: {e}")))?;
            if insns.is_empty() {
                // A byte we can't decode (data, padding, or a truncated tail).
                writeln!(w, "{addr:#012x}  {:02x}          .byte (bad)", bytes[off])?;
                off += 1;
                continue;
            }
            for insn in insns.iter() {
                let m = insn.mnemonic().unwrap_or("");
                let o = insn.op_str().unwrap_or("");
                if o.is_empty() {
                    writeln!(w, "{:#012x}  {m}", insn.address())?;
                } else {
                    writeln!(w, "{:#012x}  {m} {o}", insn.address())?;
                }
                off += insn.bytes().len();
                count += 1;
            }
        }
    }
    Ok(count)
}

// `-d --calls`: the program's call graph as a list. Linear-sweeps every
// executable section, collects every DIRECT `call` target (an indirect
// `call rax` has no static target), and prints each unique target address with
// how many times it's called -- i.e. a list of the program's functions, sorted
// by address. Each in-code target can then be inspected with `-d --addr <rva>`.
pub fn list_calls<W: Write>(file: &[u8], bin: &Binary, w: &mut W) -> io::Result<u64> {
    let mode = x86_mode(bin).ok_or_else(|| {
        io::Error::other(format!("disassembly supports x86/x86-64 only (this is {})", bin.arch))
    })?;
    let cs = Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(false)
        .build()
        .map_err(|e| io::Error::other(format!("capstone init failed: {e}")))?;

    // BTreeMap keeps targets sorted by address for free.
    let mut targets: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut call_sites: u64 = 0;

    for sec in bin.sections.iter().filter(|s| s.is_executable()) {
        let bytes = sec.on_disk_bytes(file);
        if bytes.is_empty() {
            continue;
        }
        let base = sec.virtual_addr;
        let mut off = 0usize;
        while off < bytes.len() {
            let addr = base + off as u64;
            let insns = cs
                .disasm_count(&bytes[off..], addr, 8192)
                .map_err(|e| io::Error::other(format!("capstone: {e}")))?;
            if insns.is_empty() {
                off += 1;
                continue;
            }
            for insn in insns.iter() {
                let m = insn.mnemonic().unwrap_or("");
                if m == "call" || m == "lcall" {
                    if let Some(t) = parse_target(insn.op_str().unwrap_or("")) {
                        *targets.entry(t).or_insert(0) += 1;
                        call_sites += 1;
                    }
                }
                off += insn.bytes().len();
            }
        }
    }

    let is_in_code = |addr: u64| {
        bin.sections.iter().any(|s| {
            s.is_executable() && (s.virtual_addr..s.virtual_addr + s.virtual_size.max(s.file_size)).contains(&addr)
        })
    };

    writeln!(w, "call graph: {} unique target(s), {call_sites} direct call site(s)\n", targets.len())?;
    writeln!(w, "  {:<14}  {:>9}   where", "target (RVA)", "call(s)")?;
    for (addr, count) in &targets {
        let note = if is_in_code(*addr) {
            "in code  ->  sma -d --addr <this rva>"
        } else {
            "outside code (import thunk / data)"
        };
        writeln!(w, "  {addr:#012x}  {count:>9}   {note}")?;
    }
    Ok(targets.len() as u64)
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
fn classify(mnem: &str) -> Flow {
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
fn parse_target(ops: &str) -> Option<u64> {
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
    pub fn to_text<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let index: BTreeMap<u64, usize> =
            self.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        writeln!(
            w,
            "function {:#x}  ({} instruction(s), {} basic block(s))\n",
            self.func,
            self.instrs.len(),
            self.blocks.len()
        )?;
        for (i, b) in self.blocks.iter().enumerate() {
            let tag = if b.start == self.func { "  (entry)" } else { "" };
            writeln!(w, "[block {i}] {:#x}{tag}", b.start)?;
            for &a in &b.addrs {
                writeln!(w, "    {:#010x}  {}", a, self.instrs[&a].text)?;
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

    // Graphviz DOT: one box per block (its disassembly), edges labeled. Render with
    //   sma -d <file> --dot > f.dot && dot -Tpng f.dot -o f.png
    pub fn to_dot<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let starts: BTreeSet<u64> = self.blocks.iter().map(|b| b.start).collect();
        writeln!(w, "digraph cfg {{")?;
        writeln!(w, "  labelloc=\"t\";")?;
        writeln!(w, "  label=\"CFG of function {:#x}\";", self.func)?;
        writeln!(w, "  node [shape=box, fontname=\"monospace\", fontsize=10];")?;

        for b in &self.blocks {
            let mut label = format!("{:#x}\\l", b.start);
            for &a in &b.addrs {
                label.push_str(&format!("{:#x}  {}\\l", a, dot_escape(&self.instrs[&a].text)));
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
