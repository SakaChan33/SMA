// The function inventory -- what `sma functions` prints.
//
// This used to be `-d --calls`, which named the mechanism (scan for `call`
// instructions) rather than the product. The product is a list of addresses
// worth disassembling, and the mechanism was also incomplete: seeding only from
// call targets misses the entry point, exported functions, and TLS callbacks --
// precisely where code goes when its author would rather you didn't follow a
// call chain to find it.
//
// Two things here are approximate, and both are labelled in the output rather
// than smoothed over:
//
//   * Function boundaries. A "function" is a seed address; where it ends is
//     whatever the next seed is. Real boundaries need per-function control-flow
//     analysis, which `sma cfg` does for one function at a time.
//   * API attribution. Each resolved import call is attributed to the greatest
//     seed at or below the call site. Inlined code and data interleaved with
//     code both make this wrong at the edges.
//
// Both are fine for the job: deciding which address to look at next.

use crate::binary::Binary;
use crate::cfg::{classify, new_capstone, parse_target, x86_mode, Flow};
use crate::symbols::{CallTarget, Label, Symbols};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

// Attribution pairs we're willing to hold. Generous for real binaries, and a
// backstop against a degenerate file that is one enormous call table.
const MAX_TRACKED_CALLS: usize = 200_000;
const APIS_SHOWN: usize = 4;

pub struct Function {
    pub rva: u64,
    // Direct call sites targeting this address. None for a seed that nothing
    // calls -- an entry point or export is reached from outside the image.
    pub calls: u64,
    pub label: Option<Label>,
    // Imports reached from inside this function (approximate; see above).
    pub apis: Vec<String>,
}

pub struct Inventory {
    pub functions: Vec<Function>,
    // Resolved API -> how many direct call sites reach it, most-called first.
    pub api_calls: Vec<(String, u64)>,
    // Imported, but no call site in the sweep reaches it.
    pub uncalled: Vec<String>,
    // Calls to a literal code address.
    pub direct_calls: u64,
    // Calls that reach an imported API, whether through a thunk or straight
    // through an IAT slot.
    pub import_calls: u64,
    // `call rax`, `call [rbx+rcx*8]`: no statically knowable target. A high
    // ratio here is the signature of a virtual-heavy C++ binary or of
    // deliberate indirection, and it bounds how much this view can see.
    pub indirect_calls: u64,
    pub imported_total: usize,
    pub truncated: bool,
}

impl Inventory {
    pub fn entry_count(&self) -> usize {
        self.functions.iter().filter(|f| matches!(f.label, Some(Label::Entry))).count()
    }
    pub fn export_count(&self) -> usize {
        self.functions.iter().filter(|f| matches!(f.label, Some(Label::Export(_)))).count()
    }
    pub fn tls_count(&self) -> usize {
        self.functions.iter().filter(|f| matches!(f.label, Some(Label::TlsCallback))).count()
    }
}

pub fn discover(file: &[u8], bin: &Binary, syms: &Symbols) -> Result<Inventory, String> {
    let mode = x86_mode(bin)
        .ok_or_else(|| format!("disassembly supports x86/x86-64 only (this is {})", bin.arch))?;
    let cs = new_capstone(mode).map_err(|e| e.to_string())?;

    let mut targets: BTreeMap<u64, u64> = BTreeMap::new(); // code call target -> count
    let mut resolving: Vec<(u64, String)> = Vec::new(); // (call site, API it reaches)
    let mut api_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut direct_calls: u64 = 0;
    let mut import_calls: u64 = 0;
    let mut indirect_calls: u64 = 0;
    let mut truncated = false;

    for sec in bin.sections.iter().filter(|s| s.is_executable()) {
        let bytes = sec.on_disk_bytes(file);
        if bytes.is_empty() {
            continue;
        }
        let base = sec.virtual_addr;
        let mut off = 0usize;
        while off < bytes.len() {
            let addr = base + off as u64;
            let insns = match cs.disasm_count(&bytes[off..], addr, 8192) {
                Ok(i) => i,
                Err(e) => return Err(format!("capstone: {e}")),
            };
            if insns.is_empty() {
                off += 1;
                continue;
            }
            for insn in insns.iter() {
                let mnem = insn.mnemonic().unwrap_or("");
                if classify(mnem) == Flow::Call {
                    let ops = insn.op_str().unwrap_or("");
                    let next = insn.address() + insn.bytes().len() as u64;
                    match syms.classify_call(ops, next) {
                        CallTarget::Code(t) => {
                            direct_calls += 1;
                            *targets.entry(t).or_insert(0) += 1;
                        }
                        CallTarget::Import(api) => {
                            import_calls += 1;
                            *api_counts.entry(api.clone()).or_insert(0) += 1;
                            // A direct call to a thunk still names a code
                            // address worth counting; a call straight through
                            // the IAT does not.
                            if let Some(t) = parse_target(ops) {
                                *targets.entry(t).or_insert(0) += 1;
                            }
                            if resolving.len() < MAX_TRACKED_CALLS {
                                resolving.push((insn.address(), api));
                            } else {
                                truncated = true;
                            }
                        }
                        CallTarget::Unknown => indirect_calls += 1,
                    }
                }
                off += insn.bytes().len();
            }
        }
    }

    // Seeds: everything we know is a function, from any direction. A call target
    // that resolves to an import is a thunk, not a function worth listing --
    // it's counted in `api_calls` instead.
    let mut seeds: BTreeSet<u64> = BTreeSet::new();
    seeds.insert(bin.entry_point);
    for &cb in bin.tls_callbacks() {
        seeds.insert(cb);
    }
    for e in &bin.exports {
        if e.forwarder.is_none() {
            seeds.insert(e.rva);
        }
    }
    for &t in targets.keys() {
        if in_executable(bin, t) && syms.describe(t).is_none() {
            seeds.insert(t);
        }
    }
    // A seed with no bytes on disk can't be disassembled, so don't offer it.
    seeds.retain(|&s| bin.va_to_file_offset(s).is_some());

    // Attribute each resolved call to the nearest seed at or below it.
    let ordered: Vec<u64> = seeds.iter().copied().collect();
    let mut per_function: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for (site, api) in resolving {
        if let Some(owner) = nearest_seed(&ordered, site) {
            per_function.entry(owner).or_default().insert(api);
        }
    }

    let mut api_calls: Vec<(String, u64)> = api_counts.into_iter().collect();
    api_calls.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Imports the sweep never saw reached. An observation, not an accusation:
    // delay-loaded imports, callees reached only through computed calls, and
    // genuinely unused declarations all land here, and so does an import table
    // padded to look ordinary. Which one it is, is the analyst's call.
    let called: BTreeSet<&str> = api_calls.iter().map(|(n, _)| n.as_str()).collect();
    let mut uncalled: Vec<String> = bin
        .imports
        .iter()
        .flat_map(|imp| {
            imp.names().map(move |n| crate::symbols::qualified_name(&imp.dll, n))
        })
        .filter(|q| !called.contains(q.as_str()))
        .collect();
    uncalled.sort();
    uncalled.dedup();

    let functions = ordered
        .iter()
        .map(|&rva| Function {
            rva,
            calls: targets.get(&rva).copied().unwrap_or(0),
            label: syms.label_at(rva).cloned(),
            apis: per_function.remove(&rva).map(|s| s.into_iter().collect()).unwrap_or_default(),
        })
        .collect();

    Ok(Inventory {
        functions,
        api_calls,
        uncalled,
        direct_calls,
        import_calls,
        indirect_calls,
        imported_total: bin.total_imported_functions(),
        truncated,
    })
}

// The greatest seed at or below `site` -- our stand-in for "the function this
// instruction is inside of".
fn nearest_seed(ordered: &[u64], site: u64) -> Option<u64> {
    match ordered.binary_search(&site) {
        Ok(i) => Some(ordered[i]),
        Err(0) => None, // before the first seed: no owner we can name
        Err(i) => Some(ordered[i - 1]),
    }
}

fn in_executable(bin: &Binary, addr: u64) -> bool {
    bin.section_at(addr).is_some_and(|s| s.is_executable())
}

pub fn write_text<W: Write>(w: &mut W, inv: &Inventory) -> io::Result<()> {
    writeln!(
        w,
        "functions      : {} discovered  ({} entry, {} export(s), {} TLS callback(s))",
        inv.functions.len(),
        inv.entry_count(),
        inv.export_count(),
        inv.tls_count()
    )?;
    writeln!(
        w,
        "call sites     : {} to code, {} to imported APIs, {} computed at runtime",
        inv.direct_calls, inv.import_calls, inv.indirect_calls
    )?;
    writeln!(w)?;

    writeln!(w, "  {:<10} {:>7}  {:<20} reaches (imported APIs)", "rva", "calls", "label")?;
    for f in &inv.functions {
        let calls = if f.calls == 0 { "-".to_string() } else { f.calls.to_string() };
        let label = f.label.as_ref().map(|l| l.text()).unwrap_or_else(|| "-".to_string());
        let shown: Vec<&str> = f.apis.iter().take(APIS_SHOWN).map(|s| s.as_str()).collect();
        let more = if f.apis.len() > APIS_SHOWN {
            format!("  (+{} more)", f.apis.len() - APIS_SHOWN)
        } else {
            String::new()
        };
        writeln!(w, "  {:#010x} {calls:>7}  {label:<20} {}{more}", f.rva, shown.join(", "))?;
    }
    writeln!(w)?;

    if inv.api_calls.is_empty() {
        writeln!(w, "APIs called    : none resolved from the code")?;
        writeln!(
            w,
            "                 imports are declared but no call reaches them statically -- see the\n\
             \x20                'limits' section of `sma scan`"
        )?;
    } else {
        writeln!(
            w,
            "APIs called    : {} of {} imported function(s) are reached by a resolvable call",
            inv.api_calls.len(),
            inv.imported_total
        )?;
        for (name, count) in &inv.api_calls {
            writeln!(w, "  {count:>6}  {name}")?;
        }
    }
    writeln!(w)?;

    // The complement. Listed in full, because "declared but never reached" is
    // the kind of thing that only matters once you can see the whole set.
    if inv.uncalled.is_empty() {
        writeln!(w, "never called   : none -- every import is reached by a resolvable call")?;
    } else {
        writeln!(
            w,
            "never called   : {} import(s) declared but never reached by any call site found here",
            inv.uncalled.len()
        )?;
        writeln!(
            w,
            "                 delay-loading, computed calls, dead declarations and padding all\n\
             \x20                look like this. it is an observation, not an accusation."
        )?;
        for name in &inv.uncalled {
            writeln!(w, "      {name}")?;
        }
    }
    writeln!(w)?;

    // The one limit whose evidence is measured here rather than in `scan`.
    if let Some(l) = crate::limits::call_graph_limit(
        inv.direct_calls + inv.import_calls,
        inv.indirect_calls,
    ) {
        crate::limits::write(w, &[l])?;
        writeln!(w)?;
    }

    if inv.truncated {
        writeln!(w, "note           : call attribution was truncated at {MAX_TRACKED_CALLS} sites")?;
    }
    writeln!(w, "  inspect any function:  sma cfg <file> --addr <rva>")?;
    writeln!(
        w,
        "  function boundaries and API attribution are approximate: a function starts at a\n\
         \x20 known address and is assumed to run until the next one."
    )
}

pub fn write_json<W: Write>(w: &mut W, path: &str, inv: &Inventory) -> io::Result<()> {
    let q = crate::json::quote;
    writeln!(w, "{{")?;
    writeln!(w, "  \"file\": {},", q(path))?;
    writeln!(w, "  \"code_calls\": {},", inv.direct_calls)?;
    writeln!(w, "  \"import_calls\": {},", inv.import_calls)?;
    writeln!(w, "  \"indirect_calls\": {},", inv.indirect_calls)?;
    writeln!(w, "  \"imported_functions\": {},", inv.imported_total)?;
    writeln!(w, "  \"attribution\": \"approximate\",")?;
    writeln!(w, "  \"functions\": [")?;
    for (i, f) in inv.functions.iter().enumerate() {
        let comma = if i + 1 < inv.functions.len() { "," } else { "" };
        let label = match &f.label {
            Some(Label::Entry) => q("entry"),
            Some(Label::Export(n)) => q(&format!("export:{n}")),
            Some(Label::TlsCallback) => q("tls_callback"),
            None => "null".to_string(),
        };
        let apis: Vec<String> = f.apis.iter().map(|a| q(a)).collect();
        writeln!(
            w,
            "    {{\"rva\": {}, \"calls\": {}, \"label\": {label}, \"reaches\": [{}]}}{comma}",
            f.rva,
            f.calls,
            apis.join(", ")
        )?;
    }
    writeln!(w, "  ],")?;
    writeln!(w, "  \"api_calls\": [")?;
    for (i, (name, count)) in inv.api_calls.iter().enumerate() {
        let comma = if i + 1 < inv.api_calls.len() { "," } else { "" };
        writeln!(w, "    {{\"api\": {}, \"call_sites\": {count}}}{comma}", q(name))?;
    }
    writeln!(w, "  ],")?;
    let uncalled: Vec<String> = inv.uncalled.iter().map(|n| q(n)).collect();
    writeln!(w, "  \"never_called\": [{}]", uncalled.join(", "))?;
    writeln!(w, "}}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_seed_finds_the_enclosing_function() {
        let seeds = [0x1000u64, 0x1100, 0x1200];
        assert_eq!(nearest_seed(&seeds, 0x1000), Some(0x1000)); // exactly on a seed
        assert_eq!(nearest_seed(&seeds, 0x1050), Some(0x1000)); // inside the first
        assert_eq!(nearest_seed(&seeds, 0x1100), Some(0x1100)); // on the second
        assert_eq!(nearest_seed(&seeds, 0x9999), Some(0x1200)); // after the last
        assert_eq!(nearest_seed(&seeds, 0x0900), None); // before any seed
        assert_eq!(nearest_seed(&[], 0x1000), None);
    }
}
