# Static Malware Analysis Framework

Current Works-in-Progress

Last Edited: 2026-07-17

---

What is the primary research question?

> **Primary research question:** *To what extent can static features of executable
> binaries distinguish malicious from benign software — and under what adversarial
> conditions does that distinction break down?*

This work investigates whether structural and semantic features extracted
**without executing** a program — headers, per-section entropy, imports,
suspicious-API combinations, embedded strings/IOCs, and control-flow structure —
provide sufficient evidence to classify an executable as malicious or benign, and
characterizes the adversarial conditions (packing, obfuscation, import hiding)
under which purely static evidence becomes insufficient. It positions static
analysis as a **triage layer that ranks suspicion cheaply**, not a definitive
classifier.

The fourteen questions below are **sub-questions** of this one — each milestone
extracts a feature that becomes a variable in the same experiment (which features
separate the classes best, which cause false positives, which malware resists
static analysis, and where the technique fails).

Questions to Consider:

1. How accurately can static characteristics of an executable distinguish malicious software from benign software?
This is the classic classification question and is broad enough to support an entire thesis.

2. Which static features contribute most to malware classification accuracy?
Investigates feature importance rather than simply building a detector.

3. To what extent can import-table analysis alone predict whether a PE executable is malicious?
Focuses on one commonly used static technique.

4. How effective is entropy analysis as an indicator of packed or obfuscated malware?
Evaluates the strengths and weaknesses of entropy-based heuristics.

5. Can combinations of static heuristics outperform individual heuristics for malware detection?
Studies whether multiple weak signals become a stronger classifier.

6. How resilient are static-analysis techniques against common malware obfuscation methods?
Examines the limitations of static analysis when attackers deliberately hide behavior.

7. What is the relationship between executable metadata and malicious classification accuracy?
Looks at timestamps, section names, compiler artifacts, certificates, resources, version information, and similar metadata.

8. How accurately can suspicious API usage predict malicious functionality?
Measures whether API-based heuristics correlate with malicious behavior.

9. To what extent can embedded strings and indicators of compromise improve static malware classification?
Evaluates URLs, registry paths, mutex names, IP addresses, domain names, and other embedded artifacts.

10. How does rule-based static malware classification compare with statistical or machine-learning approaches using the same extracted features?
A strong comparative research question if you decide to include a simple ML baseline.

11. What types of malware are most difficult to distinguish using static analysis alone?
Explores ransomware, stealers, droppers, loaders, RATs, miners, etc.

12. How does executable packing influence the reliability of static malware analysis?
A focused study on one of the biggest challenges in static analysis.

13. What are the primary causes of false positives and false negatives in static malware detection?
This often produces valuable research because understanding failures is as important as reporting accuracy.

14. Can explainable heuristic scoring improve analyst understanding without significantly reducing detection performance?
Investigates interpretability, which is increasingly important in cybersecurity tools.

15. What are the practical limits of static malware analysis, and when should dynamic analysis become necessary?
This provides an opportunity to discuss where static analysis succeeds and where it fundamentally cannot answer certain questions.

A framework that extracts meaningful features from executable binaries **without
running them**, to support malware triage and behavioral prediction.

---

- **Implementation:** (`src/`) is the primary research artifact, a Rust command-line tool that parses PE and ELF binaries,
extracts features, and produces a structured report. It is designed to be *safe* (never executes the sample) and *deterministic* (same input always yields the same output).

- **Language:** Rust — a malware parser consumes hostile, malformed input, so a
  memory-safe language that *cannot itself be exploited by a crafted binary* is
  the correct engineering choice. That argument is part of the research story.

---

## Why "static"? (and why that's safe)

**Static analysis** inspects the *bytes and structure* of a program — headers,
sections, imported functions, embedded strings, code layout — **without ever
executing it**. The opposite, *dynamic analysis*, runs the sample in a sandbox
and watches its behavior.

Static analysis is the right first project because:

- **It is safe.** We never execute a sample, so no VM, sandbox, or isolated lab
  is required. Malformed input can crash a *parser*, but Rust contains that.

- **It is deterministic.** The same file always yields the same features —
  perfect for reproducible experiments.

- **It is fast.** Milliseconds per file, so we can evaluate over large datasets.

The tradeoff — which I *measure*, not hide — is that packing, encryption,
and obfuscation can defeat static features. However, it is precisely *those failures*
that create suspicion and motivate further analysis. Quantifying exactly *when* static
analysis fails is a core research contribution of this project.

Early analysis shows that static features are surprisingly predictive. Even legitimate software 
often trip the same heuristics as malware. This makes static analysis a *triage tool* rather than
a definitive classifier. Static Malware Analysis (SMA) can quickly idenitify suspicious executables
for further inspection, but it will never be 100% accurate.

---

## Threat model & scope

| Aspect | Decision |
|---|---|
| **Adversary** | Author of a potentially-malicious executable trying to evade *static* detection (packing, obfuscation, import hiding). |
| **In scope** | PE (Windows) first; ELF (Linux) second. Feature extraction, rule-based capability findings, and an explicit statement of where static evidence runs out. |
| **Out of scope** | Executing samples, kernel/driver analysis, full decompilation, network C2 interaction. |
| **Trust boundary** | Every input byte is **untrusted**. The parser must never panic or read out of bounds on hostile input — this is a security property we test. |

---

## Milestones

| M | Deliverable | Maps to research |
|---|---|---|
| **M0** | Research scaffold: this README, threat model, sample policy, docs templates | framing, reproducibility |
| **M1** | PE parser (DOS → NT headers → sections) → structured output | parse executable formats |
| **M2** | Per-section Shannon entropy → packing heuristic | entropy, packer detection |
| **M3** | Import table extraction (DLLs + APIs) | imported libraries/APIs |
| **M4** | Suspicious-API rules (injection, anti-debug, persistence, net, crypto) | suspicious API usage |
| **M5** | String + IOC extraction (URLs, IPs, registry keys) | recover embedded strings |
| **M6** | Format-abstraction layer → add ELF | multi-platform abstraction |
| **M7** | Control-Flow Graph for a function → Graphviz | CFG construction + viz |
| **M8** | Machine-readable JSON report | machine-readable reports |
| **M9** | Plugin architecture (analyzers as plugins) | extensibility |
| **M10** | **Evaluation:** run over labeled dataset → precision/recall/F1, ROC/AUC vs. baseline; document false positives + limits |

**Status:** M0–M8 complete. PE and ELF parsers, per-section entropy, imports,
suspicious-API rules, strings + IOCs, a disassembler and control-flow graph built
on Capstone, and a machine-readable JSON report for the evaluation pipeline.

Beyond the original M1–M8 the tool now also resolves **imports to the code that
calls them** — a call target is reported as `KERNEL32!VirtualAllocEx`, not as a
bare address — surfaces the **PE metadata** that answers research question 7
(build timestamp, subsystem, mitigations, exports, TLS callbacks, signature
presence, overlay), and closes every report with a **`limits` section** stating
what static analysis could not resolve in that specific sample and which
technique takes over. That last part is research question 15 answered per-file
instead of in the abstract.

M9 (plugin architecture) is next.

---

## Usage

`sma` is a **command-line tool**: you run it from a terminal, hand it one file
path, and it prints a static report to standard output. It never executes the
sample — it only reads the bytes.

### Install

**Option 1 — download a prebuilt binary (no toolchain needed).** Grab the
self-contained binary for your OS from the [Releases](../../releases) page —
`sma-windows-x86_64.exe` or `sma-linux-x86_64` — and run it. There is nothing to
install and no separate libraries: Capstone (the disassembler) is compiled into
the binary, so it's a single file.

```sh
# Windows (PowerShell): rename and run
./sma-windows-x86_64.exe --help
# Linux
chmod +x sma-linux-x86_64 && ./sma-linux-x86_64 --help
```

**Option 2 — build from source with Rust** (`rustup` + a C toolchain for
Capstone, which the build finds automatically on Windows/Linux):

```sh
cargo install --path .     # builds a release binary and puts `sma` on your PATH
sma --help                 # now callable by name from any terminal
```

(For development, `cargo run -- <args>` works from the project directory; the
built binary lands at `target/release/sma`.)

> Prebuilt binaries are produced automatically by CI: pushing a `v*` tag builds
> `sma` for Windows and Linux and attaches them to a GitHub Release
> (see `.github/workflows/release.yml`).

### Verbs

The interface follows the three questions a static analyst actually asks, in
order: *what is this and what stands out?* → *where is the interesting code?* →
*what does that code do?* One verb per question, one artifact per verb.

```
sma <verb> <file> [options]
sma <file>                       same as: sma scan <file>

  scan       triage report: headers, sections + entropy, imports, capabilities,
             strings/IOCs, and the limits of what static analysis can see here
  functions  inventory of discovered functions (entry point, exports, TLS
             callbacks, call targets) and the APIs each one reaches
  cfg        control-flow graph of one function
  disasm     flat instruction listing, like objdump -d
  hex        a window of raw bytes

scan / functions options:
      --json               machine-readable output instead of the human report

cfg options:
      --addr <hex>         function to graph (default: the entry point)
      --dot                emit Graphviz DOT instead of a text listing

disasm options:
      --addr <hex>         start here instead of listing whole sections
      --count <n>          stop after n instructions
      --section <name>     restrict to one section

hex options:
      --at <hex>           start at a virtual address (RVA)
      --section <name>     start at a section
      --headers            the header region
      --len <n>            how many bytes (default 256)

  -h, --help    -V, --version
```

A flag belongs to exactly one verb. Using it under the wrong one is an error, not
a silent no-op — `sma scan f.exe --dot` tells you `--dot` belongs to `cfg`.

### A typical session

```sh
sma scan sample.exe                    # what is this, and what stands out?
sma functions sample.exe               # where is the interesting code?
sma cfg sample.exe --addr 0x24c0       # what does that function do?

sma cfg sample.exe --addr 0x24c0 --dot > f.dot && dot -Tpng f.dot -o f.png
sma scan sample.exe --json > data/sample.json     # for the evaluation pipeline
sma disasm sample.exe --addr 0x24c0 --count 40    # a window, not the whole program
sma hex sample.exe --at 0x24c0 --len 128          # the bytes behind it
sma hex sample.exe --headers                      # the header region
```

`functions` is the bridge between the report and the disassembly: it lists every
address worth looking at, alongside the imported APIs each one reaches, so you
pick a target instead of guessing one.

```
  rva          calls  label                reaches (imported APIs)
  0x000019c0       -  [entry]
  0x000024c0       3  -                    KERNEL32!VirtualAllocEx, KERNEL32!WriteProcessMemory
  0x00002310      17  [export: Install]    ADVAPI32!RegCreateKeyExW, ADVAPI32!RegSetValueExW
```

That same resolution runs inside `cfg` and `disasm`, so a call reads as behaviour
rather than as an address:

```
    0x00001368  call qword ptr [rip + 0x29079]   ; KERNEL32!EventWriteTransfer
```

### What the scan report shows

PE/ELF header summary (M1); **build metadata** — timestamp, subsystem,
mitigations, signature, TLS callbacks, packer hints; per-section **entropy** +
packing assessment (M2); **imports** (M3) and **exports** (including forwarders);
**capability findings** with severities (M4); **strings + IOCs** (M5); any
**overlay** appended past the last section; and finally the **limits** section.

A finding is a *reason to look closer*, never definitive — benign software trips
these rules constantly, which is the point the project is making.

### The `limits` section

Every report ends by naming what static analysis could **not** resolve in that
sample, the evidence for saying so, and which technique answers it instead:

```
limits         : 2 thing(s) static analysis cannot resolve here
  cannot see   : the real import table
    because    : 3 declared import(s) alongside packed section(s) [.text] -- too few to
                 account for a working program, so the rest are resolved at runtime
    next step  : run to the original entry point, then dump the unpacked image from memory
```

This is deliberately **not** a verdict. It never scores or ranks maliciousness;
it reports where the evidence stops. Static analysis being *indicative, not
definitive* is the thesis, so the tool states its own boundary rather than
hiding it.

---

## Layout

```
SMA/
  README.md          ← you are here
  Cargo.toml         one dependency: capstone
  src/               the implementation (Rust)

    main.rs          plumbing only: parse args, read file, dispatch one view
    cli.rs           verbs, flags, and the rule that a flag belongs to one verb
    lib.rs           module list + the PE/ELF format sniffer

    reader.rs        bounds-checked little-endian reads; the trust boundary
    error.rs         every parse failure as a value, never a panic
    binary.rs        the format-neutral model (Binary/Section/Import/Export)
    pe.rs            PE/COFF: DOS → NT headers → sections → data directories
    elf.rs           ELF32/64: header → section table → dynamic symbols
    imports.rs       PE import table, including each function's IAT slot
    exports.rs       PE export directory (with forwarders) + TLS callbacks

    entropy.rs       Shannon entropy over a byte range
    packers.rs       packer identification from section names
    strings.rs       ASCII/UTF-16 extraction + IOC classification
    rules.rs         suspicious-API capability rules
    limits.rs        what static analysis could not resolve, and what takes over

    symbols.rs       names for addresses: IAT lookup + import-thunk following
    cfg.rs           Capstone disassembly, control-flow graph, linear sweep
    functions.rs     the function inventory and the APIs each one reaches

    report.rs        the human report
    json.rs          the machine-readable report
    hexdump.rs       hex output and window resolution
```

## Software Artifact

## Research Artifact

## Experimental Results

## Contribution

This work does not attempt to replace mature reverse engineering frameworks such as Ghidra or IDA.

Instead, it provides a reproducible experimental platform for extracting static executable features and evaluating how well those features predict maliciousness.

The implementation exists to answer the research question through controlled experimentation.

## Artifical Intelligence Usage

This project includes the use of Artifical Intelligence. Claude (Opus 4.8, and Opus 5 for later
revisions) was the primary AI model used to generate aspects of the program
such as the projects scaffolding, README.md (specific parts), and some code. Claude was also the model responsible for the learning
aspect of the project. Additionally, Claude was used to push the
project to Github.

## Stuff to Include

These are some additional questions to consider. Not necessarily for research purposes, but for the artifact and the reader themselves.

| Question | As of this revision |
|---|---|
| How many lines of Rust? | ~4,600 across `src/` |
| How many modules? | 21 |
| How many unit tests? | 80 |
| How many executable formats? | 2 (PE, ELF) |
| How many APIs are recognized? | 67, across 9 capability rules |
| How many heuristics? | 9 capability rules + 8 `limits` rules + 13 packer signatures |
| How many IOC types? | 4 (URL, IPv4, registry key, file path) |
| What parser architecture? | Hand-rolled, bounds-checked `ByteReader`; every parse error is a value, never a panic |
| What crates are used? | One: `capstone` (disassembly). Parsers, CLI, JSON, and graph code are std-only, on purpose |
| Performance? | Milliseconds per file; 400 System32 binaries scan without a single failure |
