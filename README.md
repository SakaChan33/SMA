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
| **In scope** | PE (Windows) first; ELF (Linux) second; Mach-O stubbed. Feature extraction + a rule/score-based maliciousness estimate. |
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
| **M8** | Machine-readable JSON report (+ optional HTML) | machine-readable reports |
| **M9** | Plugin architecture (analyzers as plugins) | extensibility |
| **M10** | **Evaluation:** run over labeled dataset → precision/recall/F1, ROC/AUC vs. baseline; document false positives + limits |

**Status:** M0–M8 complete — PE parser, entropy, imports, suspicious-API rules,
strings + IOCs, a **format-abstraction layer with ELF support** (one `sma`
analyzes both Windows PE and Linux ELF), a **disassembler + control-flow graph**
(`sma -d`, text or Graphviz DOT, built on Capstone), and a **machine-readable JSON
report** (`sma --json`) for the evaluation pipeline. M9 (plugin architecture) is next.

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

### Modes

One binary, several analysis modes (scan and disassemble are implemented; debug
is declared so the interface is stable as the project grows):

```
sma [MODE] <path-to-exe> [options]

  -s, --scan           static report (default): headers, entropy, imports,
                       capabilities, strings/IOCs
  -d, --disassemble    build a function's control-flow graph (CFG)
  -b, --debug          dynamic / debug analysis                 [planned: future]
  -h, --help           show help

scan options:
  -f, --full           also print the COMPLETE hex of the headers and every
                       section to stdout (massive; redirect it to a file)
      --dump-sections <dir>   write per-section hex files (see below)

disassemble options:
      --addr <hex>     function start address (default: the entry point)
      --dot            emit Graphviz DOT instead of a text listing
```

### Examples

```sh
sma -s "C:/Windows/System32/notepad.exe"                 # or just: sma <path>
sma "C:/Windows/explorer.exe" | grep -A20 '^capabilities' # pipe like any Unix tool
sma "C:/Windows/System32/cmd.exe" > data/cmd.exe.analysis.txt     # save a report
sma --json "C:/Windows/System32/notepad.exe" > data/notepad.json  # machine-readable (M8)

# -f appends the ENTIRE hex of every section to the report. Redirect to a file:
sma -s -f "C:/path/to/big.exe" > output/big.full.txt      # e.g. 223 MB exe -> ~1 GB text

# -d builds a function's control-flow graph (default: the entry point).
sma -d "C:/Windows/System32/cmd.exe"                      # readable text CFG (one function)
sma -d "C:/Windows/System32/cmd.exe" --dot > cfg.dot      # Graphviz; dot -Tpng cfg.dot -o cfg.png
sma -d "C:/Windows/System32/cmd.exe" --addr 0x27c54       # a specific function

# --all linear-disassembles the WHOLE program (every function). Redirect to a file:
sma -d --all "C:/path/to/app.exe" > output/app.disassembled.txt   # can be multi-GB

# --calls lists the program's call targets (function RVAs + how often called),
# so you can jump to any one with --addr:
sma -d --calls "C:/path/to/app.exe" > output/app.calls.txt
sma -d --addr 0x509e900 "C:/path/to/app.exe"   # inspect one function from that list
```

The CFG (`-d`) shows *one function* with its branch/loop structure; `--all` shows
*every* instruction in every executable section, flat (like `objdump -d`).

The full hex is *streamed* (constant memory), so even a 200 MB+ binary dumps in a
few seconds when redirected to a file. Piping it through another program in a
Git-Bash/MSYS shell is much slower (small pipe buffers) — redirect to a file.

**Full hex, per section** — stdout stays the generalized report; the raw bytes go
to separate files (one per section + a headers file), each with that section's
specifics (entropy, flags, sizes, RVA) followed by its **complete** hex dump:

```sh
sma <path> --dump-sections output/ > output/<name>.analysis.txt
```

Writes `output/<name>.headers.txt` and `output/<name>.section-NN-<name>.txt`.
Note: a section's hex file is ~10× its raw size, so dumping a very large binary's
`.text` (e.g. an Electron app) can produce a multi-hundred-MB file.

### What the scan report shows

Five parts, one per milestone: PE header summary (M1), per-section **entropy** +
packing results (M2), **imports** (M3), **capability findings** with severities
(M4), and **strings + IOCs** (M5). A finding is a *reason to look closer*, never definitive
— benign software trips these rules constantly.

---

## Layout

```
static_malware_analysus/
  README.md         ← you are here
  src/              MY implementation (Rust)
  Cargo.toml
```

## Software Artifact

## Research Artifact

## Experimental Results

## Contribution

This work does not attempt to replace mature reverse engineering frameworks such as Ghidra or IDA.

Instead, it provides a reproducible experimental platform for extracting static executable features and evaluating how well those features predict maliciousness.

The implementation exists to answer the research question through controlled experimentation.

## Stuff to Include

These are some additional questions to consider. Not necessarily for research purposes, but for the artifact and the reader themselves.

- How many lines of Rust?
- How many modules?
- How many executable formats?
- How many APIs are recognized?
- How many heuristics?
- How many IOC types?
- What parser architecture?
- What crates are used?
- Performance?
