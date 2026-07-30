use crate::hexdump::HexWindow;

pub const DEFAULT_HEX_LEN: usize = 256;
pub const DEFAULT_DISASM_COUNT: usize = 100; // only when --addr narrows the view

// One verb, one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // Triage report: headers, sections/entropy, imports, capabilities, IOCs, limits.
    Scan { path: String, json: bool },
    // Inventory of discovered functions and the APIs each one reaches.
    Functions { path: String, json: bool },
    // Control-flow graph of a single function.
    Cfg { path: String, addr: Option<u64>, dot: bool },
    // Flat instruction listing (whole executable sections, or a window).
    Disasm { path: String, addr: Option<u64>, count: Option<usize>, section: Option<String> },
    // A window of raw bytes.
    Hex { path: String, window: HexWindow, len: Option<usize> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    Run(Command),
    Help,
    Version,
}

const VERBS: &[&str] = &["scan", "functions", "cfg", "disasm", "hex"];

// Which verb(s) each flag belongs to. The single source of truth for the
// "wrong verb" error, so help text and validation cannot drift apart.
const FLAG_OWNERS: &[(&str, &[&str])] = &[
    ("--json", &["scan", "functions"]),
    ("--addr", &["cfg", "disasm"]),
    ("--dot", &["cfg"]),
    ("--count", &["disasm"]),
    ("--section", &["disasm", "hex"]),
    ("--at", &["hex"]),
    ("--headers", &["hex"]),
    ("--len", &["hex"]),
];

// Flags this tool used to have
// This section can be removed. Not needed. No one but me knew about the old flags. So this makes this
// extremely pointless
const RETIRED: &[(&str, &str)] = &[
    ("-s", "use: sma scan <file>"),
    ("--scan", "use: sma scan <file>"),
    ("-d", "use: sma cfg <file> (one function), or sma disasm <file> (flat listing)"),
    ("--disassemble", "use: sma cfg <file> (one function), or sma disasm <file> (flat listing)"),
    (
        "-b",
        "removed. sma is static-only by design -- use a debugger (x64dbg, WinDbg) for dynamic\n       \
         analysis. 'sma scan' now ends with a 'limits' section naming where static analysis stops.",
    ),
    (
        "--debug",
        "removed. sma is static-only by design -- use a debugger (x64dbg, WinDbg) for dynamic\n       \
         analysis. 'sma scan' now ends with a 'limits' section naming where static analysis stops.",
    ),
    ("-f", "removed. Dumping every byte was never analysis. Use a window: sma hex <file> --at <rva>"),
    ("--full", "removed. Dumping every byte was never analysis. Use a window: sma hex <file> --at <rva>"),
    (
        "--dump-sections",
        "removed. Per-section metadata is in 'sma scan'; raw bytes via: sma hex <file> --section <name>",
    ),
    ("--all", "use: sma disasm <file>  (with no --addr, that is every executable section)"),
    ("--calls", "renamed: sma functions <file>"),
];

const HINT: &str = "try: sma --help";

pub fn parse(args: &[String]) -> Result<Invocation, String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(Invocation::Help);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        return Ok(Invocation::Version);
    }
    if args.is_empty() {
        return Ok(Invocation::Help);
    }

    // The verb is optional: `sma <file>` means `sma scan <file>`, which keeps the
    // most common invocation the shortest one.
    let (verb, rest) = match args[0].as_str() {
        v if VERBS.contains(&v) => (v, &args[1..]),
        _ => ("scan", args),
    };

    let mut path: Option<String> = None;
    let mut json = false;
    let mut dot = false;
    let mut headers = false;
    let mut addr: Option<u64> = None;
    let mut at: Option<u64> = None;
    let mut count: Option<usize> = None;
    let mut section: Option<String> = None;
    let mut len: Option<usize> = None;

    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();

        if !a.starts_with('-') {
            if let Some(seen) = &path {
                // A bare address as a positional is a forgotten flag, not a
                // second file. Saying "already analyzing '0x510c8'" would be
                // technically true and useless -- name the real mistake.
                if let Some(flag) = address_flag(verb) {
                    let addr_first = looks_like_address(seen);
                    if addr_first || looks_like_address(a) {
                        let (addr, file) = if addr_first { (seen.as_str(), a) } else { (a, seen.as_str()) };
                        return Err(format!(
                            "error: an address needs the {flag} flag, it is not a positional argument\n       \
                             try: sma {verb} {flag} {addr} \"{file}\""
                        ));
                    }
                }
                return Err(format!(
                    "error: unexpected extra argument '{a}' (already analyzing '{seen}')\n{HINT}"
                ));
            }
            path = Some(a.to_string());
            i += 1;
            continue;
        }

        // Reject the flag before consuming any value it might carry, so a
        // mistyped flag never silently swallows the file path.
        check_owner(a, verb)?;

        match a {
            "--json" => json = true,
            "--dot" => dot = true,
            "--headers" => headers = true,
            "--addr" => addr = Some(parse_hex(take_value(rest, &mut i, "--addr")?, "--addr")?),
            "--at" => at = Some(parse_hex(take_value(rest, &mut i, "--at")?, "--at")?),
            "--count" => count = Some(parse_count(take_value(rest, &mut i, "--count")?, "--count")?),
            "--len" => len = Some(parse_count(take_value(rest, &mut i, "--len")?, "--len")?),
            "--section" => section = Some(take_value(rest, &mut i, "--section")?.to_string()),
            _ => unreachable!("check_owner accepts nothing else"),
        }
        i += 1;
    }

    let path = match path {
        Some(p) => p,
        None => return Err(format!("error: '{verb}' needs a path to a file\n{HINT}")),
    };

    let cmd = match verb {
        "scan" => Command::Scan { path, json },
        "functions" => Command::Functions { path, json },
        "cfg" => Command::Cfg { path, addr, dot },
        "disasm" => Command::Disasm { path, addr, count, section },
        "hex" => {
            let window = match (at, section, headers) {
                (Some(a), None, false) => HexWindow::At(a),
                (None, Some(s), false) => HexWindow::Section(s),
                (None, None, true) => HexWindow::Headers,
                (None, None, false) => {
                    return Err(format!(
                        "error: hex needs a window: --at <hex>, --section <name>, or --headers\n{HINT}"
                    ))
                }
                _ => {
                    return Err(format!(
                        "error: hex takes exactly one of --at, --section, --headers\n{HINT}"
                    ))
                }
            };
            Command::Hex { path, window, len }
        }
        _ => unreachable!("verb came from VERBS"),
    };

    Ok(Invocation::Run(cmd))
}

fn check_owner(flag: &str, verb: &str) -> Result<(), String> {
    if let Some((_, owners)) = FLAG_OWNERS.iter().find(|(f, _)| *f == flag) {
        if owners.contains(&verb) {
            return Ok(());
        }
        return Err(format!(
            "error: {flag} is not an option of '{verb}' -- it belongs to: {}\n{HINT}",
            owners.join(", ")
        ));
    }
    if let Some((_, advice)) = RETIRED.iter().find(|(f, _)| *f == flag) {
        return Err(format!("error: {flag} no longer exists.\n       {advice}"));
    }
    Err(format!("error: unknown option '{flag}'\n{HINT}"))
}

// The flag each verb uses to take an address, if it takes one at all.
pub fn address_flag(verb: &str) -> Option<&'static str> {
    match verb {
        "cfg" | "disasm" => Some("--addr"),
        "hex" => Some("--at"),
        _ => None,
    }
}

// Is this token a hex address someone forgot to put a flag on?
//
// An explicit 0x prefix is unambiguous. Without one, the bar is five hex digits
// and nothing path-like, because four-letter hex words ("face", "beef", "cafe")
// are plausible filenames and guessing wrong on those would be worse than not
// guessing at all. This only ever produces a suggestion in an error message,
// never a silent reinterpretation of what was typed.
const MIN_BARE_HEX_DIGITS: usize = 5;

pub fn looks_like_address(s: &str) -> bool {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(rest) => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()),
        None => {
            s.len() >= MIN_BARE_HEX_DIGITS
                && s.chars().all(|c| c.is_ascii_hexdigit())
                && !s.contains(['.', '/', '\\'])
        }
    }
}

// Advance past the flag and hand back its value.
fn take_value<'a>(rest: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, String> {
    *i += 1;
    match rest.get(*i) {
        Some(v) => Ok(v.as_str()),
        None => Err(format!("error: {flag} needs a value\n{HINT}")),
    }
}

// A hex address, with or without a leading "0x".
fn parse_hex(s: &str, flag: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u64::from_str_radix(t, 16)
        .map_err(|_| format!("error: {flag} wants a hex address like 0x1400 or 1400 (got '{s}')"))
}

// A count: decimal, or hex with an explicit 0x prefix.
fn parse_count(s: &str, flag: &str) -> Result<usize, String> {
    let t = s.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(h) => usize::from_str_radix(h, 16),
        None => t.parse::<usize>(),
    };
    match parsed {
        Ok(0) => Err(format!("error: {flag} must be greater than zero")),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("error: {flag} wants a positive number (got '{s}')")),
    }
}

pub fn help() -> String {
    format!(
        "sma {} - static malware analysis

usage:
  sma <verb> <file> [options]
  sma <file>                       same as: sma scan <file>

verbs:
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
      --count <n>          stop after n instructions (default {} with --addr)
      --section <name>     restrict to one section

hex options:
      --at <hex>           start at a virtual address (RVA)
      --section <name>     start at a section
      --headers            the header region
      --len <n>            how many bytes (default {})

  -h, --help               show this help
  -V, --version            show the version

a typical session:
  sma scan sample.exe                     # what is this, and what stands out?
  sma functions sample.exe                # where is the interesting code?
  sma cfg sample.exe --addr 0x24c0        # what does that function do?
  sma cfg sample.exe --addr 0x24c0 --dot > f.dot && dot -Tpng f.dot -o f.png

findings are indicative, never definitive. benign software trips these rules too.
",
        env!("CARGO_PKG_VERSION"),
        DEFAULT_DISASM_COUNT,
        DEFAULT_HEX_LEN
    )
}

pub fn version() -> String {
    format!("sma {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn run(s: &[&str]) -> Result<Invocation, String> {
        parse(&args(s))
    }

    #[test]
    fn bare_path_defaults_to_scan() {
        let got = run(&["sample.exe"]).unwrap();
        assert_eq!(got, Invocation::Run(Command::Scan { path: "sample.exe".into(), json: false }));
    }

    #[test]
    fn flag_before_bare_path_still_defaults_to_scan() {
        let got = run(&["--json", "sample.exe"]).unwrap();
        assert_eq!(got, Invocation::Run(Command::Scan { path: "sample.exe".into(), json: true }));
    }

    #[test]
    fn verb_selects_the_command() {
        assert!(matches!(
            run(&["functions", "a.exe"]).unwrap(),
            Invocation::Run(Command::Functions { .. })
        ));
        assert!(matches!(run(&["cfg", "a.exe"]).unwrap(), Invocation::Run(Command::Cfg { .. })));
        assert!(matches!(run(&["disasm", "a.exe"]).unwrap(), Invocation::Run(Command::Disasm { .. })));
    }

    #[test]
    fn a_file_named_like_a_verb_is_still_reachable() {
        // "scan" as the verb, "cfg" as the path -- the verb is only ever args[0].
        let got = run(&["scan", "cfg"]).unwrap();
        assert_eq!(got, Invocation::Run(Command::Scan { path: "cfg".into(), json: false }));
    }

    #[test]
    fn flags_are_scoped_to_their_verb() {
        let err = run(&["scan", "a.exe", "--dot"]).unwrap_err();
        assert!(err.contains("--dot is not an option of 'scan'"), "got: {err}");
        assert!(err.contains("cfg"), "error should name the owning verb: {err}");

        let err = run(&["cfg", "a.exe", "--json"]).unwrap_err();
        assert!(err.contains("--json is not an option of 'cfg'"), "got: {err}");
    }

    #[test]
    fn retired_flags_name_their_replacement() {
        for (flag, expect) in [
            ("-f", "sma hex"),
            ("--dump-sections", "sma hex"),
            ("--calls", "sma functions"),
            ("--all", "sma disasm"),
            ("-b", "static-only by design"),
            ("-s", "sma scan"),
        ] {
            let err = run(&[flag, "a.exe"]).unwrap_err();
            assert!(err.contains(expect), "{flag} should point at {expect}, got: {err}");
        }
    }

    #[test]
    fn addr_accepts_both_hex_spellings_and_rejects_junk() {
        let with_prefix = run(&["cfg", "a.exe", "--addr", "0x1400"]).unwrap();
        let bare = run(&["cfg", "a.exe", "--addr", "1400"]).unwrap();
        assert_eq!(with_prefix, bare);
        assert!(matches!(
            with_prefix,
            Invocation::Run(Command::Cfg { addr: Some(0x1400), .. })
        ));

        let err = run(&["cfg", "a.exe", "--addr", "zzz"]).unwrap_err();
        assert!(err.contains("hex address"), "got: {err}");
    }

    #[test]
    fn a_flag_missing_its_value_does_not_eat_the_path() {
        // `--addr` with nothing after it must error, not consume "a.exe".
        let err = run(&["cfg", "--addr"]).unwrap_err();
        assert!(err.contains("--addr needs a value"), "got: {err}");
    }

    #[test]
    fn hex_requires_exactly_one_window() {
        let err = run(&["hex", "a.exe"]).unwrap_err();
        assert!(err.contains("needs a window"), "got: {err}");

        let err = run(&["hex", "a.exe", "--headers", "--at", "0x1000"]).unwrap_err();
        assert!(err.contains("exactly one"), "got: {err}");

        assert!(matches!(
            run(&["hex", "a.exe", "--section", ".text"]).unwrap(),
            Invocation::Run(Command::Hex { window: HexWindow::Section(_), .. })
        ));
    }

    #[test]
    fn count_and_len_reject_zero_and_junk() {
        assert!(run(&["disasm", "a.exe", "--count", "0"]).unwrap_err().contains("greater than zero"));
        assert!(run(&["hex", "a.exe", "--headers", "--len", "x"]).unwrap_err().contains("positive number"));
        assert!(matches!(
            run(&["disasm", "a.exe", "--count", "40"]).unwrap(),
            Invocation::Run(Command::Disasm { count: Some(40), .. })
        ));
    }

    #[test]
    fn a_positional_address_names_the_flag_it_needs() {
        // The mistake this guards: `sma disasm 0x510c8 file.exe` used to report
        // "unexpected extra argument 'file.exe' (already analyzing '0x510c8')",
        // which blames the file and never mentions --addr.
        let err = run(&["disasm", "0x510c8", "a.exe"]).unwrap_err();
        assert!(err.contains("--addr"), "got: {err}");
        assert!(err.contains("sma disasm --addr 0x510c8 \"a.exe\""), "got: {err}");

        // Either order, and hex takes --at rather than --addr.
        let err = run(&["cfg", "a.exe", "0x510c8"]).unwrap_err();
        assert!(err.contains("sma cfg --addr 0x510c8 \"a.exe\""), "got: {err}");
        let err = run(&["hex", "a.exe", "0x1000"]).unwrap_err();
        assert!(err.contains("sma hex --at 0x1000 \"a.exe\""), "got: {err}");

        // Verbs with no address flag keep the plain message.
        let err = run(&["scan", "a.exe", "0x510c8"]).unwrap_err();
        assert!(err.contains("extra argument"), "got: {err}");
    }

    #[test]
    fn ordinary_filenames_are_not_mistaken_for_addresses() {
        for name in ["notepad.exe", "abc", "data.bin", "C:\\tmp\\beef", "face"] {
            assert!(!looks_like_address(name), "{name} should not read as an address");
        }
        for addr in ["0x1400", "0X1400", "510c8", "deadbeef"] {
            assert!(looks_like_address(addr), "{addr} should read as an address");
        }
        // Two real files still produce the plain duplicate-path error.
        let err = run(&["disasm", "a.exe", "b.exe"]).unwrap_err();
        assert!(err.contains("extra argument"), "got: {err}");
    }

    #[test]
    fn missing_path_and_unknown_flags_are_errors() {
        assert!(run(&["scan"]).unwrap_err().contains("needs a path"));
        assert!(run(&["scan", "a.exe", "--nope"]).unwrap_err().contains("unknown option"));
        assert!(run(&["scan", "a.exe", "b.exe"]).unwrap_err().contains("extra argument"));
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert_eq!(run(&["--help"]).unwrap(), Invocation::Help);
        assert_eq!(run(&["scan", "a.exe", "-h"]).unwrap(), Invocation::Help);
        assert_eq!(run(&["--version"]).unwrap(), Invocation::Version);
        assert_eq!(run(&[]).unwrap(), Invocation::Help);
    }

    #[test]
    fn every_flag_in_help_is_owned_by_a_verb() {
        // Guards the drift the old CLI had: help advertising a flag nothing accepts.
        let text = help();
        for (flag, _) in FLAG_OWNERS {
            assert!(text.contains(flag), "help never mentions {flag}");
        }
    }
}
