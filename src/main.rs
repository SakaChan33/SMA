// SMA - Static Malware Analysis
//
// Usage: sma <verb> <file> [options]   (see `sma --help`)
//
// This binary is only plumbing: parse arguments, read the file, hand the bytes
// to the library, and stream one view to stdout. Every analysis decision lives
// in the library so it can be tested without a process.

use static_malware_analysis::cli::{self, Command, Invocation};
use static_malware_analysis::symbols::Symbols;
use static_malware_analysis::{cfg, functions, hexdump, json, parse, report};
use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let invocation = match cli::parse(&args) {
        Ok(i) => i,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    let command = match invocation {
        Invocation::Help => {
            print!("{}", cli::help());
            return ExitCode::SUCCESS;
        }
        Invocation::Version => {
            println!("{}", cli::version());
            return ExitCode::SUCCESS;
        }
        Invocation::Run(c) => c,
    };

    match run(&command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: &Command) -> Result<(), String> {
    let path = command_path(command);

    // Every byte from here on is UNTRUSTED input.
    let bytes = std::fs::read(path).map_err(|e| {
        // A path that is really an address means the flag was left off. Only
        // said once the read has actually failed, so a file genuinely named
        // like an address still works.
        match cli::address_flag(verb_of(command)) {
            Some(flag) if cli::looks_like_address(path) => format!(
                "error: cannot read {path}: {e}\n       \
                 that looks like an address -- it belongs to {flag}: sma {} {flag} {path} <file>",
                verb_of(command)
            ),
            _ => format!("error: cannot read {path}: {e}"),
        }
    })?;
    let bin = parse(&bytes).map_err(|e| format!("parse error: {e}"))?;

    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());

    let result = match command {
        Command::Scan { json: true, .. } => {
            write!(w, "{}", json::report(path, bytes.len(), &bin)).map_err(Into::into)
        }
        Command::Scan { .. } => report::write(&mut w, path, bytes.len(), &bin).map_err(Into::into),

        Command::Functions { json, .. } => {
            let syms = Symbols::build(&bytes, &bin);
            match functions::discover(&bytes, &bin, &syms) {
                Err(m) => Err(Failure::Message(m)),
                Ok(inv) if *json => functions::write_json(&mut w, path, &inv).map_err(Into::into),
                Ok(inv) => functions::write_text(&mut w, &inv).map_err(Into::into),
            }
        }

        Command::Cfg { addr, dot, .. } => {
            let syms = Symbols::build(&bytes, &bin);
            match cfg::build(&bytes, &bin, *addr) {
                Err(m) => Err(Failure::Message(m)),
                Ok(graph) if *dot => graph.to_dot(&mut w, Some(&syms)).map_err(Into::into),
                Ok(graph) => graph.to_text(&mut w, Some(&syms)).map_err(Into::into),
            }
        }

        Command::Disasm { addr, count, section, .. } => {
            let syms = Symbols::build(&bytes, &bin);
            let opts = cfg::DisasmOpts {
                addr: *addr,
                // A window needs a default length; whole sections do not.
                count: count.or_else(|| addr.map(|_| cli::DEFAULT_DISASM_COUNT)),
                section: section.as_deref(),
            };
            cfg::disassemble(&bytes, &bin, &mut w, &opts, Some(&syms)).map(|_| ()).map_err(Into::into)
        }

        Command::Hex { window, len, .. } => {
            match hexdump::resolve_window(&bytes, &bin, window, *len, cli::DEFAULT_HEX_LEN) {
                Err(m) => Err(Failure::Message(m)),
                Ok((off, n)) => {
                    hexdump::dump_to(&mut w, &bytes[off..off + n], off).map_err(Into::into)
                }
            }
        }
    };

    match result {
        Ok(()) => {}
        // Piping into `head` closes the pipe early; that is a normal end to a
        // stream, not a failure.
        Err(Failure::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
        Err(Failure::Io(e)) => return Err(format!("{}: {e}", verb_of(command))),
        Err(Failure::Message(m)) => return Err(format!("{}: {m}", verb_of(command))),
    }

    match w.flush() {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(format!("error: writing output failed: {e}")),
    }
}

// Two ways a view can fail: an io error while streaming, or an analysis that
// could not start (no section at that address, wrong architecture).
enum Failure {
    Io(io::Error),
    Message(String),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Failure::Io(e)
    }
}

fn command_path(c: &Command) -> &str {
    match c {
        Command::Scan { path, .. }
        | Command::Functions { path, .. }
        | Command::Cfg { path, .. }
        | Command::Disasm { path, .. }
        | Command::Hex { path, .. } => path,
    }
}

fn verb_of(c: &Command) -> &'static str {
    match c {
        Command::Scan { .. } => "scan",
        Command::Functions { .. } => "functions",
        Command::Cfg { .. } => "cfg",
        Command::Disasm { .. } => "disasm",
        Command::Hex { .. } => "hex",
    }
}
