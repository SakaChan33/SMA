use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IocKind {
    Url,
    Ipv4,
    RegistryKey,
    FilePath,
}

impl fmt::Display for IocKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            IocKind::Url => "URL",
            IocKind::Ipv4 => "IPv4",
            IocKind::RegistryKey => "Registry",
            IocKind::FilePath => "Path",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct StringScan {
    pub ascii_count: usize,
    pub wide_count: usize,
    pub iocs: Vec<Ioc>,
}

const MAX_IOCS: usize = 500; // cap so a huge file can't produce an unbounded list

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

// Scan a buffer for ASCII and UTF-16LE strings of at least `min_len`, counting
// them and extracting IOCs from each.
pub fn scan(data: &[u8], min_len: usize) -> StringScan {
    let mut out = StringScan::default();
    let mut seen: HashSet<(IocKind, String)> = HashSet::new();

    // --- ASCII strings: runs of printable bytes ---
    let mut i = 0;
    while i < data.len() {
        if is_printable(data[i]) {
            let start = i;
            while i < data.len() && is_printable(data[i]) {
                i += 1;
            }
            if i - start >= min_len {
                out.ascii_count += 1;
                // every byte is 0x20..=0x7e, so this slice is valid UTF-8
                let s = std::str::from_utf8(&data[start..i]).unwrap_or("");
                classify(s, &mut out.iocs, &mut seen);
            }
        } else {
            i += 1;
        }
    }

    // --- UTF-16LE strings: (printable, 0x00) pairs ---
    let mut i = 0;
    while i + 1 < data.len() {
        if is_printable(data[i]) && data[i + 1] == 0 {
            let mut s = String::new();
            while i + 1 < data.len() && is_printable(data[i]) && data[i + 1] == 0 {
                s.push(data[i] as char);
                i += 2;
            }
            if s.len() >= min_len {
                out.wide_count += 1;
                classify(&s, &mut out.iocs, &mut seen);
            }
        } else {
            i += 1;
        }
    }

    out
}

// Inspect one string and record any IOCs it contains. Cheap substring/byte gates
// come first so the common (boring) string is rejected fast.
fn classify(s: &str, iocs: &mut Vec<Ioc>, seen: &mut HashSet<(IocKind, String)>) {
    if iocs.len() >= MAX_IOCS {
        return;
    }

    // URL
    if s.contains("://") {
        if let Some(url) = find_url(s) {
            add(iocs, seen, IocKind::Url, url.to_string());
        }
    }

    // Registry key (else file path -- a registry key is not also a path)
    if s.contains("HKEY_") || s.contains("HKLM") || s.contains("HKCU")
        || s.contains("HKCR") || s.contains("CurrentVersion\\Run")
    {
        add(iocs, seen, IocKind::RegistryKey, s.to_string());
    } else if is_path(s) {
        add(iocs, seen, IocKind::FilePath, s.to_string());
    }

    // IPv4 -- only bother if the string has at least 3 dots
    if s.as_bytes().iter().filter(|&&b| b == b'.').count() >= 3 {
        for token in s.split(|c: char| !c.is_ascii_digit() && c != '.') {
            if is_ipv4(token) {
                add(iocs, seen, IocKind::Ipv4, token.to_string());
            }
        }
    }
}

fn add(iocs: &mut Vec<Ioc>, seen: &mut HashSet<(IocKind, String)>, kind: IocKind, value: String) {
    if iocs.len() < MAX_IOCS && seen.insert((kind, value.clone())) {
        iocs.push(Ioc { kind, value });
    }
}

// Extract the URL substring starting at its scheme, trimmed at the first
// whitespace/quote/bracket.
fn find_url(s: &str) -> Option<&str> {
    for scheme in ["https://", "http://", "ftp://"] {
        if let Some(pos) = s.find(scheme) {
            let url = &s[pos..];
            let end = url
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')'))
                .unwrap_or(url.len());
            return Some(&url[..end]);
        }
    }
    None
}

fn is_path(s: &str) -> bool {
    let b = s.as_bytes();
    // Drive path: X:\  (require a backslash -- "e://" is a URL fragment, not a path)
    let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    // UNC path: \\server\share
    let unc = s.starts_with("\\\\");
    drive || unc
}

// A token is an IPv4 if it's four dot-separated parts, each parseable as a u8
// (which enforces the 0..=255 range for free).
fn is_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_string() {
        let data = b"\x00\x01Hello, World!\x00\x02";
        assert!(scan(data, 5).ascii_count >= 1);
    }

    #[test]
    fn extracts_wide_string() {
        // "OKAY" in UTF-16LE
        let data = b"\x4f\x00\x4b\x00\x41\x00\x59\x00";
        assert!(scan(data, 4).wide_count >= 1);
    }

    #[test]
    fn finds_url_ip_registry_path() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00visit http://evil.example/gate.php now\x00");
        data.extend_from_slice(b"\x00connect 185.220.101.1 here\x00");
        data.extend_from_slice(b"\x00HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00");
        data.extend_from_slice(b"\x00C:\\Windows\\Temp\\evil.exe\x00");
        let scan = scan(&data, 5);
        assert!(scan.iocs.iter().any(|i| i.kind == IocKind::Url && i.value.starts_with("http://evil")));
        assert!(scan.iocs.iter().any(|i| i.kind == IocKind::Ipv4 && i.value == "185.220.101.1"));
        assert!(scan.iocs.iter().any(|i| i.kind == IocKind::RegistryKey));
        assert!(scan.iocs.iter().any(|i| i.kind == IocKind::FilePath && i.value.contains("evil.exe")));
    }

    #[test]
    fn validates_ipv4() {
        assert!(is_ipv4("1.2.3.4"));
        assert!(!is_ipv4("999.1.1.1")); // 999 > 255
        assert!(!is_ipv4("1.2.3")); // only 3 parts
        assert!(!is_ipv4("1.2.3.4.5")); // 5 parts
    }
}
