use crate::binary::Import;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub capability: &'static str,
    pub severity: Severity,
    pub matched: Vec<String>, // the imported APIs that matched this rule
}

// A rule fires when at least `min_hits` of its APIs are imported.
struct Rule {
    capability: &'static str,
    severity: Severity,
    min_hits: usize,
    apis: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        capability: "Process injection",
        severity: Severity::High,
        min_hits: 2,
        apis: &[
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "QueueUserAPC", "RtlCreateUserThread",
            "NtMapViewOfSection", "SetThreadContext",
        ],
    },
    Rule {
        capability: "Keylogging / input capture",
        severity: Severity::High,
        min_hits: 2,
        apis: &[
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState",
            "GetRawInputData", "RegisterRawInputDevices",
        ],
    },
    Rule {
        capability: "Networking / possible C2",
        severity: Severity::Medium,
        min_hits: 2,
        apis: &[
            "socket", "connect", "send", "recv", "WSASocket", "WSAConnect",
            "WSASend", "WSARecv", "GetAddrInfo", "InternetOpen", "InternetConnect",
            "HttpSendRequest", "URLDownloadToFile", "WinHttpOpen", "WinHttpConnect",
        ],
    },
    Rule {
        capability: "Cryptography (possible ransomware)",
        severity: Severity::Medium,
        min_hits: 2,
        apis: &[
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptGenRandom",
            "CryptAcquireContext", "CryptExportKey", "CryptImportKey",
            "BCryptEncrypt", "BCryptGenRandom",
        ],
    },
    Rule {
        capability: "Runtime API resolution (import hiding)",
        severity: Severity::Medium,
        min_hits: 2,
        apis: &[
            "LoadLibrary", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
            "dlopen", "dlsym", // ELF/Linux equivalents
        ],
    },
    Rule {
        capability: "Privilege / token manipulation",
        severity: Severity::Medium,
        min_hits: 2,
        apis: &[
            "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue",
            "GetTokenInformation", "DuplicateTokenEx",
        ],
    },
    Rule {
        capability: "Anti-debugging",
        severity: Severity::Low,
        min_hits: 1,
        apis: &[
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugString",
            "ptrace", // Linux: PTRACE_TRACEME is the classic anti-debug trick
        ],
    },
    Rule {
        capability: "Persistence (registry / services)",
        severity: Severity::Low,
        min_hits: 1,
        apis: &["RegSetValueEx", "RegCreateKeyEx", "CreateService", "StartService"],
    },
    Rule {
        capability: "Process / command execution",
        severity: Severity::Low,
        min_hits: 1,
        apis: &[
            "CreateProcess", "ShellExecute", "WinExec",
            "system", "popen", "execve", "execl", "execlp", "execvp", "fork", // POSIX/Linux
        ],
    },
];

fn name_matches(imported_lower: &str, api: &str) -> bool {
    let a = api.to_ascii_lowercase();
    imported_lower == a.as_str()
        || imported_lower == format!("{a}a").as_str()
        || imported_lower == format!("{a}w").as_str()
}

pub fn assess_imports(imports: &[Import]) -> Vec<Finding> {
    // Flatten every imported function name once, lowercased, for matching.
    let names: Vec<String> = imports
        .iter()
        .flat_map(|i| i.functions.iter())
        .map(|f| f.to_ascii_lowercase())
        .collect();

    let mut findings = Vec::new();
    for rule in RULES {
        let matched: Vec<String> = rule
            .apis
            .iter()
            .filter(|&&api| names.iter().any(|n| name_matches(n, api)))
            .map(|&api| api.to_string())
            .collect();

        if matched.len() >= rule.min_hits {
            findings.push(Finding {
                capability: rule.capability,
                severity: rule.severity,
                matched,
            });
        }
    }

    findings.sort_by_key(|f| std::cmp::Reverse(f.severity)); // most severe first
    findings
}

pub fn max_severity(findings: &[Finding]) -> Option<Severity> {
    findings.iter().map(|f| f.severity).max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::Import;

    fn imp(dll: &str, funcs: &[&str]) -> Import {
        Import {
            dll: dll.into(),
            functions: funcs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn injection_combo_flags_high() {
        let imports = vec![imp(
            "kernel32.dll",
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        )];
        let f = assess_imports(&imports);
        assert!(f.iter().any(|x| x.capability == "Process injection" && x.severity == Severity::High));
    }

    #[test]
    fn benign_imports_do_not_flag_injection() {
        let imports = vec![imp("kernel32.dll", &["HeapAlloc", "HeapFree", "CreateFileW", "ReadFile"])];
        let f = assess_imports(&imports);
        assert!(!f.iter().any(|x| x.capability == "Process injection"));
    }

    #[test]
    fn aw_suffix_is_tolerated() {
        // The real import is CreateProcessW; the rule lists "CreateProcess".
        let imports = vec![imp("kernel32.dll", &["CreateProcessW"])];
        let f = assess_imports(&imports);
        assert!(f.iter().any(|x| x.capability == "Process / command execution"));
    }
}
