//! Reference lookup that labels a 32-bit constant in a captured blob with the Windows API name
//! whose rotate-13 name hash it matches. A position-independent loader resolves its imports by
//! comparing such hashes; recognising them is a standard triage step (as in scdbg or the IDA
//! "shellcode hashes" plugin). Read-only: it only names constants the analyst already has.

/// The common rotate-right-13 name hash, computed over the ASCII name bytes.
fn ror13(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = h.rotate_right(13).wrapping_add(u32::from(b));
    }
    h
}

/// A matched constant: its offset in the blob, the value, and the API name it hashes to.
pub struct HashMatch {
    pub offset: usize,
    pub value: u32,
    pub name: &'static str,
}

/// Scans every 4-byte little-endian window of `blob` for a value equal to a reference API-name
/// hash, returning the labelled matches.
pub fn scan(blob: &[u8]) -> Vec<HashMatch> {
    let table: Vec<(u32, &'static str)> = API_NAMES
        .iter()
        .map(|&n| (ror13(n.as_bytes()), n))
        .collect();
    let mut out = Vec::new();
    if blob.len() < 4 {
        return out;
    }
    for off in 0..=blob.len() - 4 {
        let v = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
        if let Some(&(_, name)) = table.iter().find(|&&(h, _)| h == v) {
            out.push(HashMatch {
                offset: off,
                value: v,
                name,
            });
        }
    }
    out
}

/// A modest reference set of Windows API names a loader commonly resolves.
const API_NAMES: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "GetProcessHeap",
    "HeapAlloc",
    "ExitProcess",
    "ExitThread",
    "CreateThread",
    "Sleep",
    "WaitForSingleObject",
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "GetFileSize",
    "SetFilePointer",
    "GetModuleFileNameA",
    "GetCommandLineA",
    "GetTempPathA",
    "GetProcAddress",
    "LoadLibrary",
    "WSAStartup",
    "WSASocketA",
    "socket",
    "connect",
    "send",
    "recv",
    "closesocket",
    "InternetOpenA",
    "InternetOpenUrlA",
    "InternetConnectA",
    "HttpOpenRequestA",
    "HttpSendRequestA",
    "InternetReadFile",
    "URLDownloadToFileA",
    "RegOpenKeyExA",
    "RegSetValueExA",
    "RegQueryValueExA",
    "GetUserNameA",
    "GetComputerNameA",
    "OpenProcess",
    "ReadProcessMemory",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "GetThreadContext",
    "SetThreadContext",
    "ResumeThread",
    "CreateProcessA",
    "TerminateProcess",
    "MessageBoxA",
    "GetWindowsDirectoryA",
    "GetSystemDirectoryA",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "IsDebuggerPresent",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ror13_is_stable_and_scans() {
        // Encode the LoadLibraryA hash as a little-endian constant in a blob and find it.
        let h = ror13(b"LoadLibraryA");
        let mut blob = vec![0x90u8, 0x90];
        blob.extend_from_slice(&h.to_le_bytes());
        blob.push(0xc3);
        let matches = scan(&blob);
        assert!(
            matches
                .iter()
                .any(|m| m.name == "LoadLibraryA" && m.value == h)
        );
    }
}
