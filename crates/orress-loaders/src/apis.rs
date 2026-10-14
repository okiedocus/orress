//! A small knowledge base of library functions that matter in reverse engineering.
//! Used to explain imports and to spot what a program is likely to do.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApiCategory {
    Input,
    Compare,
    Crypto,
    AntiDebug,
    Network,
    Injection,
    Process,
    File,
    Registry,
    DynamicLoading,
    Memory,
}

impl ApiCategory {
    pub fn name(self) -> &'static str {
        match self {
            Self::Input => "Input",
            Self::Compare => "Comparison",
            Self::Crypto => "Crypto",
            Self::AntiDebug => "Anti-debugging",
            Self::Network => "Network",
            Self::Injection => "Code injection",
            Self::Process => "Processes",
            Self::File => "Files",
            Self::Registry => "Registry",
            Self::DynamicLoading => "Dynamic loading",
            Self::Memory => "Memory",
        }
    }

    /// Whether this category deserves attention in a malware context.
    pub fn suspicious(self) -> bool {
        matches!(
            self,
            Self::AntiDebug | Self::Injection | Self::Network | Self::DynamicLoading
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ApiInfo {
    pub name: &'static str,
    pub category: ApiCategory,
    pub explain: &'static str,
}

use ApiCategory::*;

const fn api(name: &'static str, category: ApiCategory, explain: &'static str) -> ApiInfo {
    ApiInfo {
        name,
        category,
        explain,
    }
}

pub static APIS: &[ApiInfo] = &[
    // Input
    api(
        "scanf",
        Input,
        "Reads formatted input from the keyboard (stdin). Look at the format string to learn what it expects.",
    ),
    api(
        "__isoc99_scanf",
        Input,
        "glibc's name for scanf: reads formatted input from stdin.",
    ),
    api(
        "__isoc23_scanf",
        Input,
        "glibc's name for scanf: reads formatted input from stdin.",
    ),
    api(
        "fgets",
        Input,
        "Reads one line of text, at most N characters. Often how a crackme reads the password.",
    ),
    api(
        "gets",
        Input,
        "Reads a line with no length limit. Always a buffer overflow: a classic pwn target.",
    ),
    api(
        "read",
        Input,
        "Reads raw bytes from a file descriptor (0 = stdin).",
    ),
    api("getchar", Input, "Reads one character from stdin."),
    api(
        "getline",
        Input,
        "Reads a whole line, growing the buffer as needed.",
    ),
    api(
        "ReadConsoleA",
        Input,
        "Reads text typed in a Windows console window.",
    ),
    api(
        "ReadConsoleW",
        Input,
        "Reads text typed in a Windows console window (wide characters).",
    ),
    api(
        "GetWindowTextA",
        Input,
        "Reads the text of a window or text box: how GUI crackmes read the serial.",
    ),
    api(
        "GetWindowTextW",
        Input,
        "Reads the text of a window or text box: how GUI crackmes read the serial.",
    ),
    api(
        "GetDlgItemTextA",
        Input,
        "Reads the text of a dialog box field: how GUI crackmes read the serial.",
    ),
    api(
        "GetDlgItemTextW",
        Input,
        "Reads the text of a dialog box field: how GUI crackmes read the serial.",
    ),
    // Comparison
    api(
        "strcmp",
        Compare,
        "Compares two strings; returns 0 when equal. If your input is compared with the password, both are arguments here.",
    ),
    api(
        "strncmp",
        Compare,
        "Compares the first N characters of two strings; returns 0 when equal.",
    ),
    api(
        "memcmp",
        Compare,
        "Compares two blocks of bytes; returns 0 when equal. Used for binary passwords and hashes.",
    ),
    api(
        "strcasecmp",
        Compare,
        "Compares two strings ignoring upper/lower case.",
    ),
    api("wcscmp", Compare, "Compares two wide (UTF-16/32) strings."),
    api(
        "lstrcmpA",
        Compare,
        "Windows string comparison; returns 0 when equal.",
    ),
    api(
        "lstrcmpW",
        Compare,
        "Windows wide string comparison; returns 0 when equal.",
    ),
    api(
        "lstrcmpiA",
        Compare,
        "Windows case-insensitive string comparison.",
    ),
    api(
        "strstr",
        Compare,
        "Searches for a substring inside a string.",
    ),
    // Crypto
    api(
        "CryptEncrypt",
        Crypto,
        "Windows CryptoAPI: encrypts data. Ransomware and C2 traffic use it.",
    ),
    api(
        "CryptDecrypt",
        Crypto,
        "Windows CryptoAPI: decrypts data. Malware decrypts its configuration with it.",
    ),
    api(
        "CryptAcquireContextA",
        Crypto,
        "Windows CryptoAPI: opens a crypto provider; the first step before hashing or encrypting.",
    ),
    api(
        "CryptAcquireContextW",
        Crypto,
        "Windows CryptoAPI: opens a crypto provider.",
    ),
    api(
        "CryptCreateHash",
        Crypto,
        "Windows CryptoAPI: starts computing a hash (MD5, SHA ...).",
    ),
    api(
        "CryptHashData",
        Crypto,
        "Windows CryptoAPI: adds data to a hash.",
    ),
    api(
        "BCryptEncrypt",
        Crypto,
        "Windows CNG: encrypts data (modern replacement for CryptEncrypt).",
    ),
    api("BCryptDecrypt", Crypto, "Windows CNG: decrypts data."),
    api(
        "BCryptGenRandom",
        Crypto,
        "Windows CNG: generates random bytes, e.g. for keys.",
    ),
    api(
        "EVP_EncryptInit_ex",
        Crypto,
        "OpenSSL: starts encryption. The cipher argument tells you the algorithm.",
    ),
    api(
        "EVP_DecryptInit_ex",
        Crypto,
        "OpenSSL: starts decryption. The key and IV are arguments.",
    ),
    api("MD5", Crypto, "OpenSSL: computes an MD5 hash."),
    api("SHA256", Crypto, "OpenSSL: computes a SHA-256 hash."),
    api(
        "srand",
        Crypto,
        "Seeds the C random generator. srand(time(0)) is predictable: a common CTF weakness.",
    ),
    api(
        "rand",
        Crypto,
        "C pseudo-random numbers. Not secure: the sequence repeats for the same seed.",
    ),
    // Anti-debugging
    api(
        "IsDebuggerPresent",
        AntiDebug,
        "Returns true when a debugger is attached. Programs use it to behave differently under analysis. Easy to bypass by patching the result.",
    ),
    api(
        "CheckRemoteDebuggerPresent",
        AntiDebug,
        "Checks whether a process is being debugged.",
    ),
    api(
        "NtQueryInformationProcess",
        AntiDebug,
        "Low-level Windows call; with ProcessDebugPort or ProcessDebugFlags it detects debuggers.",
    ),
    api(
        "OutputDebugStringA",
        AntiDebug,
        "Sends text to a debugger. Old trick: its behavior differs when a debugger is attached.",
    ),
    api(
        "GetTickCount",
        AntiDebug,
        "Milliseconds since boot. Two calls around code detect slow single-stepping (timing check).",
    ),
    api(
        "QueryPerformanceCounter",
        AntiDebug,
        "High-precision timer, also used for timing checks against debuggers.",
    ),
    api(
        "ptrace",
        AntiDebug,
        "Linux debugging interface. ptrace(PTRACE_TRACEME) fails when a debugger is attached: a classic anti-debug check.",
    ),
    api(
        "NtSetInformationThread",
        AntiDebug,
        "With ThreadHideFromDebugger it hides a thread from the debugger.",
    ),
    // Network
    api(
        "WSAStartup",
        Network,
        "Initializes Windows sockets: the program uses the network.",
    ),
    api("socket", Network, "Creates a network socket."),
    api(
        "connect",
        Network,
        "Connects to a server. The address argument may be a command-and-control server.",
    ),
    api("send", Network, "Sends data over a socket."),
    api("recv", Network, "Receives data from a socket."),
    api(
        "InternetOpenA",
        Network,
        "WinINet: starts HTTP/FTP access. Malware downloaders use it.",
    ),
    api(
        "InternetOpenUrlA",
        Network,
        "WinINet: opens a URL and downloads from it.",
    ),
    api(
        "HttpSendRequestA",
        Network,
        "WinINet: sends an HTTP request.",
    ),
    api(
        "URLDownloadToFileA",
        Network,
        "Downloads a URL straight to a file: typical for droppers.",
    ),
    api(
        "URLDownloadToFileW",
        Network,
        "Downloads a URL straight to a file: typical for droppers.",
    ),
    api("WinHttpOpen", Network, "WinHTTP: starts HTTP access."),
    api(
        "gethostbyname",
        Network,
        "Resolves a domain name to an IP address.",
    ),
    api("getaddrinfo", Network, "Resolves a host name to addresses."),
    // Injection
    api(
        "VirtualAllocEx",
        Injection,
        "Allocates memory inside another process: the first step of code injection.",
    ),
    api(
        "WriteProcessMemory",
        Injection,
        "Writes into another process's memory: injection or patching.",
    ),
    api(
        "CreateRemoteThread",
        Injection,
        "Starts a thread in another process. Together with VirtualAllocEx and WriteProcessMemory this is classic DLL/shellcode injection.",
    ),
    api(
        "NtCreateThreadEx",
        Injection,
        "Low-level version of CreateRemoteThread.",
    ),
    api(
        "QueueUserAPC",
        Injection,
        "Queues code to run in another thread: APC injection.",
    ),
    api(
        "SetThreadContext",
        Injection,
        "Changes a thread's registers. Used in process hollowing to redirect execution.",
    ),
    api(
        "SetWindowsHookExA",
        Injection,
        "Installs a hook, e.g. on the keyboard: keyloggers and DLL injection.",
    ),
    api(
        "SetWindowsHookExW",
        Injection,
        "Installs a hook, e.g. on the keyboard: keyloggers and DLL injection.",
    ),
    // Processes
    api("CreateProcessA", Process, "Starts another program."),
    api("CreateProcessW", Process, "Starts another program."),
    api(
        "ShellExecuteA",
        Process,
        "Opens a file or URL, or runs a program.",
    ),
    api(
        "ShellExecuteW",
        Process,
        "Opens a file or URL, or runs a program.",
    ),
    api(
        "WinExec",
        Process,
        "Runs a command (old API, still used by shellcode).",
    ),
    api(
        "system",
        Process,
        "Runs a shell command. In a CTF, check if you control its argument.",
    ),
    api(
        "execve",
        Process,
        "Replaces the current program with another one.",
    ),
    api(
        "OpenProcess",
        Process,
        "Gets a handle to another process, e.g. to read or inject into it.",
    ),
    // Files
    api("CreateFileA", File, "Opens or creates a file (or device)."),
    api("CreateFileW", File, "Opens or creates a file (or device)."),
    api(
        "fopen",
        File,
        "Opens a file. The file name argument is often interesting (flag.txt?).",
    ),
    api("open", File, "Opens a file (Linux system call)."),
    api("DeleteFileA", File, "Deletes a file."),
    // Registry
    api("RegOpenKeyExA", Registry, "Opens a registry key."),
    api(
        "RegSetValueExA",
        Registry,
        "Writes a registry value. Run keys make malware start at login (persistence).",
    ),
    api(
        "RegSetValueExW",
        Registry,
        "Writes a registry value. Run keys make malware start at login (persistence).",
    ),
    api("RegCreateKeyExA", Registry, "Creates a registry key."),
    // Dynamic loading
    api(
        "LoadLibraryA",
        DynamicLoading,
        "Loads a DLL at run time. Together with GetProcAddress it hides which functions are used.",
    ),
    api("LoadLibraryW", DynamicLoading, "Loads a DLL at run time."),
    api("LoadLibraryExA", DynamicLoading, "Loads a DLL at run time."),
    api(
        "GetProcAddress",
        DynamicLoading,
        "Finds a function in a DLL by name at run time. Packers and malware use it to hide their imports.",
    ),
    api(
        "dlopen",
        DynamicLoading,
        "Loads a shared library at run time (Linux).",
    ),
    api(
        "dlsym",
        DynamicLoading,
        "Finds a function in a shared library by name (Linux).",
    ),
    // Memory
    api(
        "VirtualAlloc",
        Memory,
        "Allocates memory. With PAGE_EXECUTE_READWRITE it often holds unpacked or decrypted code.",
    ),
    api(
        "VirtualProtect",
        Memory,
        "Changes memory permissions, e.g. making data executable after unpacking it.",
    ),
    api(
        "mprotect",
        Memory,
        "Changes memory permissions (Linux). Self-modifying CTF binaries use it.",
    ),
    api("mmap", Memory, "Maps memory or a file into memory."),
    api("malloc", Memory, "Allocates heap memory."),
    api("memcpy", Memory, "Copies a block of bytes."),
    api(
        "strcpy",
        Memory,
        "Copies a string with no length check: a buffer overflow risk.",
    ),
];

/// Looks up a function name. Ignores a leading `_` (32-bit Windows decoration) and a
/// trailing `@N` (stdcall suffix).
pub fn lookup(name: &str) -> Option<&'static ApiInfo> {
    let trimmed = name.trim_start_matches('_');
    let trimmed = trimmed.split('@').next().unwrap_or(trimmed);
    let find = |n: &str| APIS.iter().find(|a| a.name.trim_start_matches('_') == n);
    APIS.iter()
        .find(|a| a.name == name)
        .or_else(|| find(trimmed))
        .or_else(|| {
            // Windows APIs come as ...A (ANSI) and ...W (wide) variants; the knowledge
            // base often lists only one of them.
            let base = trimmed
                .strip_suffix('A')
                .or_else(|| trimmed.strip_suffix('W'))?;
            find(&format!("{base}A")).or_else(|| find(&format!("{base}W")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_handles_decorations() {
        assert_eq!(lookup("strcmp").unwrap().category, Compare);
        assert_eq!(lookup("_IsDebuggerPresent@0").unwrap().category, AntiDebug);
        assert!(lookup("totally_unknown").is_none());
        // A/W variants map to each other.
        assert_eq!(lookup("RegOpenKeyExW").unwrap().name, "RegOpenKeyExA");
        assert_eq!(lookup("InternetOpenW").unwrap().name, "InternetOpenA");
        assert!(lookup("SHOW").is_none());
    }

    #[test]
    fn no_duplicate_names() {
        let mut names: Vec<_> = APIS.iter().map(|a| a.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }
}
