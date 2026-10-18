//! crackme15 - HARMLESS malware-like TRAINING SAMPLE (Level 6, Malware analysis).
//!
//! THIS PROGRAM DOES NOTHING HARMFUL. It only prints a message and exits with code 0.
//! It touches no network, no registry, no other processes and no files. It exists so the
//! Academy's malware lessons (triage, IOC extraction, YARA, reporting) have a realistic
//! target to analyse safely.
//!
//! To make triage interesting it deliberately *contains the indicators an analyst looks for*,
//! but never acts on any of them:
//!   - suspicious strings: a fake C2 URL on the reserved, non-routable `.invalid` TLD, a
//!     registry Run-key path, a browser User-Agent and a mutex name;
//!   - an XOR-encoded configuration blob in the `ExampleRAT` demo format (marker `ORCFG`,
//!     2-byte little-endian length, then `key=value;` text XOR-ed with 0x5A) that ORRESS's
//!     Triage config extractor decodes;
//!   - imports that malware uses for process injection (`VirtualAllocEx`,
//!     `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess`), HTTP C2 (`InternetOpenA`,
//!     `HttpSendRequestA`), persistence/crypto (`RegCreateKeyExA`, `RegSetValueExA`,
//!     `CryptEncrypt`) and dynamic API resolution (`LoadLibraryA`, `GetProcAddress`) - all of
//!     which are merely *referenced* (their addresses are read into a checksum) and never
//!     called. No injection, no network, no registry write, no encryption ever happens.
//!
//! Used by: the Level 6 lessons l6-malware-triage and l6-static-deep-dive.
//! Solution: there is nothing to "solve" - you analyse it. The decoded C2 host is
//! `update.example.invalid` and the distinctive marker string is `ORRESS_TRAINING_SAMPLE_v1`.

// Suspicious-looking indicators. All inert: `.invalid` never resolves, and nothing here is
// ever connected to, written or executed.
static MARKER: &str = "ORRESS_TRAINING_SAMPLE_v1";
static C2_URL: &str = "http://cdn.example.invalid/beacon";
static USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0) ORRESS-Trainer/1.0";
static RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
static MUTEX: &str = r"Global\ORRESS-TRAIN-01";

// XOR-encoded (0x5A) ExampleRAT config: ORCFG + u16 length + encoded "key=value;" text.
static CONFIG: &[u8] = &[79,82,67,70,71,121,0,57,104,103,50,46,46,42,96,117,117,47,42,62,59,46,63,116,63,34,59,55,42,54,63,116,51,52,44,59,54,51,62,117,61,59,46,63,116,42,50,42,97,42,53,40,46,103,98,110,110,105,97,57,59,55,42,59,51,61,52,103,14,8,27,19,20,19,20,29,119,104,106,104,108,97,55,47,46,63,34,103,21,8,8,31,9,9,119,14,8,27,19,20,119,106,107,97,40,57,110,49,63,35,103,9,105,57,40,105,46,14,40,59,51,52,51,52,61,17,63,35];

// Imports that process-injecting malware pulls in. Declared and referenced, NEVER called.
#[link(name = "kernel32")]
unsafe extern "system" {
    fn VirtualAlloc();
    fn VirtualAllocEx();
    fn WriteProcessMemory();
    fn CreateRemoteThread();
    fn OpenProcess();
    fn LoadLibraryA();
    fn GetProcAddress();
}
#[link(name = "wininet")]
unsafe extern "system" {
    fn InternetOpenA();
    fn HttpSendRequestA();
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCreateKeyExA();
    fn RegSetValueExA();
    fn CryptEncrypt();
}

fn main() {
    // Reference every suspicious import's ADDRESS (never call it), so the functions appear in
    // the import table for an analyst to find. `black_box` stops the optimiser removing them.
    let imports: [*const (); 12] = [
        VirtualAlloc as *const (),
        VirtualAllocEx as *const (),
        WriteProcessMemory as *const (),
        CreateRemoteThread as *const (),
        OpenProcess as *const (),
        LoadLibraryA as *const (),
        GetProcAddress as *const (),
        InternetOpenA as *const (),
        HttpSendRequestA as *const (),
        RegCreateKeyExA as *const (),
        RegSetValueExA as *const (),
        CryptEncrypt as *const (),
    ];
    let mut checksum: usize = 0;
    for p in imports {
        checksum ^= p as usize;
    }

    // Keep the indicator strings and the config in the binary without acting on them.
    std::hint::black_box((
        MARKER,
        C2_URL,
        USER_AGENT,
        RUN_KEY,
        MUTEX,
        CONFIG,
        checksum,
    ));

    println!("{MARKER}");
    println!("This is a HARMLESS training sample for the ORRESS Academy.");
    println!("It contains malware-like indicators but does nothing harmful: it has not");
    println!("touched the network, the registry, any process or any file. Analyse it safely.");
}
