//! Plain-language explanations of common section names.

/// Explains what a section with this name usually contains.
pub fn explain(name: &str) -> &'static str {
    match name {
        ".text" | "__text" | "CODE" | ".code" => {
            "Machine code: the program's instructions. This is where you will spend most \
             of your time."
        }
        ".data" | "__data" | "DATA" => "Initialized global variables that the program can change.",
        ".rdata" | ".rodata" | "__const" | "__cstring" => {
            "Read-only data: constant strings, tables and numbers. Passwords and flag \
             fragments are often here."
        }
        ".bss" | "__bss" | "BSS" => {
            "Global variables that start as zero. Takes no space in the file, only in memory."
        }
        ".idata" => "Import table: which DLL functions the program uses.",
        ".edata" => "Export table: functions this file offers to other programs.",
        ".rsrc" => {
            "Resources: icons, dialogs, version info and sometimes embedded files. Malware \
             likes to hide payloads here."
        }
        ".reloc" => "Relocations: fix-ups needed when the program loads at a different address.",
        "fothk" => {
            "Hot-patching thunks used by Microsoft system files. Normal in Windows binaries."
        }
        ".didat" => "Delay-load import table: DLLs loaded only when first used.",
        ".pdata" | ".xdata" => {
            "Exception handling tables (64-bit Windows). They also reveal where functions start."
        }
        ".tls" => {
            "Thread Local Storage. TLS callbacks run before the entry point: a known anti-debug trick."
        }
        ".plt" | ".plt.got" | ".plt.sec" | "__stubs" => {
            "Procedure Linkage Table: small stubs that jump to library functions. A call to \
             puts@plt calls puts."
        }
        ".got" | ".got.plt" | "__got" | "__la_symbol_ptr" => {
            "Global Offset Table: addresses of library functions, filled in at load time."
        }
        ".init" | ".fini" | ".init_array" | ".fini_array" | "__mod_init_func" => {
            "Code or function pointers that run before main starts or after it ends. Hidden \
             checks sometimes live here."
        }
        ".symtab" => {
            "Symbol table: names of functions and variables. Missing in stripped binaries."
        }
        ".dynsym" => "Dynamic symbols: names needed to link with shared libraries.",
        ".strtab" | ".dynstr" | ".shstrtab" => "String table: the names used by other tables.",
        ".dynamic" => "Dynamic linking information: needed libraries and loader settings.",
        ".interp" => "Path of the dynamic loader (e.g. /lib64/ld-linux-x86-64.so.2).",
        ".comment" => "Compiler version strings, e.g. \"GCC: (Ubuntu ...)\".",
        ".eh_frame" | ".eh_frame_hdr" | ".gcc_except_table" => {
            "Stack unwinding information for exceptions; also reveals function boundaries."
        }
        ".gopclntab" | "__gopclntab" => {
            "Go runtime table that maps code to function names and line numbers. Lets \
             ORRESS recover names even in stripped Go binaries."
        }
        ".go.buildinfo" => "Go build information: Go version and module paths.",
        "UPX0" | "UPX1" | "UPX2" | ".UPX0" | ".UPX1" => {
            "Created by the UPX packer. UPX0 is empty in the file and receives the unpacked \
             code at run time; UPX1 holds the compressed program."
        }
        n if n.starts_with(".debug") || n.starts_with("__debug") => {
            "Debug information (DWARF): names, types and line numbers. A gift for reversers."
        }
        n if n.starts_with(".note") => "Notes such as the build ID and ABI version.",
        n if n.starts_with(".rela") || n.starts_with(".rel.") => {
            "Relocation entries for the dynamic linker."
        }
        _ => {
            "No standard meaning. Custom or unusual section names can be a sign of a packer or protector."
        }
    }
}
