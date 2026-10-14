//! Am I running inside a virtual machine? The execution guard refuses to run flagged samples on
//! a bare-metal host, so this needs to be reasonably reliable. The primary signal is the CPUID
//! hypervisor-present bit (and the hypervisor vendor string); file artifacts of common guest
//! additions and the firmware's SMBIOS/DMI system identity (Linux `/sys/class/dmi/id`, the
//! Windows registry's BIOS key) are secondary hints. The firmware identity is what tells a
//! genuine Hyper-V guest ("Virtual Machine" by Microsoft Corporation) apart from VBS on a
//! physical host, where CPUID alone reports "Microsoft Hv" either way.

#[cfg(windows)]
use std::path::Path;

/// What the VM check found.
#[derive(Debug, Clone, Default)]
pub struct VmEvidence {
    /// The CPUID hypervisor-present bit was set.
    pub hypervisor: bool,
    /// The hypervisor vendor string (e.g. "VMwareVMware", "VBoxVBoxVBox", "Microsoft Hv").
    pub vendor: Option<String>,
    /// Secondary hints (guest-additions files, etc.).
    pub hints: Vec<String>,
}

impl VmEvidence {
    /// Whether this is a confident VM determination. A bare hypervisor bit is **not** enough on
    /// Windows: virtualization-based security reports vendor "Microsoft Hv" on physical hosts
    /// too, so we only trust an unambiguous guest hypervisor vendor or a guest-additions file.
    pub fn looks_like_vm(&self) -> bool {
        (self.hypervisor && self.vendor.as_deref().is_some_and(is_vm_vendor))
            || !self.hints.is_empty()
    }

    /// A hypervisor is present but the evidence is ambiguous (likely VBS on a physical host).
    pub fn ambiguous(&self) -> bool {
        self.hypervisor && !self.looks_like_vm()
    }
}

/// Whether the hypervisor vendor string names a guest VM (not host-side VBS).
fn is_vm_vendor(vendor: &str) -> bool {
    let v = vendor.to_ascii_lowercase();
    [
        "vmware",
        "vbox",
        "kvm",
        "xen",
        "qemu",
        "tcg",
        "prl",
        "bhyve",
        "virtualapple",
    ]
    .iter()
    .any(|m| v.contains(m))
}

/// Collects VM evidence.
pub fn detect() -> VmEvidence {
    let (hypervisor, vendor) = cpuid_hypervisor();
    let mut hints = file_hints();
    hints.extend(firmware_hint());
    VmEvidence {
        hypervisor,
        vendor,
        hints,
    }
}

/// Classifies the firmware's (SMBIOS/DMI) system identity — manufacturer, product name, and
/// board vendor — into a VM hint. Only unambiguous virtual-hardware identities count: in
/// particular Hyper-V is recognised solely by Microsoft's "Virtual Machine" product, so a
/// physical Microsoft device (a Surface) running virtualization-based security does not.
// Firmware identity is only read on Windows and Linux; elsewhere this is used by tests alone.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
fn classify_firmware(manufacturer: &str, product: &str, board_vendor: &str) -> Option<String> {
    let m = manufacturer.trim().to_ascii_lowercase();
    let p = product.trim().to_ascii_lowercase();
    let b = board_vendor.trim().to_ascii_lowercase();
    let any = |needle: &str| m.contains(needle) || p.contains(needle) || b.contains(needle);
    let name = if any("innotek") || any("virtualbox") {
        "VirtualBox"
    } else if any("vmware") {
        "VMware"
    } else if p.contains("kvm") || m == "kvm" {
        "KVM"
    } else if any("qemu") {
        "QEMU"
    } else if m == "xen" || p.contains("hvm domu") {
        "Xen"
    } else if any("parallels") {
        "Parallels"
    } else if m == "bochs" || p == "bochs" {
        "Bochs"
    } else if m == "microsoft corporation" && p == "virtual machine" {
        "Hyper-V"
    } else {
        return None;
    };
    Some(format!(
        "{name} virtual hardware (firmware reports \"{}\" / \"{}\")",
        manufacturer.trim(),
        product.trim()
    ))
}

/// Linux: the DMI identity the kernel exposes under `/sys/class/dmi/id`.
#[cfg(target_os = "linux")]
fn firmware_hint() -> Option<String> {
    let read = |f: &str| {
        std::fs::read_to_string(format!("/sys/class/dmi/id/{f}"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    classify_firmware(
        &read("sys_vendor"),
        &read("product_name"),
        &read("board_vendor"),
    )
}

/// Windows: the SMBIOS identity the OS caches in the registry under
/// `HKLM\HARDWARE\DESCRIPTION\System\BIOS` (read via `reg.exe` — no WMI, no FFI).
#[cfg(windows)]
fn firmware_hint() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let reg = Path::new(&root).join(r"System32\reg.exe");
    let out = std::process::Command::new(reg)
        .args(["query", r"HKLM\HARDWARE\DESCRIPTION\System\BIOS"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let value = |name: &str| reg_value(&text, name).unwrap_or_default();
    classify_firmware(
        &value("SystemManufacturer"),
        &value("SystemProductName"),
        &value("BaseBoardManufacturer"),
    )
}

#[cfg(not(any(windows, target_os = "linux")))]
fn firmware_hint() -> Option<String> {
    None
}

/// Extracts a `REG_SZ` value from `reg query` output (`    Name    REG_SZ    Data`).
#[cfg(any(windows, test))]
fn reg_value(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim_start();
        let rest = line
            .strip_prefix(name)
            .filter(|r| r.starts_with(char::is_whitespace))?;
        let (_, data) = rest.trim_start().split_once("REG_SZ")?;
        Some(data.trim().to_string())
    })
}

/// Whether we appear to be *confidently* inside a VM (see [`VmEvidence::looks_like_vm`]).
pub fn in_vm() -> bool {
    detect().looks_like_vm()
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpuid_hypervisor() -> (bool, Option<String>) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::__cpuid;

    // __cpuid only reads CPU identification registers (no side effects) and is callable safely
    // on the x86-64 baseline where CPUID is always present.
    let leaf1 = __cpuid(1);
    let present = (leaf1.ecx >> 31) & 1 == 1;
    if !present {
        return (false, None);
    }
    let v = __cpuid(0x4000_0000);
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&v.ebx.to_le_bytes());
    bytes.extend_from_slice(&v.ecx.to_le_bytes());
    bytes.extend_from_slice(&v.edx.to_le_bytes());
    let vendor = String::from_utf8_lossy(&bytes)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    (true, (!vendor.is_empty()).then_some(vendor))
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpuid_hypervisor() -> (bool, Option<String>) {
    (false, None)
}

#[cfg(windows)]
fn file_hints() -> Vec<String> {
    const FILES: &[(&str, &str)] = &[
        (r"C:\Windows\System32\drivers\vmmouse.sys", "VMware"),
        (r"C:\Windows\System32\drivers\vmhgfs.sys", "VMware"),
        (r"C:\Windows\System32\drivers\VBoxMouse.sys", "VirtualBox"),
        (r"C:\Windows\System32\drivers\VBoxGuest.sys", "VirtualBox"),
        (r"C:\Windows\System32\vboxservice.exe", "VirtualBox"),
        (r"C:\Windows\System32\drivers\vioscsi.sys", "QEMU/KVM"),
    ];
    FILES
        .iter()
        .filter(|(p, _)| Path::new(p).exists())
        .map(|(_, name)| format!("{name} guest file present"))
        .collect()
}

#[cfg(not(windows))]
fn file_hints() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_hv_alone_is_not_a_confirmed_vm() {
        let e = VmEvidence {
            hypervisor: true,
            vendor: Some("Microsoft Hv".into()),
            hints: Vec::new(),
        };
        assert!(
            !e.looks_like_vm(),
            "VBS on a physical host must not count as a VM"
        );
        assert!(e.ambiguous());
    }

    #[test]
    fn known_vm_vendor_counts() {
        let e = VmEvidence {
            hypervisor: true,
            vendor: Some("VMwareVMware".into()),
            hints: Vec::new(),
        };
        assert!(e.looks_like_vm());
        assert!(!e.ambiguous());
    }

    #[test]
    fn guest_files_count() {
        let e = VmEvidence {
            hypervisor: false,
            vendor: None,
            hints: vec!["VirtualBox guest file present".into()],
        };
        assert!(e.looks_like_vm());
    }

    #[test]
    fn firmware_identities_of_known_hypervisors() {
        let hit = |m, p, b| classify_firmware(m, p, b);
        assert!(
            hit("innotek GmbH", "VirtualBox", "Oracle Corporation")
                .unwrap()
                .starts_with("VirtualBox")
        );
        assert!(
            hit(
                "VMware, Inc.",
                "VMware Virtual Platform",
                "Intel Corporation"
            )
            .unwrap()
            .starts_with("VMware")
        );
        assert!(
            hit("VMware, Inc.", "VMware20,1", "")
                .unwrap()
                .starts_with("VMware")
        );
        assert!(
            hit("QEMU", "Standard PC (Q35 + ICH9, 2009)", "")
                .unwrap()
                .starts_with("QEMU")
        );
        assert!(hit("Red Hat", "KVM", "").unwrap().starts_with("KVM"));
        assert!(hit("Xen", "HVM domU", "").unwrap().starts_with("Xen"));
        assert!(
            hit(
                "Parallels Software International Inc.",
                "Parallels Virtual Platform",
                ""
            )
            .unwrap()
            .starts_with("Parallels")
        );
        assert!(
            hit(
                "Microsoft Corporation",
                "Virtual Machine",
                "Microsoft Corporation"
            )
            .unwrap()
            .starts_with("Hyper-V")
        );
    }

    #[test]
    fn physical_machines_are_not_flagged() {
        // A Surface is Microsoft hardware but not a VM — VBS on it must stay ambiguous.
        assert_eq!(
            classify_firmware(
                "Microsoft Corporation",
                "Surface Pro 7",
                "Microsoft Corporation"
            ),
            None
        );
        assert_eq!(
            classify_firmware("Dell Inc.", "XPS 15 9520", "Dell Inc."),
            None
        );
        assert_eq!(classify_firmware("LENOVO", "20XW0026GE", "LENOVO"), None);
        assert_eq!(
            classify_firmware("ASUS", "System Product Name", "ASUSTeK COMPUTER INC."),
            None
        );
        assert_eq!(classify_firmware("", "", ""), None);
    }

    #[test]
    fn hyper_v_guest_is_confirmed_by_firmware() {
        let e = VmEvidence {
            hypervisor: true,
            vendor: Some("Microsoft Hv".into()),
            hints: classify_firmware("Microsoft Corporation", "Virtual Machine", "")
                .into_iter()
                .collect(),
        };
        assert!(e.looks_like_vm());
        assert!(!e.ambiguous());
    }

    #[test]
    fn parses_reg_query_output() {
        let out = "\r\nHKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\r\n    \
                   BaseBoardManufacturer    REG_SZ    Microsoft Corporation\r\n    \
                   BiosMajorRelease    REG_DWORD    0x4\r\n    \
                   SystemManufacturer    REG_SZ    Microsoft Corporation\r\n    \
                   SystemProductName    REG_SZ    Virtual Machine\r\n";
        assert_eq!(
            reg_value(out, "SystemManufacturer").as_deref(),
            Some("Microsoft Corporation")
        );
        assert_eq!(
            reg_value(out, "SystemProductName").as_deref(),
            Some("Virtual Machine")
        );
        assert_eq!(reg_value(out, "BiosMajorRelease"), None);
        assert_eq!(reg_value(out, "Missing"), None);
    }

    #[test]
    fn detect_runs_without_panicking() {
        // We can't assert the value (depends where the test runs), only that it works.
        let e = detect();
        if e.hypervisor {
            // A vendor string is usually, but not always, present.
            let _ = &e.vendor;
        }
        let _ = in_vm();
    }
}
