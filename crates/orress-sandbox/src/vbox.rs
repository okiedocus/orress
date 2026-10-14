//! VirtualBox control, by driving the `VBoxManage` CLI. This lets ORRESS orchestrate an analysis
//! VM from the host — list VMs, snapshot, revert, start/stop — for the "revert to clean, run the
//! sample, collect results, revert" workflow. The output parsers are pure (and unit-tested); the
//! wrappers shell out.

use std::path::PathBuf;
use std::process::Command;

/// A VirtualBox VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vm {
    pub name: String,
    pub uuid: String,
}

/// Finds the `VBoxManage` executable (PATH, then the default install location).
pub fn vboxmanage() -> Option<PathBuf> {
    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            for exe in ["VBoxManage", "VBoxManage.exe"] {
                let p = dir.join(exe);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    for cand in [
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        "/usr/bin/VBoxManage",
        "/usr/local/bin/VBoxManage",
        "/Applications/VirtualBox.app/Contents/MacOS/VBoxManage",
    ] {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Whether VirtualBox is available.
pub fn available() -> bool {
    vboxmanage().is_some()
}

/// Runs `VBoxManage` with `args`, returning stdout or an error string.
fn run(args: &[&str]) -> Result<String, String> {
    let exe = vboxmanage().ok_or("VBoxManage not found — is VirtualBox installed?")?;
    let out = Command::new(exe)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr)
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("VBoxManage failed")
            .to_string())
    }
}

// --- pure parsers ---------------------------------------------------------

/// Parses `VBoxManage list vms` output: lines like `"Name" {uuid}`.
pub fn parse_vms(output: &str) -> Vec<Vm> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let name_end = line.rfind('"')?;
            let name = line.get(1..name_end)?.to_string();
            let brace = line.find('{')?;
            let close = line.find('}')?;
            let uuid = line.get(brace + 1..close)?.to_string();
            (!name.is_empty()).then_some(Vm { name, uuid })
        })
        .collect()
}

/// Parses `VMState="..."` from `showvminfo --machinereadable` output.
pub fn parse_state(machinereadable: &str) -> Option<String> {
    machinereadable
        .lines()
        .find_map(|l| l.strip_prefix("VMState="))
        .map(|v| v.trim_matches('"').to_string())
}

/// Parses `SnapshotName*="..."` entries from `snapshot <vm> list --machinereadable`.
pub fn parse_snapshots(machinereadable: &str) -> Vec<String> {
    machinereadable
        .lines()
        .filter(|l| l.starts_with("SnapshotName"))
        .filter_map(|l| l.split_once('='))
        .map(|(_, v)| v.trim_matches('"').to_string())
        .collect()
}

// --- wrappers -------------------------------------------------------------

pub fn list_vms() -> Result<Vec<Vm>, String> {
    Ok(parse_vms(&run(&["list", "vms"])?))
}

pub fn state(vm: &str) -> Result<String, String> {
    Ok(parse_state(&run(&["showvminfo", vm, "--machinereadable"])?)
        .unwrap_or_else(|| "unknown".into()))
}

pub fn snapshots(vm: &str) -> Result<Vec<String>, String> {
    // `snapshot list` errors when a VM has none; treat that as an empty list.
    match run(&["snapshot", vm, "list", "--machinereadable"]) {
        Ok(out) => Ok(parse_snapshots(&out)),
        Err(e) if e.to_lowercase().contains("does not have any snapshot") => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

pub fn take_snapshot(vm: &str, name: &str) -> Result<(), String> {
    run(&["snapshot", vm, "take", name]).map(|_| ())
}

pub fn restore_snapshot(vm: &str, name: &str) -> Result<(), String> {
    run(&["snapshot", vm, "restore", name]).map(|_| ())
}

pub fn restore_current(vm: &str) -> Result<(), String> {
    run(&["snapshot", vm, "restorecurrent"]).map(|_| ())
}

pub fn start(vm: &str, headless: bool) -> Result<(), String> {
    let kind = if headless { "headless" } else { "gui" };
    run(&["startvm", vm, "--type", kind]).map(|_| ())
}

pub fn poweroff(vm: &str) -> Result<(), String> {
    run(&["controlvm", vm, "poweroff"]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vm_list() {
        let out = "\"Kali-Linux\" {b3d301da-f47e-45e3-865e-70f8e88ecd5a}\n\"Linux-Mint\" {1ae66575-e681-4c44-9d71-ae4089cfad5d}\n";
        let vms = parse_vms(out);
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0].name, "Kali-Linux");
        assert_eq!(vms[0].uuid, "b3d301da-f47e-45e3-865e-70f8e88ecd5a");
        assert_eq!(vms[1].name, "Linux-Mint");
    }

    #[test]
    fn parses_state() {
        let mr = "name=\"VM\"\nVMState=\"poweroff\"\nVMStateChangeTime=\"...\"\n";
        assert_eq!(parse_state(mr).as_deref(), Some("poweroff"));
    }

    #[test]
    fn parses_snapshots() {
        let mr = "SnapshotName=\"clean\"\nSnapshotUUID=\"...\"\nSnapshotName-1=\"after-run\"\nCurrentSnapshotName=\"clean\"\n";
        let snaps = parse_snapshots(mr);
        assert!(snaps.contains(&"clean".to_string()));
        assert!(snaps.contains(&"after-run".to_string()));
    }
}
