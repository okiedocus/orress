//! Reading a (possibly non-debugged) process's memory, for in-memory YARA scanning. Enumerates
//! the committed, readable regions of a process by PID and copies them out: on Windows via
//! `VirtualQueryEx` + `ReadProcessMemory`, on Linux via `/proc/<pid>/maps` + `/proc/<pid>/mem`;
//! other platforms return an error.

/// A snapshot of one readable memory region.
#[derive(Debug, Clone)]
pub struct MemRegion {
    pub base: u64,
    pub data: Vec<u8>,
}

/// One entry of a process's memory map (name includes `[heap]`, `[stack]` and file paths on Linux).
#[derive(Debug, Clone)]
pub struct MapRegion {
    pub base: u64,
    pub size: u64,
    pub perms: String,
    pub name: String,
}

#[cfg(windows)]
pub fn read_all_memory(pid: u32, max_total: usize) -> Result<Vec<MemRegion>, String> {
    use core::ffi::c_void;

    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // SAFETY: a standard OpenProcess for read access; fails cleanly on protected processes.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| e.message())?;

    let mut regions = Vec::new();
    let mut total = 0usize;
    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `handle` is valid; `mbi` is a correctly-sized out buffer.
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let readable = mbi.State == MEM_COMMIT
            && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
            && (mbi.Protect.0 & PAGE_GUARD.0) == 0;
        if readable && size > 0 && total < max_total {
            let to_read = size.min(max_total - total);
            let mut buf = vec![0u8; to_read];
            let mut read = 0usize;
            // SAFETY: valid handle; `buf` has `to_read` bytes; `read` receives the count.
            let _ = unsafe {
                ReadProcessMemory(
                    handle,
                    base as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    to_read,
                    Some(&mut read),
                )
            };
            // A region with an unreadable tail fails with ERROR_PARTIAL_COPY yet still
            // copies the readable prefix: keep whatever was read.
            if read > 0 {
                buf.truncate(read);
                total += read;
                regions.push(MemRegion {
                    base: base as u64,
                    data: buf,
                });
            }
        }
        match base.checked_add(size) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
        if total >= max_total {
            break;
        }
    }
    // SAFETY: `handle` came from OpenProcess and is closed exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    Ok(regions)
}

/// Windows: enumerate committed regions (no file names; used only for parity — the glibc heap
/// view is Linux-only).
#[cfg(windows)]
pub fn memory_map(pid: u32) -> Result<Vec<MapRegion>, String> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    // SAFETY: a standard query-only OpenProcess; fails cleanly on protected processes.
    let handle =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }.map_err(|e| e.message())?;
    let mut out = Vec::new();
    let mut addr: usize = 0;
    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `handle` is valid; `mbi` is a correctly-sized out buffer.
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let base = mbi.BaseAddress as u64;
        let size = mbi.RegionSize as u64;
        if mbi.State == MEM_COMMIT && size > 0 {
            out.push(MapRegion {
                base,
                size,
                perms: format!("{:#x}", mbi.Protect.0),
                name: String::new(),
            });
        }
        match (base as usize).checked_add(mbi.RegionSize) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
    }
    // SAFETY: `handle` came from OpenProcess and is closed exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    Ok(out)
}

/// Windows: read `len` bytes at `addr` from process `pid`.
#[cfg(windows)]
pub fn read_mem(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_READ};

    // SAFETY: a standard read-only OpenProcess.
    let handle = unsafe { OpenProcess(PROCESS_VM_READ, false, pid) }.map_err(|e| e.message())?;
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    // SAFETY: valid handle; `buf` has `len` bytes; `read` receives the count.
    let _ = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            Some(&mut read),
        )
    };
    // SAFETY: handle closed exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    buf.truncate(read);
    Ok(buf)
}

/// Linux: the process's memory map from `/proc/<pid>/maps`, including `[heap]` and file paths.
#[cfg(target_os = "linux")]
pub fn memory_map(pid: u32) -> Result<Vec<MapRegion>, String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("/proc/{pid}/maps: {e}"))?;
    let mut out = Vec::new();
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        // After perms: offset, dev, inode, then the optional path.
        let name = it.nth(3).unwrap_or("").to_string();
        let Some((start, end)) = range.split_once('-').and_then(|(s, e)| {
            Some((
                u64::from_str_radix(s, 16).ok()?,
                u64::from_str_radix(e, 16).ok()?,
            ))
        }) else {
            continue;
        };
        out.push(MapRegion {
            base: start,
            size: end.saturating_sub(start),
            perms: perms.to_string(),
            name,
        });
    }
    Ok(out)
}

/// Linux: read `len` bytes at `addr` from `/proc/<pid>/mem` (chunked; returns the readable prefix).
#[cfg(target_os = "linux")]
pub fn read_mem(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::FileExt;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))
        .map_err(|e| format!("/proc/{pid}/mem: {e}"))?;
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        let chunk = (len - got).min(1 << 20);
        match mem.read_at(&mut buf[got..got + chunk], addr + got as u64) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Linux: walk `/proc/<pid>/maps` and copy each readable mapping out of `/proc/<pid>/mem`.
/// Needs ptrace-read access to the process (same user, and Yama's `ptrace_scope` permitting).
#[cfg(target_os = "linux")]
pub fn read_all_memory(pid: u32, max_total: usize) -> Result<Vec<MemRegion>, String> {
    use std::os::unix::fs::FileExt;

    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("/proc/{pid}/maps: {e}"))?;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))
        .map_err(|e| format!("/proc/{pid}/mem: {e}"))?;

    let mut regions = Vec::new();
    let mut total = 0usize;
    for line in maps.lines() {
        if total >= max_total {
            break;
        }
        // start-end perms offset dev inode [path]
        let mut it = line.split_whitespace();
        let (Some(range), Some(perms)) = (it.next(), it.next()) else {
            continue;
        };
        let path = it.nth(3).unwrap_or("");
        // Unreadable, or a kernel page that can't be read through /proc/<pid>/mem.
        if !perms.starts_with('r') || path == "[vvar]" || path == "[vsyscall]" {
            continue;
        }
        let Some((start, end)) = range.split_once('-').and_then(|(s, e)| {
            Some((
                u64::from_str_radix(s, 16).ok()?,
                u64::from_str_radix(e, 16).ok()?,
            ))
        }) else {
            continue;
        };
        let size = usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX);
        let to_read = size.min(max_total - total);
        if to_read == 0 {
            continue;
        }
        // Read in chunks so an unreadable page part-way through keeps the prefix.
        let mut buf = vec![0u8; to_read];
        let mut got = 0usize;
        while got < to_read {
            let chunk = (to_read - got).min(1 << 20);
            match mem.read_at(&mut buf[got..got + chunk], start + got as u64) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        if got > 0 {
            buf.truncate(got);
            total += got;
            regions.push(MemRegion {
                base: start,
                data: buf,
            });
        }
    }
    Ok(regions)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn read_all_memory(_pid: u32, _max_total: usize) -> Result<Vec<MemRegion>, String> {
    Err("reading process memory is only implemented on Windows and Linux".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn memory_map(_pid: u32) -> Result<Vec<MapRegion>, String> {
    Err("reading a process memory map is only implemented on Windows and Linux".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn read_mem(_pid: u32, _addr: u64, _len: usize) -> Result<Vec<u8>, String> {
    Err("reading process memory is only implemented on Windows and Linux".into())
}

#[cfg(all(test, any(windows, target_os = "linux")))]
mod tests {
    use super::*;

    #[test]
    fn reads_own_memory_and_finds_a_marker() {
        // A unique marker on the heap (committed, readable) — we should read it back.
        let marker: &[u8] = b"ORRESS_PROCMEM_MARKER_7a3f91";
        let held: Vec<u8> = marker.to_vec();
        std::hint::black_box(&held);

        let regions = read_all_memory(std::process::id(), 512 * 1024 * 1024).unwrap();
        assert!(!regions.is_empty(), "should read some committed regions");
        let found = regions
            .iter()
            .any(|r| r.data.windows(marker.len()).any(|w| w == marker));
        assert!(found, "should find our marker in our own memory");
        std::hint::black_box(&held);
    }
}
