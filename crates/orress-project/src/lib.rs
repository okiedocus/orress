//! Open documents and their shared state.
//!
//! A [`Document`] is one opened file. Reading and analysis run on a background thread
//! so the interface never freezes; views show what is ready and fill in the rest when
//! the work finishes. All views of a document share its cursor, which is how clicking
//! a string or a section moves the hex view and updates the inspector.

mod annotations;
pub mod ctypes;
pub mod interop;
pub mod types;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

pub use annotations::{Annotations, validate_name};
pub use ctypes::{parse_c_decls, parse_header};
pub use orress_analysis::Program;
use orress_bytes::Endian;
use orress_bytes::strings::FoundString;
use orress_loaders::BinaryInfo;
pub use types::{FieldDef, FuncProto, LaidField, Prim, TypeCatalog, TypeRef, UserType, references};

/// Navigation history depth.
const MAX_HISTORY: usize = 200;

/// Largest file ORRESS loads fully into memory.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;
/// Minimum characters for the strings list.
pub const MIN_STRING_LEN: usize = 4;
/// Cap on extracted strings, so random data cannot exhaust memory.
pub const MAX_STRINGS: usize = 500_000;
/// Number of blocks in the entropy overview.
pub const ENTROPY_BLOCKS: usize = 2048;

/// Results of the background analysis.
pub struct Analysis {
    pub info: BinaryInfo,
    pub strings: Vec<FoundString>,
    pub entropy: Vec<f32>,
    /// Bytes per entry in `entropy`.
    pub entropy_block: usize,
}

impl Analysis {
    pub fn run(data: &[u8]) -> Self {
        let info = orress_loaders::triage(data);
        let strings = orress_bytes::strings::extract(data, MIN_STRING_LEN, MAX_STRINGS);
        let entropy_block = orress_bytes::entropy::block_size_for(data.len(), ENTROPY_BLOCKS);
        let entropy = orress_bytes::entropy::blocks(data, entropy_block);
        Self {
            info,
            strings,
            entropy,
            entropy_block,
        }
    }
}

pub type Bytes = Arc<Vec<u8>>;

pub struct Document {
    pub path: PathBuf,
    data: Arc<OnceLock<Result<Bytes, String>>>,
    analysis: Arc<OnceLock<Arc<Analysis>>>,
    /// Code analysis; `Some(None)` when the architecture is not supported.
    program: Arc<OnceLock<Option<Arc<Program>>>>,
    /// The file as read from disk, before patches.
    original: Arc<OnceLock<Bytes>>,
    notify: Arc<dyn Fn() + Send + Sync>,
    /// Coalesces re-analysis after patches (one worker, latest request wins).
    rebuilds: Arc<Mutex<RebuildQueue>>,
    /// Your names, comments and bookmarks (loaded once the file hash is known).
    pub annotations: Annotations,
    annotations_file: Option<PathBuf>,
    annotations_loaded: bool,
    /// Last error loading or saving annotations, for the UI to show.
    pub annotations_error: Option<String>,
    /// Increases on every annotation change, so views can refresh cached layouts.
    pub generation: u64,
    back: Vec<u64>,
    forward: Vec<u64>,
    /// Address the cross-references panel is pinned to (set with X in the disassembly). While
    /// `None`, the panel follows the function under the cursor.
    pub xref_target: Option<u64>,
    /// Shared cursor: the byte offset all views of this document point at.
    pub cursor: u64,
    /// Selected byte range (inclusive start, exclusive end), if any.
    pub selection: Option<(u64, u64)>,
    /// Set by a view that wants the hex view to scroll to the cursor.
    pub reveal: bool,
    /// Byte order the inspector uses.
    pub endian: Endian,
}

impl Document {
    fn open(path: PathBuf, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        let original = Arc::new(OnceLock::new());
        let slots = Slots::default();
        spawn_load(
            path.clone(),
            Source::File(Arc::clone(&original)),
            &slots,
            Arc::clone(&notify),
        );
        Self {
            path,
            data: slots.data,
            analysis: slots.analysis,
            program: slots.program,
            original,
            notify,
            rebuilds: Arc::default(),
            annotations: Annotations::default(),
            annotations_file: None,
            annotations_loaded: false,
            annotations_error: None,
            generation: 0,
            back: Vec::new(),
            forward: Vec::new(),
            xref_target: None,
            cursor: 0,
            selection: None,
            reveal: false,
            endian: Endian::Little,
        }
    }

    /// Re-runs loading and analysis on the original bytes with all patches applied.
    fn rebuild(&mut self) {
        let Some(original) = self.original.get() else {
            return;
        };
        let mut bytes = original.as_ref().clone();
        for (&offset, &value) in &self.annotations.patches {
            if let Some(b) = usize::try_from(offset).ok().and_then(|o| bytes.get_mut(o)) {
                *b = value;
            }
        }
        let bytes = Arc::new(bytes);
        let slots = Slots::default();
        // The bytes are known now; only the analysis needs the background thread. Patching
        // byte by byte calls this often, so requests are queued: one worker analyzes the
        // newest bytes and drops any request that a later patch has already replaced.
        let _ = slots.data.set(Ok(Arc::clone(&bytes)));
        queue_rebuild(
            &self.rebuilds,
            self.path.clone(),
            bytes,
            slots.clone(),
            Arc::clone(&self.notify),
        );
        self.data = slots.data;
        self.analysis = slots.analysis;
        self.program = slots.program;
        self.generation += 1;
    }

    /// Changes bytes at `offset`. Bytes that equal the original remove their patch.
    /// The file on disk is not touched; use [`Document::export`] to save a copy.
    pub fn patch(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        let original = self
            .original
            .get()
            .ok_or("the file is still loading")?
            .clone();
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|&e| e <= original.len() as u64)
            .ok_or("the patch goes past the end of the file")?;
        for (off, &value) in (offset..end).zip(bytes) {
            if original[off as usize] == value {
                self.annotations.patches.remove(&off);
            } else {
                self.annotations.patches.insert(off, value);
            }
        }
        self.save_annotations();
        self.rebuild();
        Ok(())
    }

    /// Removes all patches.
    pub fn revert_patches(&mut self) {
        if self.annotations.patches.is_empty() {
            return;
        }
        self.annotations.patches.clear();
        self.save_annotations();
        self.rebuild();
    }

    pub fn is_patched(&self, offset: u64) -> bool {
        self.annotations.patches.contains_key(&offset)
    }

    /// The original (unpatched) byte at `offset`.
    pub fn original_byte(&self, offset: u64) -> Option<u8> {
        self.original
            .get()?
            .get(usize::try_from(offset).ok()?)
            .copied()
    }

    /// Writes the current (patched) bytes to `path`.
    pub fn export(&self, path: &Path) -> Result<(), String> {
        if path == self.path {
            return Err("refusing to overwrite the original file; choose another name".into());
        }
        let bytes = self.bytes().ok_or("the file is still loading")?;
        std::fs::write(path, bytes.as_slice()).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// `None` while still reading the file.
    pub fn data(&self) -> Option<&Result<Bytes, String>> {
        self.data.get()
    }

    pub fn bytes(&self) -> Option<&Bytes> {
        self.data.get().and_then(|r| r.as_ref().ok())
    }

    /// `None` while the analysis is still running (or if loading failed).
    pub fn analysis(&self) -> Option<&Arc<Analysis>> {
        self.analysis.get()
    }

    /// `None` while disassembling; `Some(None)` if the architecture is not supported.
    pub fn program_state(&self) -> Option<Option<&Arc<Program>>> {
        self.program.get().map(Option::as_ref)
    }

    pub fn program(&self) -> Option<&Arc<Program>> {
        self.program.get().and_then(Option::as_ref)
    }

    /// Loads saved annotations once the file's hash is known.
    fn load_annotations(&mut self, dir: Option<&Path>) {
        if self.annotations_loaded {
            return;
        }
        let Some(analysis) = self.analysis.get() else {
            return;
        };
        self.annotations_loaded = true;
        let sha = analysis.info.hashes.sha256.clone();
        self.annotations = Annotations::new(&sha, &self.path);
        let Some(dir) = dir else {
            return;
        };
        let file = Annotations::file_for(dir, &sha);
        match Annotations::load(&file) {
            Ok(Some(saved)) => {
                self.annotations = saved;
                self.annotations.last_path = Some(self.path.clone());
            }
            Ok(None) => {}
            Err(e) => {
                // Never overwrite a file we could not read: move it aside first, and if
                // that fails keep the annotations in memory only.
                let mut backup = file.clone().into_os_string();
                backup.push(".corrupt");
                let backup = PathBuf::from(backup);
                if let Err(re) = std::fs::rename(&file, &backup) {
                    self.annotations_error = Some(format!(
                        "{e} (could not move it aside: {re}; changes stay in memory only)"
                    ));
                    return;
                }
                self.annotations_error = Some(format!(
                    "{e} (the unreadable file was kept as {})",
                    backup.display()
                ));
            }
        }
        self.annotations_file = Some(file);
        if !self.annotations.patches.is_empty() {
            self.rebuild();
        }
    }

    fn save_annotations(&mut self) {
        self.generation += 1;
        if let Some(file) = &self.annotations_file {
            self.annotations_error = self.annotations.save(file).err();
        }
    }

    /// Marks the annotations changed (bumps `generation` so views refresh, and persists). Use after
    /// mutating [`Document::annotations`] directly — e.g. when applying a teammate's shared edits.
    pub fn touch_annotations(&mut self) {
        self.save_annotations();
    }

    /// Renames `addr`. An empty name removes your name and shows the original again.
    pub fn rename(&mut self, addr: u64, name: &str) -> Result<(), String> {
        validate_name(name)?;
        let name = name.trim();
        if name.is_empty() {
            self.annotations.names.remove(&addr);
        } else {
            self.annotations.names.insert(addr, name.to_owned());
        }
        self.save_annotations();
        Ok(())
    }

    /// Sets the comment at `addr`; empty removes it.
    pub fn set_comment(&mut self, addr: u64, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            self.annotations.comments.remove(&addr);
        } else {
            self.annotations.comments.insert(addr, text.to_owned());
        }
        self.save_annotations();
    }

    /// The user's type catalog, with the pointer size set from this binary's bitness.
    pub fn type_catalog(&self) -> TypeCatalog {
        let bits = self.analysis.get().and_then(|a| a.info.bits);
        TypeCatalog::new(self.annotations.types.clone(), bits)
    }

    /// Defines or replaces a user type. Validated against the current catalog.
    pub fn define_type(&mut self, ty: UserType) -> Result<(), String> {
        self.type_catalog().validate(&ty)?;
        self.annotations.types.insert(ty.name().to_owned(), ty);
        self.save_annotations();
        Ok(())
    }

    /// Removes a user type by name, and any data applications that referenced it.
    pub fn remove_type(&mut self, name: &str) {
        if self.annotations.types.remove(name).is_some() {
            self.annotations
                .data_types
                .retain(|_, t| !references(t, name));
            self.save_annotations();
        }
    }

    /// Applies a type to a data address.
    pub fn apply_data_type(&mut self, addr: u64, ty: TypeRef) {
        self.annotations.data_types.insert(addr, ty);
        self.save_annotations();
    }

    /// Removes any type applied at `addr`.
    pub fn clear_data_type(&mut self, addr: u64) {
        if self.annotations.data_types.remove(&addr).is_some() {
            self.save_annotations();
        }
    }

    /// Pins a function prototype to `addr` (consumed by the decompiler).
    pub fn set_prototype(&mut self, addr: u64, proto: FuncProto) {
        self.annotations.func_prototypes.insert(addr, proto);
        self.save_annotations();
    }

    /// Removes any prototype pinned to `addr`.
    pub fn clear_prototype(&mut self, addr: u64) {
        if self.annotations.func_prototypes.remove(&addr).is_some() {
            self.save_annotations();
        }
    }

    pub fn toggle_bookmark(&mut self, addr: u64) {
        if !self.annotations.bookmarks.remove(&addr) {
            self.annotations.bookmarks.insert(addr);
        }
        self.save_annotations();
    }

    /// Name shown for `addr`: yours first, then what the analysis found.
    pub fn name_of(&self, addr: u64) -> Option<String> {
        if let Some(n) = self.annotations.names.get(&addr) {
            return Some(n.clone());
        }
        self.program()?.name(addr).map(|n| n.text.clone())
    }

    /// Memory address of the cursor, if the cursor is inside a loaded section.
    pub fn cursor_address(&self) -> Option<u64> {
        self.analysis.get()?.info.offset_to_address(self.cursor)
    }

    pub fn address_to_offset(&self, addr: u64) -> Option<u64> {
        self.analysis.get()?.info.address_to_offset(addr)
    }

    /// Jumps to a memory address, remembering where you came from (Esc goes back).
    pub fn navigate_to_address(&mut self, addr: u64) -> bool {
        match self.address_to_offset(addr) {
            Some(offset) => {
                self.navigate(offset);
                true
            }
            None => false,
        }
    }

    /// Jumps to a file offset, remembering where you came from.
    pub fn navigate(&mut self, offset: u64) {
        if offset != self.cursor {
            self.back.push(self.cursor);
            if self.back.len() > MAX_HISTORY {
                self.back.remove(0);
            }
            self.forward.clear();
        }
        self.go_to(offset);
    }

    pub fn go_back(&mut self) -> bool {
        match self.back.pop() {
            Some(offset) => {
                self.forward.push(self.cursor);
                self.go_to(offset);
                true
            }
            None => false,
        }
    }

    pub fn go_forward(&mut self) -> bool {
        match self.forward.pop() {
            Some(offset) => {
                self.back.push(self.cursor);
                self.go_to(offset);
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> u64 {
        self.bytes().map_or(0, |b| b.len() as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn file_name(&self) -> String {
        file_name(&self.path)
    }

    /// Moves the cursor and asks the hex view to scroll there. Clears the selection.
    pub fn go_to(&mut self, offset: u64) {
        self.cursor = offset.min(self.len().saturating_sub(1));
        self.selection = None;
        self.reveal = true;
    }

    /// Selects `len` bytes at `offset` and reveals them.
    pub fn select(&mut self, offset: u64, len: u64) {
        self.go_to(offset);
        if len > 0 {
            let end = self.cursor.saturating_add(len).min(self.len());
            self.selection = Some((self.cursor, end.max(self.cursor)));
        }
    }
}

/// Where loading gets its bytes.
enum Source {
    /// Read the file; the bytes are also stored as the document's original.
    File(Arc<OnceLock<Bytes>>),
}

#[derive(Default, Clone)]
struct Slots {
    data: Arc<OnceLock<Result<Bytes, String>>>,
    analysis: Arc<OnceLock<Arc<Analysis>>>,
    program: Arc<OnceLock<Option<Arc<Program>>>>,
}

/// Loads and analyzes on a background thread, filling `slots` as results arrive.
fn spawn_load(path: PathBuf, source: Source, slots: &Slots, notify: Arc<dyn Fn() + Send + Sync>) {
    let data = Arc::clone(&slots.data);
    let analysis = Arc::clone(&slots.analysis);
    let program = Arc::clone(&slots.program);
    let error_slot = Arc::clone(&slots.data);
    let spawned = std::thread::Builder::new()
        .name(format!("load {}", path.display()))
        .spawn(move || {
            let loaded = match source {
                Source::File(original) => {
                    let loaded = read(&path);
                    if let Ok(bytes) = &loaded {
                        let _ = original.set(Arc::clone(bytes));
                    }
                    loaded
                }
            };
            let bytes = loaded.as_ref().ok().cloned();
            let _ = data.set(loaded);
            notify();
            let Some(bytes) = bytes else {
                return;
            };
            analyze_into(&path, bytes, &analysis, &program, notify.as_ref(), || false);
        });
    if let Err(e) = spawned {
        let _ = error_slot.set(Err(format!("could not start loader thread: {e}")));
    }
}

/// Triage, then code analysis, filling the slots as each finishes. `stale` is checked
/// between the steps; when it returns true the rest is skipped (a newer request exists).
fn analyze_into(
    path: &Path,
    bytes: Bytes,
    analysis: &OnceLock<Arc<Analysis>>,
    program: &OnceLock<Option<Arc<Program>>>,
    notify: &(dyn Fn() + Send + Sync),
    stale: impl Fn() -> bool,
) {
    let started = std::time::Instant::now();
    let triaged = Arc::new(Analysis::run(&bytes));
    if stale() {
        return;
    }
    let _ = analysis.set(Arc::clone(&triaged));
    tracing::info!("triaged {} in {:.2?}", path.display(), started.elapsed());
    notify();
    let started = std::time::Instant::now();
    let analyzed = Program::analyze(&triaged.info, bytes, &triaged.strings).map(Arc::new);
    if stale() {
        return;
    }
    if let Some(p) = &analyzed {
        tracing::info!(
            "disassembled {}: {} functions in {:.2?}",
            path.display(),
            p.functions.len(),
            started.elapsed()
        );
    }
    let _ = program.set(analyzed);
    notify();
}

/// Pending re-analysis for one document.
#[derive(Default)]
struct RebuildQueue {
    /// The newest bytes still waiting to be analyzed (older ones are simply replaced).
    pending: Option<(Bytes, Slots)>,
    /// Whether a worker thread is draining the queue.
    running: bool,
}

/// Queues analysis of patched `bytes` into `slots`. At most one worker runs per document;
/// it always picks the newest request and abandons work that a newer request made stale,
/// so a burst of patches costs about one analysis instead of one per byte.
fn queue_rebuild(
    queue: &Arc<Mutex<RebuildQueue>>,
    path: PathBuf,
    bytes: Bytes,
    slots: Slots,
    notify: Arc<dyn Fn() + Send + Sync>,
) {
    let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
    q.pending = Some((bytes, slots));
    if q.running {
        return;
    }
    q.running = true;
    drop(q);
    let worker_queue = Arc::clone(queue);
    let spawned = std::thread::Builder::new()
        .name(format!("reanalyze {}", path.display()))
        .spawn(move || {
            let lock = || worker_queue.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                let next = {
                    let mut q = lock();
                    let next = q.pending.take();
                    if next.is_none() {
                        q.running = false;
                    }
                    next
                };
                let Some((bytes, slots)) = next else {
                    return;
                };
                let stale = || lock().pending.is_some();
                let worked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    analyze_into(
                        &path,
                        bytes,
                        &slots.analysis,
                        &slots.program,
                        notify.as_ref(),
                        stale,
                    );
                }));
                if worked.is_err() {
                    tracing::error!("re-analysis of {} panicked", path.display());
                }
            }
        });
    if let Err(e) = spawned {
        tracing::error!("could not start re-analysis thread: {e}");
        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
        q.running = false;
        q.pending = None;
    }
}

pub fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn read(path: &Path) -> Result<Bytes, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if meta.len() > MAX_FILE_SIZE {
        return Err(format!(
            "{} is {} MB; ORRESS currently opens files up to {} MB.",
            path.display(),
            meta.len() / (1024 * 1024),
            MAX_FILE_SIZE / (1024 * 1024)
        ));
    }
    std::fs::read(path)
        .map(Arc::new)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// All open documents.
pub struct DocStore {
    docs: Vec<Document>,
    /// The document whose view was focused last; the inspector follows it.
    pub active: Option<PathBuf>,
    notify: Arc<dyn Fn() + Send + Sync>,
    /// Where annotations are saved; `None` keeps them in memory only.
    projects_dir: Option<PathBuf>,
}

impl DocStore {
    /// `notify` is called from a background thread when loading or analysis finishes;
    /// the app passes a function that requests a repaint.
    pub fn new(notify: impl Fn() + Send + Sync + 'static, projects_dir: Option<PathBuf>) -> Self {
        Self {
            docs: Vec::new(),
            active: None,
            notify: Arc::new(notify),
            projects_dir,
        }
    }

    /// Opens `path`, or returns the already open document.
    pub fn open(&mut self, path: &Path) -> &mut Document {
        let index = match self.docs.iter().position(|d| d.path == path) {
            Some(i) => i,
            None => {
                self.docs
                    .push(Document::open(path.to_path_buf(), Arc::clone(&self.notify)));
                self.docs.len() - 1
            }
        };
        let doc = &mut self.docs[index];
        doc.load_annotations(self.projects_dir.as_deref());
        doc
    }

    pub fn get(&self, path: &Path) -> Option<&Document> {
        self.docs.iter().find(|d| d.path == path)
    }

    pub fn get_mut(&mut self, path: &Path) -> Option<&mut Document> {
        self.docs.iter_mut().find(|d| d.path == path)
    }

    pub fn active(&self) -> Option<&Document> {
        self.active.as_deref().and_then(|p| self.get(p))
    }

    pub fn active_mut(&mut self) -> Option<&mut Document> {
        let path = self.active.clone()?;
        self.get_mut(&path)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Document> {
        self.docs.iter()
    }

    /// Drops documents that no tab shows any more, freeing their memory.
    pub fn retain(&mut self, mut in_use: impl FnMut(&Path) -> bool) {
        self.docs.retain(|d| in_use(&d.path));
        if self
            .active
            .as_deref()
            .is_some_and(|p| self.get(p).is_none())
        {
            self.active = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(doc: &Document) {
        let start = Instant::now();
        while doc.analysis().is_none() && doc.data().is_none_or(Result::is_ok) {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "analysis timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn opens_and_analyzes_in_background() {
        let path =
            std::env::temp_dir().join(format!("orress-project-test-{}.bin", std::process::id()));
        std::fs::write(&path, b"\x00\x00hello flag{x}\x00").unwrap();
        let mut store = DocStore::new(|| {}, None);
        let doc = store.open(&path);
        wait_for(doc);
        let analysis = doc.analysis().expect("analysis done");
        assert_eq!(analysis.strings[0].text, "hello flag{x}");
        assert_eq!(doc.len(), 16);

        doc.select(2, 5);
        assert_eq!(doc.selection, Some((2, 7)));
        assert!(doc.reveal);
        doc.go_to(1_000);
        assert_eq!(doc.cursor, 15, "cursor is clamped to the file");

        // Opening again returns the same document.
        store.open(&path).cursor = 3;
        assert_eq!(store.iter().count(), 1);
        assert_eq!(store.get(&path).unwrap().cursor, 3);

        store.active = Some(path.clone());
        store.retain(|_| false);
        assert!(store.active.is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn history_and_annotations_persist() {
        let dir = std::env::temp_dir().join(format!("orress-history-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        std::fs::write(&path, vec![0x90u8; 256]).unwrap();
        let projects = dir.join("projects");

        let mut store = DocStore::new(|| {}, Some(projects.clone()));
        wait_for(store.open(&path));
        let doc = store.open(&path);
        doc.navigate(0x10);
        doc.navigate(0x20);
        assert!(doc.go_back());
        assert_eq!(doc.cursor, 0x10);
        assert!(doc.go_forward());
        assert_eq!(doc.cursor, 0x20);
        assert!(doc.rename(0x1000, "has space").is_err());
        doc.rename(0x1000, "check_flag").unwrap();
        doc.set_comment(0x1004, "xor key is 0x42");
        assert_eq!(doc.name_of(0x1000).as_deref(), Some("check_flag"));
        assert!(doc.annotations_error.is_none());

        // A new store (a restart) brings the annotations back.
        let mut again = DocStore::new(|| {}, Some(projects));
        wait_for(again.open(&path));
        let doc = again.open(&path);
        assert_eq!(
            doc.annotations.names.get(&0x1000).map(String::as_str),
            Some("check_flag")
        );
        assert_eq!(doc.annotations.comments.len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn patches_apply_export_and_persist() {
        let dir = std::env::temp_dir().join(format!("orress-patch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("target.bin");
        std::fs::write(&path, b"\x74\x05hello").unwrap();
        let projects = dir.join("projects");

        let mut store = DocStore::new(|| {}, Some(projects.clone()));
        wait_for(store.open(&path));
        let doc = store.open(&path);
        // jz -> jnz: change one byte.
        doc.patch(0, &[0x75]).unwrap();
        assert!(doc.is_patched(0));
        assert_eq!(doc.original_byte(0), Some(0x74));
        wait_for(doc);
        assert_eq!(
            doc.bytes().unwrap()[0],
            0x75,
            "current bytes include the patch"
        );
        assert!(doc.patch(6, &[1, 2, 3]).is_err(), "past the end");
        // Writing the original value back removes the patch.
        doc.patch(1, &[0x05]).unwrap();
        assert_eq!(doc.annotations.patches.len(), 1);

        let out = dir.join("target.patched.bin");
        assert!(doc.export(&path).is_err(), "never overwrite the original");
        doc.export(&out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"\x75\x05hello");
        assert_eq!(std::fs::read(&path).unwrap()[0], 0x74, "original untouched");

        // A restart applies saved patches again.
        let mut again = DocStore::new(|| {}, Some(projects));
        wait_for(again.open(&path));
        let doc = again.open(&path);
        wait_for(doc);
        assert_eq!(doc.bytes().unwrap()[0], 0x75);
        doc.revert_patches();
        wait_for(doc);
        assert_eq!(doc.bytes().unwrap()[0], 0x74);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn burst_of_patches_ends_with_fresh_analysis() {
        let path =
            std::env::temp_dir().join(format!("orress-burst-test-{}.bin", std::process::id()));
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let mut store = DocStore::new(|| {}, None);
        let doc = store.open(&path);
        wait_for(doc);
        for i in 0..64u64 {
            doc.patch(i, b"A").unwrap();
        }
        wait_for(doc);
        let analysis = doc.analysis().expect("the newest patch is analyzed");
        assert!(analysis.strings.iter().any(|s| s.text.len() == 64));
        doc.select(10, u64::MAX);
        assert_eq!(doc.selection, Some((10, 4096)), "no overflow");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn corrupt_annotations_are_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("orress-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.bin");
        std::fs::write(&path, vec![0x90u8; 64]).unwrap();
        let projects = dir.join("projects");
        let mut store = DocStore::new(|| {}, None);
        let doc = store.open(&path);
        wait_for(doc);
        let sha = doc.analysis().unwrap().info.hashes.sha256.clone();
        std::fs::create_dir_all(&projects).unwrap();
        let file = Annotations::file_for(&projects, &sha);
        std::fs::write(&file, "{ not json").unwrap();

        let mut store = DocStore::new(|| {}, Some(projects));
        wait_for(store.open(&path));
        let doc = store.open(&path);
        assert!(doc.annotations_error.is_some());
        doc.rename(0x10, "fresh").unwrap();
        let mut backup = file.clone().into_os_string();
        backup.push(".corrupt");
        assert_eq!(std::fs::read_to_string(backup).unwrap(), "{ not json");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn missing_file_reports_error() {
        let mut store = DocStore::new(|| {}, None);
        let doc = store.open(Path::new("definitely/not/here.exe"));
        wait_for(doc);
        assert!(doc.data().unwrap().is_err());
        assert!(doc.analysis().is_none());
    }
}
