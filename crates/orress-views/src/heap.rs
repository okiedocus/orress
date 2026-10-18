//! The Heap panel: while a Linux program is stopped in the debugger, read its `[heap]` and show the
//! glibc chunks and the tcache bins (GEF's `heap chunks` / `heap bins tcache`). The parsing lives
//! in `orress-heap`; this reads the target's memory through the debugger's pid-based helpers.
//!
//! Chunks + tcache need only the `[heap]` region. The arena bins (fastbins/unsorted/small/large)
//! need `main_arena`, whose address is libc-version dependent and located in a later tier; until
//! then a note says so.

use egui::{RichText, Ui};
use orress_heap::Heap;
use orress_ui::muted;

use crate::DebugSession;

/// Persistent UI state for the Heap tab.
pub struct HeapView {
    /// (pid, generation, mangled, main_arena) the cached parse belongs to.
    cache_key: Option<(u32, u64, bool, Option<u64>)>,
    heap: Option<Heap>,
    error: Option<String>,
    /// Whether to de-mangle free-list pointers (glibc >= 2.32 safe-linking).
    mangled: bool,
    /// Optional `main_arena` address (hex), to show the fastbins/unsorted/small/large bins.
    arena_input: String,
}

impl Default for HeapView {
    fn default() -> Self {
        Self {
            cache_key: None,
            heap: None,
            error: None,
            mangled: true,
            arena_input: String::new(),
        }
    }
}

/// Parses a `0x…` / decimal hex address, if non-empty and valid.
fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse().ok(), |h| u64::from_str_radix(h, 16).ok())
}

pub fn heap_view(ui: &mut Ui, view: &mut HeapView, session: &mut DebugSession) {
    orress_ui::spotlight::mark(ui.ctx(), "view.Heap", ui.max_rect());
    session.refresh();

    ui.horizontal(|ui| {
        ui.label(RichText::new("Heap").strong());
        ui.label(muted("glibc chunks and bins · stop the program to inspect"));
    });
    ui.separator();

    let Some(pid) = session.stopped_pid() else {
        ui.label(muted(
            "Start the program in the Debugger and stop it (a breakpoint), then the heap shows here.",
        ));
        return;
    };

    let generation = session.generation();
    ui.horizontal(|ui| {
        if ui.button("⟳ Refresh").clicked() {
            view.cache_key = None;
        }
        if ui
            .checkbox(&mut view.mangled, "safe-linking")
            .on_hover_text("De-mangle free-list pointers (glibc >= 2.32).")
            .changed()
        {
            view.cache_key = None;
        }
    });
    ui.horizontal(|ui| {
        ui.label("main_arena");
        ui.add(
            egui::TextEdit::singleline(&mut view.arena_input)
                .hint_text("0x… (optional, for fastbins/unsorted/small/large)")
                .desired_width(260.0),
        )
        .on_hover_text(
            "Paste the main_arena address (e.g. from GEF, or libc base + offset) to also show the \
             arena bins. Chunks and tcache show without it.",
        );
    });

    let arena_addr = parse_addr(&view.arena_input);
    let key = (pid, generation, view.mangled, arena_addr);
    if view.cache_key != Some(key) {
        recompute(view, pid, arena_addr);
        view.cache_key = Some(key);
    }

    if let Some(e) = &view.error {
        ui.add_space(4.0);
        ui.colored_label(ui.visuals().warn_fg_color, e);
        return;
    }
    let Some(heap) = &view.heap else {
        return;
    };

    for note in &heap.notes {
        ui.label(muted(note));
    }
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Bins first (what you usually want), then the chunk list.
            if heap.bins.is_empty() {
                ui.label(muted("No free chunks on any bin."));
            } else {
                ui.label(RichText::new("Bins").strong());
                for bin in &heap.bins {
                    let size = bin
                        .size
                        .map(|s| format!(" (size {s:#x})"))
                        .unwrap_or_default();
                    let chain = bin
                        .entries
                        .iter()
                        .map(|a| format!("{a:#x}"))
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    ui.label(
                        RichText::new(format!(
                            "{} {}{size}: {chain}",
                            bin.kind.label(),
                            bin.index
                        ))
                        .monospace(),
                    );
                }
            }

            ui.add_space(8.0);
            ui.label(RichText::new(format!("Chunks ({})", heap.chunks.len())).strong());
            let row_h = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
            egui::ScrollArea::vertical()
                .id_salt("heap-chunks")
                .max_height(ui.available_height().max(120.0))
                .auto_shrink([false, false])
                .show_rows(ui, row_h, heap.chunks.len(), |ui, range| {
                    for c in &heap.chunks[range] {
                        let state = if c.in_use { "in use" } else { "free" };
                        let mut flags = String::new();
                        if c.prev_inuse {
                            flags.push('P');
                        }
                        if c.is_mmapped {
                            flags.push('M');
                        }
                        if c.non_main_arena {
                            flags.push('N');
                        }
                        let free_info = if c.in_use {
                            String::new()
                        } else {
                            format!("  fd={:#x} bk={:#x}", c.fd, c.bk)
                        };
                        ui.label(
                            RichText::new(format!(
                                "{:#x}  size {:#x}  [{flags:<3}]  {state}{free_info}",
                                c.addr, c.size
                            ))
                            .monospace(),
                        );
                    }
                });
        });

}

fn recompute(view: &mut HeapView, pid: u32, arena_addr: Option<u64>) {
    view.heap = None;
    view.error = None;
    let map = match orress_debug::memory_map(pid) {
        Ok(m) => m,
        Err(e) => {
            view.error = Some(format!("Could not read the memory map: {e}"));
            return;
        }
    };
    let Some(region) = map.iter().find(|r| r.name == "[heap]") else {
        view.error = Some(
            "No [heap] mapping yet — nothing has been allocated, or this is not a glibc program."
                .into(),
        );
        return;
    };
    let bytes = match orress_debug::read_mem(pid, region.base, region.size as usize) {
        Ok(b) => b,
        Err(e) => {
            view.error = Some(format!("Could not read the heap: {e}"));
            return;
        }
    };
    // When the user supplies main_arena, read it too so the arena bins show.
    let arena = arena_addr.and_then(|addr| {
        orress_debug::read_mem(pid, addr, 0x900)
            .ok()
            .map(|b| (b, addr))
    });
    let arena_ref = arena.as_ref().map(|(b, a)| (b.as_slice(), *a));
    view.heap = Some(orress_heap::parse(&bytes, region.base, arena_ref, view.mangled));
}
