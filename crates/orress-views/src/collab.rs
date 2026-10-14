//! The Collaboration panel (M13): join a team room over a relay, see who is where (presence +
//! follow mode), share renames/comments/bookmarks/notes through the CRDT, claim and chat about
//! challenges, and import/submit flags from a CTFd or rCTF instance — all in one place.
//!
//! The live [`CollabSession`] is polled every frame by [`CollabView::tick`]; CTF network calls run
//! on background threads so the UI never blocks.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use egui::{Color32, RichText, Ui};
use orress_collab::{ChatMessage, CollabSession, Peer};
use orress_ctf::{Challenge, CtfClient, Platform};
use orress_project::{Document, validate_name};
use orress_ui::muted;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// All collaboration + CTF UI state the app owns.
pub struct CollabView {
    // Connect form.
    url: String,
    room: String,
    pass: String,
    name: String,
    session: Option<CollabSession>,
    /// A connection being made on a worker thread (key derivation + WebSocket handshake).
    connecting: Option<Receiver<Result<CollabSession, String>>>,
    status: Option<String>,
    chat_input: String,
    claim_input: String,
    /// SHA-256 of the binary this room's annotations belong to: the first analysed document
    /// bridged after connecting. Other files are never merged into the room.
    room_sha: Option<String>,
    /// The file name of the room's binary, for the panel.
    room_file: Option<String>,
    /// Set when the active document is not the room's binary (its file name), for the panel.
    other_file: Option<String>,
    // Last annotation state reconciled with the CRDT, the base for the three-way merge in `bridge`,
    // tagged with the SHA-256 of the document it was taken from.
    synced_sha: Option<String>,
    synced_names: BTreeMap<u64, String>,
    synced_comments: BTreeMap<u64, String>,
    synced_bookmarks: BTreeSet<u64>,
    /// Last address we broadcast as our presence, and last address we jumped to while following —
    /// so we only act on changes.
    last_local_addr: Option<u64>,
    last_follow: Option<u64>,
    // CTF browser (network work runs on a thread).
    platform: Platform,
    ctf_base: String,
    ctf_token: String,
    challenges: Arc<Mutex<Vec<Challenge>>>,
    ctf_busy: Arc<AtomicBool>,
    ctf_status: Arc<Mutex<Option<String>>>,
    flags: HashMap<String, String>,
}

impl Default for CollabView {
    fn default() -> Self {
        Self {
            url: "ws://127.0.0.1:8787".to_string(),
            room: String::new(),
            pass: String::new(),
            name: String::new(),
            session: None,
            connecting: None,
            status: None,
            chat_input: String::new(),
            claim_input: String::new(),
            room_sha: None,
            room_file: None,
            other_file: None,
            synced_sha: None,
            synced_names: BTreeMap::new(),
            synced_comments: BTreeMap::new(),
            synced_bookmarks: BTreeSet::new(),
            last_local_addr: None,
            last_follow: None,
            platform: Platform::Ctfd,
            ctf_base: String::new(),
            ctf_token: String::new(),
            challenges: Arc::new(Mutex::new(Vec::new())),
            ctf_busy: Arc::new(AtomicBool::new(false)),
            ctf_status: Arc::new(Mutex::new(None)),
            flags: HashMap::new(),
        }
    }
}

impl CollabView {
    /// Polls the live session once (called every frame by the app). Returns whether the UI should
    /// repaint. Drops the session if the relay connection was lost.
    pub fn tick(&mut self) -> bool {
        let mut changed = false;
        // A connection finished on its worker thread.
        if let Some(rx) = &self.connecting {
            match rx.try_recv() {
                Ok(Ok(session)) => {
                    self.session = Some(session);
                    self.status = None;
                    self.reset_sync();
                    self.connecting = None;
                    changed = true;
                }
                Ok(Err(e)) => {
                    self.status = Some(e);
                    self.connecting = None;
                    changed = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.status = Some("the connection attempt failed".into());
                    self.connecting = None;
                    changed = true;
                }
            }
        }
        if let Some(session) = &mut self.session {
            changed = session.poll(now_ms());
            if !session.is_connected() {
                self.status = Some(
                    session
                        .error()
                        .unwrap_or_else(|| "disconnected from the relay".to_string()),
                );
                self.session = None;
                self.reset_sync();
                changed = true;
            }
        }
        changed
    }

    /// Whether a live session is connected (so the app keeps repainting to drive sync).
    pub fn is_connected(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(CollabSession::is_connected)
    }

    /// Whether a connection is being made in the background (the app keeps polling).
    pub fn is_connecting(&self) -> bool {
        self.connecting.is_some()
    }

    /// Whether `doc` is the binary this room shares (so presence and follow jumps apply to it).
    /// Before the room's binary is known, any analysed document qualifies.
    pub fn shares(&self, doc: &Document) -> bool {
        let sha = &doc.annotations.sha256;
        !sha.is_empty() && self.room_sha.as_ref().is_none_or(|room| room == sha)
    }

    /// The address the user is currently following a teammate to, if any (the app can jump to it).
    pub fn follow_addr(&self) -> Option<u64> {
        self.session.as_ref().and_then(CollabSession::follow_addr)
    }

    /// Tells the session where this user is looking, so teammates following them jump along.
    pub fn set_local_addr(&mut self, addr: u64) {
        if let Some(s) = &mut self.session {
            s.set_local_addr(Some(addr), now_ms());
        }
    }

    fn reset_sync(&mut self) {
        self.room_sha = None;
        self.room_file = None;
        self.other_file = None;
        self.synced_sha = None;
        self.synced_names.clear();
        self.synced_comments.clear();
        self.synced_bookmarks.clear();
        self.last_local_addr = None;
        self.last_follow = None;
    }

    /// Broadcasts our current address as presence, but only when it changed (so teammates following
    /// us jump along without a flood of identical updates).
    pub fn set_local_addr_if_changed(&mut self, addr: u64) {
        if self.last_local_addr != Some(addr) {
            self.last_local_addr = Some(addr);
            self.set_local_addr(addr);
        }
    }

    /// The address to jump the disassembly to *now* because the teammate we follow moved there —
    /// `Some` only when the followed address changed since the last jump, so we do not fight the
    /// user's own scrolling while they sit on a followed location.
    pub fn take_follow_jump(&mut self) -> Option<u64> {
        let target = self.follow_addr();
        if target != self.last_follow {
            self.last_follow = target;
            return target;
        }
        None
    }

    /// Bidirectionally reconciles `doc`'s annotations (names, comments, bookmarks) with the shared
    /// CRDT, using the last-synced snapshot as the three-way-merge base: local edits are pushed to
    /// the room (local wins a tie), teammates' edits are applied to `doc`. Call every frame while a
    /// session is connected, with the active document. Returns whether `doc` changed (so the UI can
    /// refresh and persist).
    ///
    /// Only the room's binary is bridged: the first analysed document after connecting pins the
    /// room to its SHA-256, and any other file is left alone (the panel says so) — so switching
    /// files never pushes one binary's names as deletions or merges them into another's room.
    pub fn bridge(&mut self, doc: &mut Document) -> bool {
        if self.session.is_none() {
            return false;
        }
        let sha = doc.annotations.sha256.clone();
        if sha.is_empty() {
            return false; // not analysed yet: its annotations are not loaded
        }
        match &self.room_sha {
            None => {
                self.room_sha = Some(sha.clone());
                self.room_file = Some(doc.file_name());
            }
            Some(room) if *room != sha => {
                self.other_file = Some(doc.file_name());
                return false;
            }
            Some(_) => {}
        }
        self.other_file = None;
        // The merge base must come from this document. If it does not (first sync), start from
        // an empty base: the initial merge shares this file's annotations and takes the room's.
        if self.synced_sha.as_deref() != Some(sha.as_str()) {
            self.synced_names.clear();
            self.synced_comments.clear();
            self.synced_bookmarks.clear();
            self.synced_sha = Some(sha);
        }
        let mut changed = false;
        let session = self.session.as_ref().unwrap();

        // Names (validated on inbound, so a peer cannot inject an illegal identifier).
        let crdt_names = session.doc.renames();
        changed |= reconcile_map(
            &mut doc.annotations.names,
            &crdt_names,
            &self.synced_names,
            |addr, name| session.doc.set_rename(addr, name),
            |addr| session.doc.remove_rename(addr),
            |name| validate_name(name).is_ok(),
        );

        // Comments (free text).
        let crdt_comments = session.doc.comments();
        changed |= reconcile_map(
            &mut doc.annotations.comments,
            &crdt_comments,
            &self.synced_comments,
            |addr, text| session.doc.set_comment(addr, text),
            |addr| session.doc.remove_comment(addr),
            |_| true,
        );

        // Bookmarks (a local set <-> a CRDT map keyed by address; the label is unused here).
        let crdt_bm = session.doc.bookmarks();
        let bm_addrs: BTreeSet<u64> = doc
            .annotations
            .bookmarks
            .iter()
            .chain(crdt_bm.keys())
            .chain(self.synced_bookmarks.iter())
            .copied()
            .collect();
        for addr in bm_addrs {
            let local = doc.annotations.bookmarks.contains(&addr);
            let remote = crdt_bm.contains_key(&addr);
            let base = self.synced_bookmarks.contains(&addr);
            if local != base {
                if local {
                    session.doc.set_bookmark(addr, "");
                } else {
                    session.doc.remove_bookmark(addr);
                }
            } else if remote != base {
                if remote {
                    changed |= doc.annotations.bookmarks.insert(addr);
                } else {
                    changed |= doc.annotations.bookmarks.remove(&addr);
                }
            }
        }

        // New baseline: whatever the CRDT now holds (which both sides have converged to).
        self.synced_names = session.doc.renames();
        self.synced_comments = session.doc.comments();
        self.synced_bookmarks = session.doc.bookmarks().into_keys().collect();

        if changed {
            doc.touch_annotations();
        }
        changed
    }
}

/// Three-way merges one annotation dimension (`local` vs the shared `remote`, against the
/// last-synced `base`): local-only changes are pushed to the room (and win a concurrent tie),
/// remote-only changes are applied to `local`. Returns whether `local` changed.
fn reconcile_map(
    local: &mut BTreeMap<u64, String>,
    remote: &BTreeMap<u64, String>,
    base: &BTreeMap<u64, String>,
    mut push: impl FnMut(u64, &str),
    mut remove: impl FnMut(u64),
    valid: impl Fn(&str) -> bool,
) -> bool {
    let mut changed = false;
    let addrs: BTreeSet<u64> = local
        .keys()
        .chain(remote.keys())
        .chain(base.keys())
        .copied()
        .collect();
    for addr in addrs {
        let local_v = local.get(&addr);
        let remote_v = remote.get(&addr);
        let base_v = base.get(&addr);
        if local_v != base_v {
            // Edited locally since the last sync — push it (local wins a conflict).
            match local_v {
                Some(v) => push(addr, v),
                None => remove(addr),
            }
        } else if remote_v != base_v {
            // Only a teammate changed it — apply to the local document.
            match remote_v {
                Some(v) if valid(v) => {
                    local.insert(addr, v.clone());
                    changed = true;
                }
                Some(_) => {} // an invalid inbound value (e.g. a bad name) is ignored
                None => {
                    if local.remove(&addr).is_some() {
                        changed = true;
                    }
                }
            }
        }
    }
    changed
}

/// Renders the Collaboration tab.
pub fn collab_panel(ui: &mut Ui, view: &mut CollabView) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Collaboration").strong());
        ui.label(muted("team CTFs · shared project · follow mode"));
    });
    ui.separator();

    match view.session.is_some() {
        false => connect_form(ui, view),
        true => connected(ui, view),
    }

    ui.add_space(8.0);
    ui.separator();
    ctf_browser(ui, view);
}

fn connect_form(ui: &mut Ui, view: &mut CollabView) {
    ui.label(muted("Join a team room. Everything is end-to-end encrypted with the passphrase; the relay never sees your work."));
    egui::Grid::new("collab-connect")
        .num_columns(2)
        .spacing([8.0, 4.0])
        .show(ui, |ui| {
            ui.label("Relay URL:");
            ui.text_edit_singleline(&mut view.url);
            ui.end_row();
            ui.label("Room:");
            ui.text_edit_singleline(&mut view.room);
            ui.end_row();
            ui.label("Passphrase:");
            ui.add(egui::TextEdit::singleline(&mut view.pass).password(true));
            ui.end_row();
            ui.label("Your name:");
            ui.text_edit_singleline(&mut view.name);
            ui.end_row();
        });
    let ready =
        !view.room.trim().is_empty() && !view.pass.is_empty() && !view.name.trim().is_empty();
    let connecting = view.connecting.is_some();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(ready && !connecting, egui::Button::new("Connect"))
            .clicked()
        {
            start_connect(ui.ctx(), view);
        }
        if connecting {
            ui.spinner();
            ui.label(muted("connecting…"));
        }
    });
    if let Some(s) = &view.status {
        ui.colored_label(ui.visuals().error_fg_color, s);
    }
}

/// Connects on a worker thread: the passphrase key derivation is deliberately slow and the relay
/// handshake blocks on the network, neither of which may freeze the UI. [`CollabView::tick`]
/// adopts the session when it is ready.
fn start_connect(ctx: &egui::Context, view: &mut CollabView) {
    let id = format!("{}-{}", view.name.trim(), now_ms());
    let peer = Peer::new(id, view.name.trim());
    let (url, room, pass) = (
        view.url.trim().to_string(),
        view.room.trim().to_string(),
        view.pass.clone(),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let ctx = ctx.clone();
    let spawned = std::thread::Builder::new()
        .name("orress-collab-connect".into())
        .spawn(move || {
            let _ = tx.send(CollabSession::connect(&url, &room, &pass, peer));
            ctx.request_repaint();
        });
    match spawned {
        Ok(_) => {
            view.connecting = Some(rx);
            view.status = None;
        }
        Err(e) => view.status = Some(format!("could not start connecting: {e}")),
    }
}

fn connected(ui: &mut Ui, view: &mut CollabView) {
    ui.horizontal(|ui| {
        ui.colored_label(Color32::from_rgb(0x4c, 0xaf, 0x50), "● connected");
        ui.label(muted(format!("room {}", view.room.trim())));
        if ui.button("Disconnect").clicked() {
            view.session = None;
            view.reset_sync();
        }
    });
    let Some(session) = &mut view.session else {
        return;
    };

    // Presence + follow mode.
    ui.add_space(6.0);
    ui.label(RichText::new("Team").strong());
    let following = session.presence().following().map(str::to_string);
    let peers: Vec<Peer> = session.presence().peers().into_iter().cloned().collect();
    if peers.is_empty() {
        ui.label(muted("No teammates connected yet."));
    }
    let mut follow: Option<String> = None;
    let mut unfollow = false;
    for p in &peers {
        ui.horizontal(|ui| {
            let [r, g, b] = [(p.color >> 16) as u8, (p.color >> 8) as u8, p.color as u8];
            ui.colored_label(Color32::from_rgb(r, g, b), "●");
            ui.label(&p.name);
            match p.addr {
                Some(a) => ui.label(muted(format!("@ {a:#x}"))),
                None => ui.label(muted("idle")),
            };
            if following.as_deref() == Some(p.id.as_str()) {
                if ui.small_button("unfollow").clicked() {
                    unfollow = true;
                }
            } else if ui.small_button("follow").clicked() {
                follow = Some(p.id.clone());
            }
        });
    }
    if let Some(id) = follow {
        session.follow(&id);
    }
    if unfollow {
        session.unfollow();
    }

    // Claims.
    ui.add_space(6.0);
    ui.label(RichText::new("Claims").strong());
    for (challenge, who) in session.doc.claims() {
        ui.label(muted(format!("{challenge} — {who}")));
    }
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut view.claim_input)
                .hint_text("challenge id")
                .desired_width(140.0),
        );
        if ui.button("Claim").clicked() && !view.claim_input.trim().is_empty() {
            session.doc.claim(view.claim_input.trim(), view.name.trim());
            view.claim_input.clear();
        }
    });

    // Shared annotations (read-only summary of what the team has recorded).
    let (renames, comments, bookmarks) = (
        session.doc.renames().len(),
        session.doc.comments().len(),
        session.doc.bookmarks().len(),
    );
    ui.add_space(4.0);
    ui.label(muted(format!(
        "shared: {renames} renames · {comments} comments · {bookmarks} bookmarks"
    )));
    match (&view.room_file, &view.other_file) {
        (_, Some(other)) => {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!(
                    "{other} is not this room's binary ({}), so its annotations are not shared. \
                     Switch back to that file to sync.",
                    view.room_file.as_deref().unwrap_or("?")
                ),
            );
        }
        (Some(file), None) => {
            ui.label(muted(format!("syncing annotations of {file}")));
        }
        (None, None) => {
            ui.label(muted(
                "Open the challenge binary: the first analysed file becomes the room's binary.",
            ));
        }
    }

    // Chat.
    ui.add_space(6.0);
    ui.label(RichText::new("Chat").strong());
    let chat = session.doc.chat();
    egui::ScrollArea::vertical()
        .max_height(140.0)
        .stick_to_bottom(true)
        .id_salt("collab-chat")
        .show(ui, |ui| {
            for m in &chat {
                chat_line(ui, m);
            }
        });
    ui.horizontal(|ui| {
        let send = ui
            .add(
                egui::TextEdit::singleline(&mut view.chat_input)
                    .hint_text("message…")
                    .desired_width(ui.available_width() - 60.0),
            )
            .lost_focus()
            && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if (ui.button("Send").clicked() || send) && !view.chat_input.trim().is_empty() {
            session.doc.post_chat(&ChatMessage {
                peer: view.name.trim().to_string(),
                text: view.chat_input.trim().to_string(),
                ts: now_ms(),
                addr: None,
            });
            view.chat_input.clear();
        }
    });
}

fn chat_line(ui: &mut Ui, m: &ChatMessage) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{}:", m.peer)).strong());
        ui.label(&m.text);
        if let Some(a) = m.addr {
            ui.label(muted(format!("@ {a:#x}")));
        }
    });
}

fn ctf_browser(ui: &mut Ui, view: &mut CollabView) {
    ui.label(RichText::new("CTF challenges").strong());
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("ctf-platform")
            .selected_text(match view.platform {
                Platform::Ctfd => "CTFd",
                Platform::Rctf => "rCTF",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut view.platform, Platform::Ctfd, "CTFd");
                ui.selectable_value(&mut view.platform, Platform::Rctf, "rCTF");
            });
        ui.add(
            egui::TextEdit::singleline(&mut view.ctf_base)
                .hint_text("https://ctf.example.com")
                .desired_width(220.0),
        );
    });
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut view.ctf_token)
                .password(true)
                .hint_text("API token")
                .desired_width(220.0),
        );
        let busy = view.ctf_busy.load(Ordering::Relaxed);
        let ready = !busy && !view.ctf_base.trim().is_empty() && !view.ctf_token.trim().is_empty();
        if ui.add_enabled(ready, egui::Button::new("Load")).clicked() {
            load_challenges(view);
        }
        if busy {
            ui.spinner();
        }
    });
    if let Some(s) = view.ctf_status.lock().unwrap().as_ref() {
        ui.label(muted(s));
    }

    let challenges = view.challenges.lock().unwrap().clone();
    egui::ScrollArea::vertical()
        .max_height(220.0)
        .id_salt("ctf-list")
        .show(ui, |ui| {
            for ch in &challenges {
                ui.horizontal(|ui| {
                    let mark = if ch.solved { "✔ " } else { "" };
                    ui.label(format!(
                        "{mark}{} [{}] {}pts",
                        ch.name, ch.category, ch.value
                    ));
                });
                ui.horizontal(|ui| {
                    let flag = view.flags.entry(ch.id.clone()).or_default();
                    ui.add(
                        egui::TextEdit::singleline(flag)
                            .hint_text("flag{…}")
                            .desired_width(220.0),
                    );
                    if ui.button("Submit").clicked() {
                        submit_flag(view, &ch.id);
                    }
                });
            }
        });
}

fn client(view: &CollabView) -> CtfClient {
    CtfClient::new(view.platform, view.ctf_base.trim(), view.ctf_token.trim())
}

fn load_challenges(view: &CollabView) {
    let client = client(view);
    let out = Arc::clone(&view.challenges);
    let busy = Arc::clone(&view.ctf_busy);
    let status = Arc::clone(&view.ctf_status);
    busy.store(true, Ordering::Relaxed);
    *status.lock().unwrap() = None;
    std::thread::spawn(move || {
        match client.challenges() {
            Ok(list) => {
                *status.lock().unwrap() = Some(format!("{} challenges", list.len()));
                *out.lock().unwrap() = list;
            }
            Err(e) => *status.lock().unwrap() = Some(e),
        }
        busy.store(false, Ordering::Relaxed);
    });
}

fn submit_flag(view: &CollabView, id: &str) {
    let flag = view.flags.get(id).cloned().unwrap_or_default();
    if flag.trim().is_empty() {
        return;
    }
    let client = client(view);
    let status = Arc::clone(&view.ctf_status);
    let busy = Arc::clone(&view.ctf_busy);
    let id = id.to_string();
    busy.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        let msg = match client.submit(&id, flag.trim()) {
            Ok(o) if o.correct => format!("✔ {id}: {}", o.message),
            Ok(o) if o.already_solved => format!("{id}: already solved"),
            Ok(o) => format!("✘ {id}: {}", o.message),
            Err(e) => format!("{id}: {e}"),
        };
        *status.lock().unwrap() = Some(msg);
        busy.store(false, Ordering::Relaxed);
    });
}

#[cfg(test)]
mod tests {
    use super::reconcile_map;
    use std::collections::BTreeMap;

    fn map(pairs: &[(u64, &str)]) -> BTreeMap<u64, String> {
        pairs.iter().map(|(a, v)| (*a, v.to_string())).collect()
    }

    #[test]
    fn pushes_local_edits_and_applies_remote_edits() {
        let base = BTreeMap::new();
        let mut local = map(&[(0x10, "local_fn")]); // added locally
        let remote = map(&[(0x20, "remote_fn")]); // added by a teammate
        let (mut pushes, mut removes) = (Vec::new(), Vec::new());
        let changed = reconcile_map(
            &mut local,
            &remote,
            &base,
            |a, v| pushes.push((a, v.to_string())),
            |a| removes.push(a),
            |_| true,
        );
        assert!(changed);
        assert_eq!(local.get(&0x20).map(String::as_str), Some("remote_fn")); // remote applied
        assert_eq!(pushes, vec![(0x10, "local_fn".to_string())]); // local pushed to the room
        assert!(removes.is_empty());
    }

    #[test]
    fn local_edit_wins_a_conflict() {
        let base = map(&[(0x10, "old")]);
        let mut local = map(&[(0x10, "mine")]);
        let remote = map(&[(0x10, "theirs")]);
        let (mut pushes, mut removes) = (Vec::new(), Vec::new());
        let changed = reconcile_map(
            &mut local,
            &remote,
            &base,
            |a, v| pushes.push((a, v.to_string())),
            |a| removes.push(a),
            |_| true,
        );
        assert!(!changed); // local was not overwritten
        assert_eq!(local.get(&0x10).map(String::as_str), Some("mine"));
        assert_eq!(pushes, vec![(0x10, "mine".to_string())]); // local wins: pushed to the room
    }

    #[test]
    fn remote_removal_applies_and_local_removal_pushes() {
        // Remote removed a key both sides had.
        let base = map(&[(0x10, "x")]);
        let mut local = map(&[(0x10, "x")]);
        let remote = BTreeMap::new();
        let (mut pushes, mut removes) = (Vec::new(), Vec::new());
        let changed = reconcile_map(
            &mut local,
            &remote,
            &base,
            |a, v| pushes.push((a, v.to_string())),
            |a| removes.push(a),
            |_| true,
        );
        assert!(changed && local.is_empty() && pushes.is_empty() && removes.is_empty());

        // Local removed a key both sides had -> push a removal.
        let mut local2 = BTreeMap::new();
        let (mut pushes2, mut removes2): (Vec<(u64, String)>, Vec<u64>) = (Vec::new(), Vec::new());
        let changed2 = reconcile_map(
            &mut local2,
            &base,
            &base,
            |a, v| pushes2.push((a, v.to_string())),
            |a| removes2.push(a),
            |_| true,
        );
        assert!(!changed2 && removes2 == vec![0x10]);
    }

    #[test]
    fn invalid_inbound_value_is_ignored() {
        let base = BTreeMap::new();
        let mut local = BTreeMap::new();
        let remote = map(&[(0x10, "bad name")]);
        let (mut pushes, mut removes) = (Vec::new(), Vec::new());
        let changed = reconcile_map(
            &mut local,
            &remote,
            &base,
            |a, v| pushes.push((a, v.to_string())),
            |a| removes.push(a),
            |n| !n.contains(' '),
        );
        assert!(!changed && local.is_empty());
    }
}
