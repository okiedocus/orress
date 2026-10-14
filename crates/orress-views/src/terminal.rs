//! The integrated terminal view: renders the `orress-term` PTY screen as a character grid
//! and sends keyboard input to the shell. Colours follow the standard ANSI palette.

use std::path::PathBuf;
use std::sync::Arc;

use egui::text::LayoutJob;
use egui::{Color32, FontId, Pos2, Rect, Sense, Stroke, TextFormat, Ui, Vec2};
use orress_term::Terminal;

/// The terminal's persistent state (owned by the app).
#[derive(Default)]
pub struct TerminalSession {
    term: Option<Terminal>,
    /// Where to start the shell (the current project directory, if any).
    cwd: Option<PathBuf>,
    /// Scrollback offset in rows (0 = bottom / live).
    scrollback: usize,
    /// Why the shell could not be started. Kept (and shown) until the user presses Restart, so a
    /// missing shell is not re-spawned on every repaint.
    spawn_error: Option<String>,
}

impl TerminalSession {
    /// Sets the directory a newly started shell opens in (applies on the next start/Restart; a
    /// failed start keeps its directory until Restart so the error stays accurate).
    pub fn set_cwd(&mut self, cwd: Option<PathBuf>) {
        if self.term.is_none() && self.spawn_error.is_none() {
            self.cwd = cwd;
        }
    }

    pub fn is_running(&self) -> bool {
        self.term.as_ref().is_some_and(Terminal::is_alive)
    }

    fn ensure(&mut self, rows: u16, cols: u16, notify: Arc<dyn Fn() + Send + Sync>) {
        if self.term.is_none() && self.spawn_error.is_none() {
            let (shell, args) = orress_term::default_shell();
            match Terminal::spawn(&shell, &args, self.cwd.as_deref(), rows, cols, notify) {
                Ok(t) => self.term = Some(t),
                Err(e) => self.spawn_error = Some(format!("Could not start {shell}: {e}")),
            }
        }
    }

    /// Restarts the shell (after it exits, after a failed start, or on demand).
    pub fn restart(&mut self) {
        self.term = None;
        self.spawn_error = None;
        self.scrollback = 0;
    }
}

/// One ANSI palette colour (0..16), approximating a dark theme's 16-colour set.
fn ansi16(i: u8) -> Color32 {
    const P: [(u8, u8, u8); 16] = [
        (30, 30, 30),
        (205, 80, 70),
        (120, 190, 110),
        (210, 180, 90),
        (90, 150, 230),
        (190, 130, 210),
        (90, 190, 200),
        (200, 200, 200),
        (110, 110, 110),
        (235, 110, 100),
        (150, 220, 140),
        (235, 210, 120),
        (120, 175, 245),
        (215, 160, 235),
        (120, 215, 225),
        (245, 245, 245),
    ];
    let (r, g, b) = P[(i & 15) as usize];
    Color32::from_rgb(r, g, b)
}

/// The xterm 256-colour cube and greyscale ramp (indices 16..256).
fn xterm256(i: u8) -> Color32 {
    if i < 16 {
        return ansi16(i);
    }
    if i >= 232 {
        let v = 8 + 10 * (i - 232) as u32;
        return Color32::from_gray(v as u8);
    }
    let i = i - 16;
    let levels = [0u8, 95, 135, 175, 215, 255];
    Color32::from_rgb(
        levels[(i / 36 % 6) as usize],
        levels[(i / 6 % 6) as usize],
        levels[(i % 6) as usize],
    )
}

fn to_color(c: vt100::Color, default: Color32) -> Color32 {
    match c {
        vt100::Color::Default => default,
        vt100::Color::Idx(i) => xterm256(i),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    }
}

/// Draws the terminal panel.
pub fn terminal_panel(
    ui: &mut Ui,
    session: &mut TerminalSession,
    notify: Arc<dyn Fn() + Send + Sync>,
) {
    let font = FontId::monospace(13.0);
    let (char_w, row_h) = ui.fonts_mut(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));
    let rect = ui.available_rect_before_wrap();

    // Grid size from the available area.
    let cols = ((rect.width() / char_w).floor() as u16).clamp(8, 400);
    let rows = ((rect.height() / row_h).floor() as u16).clamp(2, 200);

    session.ensure(rows, cols, Arc::clone(&notify));
    let Some(term) = &mut session.term else {
        let error = session
            .spawn_error
            .clone()
            .unwrap_or_else(|| "Could not start a shell.".into());
        ui.colored_label(ui.visuals().error_fg_color, error);
        if ui.button("Restart").clicked() {
            session.restart();
        }
        return;
    };
    term.resize(rows, cols);

    let id = ui.id().with("orress-terminal");
    let response = ui.interact(rect, id, Sense::click());
    if response.clicked() {
        response.request_focus();
    }
    let focused = response.has_focus();

    // Scrollback via the wheel.
    if ui.rect_contains_pointer(rect) {
        let dy = ui.input(|i| i.smooth_scroll_delta.y);
        if dy.abs() > 0.5 {
            let step = (dy / row_h).round() as i64;
            session.scrollback = (session.scrollback as i64 + step).max(0) as usize;
        }
    }

    // Draw the grid.
    let painter = ui.painter_at(rect);
    let text_color = ui.visuals().text_color();
    let bg = ui.visuals().extreme_bg_color;
    painter.rect_filled(rect, 0.0, bg);

    let mut cursor_pos = None;
    if let Ok(mut parser) = term.parser().lock() {
        parser.screen_mut().set_scrollback(session.scrollback);
        session.scrollback = parser.screen().scrollback();
        let screen = parser.screen();
        let (srows, scols) = screen.size();
        for r in 0..srows {
            let y = rect.top() + f32::from(r) * row_h;
            // Group runs of cells with the same colours into one galley.
            let mut c = 0u16;
            while c < scols {
                let Some(cell) = screen.cell(r, c) else {
                    c += 1;
                    continue;
                };
                if cell.is_wide_continuation() {
                    c += 1;
                    continue;
                }
                let (mut fg, mut bgc) = (
                    to_color(cell.fgcolor(), text_color),
                    to_color(cell.bgcolor(), bg),
                );
                if cell.inverse() {
                    std::mem::swap(&mut fg, &mut bgc);
                }
                let x = rect.left() + f32::from(c) * char_w;
                // Background.
                if bgc != bg {
                    let w = char_w * if cell.is_wide() { 2.0 } else { 1.0 };
                    painter.rect_filled(
                        Rect::from_min_size(Pos2::new(x, y), Vec2::new(w, row_h)),
                        0.0,
                        bgc,
                    );
                }
                let contents = cell.contents();
                if !contents.is_empty() {
                    let mut job = LayoutJob::default();
                    let mut fmt = TextFormat::simple(font.clone(), fg);
                    if cell.underline() {
                        fmt.underline = Stroke::new(1.0, fg);
                    }
                    job.append(contents, 0.0, fmt);
                    let galley = ui.fonts_mut(|f| f.layout_job(job));
                    painter.galley(Pos2::new(x, y), galley, fg);
                }
                c += if cell.is_wide() { 2 } else { 1 };
            }
        }
        if !screen.hide_cursor() && session.scrollback == 0 {
            let (cr, cc) = screen.cursor_position();
            cursor_pos = Some((cr, cc));
        }
    }

    if let Some((cr, cc)) = cursor_pos {
        let x = rect.left() + f32::from(cc) * char_w;
        let y = rect.top() + f32::from(cr) * row_h;
        let cursor_rect = Rect::from_min_size(Pos2::new(x, y), Vec2::new(char_w, row_h));
        let col = ui
            .visuals()
            .text_color()
            .gamma_multiply(if focused { 0.8 } else { 0.4 });
        painter.rect(
            cursor_rect,
            0.0,
            Color32::TRANSPARENT,
            Stroke::new(1.0, col),
            egui::StrokeKind::Inside,
        );
    }

    // Keyboard input.
    if focused {
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                egui::EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    tab: true,
                    escape: true,
                },
            );
        });
        let bytes = collect_input(ui);
        if !bytes.is_empty() {
            term.input(&bytes);
            session.scrollback = 0;
        }
    }

    if !term.is_alive() {
        let banner = Rect::from_min_size(rect.min, Vec2::new(rect.width(), row_h + 6.0));
        let builder = egui::UiBuilder::new()
            .max_rect(banner)
            .layout(egui::Layout::left_to_right(egui::Align::Center));
        ui.scope_builder(builder, |ui| {
            ui.colored_label(ui.visuals().weak_text_color(), "[shell exited]");
            if ui.small_button("Restart").clicked() {
                session.restart();
            }
        });
    }
}

/// Takes this frame's keyboard input out of egui and translates it into terminal bytes. The
/// events are *consumed*, so the app's global shortcuts (Ctrl+W, Ctrl+Q, Ctrl+D, …) do not also
/// fire while the shell has focus. Ctrl+Shift combinations and function keys are left for the app
/// (the command palette, F1, …), since a shell has no use for them.
fn collect_input(ui: &Ui) -> Vec<u8> {
    let mut out = Vec::new();
    ui.input_mut(|i| {
        i.events.retain(|event| {
            match event {
                egui::Event::Text(t) => out.extend_from_slice(t.as_bytes()),
                egui::Event::Paste(t) => out.extend_from_slice(t.as_bytes()),
                // egui-winit turns Ctrl+C / Ctrl+X into Copy / Cut events (no Key event), so map
                // them back to the interrupt (ETX) and Ctrl+X (CAN) control codes.
                egui::Event::Copy => out.push(0x03),
                egui::Event::Cut => out.push(0x18),
                egui::Event::Key {
                    key,
                    pressed,
                    modifiers,
                    ..
                } => {
                    if leave_for_app(*key, modifiers) {
                        return true;
                    }
                    if *pressed {
                        push_key(&mut out, *key, modifiers);
                    }
                }
                _ => return true,
            }
            false
        });
    });
    out
}

/// Keys the terminal does not take: app shortcuts with Ctrl+Shift (or Cmd+Shift), and the
/// function keys, which the shell does not use but the app does (F1 = keybindings, …).
fn leave_for_app(key: egui::Key, modifiers: &egui::Modifiers) -> bool {
    use egui::Key::*;
    let ctrl = modifiers.ctrl || modifiers.command;
    (ctrl && modifiers.shift)
        || matches!(
            key,
            F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | F9 | F10 | F11 | F12
        )
}

fn push_key(out: &mut Vec<u8>, key: egui::Key, modifiers: &egui::Modifiers) {
    use egui::Key::*;
    // Ctrl + letter -> control code.
    if (modifiers.ctrl || modifiers.command)
        && key.name().len() == 1
        && let Some(c) = key.name().chars().next()
        && c.is_ascii_alphabetic()
    {
        out.push((c.to_ascii_uppercase() as u8) & 0x1f);
        return;
    }
    match key {
        Enter => out.push(b'\r'),
        Backspace => out.push(0x7f),
        Tab => out.push(b'\t'),
        Escape => out.push(0x1b),
        ArrowUp => out.extend_from_slice(b"\x1b[A"),
        ArrowDown => out.extend_from_slice(b"\x1b[B"),
        ArrowRight => out.extend_from_slice(b"\x1b[C"),
        ArrowLeft => out.extend_from_slice(b"\x1b[D"),
        Home => out.extend_from_slice(b"\x1b[H"),
        End => out.extend_from_slice(b"\x1b[F"),
        Delete => out.extend_from_slice(b"\x1b[3~"),
        PageUp => out.extend_from_slice(b"\x1b[5~"),
        PageDown => out.extend_from_slice(b"\x1b[6~"),
        _ => {}
    }
}
