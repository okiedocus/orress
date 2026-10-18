//! Academy screens: the overview, the lesson panel, the CPU simulator, widgets, and
//! the spotlight overlay.

use egui::{Color32, Context, RichText, Ui};
use orress_ui::{ExplainExt as _, muted, spotlight};

use crate::sim::{self, STACK_TOP};
use crate::{Academy, Check, LEVELS, Page, Request, numbers, progress};

fn markdown(ui: &mut Ui, academy: &mut Academy, text: &str) {
    let mut cache = std::mem::take(&mut academy.markdown);
    egui_commonmark::CommonMarkViewer::new().show(ui, &mut cache, text);
    academy.markdown = cache;
}

/// A status dot: filled for done/current, hollow for to-do. Drawn rather than typed,
/// because the default fonts lack the circle characters.
fn dot(ui: &mut Ui, filled: bool, color: Color32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::click());
    let center = rect.center();
    if filled {
        ui.painter().circle_filled(center, 5.0, color);
    } else {
        ui.painter()
            .circle_stroke(center, 4.5, egui::Stroke::new(1.5, color));
    }
    response
}

fn success_color(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(120, 200, 120)
    } else {
        Color32::from_rgb(40, 130, 40)
    }
}

/// The Academy tab: the lesson overview, or the glossary.
pub fn overview(ui: &mut Ui, academy: &mut Academy) {
    ui.horizontal(|ui| {
        ui.selectable_value(
            &mut academy.page,
            Page::Lessons,
            RichText::new("Lessons").strong(),
        );
        ui.selectable_value(
            &mut academy.page,
            Page::Glossary,
            RichText::new("Glossary").strong(),
        )
        .explain(
            "Glossary",
            "Every technical word used in the lessons, explained in plain language.",
        );
    });
    ui.separator();
    match academy.page {
        Page::Lessons => lessons_page(ui, academy),
        Page::Glossary => glossary_page(ui, academy),
    }
}

fn glossary_page(ui: &mut Ui, academy: &mut Academy) {
    ui.horizontal(|ui| {
        ui.label("Search:");
        ui.add(
            egui::TextEdit::singleline(&mut academy.glossary_filter)
                .id_salt("orress::glossary_filter")
                .hint_text("a word, e.g. stack")
                .desired_width(240.0),
        );
        ui.label(muted(format!("{} words", academy.glossary.len())));
    });
    ui.add_space(4.0);
    let filter = academy.glossary_filter.trim().to_lowercase();
    let focus = academy.glossary_focus.take();
    let mut jump = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut letter = None;
            for i in 0..academy.glossary.len() {
                let term = academy.glossary[i].clone();
                let matches = filter.is_empty()
                    || term.term.to_lowercase().contains(&filter)
                    || term
                        .aliases
                        .iter()
                        .any(|a| a.to_lowercase().contains(&filter))
                    || term.short.to_lowercase().contains(&filter);
                if !matches {
                    continue;
                }
                let first = term.term.chars().next().map(|c| c.to_ascii_uppercase());
                if filter.is_empty() && first != letter {
                    letter = first;
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(first.unwrap_or(' ').to_string())
                            .strong()
                            .size(16.0),
                    );
                }
                // The term, then its one-line explanation wrapping below it in a narrow
                // panel; click the term to open the full explanation.
                let id = ui.make_persistent_id(("orress::glossary_term", i));
                let mut open = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
                if focus == Some(i) {
                    open = true;
                }
                let header = ui
                    .horizontal_wrapped(|ui| {
                        let r = ui
                            .selectable_label(open, RichText::new(&term.term).strong())
                            .on_hover_text(if open { "Fold" } else { "Read more" });
                        ui.label(muted(&term.short));
                        r
                    })
                    .inner;
                if header.clicked() {
                    open = !open;
                }
                ui.data_mut(|d| d.insert_temp(id, open));
                if open {
                    ui.indent(id, |ui| {
                        if !term.aliases.is_empty() {
                            ui.label(muted(format!("Also written: {}", term.aliases.join(", "))));
                        }
                        if let Some(text) = &term.text {
                            markdown(ui, academy, text);
                        }
                        if !term.see.is_empty() {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(muted("See also:"));
                                for see in &term.see {
                                    if ui.link(see).clicked() {
                                        jump = crate::glossary::find(&academy.glossary, see);
                                    }
                                }
                            });
                        }
                    });
                }
                ui.add_space(2.0);
                if focus == Some(i) {
                    header.scroll_to_me(Some(egui::Align::TOP));
                }
            }
        });
    if let Some(i) = jump {
        academy.glossary_filter.clear();
        academy.glossary_focus = Some(i);
    }
}

fn lessons_page(ui: &mut Ui, academy: &mut Academy) {
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.heading("ORRESS Academy");
        ui.label(muted(
            "Learn reverse engineering step by step, from binary numbers to cracking programs. \
             Every lesson checks what you do in ORRESS itself, and the examples are written in Rust.",
        ));
        ui.label(muted(
            "You only need to know some basic Rust. Everything else is taught here, and every \
             technical word is explained in the Glossary (the tab above).",
        ));
        ui.add_space(8.0);

        let p = &academy.progress;
        let today = progress::today();
        ui.horizontal(|ui| {
            ui.label(RichText::new(p.rank()).strong().size(16.0)).explain(
                "Rank",
                "Your title, based on the experience points (XP) you earned. Every finished step \
                 gives 10 XP, every finished lesson 50 XP more.",
            );
            ui.separator();
            ui.label(format!("{} XP", p.xp));
            ui.separator();
            let streak = p.streak(today);
            ui.label(format!("{streak} day streak")).explain(
                "Streak",
                "Days in a row on which you finished at least one step. A little every day is the \
                 fastest way to learn.",
            );
        });
        let (done, total) = (academy.done_steps(), academy.total_steps());
        ui.add(
            egui::ProgressBar::new(done as f32 / total.max(1) as f32)
                .text(format!("{done} of {total} steps"))
                .desired_width(360.0),
        );
        if !p.badges.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(muted("Badges:"));
                for badge in &p.badges {
                    ui.label(RichText::new(badge).strong().color(Color32::from_rgb(230, 180, 60)));
                }
            });
        }
        ui.add_space(8.0);
        if let Some(next) = academy.next_lesson() {
            let title = academy.lessons[next].title.clone();
            if ui
                .button(RichText::new(format!("Continue: {title}")).size(16.0).strong())
                .clicked()
            {
                academy.start(next);
            }
        } else {
            ui.label(RichText::new("You finished every lesson available so far!").strong());
        }
        ui.add_space(12.0);

        for (level, (name, about)) in LEVELS.iter().enumerate() {
            let lessons: Vec<usize> = (0..academy.lessons.len())
                .filter(|&i| usize::from(academy.lessons[i].level) == level)
                .collect();
            egui::Frame::group(ui.style()).inner_margin(10.0).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(format!("Level {level} · {name}")).strong().size(15.0));
                ui.label(muted(*about));
                if lessons.is_empty() {
                    ui.label(muted("Coming in a later version of ORRESS."));
                }
                for i in lessons {
                    let lesson = &academy.lessons[i];
                    let finished = academy.progress.lessons.contains(&lesson.id);
                    let steps_done = (0..lesson.steps.len())
                        .filter(|&s| academy.progress.step_done(&lesson.id, s))
                        .count();
                    let active = academy.active.map(|(l, _)| l) == Some(i);
                    let mut start = false;
                    ui.horizontal(|ui| {
                        let (filled, color) = if finished {
                            (true, success_color(ui))
                        } else if active {
                            (true, ui.visuals().hyperlink_color)
                        } else {
                            (false, ui.visuals().weak_text_color())
                        };
                        dot(ui, filled, color);
                        ui.label(RichText::new(&lesson.title).strong());
                        ui.label(muted(format!("{steps_done}/{}", lesson.steps.len())));
                        let label = if finished {
                            "Review"
                        } else if steps_done > 0 {
                            "Continue"
                        } else {
                            "Start"
                        };
                        start = ui.small_button(label).clicked();
                    });
                    ui.label(RichText::new(&lesson.summary).small());
                    if start {
                        academy.start(i);
                    }
                }
            });
            ui.add_space(6.0);
        }
    });
}

/// The lesson panel (right dock while a lesson runs).
pub fn lesson_panel(ui: &mut Ui, academy: &mut Academy) {
    let Some((lesson, step_index, step)) =
        academy.current().map(|(l, i, s)| (l.clone(), i, s.clone()))
    else {
        ui.heading("Lessons");
        ui.label("No lesson is running. Open the Academy (Learn menu) and pick one.");
        return;
    };
    let done = academy.current_done();
    spotlight::mark(ui.ctx(), "lesson", ui.max_rect());
    // Both scrollbars: prose wraps to the panel width (pinned below), but anything that can't wrap
    // to fit — a wide table, a long unbroken token, a widget — gets a horizontal scrollbar instead
    // of being clipped by the narrow dock.
    let content_width = ui.available_width();
    egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(content_width);
        if let Some(title) = academy.celebrate.clone() {
            egui::Frame::new()
                .fill(success_color(ui).gamma_multiply(0.25))
                .corner_radius(6.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.label(RichText::new(format!("Lesson complete: {title}")).strong());
                    ui.label(format!("+{} XP. Great work!", progress::XP_PER_LESSON));
                    if ui.small_button("OK").clicked() {
                        academy.celebrate = None;
                    }
                });
            ui.add_space(6.0);
        }

        ui.label(muted(format!("Level {} · {}", lesson.level, LEVELS[usize::from(lesson.level)].0)));
        ui.horizontal(|ui| {
            ui.label(RichText::new(&lesson.title).strong().size(16.0));
            if ui
                .small_button("Glossary")
                .on_hover_text("Look up any word in the Academy glossary.")
                .clicked()
            {
                academy.show_glossary(None);
            }
        });
        // Step dots: click to jump to a step.
        ui.horizontal_wrapped(|ui| {
            for i in 0..lesson.steps.len() {
                let step_done = academy.progress.step_done(&lesson.id, i);
                let color = if i == step_index {
                    ui.visuals().hyperlink_color
                } else if step_done {
                    success_color(ui)
                } else {
                    ui.visuals().weak_text_color()
                };
                if dot(ui, step_done || i == step_index, color)
                    .on_hover_text(&lesson.steps[i].title)
                    .clicked()
                {
                    academy.go_to_step(i);
                }
            }
            ui.label(muted(format!("step {} of {}", step_index + 1, lesson.steps.len())));
        });
        ui.separator();

        if step_index == 0 && !lesson.goals.is_empty() {
            egui::Frame::group(ui.style()).inner_margin(8.0).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("In this lesson you will learn to").strong());
                for goal in &lesson.goals {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("-");
                        ui.label(goal);
                    });
                }
            });
            ui.add_space(4.0);
        }
        ui.label(RichText::new(&step.title).strong().size(15.0));
        if let Some(goal) = &step.goal {
            ui.label(muted(format!("Goal: {goal}")));
        }
        markdown(ui, academy, &step.text);
        if let Some(deep) = &step.deep_dive {
            ui.collapsing("Learn more", |ui| markdown(ui, academy, deep));
        }
        if let Some(widget) = &step.widget {
            ui.add_space(4.0);
            egui::Frame::group(ui.style()).show(ui, |ui| match widget.as_str() {
                "number_converter" => number_converter(ui, &mut academy.converter),
                "ascii_table" => ascii_table(ui),
                other => {
                    ui.label(muted(format!("(unknown widget {other})")));
                }
            });
        }
        ui.add_space(6.0);
        instructions(ui, academy, &step, done);
        task(ui, academy, &step, done);

        if let Some(f) = &academy.feedback {
            let color = if f.correct { success_color(ui) } else { ui.visuals().warn_fg_color };
            ui.colored_label(color, &f.text);
        }
        if done && let Some(success) = &step.success {
            egui::Frame::new()
                .fill(success_color(ui).gamma_multiply(0.15))
                .corner_radius(6.0)
                .inner_margin(8.0)
                .show(ui, |ui| markdown(ui, academy, success));
        }

        hints(ui, academy, &step, done);
        step_words(ui, academy);

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(step_index > 0, egui::Button::new("Back")).clicked() {
                academy.previous();
            }
            let can_continue = done || matches!(step.check, Check::Continue);
            let last = step_index + 1 == lesson.steps.len();
            let finished = academy.progress.lessons.contains(&lesson.id);
            if last && finished {
                if let Some(next) = academy.following_lesson() {
                    let title = academy.lessons[next].title.clone();
                    if ui.button(RichText::new(format!("Next lesson: {title}")).strong()).clicked() {
                        academy.celebrate = None;
                        academy.start(next);
                    }
                } else {
                    ui.label(RichText::new("You finished every lesson available so far!").strong());
                }
            } else {
                let label = if last { "Finish lesson" } else { "Next" };
                if ui
                    .add_enabled(can_continue, egui::Button::new(RichText::new(label).strong()))
                    .on_disabled_hover_text("Complete the task above first.")
                    .clicked()
                {
                    academy.next();
                }
            }
        });

        if academy.progress.lessons.contains(&lesson.id)
            && let Some(name) = &lesson.reveal_source
            && let Some(c) = crate::crackmes::find(name)
        {
            ui.add_space(10.0);
            ui.collapsing("Source code of the practice program (unlocked)", |ui| {
                ui.label(muted("Now that you cracked it, compare what you saw with the original Rust code."));
                ui.add(
                    egui::TextEdit::multiline(&mut c.source.to_owned())
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }
    });
}

/// The numbered "Do this" list: exactly what the learner has to do.
fn instructions(ui: &mut Ui, academy: &mut Academy, step: &crate::Step, done: bool) {
    if step.instructions.is_empty() {
        return;
    }
    let accent = if done {
        success_color(ui)
    } else {
        ui.visuals().hyperlink_color
    };
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0, accent))
        .corner_radius(6.0)
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(if done { "Done:" } else { "Do this:" })
                    .strong()
                    .color(accent),
            );
            for (i, line) in step.instructions.iter().enumerate() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("{}.", i + 1)).strong());
                    // Instructions may use **bold** and `code`.
                    ui.vertical(|ui| markdown(ui, academy, line));
                });
            }
        });
    ui.add_space(4.0);
}

/// Glossary terms used in this step, folded away until needed.
fn step_words(ui: &mut Ui, academy: &mut Academy) {
    if academy.step_terms.is_empty() {
        return;
    }
    ui.add_space(6.0);
    let terms = academy.step_terms.clone();
    let mut open = None;
    ui.collapsing(format!("Words in this step ({})", terms.len()), |ui| {
        for i in terms {
            let term = &academy.glossary[i];
            ui.horizontal_wrapped(|ui| {
                if ui
                    .link(RichText::new(&term.term).strong())
                    .on_hover_text("Open in the glossary")
                    .clicked()
                {
                    open = Some(i);
                }
                ui.label(&term.short);
            });
        }
    });
    if let Some(i) = open {
        academy.show_glossary(Some(i));
    }
}

fn task(ui: &mut Ui, academy: &mut Academy, step: &crate::Step, done: bool) {
    let status = |ui: &mut Ui, text: &str| {
        let (mark, color) = if done {
            ("Done: ", success_color(ui))
        } else {
            ("Your task: ", ui.visuals().hyperlink_color)
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(mark).strong().color(color));
            ui.label(text);
        });
    };
    match &step.check {
        Check::Continue => {}
        Check::Action { .. } => status(
            ui,
            "follow the steps above. The lesson notices when you did it.",
        ),
        Check::View { view } => status(ui, &format!("open the {view} view (see the steps above).")),
        Check::OpenCrackme { name } => {
            status(ui, &format!("open the practice program {name}."));
            if !done && ui.button(format!("Open {name}")).clicked() {
                academy.open_crackme(name);
            }
        }
        Check::CursorInMain => status(ui, "put the cursor inside the main function."),
        Check::Renamed => status(ui, "rename something (N in the disassembly)."),
        Check::Commented => status(ui, "add a comment (; in the disassembly)."),
        Check::Answer { .. } | Check::Secret { .. } => {
            if done {
                status(ui, "answered correctly.");
            } else {
                ui.horizontal(|ui| {
                    let edit = ui.add(
                        egui::TextEdit::singleline(&mut academy.answer)
                            .id_salt("orress::lesson_answer")
                            .hint_text("Your answer")
                            .desired_width(200.0),
                    );
                    let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Check").clicked() || enter {
                        academy.submit_answer();
                    }
                });
            }
        }
        Check::Choice {
            options, correct, ..
        } => {
            for (i, option) in options.iter().enumerate() {
                let text = if done && i == *correct {
                    RichText::new(format!("{option}  (correct)")).color(success_color(ui))
                } else {
                    RichText::new(option)
                };
                if ui
                    .add_enabled(!done, egui::Button::new(text).wrap())
                    .clicked()
                {
                    academy.choose(i);
                }
            }
        }
        Check::Sim { .. } => {
            status(
                ui,
                "make the program in the CPU simulator do what is asked, then Run it.",
            );
            ui.horizontal(|ui| {
                if ui.button("Open CPU simulator").clicked() {
                    academy.requests.push(Request::OpenSimulator);
                }
                if let Some(code) = &step.sim_code
                    && ui.button("Load starting code").clicked()
                {
                    academy.sim.load(code);
                    academy.requests.push(Request::OpenSimulator);
                }
            });
        }
    }
}

fn hints(ui: &mut Ui, academy: &mut Academy, step: &crate::Step, done: bool) {
    if step.hints.is_empty() && step.solution.is_none() {
        return;
    }
    ui.add_space(6.0);
    for (i, hint) in step.hints.iter().take(academy.hints_shown).enumerate() {
        ui.label(RichText::new(format!("Hint {}: {hint}", i + 1)).italics());
    }
    if done {
        return;
    }
    if academy.hints_shown < step.hints.len() {
        if ui
            .small_button(format!(
                "Show hint {} of {}",
                academy.hints_shown + 1,
                step.hints.len()
            ))
            .clicked()
        {
            academy.reveal_hint();
        }
    } else if let Some(solution) = &step.solution {
        ui.collapsing("Show a solution", |ui| {
            ui.label(muted(
                "Try it yourself first! Reading a solution teaches less than finding one.",
            ));
            ui.add(
                egui::TextEdit::multiline(&mut solution.clone())
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .interactive(false),
            );
            if ui.button("Load it into the simulator").clicked() {
                academy.sim.load(solution);
                academy.requests.push(Request::OpenSimulator);
            }
        });
    }
}

fn number_converter(ui: &mut Ui, input: &mut String) {
    ui.label(RichText::new("Number converter").strong())
        .explain(
            "Number converter",
            "Type a number as decimal (42), hexadecimal (0x2a), binary (0b101010) or a character \
         ('A'), and see it in every form at once.",
        );
    ui.add(
        egui::TextEdit::singleline(input)
            .id_salt("orress::number_converter")
            .desired_width(200.0)
            .font(egui::TextStyle::Monospace),
    );
    let Some(value) = numbers::parse(input) else {
        ui.label(muted("Not a number yet."));
        return;
    };
    let v = value as u64;
    let bits = if value < 0 {
        if value >= -128 {
            8
        } else if value >= -(1 << 31) {
            32
        } else {
            64
        }
    } else if v <= 0xff {
        8
    } else if v <= 0xffff {
        16
    } else if v <= 0xffff_ffff {
        32
    } else {
        64
    };
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let v = v & mask;
    egui::Grid::new("converter").num_columns(2).spacing([12.0, 3.0]).show(ui, |ui| {
        let mut row = |label: &str, value: String, explain: &str| {
            ui.label(muted(label)).explain(label, explain);
            ui.label(RichText::new(value).monospace());
            ui.end_row();
        };
        row("decimal", v.to_string(), "Base 10, the way people count.");
        row("hexadecimal", format!("0x{v:X}"), "Base 16: digits 0–9 and A–F. Each hex digit is exactly 4 bits, so two digits make one byte.");
        row("binary", numbers::binary_grouped(v, bits), "Base 2: only 0 and 1, the way the computer stores it. Grouped by 4 bits = one hex digit.");
        row(
            &format!("signed ({bits}-bit)"),
            numbers::signed(v, bits).to_string(),
            "The same bits read as a signed number (two's complement): if the top bit is 1, the number is negative.",
        );
        let le: Vec<String> = numbers::le_bytes(v, bits).iter().map(|b| format!("{b:02X}")).collect();
        let mut be = le.clone();
        be.reverse();
        row("bytes, little-endian", le.join(" "), "How x86 and ARM store it in memory: lowest byte first.");
        row("bytes, big-endian", be.join(" "), "Highest byte first: how people write numbers, and how network protocols send them.");
        if v <= 0xff {
            row("character", numbers::char_of(v), "The ASCII character with this code.");
        }
    });
}

fn ascii_table(ui: &mut Ui) {
    ui.label(RichText::new("ASCII table").strong());
    ui.label(muted(
        "Each printable character and its code in hex. Hover for decimal.",
    ));
    egui::Grid::new("ascii")
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            for row in 0..6u8 {
                for col in 0..16u8 {
                    let code = 0x20 + row * 16 + col;
                    if code > 0x7e {
                        ui.label("");
                        continue;
                    }
                    ui.label(RichText::new(format!("{:02X} {}", code, code as char)).monospace())
                        .on_hover_text(format!("{code} decimal"));
                }
                ui.end_row();
            }
        });
}

/// The CPU simulator tab.
pub fn simulator(ui: &mut Ui, academy: &mut Academy) {
    let mut ran = false;
    ui.horizontal(|ui| {
        ui.heading("CPU simulator");
        ui.label(muted("x86-64, one instruction at a time"));
    });
    ui.label(muted(
        "Type instructions on the left. Step runs one line, Run runs to the end. Changed \
         registers light up. Labels end with ':' and comments start with ';'.",
    ));
    let running = academy.sim.cpu.as_ref().is_some_and(|c| c.steps > 0);
    ui.horizontal(|ui| {
        let can_run = academy.sim.cpu.as_ref().is_some_and(|c| c.halted.is_none());
        let step = ui.add_enabled(can_run, egui::Button::new("Step")).explain(
            "Step",
            "Run one instruction and see what changed. The best way to understand assembly.",
        );
        spotlight::mark(ui.ctx(), "sim.step", step.rect);
        if step.clicked()
            && let Some(cpu) = &mut academy.sim.cpu
        {
            cpu.step();
            ran = true;
        }
        let run = ui
            .add_enabled(can_run, egui::Button::new("Run"))
            .explain("Run", "Run until the program ends.");
        spotlight::mark(ui.ctx(), "sim.run", run.rect);
        if run.clicked()
            && let Some(cpu) = &mut academy.sim.cpu
        {
            cpu.run();
            ran = true;
        }
        let back = academy
            .sim
            .cpu
            .as_ref()
            .is_some_and(sim::Cpu::can_step_back);
        if ui
            .add_enabled(back, egui::Button::new("Step back"))
            .explain("Step back", "Undo the last step: time travel for learning.")
            .clicked()
            && let Some(cpu) = &mut academy.sim.cpu
        {
            cpu.step_back();
        }
        if ui
            .button("Reset")
            .explain(
                "Reset",
                "Start the program again from the first line, with all registers at 0.",
            )
            .clicked()
        {
            academy.sim.reset();
        }
        if let Some(cpu) = &academy.sim.cpu {
            ui.label(muted(format!("{} steps", cpu.steps)));
        }
    });
    if ran {
        academy.sim_updated();
    }
    if let Some(cpu) = &academy.sim.cpu
        && let Some(why) = &cpu.halted
    {
        let color = if cpu.error {
            ui.visuals().warn_fg_color
        } else {
            success_color(ui)
        };
        ui.colored_label(color, why);
    }
    if let Some(f) = &academy.feedback
        && academy
            .current()
            .is_some_and(|(_, _, s)| matches!(s.check, Check::Sim { .. }))
    {
        let color = if f.correct {
            success_color(ui)
        } else {
            ui.visuals().warn_fg_color
        };
        ui.colored_label(color, format!("Lesson: {}", f.text));
    }
    ui.separator();

    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        let current_line = academy.sim.cpu.as_ref().and_then(sim::Cpu::line);
        if running {
            ui.label(RichText::new("Program (press Reset to edit)").strong());
            for (i, line) in academy.sim.source.lines().enumerate() {
                let here = current_line == Some(i + 1);
                let text = format!("{} {:>3}  {line}", if here { ">" } else { " " }, i + 1);
                let mut rt = RichText::new(text).monospace();
                if here {
                    rt = rt.background_color(ui.visuals().selection.bg_fill).strong();
                }
                ui.label(rt);
            }
        } else {
            ui.label(RichText::new("Program").strong());
            let edit = ui.add(
                egui::TextEdit::multiline(&mut academy.sim.source)
                    // A fixed id: messages above the editor come and go while typing, which
                    // would otherwise change its automatic id and drop the keyboard focus.
                    .id_salt("orress::sim_source")
                    .code_editor()
                    .desired_rows(16)
                    .desired_width(f32::INFINITY),
            );
            spotlight::mark(ui.ctx(), "sim.code", edit.rect);
            if edit.changed() {
                academy.sim.reset();
            }
            if let Some(e) = &academy.sim.error {
                ui.colored_label(ui.visuals().warn_fg_color, format!("Line {}: {}", e.line, e.message));
            }
        }

        let ui = &mut cols[1];
        let Some(cpu) = &academy.sim.cpu else {
            ui.label(muted("Fix the program to see the registers."));
            return;
        };
        let regs_rect = ui
            .scope(|ui| {
                ui.label(RichText::new("Registers").strong()).explain(
                    "Registers",
                    "Tiny, very fast storage slots inside the CPU. Instructions work on these. \
                     rax holds a function's result; rsp points at the top of the stack.",
                );
                egui::Grid::new("sim_regs").num_columns(3).spacing([10.0, 2.0]).striped(true).show(ui, |ui| {
                    // r8-r15 only when the program uses them, to keep the list short.
                    let source = academy.sim.source.to_ascii_lowercase();
                    for (i, name) in sim::REGS.iter().enumerate() {
                        let v = cpu.regs[i];
                        if i >= 8 && v == 0 && !source.contains(name) {
                            continue;
                        }
                        let changed = cpu.changed.contains(&i);
                        let color = if changed { Color32::from_rgb(255, 200, 60) } else { ui.visuals().text_color() };
                        let explain = orress_arch::explain::register(orress_arch::Isa::X64, name).unwrap_or("A general-purpose register.");
                        ui.label(RichText::new(*name).monospace().strong()).explain(name, explain);
                        ui.label(RichText::new(format!("0x{v:016x}")).monospace().color(color));
                        ui.label(RichText::new(format!("{}", v as i64)).monospace().color(color));
                        ui.end_row();
                    }
                });
            })
            .response
            .rect;
        spotlight::mark(ui.ctx(), "sim.registers", regs_rect);
        ui.add_space(6.0);
        let flags_rect = ui
            .scope(|ui| {
                ui.label(RichText::new("Flags").strong()).explain(
                    "Flags",
                    "Single bits the CPU sets after arithmetic and comparisons. Conditional jumps \
                     (je, jne, jl ...) decide by looking at them.",
                );
                ui.horizontal(|ui| {
                    let f = cpu.flags;
                    for (name, on, explain) in [
                        ("ZF", f.zf, "Zero flag: the last result was 0. After cmp a, b: a == b."),
                        ("SF", f.sf, "Sign flag: the last result was negative."),
                        ("CF", f.cf, "Carry flag: unsigned overflow. After cmp a, b: a < b as unsigned numbers."),
                        ("OF", f.of, "Overflow flag: the signed result did not fit."),
                    ] {
                        let text = RichText::new(format!("{name}={}", u8::from(on))).monospace();
                        let text = if on { text.strong().color(Color32::from_rgb(255, 200, 60)) } else { text.weak() };
                        ui.label(text).explain(name, explain);
                    }
                });
            })
            .response
            .rect;
        spotlight::mark(ui.ctx(), "sim.flags", flags_rect);
        ui.add_space(6.0);
        let stack_rect = ui
            .scope(|ui| {
                ui.label(RichText::new("Stack").strong()).explain(
                    "Stack",
                    "Memory that grows downward. push puts a value on top (rsp goes down by 8), \
                     pop takes it off (rsp goes up). call pushes the return address.",
                );
                let rsp = cpu.regs[7];
                let mut addr = rsp;
                let mut shown = 0;
                while addr < STACK_TOP && shown < 12 {
                    let value = cpu.read_mem(addr).unwrap_or(0);
                    let marker = if addr == rsp { "rsp >" } else { "     " };
                    let note = if value == 0xdead_0000 { "  (end of program)" } else { "" };
                    ui.label(RichText::new(format!("{marker} {addr:08x}: 0x{value:x}{note}")).monospace());
                    addr += 8;
                    shown += 1;
                }
            })
            .response
            .rect;
        spotlight::mark(ui.ctx(), "sim.stack", stack_rect);
    });
}

/// Draws the spotlight for the current step, if any.
pub fn spotlight_overlay(ctx: &Context, academy: &Academy) {
    let Some((_, _, step)) = academy.current() else {
        return;
    };
    if let Some(target) = academy.spotlight() {
        // Never dim the lesson itself: that is where the learner reads and answers.
        let lesson = spotlight::rect(ctx, "lesson")
            .into_iter()
            .collect::<Vec<_>>();
        spotlight::paint(ctx, target, &step.title, &lesson);
    }
}
