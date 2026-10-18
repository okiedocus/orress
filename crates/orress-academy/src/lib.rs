//! The ORRESS Academy: step-by-step lessons that check what you do in the app,
//! practice crackmes, and a CPU simulator.
//!
//! The app feeds [`Event`]s (commands run, views opened, files opened) and a
//! [`PollState`] (what is true right now) into the [`Academy`]; the academy decides
//! when the current step is done, awards XP and badges, and tells the UI what to
//! spotlight.

pub mod crackmes;
pub mod glossary;
pub mod lesson;
pub mod numbers;
pub mod progress;
pub mod sim;
mod ui;

use std::path::{Path, PathBuf};

pub use glossary::Term;
pub use lesson::{Check, LEVELS, Lesson, Step};
pub use progress::Progress;
use sha2::{Digest, Sha256};
pub use ui::{lesson_panel, overview, simulator, spotlight_overlay};

/// Something the user did, reported by the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A command (action id) ran, e.g. `command_palette::Toggle`.
    Action(String),
    /// A view of a file got focus, e.g. "Strings".
    ViewFocused(String),
    /// A file was opened.
    FileOpened(PathBuf),
}

/// Facts about the app that some checks look at every frame.
#[derive(Clone, Debug, Default)]
pub struct PollState {
    /// Name of the focused file view, e.g. "Strings".
    pub focused_view: Option<String>,
    pub cursor_in_main: bool,
    pub renamed: bool,
    pub commented: bool,
}

/// Things the academy asks the app to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    OpenFile(PathBuf),
    OpenSimulator,
    OpenLesson,
    /// Show the Academy tab, on the glossary.
    OpenGlossary,
    Message(String),
}

/// Feedback on an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feedback {
    pub correct: bool,
    pub text: String,
}

pub struct SimState {
    pub source: String,
    pub cpu: Option<sim::Cpu>,
    pub error: Option<sim::ParseError>,
}

impl Default for SimState {
    fn default() -> Self {
        let source =
            "; Type assembly here, then press Run or Step.\nmov rax, 5\nadd rax, 10\n".to_owned();
        let mut s = Self {
            source,
            cpu: None,
            error: None,
        };
        s.reset();
        s
    }
}

impl SimState {
    pub fn reset(&mut self) {
        match sim::Cpu::new(&self.source) {
            Ok(cpu) => {
                self.cpu = Some(cpu);
                self.error = None;
            }
            Err(e) => {
                self.cpu = None;
                self.error = Some(e);
            }
        }
    }

    pub fn load(&mut self, source: &str) {
        source.clone_into(&mut self.source);
        self.reset();
    }
}

/// Which page the Academy tab shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    #[default]
    Lessons,
    Glossary,
}

pub struct Academy {
    pub lessons: Vec<Lesson>,
    pub glossary: Vec<Term>,
    /// Glossary terms mentioned in the current step (indices into `glossary`).
    pub step_terms: Vec<usize>,
    pub page: Page,
    /// Search text on the glossary page.
    pub glossary_filter: String,
    /// Term to scroll to and open on the glossary page.
    pub glossary_focus: Option<usize>,
    pub progress: Progress,
    progress_file: Option<PathBuf>,
    crackme_dir: Option<PathBuf>,
    /// Active lesson index and step index.
    pub active: Option<(usize, usize)>,
    /// Hints revealed for the current step.
    pub hints_shown: usize,
    pub answer: String,
    pub feedback: Option<Feedback>,
    pub sim: SimState,
    /// Number typed into the number converter widget.
    pub converter: String,
    requests: Vec<Request>,
    opened: Vec<PathBuf>,
    /// Lesson completed just now (for a celebration message).
    pub celebrate: Option<String>,
    markdown: egui_commonmark::CommonMarkCache,
}

impl Academy {
    /// `config_dir`: where progress (`academy.json`) and extracted crackmes go.
    pub fn new(config_dir: Option<&Path>) -> Self {
        let progress_file = config_dir.map(|d| d.join("academy.json"));
        let progress = progress_file
            .as_deref()
            .map(Progress::load)
            .unwrap_or_default();
        let lessons = lesson::catalog();
        let active = progress
            .current
            .as_ref()
            .and_then(|id| lessons.iter().position(|l| &l.id == id))
            .map(|i| (i, first_open_step(&progress, &lessons[i])));
        let mut academy = Self {
            lessons,
            glossary: glossary::catalog(),
            step_terms: Vec::new(),
            page: Page::default(),
            glossary_filter: String::new(),
            glossary_focus: None,
            progress,
            progress_file,
            crackme_dir: config_dir.map(|d| d.join("academy").join("crackmes")),
            active,
            hints_shown: 0,
            answer: String::new(),
            feedback: None,
            sim: SimState::default(),
            converter: "42".into(),
            requests: Vec::new(),
            opened: Vec::new(),
            celebrate: None,
            markdown: egui_commonmark::CommonMarkCache::default(),
        };
        // Restore the current step (e.g. its simulator starting code) after a restart.
        academy.enter_step();
        academy
    }

    pub fn take_requests(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.requests)
    }

    fn save(&mut self) {
        if let Some(file) = &self.progress_file
            && let Err(e) = self.progress.save(file)
        {
            self.requests.push(Request::Message(format!(
                "Could not save Academy progress: {e}"
            )));
        }
    }

    /// The lesson to continue with: the active one, or the first unfinished one.
    pub fn next_lesson(&self) -> Option<usize> {
        self.active.map(|(l, _)| l).or_else(|| {
            self.lessons
                .iter()
                .position(|l| !self.progress.lessons.contains(&l.id))
        })
    }

    pub fn start(&mut self, lesson: usize) {
        let Some(l) = self.lessons.get(lesson) else {
            return;
        };
        let step = first_open_step(&self.progress, l);
        self.progress.current = Some(l.id.clone());
        self.active = Some((lesson, step));
        self.enter_step();
        self.save();
        self.requests.push(Request::OpenLesson);
    }

    pub fn current(&self) -> Option<(&Lesson, usize, &Step)> {
        let (l, s) = self.active?;
        let lesson = self.lessons.get(l)?;
        Some((lesson, s, lesson.steps.get(s)?))
    }

    pub fn current_done(&self) -> bool {
        self.current()
            .is_some_and(|(l, s, _)| self.progress.step_done(&l.id, s))
    }

    /// UI element to highlight for the current step, while it is not done.
    pub fn spotlight(&self) -> Option<&str> {
        let (_, _, step) = self.current()?;
        (!self.current_done())
            .then_some(step.spotlight.as_deref())
            .flatten()
    }

    fn enter_step(&mut self) {
        self.hints_shown = 0;
        self.answer.clear();
        self.feedback = None;
        self.step_terms.clear();
        let Some((_, _, step)) = self.current() else {
            return;
        };
        let mut text = format!("{}\n{}", step.title, step.text);
        for line in step.instructions.iter().chain(&step.goal) {
            text.push('\n');
            text.push_str(line);
        }
        if let Check::Choice { options, .. } = &step.check {
            text.push('\n');
            text.push_str(&options.join("\n"));
        }
        let code = step.sim_code.clone();
        self.step_terms = glossary::mentioned(&self.glossary, &text);
        if let Some(code) = code {
            self.sim.load(&code);
        }
    }

    /// Opens the glossary page of the Academy tab, at `term` if given.
    pub fn show_glossary(&mut self, term: Option<usize>) {
        self.page = Page::Glossary;
        self.glossary_focus = term;
        if term.is_some() {
            self.glossary_filter.clear();
        }
        self.requests.push(Request::OpenGlossary);
    }

    pub fn go_to_step(&mut self, step: usize) {
        if let Some((l, _)) = self.active
            && step < self.lessons[l].steps.len()
        {
            self.active = Some((l, step));
            self.enter_step();
        }
    }

    pub fn next(&mut self) {
        let Some((l, s)) = self.active else {
            return;
        };
        if matches!(self.lessons[l].steps[s].check, Check::Continue) {
            self.complete();
        }
        if s + 1 < self.lessons[l].steps.len() {
            self.go_to_step(s + 1);
        }
        // On the last step the lesson stays open, so its closing text and unlocked
        // source remain visible; the panel then offers the next lesson.
    }

    /// The lesson after the active one, if any.
    pub fn following_lesson(&self) -> Option<usize> {
        let (l, _) = self.active?;
        (l + 1 < self.lessons.len()).then_some(l + 1)
    }

    pub fn previous(&mut self) {
        if let Some((_, s)) = self.active
            && s > 0
        {
            self.go_to_step(s - 1);
        }
    }

    pub fn reveal_hint(&mut self) {
        let Some((lesson, _, step)) = self.current() else {
            return;
        };
        if self.hints_shown < step.hints.len() {
            let id = lesson.id.clone();
            self.hints_shown += 1;
            *self.progress.hints_used.entry(id).or_default() += 1;
            self.save();
        }
    }

    /// Marks the current step done, and the lesson when all its steps are.
    fn complete(&mut self) {
        let Some((l, s)) = self.active else {
            return;
        };
        let id = self.lessons[l].id.clone();
        self.progress.complete_step(&id, s, progress::today());
        let all = (0..self.lessons[l].steps.len()).all(|i| self.progress.step_done(&id, i));
        if all && self.progress.complete_lesson(&id) > 0 {
            let lesson = &self.lessons[l];
            if let Some(badge) = &lesson.badge {
                self.progress.badges.insert(badge.clone());
            }
            let level = lesson.level;
            let level_done = self
                .lessons
                .iter()
                .filter(|x| x.level == level)
                .all(|x| self.progress.lessons.contains(&x.id));
            if level_done {
                self.progress
                    .badges
                    .insert(format!("Level {level}: {}", LEVELS[usize::from(level)].0));
            }
            self.celebrate = Some(lesson.title.clone());
        }
        self.save();
    }

    fn check_matches(&self, f: impl Fn(&Check) -> bool) -> bool {
        self.current()
            .is_some_and(|(_, _, step)| !self.current_done() && f(&step.check))
    }

    /// Reports a user action.
    pub fn handle(&mut self, event: &Event) {
        if let Event::FileOpened(path) = event {
            self.opened.push(path.clone());
        }
        let done = self.check_matches(|check| match (check, event) {
            (Check::Action { id }, Event::Action(a)) => id == a,
            (Check::View { view }, Event::ViewFocused(v)) => view.eq_ignore_ascii_case(v),
            (Check::OpenCrackme { name }, Event::FileOpened(path)) => crackmes::find(name)
                .is_some_and(|c| path.file_name().is_some_and(|f| f == c.file_name)),
            _ => false,
        });
        if done {
            self.complete();
        }
    }

    /// Checks conditions that are about the current state.
    pub fn poll(&mut self, state: &PollState) {
        let done = self.check_matches(|check| match check {
            Check::View { view } => state
                .focused_view
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case(view)),
            Check::CursorInMain => state.cursor_in_main,
            Check::Renamed => state.renamed,
            Check::Commented => state.commented,
            _ => false,
        });
        if done {
            self.complete();
        }
    }

    /// Checks the typed answer (for answer and secret steps).
    pub fn submit_answer(&mut self) {
        let Some((_, _, step)) = self.current() else {
            return;
        };
        let given = self.answer.trim().to_owned();
        let correct = match &step.check {
            Check::Answer {
                answers,
                number,
                case_sensitive,
            } => answers.iter().any(|a| {
                if *number {
                    numbers::parse(a).is_some() && numbers::parse(a) == numbers::parse(&given)
                } else if *case_sensitive {
                    a.trim() == given
                } else {
                    a.trim().eq_ignore_ascii_case(&given)
                }
            }),
            Check::Secret { sha256 } => {
                let digest = Sha256::digest(given.as_bytes());
                let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                hex.eq_ignore_ascii_case(sha256)
            }
            _ => return,
        };
        self.feedback = Some(Feedback {
            correct,
            text: if correct {
                "Correct!".into()
            } else if given.is_empty() {
                "Type an answer first.".into()
            } else {
                "Not quite. Try again, or take a hint.".into()
            },
        });
        if correct {
            self.complete();
        }
    }

    /// Checks a multiple-choice pick.
    pub fn choose(&mut self, option: usize) {
        let Some((_, _, step)) = self.current() else {
            return;
        };
        let Check::Choice {
            correct, explain, ..
        } = &step.check
        else {
            return;
        };
        let ok = option == *correct;
        let why = explain
            .get(option)
            .map(|w| format!(" {w}"))
            .unwrap_or_default();
        self.feedback = Some(Feedback {
            correct: ok,
            text: if ok {
                format!("Correct!{why}")
            } else if why.is_empty() {
                "Not that one. Read the text again, or take a hint.".into()
            } else {
                format!("Not that one.{why}")
            },
        });
        if ok {
            self.complete();
        }
    }

    /// Call after the simulator ran or stepped.
    pub fn sim_updated(&mut self) {
        let Some(cpu) = &self.sim.cpu else {
            return;
        };
        if !cpu.finished_ok() {
            return;
        }
        let Some((_, _, step)) = self.current() else {
            return;
        };
        let Check::Sim { expect, requires } = &step.check else {
            return;
        };
        let missing: Vec<&String> = requires.iter().filter(|m| !cpu.uses(m)).collect();
        let wrong: Vec<String> = expect
            .iter()
            .filter(|(reg, value)| cpu.reg(reg) != Some(*value as u64))
            .map(|(reg, value)| {
                format!(
                    "{reg} should be {value}, but it is {}",
                    cpu.reg(reg).unwrap_or(0) as i64
                )
            })
            .collect();
        let correct = missing.is_empty() && wrong.is_empty();
        let text = if correct {
            "The program does what was asked. Well done!".to_owned()
        } else if !missing.is_empty() {
            let list: Vec<&str> = missing.iter().map(|s| s.as_str()).collect();
            format!("Use {} in your program.", list.join(", "))
        } else {
            wrong.join("; ")
        };
        self.feedback = Some(Feedback { correct, text });
        if correct && !self.current_done() {
            self.complete();
        }
    }

    /// Extracts a practice program and asks the app to open it.
    pub fn open_crackme(&mut self, name: &str) {
        let Some(c) = crackmes::find(name) else {
            return;
        };
        let dir = self
            .crackme_dir
            .clone()
            .unwrap_or_else(|| std::env::temp_dir().join("orress-academy"));
        match crackmes::extract(c, &dir) {
            Ok(path) => self.requests.push(Request::OpenFile(path)),
            Err(e) => self
                .requests
                .push(Request::Message(format!("Could not extract {name}: {e}"))),
        }
    }

    pub fn total_steps(&self) -> usize {
        self.lessons.iter().map(|l| l.steps.len()).sum()
    }

    pub fn done_steps(&self) -> usize {
        self.lessons
            .iter()
            .map(|l| {
                (0..l.steps.len())
                    .filter(|&i| self.progress.step_done(&l.id, i))
                    .count()
            })
            .sum()
    }
}

fn first_open_step(progress: &Progress, lesson: &Lesson) -> usize {
    (0..lesson.steps.len())
        .find(|&i| !progress.step_done(&lesson.id, i))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn academy() -> Academy {
        Academy::new(None)
    }

    fn find_step(a: &Academy, f: impl Fn(&Check) -> bool) -> (usize, usize) {
        for (li, l) in a.lessons.iter().enumerate() {
            for (si, s) in l.steps.iter().enumerate() {
                if f(&s.check) {
                    return (li, si);
                }
            }
        }
        panic!("no such step in the built-in lessons");
    }

    #[test]
    fn action_step_completes_on_event() {
        let mut a = academy();
        let (l, s) = find_step(&a, |c| matches!(c, Check::Action { .. }));
        a.start(l);
        a.go_to_step(s);
        let Check::Action { id } = a.current().unwrap().2.check.clone() else {
            unreachable!()
        };
        a.handle(&Event::Action("something::Else".into()));
        assert!(!a.current_done());
        a.handle(&Event::Action(id));
        assert!(a.current_done());
        assert!(a.progress.xp > 0);
        assert_eq!(a.spotlight(), None, "no spotlight once done");
    }

    #[test]
    fn number_answers_accept_any_base() {
        let mut a = academy();
        let (l, s) = find_step(&a, |c| matches!(c, Check::Answer { number: true, .. }));
        a.start(l);
        a.go_to_step(s);
        let Check::Answer { answers, .. } = a.current().unwrap().2.check.clone() else {
            unreachable!()
        };
        let value = numbers::parse(&answers[0]).unwrap();
        a.answer = "definitely wrong".into();
        a.submit_answer();
        assert!(!a.feedback.as_ref().unwrap().correct);
        a.answer = format!("0x{value:x}");
        a.submit_answer();
        assert!(a.feedback.as_ref().unwrap().correct, "hex form of {value}");
    }

    #[test]
    fn crackme_passwords_match_their_secrets() {
        let mut a = academy();
        // Every practice program's password, so a typo in a lesson's sha256 is caught.
        for password in [
            "open_sesame_101",
            "R3v3rs3",
            "ORRESS42",
            "w4tch_1t_run",
            "n0_debugger_here",
            "pa7ch_0r_3mulat3",
            "flag{te4_h4s_a_g0ld_k3y}",
            "s0lv3_m3_n0w",
            "unfl4tt3",
            "vm_0wned",
            "h4ckv3rs",
            "r3g_v4lz",
            "ORR-DIFF-7",
        ] {
            let (l, s) = find_step(&a, |c| {
                matches!(c, Check::Secret { sha256 } if *sha256 == {
                    let d = Sha256::digest(password.as_bytes());
                    d.iter().map(|b| format!("{b:02x}")).collect::<String>()
                })
            });
            a.start(l);
            a.go_to_step(s);
            a.answer = password.into();
            a.submit_answer();
            assert!(a.current_done(), "{password}");
        }
    }

    #[test]
    fn sim_steps_complete_with_their_solution() {
        // Lesson validation already runs every solution; here the whole flow is tested:
        // load the solution into the simulator, run it, and the step completes.
        let mut a = academy();
        let steps: Vec<(usize, usize)> = a
            .lessons
            .iter()
            .enumerate()
            .flat_map(|(li, l)| {
                l.steps
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| matches!(s.check, Check::Sim { .. }))
                    .map(move |(si, _)| (li, si))
            })
            .collect();
        assert!(steps.len() >= 4, "Level 1 has simulator exercises");
        for (l, s) in steps {
            a.start(l);
            a.go_to_step(s);
            let solution = a.current().unwrap().2.solution.clone().unwrap();
            a.sim.load(&solution);
            a.sim.cpu.as_mut().unwrap().run();
            a.sim_updated();
            assert!(a.current_done(), "lesson {l} step {s}");
        }
    }

    #[test]
    fn completing_all_steps_completes_the_lesson() {
        let mut a = academy();
        a.start(0);
        let id = a.lessons[0].id.clone();
        for s in 0..a.lessons[0].steps.len() {
            a.go_to_step(s);
            a.complete();
        }
        assert!(a.progress.lessons.contains(&id));
        assert_eq!(a.celebrate.as_deref(), Some(a.lessons[0].title.as_str()));
    }
}
