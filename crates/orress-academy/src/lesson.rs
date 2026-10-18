//! Lesson files.
//!
//! A lesson is a TOML file with Markdown text, in `academy/lessons/`:
//!
//! ```toml
//! id = "l0-numbers"
//! level = 0
//! order = 2
//! title = "Number systems"
//! summary = "Binary, hexadecimal and how computers store negative numbers."
//!
//! goals = ["Read and write hexadecimal numbers", "..."]   # shown when the lesson starts
//!
//! [[steps]]
//! title = "Hexadecimal"
//! goal = "Convert a hex number to decimal."   # one line: what this step is for
//! text = """Markdown explanation..."""
//! instructions = ["Click ...", "Type ... and press Check."]  # numbered "Do this" list
//! deep_dive = """Optional extra depth, folded away under 'Learn more'."""
//! widget = "number_converter"          # optional interactive tool
//! spotlight = "palette"                # optional: highlight a part of the UI
//! check = { kind = "answer", answers = ["42"], number = true }
//! hints = ["a nudge", "a direction", "almost the answer"]
//! success = "Shown after the step is done: why it works."
//! ```

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Check {
    /// Just read and press Next.
    Continue,
    /// Run a command (by action id), e.g. open the command palette.
    Action { id: String },
    /// Open (or focus) a view of a file, e.g. "Strings".
    View { view: String },
    /// Open one of the Academy's practice programs.
    OpenCrackme { name: String },
    /// Type an answer. With `number = true`, `42`, `0x2a` and `0b101010` are equal.
    Answer {
        answers: Vec<String>,
        #[serde(default)]
        number: bool,
        #[serde(default)]
        case_sensitive: bool,
    },
    /// Pick one option. `explain`, if given, has one entry per option: why that option is
    /// right or wrong, shown when it is picked.
    Choice {
        options: Vec<String>,
        correct: usize,
        #[serde(default)]
        explain: Vec<String>,
    },
    /// Type a secret (a password). Only its SHA-256 is stored, so reading the lesson
    /// file does not spoil it.
    Secret { sha256: String },
    /// Run a program in the CPU simulator that ends with these register values.
    Sim {
        expect: Vec<(String, i64)>,
        #[serde(default)]
        requires: Vec<String>,
    },
    /// The cursor is inside the detected main function of the open file.
    CursorInMain,
    /// You renamed something in the open file.
    Renamed,
    /// You added a comment in the open file.
    Commented,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Step {
    pub title: String,
    /// One line: what the learner gets out of this step.
    #[serde(default)]
    pub goal: Option<String>,
    pub text: String,
    /// Exactly what to do, one action per entry; shown as a numbered list. Required for
    /// every step with a task other than a multiple-choice question.
    #[serde(default)]
    pub instructions: Vec<String>,
    /// Optional extra depth, folded away under "Learn more".
    #[serde(default)]
    pub deep_dive: Option<String>,
    #[serde(default)]
    pub widget: Option<String>,
    #[serde(default)]
    pub spotlight: Option<String>,
    /// Example program loaded into the CPU simulator for this step.
    #[serde(default)]
    pub sim_code: Option<String>,
    /// Reference solution for simulator steps; shown after all hints, and run by the
    /// tests to prove the exercise can be solved.
    #[serde(default)]
    pub solution: Option<String>,
    #[serde(default = "continue_check")]
    pub check: Check,
    #[serde(default)]
    pub hints: Vec<String>,
    #[serde(default)]
    pub success: Option<String>,
}

fn continue_check() -> Check {
    Check::Continue
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Lesson {
    pub id: String,
    pub level: u8,
    pub order: u32,
    pub title: String,
    pub summary: String,
    /// What the learner can do after the lesson; shown at its start.
    #[serde(default)]
    pub goals: Vec<String>,
    #[serde(default)]
    pub badge: Option<String>,
    /// Crackme whose source is shown after the lesson is completed.
    #[serde(default)]
    pub reveal_source: Option<String>,
    pub steps: Vec<Step>,
}

pub const LEVELS: [(&str, &str); 8] = [
    (
        "Foundations",
        "Binary and hex, bytes and text, what a compiler does, a tour of ORRESS.",
    ),
    (
        "Reading assembly",
        "Registers, flags, the stack, calling conventions, your first crackmes.",
    ),
    (
        "Static analysis",
        "PE and ELF files, graph view, the decompiler, XOR-encoded passwords, keygens.",
    ),
    (
        "Dynamic analysis",
        "Debugging, patching, emulation, beating anti-debugging tricks.",
    ),
    (
        "Intermediate CTF",
        "Crypto recognition, z3, symbolic execution, side channels, .NET/Java/Python/WASM.",
    ),
    (
        "Advanced",
        "Packers, obfuscation, custom VMs, self-modifying code, other CPU architectures.",
    ),
    (
        "Malware analysis",
        "Safe lab setup, triage, behavior, YARA rules, reporting.",
    ),
    (
        "Expert",
        "Drivers and rootkits, time-travel debugging, binary diffing, your own analysis passes.",
    ),
];

// Every `academy/lessons/*.toml` file, as `BUILT_IN: &[(file name, source)]`, plus the
// glossary files (see `build.rs`).
include!(concat!(env!("OUT_DIR"), "/academy_files.rs"));

pub fn parse(source: &str) -> Result<Lesson, String> {
    let lesson: Lesson = toml::from_str(source).map_err(|e| e.to_string())?;
    validate(&lesson)?;
    Ok(lesson)
}

fn validate(lesson: &Lesson) -> Result<(), String> {
    if lesson.steps.is_empty() {
        return Err(format!("{}: a lesson needs at least one step", lesson.id));
    }
    for (i, step) in lesson.steps.iter().enumerate() {
        let at = format!("{} step {}", lesson.id, i + 1);
        if step.hints.len() > 3 {
            return Err(format!("{at}: at most 3 hints"));
        }
        match &step.check {
            Check::Choice {
                options, correct, ..
            } if *correct >= options.len() => {
                return Err(format!("{at}: `correct` is out of range"));
            }
            Check::Choice {
                options, explain, ..
            } if !explain.is_empty() && explain.len() != options.len() => {
                return Err(format!("{at}: `explain` needs one entry per option"));
            }
            Check::Answer {
                answers, number, ..
            } => {
                if answers.is_empty() {
                    return Err(format!("{at}: no answers"));
                }
                if *number && answers.iter().any(|a| crate::numbers::parse(a).is_none()) {
                    return Err(format!("{at}: number answers must be numbers"));
                }
            }
            Check::Secret { sha256 } if sha256.len() != 64 => {
                return Err(format!("{at}: sha256 must be 64 hex digits"));
            }
            Check::Sim { expect, .. }
                if expect
                    .iter()
                    .any(|(r, _)| !crate::sim::REGS.contains(&r.as_str())) =>
            {
                return Err(format!("{at}: unknown register in `expect`"));
            }
            Check::OpenCrackme { name } if crate::crackmes::find(name).is_none() => {
                return Err(format!("{at}: unknown crackme `{name}`"));
            }
            _ => {}
        }
        let needs_instructions = !matches!(step.check, Check::Continue | Check::Choice { .. });
        if needs_instructions && step.instructions.is_empty() {
            return Err(format!(
                "{at}: steps with a task need `instructions` that say exactly what to do"
            ));
        }
        if let Some(code) = &step.sim_code {
            crate::sim::Cpu::new(code)
                .map_err(|e| format!("{at}: sim_code line {}: {}", e.line, e.message))?;
        }
        if let Check::Sim { expect, requires } = &step.check {
            let solution = step
                .solution
                .as_ref()
                .ok_or_else(|| format!("{at}: simulator steps need a `solution`"))?;
            let mut cpu = crate::sim::Cpu::new(solution)
                .map_err(|e| format!("{at}: solution line {}: {}", e.line, e.message))?;
            cpu.run();
            if !cpu.finished_ok() {
                return Err(format!("{at}: solution stopped with: {:?}", cpu.halted));
            }
            for (reg, value) in expect {
                if cpu.reg(reg) != Some(*value as u64) {
                    return Err(format!(
                        "{at}: solution leaves {reg} = {:?}, expected {value}",
                        cpu.reg(reg)
                    ));
                }
            }
            if let Some(m) = requires.iter().find(|m| !cpu.uses(m)) {
                return Err(format!("{at}: solution does not use `{m}`"));
            }
        }
    }
    Ok(())
}

/// All built-in lessons, sorted by level and order.
pub fn catalog() -> Vec<Lesson> {
    let mut lessons: Vec<Lesson> = BUILT_IN
        .iter()
        .map(|(file, source)| {
            parse(source).unwrap_or_else(|e| panic!("built-in lesson {file}: {e}"))
        })
        .collect();
    lessons.sort_by_key(|l| (l.level, l.order));
    lessons
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks every file on its own and lists all problems at once, so one broken file
    /// does not hide the others.
    #[test]
    fn every_lesson_file_is_valid() {
        let errors: Vec<String> = BUILT_IN
            .iter()
            .filter_map(|(file, source)| parse(source).err().map(|e| format!("{file}: {e}")))
            .chain(
                crate::lesson::GLOSSARY_FILES
                    .iter()
                    .filter_map(|(file, source)| {
                        crate::glossary::parse(source)
                            .err()
                            .map(|e| format!("glossary/{file}: {e}"))
                    }),
            )
            .collect();
        assert!(errors.is_empty(), "invalid files:\n{}", errors.join("\n"));
    }

    #[test]
    fn built_in_lessons_are_valid() {
        let lessons = catalog();
        assert_eq!(lessons.len(), BUILT_IN.len());
        let mut ids: Vec<_> = lessons.iter().map(|l| l.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), lessons.len(), "lesson ids are unique");
        // ORRESS's default fonts have no glyphs for these; they would show as boxes.
        for (file, source) in BUILT_IN {
            for ch in ['→', '←', '✔', '✓', '●', '○'] {
                assert!(
                    !source.contains(ch),
                    "{file} uses `{ch}`, which the UI font cannot show"
                );
            }
        }
    }

    /// Every spotlight target a lesson names must be one the UI actually marks, or the lesson
    /// points at nothing. The list mirrors the `orress_ui::spotlight::mark` call sites across the
    /// workspace (this crate cannot depend on the view crates, so it is kept here by hand):
    /// - `orress` app: `palette`, `explain_toggle`;
    /// - `orress-academy`: `lesson`, `sim.*`;
    /// - `orress-workspace`: `dock.*`, and `view.<View::name()>` for every document tab;
    /// - `orress-views`: `tree.<View::name()>` in the project tree, plus each tool view's own
    ///   `view.<Name>`.
    #[test]
    fn spotlight_targets_are_marked_somewhere() {
        // `orress_views::View::name()` — marked as `view.<name>` (document tabs) and
        // `tree.<name>` (project tree).
        const DOC_VIEWS: &[&str] = &[
            "Disassembly",
            "Graph",
            "Functions",
            "Info",
            "Hex",
            "Sections",
            "Imports",
            "Strings",
        ];
        const TOOL_VIEWS: &[&str] = &[
            "Archive",
            "Assistant",
            "DebugSource",
            "Debugger",
            "Decompiler",
            "DotNet",
            "Editor",
            "Emulator",
            "Java",
            "Js",
            "Output",
            "Problems",
            "Pyc",
            "Sandbox",
            "Script",
            "Shellcode",
            "Terminal",
            "Triage",
            "Wasm",
            "Yara",
        ];
        const OTHER: &[&str] = &[
            "palette",
            "explain_toggle",
            "lesson",
            "sim.step",
            "sim.run",
            "sim.code",
            "sim.registers",
            "sim.flags",
            "sim.stack",
            "dock.center",
            "dock.left",
            "dock.right",
            "dock.bottom",
        ];
        let mut known: Vec<String> = OTHER.iter().map(|s| s.to_string()).collect();
        for v in DOC_VIEWS {
            known.push(format!("view.{v}"));
            known.push(format!("tree.{v}"));
        }
        known.extend(TOOL_VIEWS.iter().map(|v| format!("view.{v}")));
        // The three named in the audit must be among them.
        for must in ["view.Disassembly", "view.Info", "view.Strings"] {
            assert!(known.iter().any(|k| k == must));
        }

        for lesson in catalog() {
            for step in &lesson.steps {
                if let Some(target) = &step.spotlight {
                    assert!(
                        known.iter().any(|k| k == target),
                        "lesson `{}` step `{}` spotlights `{target}`, which no UI element marks",
                        lesson.id,
                        step.title
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_bad_lessons() {
        let bad = r#"
            id = "x"
            level = 0
            order = 1
            title = "t"
            summary = "s"
            [[steps]]
            title = "q"
            text = "?"
            check = { kind = "choice", options = ["a"], correct = 3 }
        "#;
        assert!(parse(bad).unwrap_err().contains("out of range"));
        assert!(parse("id = 1").is_err());
    }
}
