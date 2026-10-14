//! Learner progress: completed steps and lessons, XP, badges and the daily streak.
//! Saved as `academy.json` in the config folder.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const XP_PER_STEP: u32 = 10;
pub const XP_PER_LESSON: u32 = 50;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Progress {
    /// Completed step indices per lesson id.
    pub steps: BTreeMap<String, BTreeSet<usize>>,
    pub lessons: BTreeSet<String>,
    pub xp: u32,
    pub badges: BTreeSet<String>,
    /// Hints revealed per lesson id.
    pub hints_used: BTreeMap<String, u32>,
    /// Days (since 1970) on which a step was completed, for the streak.
    pub active_days: BTreeSet<u32>,
    /// Lesson to continue with.
    pub current: Option<String>,
}

impl Progress {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn step_done(&self, lesson: &str, step: usize) -> bool {
        self.steps.get(lesson).is_some_and(|s| s.contains(&step))
    }

    /// Marks a step complete. Returns the XP earned (0 if it was already done).
    pub fn complete_step(&mut self, lesson: &str, step: usize, today: u32) -> u32 {
        if !self
            .steps
            .entry(lesson.to_owned())
            .or_default()
            .insert(step)
        {
            return 0;
        }
        self.active_days.insert(today);
        self.xp += XP_PER_STEP;
        XP_PER_STEP
    }

    /// Marks a lesson complete. Returns the XP earned (0 if it was already done).
    pub fn complete_lesson(&mut self, lesson: &str) -> u32 {
        if !self.lessons.insert(lesson.to_owned()) {
            return 0;
        }
        self.xp += XP_PER_LESSON;
        XP_PER_LESSON
    }

    /// Consecutive days up to `today` with at least one completed step.
    pub fn streak(&self, today: u32) -> u32 {
        let mut day = today;
        // A streak survives until the end of the next day.
        if !self.active_days.contains(&day) {
            day = day.saturating_sub(1);
        }
        let mut n = 0;
        while self.active_days.contains(&day) {
            n += 1;
            if day == 0 {
                break;
            }
            day -= 1;
        }
        n
    }

    /// Level title for an XP amount, to make progress visible.
    pub fn rank(&self) -> &'static str {
        match self.xp {
            0..100 => "Newcomer",
            100..300 => "Bit Flipper",
            300..600 => "Byte Reader",
            600..1000 => "Assembly Apprentice",
            1000..2000 => "Crackme Cracker",
            _ => "Reverse Engineer",
        }
    }
}

pub fn today() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 86_400) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xp_and_streak() {
        let mut p = Progress::default();
        assert_eq!(p.complete_step("a", 0, 100), XP_PER_STEP);
        assert_eq!(p.complete_step("a", 0, 100), 0, "no double XP");
        p.complete_step("a", 1, 101);
        p.complete_step("a", 2, 102);
        assert_eq!(p.streak(102), 3);
        assert_eq!(p.streak(103), 3, "still alive the next day");
        assert_eq!(p.streak(105), 0);
        assert_eq!(p.complete_lesson("a"), XP_PER_LESSON);
        assert_eq!(p.xp, 3 * XP_PER_STEP + XP_PER_LESSON);
        assert_eq!(p.rank(), "Newcomer");
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join(format!("orress-progress-{}", std::process::id()));
        let path = dir.join("academy.json");
        let mut p = Progress::default();
        p.complete_step("l0", 0, 5);
        p.badges.insert("First steps".into());
        p.save(&path).unwrap();
        assert_eq!(Progress::load(&path), p);
        assert_eq!(
            Progress::load(&dir.join("missing.json")),
            Progress::default()
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
