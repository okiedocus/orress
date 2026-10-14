//! A capped, append-only event log shared between recorder threads and the UI. Besides the
//! retained events it counts every event ever recorded, so a reader can fetch only what is new
//! since its last read ([`EventLog::since`]) even after the oldest entries were dropped — instead
//! of copying the whole (up to tens of thousands of entries) log on every refresh.

/// A capped event log: the retained events plus a running total of all events recorded.
#[derive(Debug)]
pub(crate) struct EventLog<T> {
    events: Vec<T>,
    total: usize,
}

impl<T> Default for EventLog<T> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            total: 0,
        }
    }
}

impl<T: Clone> EventLog<T> {
    /// Appends `ev`; once `cap` events are retained the oldest fifth is dropped first, so the log
    /// can't grow without bound.
    pub(crate) fn push(&mut self, ev: T, cap: usize) {
        if self.events.len() >= cap {
            self.events.drain(0..(cap / 5).max(1));
        }
        self.events.push(ev);
        self.total += 1;
    }

    /// The retained events, oldest first.
    pub(crate) fn events(&self) -> &[T] {
        &self.events
    }

    /// The events recorded after the first `seen` (counting every event ever recorded), and the
    /// new count to pass next time. Events that were already dropped from the log are skipped.
    pub(crate) fn since(&self, seen: usize) -> (Vec<T>, usize) {
        let dropped = self.total - self.events.len();
        let from = seen.saturating_sub(dropped).min(self.events.len());
        (self.events[from..].to_vec(), self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::EventLog;

    #[test]
    fn since_returns_only_new_events_across_drops() {
        let mut log = EventLog::default();
        for i in 0..4 {
            log.push(i, 10);
        }
        let (new, seen) = log.since(0);
        assert_eq!((new, seen), (vec![0, 1, 2, 3], 4));
        log.push(4, 10);
        assert_eq!(log.since(seen), (vec![4], 5));
        assert_eq!(log.since(5), (vec![], 5));
        // Fill past the cap: the oldest are dropped, yet `since` still lines up.
        for i in 5..12 {
            log.push(i, 10);
        }
        assert_eq!(log.events().len(), 10);
        assert_eq!(log.since(5), (vec![5, 6, 7, 8, 9, 10, 11], 12));
        // A reader that fell behind the drop just gets everything retained.
        assert_eq!(log.since(0).0.first(), Some(&2));
    }
}
