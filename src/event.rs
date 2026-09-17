//! Fold time-ordered lines into single-line or multi-line fatal/ANR events.
//!
//! Uses line index (not `Instant`) so offline files and bugreports work.

use crate::fingerprint::redact;
use crate::parse::LogLine;
use crate::severity::is_high_severity;

const MAX_FOLD_LINES: usize = 32;

/// One log line input to the reducer.
#[derive(Debug, Clone)]
pub struct InsightLine {
    pub index: usize,
    pub pid: u32,
    pub level: char,
    pub tag: String,
    pub message: String,
}

impl From<(usize, &LogLine)> for InsightLine {
    fn from((index, line): (usize, &LogLine)) -> Self {
        Self {
            index,
            pid: line.pid,
            level: line.level,
            tag: line.tag.clone(),
            message: line.message.clone(),
        }
    }
}

/// One insight incident: a single error line, or a folded fatal/ANR stack.
#[derive(Debug, Clone)]
pub struct InsightEvent {
    pub index: usize,
    pub pid: u32,
    pub level: char,
    pub tag: String,
    /// First line message; used for fingerprinting.
    pub headline: String,
    /// Redacted sample lines from the event (headline first).
    pub samples: Vec<String>,
}

impl InsightEvent {
    /// Returns true when this event's headline is high severity.
    pub fn is_high_severity(&self) -> bool {
        is_high_severity(self.level, &self.tag, &self.headline)
    }
}

/// Returns true when level/message start a multi-line fatal/ANR event.
pub fn is_stack_head_message(level: char, message: &str) -> bool {
    if level == 'F' {
        return true;
    }
    let message = message.to_ascii_lowercase();
    message.contains("fatal exception")
        || message.contains("anr in")
        || message.contains("fatal signal")
}

/// Folds time-ordered lines into events. Every line is consumed.
pub fn fold_lines_to_events(lines: &[InsightLine]) -> Vec<InsightEvent> {
    let mut events = Vec::new();
    let mut builder: Option<LineStackBuilder> = None;

    for line in lines {
        if let Some(stack) = builder.as_mut() {
            if is_stack_continuation(stack, line) {
                stack.lines.push(line.clone());
                continue;
            }
            events.push(builder.take().expect("stack builder present").into_event());
        }

        if is_stack_head_message(line.level, &line.message) {
            builder = Some(LineStackBuilder::start(line.clone()));
        } else {
            events.push(InsightEvent::from_line(line.clone()));
        }
    }

    if let Some(stack) = builder {
        events.push(stack.into_event());
    }
    events
}

fn is_stack_continuation(builder: &LineStackBuilder, line: &InsightLine) -> bool {
    if line.pid != builder.pid || is_stack_head_message(line.level, &line.message) {
        return false;
    }
    if builder.lines.len() >= MAX_FOLD_LINES {
        return false;
    }

    let msg = line.message.trim_start();
    let lower = msg.to_ascii_lowercase();
    if lower.starts_with("at ")
        || lower.starts_with("caused by:")
        || lower.starts_with("process:")
        || lower.starts_with("pid:")
        || lower.starts_with("reason:")
        || msg.starts_with('\t')
    {
        return true;
    }

    match builder.kind {
        StackKind::Crash => matches!(line.tag.as_str(), "AndroidRuntime" | "DEBUG" | "libc"),
        StackKind::Anr => line.tag == "ActivityManager" || line.tag == builder.tag,
    }
}

#[derive(Clone, Copy)]
enum StackKind {
    Crash,
    Anr,
}

struct LineStackBuilder {
    kind: StackKind,
    pid: u32,
    tag: String,
    level: char,
    index: usize,
    lines: Vec<InsightLine>,
}

impl LineStackBuilder {
    fn start(line: InsightLine) -> Self {
        let lower = line.message.to_ascii_lowercase();
        let kind = if lower.contains("anr in") {
            StackKind::Anr
        } else {
            StackKind::Crash
        };
        Self {
            kind,
            pid: line.pid,
            tag: line.tag.clone(),
            level: line.level,
            index: line.index,
            lines: vec![line],
        }
    }

    fn into_event(self) -> InsightEvent {
        InsightEvent::from_lines(self.tag, self.level, self.pid, self.index, self.lines)
    }
}

impl InsightEvent {
    fn from_line(line: InsightLine) -> Self {
        Self::from_lines(
            line.tag.clone(),
            line.level,
            line.pid,
            line.index,
            vec![line],
        )
    }

    fn from_lines(
        tag: String,
        level: char,
        pid: u32,
        index: usize,
        lines: Vec<InsightLine>,
    ) -> Self {
        let headline = lines.first().map(|l| l.message.clone()).unwrap_or_default();
        let samples: Vec<String> = lines.iter().map(|l| redact(&l.message)).collect();
        Self {
            index,
            level,
            tag,
            pid,
            headline,
            samples,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(index: usize, pid: u32, tag: &str, message: &str) -> InsightLine {
        InsightLine {
            index,
            pid,
            level: 'E',
            tag: tag.to_string(),
            message: message.to_string(),
        }
    }

    #[test]
    fn single_error_is_one_event() {
        let events = fold_lines_to_events(&[line(0, 1, "OkHttp", "boom")]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].headline, "boom");
        assert_eq!(events[0].samples.len(), 1);
    }

    #[test]
    fn fatal_stack_folds_to_one_event() {
        let events = fold_lines_to_events(&[
            line(0, 3178, "AndroidRuntime", "FATAL EXCEPTION: main"),
            line(
                1,
                3178,
                "AndroidRuntime",
                "Process: com.android.settings, PID: 3178",
            ),
            line(
                2,
                3178,
                "AndroidRuntime",
                "android.app.RemoteServiceException$CrashedByAdbException: shell-induced crash",
            ),
            line(
                3,
                3178,
                "AndroidRuntime",
                "at android.app.ActivityThread.throwRemoteServiceException(ActivityThread.java:2257)",
            ),
            line(4, 99, "OkHttp", "other error"),
        ]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].headline, "FATAL EXCEPTION: main");
        assert_eq!(events[0].samples.len(), 4);
        assert!(
            events[0]
                .samples
                .iter()
                .any(|s| s.contains("shell-induced"))
        );
        assert_eq!(events[1].headline, "other error");
    }

    #[test]
    fn anr_head_folds_activity_manager_followups() {
        let events = fold_lines_to_events(&[
            line(
                0,
                14205,
                "ActivityManager",
                "ANR in com.example.myapp (com.example.myapp/.MainActivity)",
            ),
            line(1, 14205, "ActivityManager", "PID: 14205"),
            line(
                2,
                14205,
                "ActivityManager",
                "Reason: Input dispatching timed out",
            ),
            line(3, 1, "OkHttp", "unrelated"),
        ]);
        assert_eq!(events.len(), 2);
        assert!(events[0].headline.contains("ANR in"));
        assert_eq!(events[1].tag, "OkHttp");
    }

    #[test]
    fn different_pid_does_not_fold() {
        let events = fold_lines_to_events(&[
            line(0, 1, "AndroidRuntime", "FATAL EXCEPTION: main"),
            line(1, 2, "AndroidRuntime", "at other.Process.main"),
        ]);
        assert_eq!(events.len(), 2);
    }
}
