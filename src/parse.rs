//! Parse `adb logcat -v threadtime` lines.
//!
//! Message wrapping for a TUI is intentionally omitted; callers own display layout.

use regex::Regex;
use std::sync::LazyLock;

static MULTIPLE_SPACES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\s+").expect("valid multiple spaces regex"));

static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]*): ?(.*)$",
    )
    .expect("valid threadtime regex")
});

/// One parsed threadtime logcat line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Timestamp as printed by logcat (`MM-DD HH:MM:SS.mmm`).
    pub timestamp: String,
    /// Process id.
    pub pid: u32,
    /// Thread id.
    pub tid: u32,
    /// Priority letter: `V`, `D`, `I`, `W`, `E`, or `F`.
    pub level: char,
    /// Log tag (whitespace-trimmed).
    pub tag: String,
    /// Message body after the tag colon.
    pub message: String,
}

impl LogLine {
    /// Returns true for Error (`E`) and Fatal (`F`) levels.
    pub fn is_error_level(&self) -> bool {
        matches!(self.level, 'E' | 'F')
    }
}

/// Parse a single `adb logcat -v threadtime` line.
///
/// Returns `None` for headers and other non-matching input.
pub(crate) fn parse_threadtime(line: &str) -> Option<LogLine> {
    let captures = LINE.captures(line.trim_end())?;
    let pid = captures.get(2)?.as_str().parse().ok()?;
    let tid = captures.get(3)?.as_str().parse().ok()?;
    let level = captures.get(4)?.as_str().chars().next()?;
    let tag = captures.get(5)?.as_str().trim().to_string();
    let message = MULTIPLE_SPACES
        .replace_all(captures.get(6).map(|m| m.as_str()).unwrap_or_default(), " ")
        .trim()
        .to_string();

    Some(LogLine {
        timestamp: captures.get(1)?.as_str().to_string(),
        pid,
        tid,
        level,
        tag,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard_line() {
        let line = parse_threadtime("03-15 10:23:45.123  1234  5678 I MyTag: Hello world").unwrap();
        assert_eq!(line.timestamp, "03-15 10:23:45.123");
        assert_eq!(line.pid, 1234);
        assert_eq!(line.tid, 5678);
        assert_eq!(line.level, 'I');
        assert_eq!(line.tag, "MyTag");
        assert_eq!(line.message, "Hello world");
    }

    #[test]
    fn parse_error_line() {
        let line =
            parse_threadtime("09-01 17:00:01.456  9999  9999 E AndroidRuntime: FATAL EXCEPTION")
                .unwrap();
        assert_eq!(line.level, 'E');
        assert!(line.is_error_level());
        assert_eq!(line.tag, "AndroidRuntime");
        assert_eq!(line.message, "FATAL EXCEPTION");
    }

    #[test]
    fn skip_unrecognized() {
        assert!(parse_threadtime("--------- beginning of main").is_none());
    }

    #[test]
    fn trims_tag_padding() {
        let line = parse_threadtime(
            "09-02 11:05:45.782  1959  1959 I artd    : GetBestInfo checking vdex",
        )
        .unwrap();
        assert_eq!(line.tag, "artd");
    }
}
