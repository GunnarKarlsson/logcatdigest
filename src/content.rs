//! Public filter enums: content type and log priority level.

/// Shape of log content a caller may request in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// Fatal exceptions / fatal signals / Fatal priority.
    Fatal,
    /// Application Not Responding.
    Anr,
    /// Native or runtime crash-shaped lines (tombstone, libc, panic, etc.).
    Crash,
}

impl ContentType {
    /// True when this content type matches the given level, tag, and message text.
    ///
    /// Message matching is ASCII case-insensitive for the built-in needles.
    pub fn matches(self, level: char, tag: &str, message: &str) -> bool {
        let lower = message.to_ascii_lowercase();
        match self {
            ContentType::Fatal => {
                level == 'F' || lower.contains("fatal exception") || lower.contains("fatal signal")
            }
            ContentType::Anr => lower.contains("anr in"),
            ContentType::Crash => {
                matches!(tag, "AndroidRuntime" | "DEBUG" | "libc")
                    || lower.contains("tombstone")
                    || lower.contains("checkjni")
                    || lower.contains("panic")
            }
        }
    }
}

/// Android logcat priority letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// `V`
    Verbose,
    /// `D`
    Debug,
    /// `I`
    Info,
    /// `W`
    Warn,
    /// `E`
    Error,
    /// `F`
    Fatal,
}

impl LogLevel {
    /// Priority letter used in threadtime lines and snapshot JSON.
    pub fn as_char(self) -> char {
        match self {
            LogLevel::Verbose => 'V',
            LogLevel::Debug => 'D',
            LogLevel::Info => 'I',
            LogLevel::Warn => 'W',
            LogLevel::Error => 'E',
            LogLevel::Fatal => 'F',
        }
    }

    /// Static label for snapshot `levels` field.
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Verbose => "V",
            LogLevel::Debug => "D",
            LogLevel::Info => "I",
            LogLevel::Warn => "W",
            LogLevel::Error => "E",
            LogLevel::Fatal => "F",
        }
    }

    /// Parse a priority letter into a level.
    pub fn from_char(c: char) -> Option<Self> {
        Some(match c {
            'V' | 'v' => LogLevel::Verbose,
            'D' | 'd' => LogLevel::Debug,
            'I' | 'i' => LogLevel::Info,
            'W' | 'w' => LogLevel::Warn,
            'E' | 'e' => LogLevel::Error,
            'F' | 'f' => LogLevel::Fatal,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_fatal_and_anr() {
        assert!(ContentType::Fatal.matches('F', "Tag", "x"));
        assert!(ContentType::Fatal.matches('E', "T", "FATAL EXCEPTION: main"));
        assert!(ContentType::Anr.matches('E', "ActivityManager", "ANR in com.app"));
        assert!(!ContentType::Anr.matches('E', "OkHttp", "timeout"));
    }

    #[test]
    fn content_type_crash() {
        assert!(ContentType::Crash.matches('E', "AndroidRuntime", "boom"));
        assert!(ContentType::Crash.matches('E', "System", "tombstone written"));
        assert!(!ContentType::Crash.matches('E', "OkHttp", "stream reset"));
    }

    #[test]
    fn log_level_roundtrip() {
        for level in [
            LogLevel::Verbose,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
            LogLevel::Fatal,
        ] {
            assert_eq!(LogLevel::from_char(level.as_char()), Some(level));
        }
    }
}
