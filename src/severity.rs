//! High-severity heuristics for fatal / ANR / native-crash shaped lines.

use crate::content::ContentType;

/// Returns true for fatal, ANR, panic, or native-crash shaped logcat lines.
///
/// Equivalent to matching any [`ContentType`].
pub(crate) fn is_high_severity(level: char, tag: &str, message: &str) -> bool {
    ContentType::Fatal.matches(level, tag, message)
        || ContentType::Anr.matches(level, tag, message)
        || ContentType::Crash.matches(level, tag, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_fatal_level() {
        assert!(is_high_severity('F', "Tag", "something died"));
    }

    #[test]
    fn matches_android_runtime_fatal_exception() {
        assert!(is_high_severity(
            'E',
            "AndroidRuntime",
            "FATAL EXCEPTION: main"
        ));
    }

    #[test]
    fn matches_anr_in_activity_manager() {
        assert!(is_high_severity(
            'E',
            "ActivityManager",
            "ANR in com.example.myapp (com.example.myapp/.MainActivity)"
        ));
    }

    #[test]
    fn rejects_ordinary_error() {
        assert!(!is_high_severity('E', "OkHttp", "unexpected end of stream"));
    }
}
