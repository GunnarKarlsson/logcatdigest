//! Noise-stable fingerprints and best-effort secret redaction.

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::ops::Deref;
use std::sync::LazyLock;

/// Noise that changes between copies of the same bug (hex, paths, numbers).
static NOISE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
            0x[0-9a-fA-F]+
          | /[^\s]+
          | \b\d+\b
        ",
    )
    .expect("valid noise regex")
});

/// Secrets and real-world identifiers (MAC, Bearer, JWT-like, email, assignments, IPv4, long digits).
static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
            (?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}
          | Bearer\s+\S+
          | eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+
          | [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}
          | (?i:\b(?:password|passwd|pwd|token|api[_-]?key|authorization)\s*[=:]\s*\S+)
          | \b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b
          | \b\d{10,15}\b
        ",
    )
    .expect("valid secret regex")
});

const DEVICE_LABEL_HASH_LEN: usize = 8;
const FINGERPRINT_HEX_LEN: usize = 16;

/// Non-reversible device id: `{sanitized_model}:{sha256(serial)[..8]}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceLabel(String);

impl DeviceLabel {
    /// Build a stable, non-reversible label from model name and device serial.
    pub fn new(model: &str, serial: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(serial.as_bytes());
        let hex = format!("{:x}", hasher.finalize());
        let model: String = model
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        Self(format!("{model}:{}", &hex[..DEVICE_LABEL_HASH_LEN]))
    }
}

impl From<(&str, &str)> for DeviceLabel {
    fn from((model, serial): (&str, &str)) -> Self {
        Self::new(model, serial)
    }
}

impl Deref for DeviceLabel {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for DeviceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl AsRef<str> for DeviceLabel {
    fn as_ref(&self) -> &str {
        self
    }
}

/// Human-readable Android device model (e.g. `Pixel 8`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DeviceModel(String);

impl DeviceModel {
    /// Wrap a human-readable model string.
    pub fn new(model: impl Into<String>) -> Self {
        Self(model.into())
    }
}

impl Deref for DeviceModel {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for DeviceModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl AsRef<str> for DeviceModel {
    fn as_ref(&self) -> &str {
        self
    }
}

impl From<&str> for DeviceModel {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for DeviceModel {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Hex fingerprint of length 16 from tag + noise-stripped message.
pub(crate) fn fingerprint(tag: &str, message: &str) -> String {
    let collapsed = NOISE_RE.replace_all(message, "#");
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update(b"|");
    hasher.update(collapsed.as_bytes());
    format!("{:x}", hasher.finalize())[..FINGERPRINT_HEX_LEN].to_string()
}

/// Best-effort redaction of secrets and real-world identifiers.
///
/// Replaces MACs, Bearer tokens, JWT-like blobs, emails, `password=`/`token=`/
/// `api_key=`/`authorization:` assignments, IPv4 addresses, and 10–15 digit runs.
/// Leaves paths and short numbers unchanged. Not a guarantee of PII safety.
pub(crate) fn redact(message: &str) -> String {
    SECRET_RE.replace_all(message, "#").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_numbers_and_paths() {
        let left = fingerprint("OkHttp", "failed 3 times at /data/app/foo");
        let right = fingerprint("OkHttp", "failed 9 times at /data/app/bar");
        assert_eq!(left, right);
    }

    #[test]
    fn different_tags_differ() {
        assert_ne!(fingerprint("OkHttp", "boom"), fingerprint("System", "boom"));
    }

    #[test]
    fn redact_email_bearer_and_mac() {
        let text = redact("user a@b.com Bearer abc.def aa:bb:cc:dd:ee:ff");
        assert!(!text.contains("a@b.com"));
        assert!(!text.contains("abc.def"));
        assert!(!text.contains("aa:bb:cc:dd:ee:ff"));
        assert!(text.contains('#'));
    }

    #[test]
    fn redact_keeps_status_codes_and_paths() {
        let text = redact("HTTP 500 from /data/user/0/com.app/cache");
        assert!(text.contains("500"));
        assert!(text.contains("/data/user/0/com.app/cache"));
    }

    #[test]
    fn redact_assignment_secrets() {
        let text = redact(
            "password=s3cret token=abc123 api_key=key-99 api-key=key-88 authorization: Bearer.xyz",
        );
        assert!(!text.contains("s3cret"));
        assert!(!text.contains("abc123"));
        assert!(!text.contains("key-99"));
        assert!(!text.contains("key-88"));
        assert!(!text.contains("Bearer.xyz"));
        assert!(text.contains('#'));
    }

    #[test]
    fn redact_ipv4() {
        let text = redact("connect failed to 10.0.0.1 port 443");
        assert!(!text.contains("10.0.0.1"));
        assert!(text.contains("port 443"));
        assert!(text.contains('#'));
    }

    #[test]
    fn redact_long_digit_runs() {
        let text = redact("call 5551234567 or pid 12345 code 500");
        assert!(!text.contains("5551234567"));
        assert!(text.contains("12345"));
        assert!(text.contains("500"));
        assert!(text.contains('#'));
    }

    #[test]
    fn device_label_hides_serial() {
        let label = DeviceLabel::new("Pixel 8", "emulator-5554");
        assert!(label.starts_with("Pixel_8:"));
        assert!(!label.contains("emulator-5554"));
        assert_eq!(label, DeviceLabel::new("Pixel 8", "emulator-5554"));
        assert_ne!(label, DeviceLabel::new("Pixel 8", "emulator-5556"));
    }
}
