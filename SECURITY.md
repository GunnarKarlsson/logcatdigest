# Security Policy

## Supported versions

Security fixes are applied to the latest code on `main`. If tagged releases
exist, the most recent release is also considered supported.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report them privately using
[GitHub Security Advisories](https://github.com/GunnarKarlsson/logcatdigest/security/advisories/new):

1. Go to the repository’s **Security** tab.
2. Choose **Advisories** → **New draft security advisory** (or use the link above).
3. Include a clear description, steps to reproduce, affected versions if known,
   and any suggested fix.

We aim to acknowledge reports promptly, typically within a few days. After
triage, we will work with you on a fix and coordinated disclosure when
appropriate.

## Scope notes

This crate redacts log text with best-effort regex before you send a snapshot
elsewhere. Reports related to secret leakage through redaction gaps, reversible
device labels, or unexpected handling of credentials in samples are especially
welcome.

Out of scope: claiming perfect PII removal (documented as best-effort), bugs in
`adb` or OEM logcat itself, and issues in third-party LLM providers you wire up
outside this crate.
