dev:

Before I publish the crate, if I have the crate project dir at same level as dashboard, how do I test it with the dashboard logic locally

grok:

Confirming the dashboard workspace layout so the path-dep advice matches the repo.Keep `logcat-digest` as its own repo. Point the dashboard at it with a **path dependency**. Do not add it to the dashboard workspace `members` list.

```
parent/
├── android-dashboard/          # existing workspace
│   ├── Cargo.toml
│   └── crates/
│       ├── adb-client/
│       ├── ai-insight/         # this crate should depend on logcat-digest
│       └── android-dashboard/
└── logcat-digest/              # new crate
    └── Cargo.toml
```

## 1. Depend from `ai-insight`

In `android-dashboard/Cargo.toml` (workspace root):

```toml
[workspace.dependencies]
logcat-digest = { path = "../logcat-digest" }
```

In `android-dashboard/crates/ai-insight/Cargo.toml`:

```toml
[dependencies]
logcat-digest.workspace = true
```

Only `ai-insight` needs the dep. The GUI crate already talks to `ai-insight`.

## 2. Swap internals, keep the HUD API

Replace local `fingerprint` / `event` / `reduce` with re-exports or thin wrappers so `spawn_insight` still works:

```rust
// crates/ai-insight/src/lib.rs
pub use logcat_digest::{
    build_snapshot, digest_threadtime, fingerprint, generate_device_label, redact,
    Snapshot, SnapshotOpts,
};
```

Map dashboard `LogEntry` / `InsightLine` into `logcat_digest::LogLine` at the boundary (timestamp string + pid/level/tag/message). Keep `Instant`, channels, cooldown, and `ureq` in `ai-insight`.

## 3. Run it

From the dashboard repo:

```bash
cargo test -p ai-insight
cargo test -p android-dashboard
cargo run -p android-dashboard
```

Cargo builds `../logcat-digest` from source every time. Edits in the sibling dir show up on the next build. No publish needed.

From the crate repo, keep its own tests too:

```bash
cd ../logcat-digest
cargo test
cargo run --example snapshot
```

## 4. After publish

Change only the workspace pin:

```toml
[workspace.dependencies]
logcat-digest = "0.1.0"
```

To keep hacking on a local checkout after publish:

```toml
[workspace.dependencies]
logcat-digest = "0.1.0"

[patch.crates-io]
logcat-digest = { path = "../logcat-digest" }
```

`[patch]` overrides crates.io for the whole workspace. Remove it when you want the published version.

## Don’t

- Don’t put `logcat-digest` in `workspace.members` unless you move the crate *into* the dashboard repo.
- Don’t add the path dep to `android-dashboard` the GUI crate; that pulls digest types into UI code.
- Don’t mix `version` and `path` on the same dep until it is published (`logcat-digest = { version = "0.1.0", path = "../logcat-digest" }` is the later “still local but versioned” form).