//! Audit POW-9 (residual): the reference crate's release profile must trap
//! integer overflow, like the consensus workspace's (root `Cargo.toml`): a
//! consensus computation must fail closed identically in every profile,
//! never wrap in release and panic in debug.

/// The profile this test binary was built with traps overflow. CI runs this
/// crate's tests with `cargo test --release`, so this is the release check
/// there and the dev check locally.
#[test]
fn integer_overflow_panics_in_this_profile() {
    let r = std::panic::catch_unwind(|| std::hint::black_box(u32::MAX) + std::hint::black_box(1u32));
    assert!(r.is_err(), "overflow-checks are off in this build profile");
}

/// `[profile.release]` of this crate's manifest sets `overflow-checks = true`
/// (a dev build cannot observe the release profile at run time).
#[test]
fn release_profile_sets_overflow_checks() {
    let manifest = include_str!("../Cargo.toml");
    let mut in_release = false;
    let mut found = false;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_release = line == "[profile.release]";
            continue;
        }
        if in_release {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "overflow-checks" {
                    found = v.trim() == "true";
                }
            }
        }
    }
    assert!(found, "rust/Cargo.toml [profile.release] must set overflow-checks = true");
}
