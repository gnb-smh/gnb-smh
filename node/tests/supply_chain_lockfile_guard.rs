//! Supply-chain guards on the workspace Cargo.lock.
//!
//! 1. Audit finding SC3-yamux-dedupe (Bloch, round 2), moved here from the
//!    retired `crates/libp2p-yamux` fork (audit OPS-2): Cargo.lock once carried
//!    yamux 0.12.1 (GHSA-vxx9-2994-q338, remote DoS reachable by any peer)
//!    next to a fixed 0.13.x, and libp2p-yamux 0.47 ran connections on the
//!    0.12 copy as soon as `set_max_num_streams` was called (the node calls
//!    it). libp2p 0.57 brings libp2p-yamux 0.48, whose only backend is
//!    yamux 0.14, so the fork is gone; these tests keep a second or a
//!    pre-0.13.10 yamux, and a dual-backend libp2p-yamux, out of the lock.
//! 2. Audit OPS-2: hickory-proto 0.25.2 (RUSTSEC-2026-0118, RUSTSEC-2026-0119)
//!    was pinned by libp2p 0.56; the ignores in deny.toml and
//!    .cargo/audit.toml were removed with the move to libp2p 0.57. Keep
//!    hickory at a fixed release (>= 0.26.1).
//!
//! Plain string parsing on purpose: a TOML crate here would itself add
//! dependency-graph surface.

use std::path::Path;

struct LockPackage {
    name: String,
    version: String,
    source: String,
    dependencies: Vec<String>,
}

fn lock_packages() -> Vec<LockPackage> {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", lock_path.display()));
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| -> String {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or("")
                .to_string()
        };
        let dependencies = match block.split_once("dependencies = [") {
            Some((_, rest)) => rest
                .split(']')
                .next()
                .unwrap_or("")
                .lines()
                .map(|l| l.trim().trim_end_matches(',').trim_matches('"').to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            None => Vec::new(),
        };
        out.push(LockPackage { name: field("name"), version: field("version"), source: field("source"), dependencies });
    }
    assert!(out.len() > 100, "Cargo.lock parse looks broken: only {} packages found", out.len());
    out
}

fn semver(v: &str) -> (u64, u64, u64) {
    let mut it = v.split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0))
}

fn versions_of(name: &str) -> Vec<String> {
    lock_packages().into_iter().filter(|p| p.name == name).map(|p| p.version).collect()
}

/// GHSA-vxx9-2994-q338: exactly one yamux in the graph, and it is >= 0.13.10.
#[test]
fn exactly_one_yamux_and_it_is_at_least_0_13_10() {
    let yamuxes = versions_of("yamux");
    assert_eq!(
        yamuxes.len(),
        1,
        "Cargo.lock must contain exactly ONE yamux; a second copy re-opens \
         GHSA-vxx9-2994-q338 (a dual-backend libp2p-yamux runs connections on \
         the 0.12 line once any config setter is used). Found: {yamuxes:?}"
    );
    assert!(semver(&yamuxes[0]) >= (0, 13, 10), "yamux {} < 0.13.10 (GHSA-vxx9-2994-q338)", yamuxes[0]);
}

/// libp2p-yamux must be a single-backend release (>= 0.48, registry) that
/// depends on exactly one yamux.
#[test]
fn libp2p_yamux_is_single_backend() {
    let entries: Vec<LockPackage> = lock_packages().into_iter().filter(|p| p.name == "libp2p-yamux").collect();
    assert_eq!(entries.len(), 1, "one libp2p-yamux expected");
    let e = &entries[0];
    assert!(semver(&e.version) >= (0, 48, 0), "libp2p-yamux {} still has the yamux 0.12 backend", e.version);
    assert!(e.source.starts_with("registry+"), "unexpected libp2p-yamux source {:?}", e.source);
    let yamux_deps: Vec<&String> = e.dependencies.iter().filter(|d| d.split(' ').next() == Some("yamux")).collect();
    assert_eq!(yamux_deps.len(), 1, "libp2p-yamux must depend on one yamux: {yamux_deps:?}");
}

/// RUSTSEC-2026-0118 / RUSTSEC-2026-0119: hickory-proto must be >= 0.26.1.
#[test]
fn hickory_is_at_a_fixed_release() {
    for name in ["hickory-proto", "hickory-resolver"] {
        for v in versions_of(name) {
            assert!(semver(&v) >= (0, 26, 1), "{name} {v} is affected by RUSTSEC-2026-0118/0119");
        }
    }
    assert!(!versions_of("hickory-proto").is_empty(), "the guard must see hickory-proto");
}
