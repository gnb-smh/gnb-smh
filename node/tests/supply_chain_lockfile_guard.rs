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
    let out = parse_lock(&lock);
    assert!(out.len() > 100, "Cargo.lock parse looks broken: only {} packages found", out.len());
    out
}

fn parse_lock(lock: &str) -> Vec<LockPackage> {
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

// ── Audit CRY-6: crates removed from the build stay removed ──────────────────

/// `blst` and `secp256k1` were declared by the node, used by no source file,
/// and compiled their C/assembly into every build; they were removed, but
/// nothing failed if they came back (directly or through a new dependency).
/// deny.toml bans them for `cargo deny`; this guard checks the same in
/// `cargo test`.
const REMOVED_CRATES: &[&str] = &["blst", "secp256k1", "secp256k1-sys"];

/// The removed crates (name and version) among a lockfile's packages.
fn removed_crates_in(packages: &[LockPackage]) -> Vec<String> {
    packages
        .iter()
        .filter(|p| REMOVED_CRATES.contains(&p.name.as_str()))
        .map(|p| format!("{} {}", p.name, p.version))
        .collect()
}

/// Every lockfile of the repository's GnB builds: the workspace, and the
/// separate `rust/` and `node/fuzz/` ones when present. (The rust-bitcoin
/// oracle of `audit/consistency` uses secp256k1 on purpose; it is not a GnB
/// build.)
#[test]
fn removed_crypto_crates_stay_out_of_every_lockfile() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for rel in ["Cargo.lock", "rust/Cargo.lock", "node/fuzz/Cargo.lock"] {
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            assert_ne!(rel, "Cargo.lock", "the workspace Cargo.lock must exist");
            continue;
        };
        let packages = parse_lock(&text);
        assert!(!packages.is_empty(), "{rel}: the parse found no packages");
        let found = removed_crates_in(&packages);
        assert!(found.is_empty(), "{rel} contains crates removed by audit CRY-6: {found:?}");
    }
}

/// The guard itself: a lockfile that re-adds any removed crate is caught.
#[test]
fn the_cry6_guard_catches_a_re_added_crate() {
    for name in REMOVED_CRATES {
        let lock = format!(
            "version = 4\n\n[[package]]\nname = \"gnb\"\nversion = \"0.1.0\"\ndependencies = [\n \"{name}\",\n]\n\n\
             [[package]]\nname = \"{name}\"\nversion = \"0.30.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        );
        assert_eq!(removed_crates_in(&parse_lock(&lock)), [format!("{name} 0.30.0")]);
    }
}

/// deny.toml keeps the matching `[bans] deny` entries, so `cargo deny`
/// fails on a re-add, also through a new transitive dependency.
#[test]
fn deny_toml_bans_the_removed_crates() {
    let deny = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../deny.toml"))
        .expect("read deny.toml");
    let bans = deny.split_once("\n[bans]").expect("deny.toml has a [bans] table").1;
    let bans = bans.split("\n[").next().unwrap_or("");
    for name in REMOVED_CRATES {
        assert!(
            bans.contains(&format!("{{ crate = \"{name}\",")),
            "deny.toml [bans] must deny {name} (audit CRY-6)"
        );
    }
}

/// Audit OPS-2: cargo-deny checks the graph with every feature enabled (an
/// optional dependency of a documented build, e.g. `sev-snp`, is held to the
/// license policy), and CI pins the cargo-deny and cargo-audit releases.
#[test]
fn cargo_deny_covers_every_feature_and_ci_pins_the_tools() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let deny = std::fs::read_to_string(root.join("deny.toml")).expect("read deny.toml");
    let graph = deny.split_once("\n[graph]\n").expect("deny.toml has a [graph] table").1;
    let graph = graph.split("\n[").next().unwrap_or("");
    assert!(graph.lines().any(|l| l.trim() == "all-features = true"), "deny.toml [graph] all-features = true");
    let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("read ci.yml");
    let tools = ci
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("tool:") && l.contains("cargo-deny"))
        .expect("ci.yml installs cargo-deny");
    for tool in ["cargo-deny@", "cargo-audit@"] {
        let at = tools.find(tool).unwrap_or_else(|| panic!("ci.yml must pin {tool}<version>: {tools}"));
        let version = tools[at + tool.len()..].split(',').next().unwrap_or("");
        assert!(
            version.split('.').count() == 3 && version.split('.').all(|p| p.parse::<u32>().is_ok()),
            "{tool} must be pinned to an exact x.y.z release: {tools}"
        );
    }
}
