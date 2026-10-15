//! CI workflow triggers (`.github/workflows/`): a scheduled run starts only
//! the jobs it exists for.
//!
//! Integration review of the mutation-testing package (H-mutants): its weekly
//! cron (`41 4 * * 0`) was added to the one `on.schedule` of ci.yml, next to
//! the nightly cron. A cron starts every job of its workflow that has no
//! job-level event filter, and only `fuzz` and `mutants` had one, so every
//! Sunday the whole of CI (python-reference, the release `rust/` tests,
//! workspace-test, consensus-crates, vendored-guards, wasm-reproducible with
//! its wasi-sdk download, clippy, supply-chain, audit-harness) ran a second
//! time on the commit the nightly run had checked an hour earlier. The
//! mutation jobs now live in their own workflow, mutants.yml, with the weekly
//! cron; ci.yml keeps only the nightly one.
//!
//! Plain line parsing of the subset of YAML these files use (block mappings,
//! two-space indentation), like supply_chain_lockfile_guard.rs: no YAML crate
//! in the dependency graph for one test. `load` fails loudly when a file no
//! longer has the expected shape.

use std::path::{Path, PathBuf};

struct Workflow {
    file: String,
    text: String,
    /// Keys of the top-level `on:` mapping (push, pull_request, ...).
    triggers: Vec<String>,
    /// The `cron:` values of `on.schedule`.
    crons: Vec<String>,
    /// Job id and its job-level `if:` condition (None: no filter, the job
    /// runs on every event of the workflow, every cron included).
    jobs: Vec<(String, Option<String>)>,
}

fn workflows_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows")
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn is_blank_or_comment(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// The lines of the top-level mapping entry `key:` (up to the next line at
/// column 0 that is not blank or a comment).
fn top_level_block<'a>(lines: &[&'a str], key: &str) -> Option<Vec<&'a str>> {
    let start = lines.iter().position(|l| l.trim_end() == format!("{key}:"))?;
    Some(
        lines[start + 1..]
            .iter()
            .take_while(|l| is_blank_or_comment(l) || indent(l) > 0)
            .copied()
            .collect(),
    )
}

/// `name:` (optionally followed by a comment) at exactly `depth` spaces.
fn mapping_key(line: &str, depth: usize) -> Option<String> {
    if is_blank_or_comment(line) || indent(line) != depth {
        return None;
    }
    let t = line.trim();
    let (key, rest) = t.split_once(':')?;
    let rest = rest.trim();
    if key.starts_with('-') || !(rest.is_empty() || rest.starts_with('#')) {
        return None;
    }
    Some(key.to_string())
}

/// The first single- or double-quoted string of `s`.
fn quoted(s: &str) -> Option<String> {
    let start = s.find(['"', '\''])?;
    let q = &s[start..start + 1];
    let rest = &s[start + 1..];
    Some(rest[..rest.find(q)?].to_string())
}

fn load(name: &str) -> Workflow {
    let path = workflows_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let lines: Vec<&str> = text.lines().collect();

    // The block form, or inline (`on: push`, `on: [push, pull_request]`),
    // which cannot carry a schedule.
    let inline_on = lines.iter().find_map(|l| l.strip_prefix("on:")).map(|v| v.split('#').next().unwrap_or("").trim());
    let (triggers, crons): (Vec<String>, Vec<String>) = match inline_on {
        Some(v) if !v.is_empty() => {
            let triggers = v
                .split(|c: char| c == '[' || c == ']' || c == ',' || c.is_whitespace())
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect();
            (triggers, Vec::new())
        }
        _ => {
            let on = top_level_block(&lines, "on").unwrap_or_else(|| panic!("{name}: no top-level `on:` entry"));
            let triggers = on.iter().filter_map(|l| mapping_key(l, 2)).collect();
            let crons = on
                .iter()
                .filter_map(|l| l.trim().strip_prefix("- cron:"))
                .map(|v| quoted(v).unwrap_or_else(|| panic!("{name}: unquoted cron value {v:?}")))
                .collect();
            (triggers, crons)
        }
    };

    let job_lines = top_level_block(&lines, "jobs").unwrap_or_else(|| panic!("{name}: no top-level `jobs:` mapping"));
    let mut jobs: Vec<(String, Option<String>)> = Vec::new();
    for l in job_lines {
        if let Some(id) = mapping_key(l, 2) {
            jobs.push((id, None));
        } else if indent(l) == 4 {
            if let (Some(cond), Some(job)) = (l.trim().strip_prefix("if:"), jobs.last_mut()) {
                job.1.get_or_insert_with(|| cond.trim().to_string());
            }
        }
    }
    assert!(!triggers.is_empty(), "{name}: parsed no trigger");
    assert!(!jobs.is_empty(), "{name}: parsed no job");
    Workflow { file: name.to_string(), text, triggers, crons, jobs }
}

fn all_workflows() -> Vec<Workflow> {
    let mut names: Vec<String> = std::fs::read_dir(workflows_dir())
        .expect("read .github/workflows")
        .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    names.sort();
    names.iter().map(|n| load(n)).collect()
}

fn job_if<'a>(w: &'a Workflow, job: &str) -> Option<&'a str> {
    w.jobs
        .iter()
        .find(|(id, _)| id == job)
        .unwrap_or_else(|| panic!("{}: no job `{job}`", w.file))
        .1
        .as_deref()
}

/// The parser sees what GitHub sees in ci.yml (guards the guard).
#[test]
fn parser_reads_the_ci_workflow() {
    let ci = load("ci.yml");
    assert_eq!(ci.triggers, ["push", "pull_request", "schedule", "workflow_dispatch"]);
    for job in ["python-reference", "workspace-test", "consensus-crates", "wasm-reproducible", "clippy", "fuzz"] {
        assert!(ci.jobs.iter().any(|(id, _)| id == job), "ci.yml: job `{job}` not parsed: {:?}", ci.jobs);
    }
    assert_eq!(job_if(&ci, "workspace-test"), None);
    assert!(job_if(&ci, "fuzz").is_some(), "ci.yml: the fuzz job's `if:` not parsed");
}

/// At most one cron per workflow file. Each cron starts every job of its
/// workflow that has no event filter, so a second cron re-runs all of them on
/// the same commit (the weekly mutation cron did this to the whole of CI). A
/// schedule with another purpose gets a workflow of its own.
#[test]
fn every_workflow_has_at_most_one_cron() {
    for w in all_workflows() {
        let unfiltered: Vec<&str> =
            w.jobs.iter().filter(|(_, cond)| cond.is_none()).map(|(id, _)| id.as_str()).collect();
        assert!(
            w.crons.len() <= 1,
            "{}: {} crons {:?}; each one starts every job without an event filter, so these \
             run once per cron: {unfiltered:?}. Put the second schedule in a workflow of its own.",
            w.file,
            w.crons.len(),
            w.crons
        );
    }
}

/// ci.yml: only the nightly cron, and no mutation job (they would run on every
/// push, every pull request and every nightly run).
#[test]
fn ci_schedule_is_the_nightly_run_only() {
    let ci = load("ci.yml");
    assert_eq!(ci.crons, ["17 3 * * *"], "ci.yml schedule");
    let mutation_jobs: Vec<&str> =
        ci.jobs.iter().map(|(id, _)| id.as_str()).filter(|id| id.contains("mutants")).collect();
    assert!(mutation_jobs.is_empty(), "ci.yml runs mutation jobs {mutation_jobs:?}; they belong in mutants.yml");
    for tool in ["cargo-mutants", "mutants-gate.sh", "mutants-equivalent-check.sh"] {
        assert!(!ci.text.contains(tool), "ci.yml mentions {tool}; mutation testing belongs in mutants.yml");
    }
}

/// mutants.yml: the full campaign weekly and on demand, the diff run on pull
/// requests, nothing on push; each job filtered to its own events.
#[test]
fn mutation_workflow_runs_weekly_on_demand_and_on_pull_requests() {
    let m = load("mutants.yml");
    assert_eq!(m.triggers, ["pull_request", "schedule", "workflow_dispatch"], "mutants.yml triggers");
    assert_eq!(m.crons, ["41 4 * * 0"], "mutants.yml schedule (weekly, Sunday)");
    let ids: Vec<&str> = m.jobs.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["mutants", "mutants-diff"], "mutants.yml jobs");
    assert_eq!(
        job_if(&m, "mutants"),
        Some("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"),
        "the full campaign must not run on pull requests"
    );
    assert_eq!(
        job_if(&m, "mutants-diff"),
        Some("github.event_name == 'pull_request'"),
        "the diff run must not run on the schedule"
    );
    assert!(m.text.contains("tool: cargo-mutants@27.1.0"), "cargo-mutants pin (docs/testing/MUTATION.md)");
}

/// A filter on `github.event.schedule` must name a cron of its own workflow;
/// a stale value silently stops the job from ever running on the schedule.
#[test]
fn every_schedule_filter_names_a_cron_of_its_workflow() {
    for w in all_workflows() {
        for (i, _) in w.text.match_indices("github.event.schedule") {
            let rest = &w.text[i + "github.event.schedule".len()..];
            let line = rest.lines().next().unwrap_or("");
            let value = quoted(line)
                .unwrap_or_else(|| panic!("{}: github.event.schedule compared with no quoted cron: {line:?}", w.file));
            assert!(
                w.crons.contains(&value),
                "{}: filter on github.event.schedule == {value:?}, but the workflow's crons are {:?}",
                w.file,
                w.crons
            );
        }
    }
}
