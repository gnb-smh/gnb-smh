#!/usr/bin/env bash
# Run cargo-mutants and gate CI on its outcome (docs/testing/MUTATION.md).
#
#   scripts/mutants-gate.sh <output-dir> [cargo-mutants arguments...]
#
# Scope, exclusions and the documented equivalent mutants are in
# .cargo/mutants.toml. cargo-mutants exits 3 as soon as any mutant timed out,
# even when others were missed, so its exit code alone cannot separate a
# surviving mutant from one that hangs the test suite. This gate therefore
# fails (exit 1):
#   - on any missed (surviving) mutant (missed.txt);
#   - on any timed-out mutant that is not in .cargo/mutants-timeouts.txt
#     (the known hangs, each explained in MUTATION.md), compared by mutant
#     name without ":line:column" and counting repeats: a mutant that merely
#     slows the tests past the timeout is not proof that a test detects it;
#   - and on every cargo-mutants exit status other than 0 (all caught) and 3
#     (timeouts).
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
allow="$root/.cargo/mutants-timeouts.txt"
out=$1
shift

# Each parallel build copy (-j N) must build into its own <copy>/target. A
# CARGO_TARGET_DIR in the environment makes every copy share one target
# directory, where a job can run the test binary built from another job's
# mutant and record a wrong outcome.
unset CARGO_TARGET_DIR

cargo mutants "$@" -o "$out"
rc=$?
res="$out/mutants.out"
if [ -s "$res/missed.txt" ]; then
    echo "::error::cargo-mutants: surviving (missed) mutants"
    cat "$res/missed.txt"
    exit 1
fi
if [ -s "$res/timeout.txt" ]; then
    names() { sed -E 's/^([^:]+):[0-9]+:[0-9]+:/\1:/' | LC_ALL=C sort; }
    # Multiset difference: timeouts beyond what the allow-list permits.
    unexpected=$(LC_ALL=C comm -23 <(names < "$res/timeout.txt") \
        <(grep -v -e '^#' -e '^[[:space:]]*$' "$allow" | names))
    if [ -n "$unexpected" ]; then
        echo "::error::cargo-mutants: mutants timed out that are not known hangs (.cargo/mutants-timeouts.txt)"
        echo "$unexpected"
        exit 1
    fi
    echo "::warning::cargo-mutants: known hangs, detected by timeout (.cargo/mutants-timeouts.txt)"
    cat "$res/timeout.txt"
fi
case $rc in
    0 | 3) exit 0 ;;
    *)
        echo "::error::cargo-mutants exited with status $rc"
        exit "$rc"
        ;;
esac
