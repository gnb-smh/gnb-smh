#!/usr/bin/env bash
# Run cargo-mutants and gate CI on its outcome (docs/testing/MUTATION.md).
#
#   scripts/mutants-gate.sh <output-dir> [cargo-mutants arguments...]
#
# Scope, exclusions and the documented equivalent mutants are in
# .cargo/mutants.toml. cargo-mutants exits 3 as soon as any mutant timed out,
# even when others were missed, so its exit code alone cannot separate a
# surviving mutant from one that hangs the test suite. A timeout means the
# tests did not pass (typically the mutant turned a loop into an infinite
# one): the mutant was detected. This gate therefore fails on any missed
# mutant (missed.txt), and on every exit status other than 0 (all caught) and
# 3 (timeouts only); timed-out mutants are listed as a warning.
set -u
out=$1
shift
cargo mutants "$@" -o "$out"
rc=$?
res="$out/mutants.out"
if [ -s "$res/missed.txt" ]; then
    echo "::error::cargo-mutants: surviving (missed) mutants"
    cat "$res/missed.txt"
    exit 1
fi
if [ -s "$res/timeout.txt" ]; then
    echo "::warning::cargo-mutants: mutants detected by timeout (the tests hang)"
    cat "$res/timeout.txt"
fi
case $rc in
    0 | 3) exit 0 ;;
    *)
        echo "::error::cargo-mutants exited with status $rc"
        exit "$rc"
        ;;
esac
