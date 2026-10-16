#!/usr/bin/env bash
# Check that the equivalent-mutant exclusions of .cargo/mutants.toml exclude
# exactly the documented equivalent mutants (docs/testing/MUTATION.md, E1-E5).
#
#   scripts/mutants-equivalent-check.sh
#
# The exclusion patterns match by file, function and operator, which is wider
# than the nine mutants they are meant for: a later edit to one of those
# functions could add a non-equivalent mutant that a pattern silently
# excludes, or move a documented one out of its pattern. This script lists
# the scope (`cargo mutants --list`, nothing is built) with and without the
# block between the "BEGIN/END equivalent mutants" markers, and compares the
# mutants the block removes (names without ":line:column", repeats counted)
# with .cargo/mutants-equivalent.txt. Any difference fails (exit 1).
# Colors are forced off: CI sets CARGO_TERM_COLOR=always, which cargo-mutants
# honours, and ANSI escapes in the names would never match the plain list.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
cfg=.cargo/mutants.toml
expected_file=.cargo/mutants-equivalent.txt
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

sed '/BEGIN equivalent mutants/,/END equivalent mutants/d' "$cfg" > "$tmp/no-equivalent.toml"
if cmp -s "$cfg" "$tmp/no-equivalent.toml"; then
    echo "::error::$cfg has no 'BEGIN/END equivalent mutants' block"
    exit 1
fi

names() { sed -E 's/^([^:]+):[0-9]+:[0-9]+:/\1:/' | LC_ALL=C sort; }
: > "$tmp/excluded"
for pkg in gnb-smh gnb-crypto; do
    cargo mutants -p "$pkg" --list --colors never --config "$tmp/no-equivalent.toml" | names > "$tmp/$pkg.all"
    cargo mutants -p "$pkg" --list --colors never | names > "$tmp/$pkg.kept"
    LC_ALL=C comm -23 "$tmp/$pkg.all" "$tmp/$pkg.kept" >> "$tmp/excluded"
done
LC_ALL=C sort -o "$tmp/excluded" "$tmp/excluded"
grep -v -e '^#' -e '^[[:space:]]*$' "$expected_file" | names > "$tmp/expected"

if ! diff -u --label "$expected_file" --label "excluded by the equivalent-mutant block" \
    "$tmp/expected" "$tmp/excluded"; then
    echo "::error::the equivalent-mutant exclusions of $cfg no longer match $expected_file"
    echo "'+' lines: excluded but not documented as equivalent (a new mutant inside a pattern)."
    echo "'-' lines: documented as equivalent but no longer excluded (a pattern stopped matching)."
    exit 1
fi
echo "equivalent-mutant exclusions: $(wc -l < "$tmp/excluded") mutants, as documented"
