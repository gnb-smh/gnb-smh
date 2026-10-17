# Descriptor frontend package

Base `35ccd62`; native `codegen-units=151`, debug information and incremental
compilation disabled; target `/private/tmp/gnb-r5-target-descriptor-frontends`.

Add read-only, node-network-bound `getdescriptorinfo` and `deriveaddresses`
RPC methods, offline CLI public descriptor/pool files, and a JS binding to the
shared Rust public request dispatcher. No storage, signing, consensus,
activation, or wallet backup format changes. Public pool restoration restores
identities only. No secret-key restoration, derivation paths, live balance
index, or policy-tree spendability is implied.

Acceptance: positive old operations remain valid; new entry points first fail
at runtime on unchanged production; both networks and all descriptor kinds
work using one Rust codec; invalid checksum/network/argument variants refuse;
pool file reads are bounded, exports never overwrite existing paths; real CLI
and pinned WASM round trips preserve identities; JS caller `op` cannot redirect
to session operations. Production reversals keep the final tests unchanged.

The core and independent reference packages own all descriptor parsing. This
package does not duplicate that parser. Root owns WASM rebuild and pins and
the full integration gates. Baseline/final results will be recorded in the
package evidence after they actually run.
