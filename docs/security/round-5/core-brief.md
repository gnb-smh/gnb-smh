# R5 public descriptor core brief

Owner: core package. Base `35ccd62`; native codegen units 139; isolated target
`/private/tmp/gnb-r5-target-descriptor-core`; debug=0, incremental=0, jobs=2.

Contract: `descriptor-contract.md`. Deliver a bounded static public descriptor
codec, public pool codec, shared JSON operation, WASM dispatcher and Rust JSONL
oracle. Preserve existing scripts and exact key bytes; no consensus changes,
private material, derivation, signing or session mutation. Tree output always
reports its activation prerequisite. PF-4 remains outside this package.

Reproduce missing capability first through the existing WASM Rust dispatcher:
legacy normalization passes; descriptor creation and pool restoration assert
success and fail at runtime on the unknown operation. Only after recording that
run implement production. Final tests cover both networks, all kinds, canonical
grammar, BIP380 checksum, original script identities, pool bounds, unknown and
duplicate JSON fields, and the public operation boundary. Run production
reversals with final tests unchanged, restore, then test again.

Run `gnb-crypto` separately from `gnb`. Root owns final actual WASM builds,
pins, integration and independent review. No excluded PoWit/R7/witness work.
This is a partial technology feature, not a numerical score or superiority claim.
