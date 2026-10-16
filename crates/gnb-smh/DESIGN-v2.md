# GnB-SMH v2 (draft) — SHA-256, ASIC-friendly, Grover-hostile

Status: **draft, not consensus**. Nothing in the node uses it. Adopting it is
a hard fork (new vectors, new difficulty reset, activation height).

Code: `src/v2.rs`. Normative reference: `reference/gnb_smh_v2.py`.
Vectors: `reference/test_vectors_v2.json` (10, log2_n = 4 and 13).

## Goals

| Goal | v1 (live) | v2 draft |
| --- | --- | --- |
| Hash | SHAKE-256 (1 Keccak-f per step) | SHA-256 (1 compression per step) |
| Scratchpad | 64 MiB (DRAM) | 256 KiB (fits on-chip SRAM) |
| Steps per attempt | 1,048,578 | 16,386 |
| Verify, 1 core, no SHA-NI | ~0.53 s (Mac) / 0.61 s (server) | **3.9 ms / 4.9 ms** |
| ASIC | hostile (DRAM-bound) | friendly (SHA core + SRAM) |
| Existing Bitcoin ASICs | no | no (they only run SHA256d of 80 bytes) |

## Algorithm

```
                 header ‖ nonce
                       │
        X0 = SHA256(enc("GNB-SMH-v2/seed") ‖ u8(13) ‖ enc(header) ‖ u64le(nonce))
                       │
 FILL  (sequential)    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ V[0]=X0 ─SHA256(X‖0‖01)→ V[1] ─→ V[2] ─→ … ─→ V[8191] ─→ X     │  256 KiB SRAM
   └──────────────────────────────────────────────────────────────┘  (8192 × 32 B)
                       │
 MIX   (sequential, data-dependent)
   for i in 0..8191:
        j = u64le(X[0..8]) mod 8192        ← address known only after the
        X = SHA256((X ⊕ V[j]) ‖ u32le(i) ‖ 02)  previous hash finishes
                       │
        out = SHA256(enc("GNB-SMH-v2/final") ‖ X)
                       │
              be256(out) < target ?
```

Every inner input is 37 bytes, so each step is exactly one SHA-256
compression: an ASIC pipeline needs one SHA-256 core plus one SRAM port.

## Why it resists a quantum miner better than SHA256d

A quantum miner runs Grover: about √W iterations for a target worth W
attempts, **one after another** (Grover parallelises badly: p machines give
only √p). Each iteration must evaluate the whole PoW as a reversible circuit.

1. **Depth.** One attempt is 16,386 dependent compressions instead of 2
   (SHA256d), about 8,000× deeper. The honest network also pays per attempt,
   so difficulty falls by the same factor; the net effect is that the quantum
   miner needs a clock about √8000 ≈ 90× faster to keep the same position
   against the same classical hardware budget.
2. **QRAM.** Mix reads `V[j]` with `j` computed from the state in
   superposition, so the circuit needs 256 KiB of quantum random-access
   memory (about 2 Mbit addressed coherently). SHA256d needs none. QRAM at
   this scale is far beyond any announced hardware.
3. **Block time.** Grover returns nothing until it finishes. If the network
   finds the block first, the quantum run is wasted.

These are estimates from the structure, not measurements; there is no
quantum hardware to measure on.

## Known weaknesses (open)

- **Time–memory trade-off.** Like scrypt ROMix (and v1), an attacker can
  store every k-th block and recompute the rest, trading SRAM for SHA cores.
  This lowers both the ASIC area and the QRAM a quantum attacker needs.
  Candidates: Balloon hashing or an Argon2-style multi-pass fill.
- **CPU fairness disappears by design.** ASICs will dominate; v2 is only the
  right choice if GnB wants industrial hashrate rather than CPU mining.
- **Not reviewed.** No external review of parameters or domain separation.

## Reproduce

```sh
python3 crates/gnb-smh/reference/gen_vectors_v2.py crates/gnb-smh/reference/test_vectors_v2.json
cargo test --release -p gnb-smh
./target/release/smh-bench v2 13 500     # v2 verification time
./target/release/smh-bench verify 19 5   # v1, for comparison
```
