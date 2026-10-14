# PoW + PoWit (Proof of Witnesses)

A pure proof-of-work chain (no stake, no appointed validators) in which the
miners who *proved custody of the chain's witness data* over the last week
deterministically form the set that finalizes checkpoints with post-quantum
signatures. Built from three pieces:

| Piece | Code |
| --- | --- |
| Block PoW: GnB-SMH v3 (4 MiB, Argon2d-style fill) | `crates/gnb-smh/src/v3.rs`, `core::pow_algo` |
| Witness shares (custody proof + reward) | `core::witness_share`, `node/src/powit.rs` |
| Witness set, attestations, justification/finality, equivocation, decay | `core::powit` (pure state machine), `node/src/powit.rs` |

## Status

Implemented and consensus from `core::powit_height()`. **Mainnet keeps it
OFF** (`POWIT_HEIGHT_MAINNET = u64::MAX`) until a release fixes the height;
a testnet node sets it with `--testnet --powit-height <h>`.

Implementation choices that refine the design below:

- **Witness set size 64** (not 256): every attestation carries a hybrid
  public key and signature (~8 KiB), so 64 members keep a full round of votes
  under ~0.5 MB per checkpoint.
- **Checkpoint slots.** Slot `c` names the highest selected-chain block with
  height strictly below `c`. Heights along a selected chain can skip, so a
  slot always resolves, identically on every node sharing that chain.
- **Work continuity.** v3 targets are 4x harder than the ASERT schedule and
  each v3 block's chain work is divided by 4, so cumulative work (and
  `MIN_CHAIN_WORK`) stays comparable across the switch.
- **Accountability.** An equivocation bars the key from the witness set and
  from share rewards for `ban_epochs`; burning already-paid share rewards
  (escrow) is not implemented.
- **Witness node.** `--witness-wallet <gnb-cli wallet> --witness-password-file <f>`
  mines shares paying that key (`--share-threads`, default 2) and signs the
  newest checkpoint once it is a member, with a persistent vote record that
  refuses any double or surround vote, across restarts and reorgs.
- **Node finality.** The node never reorganises below the height of the block
  its tip's chain finalized (`finalized_height`), in addition to the depth rule.

Parameters (`core::powit::MAINNET_PARAMS` / `TESTNET_PARAMS`):

| | Mainnet | Testnet |
| --- | --- | --- |
| Epoch | 720 blocks (~6 h) | 20 |
| Checkpoint interval | 60 (~30 min) | 5 |
| Window | 28 epochs (~7 days) | 3 |
| Witnesses | 64 | 64 |
| Attestations / block | 32 | 32 |
| Vote lifetime | 720 blocks | 20 |
| Decay starts after | 4 epochs without finality | 4 |
| Ban | 28 epochs | 3 |


## 1. Block PoW: GnB-SMH v3

```
V[0] = SHAKE256(seed(header, nonce))
pass 0: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ 0),  r = V[i-1] mod i
pass p: V[i] = SHAKE256(V[i-1] ‖ V[r] ‖ i ‖ p),  r = V[i-1] mod N
out  = SHAKE256(DS_FINAL ‖ V[N-1])        N = 2^15 blocks of 128 B (4 MiB), 2 passes
```

| | v1 (live) | v3 draft |
| --- | --- | --- |
| Memory | 64 MiB | 4 MiB |
| Verify (Mac, 1 core) | 527 ms | 90 ms |
| Fill | plain hash chain (linear TMTO) | each block depends on a content-chosen earlier block (cascading TMTO, as Argon2d) |
| Grover | needs 64 MiB QRAM, 1M sequential steps | needs 4 MiB QRAM, 65k steps of 2 permutations; dropping memory to save QRAM cascades |

The hash is replaceable: the same structure with SHA-256 is a one-function
change (see v2). Off-the-shelf Bitcoin ASICs still cannot run it.

## 2. Witness shares (implemented as a draft)

A GnB-SMH proof 16× easier than a block that attests one of the last 16
blocks; every nonce pulls 8 random 64-byte chunks of that block's
transactions (signatures included) into the PoW input. 20% of the subsidy
pays up to 16 shares per block. See `DESIGN-witness-shares.md`.

## 3. The witness set (deterministic, from the DAG)

- Epoch = 720 blocks (~6 h). Window K = 28 epochs (~7 days).
- Weight of a key in epoch e = total work of its shares included in blocks
  of epochs e-K … e-1. Keys are the PQ public keys behind the payout scripts.
- W_e = the 256 heaviest keys (ties by key hash). Every node computes the
  same W_e from the selected chain: no registration, no stake, no vote.

## 4. Checkpoint attestations

- Checkpoint every 60 blocks: the selected-chain block at that blue score.
- Each member of W_e signs `DS ‖ chain_id ‖ e ‖ checkpoint hash ‖ blue score`
  with its hybrid ML-DSA-65 ‖ Falcon-1024 key.
- Attestations are gossiped and included in blocks (inclusion bonus, like shares).
- **Final** when blocks carry attestations worth ≥ 2/3 of W_e's weight.
  Nodes never reorg away a final checkpoint.

## 5. Accountability without stake

Share rewards mature only after K epochs (escrow). Two signatures by one key
for different checkpoints at the same height are an equivocation proof:
any block may include it; the key's escrowed rewards are burned and it is
excluded from W for K epochs.

## 6. Liveness fallback

If no checkpoint finalizes for 1,000 blocks, the chain keeps running as pure
PoW under the depth-finality rule (`CHECKPOINT_DEPTH`) until attestations
resume. Finality can stall; block production cannot.

## 7. Hardening (revision 2)

### 7.1 Two ledgers: available and final ("ebb-and-flow")

Impossibility results bound every design: no permissionless protocol is
both always available and always consistent under network partitions (CAP),
and deterministic agreement needs fewer than 1/3 faulty weight under partial
synchrony (Dwork–Lynch–Stockmeyer). PoW + PoWit therefore keeps **two
ledgers** (Neu–Tas–Tse, 2021):

- **LOG_avail**: the GHOSTDAG order of the PoW DAG. Always grows while
  honest miners hold a hashrate majority, even with most witnesses offline
  or the network partitioned.
- **LOG_fin**: the prefix of LOG_avail up to the last finalized checkpoint.
  Never reverted while < 1/3 of the witness weight is Byzantine, whatever the
  network delays.

LOG_fin is always a prefix of LOG_avail. Users pick their guarantee:
fast/probabilistic (LOG_avail) or deterministic (LOG_fin).

### 7.2 Byzantine generals mapping

| Generals problem | PoW + PoWit |
| --- | --- |
| Generals | Members of the witness set W_e (earned by custody work, not chosen) |
| Messages | Attestations signed with ML-DSA-65 ‖ Falcon-1024 (unforgeable, also against quantum adversaries) |
| Traitors | Any member; tolerated while their weight is < 1/3 of W_e |
| Agreement | Two checkpoints at the same height can never both finalize unless ≥ 1/3 of the weight signed both, and that is provable on chain |
| Sybil generals | Weight is work, so splitting a key into many keys gains nothing |

### 7.3 Vote rule with accountable safety

Each attestation is a link `source → target` between two checkpoints
(source = the latest justified checkpoint the signer knows):

- a checkpoint is **justified** when links from a justified source carry
  ≥ 2/3 of W_e; it is **final** when its direct child checkpoint is justified
  from it;
- **slashable** (escrow burned, key barred for K epochs): two different
  targets at the same height (double vote), or a link that surrounds another
  link by the same key (surround vote).

Theorem (as in Casper's accountable safety): two conflicting final
checkpoints imply that keys holding ≥ 1/3 of W_e broke one of the two rules,
and the evidence is publishable in any block. The voters here are earned by
PoW custody work; there is no stake and no appointed validator.

### 7.4 Agreeing on who the generals are

W_e is computed only from **LOG_fin as of the end of epoch e-2**. Every honest
node therefore derives the same set, even while LOG_avail tips disagree. If
nothing has finalized for two epochs, W_e = W_{e-1}.

### 7.5 Finality liveness: inactivity decay

If no checkpoint finalizes for 4 epochs, the weight of every member whose
attestations are not being included decays by 1/16 per epoch (deterministic,
from included attestations only). Online members regain 2/3 and finality
resumes, so > 1/3 offline or withholding can only delay finality, not stop it.

### 7.6 Fork choice

Heaviest blue-work DAG **among the branches that contain the latest final
checkpoint**. A partitioned side may keep producing blocks (LOG_avail), but
at most one side can finalize, and the other side rejoins it on heal.

### 7.7 Other attacks

- **Selfish mining / withholding**: witness shares pay every 16× easier
  proof, so small miners earn without pools and withheld blocks forfeit
  their share slots.
- **Long-range rewrite**: impossible past LOG_fin for online nodes; new
  nodes start from `MIN_CHAIN_WORK` + the release checkpoint (weak
  subjectivity, as every finality protocol).
- **Bribing witnesses**: the bribe must exceed the 7-day escrow of ≥ 1/3 of
  the weight, and the attack is attributable.
- **Data withholding**: a block whose data no one can sample earns no shares
  and no attestations.

### 7.8 What remains impossible (honest limits)

- A sustained > 2/3 majority of the 7-day witness weight controls LOG_fin.
- A hashrate majority still controls LOG_avail after the last final checkpoint.
- Finality needs partial synchrony: during long partitions, LOG_fin stalls
  (by design it never forks).

## What it buys against a 51% attacker

| Attacker | Bitcoin | PoW + PoWit |
| --- | --- | --- |
| Rents >50% hashrate for hours | Can reorg as deep as its lead allows | Reorgs at most the ~60 blocks after the last final checkpoint |
| Rents >50% for days | Same, deeper | Same bound; it is still a minority of the 7-day witness weight |
| Holds >1/3 of the 7-day witness weight | — | Can stall finality (chain keeps running) |
| Holds >2/3 of the 7-day witness weight | — | Controls finality; equivocating burns its escrow |
| Mines without the data (SPV mining) | Allowed | Earns no shares, never enters W |

Honest limits:

- This does not make a sustained majority harmless; nothing permissionless
  can. It moves the bar from *hashrate now* to *proven contribution over
  the last week*, and makes reverting finalized history cost the escrow.
- Long-range forks that rebuild W from far back are stopped by nodes already
  online and, for new nodes, by `MIN_CHAIN_WORK` and the release checkpoint
  (weak subjectivity).
- Unreviewed design; parameters (K, epoch, 2/3, 256) need simulation.
