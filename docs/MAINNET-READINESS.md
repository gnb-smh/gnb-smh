# GnB mainnet readiness (proposal, not applied)

Status on 14 Oct 2026 (read-only, from the running node):

| | |
| --- | --- |
| Nodes | one (152.236.5.112), 0 peers, mining with 28 threads |
| Tip | height 8,302, blue score 9,023, chain work 7,782,451 |
| Proof of work | GnB-SMH v1 (64 MiB); PoWit, SMH v3 and policy trees off (`POWIT_HEIGHT_MAINNET = u64::MAX`) |
| `MIN_CHAIN_WORK` | 0 |
| DNS seeds | none |

Nothing below is applied. Each item is a release decision.

## 1. `MIN_CHAIN_WORK`

**Why.** With 0, a fresh node accepts any chain from genesis, including a
fake one fed by an attacker who isolates it.

**Proposal.** At every release, set it to the chain work of a block buried
at least about one week below the tip at release time. Never use the tip
itself: a node must still be able to sync while the network keeps growing.

| Release | Value |
| --- | --- |
| Next release (if cut today) | **7,000,000** (tip 7,782,451; leaves room below the tip) |
| Later releases | the work of the tip minus ~20,160 blocks (one week), rounded down |

The node also turns finality, the reorg-depth cap and pruning on only above
this value, so a low value is safe and a high value is harmful. Err low.

## 2. Seeds

- **Hardcoded peers** in the release: at least three nodes run by different
  operators on different providers.
- **DNS seeds** under the project domain: `seed1.gnb-smh.com`,
  `seed2.gnb-smh.com`, `seed3.gnb-smh.com`, each answering with several node
  addresses, run by at least two different people.
- **Pinned post-quantum P2P keys** (`p2p_pq_pins.json`) for the seed nodes,
  published with the release.

## 3. Leaving the single node

Today one machine mines, validates and stores the chain. Any outage halts
it, and any operator mistake is final.

| Step | Goal | Done when |
| --- | --- | --- |
| 1 | Publish binaries, `RUNNING.md`, the seed list and the pinned P2P keys | a stranger can join from the docs alone |
| 2 | Two archival nodes (`--archive`) on separate providers | a fresh node syncs from genesis with the main node offline |
| 3 | At least three independent miners (different operators, machines and payout keys) | no single coinbase address finds more than 50% of blocks for 7 days |
| 4 | Public testnet with PoWit (§4) running at least two weeks | the adversarial tests (double vote, silent witnesses, private fork below finality) pass on it |
| 5 | Monitoring: tip age, peer count, orphan rate, reorg depth | alerts reach more than one person |

## 4. PoWit activation (mainnet)

A witness set needs many independent witnesses. With one miner, PoWit
finalizes whatever that miner wants. That is no worse than today, but it
adds nothing.

**Activation criterion (all of):**
1. Steps 1 to 4 of §3 are done.
2. An external audit of `core::powit`, `core::kes`, `core::witness_share` and
   the policy trees in `core::policy`, with its findings fixed.
3. On the public testnet, at least **10 distinct witness ids** each hold at
   least 1% of witness weight, and none holds more than 33%, for 7 days.
4. On mainnet, no single coinbase address finds more than 33% of blocks over
   the 14 days before the height is fixed.

**Height.** Announce at least **6 weeks** ahead: `activation = tip at
announcement + 120,960` (6 × 20,160 blocks), rounded up to a multiple of the
epoch length (720). The height goes into `POWIT_HEIGHT_MAINNET` in a release
that every node must run before it.

PoWit, GnB-SMH v3 (the target becomes 4× harder, with chain work continuous
across the switch), witness-share payouts and policy trees (bridge vault
recovery) all switch at that height.

## 5. Bridge parameters tied to readiness

| Parameter | Before PoWit | With PoWit |
| --- | --- | --- |
| Lock depth before mint | 1,000 confirmations (the node's reorg limit) | the lock's block at or below the finalized checkpoint |
| Vault type | single-branch `k`-of-`n` (no recovery: trees are off) | two-branch tree with cold recovery after `older` = 1 year |
| Caps | low (the chain has one miner) | raised as miners and witnesses diversify |

## Decisions (owner: the project)

| Decision | Recommendation |
| --- | --- |
| `MIN_CHAIN_WORK` next release | 7,000,000 |
| Seeds | 3 hardcoded peers + 3 DNS seeds, two or more operators |
| PoWit mainnet height | none yet; fix it only when §4 criteria 1-4 hold, 6 weeks ahead |
| Lock depth N before PoWit | 1,000 |
