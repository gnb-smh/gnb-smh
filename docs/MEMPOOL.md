# Transaction relay and mempool policy

This is **node-local policy**. Nothing here changes which blocks or
transactions are valid (see `CONSENSUS.md` for that); two nodes with different
policies agree on every block. The policy decides what a node keeps in its
mempool, what it relays, and what it puts into its own block templates.

Implementation: `node/src/mempool/` (`mod.rs` the pool, `admission.rs` the
shared admission function, `orphanage.rs` the orphan pool, `relay.rs` the
gossip relay) and `node/src/template.rs`. The values below are the constants
of those files; `getmempoolinfo` reports them under `policy`.

## 1. Admission (one function for every ingress)

Gossip, RPC `sendrawtransaction` and the re-injection of transactions from
blocks disconnected by a reorg all call `admission::admit`. Checks run
cheapest first, so the size-dependent signature work only runs on a
transaction that passed everything else:

1. structure: not a coinbase, at least one input and one output;
2. size: canonical wire size and bincode size at most `MAX_TX_SIZE`
   (409,600 bytes);
3. known: already pooled, already confirmed, or in the recent-rejects filter
   (50,000 wtxids, cleared whenever the selected tip changes);
4. standardness: canonical-encoding limits, MoneyRange, no dust output
   (< 546 sat), no zero-value output;
5. no input spent twice;
6. every input is an unspent output in the UTXO set **or an output of a
   pooled transaction** (§4); otherwise "missing inputs" (§3);
7. coinbase maturity at the height of the next block;
8. fees: inputs ≥ outputs, consensus minimum fee, 1 sat/byte relay minimum,
   the rolling minimum fee rate (§6);
9. pool policy: replacement rules when it conflicts with pooled transactions
   (§7), ancestor/descendant limits (§4);
10. input scripts and the hybrid ML-DSA-65 + Falcon-1024 signatures, last,
    through a bounded verified-signature cache shared with block validation.

## 2. Gossip relay

A gossiped `NewTransaction` frame is **not forwarded until the node has
judged it** (gossipsub `validate_messages`, verdict reported by the message
processor, exactly as for blocks):

| verdict | when | effect |
|---|---|---|
| Accept | the transaction entered the pool | forwarded to the mesh |
| Reject | malformed frame (non-canonical bytes, wrong claimed txid) or a consensus-invalid transaction (check 1 coinbase / no inputs, 4 except zero-value, 5, 8 consensus parts, 10) | not forwarded; the delivering peer takes gossipsub's invalid-message penalty on the transaction topic |
| Ignore | anything else: policy refusals (size, no outputs, zero-value output, fee below the relay or rolling minimum, replacement and chain limits, pool full), duplicates, recently rejected ids, missing inputs, signature budget exhausted | not forwarded, no penalty |

Because every honest node validates before forwarding, an invalid frame is
only ever delivered by its author, so the penalty lands on the author and
never on an honest relay.

**Signature budget.** Step 10 is charged to the gossip *author* (the signed
gossipsub source) as one token per input signature, all-or-nothing, from a
token bucket per author: burst 400, refill 20 per second, at most 4,096
authors tracked (least-recently-used eviction). A cache hit costs nothing. An
author without enough tokens gets `Ignore` and no signature is checked.

## 3. Orphan transactions

A gossiped transaction with missing inputs that passed the context-free checks
is kept in the orphan pool instead of being dropped:

* at most 100 orphans and 10 MiB in total, 25 orphans and 2 MiB per delivering
  peer;
* a peer over its quota loses its own oldest orphan; when the global bound is
  reached, the oldest orphan of the peer holding the most is evicted;
* an orphan expires after 20 minutes;
* when a transaction enters the pool, the orphans waiting on it are re-tried
  (at most 25 per event, breadth-first through their own children); after a
  connected block and on a 30 s sweep every orphan whose inputs are now all
  available is re-tried; orphans confirmed by a block or spending an outpoint
  the block spent are erased;
* a re-tried orphan's signatures are charged to the peer that delivered it;
  an orphan admitted this way is announced by the node itself (its original
  frame was answered `Ignore`).

## 4. Chains of unconfirmed transactions

A transaction may spend outputs of pooled transactions. Every entry records
its in-pool parents and children. A transaction is refused when

* its in-pool ancestors, itself included, would exceed 25 transactions or
  500,000 bytes, or
* any of its ancestors would get more than 25 descendants (itself included)
  or a descendant package above 500,000 bytes.

Sizes are bincode sizes, the measure of the consensus block-size rule; a
whole package always fits half a block.

## 5. Block templates: child pays for parent

The template builder (`template::build_block_template`, used by the miner and
`getblocktemplate`) selects **ancestor packages**: it repeatedly takes the
pooled transaction whose package — itself plus every not-yet-selected in-pool
ancestor — has the highest package fee rate (Σ fee / Σ size), and appends the
whole package with parents before children (`mempool::select_packages`). A
package that does not fit the remaining byte budget is skipped. Every package
member is re-validated against the UTXO set plus the outputs placed earlier in
the template; a member that fails is evicted from the pool together with its
descendants and the package is not included (all or nothing). Without in-pool
chains this is plain highest-fee-rate-first selection.

## 6. Removal, eviction, expiry

* A transaction confirmed by a connected block leaves the pool; its in-pool
  children stay (they now spend a confirmed output).
* In every other case a transaction leaves **with all its in-pool
  descendants**: conflict with a connected block, failed re-validation after a
  reorg, expiry after 72 hours, eviction, replacement, a failed template
  self-check.
* After a reorg the transactions of disconnected blocks are re-admitted in
  block order (parents first, signatures not re-checked), pooled transactions
  that spent their outputs become their children again, and the whole pool is
  re-validated against the new UTXO set plus the pool.
* The pool holds at most 50,000 transactions and 300 MiB. When full, the
  entry with the lowest **descendant score** — max(own fee rate, fee rate of
  itself plus all its descendants) — is evicted with its descendants, and the
  **rolling minimum fee rate** rises to that rate plus the incremental relay
  fee rate (1 sat/byte); it halves every 12 hours. If the package to evict
  contains the incoming transaction, the incoming transaction is refused
  instead.

## 7. Replacement: full-RBF

GnB uses full replace-by-fee without opt-in signalling (as Bitcoin Core since
v28). A transaction that spends an outpoint already spent by pooled
transactions (its *direct conflicts*) replaces them, together with all their
descendants (the *evicted set*), if and only if:

* **rule 2** — every input it spends from a pooled transaction spends an
  output of a transaction that one of the direct conflicts already spent from
  (no new unconfirmed inputs);
* **rule 3** — its absolute fee is at least the sum of the fees of the whole
  evicted set;
* **rule 4** — its fee minus that sum is at least the incremental relay fee
  (1 sat/byte) times its own size;
* **rule 5** — the evicted set has at most 100 transactions;
* **rule 6** — its fee rate is higher than the fee rate of each direct
  conflict;
* it does not spend an output of any transaction in the evicted set;
* it passes every other admission check (§1), including the chain limits
  computed without the evicted set.

Rules 2–6 are checked before the signatures (step 9) and again atomically when
the pool is modified. The replacement is relayed like any new transaction; the
evicted transactions are dropped. Why not first-seen: with block producers free
to mine any valid transaction, first-seen only protects the first broadcaster
on nodes that enforce it, while a fee-bumping rule lets a sender fix a stuck
transaction and lets miners and relays converge on the most valuable version;
rules 3–5 make each replacement pay for the bandwidth it consumes and bound
the work one replacement can cause.

The raw `Mempool::add` used by tools and tests stays first-seen; replacement
is an admission decision (`Mempool::add_with_replacement`).

## 8. RPC

* `sendrawtransaction` runs the same admission, replacement included; an
  error names the failed rule.
* `getmempoolinfo` returns `size`, `bytes`, the current rolling minimum fee
  rate and this policy's parameters under `policy`.
* `estimatefee` returns a fee rate never below the consensus minimum nor the
  rolling minimum.
