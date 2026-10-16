# GnB peer-to-peer security

## Transport: `/gnb/pq/2.0.0`

Every connection (TCP and WebSocket) is secured by a post-quantum handshake
(`node/src/transport/upgrade.rs`):

| Part | Construction |
| --- | --- |
| Key exchange | ML-KEM-768 (FIPS 203) **and** X25519, both ephemeral. Session keys come from HKDF-SHA256 over both shared secrets, salted with the transcript hash, so the session stays confidential unless both are broken. |
| Authentication | Each side signs the transcript with its libp2p key (Ed25519, from which the `PeerId` is derived) **and** its PQ identity key (hybrid ML-DSA-65 ‖ Falcon-1024, the consensus scheme, verified in the strict enveloped canonical form). |
| Mutual binding | The responder signs the transcript of both opening messages; the initiator then signs the full transcript in a third message. Neither side accepts the connection before verifying the other's signatures. |
| Cipher | ChaCha20-Poly1305, monotonic counters (replay and reorder rejected), frame length bound into the AEAD. |

Rejected outright: other handshake versions, a non-hybrid PQ key, a low-order
X25519 point, a wrong-size ML-KEM key, oversized handshake frames, and
connections to oneself.

### Identities and pinning

- `p2p_identity.bin`: libp2p Ed25519 key (owner-only permissions).
- `p2p_pq_identity.bin`: PQ identity key (owner-only, written atomically,
  self-tested on load; a corrupt file stops the node instead of being
  replaced).
- `p2p_pq_pins.json`: `PeerId` → PQ key fingerprint. The first handshake with
  a peer pins its PQ key; any later handshake for that `PeerId` with another
  PQ key is refused. Forging the Ed25519 key of a known peer is therefore not
  enough to impersonate it. A malformed pin file stops the node (dropping pins
  would re-open every known peer to impersonation).

The node logs its PQ fingerprint at start. To rotate a node's PQ key, its
peers must remove its entry from their pin files.

Not claimed: identity hiding (identities travel in clear), traffic-analysis
resistance, a formal proof, a third-party audit.

## Blocks at the network edge

GnB-SMH costs as much to verify as one mining attempt (~0.5 s, 64 MiB), so
every block received from a peer passes `node/src/network/pow_gate.rs` before
its proof is evaluated:

1. Banned peers, and peers connecting from a banned address, are ignored.
2. Context-free precheck (microseconds): structure, timestamp at most 600 s
   ahead, and `bits` no easier than `expected_bits(timestamp, height)`, the
   easiest difficulty any valid block at that height can carry.
3. Contextual precheck when every parent is in the DAG: height and `bits`
   must be exactly what block acceptance requires (max parent height + 1,
   the ASERT schedule). Blocks already known are dropped.
4. Unsolicited blocks spend a budget keyed by the peer's IP address (burst 8,
   then 30 per minute), so new identities from one address share it. A block
   with an unknown parent skips step 3 and costs 4. Blocks this node
   requested are not budgeted.
5. The proof is evaluated on a worker pool sized to the CPU count, off the
   event loop and in parallel (which also speeds up sync). Evaluations still
   queued for a peer that has been banned meanwhile are dropped.
6. **Invalid proof: the peer is disconnected, and the peer and its IP address
   are banned for 24 hours.**

Gossiped transactions are relayed only after this node's mempool accepted
them, and each peer has a transaction budget (burst 100, then 20 per second).

Gossip is validated before it is relayed (`validate_messages`): a block is
relayed only after its proof verified. An honest peer therefore never
forwards an invalid proof, so banning the peer that delivered one never
punishes an innocent relay.

## Peers and addresses

Connection management follows Bitcoin Core (details: `docs/RUNNING.md`,
"Peers and connections"):

- 8 full-relay and 2 block-relay-only outbound connections are kept whatever
  the inbound count; inbound connections never use those slots.
- When the inbound slots are full, an inbound peer is evicted as Core's
  `SelectNodeToEvict` chooses (netgroup diversity, low latency, novel blocks
  and transactions, uptime are protected; the youngest peer of the largest
  netgroup goes).
- Block-relay-only connections carry no gossip at all (no transactions, PoWit
  items, addresses or block announcements); blocks are polled over them.
  They are saved as anchors (`anchors.json`) and re-dialed first after a
  restart.
- Feeler connections test new-table addresses about every 2 minutes.
- Addresses live in keyed new and tried tables (Core's addrman with a secret
  key derived from the node's identity), learned only from answers to the
  node's own `GetPeers`; peer exchange carries public IP literals only (host
  names and IPv6 forms embedding a private IPv4 are refused).
- Sync requests are rate limited per peer; peers whose budget has refilled
  are forgotten, so the limiter never locks new peers out.

## Mempool policy

- Transactions spend confirmed outputs only (no unconfirmed chains).
- Replace-by-fee: a transaction conflicting with pool entries replaces all of
  them only if it pays their total fee plus 1 sat/byte of its own size, has a
  strictly higher fee rate than each, replaces at most 100, and fits without
  further eviction. Otherwise the first-seen transaction stays.
- A full pool evicts its lowest fee-rate entry only for a newcomer paying at
  least 1 sat/byte more (incremental relay fee).
- Entries expire after 72 hours.
