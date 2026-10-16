//! NET-11 (d): block-relay-only connections that carry NO gossip.
//!
//! Bitcoin Core keeps two outbound "block-relay-only" connections that relay
//! no transactions and no addresses. They are invisible to the
//! topology-inference attacks that work through transaction and address
//! relay (send a transaction or an address to one node, see where it comes
//! out), so an attacker cannot easily find and target them, and they are what
//! anchors persist across restarts.
//!
//! gossipsub has no per-peer topic filter: any connection it knows joins the
//! transaction topic's mesh and fanout. [`GossipGate`] wraps the gossipsub
//! behaviour and HIDES the connections of "gated" peers from it entirely:
//! such a connection gets a protocol-less handler for gossipsub (the remote
//! sees that we do not speak `/meshsub` on it) and gossipsub never learns the
//! connection exists, so no transaction, block announcement, IHAVE/IWANT or
//! subscription flows over it in either direction. The other protocols run
//! as usual on the same connection: blocks are learned from a
//! block-relay-only peer through the directed `/gnb/sync/1` protocol
//! (`GetTips` polls every `connmgr::BLOCK_RELAY_POLL_INTERVAL`, then the
//! normal header / block pulls), and the network loop neither sends nor
//! answers `GetPeers` on it (no address relay).
//!
//! A peer is gated before it is dialed ([`GossipGate::gate_peer`]) and
//! ungated when its last connection closes. All other calls go straight to
//! the wrapped `gossipsub::Behaviour` (`Deref`), so the network loop uses it
//! exactly as before.

use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::gossipsub;
// `Either` is the type libp2p-swarm implements `ConnectionHandler` for; the
// derive prelude is where libp2p exports it (the node does not depend on the
// `either` crate directly).
use libp2p::swarm::derive_prelude::Either;
use libp2p::swarm::{
    behaviour::{ConnectionClosed, ConnectionEstablished, FromSwarm},
    dummy, ConnectionDenied, ConnectionId, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent,
    ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

/// gossipsub with per-peer gating (see the module docs).
pub struct GossipGate {
    inner: gossipsub::Behaviour,
    gated: HashSet<PeerId>,
    /// Connections hidden from gossipsub.
    hidden: HashMap<ConnectionId, PeerId>,
    /// Connections gossipsub knows, per peer (its `other_established` /
    /// `remaining_established` must count only those).
    visible: HashMap<PeerId, usize>,
}

impl GossipGate {
    pub fn new(inner: gossipsub::Behaviour) -> Self {
        Self { inner, gated: HashSet::new(), hidden: HashMap::new(), visible: HashMap::new() }
    }

    /// Hide every future connection of `peer` from gossipsub (call before
    /// dialing it as block-relay-only). Lasts until its last connection
    /// closes or [`Self::ungate_peer`].
    pub fn gate_peer(&mut self, peer: PeerId) {
        self.gated.insert(peer);
    }

    /// Stop gating `peer`'s FUTURE connections (a failed block-relay-only
    /// dial); connections already hidden stay hidden until they close.
    pub fn ungate_peer(&mut self, peer: &PeerId) {
        self.gated.remove(peer);
    }

    pub fn is_gated(&self, peer: &PeerId) -> bool {
        self.gated.contains(peer)
    }

    /// Whether gossipsub knows a connection to `peer`.
    pub fn sees(&self, peer: &PeerId) -> bool {
        self.visible.get(peer).copied().unwrap_or(0) > 0
    }

    /// Connections currently hidden from gossipsub.
    pub fn hidden_connections(&self) -> usize {
        self.hidden.len()
    }
}

impl Deref for GossipGate {
    type Target = gossipsub::Behaviour;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for GossipGate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl NetworkBehaviour for GossipGate {
    type ConnectionHandler = Either<THandler<gossipsub::Behaviour>, dummy::ConnectionHandler>;
    type ToSwarm = gossipsub::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner.handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.gated.contains(&peer) {
            self.hidden.insert(connection_id, peer);
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        self.inner
            .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)
            .map(Either::Left)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(connection_id, maybe_peer, addresses, effective_role)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if self.gated.contains(&peer) {
            self.hidden.insert(connection_id, peer);
            return Ok(Either::Right(dummy::ConnectionHandler));
        }
        self.inner
            .handle_established_outbound_connection(connection_id, peer, addr, role_override, port_use)
            .map(Either::Left)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(e) => {
                if self.hidden.contains_key(&e.connection_id) {
                    return;
                }
                let n = self.visible.entry(e.peer_id).or_insert(0);
                let other_established = *n;
                *n += 1;
                self.inner
                    .on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished { other_established, ..e }));
            }
            FromSwarm::ConnectionClosed(e) => {
                if e.remaining_established == 0 {
                    self.gated.remove(&e.peer_id);
                }
                if self.hidden.remove(&e.connection_id).is_some() {
                    return;
                }
                let remaining_established = match self.visible.get_mut(&e.peer_id) {
                    Some(n) => {
                        *n = n.saturating_sub(1);
                        *n
                    }
                    None => 0,
                };
                if remaining_established == 0 {
                    self.visible.remove(&e.peer_id);
                }
                self.inner
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed { remaining_established, ..e }));
            }
            FromSwarm::AddressChange(e) if self.hidden.contains_key(&e.connection_id) => {}
            other => self.inner.on_swarm_event(other),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(e) => self.inner.on_connection_handler_event(peer_id, connection_id, e),
            Either::Right(never) => match never {},
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx).map(|ev| ev.map_in(Either::Left))
    }
}
