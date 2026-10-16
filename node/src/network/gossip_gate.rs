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
            // A connection this gate hid can still be DENIED by a behaviour
            // whose `handle_established_*` runs after ours (the derive macro
            // calls the fields in order). The swarm then reports a
            // ListenFailure / DialFailure — never a ConnectionClosed — for
            // that connection id, so its `hidden` entry must go here, or each
            // denied connection of a gated peer leaks one entry forever.
            FromSwarm::ListenFailure(e) => {
                self.hidden.remove(&e.connection_id);
                self.inner.on_swarm_event(FromSwarm::ListenFailure(e));
            }
            FromSwarm::DialFailure(e) => {
                self.hidden.remove(&e.connection_id);
                self.inner.on_swarm_event(FromSwarm::DialFailure(e));
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::behaviour::{DialFailure, ListenFailure};
    use libp2p::swarm::{DialError, ListenError};

    fn gate() -> GossipGate {
        let key = libp2p::identity::Keypair::generate_ed25519();
        let inner = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key),
            gossipsub::Config::default(),
        )
        .expect("gossipsub");
        GossipGate::new(inner)
    }

    /// NET-11 (d) review: a gated (block-relay-only / feeler) peer's
    /// connection that a LATER behaviour denies (connection_limits: per-peer
    /// or incoming cap) is reported as a ListenFailure / DialFailure, not a
    /// ConnectionClosed. Before the fix its `hidden` entry stayed forever: a
    /// gated attacker looping denied inbound connections grew the map
    /// without bound.
    #[test]
    fn denied_connections_of_a_gated_peer_leave_no_hidden_entry() {
        let mut g = gate();
        let peer = PeerId::random();
        g.gate_peer(peer);
        let local: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        let remote: Multiaddr = "/ip4/127.0.0.1/tcp/2".parse().unwrap();
        for i in 0..100usize {
            let id = ConnectionId::new_unchecked(i);
            assert!(g.handle_established_inbound_connection(id, peer, &local, &remote).is_ok());
            let error = ListenError::Denied { cause: ConnectionDenied::new("connection limit") };
            g.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                local_addr: &local,
                send_back_addr: &remote,
                error: &error,
                connection_id: id,
                peer_id: Some(peer),
            }));
        }
        assert_eq!(g.hidden_connections(), 0, "denied inbound connections must not leak");
        let id = ConnectionId::new_unchecked(1000);
        assert!(g
            .handle_established_outbound_connection(id, peer, &remote, Endpoint::Dialer, PortUse::Reuse)
            .is_ok());
        assert_eq!(g.hidden_connections(), 1);
        let error = DialError::Denied { cause: ConnectionDenied::new("connection limit") };
        g.on_swarm_event(FromSwarm::DialFailure(DialFailure { peer_id: Some(peer), error: &error, connection_id: id }));
        assert_eq!(g.hidden_connections(), 0, "a denied outbound connection must not leak");
        assert!(g.is_gated(&peer), "the gate itself stays until the peer's last connection closes");
    }
}
