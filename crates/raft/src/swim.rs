//! SWIM membership & failure detection (Das, Gupta, Motivala 2002; the
//! Serf/memberlist flavour used by dkron). Deterministic and transport-agnostic:
//! drive with `tick()`, feed received gossip to `handle()`, ship the returned
//! `(destination, Gossip)` pairs.
//!
//! - Every tick at most one member is probed (round-robin) with a `Ping`.
//! - No `Ack` within `SUSPECT_TICKS`: `PingReq` to up to `PING_REQ_FANOUT`
//!   other members, which ping the target and relay its ack (`IndirectAck`).
//! - Still nothing after another `SUSPECT_TICKS`: the target becomes
//!   `Suspect` (same incarnation) and is told so.
//! - A suspect not refuted within `DEAD_TICKS` becomes `Dead`.
//! - A member that hears it is suspected (or declared dead) refutes by
//!   bumping its own incarnation; only a member bumps its own incarnation.
//!
//! Membership state is piggybacked on every message and merged with the
//! usual precedence: higher incarnation wins, then `Dead > Suspect > Alive`.

use crate::NodeId;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Alive = 0,
    Suspect = 1,
    Dead = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub id: NodeId,
    pub incarnation: u64,
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gossip {
    Ping {
        from: NodeId,
        members: Vec<Member>,
    },
    Ack {
        from: NodeId,
        members: Vec<Member>,
    },
    PingReq {
        from: NodeId,
        target: NodeId,
        members: Vec<Member>,
    },
    IndirectAck {
        from: NodeId,
        target: NodeId,
    },
    Members {
        from: NodeId,
        members: Vec<Member>,
    },
}

pub const SUSPECT_TICKS: u64 = 5;
pub const DEAD_TICKS: u64 = 10;
pub const PING_REQ_FANOUT: usize = 3;
pub const GOSSIP_FANOUT: usize = 3;

#[derive(Clone, Debug)]
struct Probe {
    target: NodeId,
    deadline: u64,
    indirect: bool,
}

#[derive(Clone, Debug)]
struct Relay {
    target: NodeId,
    requester: NodeId,
    deadline: u64,
}

pub struct Swim {
    id: NodeId,
    members: BTreeMap<NodeId, Member>,
    tick_count: u64,
    probe: Option<Probe>,
    relays: Vec<Relay>,
    suspect_since: BTreeMap<NodeId, u64>,
    cursor: usize,
}

impl Swim {
    /// Node `id` knowing the initial members `all` (itself always included).
    pub fn new(id: NodeId, all: &[NodeId]) -> Self {
        let members = all
            .iter()
            .chain(std::iter::once(&id))
            .map(|&m| {
                (
                    m,
                    Member {
                        id: m,
                        incarnation: 0,
                        status: Status::Alive,
                    },
                )
            })
            .collect();
        Swim {
            id,
            members,
            tick_count: 0,
            probe: None,
            relays: Vec::new(),
            suspect_since: BTreeMap::new(),
            cursor: 0,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// This node's own incarnation number.
    pub fn incarnation(&self) -> u64 {
        self.members[&self.id].incarnation
    }

    pub fn members(&self) -> Vec<Member> {
        self.members.values().cloned().collect()
    }

    pub fn get(&self, id: NodeId) -> Option<&Member> {
        self.members.get(&id)
    }

    pub fn alive_count(&self) -> usize {
        self.members.values().filter(|m| m.status == Status::Alive).count()
    }

    pub fn alive_quorum(&self) -> usize {
        crate::quorum(self.alive_count())
    }

    /// Merges gossiped member states (see module docs for precedence).
    pub fn merge(&mut self, incoming: &[Member]) {
        for m in incoming {
            if m.id == self.id {
                self.refute(m);
                continue;
            }
            let newer = self
                .members
                .get(&m.id)
                .is_none_or(|cur| (m.incarnation, m.status) > (cur.incarnation, cur.status));
            if newer {
                self.members.insert(m.id, m.clone());
                match m.status {
                    Status::Suspect => {
                        self.suspect_since.entry(m.id).or_insert(self.tick_count);
                    }
                    Status::Alive | Status::Dead => {
                        self.suspect_since.remove(&m.id);
                    }
                }
            }
        }
    }

    fn refute(&mut self, claim: &Member) {
        let me = self.members.get_mut(&self.id).expect("self is a member");
        if (claim.status != Status::Alive) & (claim.incarnation >= me.incarnation) {
            me.incarnation = claim.incarnation + 1;
        }
    }

    fn snapshot(&self) -> Vec<Member> {
        self.members()
    }

    /// Members worth probing / gossiping to: everyone but us and the dead.
    fn live_peers(&self) -> Vec<NodeId> {
        self.members
            .values()
            .filter(|m| (m.id != self.id) & (m.status != Status::Dead))
            .map(|m| m.id)
            .collect()
    }

    pub fn tick(&mut self) -> Vec<(NodeId, Gossip)> {
        self.tick_count += 1;
        let now = self.tick_count;
        let mut out = Vec::new();
        let peers = self.live_peers();

        match self.probe.take() {
            Some(p) if now < p.deadline => self.probe = Some(p),
            Some(p) if !p.indirect => {
                for ask in peers.iter().filter(|&&a| a != p.target).take(PING_REQ_FANOUT) {
                    out.push((
                        *ask,
                        Gossip::PingReq {
                            from: self.id,
                            target: p.target,
                            members: self.snapshot(),
                        },
                    ));
                }
                self.probe = Some(Probe {
                    deadline: now + SUSPECT_TICKS,
                    indirect: true,
                    ..p
                });
            }
            Some(p) => {
                let m = self.members.get_mut(&p.target).expect("probed member exists");
                m.status = m.status.max(Status::Suspect);
                let claim = m.clone();
                self.suspect_since.entry(p.target).or_insert(now);
                out.push((
                    p.target,
                    Gossip::Members {
                        from: self.id,
                        members: vec![claim],
                    },
                ));
            }
            None => {}
        }

        let expired: Vec<NodeId> = self
            .suspect_since
            .iter()
            .filter(|&(_, &since)| now >= since + DEAD_TICKS)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            self.suspect_since.remove(&id);
            self.members.get_mut(&id).expect("suspect is a member").status = Status::Dead;
        }
        self.relays.retain(|r| r.deadline > now);

        if self.probe.is_none() && !peers.is_empty() {
            let target = peers[self.cursor % peers.len()];
            self.cursor = self.cursor.wrapping_add(1);
            self.probe = Some(Probe {
                target,
                deadline: now + SUSPECT_TICKS,
                indirect: false,
            });
            out.push((
                target,
                Gossip::Ping {
                    from: self.id,
                    members: self.snapshot(),
                },
            ));
        }
        for i in 0..GOSSIP_FANOUT.min(peers.len()) {
            out.push((
                peers[(self.cursor + i) % peers.len()],
                Gossip::Members {
                    from: self.id,
                    members: self.snapshot(),
                },
            ));
        }
        out
    }

    pub fn handle(&mut self, msg: Gossip) -> Vec<(NodeId, Gossip)> {
        match msg {
            Gossip::Ping { from, members } => {
                self.merge(&members);
                vec![(
                    from,
                    Gossip::Ack {
                        from: self.id,
                        members: self.snapshot(),
                    },
                )]
            }
            Gossip::Ack { from, members } => {
                self.merge(&members);
                let _ = self.probe.take_if(|p| p.target == from);
                let (done, keep): (Vec<Relay>, Vec<Relay>) = self.relays.drain(..).partition(|r| r.target == from);
                self.relays = keep;
                done.into_iter()
                    .map(|r| {
                        (
                            r.requester,
                            Gossip::IndirectAck {
                                from: self.id,
                                target: from,
                            },
                        )
                    })
                    .collect()
            }
            Gossip::PingReq { from, target, members } => {
                self.merge(&members);
                self.relays.push(Relay {
                    target,
                    requester: from,
                    deadline: self.tick_count + SUSPECT_TICKS,
                });
                vec![(
                    target,
                    Gossip::Ping {
                        from: self.id,
                        members: self.snapshot(),
                    },
                )]
            }
            Gossip::IndirectAck { target, .. } => {
                let _ = self.probe.take_if(|p| p.target == target);
                Vec::new()
            }
            Gossip::Members { members, .. } => {
                self.merge(&members);
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn member(id: NodeId, incarnation: u64, status: Status) -> Member {
        Member {
            id,
            incarnation,
            status,
        }
    }

    /// Nodes 1..=n; `cut(from, to)` drops a message.
    fn cluster(n: u64) -> Vec<Swim> {
        let all: Vec<NodeId> = (1..=n).collect();
        all.iter().map(|&id| Swim::new(id, &all)).collect()
    }

    fn run(nodes: &mut [Swim], ticks: usize, cut: &dyn Fn(NodeId, NodeId) -> bool) {
        for _ in 0..ticks {
            let mut q = VecDeque::new();
            for n in nodes.iter_mut() {
                let from = n.id();
                q.extend(n.tick().into_iter().map(|(to, g)| (from, to, g)));
            }
            while let Some((from, to, g)) = q.pop_front() {
                if cut(from, to) {
                    continue;
                }
                let replies = nodes[(to - 1) as usize].handle(g);
                q.extend(replies.into_iter().map(|(t, g)| (to, t, g)));
            }
        }
    }

    fn status(nodes: &[Swim], at: NodeId, of: NodeId) -> Status {
        nodes[(at - 1) as usize].get(of).unwrap().status
    }

    #[test]
    fn basics_and_lonely_node() {
        let mut s = Swim::new(1, &[2, 3]);
        assert_eq!(
            (s.id(), s.alive_count(), s.alive_quorum(), s.incarnation()),
            (1, 3, 2, 0)
        );
        assert_eq!(s.get(2).unwrap().status, Status::Alive);
        assert_eq!(s.members().len(), 3);
        let mut lonely = Swim::new(1, &[]);
        assert!(lonely.tick().is_empty());
        assert_eq!(lonely.tick_count(), 1);
        assert!(s.tick().iter().any(|(to, g)| (*to == 2)
            & (*g
                == Gossip::Ping {
                    from: 1,
                    members: s.members()
                })));
    }

    #[test]
    fn healthy_cluster_stays_alive() {
        let mut nodes = cluster(4);
        run(&mut nodes, 60, &|_, _| false);
        for n in &nodes {
            assert_eq!(n.alive_count(), 4);
        }
    }

    #[test]
    fn crashed_member_is_suspected_then_declared_dead() {
        let mut nodes = cluster(4);
        let down = |a: NodeId, b: NodeId| (a == 4) | (b == 4);
        run(&mut nodes, 14, &down);
        assert!((1..=3).any(|at| status(&nodes, at, 4) == Status::Suspect));
        run(&mut nodes, 60, &down);
        for at in 1..=3 {
            assert_eq!(status(&nodes, at, 4), Status::Dead);
            assert_eq!(nodes[(at - 1) as usize].alive_count(), 3);
        }
    }

    #[test]
    fn indirect_probe_masks_a_broken_link() {
        let mut nodes = cluster(3);
        let cut = |a: NodeId, b: NodeId| ((a, b) == (1, 2)) | ((a, b) == (2, 1));
        run(&mut nodes, 80, &cut);
        for at in 1..=3 {
            assert_eq!(nodes[(at - 1) as usize].alive_count(), 3);
        }
    }

    #[test]
    fn suspected_member_refutes_when_back() {
        let mut nodes = cluster(3);
        let down = |a: NodeId, b: NodeId| (a == 3) | (b == 3);
        run(&mut nodes, 12, &down);
        assert!((1..=2).any(|at| status(&nodes, at, 3) == Status::Suspect));
        run(&mut nodes, 10, &|_, _| false);
        assert!(nodes[2].incarnation() > 0);
        for at in 1..=3 {
            assert_eq!(status(&nodes, at, 3), Status::Alive);
        }
    }

    #[test]
    fn merge_precedence_and_refutation() {
        let mut a = Swim::new(1, &[1, 2]);
        a.merge(&[member(2, 5, Status::Dead)]);
        assert_eq!(a.get(2).unwrap().status, Status::Dead);
        a.merge(&[member(2, 4, Status::Alive)]);
        assert_eq!(a.get(2).unwrap().status, Status::Dead, "older incarnation ignored");
        a.merge(&[member(2, 6, Status::Suspect)]);
        assert_eq!(a.get(2).unwrap().status, Status::Suspect);
        a.merge(&[member(2, 7, Status::Alive)]);
        assert_eq!(a.get(2).unwrap().status, Status::Alive);
        a.merge(&[member(9, 0, Status::Alive)]);
        assert_eq!(a.get(9).unwrap().id, 9);
        // Claims about ourselves: alive or stale ones are ignored.
        a.merge(&[member(1, 0, Status::Alive)]);
        assert_eq!(a.incarnation(), 0);
        a.merge(&[member(1, 3, Status::Suspect)]);
        assert_eq!(a.incarnation(), 4);
        a.merge(&[member(1, 2, Status::Dead)]);
        assert_eq!(a.incarnation(), 4);
        assert_eq!(a.get(1).unwrap().status, Status::Alive);
    }

    #[test]
    fn relays_answer_requesters_and_expire() {
        let mut relay = Swim::new(2, &[1, 2, 3]);
        let out = relay.handle(Gossip::PingReq {
            from: 1,
            target: 3,
            members: vec![],
        });
        assert_eq!(out[0].0, 3);
        let acks = relay.handle(Gossip::Ack {
            from: 3,
            members: vec![],
        });
        assert_eq!(acks, vec![(1, Gossip::IndirectAck { from: 2, target: 3 })]);
        relay.handle(Gossip::PingReq {
            from: 1,
            target: 3,
            members: vec![],
        });
        for _ in 0..SUSPECT_TICKS {
            relay.tick();
        }
        let late = relay.handle(Gossip::Ack {
            from: 3,
            members: vec![],
        });
        assert!(late.is_empty(), "expired relay");
        assert!(relay.handle(Gossip::IndirectAck { from: 1, target: 3 }).is_empty());
    }
}
