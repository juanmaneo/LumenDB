//! Raft wire messages (transport-agnostic). Every message carries the
//! sender's Lamport timestamp `lc` (set by the node when it is sent).

use crate::storage::Snapshot;
use crate::{Index, NodeId, Term};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    RequestVote,
    RequestVoteReply,
    AppendEntries,
    AppendEntriesReply,
    /// Would you vote for me in `term`? Asks without anyone changing term or
    /// vote, so a node that cannot win never disturbs the cluster.
    PreVote,
    PreVoteReply,
    /// The follower needs entries the leader has compacted: the leader sends
    /// its snapshot instead, in chunks. `last_log_index` and `last_log_term`
    /// name the last entry it covers. `snapshot` holds the cluster
    /// configuration and the bytes of the state machine from `snap_offset` on,
    /// of `snap_total` in all.
    InstallSnapshot,
    /// Either the snapshot is installed (or was already covered), with
    /// `match_index` the follower's log up to there, or, when `success` and
    /// `snap_offset < snap_total`, it has `snap_offset` bytes of the snapshot
    /// at `last_log_index` and wants the rest from there.
    InstallSnapshotReply,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub msg_type: MsgType,
    pub from: NodeId,
    pub to: NodeId,
    pub term: Term,
    pub last_log_index: Index,
    pub last_log_term: Term,
    pub entries: Vec<crate::LogEntry>,
    pub commit_index: Index,
    pub vote_granted: bool,
    pub match_index: Index,
    pub success: bool,
    /// AppendEntries: the leader's last log index at send time, so that a
    /// recovering follower knows when it holds the leader's whole log.
    pub leader_last_index: Index,
    /// AppendEntries and its reply: the leader's read round (0: none). A
    /// reply echoes it, proving the follower still accepted the leader after
    /// that round began; see [`crate::Node::read_index`].
    pub read_ctx: u64,
    /// InstallSnapshot: the snapshot, shared so that resending it is cheap.
    /// A chunk of a larger one has only its `data[snap_offset..]` part.
    pub snapshot: Option<Arc<Snapshot>>,
    /// InstallSnapshot and its reply: where the chunk starts in the snapshot's
    /// data, or how much of it the follower has.
    pub snap_offset: u64,
    /// InstallSnapshot and its reply: the length of the snapshot's data.
    pub snap_total: u64,
    /// Sender's Lamport clock at send time.
    pub lc: u64,
}

impl Message {
    pub fn request_vote(from: NodeId, to: NodeId, term: Term, last_idx: Index, last_term: Term) -> Self {
        Message {
            msg_type: MsgType::RequestVote,
            from,
            to,
            term,
            last_log_index: last_idx,
            last_log_term: last_term,
            entries: Vec::new(),
            commit_index: 0,
            vote_granted: false,
            match_index: 0,
            success: false,
            leader_last_index: 0,
            read_ctx: 0,
            snapshot: None,
            snap_offset: 0,
            snap_total: 0,
            lc: 0,
        }
    }
    /// The leader's whole snapshot, covering entries up to `(index, snapshot_term)`.
    pub fn install_snapshot(
        from: NodeId,
        to: NodeId,
        term: Term,
        snapshot: Arc<Snapshot>,
        leader_commit: Index,
    ) -> Self {
        Message {
            msg_type: MsgType::InstallSnapshot,
            commit_index: leader_commit,
            snap_total: snapshot.data.len() as u64,
            snapshot: Some(snapshot.clone()),
            ..Self::request_vote(from, to, term, snapshot.index, snapshot.term)
        }
    }
    /// The part `data[offset..end]` of the leader's snapshot. A chunk that is
    /// the whole of it shares the snapshot; any other copies its bytes.
    /// `offset <= end <= data.len()`.
    pub fn install_snapshot_chunk(
        from: NodeId,
        to: NodeId,
        term: Term,
        snapshot: &Arc<Snapshot>,
        (offset, end): (usize, usize),
        leader_commit: Index,
    ) -> Self {
        let whole = (offset == 0) & (end == snapshot.data.len());
        let chunk = match whole {
            true => snapshot.clone(),
            false => Arc::new(Snapshot {
                data: snapshot.data[offset..end].to_vec(),
                voters: snapshot.voters.clone(),
                ..**snapshot
            }),
        };
        Message {
            snap_offset: offset as u64,
            snap_total: snapshot.data.len() as u64,
            ..Self::install_snapshot(from, to, term, chunk, leader_commit)
        }
    }
    /// `match_index` is the last index known to match the leader's log.
    pub fn install_snapshot_reply(from: NodeId, to: NodeId, term: Term, success: bool, match_index: Index) -> Self {
        Message {
            msg_type: MsgType::InstallSnapshotReply,
            ..Self::append_entries_reply(from, to, term, success, match_index)
        }
    }
    /// "I have `offset` of the `total` bytes of the snapshot that ends at
    /// `index`; send the rest from there." `offset < total`.
    pub fn install_snapshot_progress(
        from: NodeId,
        to: NodeId,
        term: Term,
        index: Index,
        (offset, total): (u64, u64),
    ) -> Self {
        Message {
            last_log_index: index,
            snap_offset: offset,
            snap_total: total,
            ..Self::install_snapshot_reply(from, to, term, true, 0)
        }
    }
    /// A pre-vote asks for `term`, the term the sender would campaign in.
    pub fn pre_vote(from: NodeId, to: NodeId, term: Term, last_idx: Index, last_term: Term) -> Self {
        Message {
            msg_type: MsgType::PreVote,
            ..Self::request_vote(from, to, term, last_idx, last_term)
        }
    }
    /// A grant carries the asked-for term, a refusal the sender's own term.
    pub fn pre_vote_reply(from: NodeId, to: NodeId, term: Term, granted: bool) -> Self {
        Message {
            msg_type: MsgType::PreVoteReply,
            ..Self::request_vote_reply(from, to, term, granted)
        }
    }
    pub fn request_vote_reply(from: NodeId, to: NodeId, term: Term, granted: bool) -> Self {
        Message {
            msg_type: MsgType::RequestVoteReply,
            from,
            to,
            term,
            last_log_index: 0,
            last_log_term: 0,
            entries: Vec::new(),
            commit_index: 0,
            vote_granted: granted,
            match_index: 0,
            success: false,
            leader_last_index: 0,
            read_ctx: 0,
            snapshot: None,
            snap_offset: 0,
            snap_total: 0,
            lc: 0,
        }
    }
    pub fn append_entries(
        from: NodeId,
        to: NodeId,
        term: Term,
        prev_idx: Index,
        prev_term: Term,
        entries: Vec<crate::LogEntry>,
        leader_commit: Index,
    ) -> Self {
        Message {
            msg_type: MsgType::AppendEntries,
            from,
            to,
            term,
            last_log_index: prev_idx,
            last_log_term: prev_term,
            entries,
            commit_index: leader_commit,
            vote_granted: false,
            match_index: 0,
            success: false,
            leader_last_index: 0,
            read_ctx: 0,
            snapshot: None,
            snap_offset: 0,
            snap_total: 0,
            lc: 0,
        }
    }
    pub fn append_entries_reply(from: NodeId, to: NodeId, term: Term, success: bool, match_index: Index) -> Self {
        Message {
            msg_type: MsgType::AppendEntriesReply,
            from,
            to,
            term,
            last_log_index: 0,
            last_log_term: 0,
            entries: Vec::new(),
            commit_index: 0,
            vote_granted: false,
            match_index,
            success,
            leader_last_index: 0,
            read_ctx: 0,
            snapshot: None,
            snap_offset: 0,
            snap_total: 0,
            lc: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructors() {
        let m = Message::request_vote(1, 2, 3, 10, 2);
        assert_eq!(m.last_log_index, 10);
        assert!(Message::request_vote_reply(2, 1, 3, true).vote_granted);
        let e = vec![crate::LogEntry::new(5, 3, vec![1])];
        let a = Message::append_entries(1, 2, 3, 4, 2, e.clone(), 4);
        assert_eq!(a.entries, e);
        assert_eq!(a.commit_index, 4);
        let r = Message::append_entries_reply(2, 1, 3, true, 5);
        assert!(r.success && r.match_index == 5);
        let p = Message::pre_vote(1, 2, 4, 10, 2);
        assert_eq!((p.msg_type, p.term, p.last_log_index), (MsgType::PreVote, 4, 10));
        let p = Message::pre_vote_reply(2, 1, 4, true);
        assert_eq!((p.msg_type, p.vote_granted), (MsgType::PreVoteReply, true));
        let snap = Arc::new(Snapshot {
            index: 10,
            term: 3,
            voters: vec![1, 2],
            data: vec![7],
        });
        let s = Message::install_snapshot(1, 2, 4, snap.clone(), 9);
        assert_eq!(s.msg_type, MsgType::InstallSnapshot);
        assert_eq!((s.last_log_index, s.last_log_term, s.commit_index), (10, 3, 9));
        assert_eq!(s.snapshot, Some(snap));
        assert_eq!((s.snap_offset, s.snap_total), (0, 1));
        let s = Message::install_snapshot_reply(2, 1, 4, true, 10);
        assert_eq!(
            (s.msg_type, s.success, s.match_index),
            (MsgType::InstallSnapshotReply, true, 10)
        );
        assert_eq!((s.snap_offset, s.snap_total), (0, 0));
    }

    #[test]
    fn snapshot_chunks_and_progress() {
        let snap = Arc::new(Snapshot {
            index: 10,
            term: 3,
            voters: vec![1, 2],
            data: b"abcdef".to_vec(),
        });
        // The whole snapshot is shared, not copied.
        let whole = Message::install_snapshot_chunk(1, 2, 4, &snap, (0, 6), 9);
        assert!(Arc::ptr_eq(whole.snapshot.as_ref().unwrap(), &snap));
        assert_eq!(whole, Message::install_snapshot(1, 2, 4, snap.clone(), 9));
        // A part carries the metadata and its bytes, and says where it is.
        let part = Message::install_snapshot_chunk(1, 2, 4, &snap, (2, 5), 9);
        let chunk = part.snapshot.as_ref().unwrap();
        assert_eq!((chunk.index, chunk.term, &chunk.voters), (10, 3, &vec![1, 2]));
        assert_eq!(chunk.data, b"cde");
        assert_eq!((part.snap_offset, part.snap_total), (2, 6));
        assert_eq!(
            (part.msg_type, part.last_log_index, part.last_log_term),
            (MsgType::InstallSnapshot, 10, 3)
        );
        assert_eq!(part.commit_index, 9);
        // An empty snapshot is a whole one.
        let empty = Arc::new(Snapshot::default());
        let m = Message::install_snapshot_chunk(1, 2, 4, &empty, (0, 0), 0);
        assert!(Arc::ptr_eq(m.snapshot.as_ref().unwrap(), &empty));
        // Progress.
        let p = Message::install_snapshot_progress(2, 1, 4, 10, (3, 6));
        assert_eq!(
            (p.msg_type, p.success, p.match_index),
            (MsgType::InstallSnapshotReply, true, 0)
        );
        assert_eq!((p.last_log_index, p.snap_offset, p.snap_total), (10, 3, 6));
        assert!(p.snapshot.is_none());
    }
}
