//! Raft wire messages (transport-agnostic). Every message carries the
//! sender's Lamport timestamp `lc` (set by the node when it is sent).

use crate::{Index, NodeId, Term};

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
    /// its snapshot instead. `last_log_index` and `last_log_term` name the
    /// last entry it covers, `snapshot_data` is the state machine.
    InstallSnapshot,
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
    /// InstallSnapshot: the serialized state machine.
    pub snapshot_data: Vec<u8>,
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
            snapshot_data: Vec::new(),
            lc: 0,
        }
    }
    /// The leader's snapshot, covering entries up to `(index, snapshot_term)`.
    pub fn install_snapshot(
        from: NodeId,
        to: NodeId,
        term: Term,
        index: Index,
        snapshot_term: Term,
        data: Vec<u8>,
        leader_commit: Index,
    ) -> Self {
        Message {
            msg_type: MsgType::InstallSnapshot,
            commit_index: leader_commit,
            snapshot_data: data,
            ..Self::request_vote(from, to, term, index, snapshot_term)
        }
    }
    /// `match_index` is the last index known to match the leader's log.
    pub fn install_snapshot_reply(from: NodeId, to: NodeId, term: Term, success: bool, match_index: Index) -> Self {
        Message {
            msg_type: MsgType::InstallSnapshotReply,
            ..Self::append_entries_reply(from, to, term, success, match_index)
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
            snapshot_data: Vec::new(),
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
            snapshot_data: Vec::new(),
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
            snapshot_data: Vec::new(),
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
        let e = vec![crate::LogEntry {
            index: 5,
            term: 3,
            data: vec![1],
        }];
        let a = Message::append_entries(1, 2, 3, 4, 2, e.clone(), 4);
        assert_eq!(a.entries, e);
        assert_eq!(a.commit_index, 4);
        let r = Message::append_entries_reply(2, 1, 3, true, 5);
        assert!(r.success && r.match_index == 5);
        let p = Message::pre_vote(1, 2, 4, 10, 2);
        assert_eq!((p.msg_type, p.term, p.last_log_index), (MsgType::PreVote, 4, 10));
        let p = Message::pre_vote_reply(2, 1, 4, true);
        assert_eq!((p.msg_type, p.vote_granted), (MsgType::PreVoteReply, true));
        let s = Message::install_snapshot(1, 2, 4, 10, 3, vec![7], 9);
        assert_eq!(s.msg_type, MsgType::InstallSnapshot);
        assert_eq!((s.last_log_index, s.last_log_term, s.commit_index), (10, 3, 9));
        assert_eq!(s.snapshot_data, vec![7]);
        let s = Message::install_snapshot_reply(2, 1, 4, true, 10);
        assert_eq!(
            (s.msg_type, s.success, s.match_index),
            (MsgType::InstallSnapshotReply, true, 10)
        );
    }
}
