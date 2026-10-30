//! Raft wire messages (transport-agnostic). Every message carries the
//! sender's Lamport timestamp `lc` (set by the node when it is sent).

use crate::{Index, NodeId, Term};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    RequestVote,
    RequestVoteReply,
    AppendEntries,
    AppendEntriesReply,
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
            lc: 0,
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
    }
}
