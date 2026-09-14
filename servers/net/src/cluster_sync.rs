pub const MAX_CLUSTER_NODES: usize = 8;
pub const MAX_LOG_ENTRIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

#[derive(Clone, Copy)]
pub struct DistributedCapEntry {
    pub term: u64,
    pub node_id: u32,
    pub cap_slot: u64,
    pub rights_mask: u8,
    pub valid: bool,
}

impl DistributedCapEntry {
    pub const fn empty() -> Self {
        Self {
            term: 0,
            node_id: 0,
            cap_slot: 0,
            rights_mask: 0,
            valid: false,
        }
    }
}

pub struct ClusterConsensusEngine {
    pub local_node_id: u32,
    pub current_term: u64,
    pub voted_for: Option<u32>,
    pub role: RaftRole,
    pub log: [DistributedCapEntry; MAX_LOG_ENTRIES],
    pub log_len: usize,
    pub commit_index: usize,
}

impl ClusterConsensusEngine {
    pub const fn new(local_node_id: u32) -> Self {
        Self {
            local_node_id,
            current_term: 1,
            voted_for: None,
            role: RaftRole::Follower,
            log: [const { DistributedCapEntry::empty() }; MAX_LOG_ENTRIES],
            log_len: 0,
            commit_index: 0,
        }
    }

    /// Process incoming vote request from a candidate node
    pub fn handle_request_vote(&mut self, candidate_term: u64, candidate_id: u32) -> bool {
        if candidate_term > self.current_term {
            self.current_term = candidate_term;
            self.role = RaftRole::Follower;
            self.voted_for = None;
        }

        if candidate_term >= self.current_term && (self.voted_for.is_none() || self.voted_for == Some(candidate_id)) {
            self.voted_for = Some(candidate_id);
            true // Vote granted
        } else {
            false // Vote rejected
        }
    }

    /// Propose a new capability authorization across the distributed cluster (Leader only)
    pub fn propose_capability(&mut self, cap_slot: u64, rights_mask: u8) -> Result<usize, ()> {
        if self.role != RaftRole::Leader {
            return Err(());
        }

        if self.log_len >= MAX_LOG_ENTRIES {
            return Err(());
        }

        let entry = DistributedCapEntry {
            term: self.current_term,
            node_id: self.local_node_id,
            cap_slot,
            rights_mask,
            valid: true,
        };

        self.log[self.log_len] = entry;
        let entry_idx = self.log_len;
        self.log_len += 1;
        self.commit_index = self.log_len; // Quorum committed in single-node/local cluster
        Ok(entry_idx)
    }

    /// AppendEntries RPC: Replicate remote leader's capability log entry
    pub fn handle_append_entries(
        &mut self,
        leader_term: u64,
        leader_id: u32,
        entry: DistributedCapEntry,
    ) -> bool {
        if leader_term < self.current_term {
            return false;
        }

        self.current_term = leader_term;
        self.role = RaftRole::Follower;
        self.voted_for = Some(leader_id);

        if self.log_len < MAX_LOG_ENTRIES {
            self.log[self.log_len] = entry;
            self.log_len += 1;
            self.commit_index = self.log_len;
            true
        } else {
            false
        }
    }
}
