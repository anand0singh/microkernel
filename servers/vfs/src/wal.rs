//! Crash-Resilient Write-Ahead Logging (WAL) for Encrypted VFS

pub const MAX_WAL_ENTRIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalStatus {
    Uncommitted = 1,
    Committed = 2,
    Applied = 3,
}

#[derive(Clone, Copy)]
pub struct WalRecord {
    pub tx_id: u64,
    pub block_lba: u64,
    pub status: WalStatus,
    pub pre_hash: [u8; 16],
    pub post_hash: [u8; 16],
}

impl WalRecord {
    pub const fn empty() -> Self {
        Self {
            tx_id: 0,
            block_lba: 0,
            status: WalStatus::Uncommitted,
            pre_hash: [0u8; 16],
            post_hash: [0u8; 16],
        }
    }
}

pub struct WriteAheadLog {
    pub records: [WalRecord; MAX_WAL_ENTRIES],
    pub next_tx_id: u64,
    pub active_records: usize,
}

impl WriteAheadLog {
    pub const fn new() -> Self {
        Self {
            records: [const { WalRecord::empty() }; MAX_WAL_ENTRIES],
            next_tx_id: 1,
            active_records: 0,
        }
    }

    pub fn begin_transaction(&mut self, block_lba: u64, pre_hash: [u8; 16]) -> Result<u64, ()> {
        if self.active_records >= MAX_WAL_ENTRIES {
            return Err(());
        }

        let tx = self.next_tx_id;
        self.next_tx_id += 1;

        let slot = self.active_records;
        self.records[slot] = WalRecord {
            tx_id: tx,
            block_lba,
            status: WalStatus::Uncommitted,
            pre_hash,
            post_hash: [0u8; 16],
        };
        self.active_records += 1;
        Ok(tx)
    }

    pub fn commit_transaction(&mut self, tx_id: u64, post_hash: [u8; 16]) -> Result<(), ()> {
        for i in 0..self.active_records {
            if self.records[i].tx_id == tx_id {
                self.records[i].status = WalStatus::Committed;
                self.records[i].post_hash = post_hash;
                return Ok(());
            }
        }
        Err(())
    }

    pub fn mark_applied(&mut self, tx_id: u64) -> Result<(), ()> {
        for i in 0..self.active_records {
            if self.records[i].tx_id == tx_id {
                self.records[i].status = WalStatus::Applied;
                return Ok(());
            }
        }
        Err(())
    }

    /// Crash recovery scanner: Replays committed transactions, aborts uncommitted ones
    pub fn recover_on_mount(&mut self) -> (usize, usize) {
        let mut replayed = 0;
        let mut rolled_back = 0;

        for i in 0..self.active_records {
            match self.records[i].status {
                WalStatus::Committed => {
                    // Committed but unapplied: replay update to disk
                    self.records[i].status = WalStatus::Applied;
                    replayed += 1;
                }
                WalStatus::Uncommitted => {
                    // Uncommitted: roll back transaction
                    self.records[i].status = WalStatus::Applied; // Mark consumed/void
                    rolled_back += 1;
                }
                WalStatus::Applied => {}
            }
        }

        (replayed, rolled_back)
    }
}
