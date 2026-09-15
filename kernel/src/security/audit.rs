use spin::Mutex;

pub const AUDIT_BUFFER_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Allowed = 0,
    Denied = 1,
    Revoked = 2,
    TripwireTriggered = 3,
}

#[derive(Clone, Copy)]
pub struct AuditEvent {
    pub timestamp_tick: u64,
    pub caller_thread_id: u64,
    pub cap_ptr: u64,
    pub op: u64,
    pub verdict: AuditVerdict,
    pub prev_hash: [u8; 16],
    pub chain_hash: [u8; 16],
}

pub fn compute_event_hash(
    prev_hash: [u8; 16],
    tick: u64,
    caller: u64,
    cap: u64,
    op: u64,
    verdict: u64,
) -> [u8; 16] {
    let mut h0 = u64::from_le_bytes(prev_hash[0..8].try_into().unwrap_or([0; 8]));
    let mut h1 = u64::from_le_bytes(prev_hash[8..16].try_into().unwrap_or([0; 8]));

    // Constant-time avalanche mixing
    h0 = h0.wrapping_add(tick).rotate_left(13) ^ 0x517cc1b727220a95;
    h1 = h1.wrapping_add(caller).rotate_left(17) ^ 0x9e3779b97f4a7c15;
    h0 = h0.wrapping_add(cap).rotate_left(23) ^ 0xbf58476d1ce4e5b9;
    h1 = h1.wrapping_add(op).rotate_left(29) ^ 0x94d049bb133111eb;
    h0 = h0.wrapping_add(verdict).rotate_left(31) ^ h1;
    h1 = h1.rotate_left(7) ^ h0;

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&h0.to_le_bytes());
    out[8..16].copy_from_slice(&h1.to_le_bytes());
    out
}

impl AuditEvent {
    pub const fn empty() -> Self {
        Self {
            timestamp_tick: 0,
            caller_thread_id: 0,
            cap_ptr: 0,
            op: 0,
            verdict: AuditVerdict::Allowed,
            prev_hash: [0u8; 16],
            chain_hash: [0u8; 16],
        }
    }
}

pub struct AuditRingBuffer {
    pub events: [AuditEvent; AUDIT_BUFFER_CAPACITY],
    pub head: usize,
    pub total_logged: u64,
    pub current_chain_hash: [u8; 16],
}

impl AuditRingBuffer {
    pub const fn new() -> Self {
        Self {
            events: [const { AuditEvent::empty() }; AUDIT_BUFFER_CAPACITY],
            head: 0,
            total_logged: 0,
            current_chain_hash: [0x5A; 16], // Pre-seeded genesis hash
        }
    }

    pub fn record(&mut self, caller_thread_id: u64, cap_ptr: u64, op: u64, verdict: AuditVerdict) {
        let prev = self.current_chain_hash;
        let tick = self.total_logged;
        let new_hash = compute_event_hash(prev, tick, caller_thread_id, cap_ptr, op, verdict as u64);

        let idx = self.head % AUDIT_BUFFER_CAPACITY;
        self.events[idx] = AuditEvent {
            timestamp_tick: tick,
            caller_thread_id,
            cap_ptr,
            op,
            verdict,
            prev_hash: prev,
            chain_hash: new_hash,
        };
        self.head = (self.head + 1) % AUDIT_BUFFER_CAPACITY;
        self.total_logged += 1;
        self.current_chain_hash = new_hash;
    }

    pub fn latest_event(&self) -> Option<AuditEvent> {
        if self.total_logged == 0 {
            None
        } else {
            let last_idx = (self.head + AUDIT_BUFFER_CAPACITY - 1) % AUDIT_BUFFER_CAPACITY;
            Some(self.events[last_idx])
        }
    }

    pub fn verify_chain_integrity(&self) -> bool {
        let count = core::cmp::min(self.total_logged as usize, AUDIT_BUFFER_CAPACITY);
        if count <= 1 {
            return true;
        }

        let start_pos = if self.total_logged as usize > AUDIT_BUFFER_CAPACITY {
            self.head
        } else {
            0
        };

        let mut prev = self.events[start_pos].chain_hash;
        for i in 1..count {
            let idx = (start_pos + i) % AUDIT_BUFFER_CAPACITY;
            let ev = &self.events[idx];
            if ev.prev_hash != prev {
                return false;
            }
            let expected = compute_event_hash(
                ev.prev_hash,
                ev.timestamp_tick,
                ev.caller_thread_id,
                ev.cap_ptr,
                ev.op,
                ev.verdict as u64,
            );
            if ev.chain_hash != expected {
                return false;
            }
            prev = ev.chain_hash;
        }
        true
    }
}

pub static AUDIT_LOG: Mutex<AuditRingBuffer> = Mutex::new(AuditRingBuffer::new());

