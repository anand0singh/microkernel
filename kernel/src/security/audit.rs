use spin::Mutex;

pub const AUDIT_BUFFER_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    Allowed,
    Denied,
    Revoked,
    TripwireTriggered,
}

#[derive(Clone, Copy)]
pub struct AuditEvent {
    pub timestamp_tick: u64,
    pub caller_thread_id: u64,
    pub cap_ptr: u64,
    pub op: u64,
    pub verdict: AuditVerdict,
}

impl AuditEvent {
    pub const fn empty() -> Self {
        Self {
            timestamp_tick: 0,
            caller_thread_id: 0,
            cap_ptr: 0,
            op: 0,
            verdict: AuditVerdict::Allowed,
        }
    }
}

pub struct AuditRingBuffer {
    pub events: [AuditEvent; AUDIT_BUFFER_CAPACITY],
    pub head: usize,
    pub total_logged: u64,
}

impl AuditRingBuffer {
    pub const fn new() -> Self {
        Self {
            events: [const { AuditEvent::empty() }; AUDIT_BUFFER_CAPACITY],
            head: 0,
            total_logged: 0,
        }
    }

    pub fn record(&mut self, caller_thread_id: u64, cap_ptr: u64, op: u64, verdict: AuditVerdict) {
        let idx = self.head % AUDIT_BUFFER_CAPACITY;
        self.events[idx] = AuditEvent {
            timestamp_tick: self.total_logged,
            caller_thread_id,
            cap_ptr,
            op,
            verdict,
        };
        self.head = (self.head + 1) % AUDIT_BUFFER_CAPACITY;
        self.total_logged += 1;
    }

    pub fn latest_event(&self) -> Option<AuditEvent> {
        if self.total_logged == 0 {
            None
        } else {
            let last_idx = (self.head + AUDIT_BUFFER_CAPACITY - 1) % AUDIT_BUFFER_CAPACITY;
            Some(self.events[last_idx])
        }
    }
}

pub static AUDIT_LOG: Mutex<AuditRingBuffer> = Mutex::new(AuditRingBuffer::new());
