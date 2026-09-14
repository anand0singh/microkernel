use spin::Mutex;
use super::audit::{AUDIT_LOG, AuditVerdict};

pub const MAX_MONITORED_THREADS: usize = 32;
pub const ANOMALY_TRIPWIRE_THRESHOLD: u32 = 5;

#[derive(Clone, Copy)]
pub struct ThreadSecurityProfile {
    pub thread_id: u64,
    pub violation_count: u32,
    pub quarantined: bool,
}

impl ThreadSecurityProfile {
    pub const fn new() -> Self {
        Self {
            thread_id: 0,
            violation_count: 0,
            quarantined: false,
        }
    }
}

pub struct IntrusionDetectionEngine {
    pub profiles: [ThreadSecurityProfile; MAX_MONITORED_THREADS],
}

impl IntrusionDetectionEngine {
    pub const fn new() -> Self {
        Self {
            profiles: [const { ThreadSecurityProfile::new() }; MAX_MONITORED_THREADS],
        }
    }

    pub fn record_violation(&mut self, thread_id: u64, cap_ptr: u64, op: u64) -> bool {
        let slot = (thread_id as usize) % MAX_MONITORED_THREADS;
        let profile = &mut self.profiles[slot];
        profile.thread_id = thread_id;
        profile.violation_count += 1;

        if profile.violation_count >= ANOMALY_TRIPWIRE_THRESHOLD {
            profile.quarantined = true;
            AUDIT_LOG.lock().record(thread_id, cap_ptr, op, AuditVerdict::TripwireTriggered);
            true // Tripwire triggered! Thread quarantined
        } else {
            AUDIT_LOG.lock().record(thread_id, cap_ptr, op, AuditVerdict::Denied);
            false
        }
    }

    pub fn is_quarantined(&self, thread_id: u64) -> bool {
        let slot = (thread_id as usize) % MAX_MONITORED_THREADS;
        self.profiles[slot].thread_id == thread_id && self.profiles[slot].quarantined
    }

    pub fn reset_profile(&mut self, thread_id: u64) {
        let slot = (thread_id as usize) % MAX_MONITORED_THREADS;
        self.profiles[slot] = ThreadSecurityProfile::new();
    }
}

pub static IDS_ENGINE: Mutex<IntrusionDetectionEngine> = Mutex::new(IntrusionDetectionEngine::new());
