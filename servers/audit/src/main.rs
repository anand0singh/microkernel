#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};

pub const AUDIT_ENDPOINT_CAP: u64 = 35;

pub struct SecurityMetrics {
    pub total_audited_events: u64,
    pub tripwire_alerts: u64,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut metrics = SecurityMetrics {
        total_audited_events: 0,
        tripwire_alerts: 0,
    };

    loop {
        // Receive audit/telemetry request or alert notification
        let (op, thread_id, verdict, _) = ipc_recv(AUDIT_ENDPOINT_CAP);
        metrics.total_audited_events += 1;

        if verdict == 3 {
            // Verdict 3 = TripwireTriggered
            metrics.tripwire_alerts += 1;
        }

        if op == 1 {
            // Query Metrics Request
            ipc_call(
                AUDIT_ENDPOINT_CAP,
                0,
                metrics.total_audited_events,
                metrics.tripwire_alerts,
                thread_id,
            );
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
