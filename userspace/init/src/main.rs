#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, yield_now};

pub const VFS_ENDPOINT: u64 = 10;
pub const NET_ENDPOINT: u64 = 20;
pub const CRYPTO_ENDPOINT: u64 = 25;
pub const AUDIT_ENDPOINT: u64 = 35;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Query Node Cryptographic Identity from Ring 3 Crypto Server
    let (_status, _pk_word0, _, _) = ipc_call(CRYPTO_ENDPOINT, 1, 0, 0, 0);

    // 2. Perform Initial Health Ping to Virtual Filesystem (VFS)
    let (_vfs_status, _, _, _) = ipc_call(VFS_ENDPOINT, 1, 0, 0, 0);

    // 3. Propose Initial Distributed Capability Token to Network Server
    let (_net_status, _log_idx, _term, _) = ipc_call(NET_ENDPOINT, 0xC1, 10, 0b1111, 0);

    // 4. Query Audit Telemetry Daemon
    let (_audit_status, _total_events, _tripwires, _) = ipc_call(AUDIT_ENDPOINT, 1, 0, 0, 0);

    // 5. Enter root process event loop, yielding quantum periodically
    loop {
        yield_now();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
