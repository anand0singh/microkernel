#![no_std]
#![no_main]

mod dist_cap;

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let net_endpoint_cap = 20;

    loop {
        // Network packet rx / Cap-over-wire event loop
        let (op, token_low, token_high, arg0) = ipc_recv(net_endpoint_cap);

        if op == 0xCC {
            // Remote Cap-Over-Wire Invocation event
            let mut token = [0u8; 32];
            token[0..8].copy_from_slice(&token_low.to_le_bytes());
            token[8..16].copy_from_slice(&token_high.to_le_bytes());

            let (r0, r1, r2, r3) = dist_cap::handle_remote_cap_invocation(&token, arg0, 0, 0, 0);
            ipc_call(net_endpoint_cap, r0, r1, r2, r3);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
