#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, cap_invoke};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Initial Userspace Orchestrator (Ring 3)
    let service_endpoint = 10;

    // 1. Invoke initial capability rendezvous
    let (res, _, _, _) = ipc_call(service_endpoint, 1, 42, 100, 200);

    // 2. Loop continuously in Ring 3
    loop {
        cap_invoke(0, 0, 0, 0, 0);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
