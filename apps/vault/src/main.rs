#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, cap_invoke};

pub const VFS_ENDPOINT: u64 = 10;
pub const CRYPTO_ENDPOINT: u64 = 25;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Authenticate with Crypto Daemon via capability IPC
    let (_status, pubkey_low, _, _) = ipc_call(CRYPTO_ENDPOINT, 1, 0, 0, 0);

    // 2. Persist a confidential vault record into the Encrypted VFS
    // Op 2 = Write Block (triggering XTS-AES-256 encryption + Merkle computation)
    let secret_block_idx = 42;
    let (_vfs_status, _stored_idx, _hash_low, _hash_high) =
        ipc_call(VFS_ENDPOINT, 2, secret_block_idx, pubkey_low, 0);

    // 3. Sandboxed execution loop - non-essential syscalls are filtered out
    loop {
        cap_invoke(0, 0, 0, 0, 0);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
