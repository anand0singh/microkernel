#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};

pub const BLOCK_SIZE: usize = 4096;
pub const E_INTEGRITY_FAIL: u64 = 0xE001;

pub struct MerkleNode {
    pub hash: [u8; 32],
    pub left_child: Option<usize>,
    pub right_child: Option<usize>,
}

pub fn simple_block_hash(data: &[u8; BLOCK_SIZE]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let mut sum: u64 = 0x811c9dc5;
    for &b in data.iter() {
        sum = (sum ^ (b as u64)).wrapping_mul(0x01000193);
    }
    hash[0..8].copy_from_slice(&sum.to_le_bytes());
    hash[8..16].copy_from_slice(&(!sum).to_le_bytes());
    hash
}

pub fn verify_chunk_integrity(chunk: &[u8; BLOCK_SIZE], expected_hash: &[u8; 32]) -> bool {
    let computed = simple_block_hash(chunk);
    computed == *expected_hash
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let endpoint_cap = 10; // Shared VFS Endpoint Capability Slot

    loop {
        // Wait for incoming IPC read request
        let (request_op, block_idx, expected_hash_low, expected_hash_high) = ipc_recv(endpoint_cap);

        if request_op == 1 {
            // Read Block Request
            let mut chunk = [0u8; BLOCK_SIZE];
            // Simulate chunk read from physical storage driver
            chunk[0] = block_idx as u8;

            let mut expected_hash = [0u8; 32];
            expected_hash[0..8].copy_from_slice(&expected_hash_low.to_le_bytes());
            expected_hash[8..16].copy_from_slice(&expected_hash_high.to_le_bytes());

            let is_valid = verify_chunk_integrity(&chunk, &expected_hash);

            if !is_valid {
                // Return E_INTEGRITY_FAIL response to caller
                ipc_call(endpoint_cap, E_INTEGRITY_FAIL, 0, 0, 0);
            } else {
                ipc_call(endpoint_cap, 0, block_idx, 0, 0);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
