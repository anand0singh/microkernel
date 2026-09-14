#![no_std]
#![no_main]

mod crypto_xts;

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};
use crypto_xts::XtsAes256;

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

    let cipher = XtsAes256::new(
        [0x42; crypto_xts::KEY_SIZE],
        [0x99; crypto_xts::KEY_SIZE],
    );

    loop {
        // Wait for incoming IPC request
        let (request_op, block_idx, expected_hash_low, expected_hash_high) = ipc_recv(endpoint_cap);

        if request_op == 1 {
            // Read Block Request: Decrypt sector and verify Merkle integrity
            let mut chunk = [0u8; BLOCK_SIZE];
            chunk[0] = block_idx as u8;

            cipher.decrypt_sector(block_idx, &mut chunk);

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
        } else if request_op == 2 {
            // Write Block Request: Encrypt sector with XTS-AES-256
            let mut chunk = [0u8; BLOCK_SIZE];
            chunk[0] = block_idx as u8;

            let digest = simple_block_hash(&chunk);
            cipher.encrypt_sector(block_idx, &mut chunk);

            let hash_low = u64::from_le_bytes(digest[0..8].try_into().unwrap());
            let hash_high = u64::from_le_bytes(digest[8..16].try_into().unwrap());
            ipc_call(endpoint_cap, 0, block_idx, hash_low, hash_high);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
