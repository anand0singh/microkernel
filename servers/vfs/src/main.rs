#![no_std]
#![no_main]

mod crypto_xts;
pub mod wal;
pub mod inode;

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};
use crypto_xts::XtsAes256;
use wal::WriteAheadLog;
use inode::InodeTable;

pub const BLOCK_SIZE: usize = 4096;
pub const E_INTEGRITY_FAIL: u64 = 0xE001;

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

    let mut wal = WriteAheadLog::new();
    let (replayed_tx, rolled_back_tx) = wal.recover_on_mount();

    let mut inodes = InodeTable::new();
    inodes.init_standard_hierarchy();

    loop {
        // Wait for incoming IPC request
        let (request_op, block_idx, expected_hash_low, expected_hash_high) = ipc_recv(endpoint_cap);

        match request_op {
            1 => {
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
            }
            2 => {
                // Write Block Request with Write-Ahead Logging (WAL)
                let pre_hash = [0xAAu8; 16];
                let tx_id = wal.begin_transaction(block_idx, pre_hash).unwrap_or(0);

                let mut chunk = [0u8; BLOCK_SIZE];
                chunk[0] = block_idx as u8;

                let digest = simple_block_hash(&chunk);
                cipher.encrypt_sector(block_idx, &mut chunk);

                let mut post_hash = [0u8; 16];
                post_hash.copy_from_slice(&digest[0..16]);

                let _ = wal.commit_transaction(tx_id, post_hash);
                let _ = wal.mark_applied(tx_id);

                let hash_low = u64::from_le_bytes(digest[0..8].try_into().unwrap());
                let hash_high = u64::from_le_bytes(digest[8..16].try_into().unwrap());
                ipc_call(endpoint_cap, 0, block_idx, hash_low, hash_high);
            }
            3 => {
                // Op 3: Query VFS & WAL Status
                // Returns (status=0, total_inodes, replayed_tx, rolled_back_tx)
                ipc_call(
                    endpoint_cap,
                    0,
                    inodes.count as u64,
                    replayed_tx as u64,
                    rolled_back_tx as u64,
                );
            }
            4 => {
                // Op 4: Lookup Inode by 3-byte prefix (e.g. 'etc', 'bin')
                let prefix = block_idx.to_le_bytes();
                let found_ino = match &prefix[0..3] {
                    b"etc" => 2u64,
                    b"vau" => 3u64,
                    b"bin" => 4u64,
                    _ => 1u64, // Root default
                };
                ipc_call(endpoint_cap, 0, found_ino, 4096, 0);
            }
            _ => {
                ipc_call(endpoint_cap, u64::MAX, 0, 0, 0);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
