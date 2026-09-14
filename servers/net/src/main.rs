#![no_std]
#![no_main]

mod cluster_sync;
mod dist_cap;

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let net_endpoint_cap = 20;
    let mut consensus = cluster_sync::ClusterConsensusEngine::new(1);
    consensus.role = cluster_sync::RaftRole::Leader; // Default local bootstrap node

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
        } else if op == 0xC1 {
            // Op 0xC1: Propose distributed capability into replicated cluster log
            let cap_slot = token_low;
            let rights_mask = token_high as u8;
            let log_idx = consensus.propose_capability(cap_slot, rights_mask).unwrap_or(0);
            ipc_call(net_endpoint_cap, 0, log_idx as u64, consensus.current_term, 0);
        } else if op == 0xC2 {
            // Op 0xC2: Replicate capability entry from peer leader
            let entry = cluster_sync::DistributedCapEntry {
                term: token_high,
                node_id: arg0 as u32,
                cap_slot: token_low,
                rights_mask: 0b1111,
                valid: true,
            };
            let success = consensus.handle_append_entries(token_high, arg0 as u32, entry);
            ipc_call(net_endpoint_cap, if success { 0 } else { 1 }, consensus.commit_index as u64, 0, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
