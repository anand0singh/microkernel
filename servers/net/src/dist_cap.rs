use libsys::ipc_call;
use spin::Mutex;

#[derive(Clone, Copy)]
pub struct RemoteEndpointCap {
    pub target_node_id: [u8; 32],
    pub remote_token: [u8; 32],
}

pub struct ExportedCapTableEntry {
    pub token: [u8; 32],
    pub local_cnode_slot: u64,
    pub valid: bool,
}

pub static EXPORTED_CAP_TABLE: Mutex<[ExportedCapTableEntry; 32]> = Mutex::new([const {
    ExportedCapTableEntry {
        token: [0; 32],
        local_cnode_slot: 0,
        valid: false,
    }
}; 32]);

pub fn register_exported_cap(token: [u8; 32], local_cnode_slot: u64) -> Result<(), ()> {
    let mut table = EXPORTED_CAP_TABLE.lock();
    for entry in table.iter_mut() {
        if !entry.valid {
            *entry = ExportedCapTableEntry {
                token,
                local_cnode_slot,
                valid: true,
            };
            return Ok(());
        }
    }
    Err(())
}

pub fn handle_remote_cap_invocation(
    token: &[u8; 32],
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> (u64, u64, u64, u64) {
    // 1. Verify incoming capability token in Exported Capability Table
    let table = EXPORTED_CAP_TABLE.lock();
    for entry in table.iter() {
        if entry.valid && entry.token == *token {
            let slot = entry.local_cnode_slot;
            drop(table);
            // Token valid! Invoke target local capability via microkernel IPC
            return ipc_call(slot, arg0, arg1, arg2, arg3);
        }
    }

    (0xFFFF_FFFF_FFFF_FFFF, 0, 0, 0) // Invalid token error
}
