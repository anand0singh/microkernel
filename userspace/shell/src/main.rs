#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, install_filter_rule, lock_filter};

pub const VFS_ENDPOINT: u64 = 10;
pub const NET_ENDPOINT: u64 = 20;
pub const CRYPTO_ENDPOINT: u64 = 25;
pub const KEYSTORE_ENDPOINT: u64 = 40;
pub const AUDIT_ENDPOINT: u64 = 35;
pub const DRIVER_NET_ENDPOINT: u64 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCommand {
    QueryAuditStats,
    QueryClusterTerm,
    QueryCryptoIdentity,
    QueryVfsStats,
    LookupVfsInode,
    QueryKeystoreStatus,
    QueryNetMac,
    LockSeccompFilter,
}

pub fn execute_shell_command(cmd: ShellCommand) -> (u64, u64, u64, u64) {
    match cmd {
        ShellCommand::QueryAuditStats => {
            // Op 1 on Audit endpoint -> returns (status, total_events, tripwire_alerts, caller_id)
            ipc_call(AUDIT_ENDPOINT, 1, 0, 0, 0)
        }
        ShellCommand::QueryClusterTerm => {
            // Op 0xC1 on Net endpoint -> proposes distributed cap, returns (status, log_idx, current_term, 0)
            ipc_call(NET_ENDPOINT, 0xC1, 10, 0b1111, 0)
        }
        ShellCommand::QueryCryptoIdentity => {
            // Op 1 on Crypto endpoint -> returns NodeID public key word
            ipc_call(CRYPTO_ENDPOINT, 1, 0, 0, 0)
        }
        ShellCommand::QueryVfsStats => {
            // Op 3 on VFS endpoint -> returns (status=0, total_inodes, replayed_tx, rolled_back_tx)
            ipc_call(VFS_ENDPOINT, 3, 0, 0, 0)
        }
        ShellCommand::LookupVfsInode => {
            // Op 4 on VFS endpoint -> lookup inode by prefix (e.g. 'etc')
            let mut prefix_bytes = [0u8; 8];
            prefix_bytes[0..3].copy_from_slice(b"etc");
            let word = u64::from_le_bytes(prefix_bytes);
            ipc_call(VFS_ENDPOINT, 4, word, 0, 0)
        }
        ShellCommand::QueryKeystoreStatus => {
            // Op 5 on Keystore endpoint -> returns (status=0, active_keys, is_wiped, 0)
            ipc_call(KEYSTORE_ENDPOINT, 5, 0, 0, 0)
        }
        ShellCommand::QueryNetMac => {
            // Op 1 on Driver-Net endpoint -> returns (status=0, mac_word, 0, 0)
            ipc_call(DRIVER_NET_ENDPOINT, 1, 0, 0, 0)
        }
        ShellCommand::LockSeccompFilter => {
            // Install seccomp deny rule for raw capability revocation, then lock filter
            install_filter_rule(u64::MAX, 3, true); // Deny all CapRevoke
            lock_filter();
            (0, 0, 0, 0)
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Run comprehensive diagnostic sequence across all Ring 3 service endpoints
    let _ = execute_shell_command(ShellCommand::QueryCryptoIdentity);
    let _ = execute_shell_command(ShellCommand::QueryVfsStats);
    let _ = execute_shell_command(ShellCommand::LookupVfsInode);
    let _ = execute_shell_command(ShellCommand::QueryKeystoreStatus);
    let _ = execute_shell_command(ShellCommand::QueryNetMac);
    let _ = execute_shell_command(ShellCommand::QueryAuditStats);
    let _ = execute_shell_command(ShellCommand::QueryClusterTerm);
    let _ = execute_shell_command(ShellCommand::LockSeccompFilter);

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
