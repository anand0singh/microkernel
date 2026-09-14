#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, install_filter_rule, lock_filter};

pub const VFS_ENDPOINT: u64 = 10;
pub const NET_ENDPOINT: u64 = 20;
pub const CRYPTO_ENDPOINT: u64 = 25;
pub const AUDIT_ENDPOINT: u64 = 35;

pub enum ShellCommand {
    QueryAuditStats,
    QueryClusterTerm,
    QueryCryptoIdentity,
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
    // Execute default shell diagnostics sequence
    let _ = execute_shell_command(ShellCommand::QueryCryptoIdentity);
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
