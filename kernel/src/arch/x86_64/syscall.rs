use crate::arch::x86_64::gdt::GDT;
use x86_64::registers::model_specific::Msr;
use x86_64::VirtAddr;

const IA32_EFER_MSR: u32 = 0xC000_0080;
const IA32_STAR_MSR: u32 = 0xC000_0081;
const IA32_LSTAR_MSR: u32 = 0xC000_0082;
const IA32_FMASK_MSR: u32 = 0xC000_0084;

#[no_mangle]
pub unsafe extern "C" fn rust_cap_dispatcher(
    cap_ptr: u64,
    op: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> u64 {
    let current_thread_id = 1; // Default primary thread context

    // 1. Intrusion Detection Quarantine Barrier
    if crate::security::ids::IDS_ENGINE.lock().is_quarantined(current_thread_id) {
        crate::security::audit::AUDIT_LOG.lock().record(
            current_thread_id,
            cap_ptr,
            op,
            crate::security::audit::AuditVerdict::Denied,
        );
        return 0xFFFF_FFFF_FFFF_FFFD; // Quarantined by Intrusion Detection System
    }

    // 2. Seccomp-like Programmable Capability Filter Evaluation
    let filter_action = crate::security::filter::PROCESS_FILTER.lock().evaluate(cap_ptr, op);
    if filter_action == crate::security::filter::FilterAction::Deny {
        crate::security::audit::AUDIT_LOG.lock().record(
            current_thread_id,
            cap_ptr,
            op,
            crate::security::audit::AuditVerdict::Denied,
        );
        return 0xFFFF_FFFF_FFFF_FFFC; // Blocked by Capability Filter (Seccomp)
    }

    // 3. Syscall Opcode Routing with Security Logging
    let res = match op {
        1 => {
            // CapInvoke
            crate::cap::cnode::dispatch_cap_invoke(cap_ptr, arg0, arg1, arg2, arg3)
        }
        2 => {
            // CapMint
            crate::cap::cdt::dispatch_cap_mint(cap_ptr, arg0, arg1)
        }
        3 => {
            // CapRevoke
            crate::cap::cdt::dispatch_cap_revoke(cap_ptr)
        }
        4 => {
            // IpcCall
            crate::ipc::endpoint::dispatch_ipc_call(cap_ptr, arg0, arg1, arg2, arg3)
        }
        5 => {
            // IpcRecv
            crate::ipc::endpoint::dispatch_ipc_recv(cap_ptr)
        }
        6 => {
            // Yield
            0
        }
        7 => {
            // CapBadge
            crate::cap::cdt::dispatch_cap_badge(cap_ptr, arg0, arg1)
        }
        8 => {
            // CapCopy
            crate::cap::cdt::dispatch_cap_copy(cap_ptr, arg0)
        }
        9 => {
            // InstallFilterRule(target_cap, target_op, action: 0=Allow, 1=Deny)
            let action = if arg1 == 1 {
                crate::security::filter::FilterAction::Deny
            } else {
                crate::security::filter::FilterAction::Allow
            };
            if crate::security::filter::PROCESS_FILTER.lock().add_rule(cap_ptr, arg0, action).is_ok() {
                0
            } else {
                0xFFFF_FFFF_FFFF_FFFF
            }
        }
        10 => {
            // LockFilter()
            crate::security::filter::PROCESS_FILTER.lock().lock();
            0
        }
        _ => {
            // Unknown opcode anomaly - report to IDS engine
            crate::security::ids::IDS_ENGINE.lock().record_violation(
                current_thread_id,
                cap_ptr,
                op,
            );
            return 0xFFFF_FFFF_FFFF_FFFF;
        }
    };

    crate::security::audit::AUDIT_LOG.lock().record(
        current_thread_id,
        cap_ptr,
        op,
        crate::security::audit::AuditVerdict::Allowed,
    );

    res
}

pub unsafe fn init_syscall_msrs(syscall_entry_ptr: VirtAddr) {
    // 1. Enable SCE in IA32_EFER
    let mut efer_msr = Msr::new(IA32_EFER_MSR);
    let efer_val = efer_msr.read();
    efer_msr.write(efer_val | 1); // Bit 0: SCE

    // 2. Configure IA32_STAR
    // Kernel CS: 0x08, Kernel SS: 0x10 -> STAR[47:32] = 0x0008
    // User CS: 0x20, User SS: 0x18 -> STAR[63:48] = 0x001B (User CS RPL=3)
    let star_val: u64 = ((GDT.1.kernel_code_selector.0 as u64) << 32)
        | (((GDT.1.user_data_selector.0 as u64 - 8) | 3) << 48);
    let mut star_msr = Msr::new(IA32_STAR_MSR);
    star_msr.write(star_val);

    // 3. Set IA32_LSTAR to syscall_entry target
    let mut lstar_msr = Msr::new(IA32_LSTAR_MSR);
    lstar_msr.write(syscall_entry_ptr.as_u64());

    // 4. Set IA32_FMASK to disable interrupts (IF bit 9) on syscall entry
    let mut fmask_msr = Msr::new(IA32_FMASK_MSR);
    fmask_msr.write(0x0200);
}
