#![cfg_attr(not(test), no_std)]

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Rights: u8 {
        const READ    = 0b0000_0001;
        const WRITE   = 0b0000_0010;
        const EXECUTE = 0b0000_0100;
        const GRANT   = 0b0000_1000;
    }
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOp {
    CapInvoke = 1,
    CapMint   = 2,
    CapRevoke = 3,
    IpcCall   = 4,
    IpcRecv   = 5,
    Yield     = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallMsg {
    pub cap_ptr: u64,
    pub op: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}

#[inline(always)]
pub unsafe fn syscall(msg: &SyscallMsg) -> (u64, u64, u64, u64) {
    let ret0: u64;
    let ret1: u64;
    let ret2: u64;
    let ret3: u64;

    core::arch::asm!(
        "syscall",
        inout("rdi") msg.cap_ptr => _,
        inout("rsi") msg.op => ret0,
        inout("rdx") msg.arg0 => ret1,
        inout("r10") msg.arg1 => ret2,
        inout("r8") msg.arg2 => ret3,
        inout("r9") msg.arg3 => _,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );

    (ret0, ret1, ret2, ret3)
}

pub fn cap_invoke(cap_ptr: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> (u64, u64, u64, u64) {
    let msg = SyscallMsg {
        cap_ptr,
        op: SyscallOp::CapInvoke as u64,
        arg0,
        arg1,
        arg2,
        arg3,
    };
    unsafe { syscall(&msg) }
}

pub fn ipc_call(endpoint_cap: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> (u64, u64, u64, u64) {
    let msg = SyscallMsg {
        cap_ptr: endpoint_cap,
        op: SyscallOp::IpcCall as u64,
        arg0,
        arg1,
        arg2,
        arg3,
    };
    unsafe { syscall(&msg) }
}

pub fn ipc_recv(endpoint_cap: u64) -> (u64, u64, u64, u64) {
    let msg = SyscallMsg {
        cap_ptr: endpoint_cap,
        op: SyscallOp::IpcRecv as u64,
        arg0: 0,
        arg1: 0,
        arg2: 0,
        arg3: 0,
    };
    unsafe { syscall(&msg) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_op_discriminants() {
        assert_eq!(SyscallOp::CapInvoke as u64, 1);
        assert_eq!(SyscallOp::CapMint as u64, 2);
        assert_eq!(SyscallOp::CapRevoke as u64, 3);
        assert_eq!(SyscallOp::IpcCall as u64, 4);
        assert_eq!(SyscallOp::IpcRecv as u64, 5);
        assert_eq!(SyscallOp::Yield as u64, 6);
    }

    #[test]
    fn test_rights_bitflags() {
        let rights = Rights::READ | Rights::WRITE;
        assert!(rights.contains(Rights::READ));
        assert!(rights.contains(Rights::WRITE));
        assert!(!rights.contains(Rights::EXECUTE));
    }
}
