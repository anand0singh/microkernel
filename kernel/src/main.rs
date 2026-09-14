#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod arch;
mod cap;
mod ipc;
mod mm;
mod sched;
mod security;

#[path = "../tests/fuzz_harness.rs"]
mod fuzz_harness;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialize Bare Metal Hardware & CPU Traps
    arch::init_arch();

    // 2. Initialize Low-Level Physical Frame & Kernel Memory Allocators
    mm::init_mm(0x100000, 64 * 1024 * 1024); // 64 MiB usable RAM region

    // 3. Initialize Capability Engine & CDT
    cap::init_cap_engine();

    // 4. Initialize Zero-Copy Synchronous IPC
    ipc::init_ipc();

    // 5. Initialize Security Subsystem (TPM Measured Boot, Audit Buffer, IDS Engine)
    security::init_security();

    // 6. Initialize Preemptive Scheduler
    sched::init_scheduler();

    // 7. Run Phase 6 Formal & Syscall Fuzz Verification Suite
    unsafe {
        fuzz_harness::run_syscall_fuzz_suite(256);
    }

    // 7. Test Drop to User Space (Ring 3)
    let test_user_code = ring3_test_user_code as *const () as usize as u64;
    let test_user_stack = 0x7000_0000_0000u64;

    unsafe {
        drop_to_user_space(test_user_code, test_user_stack);
    }
}

pub unsafe fn drop_to_user_space(user_rip: u64, user_rsp: u64) -> ! {
    core::arch::asm!(
        "push 0x1B",        // User Data Segment Selector (0x18 | 3)
        "push {user_rsp}",  // User Stack Pointer
        "push 0x202",       // RFLAGS (IF enabled)
        "push 0x23",        // User Code Segment Selector (0x20 | 3)
        "push {user_rip}",  // User Instruction Pointer
        "iretq",
        user_rsp = in(reg) user_rsp,
        user_rip = in(reg) user_rip,
        options(noreturn)
    );
}

extern "C" fn ring3_test_user_code() -> ! {
    // Ring 3 Test execution loop
    // 1. Invoke raw capability syscall
    libsys::cap_invoke(1, 100, 200, 300, 400);

    // 2. Intentionally read supervisor kernel memory (0xFFFF_8000_0000_0000)
    // to verify that #PF error code 0x05 (User Protection Violation Read) is immediately triggered
    unsafe {
        let supervisor_ptr = 0xFFFF_8000_0000_0000 as *const u64;
        let _val = core::ptr::read_volatile(supervisor_ptr);
    }

    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
