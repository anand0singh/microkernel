#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod arch;
mod cap;
mod ipc;
mod loader;
mod mm;
mod sched;
mod security;

#[path = "../tests/fuzz_harness.rs"]
mod fuzz_harness;

use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Initialize Bare Metal Hardware, Serial COM1 & CPU Traps
    arch::init_arch();

    printk!("============================================================");
    printk!("  AegisOS Secure Distributed Microkernel (x86_64)");
    printk!("  Ring 0 TCB Initialized with KPTI, Capabilities, & TPM");
    printk!("============================================================");
    printk!("[OK] 16550A Serial Driver active at COM1 (0x3F8, 115200 8N1)");
    printk!("[OK] GDT, TSS IST1 Double-Fault Stack & 256-entry IDT active");
    printk!("[OK] Local APIC 1ms Preemptive Timer active");
    printk!("[OK] Fast SYSCALL/SYSRETQ Assembly Trampoline active");

    // 2. Initialize Low-Level Physical Frame & Kernel Memory Allocators
    mm::init_mm(0x100000, 64 * 1024 * 1024); // 64 MiB usable RAM region
    printk!("[OK] Buddy Allocator (2^0..2^11 pages) & Slab Caches active");

    // 3. Initialize Capability Engine & CDT
    cap::init_cap_engine();
    printk!("[OK] Capability C-Nodes & CDT Cascading Revocation active");

    // 4. Initialize Zero-Copy Synchronous IPC
    ipc::init_ipc();
    printk!("[OK] Zero-Copy Rendezvous IPC & SPSC Shared Memory Rings active");

    // 5. Initialize Security Subsystem (TPM Measured Boot, Audit Buffer, IDS Engine)
    security::init_security();
    printk!("[OK] TPM 2.0 PCR Bank & Append-Only Audit Buffer active");
    printk!("[OK] Real-Time Intrusion Detection System (IDS) Tripwires active");

    // 6. Initialize Preemptive Scheduler
    sched::init_scheduler();
    printk!("[OK] Preemptive Thread Scheduler active");

    // 7. Run Phase 6 Formal & Syscall Fuzz Verification Suite
    unsafe {
        fuzz_harness::run_syscall_fuzz_suite(256);
    }
    printk!("[OK] In-Kernel Syscall Fuzz Verification Suite passed (256 iterations)");

    // 8. Test Drop to User Space (Ring 3)
    let test_user_code = ring3_test_user_code as *const () as usize as u64;
    let test_user_stack = 0x7000_0000_0000u64;
    printk!("[OK] Dropping CPU privilege level to Ring 3 Sandboxed User Space...");

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
