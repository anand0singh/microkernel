use core::arch::global_asm;

global_asm!(
    r#"
    .intel_syntax noprefix
    .global syscall_entry
    .type syscall_entry, @function
    syscall_entry:
        swapgs
        mov gs:[0x00], rsp
        mov rsp, gs:[0x08]

        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15

        mov rcx, r10
        call rust_cap_dispatcher

        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp

        mov rsp, gs:[0x00]
        swapgs
        sysretq
    "#
);

extern "C" {
    pub fn syscall_entry();
}
