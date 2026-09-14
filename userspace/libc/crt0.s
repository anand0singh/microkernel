.intel_syntax noprefix
.global _start
.type _start, @function

_start:
    # 1. Clear frame pointer to mark outermost stack frame
    xor rbp, rbp

    # 2. Align stack to 16 bytes for System V ABI compliance
    and rsp, -16

    # 3. Call user space main entry point
    call main

    # 4. Exit / Halt loop if main returns
1:
    hlt
    jmp 1b
