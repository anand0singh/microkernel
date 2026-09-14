#ifndef _LIBSYS_H
#define _LIBSYS_H

#include <stdint.h>

#define CAP_RIGHT_READ    0x01
#define CAP_RIGHT_WRITE   0x02
#define CAP_RIGHT_EXECUTE 0x04
#define CAP_RIGHT_GRANT   0x08

#define SYS_OP_CAP_INVOKE 1
#define SYS_OP_CAP_MINT   2
#define SYS_OP_CAP_REVOKE 3
#define SYS_OP_IPC_CALL   4
#define SYS_OP_IPC_RECV   5
#define SYS_OP_YIELD      6
#define SYS_OP_CAP_BADGE  7
#define SYS_OP_CAP_COPY   8

typedef struct {
    uint64_t cap_ptr;
    uint64_t op;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
} sys_msg_t;

typedef struct {
    uint64_t ret0;
    uint64_t ret1;
    uint64_t ret2;
    uint64_t ret3;
} sys_ret_t;

static inline sys_ret_t sys_call(const sys_msg_t *msg) {
    sys_ret_t ret;
    register uint64_t rdi __asm__("rdi") = msg->cap_ptr;
    register uint64_t rsi __asm__("rsi") = msg->op;
    register uint64_t rdx __asm__("rdx") = msg->arg0;
    register uint64_t r10 __asm__("r10") = msg->arg1;
    register uint64_t r8  __asm__("r8")  = msg->arg2;
    register uint64_t r9  __asm__("r9")  = msg->arg3;

    __asm__ volatile(
        "syscall"
        : "=S"(ret.ret0), "=d"(ret.ret1), "=r"(r10), "=r"(r8)
        : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    ret.ret2 = r10;
    ret.ret3 = r8;
    return ret;
}

static inline sys_ret_t sys_ipc_call(uint64_t endpoint_cap, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    sys_msg_t msg = {
        .cap_ptr = endpoint_cap,
        .op = SYS_OP_IPC_CALL,
        .arg0 = a0,
        .arg1 = a1,
        .arg2 = a2,
        .arg3 = a3
    };
    return sys_call(&msg);
}

static inline sys_ret_t sys_ipc_recv(uint64_t endpoint_cap) {
    sys_msg_t msg = {
        .cap_ptr = endpoint_cap,
        .op = SYS_OP_IPC_RECV,
        .arg0 = 0,
        .arg1 = 0,
        .arg2 = 0,
        .arg3 = 0
    };
    return sys_call(&msg);
}

#endif // _LIBSYS_H
