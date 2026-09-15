# AegisOS: Secure Distributed Operating Environment

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Language-Rust%20Nightly-red.svg)](https://www.rust-lang.org/)
[![Assembly](https://img.shields.io/badge/Language-x86__64%20Assembly-blue.svg)](https://en.wikipedia.org/wiki/X86_assembly_language)
[![C](https://img.shields.io/badge/Language-C11%20ABI-green.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

A flagship, bare-metal **Secure Distributed Operating Environment** engineered from scratch in **Rust, C, and x86_64 Assembly**. 

Rather than building another generic Linux distribution, AegisOS implements a zero-trust, capability-based microkernel (reminiscent of seL4 and Fuchsia Zircon) with an ultra-minimal Trusted Computing Base (TCB < 10,000 LOC). All traditional operating system services—including virtual filesystems, block storage, network stacks, cryptographic identity management, and audit telemetry—are strictly banished to isolated, unprivileged Ring 3 micro-services communicating over high-throughput, zero-copy capability IPC channels.

---

## 🏛 Architecture Overview

```text
               APPLICATIONS & RING 3 MICRO-SERVICES
 ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
 │  userspace/   │ │    servers/   │ │    servers/   │ │    servers/   │
 │     shell     │ │      vfs      │ │      net      │ │    crypto     │
 └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
         │                 │                 │                 │
         └─────────────────┼─────────────────┴─────────────────┘
                           │
             SYSTEM CALLS & CAPABILITY IPC (libsys)
                           │ (SYSRETQ / SYSCALL Trampoline)
                           ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │                       RING 0 SECURE MICROKERNEL                     │
 ├──────────────────────────────────┬──────────────────────────────────┤
 │  Capability C-Nodes & CDT Trees  │  Dual-PML4 KPTI Memory Isolation │
 │  Zero-Copy 4-Reg Rendezvous IPC  │  Lock-Free SPSC Shared Rings     │
 │  APIC Preemptive Scheduler       │  Buddy & Slab Memory Allocators  │
 │  Seccomp-like Capability Filter  │  TPM 2.0 PCR Measured Launch     │
 │  Append-Only Lock-Free Audit Ring│  Intrusion Detection Tripwires   │
 └──────────────────────────────────┴──────────────────────────────────┘
                           │
                           ▼
                  HARDWARE (x86_64 BARE-METAL / QEMU)
```

---

## 🛡 Security Subsystems & Flagship Capabilities

### 1. Capability-Based Security & Cascading CDT Revocation
- **Zero-Ambient Authority**: Processes possess zero inherent permissions. Resources (threads, memory frames, IPC endpoints, I/O ports) can only be accessed by presenting a cryptographically indexed capability from the process's private Capability C-Node.
- **Capability Derivation Trees (CDT)**: Every minted capability tracks its lineage. Deriving child capabilities enforces strict **rights attenuation** (e.g., child permissions $\subseteq$ parent permissions).
- **Cascading Revocation**: Revoking an intermediate capability recursively invalidates its entire descendant tree in $O(N)$ without affecting siblings or parent objects.

### 2. Hardware Memory Protection & Kernel Page-Table Isolation (KPTI)
- **Dual-PML4 Address Spaces**: Complete mitigation against Meltdown/Spectre (CVE-2017-5754). User processes run under a stripped PML4 page table containing zero executable kernel code and only trampoline stubs.
- **x86_64 Ring Transition**: Kernel entry executes via high-speed `SYSCALL`/`SYSRETQ` assembly trampolines with dedicated Interrupt Stack Tables (IST1) for double fault containment.
- **Ring 3 Sandboxing**: User execution sets Ring 3 privilege levels (`DPL=3`), catching access violations at vector 14 (`#PF` with error code `0x05`).

### 3. UEFI Secure Boot & TPM 2.0 Measured Launch
- **UEFI Bootloader (`x86_64-unknown-uefi`)**: Boots from FAT32 ESP partitions, queries EFI memory maps, allocates low-memory page structures, and transitions the CPU into 64-bit Long Mode.
- **TPM 2.0 PCR Bank Simulation**: Measures stage hashes (`KERNEL.ELF` and Ring 3 service binaries) into simulated Platform Configuration Registers (`PCR[0..7]`) via SHA-256 chains before handing over execution.

### 4. Cryptographic Identity & Noise_IK Protocol
- **Hardware Entropy**: Uses CPU `RDRAND`/`RDSEED` instructions for hardware-true randomness.
- **Ed25519 Keypairs**: Every microkernel node generates a unique asymmetric identity keypair at boot.
- **Noise_IK Authenticated Handshake**: Implements the Noise Protocol Framework (`Noise_IK_25519_AESGCM_SHA256`) to establish encrypted, mutual-identity sessions between distributed cluster nodes.

### 5. Programmable Seccomp-like Syscall & Capability Filtering
- **Sandboxed Execution Policy**: Allows processes (e.g., sandboxed vault apps or untrusted network parsers) to install customized capability filter tables.
- **Inspection Rules**: Supports default-allow, default-deny, exact argument inspection, and penalty actions (`Allow`, `Deny`, `Kill`).
- **Filter Immutability Lock**: Once locked via `SyscallOp::LockFilter`, the filter table is permanently read-only for the lifetime of that address space.

### 6. Encrypted Storage & Merkle Tree Integrity
- **XTS-AES-256 Disk Encryption**: Implements constant-time block-level XTS-AES-256 sector encryption with Galois Field $GF(2^{128})$ polynomial math ($x^{128} + x^7 + x^2 + x + 1$).
- **Merkle Tree Block Integrity**: 4096-byte disk blocks are hashed into a binary Merkle tree, allowing instantaneous detection and rejection of localized data corruption or adversary bit-flips.
- **VirtIO 1.0 Driver**: Zero-copy Ring 3 VirtIO block device driver utilizing split DMA VirtQueues.

### 7. Zero-Copy IPC & Lock-Free SPSC Memory Rings
- **Synchronous Rendezvous IPC**: Fast path passes message payloads entirely inside CPU registers (`RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`) across address spaces without touching memory buffers.
- **Lock-Free SPSC Rings**: High-throughput asynchronous transfers utilize cache-aligned, lock-free Single Producer Single Consumer shared memory rings with acquire/release memory fences.

### 8. Non-Repudiable Audit Logging & Intrusion Detection (IDS)
- **Lock-Free Audit Ring**: Ring 0 appends tamper-evident audit records (caller thread ID, capability pointer, opcode, timestamp ticks, verdict).
- **IDS Anomaly Tripwires**: Real-time rate limiters and violation detectors track access faults. Exceeding security thresholds triggers automatic address space freeze and alert propagation.

### 9. Distributed Capability Delegation & Raft Consensus
- **Capability-over-Wire**: Remote capabilities are signed into 256-bit cryptographic tokens for network transit.
- **Raft Consensus Engine**: Multi-node state machine replication ensures consistent cluster capability derivation, leader election, and distributed consensus across up to 8 cluster nodes.

### 10. Syzkaller-style Fuzz Testing & Verification
- Dedicated security test harness executing 100,000 pseudorandomized capability invocation packets across kernel boundaries, verifying that out-of-range opcodes, illegal pointers, and privilege escalations are rejected with 0 invariant violations.

---

## 📦 Workspace Crate Inventory

| Crate / Path | Target | Description |
| :--- | :--- | :--- |
| [`boot/`](boot/) | `x86_64-unknown-uefi` | UEFI bootloader loading `KERNEL.ELF` and configuring initial paging |
| [`kernel/`](kernel/) | `x86_64-unknown-none` | Ring 0 Secure Microkernel (KPTI, APIC, Buddy/Slab, C-Nodes, CDT, IPC, IDS, Seccomp, Namespaces) |
| [`userspace/libsys/`](userspace/libsys/) | `x86_64-unknown-none` | `#![no_std]` user-space syscall library wrapping assembly trampolines |
| [`userspace/init/`](userspace/init/) | `x86_64-unknown-none` | Root user space process orchestrator |
| [`userspace/shell/`](userspace/shell/) | `x86_64-unknown-none` | Interactive Ring 3 micro-shell with diagnostic diagnostics |
| [`servers/vfs/`](servers/vfs/) | `x86_64-unknown-none` | Encrypted Virtual Filesystem with XTS-AES-256 and Merkle validation |
| [`servers/driver_virtio/`](servers/driver_virtio/) | `x86_64-unknown-none` | Ring 3 VirtIO 1.0 block driver with DMA VirtQueues |
| [`servers/driver_net/`](servers/driver_net/) | `x86_64-unknown-none` | Ring 3 VirtIO 1.0 network driver with split packet VirtQueues |
| [`servers/keystore/`](servers/keystore/) | `x86_64-unknown-none` | Ring 3 Cryptographic Keystore Enclave with anti-tamper zeroization |
| [`servers/net/`](servers/net/) | `x86_64-unknown-none` | Distributed network stack with Cap-over-Wire and Raft consensus |
| [`servers/crypto/`](servers/crypto/) | `x86_64-unknown-none` | Ed25519 identity server and Noise_IK handshake engine |
| [`servers/audit/`](servers/audit/) | `x86_64-unknown-none` | Centralized audit telemetry and IDS alert daemon |
| [`apps/vault/`](apps/vault/) | `x86_64-unknown-none` | Sandboxed secret vault application running under capability constraints |
| [`include/libsys.h`](include/libsys.h) | C ABI | Polyglot C headers and minimal `crt0.s` runtime startup |
| [`tools/security_suite/`](tools/security_suite/) | Host Target | Standalone security verification and 100k-iteration fuzzer |

---

## 🚀 Building & Verification

### Prerequisites
- **Rust Toolchain**: Rust Nightly with bare-metal targets:
  ```bash
  rustup default nightly
  rustup target add x86_64-unknown-none x86_64-unknown-uefi
  ```
- **QEMU (Optional for virtualization)**:
  ```bash
  # Windows
  winget install SoftwareFreedomConservancy.QEMU
  # Linux (Ubuntu/Debian)
  sudo apt-get install qemu-system-x86 ovmf
  ```

---

### Step 1: Compile the Workspace
Compile all 13 microkernel crates into bare-metal ELF binaries:
```bash
cargo build --workspace
```

---

### Step 2: Assemble the UEFI Boot Disk Image
Package the UEFI bootloader, kernel, and Ring 3 service ELFs into the standard FAT32 ESP directory structure (`target/esp/`):

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File tools/build_disk.ps1
```

Generated layout:
```text
target/esp/
├── EFI/
│   └── BOOT/
│       └── BOOTX64.EFI        # 64-bit UEFI Bootloader
├── KERNEL.ELF                 # Ring 0 Microkernel binary
└── SERVICES/                  # Ring 3 Isolated User-Space Servers
    ├── audit.elf
    ├── crypto.elf
    ├── driver-net.elf
    ├── driver-virtio.elf
    ├── init.elf
    ├── keystore.elf
    ├── net.elf
    ├── shell.elf
    ├── vault.elf
    └── vfs.elf
```

---

### Step 3: Run Security Verification & Fuzzing Suite
Execute the automated cryptographic verification suite, Merkle tamper tests, capability attenuation checks, seccomp filters, and the 100,000-cycle Syzkaller-style fuzzer:

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File tools/test_security.ps1

# Or directly with Cargo
cargo run --manifest-path tools/security_suite/Cargo.toml
```

**Verification Output:**
```text
================================================================
   MICROKERNEL SECURITY VERIFICATION & FUZZING SUITE
================================================================

[1/10] Running XTS-AES-256 Sector Cipher Test...
  -> Encrypted 4096-byte sector at LBA 42 in 1.65ms
  -> Decrypted 4096-byte sector in 1.64ms
  [PASS] XTS-AES-256 Sector Roundtrip Verified!

[2/10] Running Merkle Tree Block Hash Integrity Test...
  -> Clean Merkle Root (4 blocks): [fa, d2, 67, 8e, 22, d9, 9e, 0e]
  -> Tampered Merkle Root:          [2e, e2, e1, d1, 40, 52, 93, b0]
  [PASS] Merkle Tree Block Tampering Rejection Verified!

[3/10] Running Capability Derivation Tree (CDT) Revocation Test...
  -> Attenuation Guard Verified: Privilege escalation rejected.
  [PASS] CDT Cascading Revocation Verified (Grandchild revoked, sibling intact)!

[4/10] Running Seccomp-like Capability Filter Test...
  -> Filter Immutability Lock Verified.
  [PASS] Seccomp-like Capability Filter Verified (Whitelist, Kill rule, Violations tracked)!

[5/10] Running Syzkaller-style Syscall Fuzzer (100,000 iterations)...
  -> Executed 100000 random syscall packets in 3.13ms
  -> Average dispatch latency: 31.33 ns/op
  [PASS] 100,000 Fuzz Iterations Passed with 0 Invariant Violations!

[6/10] Running Distributed Raft Consensus Quorum Test...
  -> Achieved quorum: 4/5 votes.
  [PASS] Raft Consensus Protocol Simulation Verified!

[7/10] Running ELF64 Binary Loader & Protection Flags Test...
  -> Validated ELF64 Header: Entry=0x400000, Segments=2
  -> Enforced NX Invariant: Data segment marked non-executable.
  -> Enforced W^X Invariant: Code segment marked non-writable.
  -> Malformed Header Rejection Verified.
  [PASS] ELF64 Loader & Memory Protection Invariants Verified!

[8/10] Running Preemptive Multi-Tasking Scheduler State Machine Test...
  -> IPC Blocking Transition Verified: Blocked Thread 1 yielded to Thread 2.
  -> Quantum Preemption Verified: Round-robin advanced to Thread 3.
  -> Unblocking & Dead Thread Elimination Verified.
  [PASS] Preemptive Multi-Tasking Scheduler State Machine Verified!

[9/10] Running Cryptographic Keystore Enclave & Anti-Tamper Test...
  -> HKDF-style Key Derivation Verified.
  -> Anti-Tamper Emergency Memory Wipe Verified: All keys zeroized.
  [PASS] Cryptographic Keystore Enclave & Anti-Tamper Zeroization Verified!

[10/10] Running Multi-Tenant Capability Namespaces Test...
  -> Multi-Tenant Isolation Verified: Cross-tenant invocation denied.
  [PASS] Multi-Tenant Capability Namespaces & Boundary Enforcement Verified!

================================================================
   ALL 10 SECURITY SUBSYSTEM TESTS PASSED - SYSTEM PRISTINE
================================================================
```

---

### Step 4: Boot in QEMU Virtual Machine
Launch the assembled UEFI disk inside QEMU with serial console output:

```powershell
powershell -ExecutionPolicy Bypass -File tools/run_qemu.ps1
```

Or via direct QEMU invocation:
```bash
qemu-system-x86_64 -drive file=fat:rw:target/esp,format=raw -serial stdio -m 512M -smp 2
```

---

## 🔒 Polyglot C Application Development

AegisOS exposes a standard C ABI interface (`include/libsys.h`), allowing developers to compile native C applications that run directly on the microkernel with capability security:

```c
#include "libsys.h"

void _start(void) {
    // Invoke capability slot 2 with operation 1
    SyscallMsg msg = {
        .cap_ptr = 2,
        .op = SYS_CAP_INVOKE,
        .arg0 = 0x1337,
        .arg1 = 0xCAFE,
        .arg2 = 0,
        .arg3 = 0
    };
    
    int64_t status = sys_cap_invoke(msg.cap_ptr, msg.op, msg.arg0, msg.arg1, msg.arg2, msg.arg3);
    
    // Relinquish execution quantum
    sys_yield();
    
    for (;;) { }
}
```

---

## 📜 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
