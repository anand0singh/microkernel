struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self { state: if seed == 0 { 0x1234_5678_9ABC_DEF0 } else { seed } }
    }

    fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

pub unsafe fn run_syscall_fuzz_suite(iterations: usize) {
    let mut rng = Xorshift64::new(0xCAFE_BABE_DEAD_BEEF);

    for _ in 0..iterations {
        let cap_ptr = rng.next();
        let op = rng.next() % 16; // Tests valid (1..=8) and invalid (0, 9..15) opcodes
        let arg0 = rng.next();
        let arg1 = rng.next();
        let arg2 = rng.next();
        let arg3 = rng.next();

        // Dispatch raw fuzzed packet into kernel entry dispatcher
        let result = crate::arch::x86_64::syscall::rust_cap_dispatcher(
            cap_ptr, op, arg0, arg1, arg2, arg3,
        );

        // Verification invariant: out-of-range opcodes must ALWAYS return -1
        if op == 0 || op > 8 {
            assert_eq!(
                result,
                0xFFFF_FFFF_FFFF_FFFF,
                "Fuzzer detected unhandled invalid opcode: {}",
                op
            );
        }
    }
}

#[test]
fn test_capability_dispatcher_fuzz_sequence() {
    unsafe {
        run_syscall_fuzz_suite(256);
    }
}
