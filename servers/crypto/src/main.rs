#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_recv, ipc_call};

pub struct NodeIdentity {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
}

impl NodeIdentity {
    pub fn generate_from_rdrand() -> Self {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];

        // Hardware entropy via RDRAND
        for i in (0..32).step_by(8) {
            let mut rand_val: u64 = 0;
            unsafe {
                core::arch::x86_64::_rdrand64_step(&mut rand_val);
            }
            sk[i..i + 8].copy_from_slice(&rand_val.to_le_bytes());
            pk[i..i + 8].copy_from_slice(&(!rand_val).to_le_bytes());
        }

        Self {
            public_key: pk,
            secret_key: sk,
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let identity = NodeIdentity::generate_from_rdrand();
    let crypto_endpoint_cap = 25;

    loop {
        // Handle cryptographic signing / Noise handshake requests
        let (op, _, _, _) = ipc_recv(crypto_endpoint_cap);
        if op == 1 {
            // Return NodeID public key word
            let pk_word0 = u64::from_le_bytes(identity.public_key[0..8].try_into().unwrap());
            ipc_call(crypto_endpoint_cap, 0, pk_word0, 0, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
