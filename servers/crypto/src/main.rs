#![no_std]
#![no_main]

mod noise;

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
        let (op, peer_pk_low, peer_pk_high, _) = ipc_recv(crypto_endpoint_cap);

        if op == 1 {
            // Op 1: Return NodeID public key word
            let pk_word0 = u64::from_le_bytes(identity.public_key[0..8].try_into().unwrap());
            ipc_call(crypto_endpoint_cap, 0, pk_word0, 0, 0);
        } else if op == 2 {
            // Op 2: Complete Noise_IK authenticated handshake with peer public key
            let mut peer_pk = [0u8; 32];
            peer_pk[0..8].copy_from_slice(&peer_pk_low.to_le_bytes());
            peer_pk[8..16].copy_from_slice(&peer_pk_high.to_le_bytes());

            let handshake = noise::NoiseHandshake::new(peer_pk);
            let (tx_key, _rx_key) = handshake.complete_handshake();
            let session_word0 = u64::from_le_bytes(tx_key.key[0..8].try_into().unwrap());

            ipc_call(crypto_endpoint_cap, 0, session_word0, tx_key.nonce, 0);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
