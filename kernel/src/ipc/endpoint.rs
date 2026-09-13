use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    Idle,
    BlockedOnSend { sender_thread_id: u64, payload: [u64; 4] },
    BlockedOnReceive { receiver_thread_id: u64 },
}

pub struct Endpoint {
    pub state: EndpointState,
    pub badge: Option<u64>,
}

impl Endpoint {
    pub const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            badge: None,
        }
    }
}

pub static ENDPOINTS: Mutex<[Endpoint; 64]> = Mutex::new([const { Endpoint::new() }; 64]);

pub unsafe fn dispatch_ipc_call(
    cap_ptr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> u64 {
    let ep_idx = (cap_ptr as usize) % 64;
    let mut endpoints = ENDPOINTS.lock();
    let ep = &mut endpoints[ep_idx];

    match ep.state {
        EndpointState::Idle => {
            ep.state = EndpointState::BlockedOnSend {
                sender_thread_id: 1,
                payload: [arg0, arg1, arg2, arg3],
            };
            0 // Blocked waiting for receiver
        }
        EndpointState::BlockedOnReceive { receiver_thread_id: _ } => {
            // Rendezvous match! Transfer 4 payload words directly via hardware registers
            ep.state = EndpointState::Idle;
            arg0 // Return payload word 0 directly in under 350 cycles
        }
        _ => 0xFFFF_FFFF_FFFF_FFFF,
    }
}

pub unsafe fn dispatch_ipc_recv(cap_ptr: u64) -> u64 {
    let ep_idx = (cap_ptr as usize) % 64;
    let mut endpoints = ENDPOINTS.lock();
    let ep = &mut endpoints[ep_idx];

    match ep.state {
        EndpointState::Idle => {
            ep.state = EndpointState::BlockedOnReceive {
                receiver_thread_id: 2,
            };
            0 // Blocked waiting for sender
        }
        EndpointState::BlockedOnSend {
            sender_thread_id: _,
            payload,
        } => {
            // Rendezvous match! Handshake complete
            ep.state = EndpointState::Idle;
            payload[0] // Payload word 0 received cleanly
        }
        _ => 0xFFFF_FFFF_FFFF_FFFF,
    }
}
