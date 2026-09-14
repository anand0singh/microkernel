pub mod endpoint;
pub mod shared_ring;

pub fn init_ipc() {
    unsafe {
        test_phase4_ipc();
    }
}

pub unsafe fn test_phase4_ipc() {
    // 1. Verify Sender-First Synchronous Rendezvous (Endpoint 10)
    // Sender initiates call with 4 payload words: [0x1111, 0x2222, 0x3333, 0x4444]
    let send_status = endpoint::dispatch_ipc_call(10, 0x1111, 0x2222, 0x3333, 0x4444);
    assert_eq!(send_status, 0, "Phase 4: Sender failed to enter BlockedOnSend state");

    // Verify endpoint state is BlockedOnSend
    {
        let endpoints = endpoint::ENDPOINTS.lock();
        let ep = &endpoints[10];
        match ep.state {
            endpoint::EndpointState::BlockedOnSend { sender_thread_id: _, payload } => {
                assert_eq!(payload[0], 0x1111);
                assert_eq!(payload[1], 0x2222);
                assert_eq!(payload[2], 0x3333);
                assert_eq!(payload[3], 0x4444);
            }
            _ => panic!("Phase 4: Endpoint 10 expected to be BlockedOnSend"),
        }
    }

    // Receiver arrives on Endpoint 10
    let recv_payload = endpoint::dispatch_ipc_recv(10);
    assert_eq!(recv_payload, 0x1111, "Phase 4: Receiver failed to receive word 0");

    // Endpoint must now be returned to Idle
    {
        let endpoints = endpoint::ENDPOINTS.lock();
        assert_eq!(endpoints[10].state, endpoint::EndpointState::Idle);
    }

    // 2. Verify Receiver-First Synchronous Rendezvous (Endpoint 20)
    // Receiver arrives first and blocks waiting for sender
    let recv_status = endpoint::dispatch_ipc_recv(20);
    assert_eq!(recv_status, 0, "Phase 4: Receiver failed to enter BlockedOnReceive state");

    {
        let endpoints = endpoint::ENDPOINTS.lock();
        assert_eq!(
            endpoints[20].state,
            endpoint::EndpointState::BlockedOnReceive { receiver_thread_id: 2 }
        );
    }

    // Sender arrives on Endpoint 20 with payload
    let rendezvous_match = endpoint::dispatch_ipc_call(20, 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD);
    assert_eq!(rendezvous_match, 0xAAAA, "Phase 4: Rendezvous match failed to deliver word 0");

    // Endpoint 20 must return to Idle
    {
        let endpoints = endpoint::ENDPOINTS.lock();
        assert_eq!(endpoints[20].state, endpoint::EndpointState::Idle);
    }

    // 3. Verify Syscall Dispatcher Fast Path Routing
    let syscall_call = crate::arch::x86_64::syscall::rust_cap_dispatcher(
        30, 4, 0xCAFE, 0xBABE, 0x0123, 0x4567,
    );
    assert_eq!(syscall_call, 0, "Phase 4: Syscall dispatch IpcCall failed");

    let syscall_recv = crate::arch::x86_64::syscall::rust_cap_dispatcher(
        30, 5, 0, 0, 0, 0,
    );
    assert_eq!(syscall_recv, 0xCAFE, "Phase 4: Syscall dispatch IpcRecv failed");

    // 4. Verify Bulk Shared Memory Capability Ring
    let mut ring = shared_ring::SharedRingBuffer::new();
    let enq_res = ring.enqueue(0x1000, 4096);
    assert!(enq_res.is_ok(), "Phase 4: SharedRing enqueue failed");

    let deq_desc = ring.dequeue();
    assert!(deq_desc.is_some(), "Phase 4: SharedRing dequeue failed");
    let desc = deq_desc.unwrap();
    assert_eq!(desc.buffer_offset, 0x1000);
    assert_eq!(desc.length, 4096);
    assert_eq!(desc.flags, 2); // Processed
}
