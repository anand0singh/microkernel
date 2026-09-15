#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, ipc_recv};

pub const DRIVER_NET_ENDPOINT: u64 = 15;
pub const NET_QUEUE_SIZE: usize = 16;
pub const MAX_PACKET_SIZE: usize = 1514;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtIONetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtIONetHdr {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        }
    }
}

pub struct VirtIONetDevice {
    pub mac_addr: [u8; 6],
    pub tx_descriptors: [[u8; MAX_PACKET_SIZE]; NET_QUEUE_SIZE],
    pub rx_descriptors: [[u8; MAX_PACKET_SIZE]; NET_QUEUE_SIZE],
    pub tx_head: usize,
    pub rx_head: usize,
    pub packets_sent: u64,
    pub packets_received: u64,
}

impl VirtIONetDevice {
    pub const fn new() -> Self {
        Self {
            mac_addr: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // Standard VirtIO MAC
            tx_descriptors: [[0u8; MAX_PACKET_SIZE]; NET_QUEUE_SIZE],
            rx_descriptors: [[0u8; MAX_PACKET_SIZE]; NET_QUEUE_SIZE],
            tx_head: 0,
            rx_head: 0,
            packets_sent: 0,
            packets_received: 0,
        }
    }

    pub fn transmit(&mut self, payload: &[u8]) -> Result<usize, ()> {
        if payload.len() > MAX_PACKET_SIZE {
            return Err(());
        }
        let slot = self.tx_head % NET_QUEUE_SIZE;
        self.tx_descriptors[slot][..payload.len()].copy_from_slice(payload);
        self.tx_head = (self.tx_head + 1) % NET_QUEUE_SIZE;
        self.packets_sent += 1;
        Ok(payload.len())
    }

    pub fn receive(&mut self, out_buf: &mut [u8]) -> Result<usize, ()> {
        let slot = self.rx_head % NET_QUEUE_SIZE;
        let len = out_buf.len().min(MAX_PACKET_SIZE);
        out_buf[..len].copy_from_slice(&self.rx_descriptors[slot][..len]);
        self.rx_head = (self.rx_head + 1) % NET_QUEUE_SIZE;
        self.packets_received += 1;
        Ok(len)
    }
}

pub static mut NET_DEV: VirtIONetDevice = VirtIONetDevice::new();

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {
        let (op, _arg0, _arg1, _) = ipc_recv(DRIVER_NET_ENDPOINT);
        let dev = unsafe { &mut *core::ptr::addr_of_mut!(NET_DEV) };

        match op {
            1 => {
                // Op 1: Query MAC address
                let mac_word = u64::from_le_bytes([
                    dev.mac_addr[0], dev.mac_addr[1], dev.mac_addr[2],
                    dev.mac_addr[3], dev.mac_addr[4], dev.mac_addr[5],
                    0, 0,
                ]);
                ipc_call(DRIVER_NET_ENDPOINT, 0, mac_word, 0, 0);
            }
            2 => {
                // Op 2: Transmit simulated 64-byte ethernet frame
                let test_frame = [0xFFu8; 64];
                let res = if dev.transmit(&test_frame).is_ok() { 0 } else { u64::MAX };
                ipc_call(DRIVER_NET_ENDPOINT, 0, res, dev.packets_sent, 0);
            }
            3 => {
                // Op 3: Query packet metrics
                ipc_call(DRIVER_NET_ENDPOINT, 0, dev.packets_sent, dev.packets_received, 0);
            }
            _ => {
                ipc_call(DRIVER_NET_ENDPOINT, 0, u64::MAX, 0, 0);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
