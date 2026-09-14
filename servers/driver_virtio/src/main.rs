#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::ipc_recv;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct VirtQueueDescriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C, align(2))]
pub struct VirtQueueAvailable {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 16],
}

#[repr(C, align(4))]
#[derive(Clone, Copy)]
pub struct VirtQueueUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C, align(4))]
pub struct VirtQueueUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtQueueUsedElem; 16],
}

pub struct VirtIOBlockDevice {
    pub mmio_base: *mut u32,
    pub desc: [VirtQueueDescriptor; 16],
    pub avail: VirtQueueAvailable,
    pub used: VirtQueueUsed,
}

impl VirtIOBlockDevice {
    pub const fn new(mmio_base: *mut u32) -> Self {
        Self {
            mmio_base,
            desc: [VirtQueueDescriptor { addr: 0, len: 0, flags: 0, next: 0 }; 16],
            avail: VirtQueueAvailable { flags: 0, idx: 0, ring: [0; 16] },
            used: VirtQueueUsed { flags: 0, idx: 0, ring: [VirtQueueUsedElem { id: 0, len: 0 }; 16] },
        }
    }

    pub fn submit_request(&mut self, desc_idx: u16, addr: u64, len: u32, is_write: bool) {
        let slot = (desc_idx as usize) % 16;
        let flags = if is_write { 0 } else { 2 }; // 2 = VRING_DESC_F_WRITE
        self.desc[slot] = VirtQueueDescriptor {
            addr,
            len,
            flags,
            next: 0,
        };
        let avail_slot = (self.avail.idx as usize) % 16;
        self.avail.ring[avail_slot] = desc_idx;
        self.avail.idx = self.avail.idx.wrapping_add(1);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let irq_endpoint_cap = 15; // VirtIO IRQ notification cap

    loop {
        // Receive IRQ notification from microkernel interrupt capability
        let (_irq_vector, _, _, _) = ipc_recv(irq_endpoint_cap);

        // Process VirtQueue used ring descriptors
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
