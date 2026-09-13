#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::ipc_recv;

#[repr(C, align(16))]
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
