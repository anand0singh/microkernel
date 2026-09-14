use core::sync::atomic::{AtomicU32, Ordering};

pub const RING_BUFFER_SLOTS: usize = 16;
pub const CHUNK_SIZE: usize = 4096;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct SharedRingDescriptor {
    pub buffer_offset: u32,
    pub length: u32,
    pub flags: u32, // 1 = Ready, 2 = Processed
    pub status: u32,
}

#[repr(C, align(64))]
pub struct SharedRingHeader {
    pub producer_idx: AtomicU32,
    pub consumer_idx: AtomicU32,
    pub capacity: u32,
    pub slot_size: u32,
}

pub struct SharedRingBuffer {
    pub header: SharedRingHeader,
    pub descriptors: [SharedRingDescriptor; RING_BUFFER_SLOTS],
}

impl SharedRingBuffer {
    pub const fn new() -> Self {
        Self {
            header: SharedRingHeader {
                producer_idx: AtomicU32::new(0),
                consumer_idx: AtomicU32::new(0),
                capacity: RING_BUFFER_SLOTS as u32,
                slot_size: CHUNK_SIZE as u32,
            },
            descriptors: [const {
                SharedRingDescriptor {
                    buffer_offset: 0,
                    length: 0,
                    flags: 0,
                    status: 0,
                }
            }; RING_BUFFER_SLOTS],
        }
    }

    pub fn enqueue(&mut self, offset: u32, length: u32) -> Result<u32, ()> {
        let prod = self.header.producer_idx.load(Ordering::Acquire);
        let cons = self.header.consumer_idx.load(Ordering::Acquire);

        if prod.wrapping_sub(cons) >= RING_BUFFER_SLOTS as u32 {
            return Err(()); // Ring full
        }

        let slot = (prod as usize) % RING_BUFFER_SLOTS;
        self.descriptors[slot] = SharedRingDescriptor {
            buffer_offset: offset,
            length,
            flags: 1, // Ready
            status: 0,
        };

        self.header.producer_idx.store(prod.wrapping_add(1), Ordering::Release);
        Ok(prod)
    }

    pub fn dequeue(&mut self) -> Option<SharedRingDescriptor> {
        let prod = self.header.producer_idx.load(Ordering::Acquire);
        let cons = self.header.consumer_idx.load(Ordering::Acquire);

        if prod == cons {
            return None; // Ring empty
        }

        let slot = (cons as usize) % RING_BUFFER_SLOTS;
        let desc = self.descriptors[slot];
        self.descriptors[slot].flags = 2; // Processed

        self.header.consumer_idx.store(cons.wrapping_add(1), Ordering::Release);
        Some(desc)
    }
}
