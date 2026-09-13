pub mod buddy;
pub mod slab;
pub mod vmm;

pub fn init_mm(physical_memory_base: u64, total_bytes: usize) {
    unsafe {
        buddy::BUDDY_ALLOCATOR
            .lock()
            .add_memory_region(physical_memory_base, total_bytes);
        vmm::init_vmm();
    }
}
