pub mod buddy;
pub mod slab;
pub mod vmm;

pub fn init_mm(physical_memory_base: u64, total_bytes: usize) {
    unsafe {
        buddy::BUDDY_ALLOCATOR
            .lock()
            .add_memory_region(physical_memory_base, total_bytes);
        vmm::init_vmm();

        test_phase2_mm();
    }
}

pub unsafe fn test_phase2_mm() {
    // 1. Verify Buddy Allocator allocation & deallocation
    let mut allocator = buddy::BuddyAllocator::new();
    // Simulate a 16 MiB region starting at physical address 0x2000000 (32 MiB)
    allocator.add_memory_region(0x2000000, 16 * 1024 * 1024);

    // Allocate order 0 (4 KiB page)
    let page0 = allocator.allocate_order(0);
    assert!(page0.is_some(), "Phase 2: Buddy Allocator order 0 allocation failed");
    let page0_addr = page0.unwrap();

    // Allocate order 3 (32 KiB block)
    let block_ord3 = allocator.allocate_order(3);
    assert!(block_ord3.is_some(), "Phase 2: Buddy Allocator order 3 allocation failed");

    // Deallocate order 0 & order 3 to trigger buddy coalescing
    allocator.deallocate_order(page0_addr, 0);
    allocator.deallocate_order(block_ord3.unwrap(), 3);

    // 2. Verify Slab Cache allocation & deallocation
    let mut slab = slab::SlabCache::<256>::new();
    let mock_frame: [u8; 4096] = [0u8; 4096];
    slab.add_slab_frame(mock_frame.as_ptr() as u64);

    let obj1 = slab.alloc();
    assert!(obj1.is_some(), "Phase 2: SlabCache allocation failed");
    let obj2 = slab.alloc();
    assert!(obj2.is_some(), "Phase 2: SlabCache second object allocation failed");

    let ptr1 = obj1.unwrap();
    slab.dealloc(ptr1);

    let obj3 = slab.alloc();
    assert_eq!(obj3.unwrap(), ptr1, "Phase 2: SlabCache LIFO object reuse failed");
}
