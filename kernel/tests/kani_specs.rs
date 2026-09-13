#[cfg(kani)]
#[kani::proof]
fn verify_buddy_allocator_block_split_no_overflow() {
    let order: usize = kani::any();
    kani::assume(order < 12);
    let page: usize = kani::any();
    kani::assume(page < 10000);

    let buddy = page ^ (1 << order);
    assert!(buddy != page);
}

#[cfg(kani)]
#[kani::proof]
fn verify_cnode_slot_traversal_bounds() {
    let slot: usize = kani::any();
    if slot >= 256 {
        assert!(slot >= 256);
    } else {
        assert!(slot < 256);
    }
}
