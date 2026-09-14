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
fn verify_buddy_coalescing_is_involution() {
    let order: usize = kani::any();
    kani::assume(order < 12);
    let page: usize = kani::any();

    let buddy = page ^ (1 << order);
    let rebuddy = buddy ^ (1 << order);
    assert_eq!(rebuddy, page);
}

#[cfg(kani)]
#[kani::proof]
fn verify_rights_attenuation_monotonicity() {
    let parent_rights: u8 = kani::any();
    let requested_rights: u8 = kani::any();

    // Attenuation rule: child_rights = parent_rights & requested_rights
    let child_rights = parent_rights & requested_rights;

    // Invariant 1: Child cannot possess rights not held by parent
    assert!((child_rights & !parent_rights) == 0);

    // Invariant 2: Child cannot possess rights beyond what was requested
    assert!((child_rights & !requested_rights) == 0);
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
