pub mod cdt;
pub mod cnode;
pub mod rights;

pub fn init_cap_engine() {
    unsafe {
        // Setup Root Capability in Slot 0
        let mut cdt = cdt::CDT.lock();
        if let Some(node_id) = cdt.alloc_node(0, None) {
            let root_cap = cnode::Capability {
                obj_type: cnode::ObjectType::CNode,
                rights: rights::Rights::all(),
                object_ptr: core::ptr::null_mut(),
                badge: None,
                cdt_node_id: node_id,
            };
            let _ = cnode::ROOT_CNODE.lock().insert(0, root_cap);
        }

        test_phase3_cap();
    }
}

pub unsafe fn test_phase3_cap() {
    // 1. Verify capability minting with rights attenuation (Slot 0 -> Slot 1)
    let mint_res1 = cdt::dispatch_cap_mint(
        0,
        1,
        (rights::Rights::READ | rights::Rights::WRITE).bits() as u64,
    );
    assert_eq!(mint_res1, 0, "Phase 3: Minting slot 0 -> slot 1 failed");

    let cap1 = cnode::ROOT_CNODE.lock().lookup(1);
    assert!(cap1.is_some(), "Phase 3: Slot 1 capability lookup failed");
    assert!(cap1.unwrap().rights.contains(rights::Rights::READ));

    // 2. Verify secondary derived minting (Slot 1 -> Slot 2)
    let mint_res2 = cdt::dispatch_cap_mint(
        1,
        2,
        rights::Rights::READ.bits() as u64,
    );
    assert_eq!(mint_res2, 0, "Phase 3: Minting slot 1 -> slot 2 failed");

    // 3. Verify sibling capability minting (Slot 0 -> Slot 3)
    let mint_res3 = cdt::dispatch_cap_mint(
        0,
        3,
        (rights::Rights::READ | rights::Rights::EXECUTE).bits() as u64,
    );
    assert_eq!(mint_res3, 0, "Phase 3: Minting slot 0 -> slot 3 failed");

    // Assert all 4 slots (0, 1, 2, 3) are populated
    {
        let cnode = cnode::ROOT_CNODE.lock();
        assert!(cnode.lookup(0).is_some());
        assert!(cnode.lookup(1).is_some());
        assert!(cnode.lookup(2).is_some());
        assert!(cnode.lookup(3).is_some());
    }

    // 4. Verify Badged Capability Creation (Slot 0 -> Slot 4 with badge 0xDEADBEEF)
    let badge_res = cdt::dispatch_cap_badge(0, 4, 0xDEAD_BEEF);
    assert_eq!(badge_res, 0, "Phase 3: Badging slot 0 -> slot 4 failed");

    let badged_cap = cnode::ROOT_CNODE.lock().lookup(4);
    assert!(badged_cap.is_some(), "Phase 3: Badged slot 4 lookup failed");
    assert_eq!(badged_cap.unwrap().badge, Some(0xDEAD_BEEF), "Phase 3: Badge mismatch");

    // 5. Verify Permission Enforcement (Attempt badging from ungranted Slot 2)
    let bad_badge_res = cdt::dispatch_cap_badge(2, 5, 0x1234);
    assert_eq!(bad_badge_res, 0xFFFF_FFFF_FFFF_FFFE, "Phase 3: Ungranted badging was not blocked");

    // 6. Trigger Cascading Revocation on Slot 1
    // Revoking slot 1 must recursively invalidate slot 1 (child) and slot 2 (grandchild),
    // while keeping slot 0 (root), slot 3 (sibling), and slot 4 (badged sibling) intact!
    let revoke_res = cdt::dispatch_cap_revoke(1);
    assert_eq!(revoke_res, 0, "Phase 3: Revoking slot 1 failed");

    {
        let cnode = cnode::ROOT_CNODE.lock();
        assert!(cnode.lookup(0).is_some(), "Phase 3: Root slot 0 was unexpectedly revoked");
        assert!(cnode.lookup(1).is_none(), "Phase 3: Slot 1 was not revoked");
        assert!(cnode.lookup(2).is_none(), "Phase 3: Grandchild slot 2 was not recursively revoked");
        assert!(cnode.lookup(3).is_some(), "Phase 3: Sibling slot 3 was unexpectedly revoked");
        assert!(cnode.lookup(4).is_some(), "Phase 3: Badged slot 4 was unexpectedly revoked");
    }
}
