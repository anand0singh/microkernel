pub mod audit;
pub mod filter;
pub mod ids;
pub mod tpm;

pub fn init_security() {
    unsafe {
        // 1. Initialize TPM 2.0 PCR baseline measurement
        let mut tpm = tpm::TPM_BANK.lock();
        let kernel_boot_digest: [u8; 32] = [0xAA; 32];
        let _ = tpm.extend(0, &kernel_boot_digest); // PCR[0] Firmware / Kernel Baseline

        let userspace_init_digest: [u8; 32] = [0x55; 32];
        let _ = tpm.extend(2, &userspace_init_digest); // PCR[2] Userspace Init Orchestrator

        // 2. Run automated security self-verification suite
        test_security_layer();
    }
}

pub unsafe fn test_security_layer() {
    // 1. Verify TPM PCR Extension
    let pcr0_val = tpm::TPM_BANK.lock().read_pcr(0).unwrap();
    assert_ne!(pcr0_val, [0u8; 32], "Security: PCR[0] failed to accumulate measurement");

    // 2. Verify Audit Logging
    audit::AUDIT_LOG.lock().record(1, 10, 4, audit::AuditVerdict::Allowed);
    let latest = audit::AUDIT_LOG.lock().latest_event().unwrap();
    assert_eq!(latest.caller_thread_id, 1);
    assert_eq!(latest.verdict, audit::AuditVerdict::Allowed);

    // 3. Verify Intrusion Detection Tripwire
    let rogue_thread_id = 99;
    ids::IDS_ENGINE.lock().reset_profile(rogue_thread_id);

    // Simulate 4 violations (below threshold of 5)
    for _ in 0..4 {
        let tripped = ids::IDS_ENGINE.lock().record_violation(rogue_thread_id, 999, 1);
        assert!(!tripped, "Security: IDS tripped prematurely");
    }
    assert!(!ids::IDS_ENGINE.lock().is_quarantined(rogue_thread_id));

    // 5th violation trips the tripwire!
    let tripped = ids::IDS_ENGINE.lock().record_violation(rogue_thread_id, 999, 1);
    assert!(tripped, "Security: IDS tripwire failed to trigger on 5th violation");
    assert!(ids::IDS_ENGINE.lock().is_quarantined(rogue_thread_id), "Security: Thread failed to quarantine");

    // 4. Verify Programmable Seccomp-like Capability Filter
    let mut pf = filter::ProcessSecurityFilter::new();
    // Deny Opcode 3 (CapRevoke) on Slot 5
    let rule_res = pf.add_rule(5, 3, filter::FilterAction::Deny);
    assert!(rule_res.is_ok());

    assert_eq!(pf.evaluate(5, 3), filter::FilterAction::Deny);
    assert_eq!(pf.evaluate(5, 4), filter::FilterAction::Allow); // Other opcodes allowed

    pf.lock();
    assert!(pf.add_rule(6, 1, filter::FilterAction::Deny).is_err(), "Filter allowed rule modification after lock");
}
