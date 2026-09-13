use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags};
use x86_64::structures::paging::PageTable;

pub const HIGHER_HALF_OFFSET: u64 = 0xFFFF_8000_0000_0000;
pub const KERNEL_PML4_INDEX: usize = 511;

pub struct ProcessPageTables {
    pub kernel_pml4_phys: u64,
    pub user_pml4_phys: u64,
    pub pcid: u16,
}

pub unsafe fn init_vmm() {
    // 1. Configure CR4 Flags: PGE (Global Pages), PCID (ASID/PCID), FSGSBASE (WRFSBASE/WRGSBASE)
    let mut cr4_flags = Cr4::read();
    cr4_flags.insert(Cr4Flags::PAGE_GLOBAL);
    cr4_flags.insert(Cr4Flags::PCID);
    cr4_flags.insert(Cr4Flags::FSGSBASE);
    Cr4::write(cr4_flags);

    // 2. Configure CR0 Flags: Enforce Write Protect in supervisor mode
    let mut cr0_flags = Cr0::read();
    cr0_flags.insert(Cr0Flags::WRITE_PROTECT);
    Cr0::write(cr0_flags);
}

pub unsafe fn create_user_page_table(kernel_pml4_phys: u64, user_pml4_phys: u64) {
    let kernel_pml4 = (HIGHER_HALF_OFFSET + kernel_pml4_phys) as *const PageTable;
    let user_pml4 = (HIGHER_HALF_OFFSET + user_pml4_phys) as *mut PageTable;

    // Zero out user entries (0..256)
    for i in 0..256 {
        (&mut *user_pml4)[i].set_unused();
    }

    // Copy Higher-Half Kernel entry (slot 511) from Kernel PML4
    (&mut *user_pml4)[KERNEL_PML4_INDEX] = (&*kernel_pml4)[KERNEL_PML4_INDEX].clone();
}

pub unsafe fn switch_page_table(pml4_phys: u64, _pcid: u16) {
    let frame = x86_64::structures::paging::PhysFrame::containing_address(
        x86_64::PhysAddr::new(pml4_phys),
    );
    let flags = x86_64::registers::control::Cr3Flags::empty();
    Cr3::write(frame, flags);
}
