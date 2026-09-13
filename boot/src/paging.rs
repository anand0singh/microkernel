use x86_64::structures::paging::{OffsetPageTable, PageTable};
use x86_64::VirtAddr;

pub const HIGHER_HALF_OFFSET: u64 = 0xFFFF_8000_0000_0000;

pub unsafe fn init_early_paging(
    physical_memory_offset: VirtAddr,
) -> OffsetPageTable<'static> {
    let (level_4_table_frame, _) = x86_64::registers::control::Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    OffsetPageTable::new(&mut *page_table_ptr, physical_memory_offset)
}
