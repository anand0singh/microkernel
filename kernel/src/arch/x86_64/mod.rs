pub mod apic;
pub mod entry;
pub mod gdt;
pub mod idt;
pub mod serial;
pub mod syscall;

pub fn init_arch() {
    serial::init_serial();
    gdt::init_gdt();
    idt::init_idt();
    unsafe {
        let mut lapic = apic::LocalApic::new();
        lapic.init();
        let syscall_ptr = entry::syscall_entry as *const () as usize as u64;
        syscall::init_syscall_msrs(x86_64::VirtAddr::new(syscall_ptr));
    }
}
