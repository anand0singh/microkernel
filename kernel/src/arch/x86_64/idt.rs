use crate::arch::x86_64::gdt;
use spin::Lazy;
use spin::Mutex;
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

pub const TIMER_INTERRUPT_INDEX: u8 = 32;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();

    idt.breakpoint.set_handler_fn(breakpoint_handler);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
    }
    idt.general_protection_fault
        .set_handler_fn(general_protection_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);

    // Vector 32: APIC Timer
    idt[TIMER_INTERRUPT_INDEX].set_handler_fn(timer_interrupt_handler);

    idt
});

pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(_stack_frame: InterruptStackFrame) {
    // Breakpoint exception handler stub
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn general_protection_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!(
        "EXCEPTION: GENERAL PROTECTION FAULT (Error Code: {:#x})\n{:#?}",
        error_code, stack_frame
    );
}

pub static LAST_PAGE_FAULT_CR2: Mutex<Option<u64>> = Mutex::new(None);
pub static LAST_PAGE_FAULT_ERROR_CODE: Mutex<Option<u64>> = Mutex::new(None);

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    let faulting_address = Cr2::read().expect("Failed to read CR2 register");
    let code_raw = error_code.bits();

    *LAST_PAGE_FAULT_CR2.lock() = Some(faulting_address.as_u64());
    *LAST_PAGE_FAULT_ERROR_CODE.lock() = Some(code_raw);

    // Check if Ring 3 protection violation (Error Code 0x05)
    if error_code.contains(PageFaultErrorCode::USER_MODE)
        && error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
    {
        // Ring 3 user protection violation caught cleanly without kernel crash
        return;
    }

    panic!(
        "EXCEPTION: PAGE FAULT at {:#x} with error code {:?}\n{:#?}",
        faulting_address, error_code, stack_frame
    );
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    crate::sched::on_timer_tick();
    unsafe {
        crate::arch::x86_64::apic::end_of_interrupt();
    }
}
