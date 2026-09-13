use x86_64::registers::model_specific::Msr;

const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;

pub struct LocalApic {
    base_address: u64,
}

impl LocalApic {
    pub unsafe fn new() -> Self {
        let msr = Msr::new(IA32_APIC_BASE_MSR);
        let base = msr.read() & 0xFFFF_F000;
        Self { base_address: base }
    }

    pub unsafe fn init(&mut self) {
        // Enable APIC in MSR
        let mut msr = Msr::new(IA32_APIC_BASE_MSR);
        let current = msr.read();
        msr.write(current | APIC_BASE_ENABLE);

        // Enable Spurious Interrupt Register (SVR) at offset 0xF0 (bit 8 set, vector 0xFF)
        self.write_reg(0xF0, 0x1FF);

        // Configure Local APIC Timer (Offset 0x320)
        // Vector 32 (0x20), Periodic Mode (bit 17 set)
        let timer_lvt = 32 | (1 << 17);
        self.write_reg(0x320, timer_lvt);

        // Set Divide Configuration Register (Offset 0x3E0) to Divide by 16
        self.write_reg(0x3E0, 0x3);

        // Set Initial Count Register (Offset 0x380) for ~1ms quantum target
        self.write_reg(0x380, 0x10000);
    }

    pub unsafe fn eoi(&mut self) {
        self.write_reg(0xB0, 0);
    }

    unsafe fn write_reg(&self, offset: u32, value: u32) {
        let ptr = (self.base_address + offset as u64) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    unsafe fn read_reg(&self, offset: u32) -> u32 {
        let ptr = (self.base_address + offset as u64) as *const u32;
        core::ptr::read_volatile(ptr)
    }
}

pub unsafe fn end_of_interrupt() {
    let mut apic = LocalApic::new();
    apic.eoi();
}
