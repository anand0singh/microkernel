//! Process Loader and Boot Information Protocol Subsystem
//! Manages ELF program parsing, memory isolation setup, and service dispatching.

pub mod elf;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub is_usable: bool,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootModule {
    pub name: [u8; 16],
    pub data_ptr: u64,
    pub data_len: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    pub memory_regions_count: usize,
    pub memory_regions: [MemoryRegion; 16],
    pub modules_count: usize,
    pub modules: [BootModule; 8],
    pub rsdp_addr: u64,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            memory_regions_count: 0,
            memory_regions: [MemoryRegion { base: 0, length: 0, is_usable: false }; 16],
            modules_count: 0,
            modules: [BootModule { name: [0u8; 16], data_ptr: 0, data_len: 0 }; 8],
            rsdp_addr: 0,
        }
    }
}
