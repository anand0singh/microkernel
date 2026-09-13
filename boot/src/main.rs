#![no_std]
#![no_main]

extern crate alloc;

mod paging;

use log::info;
use uefi::prelude::*;
use uefi::table::boot::MemoryType;

#[entry]
fn main(handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();
    info!("Initializing Distributed Microkernel UEFI Bootloader...");

    let boot_services = system_table.boot_services();

    // 1. Get Memory Map Size & Storage
    let memory_map_size = boot_services.memory_map_size();
    let mut buffer = alloc::vec![0u8; memory_map_size.map_size + 1024];

    // 2. Query UEFI Memory Map
    let memory_map = boot_services
        .memory_map(&mut buffer)
        .expect("Failed to fetch UEFI memory map");

    let mut usable_frames = 0u64;
    let mut total_memory_bytes = 0u64;

    for descriptor in memory_map.entries() {
        let pages = descriptor.page_count;
        let bytes = pages * 4096;
        total_memory_bytes += bytes;

        match descriptor.ty {
            MemoryType::CONVENTIONAL => {
                usable_frames += pages;
            }
            MemoryType::LOADER_CODE | MemoryType::LOADER_DATA => {
                // Reclaimable after boot exit
                usable_frames += pages;
            }
            _ => {}
        }
    }

    info!(
        "Memory Map Summary: Total RAM: {} MiB, Usable Frames (4KiB): {}",
        total_memory_bytes / (1024 * 1024),
        usable_frames
    );

    info!("Bootloader complete. Ready for ExitBootServices handoff to Ring 0 Kernel.");
    Status::SUCCESS
}
