#![no_std]
#![no_main]

use core::panic::PanicInfo;
use libsys::{ipc_call, ipc_recv};

pub const KEYSTORE_ENDPOINT: u64 = 40;
pub const MAX_KEYS: usize = 32;
pub const KEY_SIZE: usize = 32;

#[derive(Clone, Copy)]
pub struct KeySlot {
    pub key: [u8; KEY_SIZE],
    pub is_active: bool,
    pub is_locked: bool,
}

impl KeySlot {
    pub const fn empty() -> Self {
        Self {
            key: [0u8; KEY_SIZE],
            is_active: false,
            is_locked: false,
        }
    }

    /// Overwrite key memory with zeros using volatile writes to prevent compiler elision
    pub fn zeroize(&mut self) {
        for b in self.key.iter_mut() {
            unsafe {
                core::ptr::write_volatile(b, 0u8);
            }
        }
        self.is_active = false;
        self.is_locked = false;
    }
}

pub struct SecureKeystore {
    pub slots: [KeySlot; MAX_KEYS],
    pub emergency_wipe_triggered: bool,
}

impl SecureKeystore {
    pub const fn new() -> Self {
        Self {
            slots: [KeySlot::empty(); MAX_KEYS],
            emergency_wipe_triggered: false,
        }
    }

    pub fn store_key(&mut self, slot: usize, key_data: [u8; KEY_SIZE]) -> Result<(), ()> {
        if slot >= MAX_KEYS || self.emergency_wipe_triggered {
            return Err(());
        }
        self.slots[slot].key = key_data;
        self.slots[slot].is_active = true;
        Ok(())
    }

    /// HKDF-style key derivation function using FNV-1a mixing with salt
    pub fn derive_key(&mut self, src_slot: usize, dest_slot: usize, salt: u64) -> Result<(), ()> {
        if src_slot >= MAX_KEYS || dest_slot >= MAX_KEYS || self.emergency_wipe_triggered {
            return Err(());
        }
        if !self.slots[src_slot].is_active {
            return Err(());
        }

        let mut derived = [0u8; KEY_SIZE];
        let mut state = salt.wrapping_add(0x9E37_79B9_7F4A_7C15);

        for (i, &b) in self.slots[src_slot].key.iter().enumerate() {
            state ^= b as u64;
            state = state.wrapping_mul(0x100000001B3);
            derived[i] = (state >> ((i % 8) * 8)) as u8;
        }

        self.slots[dest_slot].key = derived;
        self.slots[dest_slot].is_active = true;
        Ok(())
    }

    pub fn zeroize_slot(&mut self, slot: usize) -> Result<(), ()> {
        if slot >= MAX_KEYS {
            return Err(());
        }
        self.slots[slot].zeroize();
        Ok(())
    }

    /// Anti-tamper emergency wipe: zeroizes every single key slot across the enclave
    pub fn emergency_wipe(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.zeroize();
        }
        self.emergency_wipe_triggered = true;
    }

    pub fn active_key_count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_active).count()
    }
}

pub static mut KEYSTORE: SecureKeystore = SecureKeystore::new();

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {
        let (op, arg0, arg1, arg2) = ipc_recv(KEYSTORE_ENDPOINT);
        let keystore = unsafe { &mut *core::ptr::addr_of_mut!(KEYSTORE) };

        match op {
            1 => {
                // Op 1: Store 16 bytes across arg1, arg2 into slot arg0
                let slot = arg0 as usize;
                let mut key = [0u8; KEY_SIZE];
                key[..8].copy_from_slice(&arg1.to_le_bytes());
                key[8..16].copy_from_slice(&arg2.to_le_bytes());
                let res = if keystore.store_key(slot, key).is_ok() { 0 } else { u64::MAX };
                ipc_call(KEYSTORE_ENDPOINT, 0, res, 0, 0);
            }
            2 => {
                // Op 2: Derive key from src (arg0) to dest (arg1) with salt (arg2)
                let res = if keystore.derive_key(arg0 as usize, arg1 as usize, arg2).is_ok() {
                    0
                } else {
                    u64::MAX
                };
                ipc_call(KEYSTORE_ENDPOINT, 0, res, 0, 0);
            }
            3 => {
                // Op 3: Zeroize key slot
                let res = if keystore.zeroize_slot(arg0 as usize).is_ok() { 0 } else { u64::MAX };
                ipc_call(KEYSTORE_ENDPOINT, 0, res, 0, 0);
            }
            4 => {
                // Op 4: Emergency Wipe (Anti-Tamper)
                keystore.emergency_wipe();
                ipc_call(KEYSTORE_ENDPOINT, 0, 0, 0, 0);
            }
            5 => {
                // Op 5: Query Keystore Status
                let count = keystore.active_key_count() as u64;
                let wiped = if keystore.emergency_wipe_triggered { 1 } else { 0 };
                ipc_call(KEYSTORE_ENDPOINT, 0, count, wiped, 0);
            }
            _ => {
                ipc_call(KEYSTORE_ENDPOINT, 0, u64::MAX, 0, 0);
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
