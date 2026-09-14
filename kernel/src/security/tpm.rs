use spin::Mutex;

pub const NUM_PCR_REGISTERS: usize = 8;
pub const HASH_LEN: usize = 32;

#[derive(Clone, Copy)]
pub struct PcrRegister {
    pub digest: [u8; HASH_LEN],
}

impl PcrRegister {
    pub const fn new() -> Self {
        Self { digest: [0u8; HASH_LEN] }
    }
}

pub struct TpmPcrRegisterBank {
    pub pcrs: [PcrRegister; NUM_PCR_REGISTERS],
    pub measurement_count: usize,
}

impl TpmPcrRegisterBank {
    pub const fn new() -> Self {
        Self {
            pcrs: [const { PcrRegister::new() }; NUM_PCR_REGISTERS],
            measurement_count: 0,
        }
    }

    /// Extends a PCR register with a new measurement digest:
    /// PCR[i] = Hash(PCR[i] || measurement)
    pub fn extend(&mut self, pcr_index: usize, measurement: &[u8; HASH_LEN]) -> Result<[u8; HASH_LEN], ()> {
        if pcr_index >= NUM_PCR_REGISTERS {
            return Err(());
        }

        let mut combined = [0u8; 64];
        combined[0..32].copy_from_slice(&self.pcrs[pcr_index].digest);
        combined[32..64].copy_from_slice(measurement);

        // Constant-time sponge hash combining PCR digest and measurement
        let mut new_digest = [0u8; HASH_LEN];
        let mut state: u64 = 0x6a09e667f3bcc908;
        for chunk in combined.chunks(8) {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            state = state.rotate_left(13) ^ val.wrapping_mul(0x9e3779b97f4a7c15);
        }

        for i in (0..HASH_LEN).step_by(8) {
            state = state.wrapping_add(0x510e527fade682d1).rotate_left(7);
            new_digest[i..i + 8].copy_from_slice(&state.to_le_bytes());
        }

        self.pcrs[pcr_index].digest = new_digest;
        self.measurement_count += 1;
        Ok(new_digest)
    }

    pub fn read_pcr(&self, pcr_index: usize) -> Option<[u8; HASH_LEN]> {
        if pcr_index < NUM_PCR_REGISTERS {
            Some(self.pcrs[pcr_index].digest)
        } else {
            None
        }
    }
}

pub static TPM_BANK: Mutex<TpmPcrRegisterBank> = Mutex::new(TpmPcrRegisterBank::new());
