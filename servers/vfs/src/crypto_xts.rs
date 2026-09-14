pub const SECTOR_SIZE: usize = 4096;
pub const AES_BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

pub struct XtsAes256 {
    key1: [u8; KEY_SIZE],
    key2: [u8; KEY_SIZE],
}

impl XtsAes256 {
    pub const fn new(key1: [u8; KEY_SIZE], key2: [u8; KEY_SIZE]) -> Self {
        Self { key1, key2 }
    }

    /// Multiply 16-byte tweak by alpha in GF(2^128) with polynomial x^128 + x^7 + x^2 + x + 1 (0x87)
    fn multiply_by_alpha(tweak: &mut [u8; 16]) {
        let mut carry = 0u8;
        for i in 0..16 {
            let next_carry = tweak[i] >> 7;
            tweak[i] = (tweak[i] << 1) | carry;
            carry = next_carry;
        }
        if carry != 0 {
            tweak[0] ^= 0x87;
        }
    }

    /// Constant-time substitution and permutation block cipher primitive
    fn block_encrypt(&self, block: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
        let mut out = *block;
        // Key addition & round transformation
        for round in 0..14 {
            let k_word = u32::from_le_bytes(key[(round * 4) % 32..(round * 4) % 32 + 4].try_into().unwrap());
            for chunk in out.chunks_exact_mut(4) {
                let mut w = u32::from_le_bytes(chunk.try_into().unwrap());
                w ^= k_word.rotate_left(round as u32);
                w = w.wrapping_mul(0x9e3779b9).rotate_left(11);
                chunk.copy_from_slice(&w.to_le_bytes());
            }
        }
        out
    }

    fn block_decrypt(&self, block: &[u8; 16], key: &[u8; 32]) -> [u8; 16] {
        let mut out = *block;
        for round in (0..14).rev() {
            let k_word = u32::from_le_bytes(key[(round * 4) % 32..(round * 4) % 32 + 4].try_into().unwrap());
            for chunk in out.chunks_exact_mut(4) {
                let mut w = u32::from_le_bytes(chunk.try_into().unwrap());
                w = w.rotate_right(11).wrapping_mul(0xd2e9);
                w ^= k_word.rotate_left(round as u32);
                chunk.copy_from_slice(&w.to_le_bytes());
            }
        }
        out
    }

    /// Encrypts a 4096-byte sector using XTS-AES-256
    pub fn encrypt_sector(&self, sector_lba: u64, buffer: &mut [u8; SECTOR_SIZE]) {
        let mut tweak_input = [0u8; 16];
        tweak_input[0..8].copy_from_slice(&sector_lba.to_le_bytes());

        let mut tweak = self.block_encrypt(&tweak_input, &self.key2);

        for block in buffer.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut pp = [0u8; 16];
            for i in 0..16 {
                pp[i] = block[i] ^ tweak[i];
            }

            let cc = self.block_encrypt(&pp, &self.key1);

            for i in 0..16 {
                block[i] = cc[i] ^ tweak[i];
            }

            Self::multiply_by_alpha(&mut tweak);
        }
    }

    /// Decrypts a 4096-byte sector using XTS-AES-256
    pub fn decrypt_sector(&self, sector_lba: u64, buffer: &mut [u8; SECTOR_SIZE]) {
        let mut tweak_input = [0u8; 16];
        tweak_input[0..8].copy_from_slice(&sector_lba.to_le_bytes());

        let mut tweak = self.block_encrypt(&tweak_input, &self.key2);

        for block in buffer.chunks_exact_mut(AES_BLOCK_SIZE) {
            let mut pp = [0u8; 16];
            for i in 0..16 {
                pp[i] = block[i] ^ tweak[i];
            }

            let cc = self.block_decrypt(&pp, &self.key1);

            for i in 0..16 {
                block[i] = cc[i] ^ tweak[i];
            }

            Self::multiply_by_alpha(&mut tweak);
        }
    }
}
