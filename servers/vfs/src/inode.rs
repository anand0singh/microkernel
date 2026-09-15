//! Capability-Guarded Inode Table for Encrypted VFS

pub const MAX_INODES: usize = 16;
pub const DIRECT_BLOCKS: usize = 8;

#[derive(Clone, Copy)]
pub struct Inode {
    pub ino: u32,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub blocks: [u32; DIRECT_BLOCKS],
    pub name: [u8; 16],
    pub required_cap_rights: u8,
}

impl Inode {
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            is_dir: false,
            size_bytes: 0,
            blocks: [0; DIRECT_BLOCKS],
            name: [0; 16],
            required_cap_rights: 0,
        }
    }
}

pub struct InodeTable {
    pub inodes: [Inode; MAX_INODES],
    pub count: usize,
}

impl InodeTable {
    pub const fn new() -> Self {
        Self {
            inodes: [const { Inode::empty() }; MAX_INODES],
            count: 0,
        }
    }

    pub fn init_standard_hierarchy(&mut self) {
        // Inode 1: Root /
        let mut root_name = [0u8; 16];
        root_name[0] = b'/';
        self.inodes[0] = Inode {
            ino: 1,
            is_dir: true,
            size_bytes: 4096,
            blocks: [1, 0, 0, 0, 0, 0, 0, 0],
            name: root_name,
            required_cap_rights: 0b0001, // Read
        };

        // Inode 2: /etc
        let mut etc_name = [0u8; 16];
        etc_name[0..3].copy_from_slice(b"etc");
        self.inodes[1] = Inode {
            ino: 2,
            is_dir: true,
            size_bytes: 4096,
            blocks: [2, 0, 0, 0, 0, 0, 0, 0],
            name: etc_name,
            required_cap_rights: 0b0001,
        };

        // Inode 3: /vault
        let mut vault_name = [0u8; 16];
        vault_name[0..5].copy_from_slice(b"vault");
        self.inodes[2] = Inode {
            ino: 3,
            is_dir: true,
            size_bytes: 4096,
            blocks: [3, 0, 0, 0, 0, 0, 0, 0],
            name: vault_name,
            required_cap_rights: 0b0111, // Read | Write | Execute (Vault cap only)
        };

        // Inode 4: /bin
        let mut bin_name = [0u8; 16];
        bin_name[0..3].copy_from_slice(b"bin");
        self.inodes[3] = Inode {
            ino: 4,
            is_dir: true,
            size_bytes: 4096,
            blocks: [4, 0, 0, 0, 0, 0, 0, 0],
            name: bin_name,
            required_cap_rights: 0b0101, // Read | Execute
        };

        self.count = 4;
    }

    pub fn lookup(&self, name_slice: &[u8]) -> Option<&Inode> {
        for i in 0..self.count {
            let inode = &self.inodes[i];
            let len = inode.name.iter().position(|&c| c == 0).unwrap_or(16);
            if &inode.name[0..len] == name_slice {
                return Some(inode);
            }
        }
        None
    }
}
