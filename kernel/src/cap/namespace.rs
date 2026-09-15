//! Multi-Tenant Capability Namespaces & Security Domain Partitioning
//! Enforces strict isolation between mutually distrusting process realms.

pub const MAX_DOMAINS: usize = 8;
pub const ROOT_DOMAIN_ID: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainId(pub u32);

pub struct SecurityDomain {
    pub id: DomainId,
    pub name: [u8; 16],
    pub root_cnode_slot: usize,
    pub is_isolated: bool,
    pub violation_count: u32,
}

impl SecurityDomain {
    pub const fn empty() -> Self {
        Self {
            id: DomainId(0),
            name: [0u8; 16],
            root_cnode_slot: 0,
            is_isolated: true,
            violation_count: 0,
        }
    }
}

pub struct DomainManager {
    pub domains: [Option<SecurityDomain>; MAX_DOMAINS],
    pub thread_domain_map: [(u64, DomainId); 32], // Maps thread_id -> DomainId
}

impl DomainManager {
    pub const fn new() -> Self {
        Self {
            domains: [None, None, None, None, None, None, None, None],
            thread_domain_map: [(0, DomainId(ROOT_DOMAIN_ID)); 32],
        }
    }

    pub fn register_domain(&mut self, id: u32, name: &[u8], cnode_slot: usize) -> Result<(), ()> {
        let idx = id as usize;
        if idx >= MAX_DOMAINS {
            return Err(());
        }

        let mut dname = [0u8; 16];
        let copy_len = name.len().min(16);
        dname[..copy_len].copy_from_slice(&name[..copy_len]);

        self.domains[idx] = Some(SecurityDomain {
            id: DomainId(id),
            name: dname,
            root_cnode_slot: cnode_slot,
            is_isolated: true,
            violation_count: 0,
        });
        Ok(())
    }

    pub fn assign_thread_domain(&mut self, thread_id: u64, domain: DomainId) {
        for entry in self.thread_domain_map.iter_mut() {
            if entry.0 == 0 || entry.0 == thread_id {
                *entry = (thread_id, domain);
                return;
            }
        }
    }

    pub fn get_thread_domain(&self, thread_id: u64) -> DomainId {
        for entry in self.thread_domain_map.iter() {
            if entry.0 == thread_id {
                return entry.1;
            }
        }
        DomainId(ROOT_DOMAIN_ID)
    }

    /// Validates whether a caller thread in Domain A is allowed to invoke an object in Domain B
    pub fn can_access(&mut self, caller_thread_id: u64, target_domain: DomainId) -> bool {
        let caller_domain = self.get_thread_domain(caller_thread_id);
        if caller_domain == target_domain || caller_domain.0 == ROOT_DOMAIN_ID {
            true
        } else {
            // Log domain isolation boundary fault
            if let Some(ref mut d) = self.domains[caller_domain.0 as usize] {
                d.violation_count += 1;
            }
            false
        }
    }
}

pub static DOMAIN_MANAGER: spin::Mutex<DomainManager> = spin::Mutex::new(DomainManager::new());
