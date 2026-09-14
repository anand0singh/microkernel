use super::cnode::{Capability, ROOT_CNODE};
use spin::Mutex;

pub const MAX_CDT_NODES: usize = 1024;

#[derive(Clone, Copy)]
pub struct CDTNode {
    pub parent: Option<usize>,
    pub first_child: Option<usize>,
    pub next_sibling: Option<usize>,
    pub owner_cnode_slot: usize,
    pub valid: bool,
}

pub struct CapabilityDerivationTree {
    pub nodes: [CDTNode; MAX_CDT_NODES],
    pub free_head: usize,
}

impl CapabilityDerivationTree {
    pub const fn new() -> Self {
        let mut nodes = [CDTNode {
            parent: None,
            first_child: None,
            next_sibling: None,
            owner_cnode_slot: 0,
            valid: false,
        }; MAX_CDT_NODES];

        let mut i = 0;
        while i < MAX_CDT_NODES - 1 {
            nodes[i].next_sibling = Some(i + 1);
            i += 1;
        }

        Self { nodes, free_head: 0 }
    }

    pub fn alloc_node(&mut self, slot: usize, parent: Option<usize>) -> Option<usize> {
        if self.free_head >= MAX_CDT_NODES {
            return None;
        }

        let idx = self.free_head;
        let next_free = self.nodes[idx].next_sibling;
        if let Some(nf) = next_free {
            self.free_head = nf;
        } else {
            self.free_head = MAX_CDT_NODES;
        }

        self.nodes[idx] = CDTNode {
            parent,
            first_child: None,
            next_sibling: None,
            owner_cnode_slot: slot,
            valid: true,
        };

        if let Some(p_idx) = parent {
            let old_child = self.nodes[p_idx].first_child;
            self.nodes[idx].next_sibling = old_child;
            self.nodes[p_idx].first_child = Some(idx);
        }

        Some(idx)
    }

    pub fn revoke(&mut self, node_idx: usize) {
        if node_idx >= MAX_CDT_NODES || !self.nodes[node_idx].valid {
            return;
        }

        // Recursively invalidate all children
        let mut child = self.nodes[node_idx].first_child;
        while let Some(c_idx) = child {
            let next_sib = self.nodes[c_idx].next_sibling;
            self.revoke(c_idx);
            child = next_sib;
        }

        // Invalidate owner slot in C-Node
        let slot = self.nodes[node_idx].owner_cnode_slot;
        ROOT_CNODE.lock().remove(slot);

        self.nodes[node_idx].valid = false;
        self.nodes[node_idx].next_sibling = Some(self.free_head);
        self.free_head = node_idx;
    }
}

pub static CDT: Mutex<CapabilityDerivationTree> = Mutex::new(CapabilityDerivationTree::new());

pub unsafe fn dispatch_cap_mint(src_slot: u64, dest_slot: u64, rights_mask: u64) -> u64 {
    let mut cnode = ROOT_CNODE.lock();
    if let Some(src_cap) = cnode.lookup(src_slot as usize) {
        let mut new_cap = src_cap.clone();
        new_cap.rights = super::rights::Rights::from_bits_truncate(rights_mask as u8);

        let mut cdt = CDT.lock();
        if let Some(node_id) = cdt.alloc_node(dest_slot as usize, Some(src_cap.cdt_node_id)) {
            new_cap.cdt_node_id = node_id;
            if cnode.insert(dest_slot as usize, new_cap).is_ok() {
                return 0; // Success
            }
        }
    }
    0xFFFF_FFFF_FFFF_FFFF
}

pub unsafe fn dispatch_cap_revoke(slot: u64) -> u64 {
    let cnode = ROOT_CNODE.lock();
    if let Some(cap) = cnode.lookup(slot as usize) {
        let cdt_node_id = cap.cdt_node_id;
        drop(cnode);
        CDT.lock().revoke(cdt_node_id);
        0
    } else {
        0xFFFF_FFFF_FFFF_FFFF
    }
}

pub unsafe fn dispatch_cap_badge(src_slot: u64, dest_slot: u64, badge: u64) -> u64 {
    let mut cnode = ROOT_CNODE.lock();
    if let Some(src_cap) = cnode.lookup(src_slot as usize) {
        if !src_cap.rights.contains(super::rights::Rights::GRANT) {
            return 0xFFFF_FFFF_FFFF_FFFE; // Permission Denied: Needs GRANT right to badge
        }

        let mut new_cap = src_cap.clone();
        new_cap.badge = Some(badge);

        let mut cdt = CDT.lock();
        if let Some(node_id) = cdt.alloc_node(dest_slot as usize, Some(src_cap.cdt_node_id)) {
            new_cap.cdt_node_id = node_id;
            if cnode.insert(dest_slot as usize, new_cap).is_ok() {
                return 0; // Success
            }
        }
    }
    0xFFFF_FFFF_FFFF_FFFF
}

pub unsafe fn dispatch_cap_copy(src_slot: u64, dest_slot: u64) -> u64 {
    let mut cnode = ROOT_CNODE.lock();
    if let Some(src_cap) = cnode.lookup(src_slot as usize) {
        if !src_cap.rights.contains(super::rights::Rights::GRANT) {
            return 0xFFFF_FFFF_FFFF_FFFE; // Permission Denied: Needs GRANT right
        }

        let mut new_cap = src_cap.clone();

        let mut cdt = CDT.lock();
        if let Some(node_id) = cdt.alloc_node(dest_slot as usize, Some(src_cap.cdt_node_id)) {
            new_cap.cdt_node_id = node_id;
            if cnode.insert(dest_slot as usize, new_cap).is_ok() {
                return 0; // Success
            }
        }
    }
    0xFFFF_FFFF_FFFF_FFFF
}
