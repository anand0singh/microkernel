use super::rights::Rights;
use spin::Mutex;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ObjectType {
    Endpoint,
    Frame,
    PageTable,
    Thread,
    CNode,
    Interrupt,
}

#[derive(Clone)]
pub struct Capability {
    pub obj_type: ObjectType,
    pub rights: Rights,
    pub object_ptr: *mut u8,
    pub badge: Option<u64>,
    pub cdt_node_id: usize,
}

unsafe impl Send for Capability {}
unsafe impl Sync for Capability {}

pub const CNODE_SLOTS: usize = 256;

pub struct CNode {
    pub slots: [Option<Capability>; CNODE_SLOTS],
}

unsafe impl Send for CNode {}
unsafe impl Sync for CNode {}

impl CNode {
    pub const fn new() -> Self {
        const EMPTY_CAP: Option<Capability> = None;
        Self {
            slots: [EMPTY_CAP; CNODE_SLOTS],
        }
    }

    pub fn lookup(&self, slot: usize) -> Option<Capability> {
        if slot < CNODE_SLOTS {
            self.slots[slot].clone()
        } else {
            None
        }
    }

    pub fn insert(&mut self, slot: usize, cap: Capability) -> Result<(), ()> {
        if slot < CNODE_SLOTS && self.slots[slot].is_none() {
            self.slots[slot] = Some(cap);
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn remove(&mut self, slot: usize) -> Option<Capability> {
        if slot < CNODE_SLOTS {
            self.slots[slot].take()
        } else {
            None
        }
    }
}

pub static ROOT_CNODE: Mutex<CNode> = Mutex::new(CNode::new());

pub unsafe fn dispatch_cap_invoke(
    cap_ptr: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> u64 {
    let cnode = ROOT_CNODE.lock();
    if let Some(cap) = cnode.lookup(cap_ptr as usize) {
        match cap.obj_type {
            ObjectType::Endpoint => {
                drop(cnode);
                crate::ipc::endpoint::dispatch_ipc_call(cap_ptr, arg0, arg1, arg2, arg3)
            }
            _ => 0,
        }
    } else {
        0xFFFF_FFFF_FFFF_FFFF
    }
}
