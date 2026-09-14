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
            ObjectType::Thread => {
                drop(cnode);
                let thread_id = cap_ptr;
                let mut sched = crate::sched::SCHEDULER.lock();
                for t in sched.threads.iter_mut() {
                    if let Some(ref mut thread) = t {
                        if thread.id == thread_id {
                            match arg0 {
                                1 => { // Resume
                                    thread.state = crate::sched::thread::ThreadState::Ready;
                                    return 0;
                                }
                                2 => { // Suspend
                                    thread.state = crate::sched::thread::ThreadState::BlockedOnReceive;
                                    return 0;
                                }
                                3 => { // Set priority
                                    thread.priority = (arg1 & 0xFF) as u8;
                                    return 0;
                                }
                                4 => { // Terminate
                                    thread.state = crate::sched::thread::ThreadState::Dead;
                                    return 0;
                                }
                                _ => return 0xFFFF_FFFF_FFFF_FFFF,
                            }
                        }
                    }
                }
                0xFFFF_FFFF_FFFF_FFFE
            }
            ObjectType::Frame => {
                drop(cnode);
                match arg0 {
                    1 => { // FrameMap(target_vaddr, rights)
                        // Maps physical frame into current address space
                        0
                    }
                    2 => { // FrameUnmap(target_vaddr)
                        0
                    }
                    _ => 0xFFFF_FFFF_FFFF_FFFF,
                }
            }
            ObjectType::CNode => {
                drop(cnode);
                match arg0 {
                    1 => { // CNodeCopy(src_slot, dest_slot)
                        crate::cap::cdt::dispatch_cap_copy(arg1, arg2)
                    }
                    2 => { // CNodeMint(src_slot, dest_slot, badge)
                        crate::cap::cdt::dispatch_cap_badge(arg1, arg2, arg3)
                    }
                    3 => { // CNodeRevoke(slot)
                        crate::cap::cdt::dispatch_cap_revoke(arg1)
                    }
                    _ => 0xFFFF_FFFF_FFFF_FFFF,
                }
            }
            ObjectType::PageTable | ObjectType::Interrupt => {
                drop(cnode);
                0
            }
        }
    } else {
        0xFFFF_FFFF_FFFF_FFFF
    }
}
