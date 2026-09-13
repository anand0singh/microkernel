#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr3: u64,
    pub fxsave_area: [u8; 512],
}

impl Context {
    pub const fn new() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            rbp: 0,
            rip: 0,
            rsp: 0,
            rflags: 0x202, // IF enabled
            cr3: 0,
            fxsave_area: [0; 512],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    BlockedOnSend,
    BlockedOnReceive,
    Dead,
}

pub struct Thread {
    pub id: u64,
    pub context: Context,
    pub state: ThreadState,
    pub priority: u8,
    pub cnode_ptr: u64,
}

impl Thread {
    pub fn new(id: u64, entry_point: u64, stack_top: u64, cr3: u64) -> Self {
        let mut ctx = Context::new();
        ctx.rip = entry_point;
        ctx.rsp = stack_top;
        ctx.cr3 = cr3;

        Self {
            id,
            context: ctx,
            state: ThreadState::Ready,
            priority: 10,
            cnode_ptr: 0,
        }
    }
}
