use spin::Mutex;

pub struct SlabCache<const OBJ_SIZE: usize> {
    free_head: Option<*mut u8>,
    total_objects: usize,
    allocated_objects: usize,
}

unsafe impl<const OBJ_SIZE: usize> Send for SlabCache<OBJ_SIZE> {}
unsafe impl<const OBJ_SIZE: usize> Sync for SlabCache<OBJ_SIZE> {}

impl<const OBJ_SIZE: usize> SlabCache<OBJ_SIZE> {
    pub const fn new() -> Self {
        assert!(OBJ_SIZE >= core::mem::size_of::<*mut u8>());
        Self {
            free_head: None,
            total_objects: 0,
            allocated_objects: 0,
        }
    }

    pub unsafe fn add_slab_frame(&mut self, frame_phys: u64) {
        let frame_virt = frame_phys; // Higher half direct map
        let num_objs = 4096 / OBJ_SIZE;

        for i in 0..num_objs {
            let obj_ptr = (frame_virt + (i * OBJ_SIZE) as u64) as *mut u8;
            let next_ptr_ptr = obj_ptr as *mut Option<*mut u8>;
            *next_ptr_ptr = self.free_head;
            self.free_head = Some(obj_ptr);
        }

        self.total_objects += num_objs;
    }

    pub unsafe fn alloc(&mut self) -> Option<*mut u8> {
        if let Some(obj_ptr) = self.free_head {
            let next_ptr_ptr = obj_ptr as *const Option<*mut u8>;
            self.free_head = *next_ptr_ptr;
            self.allocated_objects += 1;
            Some(obj_ptr)
        } else {
            None
        }
    }

    pub unsafe fn dealloc(&mut self, obj_ptr: *mut u8) {
        let next_ptr_ptr = obj_ptr as *mut Option<*mut u8>;
        *next_ptr_ptr = self.free_head;
        self.free_head = Some(obj_ptr);
        if self.allocated_objects > 0 {
            self.allocated_objects -= 1;
        }
    }
}

pub static THREAD_SLAB: Mutex<SlabCache<512>> = Mutex::new(SlabCache::new());
pub static CNODE_SLAB: Mutex<SlabCache<256>> = Mutex::new(SlabCache::new());
pub static ENDPOINT_SLAB: Mutex<SlabCache<128>> = Mutex::new(SlabCache::new());
