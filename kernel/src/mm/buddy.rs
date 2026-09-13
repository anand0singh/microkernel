use spin::Mutex;

pub const MAX_ORDER: usize = 12; // Orders 0..=11 (4 KiB to 8 MiB)
pub const PAGE_SIZE: usize = 4096;

pub struct FreeBlock {
    pub next: Option<*mut FreeBlock>,
}

pub struct BuddyAllocator {
    free_lists: [Option<*mut FreeBlock>; MAX_ORDER],
    total_frames: usize,
    allocated_frames: usize,
}

unsafe impl Send for BuddyAllocator {}
unsafe impl Sync for BuddyAllocator {}

impl BuddyAllocator {
    pub const fn new() -> Self {
        Self {
            free_lists: [None; MAX_ORDER],
            total_frames: 0,
            allocated_frames: 0,
        }
    }

    pub unsafe fn add_memory_region(&mut self, start_phys: u64, size_bytes: usize) {
        let start_page = (start_phys as usize + PAGE_SIZE - 1) / PAGE_SIZE;
        let end_page = (start_phys as usize + size_bytes) / PAGE_SIZE;

        let mut curr_page = start_page;

        while curr_page < end_page {
            let mut order = 0;
            while order + 1 < MAX_ORDER
                && (curr_page % (1 << (order + 1))) == 0
                && (curr_page + (1 << (order + 1))) <= end_page
            {
                order += 1;
            }

            let block_ptr = (curr_page * PAGE_SIZE) as *mut FreeBlock;
            (*block_ptr).next = self.free_lists[order];
            self.free_lists[order] = Some(block_ptr);

            let block_frames = 1 << order;
            self.total_frames += block_frames;
            curr_page += block_frames;
        }
    }

    pub unsafe fn allocate_order(&mut self, order: usize) -> Option<u64> {
        if order >= MAX_ORDER {
            return None;
        }

        // 1. Find smallest available order >= requested order
        let mut current_order = order;
        while current_order < MAX_ORDER && self.free_lists[current_order].is_none() {
            current_order += 1;
        }

        if current_order >= MAX_ORDER {
            return None; // Out of memory
        }

        // 2. Take block from current_order
        let block_ptr = self.free_lists[current_order].take().unwrap();
        self.free_lists[current_order] = (*block_ptr).next;

        // 3. Split down to requested order
        while current_order > order {
            current_order -= 1;
            let buddy_offset = (1 << current_order) * PAGE_SIZE;
            let buddy_ptr = (block_ptr as usize + buddy_offset) as *mut FreeBlock;

            (*buddy_ptr).next = self.free_lists[current_order];
            self.free_lists[current_order] = Some(buddy_ptr);
        }

        let allocated_frames = 1 << order;
        self.allocated_frames += allocated_frames;

        Some(block_ptr as u64)
    }

    pub unsafe fn deallocate_order(&mut self, phys_addr: u64, order: usize) {
        if order >= MAX_ORDER {
            return;
        }

        let mut block_page = phys_addr as usize / PAGE_SIZE;
        let mut current_order = order;

        while current_order + 1 < MAX_ORDER {
            let buddy_page = block_page ^ (1 << current_order);
            let buddy_ptr = (buddy_page * PAGE_SIZE) as *mut FreeBlock;

            // Search if buddy is in free list of current_order
            let mut prev: Option<*mut FreeBlock> = None;
            let mut curr = self.free_lists[current_order];
            let mut buddy_found = false;

            while let Some(node) = curr {
                if node == buddy_ptr {
                    buddy_found = true;
                    // Remove buddy from free list
                    if let Some(prev_node) = prev {
                        (*prev_node).next = (*node).next;
                    } else {
                        self.free_lists[current_order] = (*node).next;
                    }
                    break;
                }
                prev = curr;
                curr = (*node).next;
            }

            if !buddy_found {
                break;
            }

            // Merge with buddy
            block_page = block_page & buddy_page;
            current_order += 1;
        }

        let block_ptr = (block_page * PAGE_SIZE) as *mut FreeBlock;
        (*block_ptr).next = self.free_lists[current_order];
        self.free_lists[current_order] = Some(block_ptr);

        let freed_frames = 1 << order;
        if self.allocated_frames >= freed_frames {
            self.allocated_frames -= freed_frames;
        }
    }

    pub fn usage(&self) -> (usize, usize) {
        (self.allocated_frames, self.total_frames)
    }
}

pub static BUDDY_ALLOCATOR: Mutex<BuddyAllocator> = Mutex::new(BuddyAllocator::new());
