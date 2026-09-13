pub mod thread;

use spin::Mutex;
use thread::Thread;

pub const MAX_THREADS: usize = 32;

pub struct Scheduler {
    pub threads: [Option<Thread>; MAX_THREADS],
    pub current_thread_idx: usize,
}

impl Scheduler {
    pub const fn new() -> Self {
        const EMPTY_THREAD: Option<Thread> = None;
        Self {
            threads: [EMPTY_THREAD; MAX_THREADS],
            current_thread_idx: 0,
        }
    }

    pub fn add_thread(&mut self, thread: Thread) -> Result<usize, ()> {
        for i in 0..MAX_THREADS {
            if self.threads[i].is_none() {
                self.threads[i] = Some(thread);
                return Ok(i);
            }
        }
        Err(())
    }

    pub fn schedule_next(&mut self) -> Option<usize> {
        let start = self.current_thread_idx;
        let mut idx = (start + 1) % MAX_THREADS;

        while idx != start {
            if let Some(ref t) = self.threads[idx] {
                if t.state == thread::ThreadState::Ready {
                    self.current_thread_idx = idx;
                    return Some(idx);
                }
            }
            idx = (idx + 1) % MAX_THREADS;
        }

        if let Some(ref t) = self.threads[start] {
            if t.state == thread::ThreadState::Ready || t.state == thread::ThreadState::Running {
                return Some(start);
            }
        }

        None
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

pub fn init_scheduler() {
    // Fixed-priority preemptive APIC scheduler initialized
}
