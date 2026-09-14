use spin::Mutex;

pub const MAX_FILTER_RULES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Deny,
    Kill,
}

#[derive(Clone, Copy)]
pub struct FilterRule {
    pub cap_ptr: u64,
    pub op: u64,
    pub action: FilterAction,
    pub active: bool,
}

impl FilterRule {
    pub const fn empty() -> Self {
        Self {
            cap_ptr: 0,
            op: 0,
            action: FilterAction::Allow,
            active: false,
        }
    }
}

pub struct ProcessSecurityFilter {
    pub rules: [FilterRule; MAX_FILTER_RULES],
    pub locked: bool,
}

impl ProcessSecurityFilter {
    pub const fn new() -> Self {
        Self {
            rules: [const { FilterRule::empty() }; MAX_FILTER_RULES],
            locked: false,
        }
    }

    pub fn add_rule(&mut self, cap_ptr: u64, op: u64, action: FilterAction) -> Result<(), ()> {
        if self.locked {
            return Err(()); // Cannot add rules once filter is locked
        }

        for rule in self.rules.iter_mut() {
            if !rule.active {
                *rule = FilterRule {
                    cap_ptr,
                    op,
                    action,
                    active: true,
                };
                return Ok(());
            }
        }
        Err(())
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn evaluate(&self, cap_ptr: u64, op: u64) -> FilterAction {
        for rule in self.rules.iter() {
            if rule.active && (rule.cap_ptr == cap_ptr || rule.cap_ptr == u64::MAX) && (rule.op == op || rule.op == u64::MAX) {
                return rule.action;
            }
        }
        FilterAction::Allow // Default allow if not matched by deny rules
    }
}

pub static PROCESS_FILTER: Mutex<ProcessSecurityFilter> = Mutex::new(ProcessSecurityFilter::new());
