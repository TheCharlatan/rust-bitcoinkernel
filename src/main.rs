extern crate libbitcoinkernel_sys;

use libbitcoinkernel_sys::{c_chainstate_manager_delete_wrapper};
use libbitcoinkernel_sys::{ChainstateManager, Scheduler};

fn main() {
    let scheduler = Scheduler::new();
    let chainman = ChainstateManager::new("/home/drgrid/.bitcoin", &scheduler).unwrap();
    chainman.validate_block("deadbeef").unwrap();
    c_chainstate_manager_delete_wrapper(chainman, scheduler);
}
