extern crate libbitcoinkernel_sys;

use libbitcoinkernel_sys::{c_chainstate_manager_delete_wrapper, set_logging_callback_and_start_logging_wrapper};
use libbitcoinkernel_sys::{ChainstateManager, Scheduler};

fn main() {
    set_logging_callback_and_start_logging_wrapper();
    let scheduler = Scheduler::new();
    let chainman = ChainstateManager::new("/home/drgrid/.bitcoin", &scheduler).unwrap();
    chainman.validate_block("deadbeef").unwrap();
    c_chainstate_manager_delete_wrapper(chainman, scheduler);
}
