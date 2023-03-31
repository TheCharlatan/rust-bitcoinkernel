extern crate libbitcoinkernel_sys;

use libbitcoinkernel_sys::{c_chainstate_manager_delete_wrapper, set_logging_callback};
use libbitcoinkernel_sys::{ChainstateManager, Scheduler};

use env_logger::Builder;
use log::LevelFilter;

fn setup_logging() {
    let mut builder = Builder::from_default_env();
    builder.filter(None, LevelFilter::Info).init();

    let callback = |message: &str| {
        log::info!(
            target: "libbitcoinkernel", 
            "{}", message.strip_suffix("\r\n").or(message.strip_suffix("\n")).unwrap_or(message));
    };

    set_logging_callback(callback);
}

fn main() {
    setup_logging();
    let scheduler = Scheduler::new();
    let chainman = ChainstateManager::new("/home/drgrid/.bitcoin", &scheduler).unwrap();
    chainman.validate_block("deadbeef").unwrap();
    c_chainstate_manager_delete_wrapper(chainman, scheduler);
}
