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
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    };

    set_logging_callback(callback);
}

fn main() {
    setup_logging();
    let scheduler = Scheduler::new();
    let chainman = ChainstateManager::new("/home/drgrid/.bitcoin", &scheduler).unwrap();
    let chainstate_info = chainman.get_chainstate_info();
    log::info!("{:?}", chainstate_info);

    let cursor = chainman.chainstate_coins_cursor();

    let mut iter = 0;
    let mut size = 0;

    for (out_point, coin) in cursor {
        size += std::mem::size_of_val(&out_point) + std::mem::size_of_val(&coin);
        iter += 1;
        if iter > 100000 {
            println!("iterations: {}, read size: {}", iter, size);
            break;
        }
    }

    chainman.validate_block("deadbeef").unwrap();
    c_chainstate_manager_delete_wrapper(chainman, scheduler);
}
