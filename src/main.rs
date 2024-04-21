extern crate libbitcoinkernel_sys;

use libbitcoinkernel_sys::{
    execute_event, register_validation_interface, set_logging_callback,
    unregister_validation_interface, ChainType, ChainstateManager, ContextBuilder, Event,
    KernelNotificationInterfaceCallbackHolder, TaskRunnerCallbackHolder,
    ValidationInterfaceCallbackHolder, ValidationInterfaceWrapper,
};

use env_logger::Builder;
use log::LevelFilter;

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

fn setup_logging() {
    let mut builder = Builder::from_default_env();
    builder.filter(None, LevelFilter::Info).init();

    let callback = |message: &str| {
        log::info!(
            target: "libbitcoinkernel", 
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    };

    set_logging_callback(callback).unwrap();
}

fn runtime(queue: Arc<(Mutex<VecDeque<Event>>, Condvar)>) {
    thread::spawn(move || {
        let (lock, cvar) = &*queue;
        loop {
            let mut queue = lock.lock().unwrap();
            while queue.is_empty() {
                queue = cvar.wait(queue).unwrap();
            }
            let event = queue.pop_front().unwrap();
            execute_event(event);
            log::trace!("executed runtime event!");
        }
    });
}

fn empty_queue(queue: Arc<(Mutex<VecDeque<Event>>, Condvar)>) {
    log::trace!("Emptying the processing queue...");
    let (lock, _) = &*queue;
    let mut queue = lock.lock().unwrap();
    while let Some(event) = queue.pop_front() {
        execute_event(event);
    }
    log::trace!("Processing queue emptied.");
}

fn main() {
    let queue = Arc::new((Mutex::new(VecDeque::<Event>::new()), Condvar::new()));

    runtime(queue.clone());

    setup_logging();

    let context = ContextBuilder::new()
        .chain_type(ChainType::SIGNET)
        .unwrap()
        .kn_callbacks(Box::new(KernelNotificationInterfaceCallbackHolder {
            kn_block_tip: Box::new(|_state| {
                log::info!("Processed new block!");
            }),
            kn_header_tip: Box::new(|_state, height, timestamp, presync| {
                log::info!("Processed new header: {height}, at {timestamp}, presyncing {presync}");
            }),
            kn_progress: Box::new(|title, progress, resume_possible| {
                log::info!("Made progress {title}, {progress}, resume possible: {resume_possible}");
            }),
            kn_warning: Box::new(|warning| {
                log::info!("Received warning: {warning}");
            }),
            kn_flush_error: Box::new(|message| {
                log::info!("Flush error! {message}");
            }),
            kn_fatal_error: Box::new(|message| {
                log::info!("Fatal Error! {message}");
            }),
        }))
        .unwrap()
        .tr_callbacks(Box::new(TaskRunnerCallbackHolder {
            tr_insert: {
                let queue = queue.clone();
                Box::new(move |event| {
                    log::trace!("Added to process queue");
                    let (lock, cvar) = &*queue;
                    lock.lock().unwrap().push_back(event);
                    cvar.notify_one();
                })
            },

            tr_flush: {
                let queue = queue.clone();
                Box::new(move || {
                    empty_queue(queue.clone());
                })
            },

            tr_size: {
                let queue = queue.clone();
                Box::new(move || {
                    log::trace!("Callbacks pending...");
                    let (lock, _) = &*queue;
                    lock.lock().unwrap().len().try_into().unwrap()
                })
            },
        }))
        .unwrap()
        .build()
        .unwrap();

    let validation_interface =
        ValidationInterfaceWrapper::new(Box::new(ValidationInterfaceCallbackHolder {
            block_checked: Box::new(|| {
                log::info!("Block checked!");
            }),
        }));
    register_validation_interface(&validation_interface, &context).unwrap();

    let chainman = ChainstateManager::new("/home/drgrid/.bitcoin/signet", true, &context).unwrap();
    chainman.import_blocks().unwrap();

    let cursor = chainman.chainstate_coins_cursor().unwrap();
    let mut iter = 0;
    let mut size = 0;
    for (out_point, coin) in cursor {
        size += std::mem::size_of_val(&out_point) + std::mem::size_of_val(&coin);
        iter += 1;
        if iter > 100000 {
            log::info!("Coins db iterations: {}, read size: {}", iter, size);
            break;
        }
    }

    log::info!("validating block");
    chainman.validate_block("deadbeef").unwrap();
    log::info!("validated block");

    empty_queue(queue.clone());

    unregister_validation_interface(&validation_interface, &context).unwrap();
}
