#[cfg(test)]
mod tests {
    use env_logger::Builder;
    use libbitcoinkernel_sys::{execute_event, register_validation_interface, set_logging_callback, unregister_validation_interface, Block, ChainType, ChainstateManager, Context, ContextBuilder, Event, KernelNotificationInterfaceCallbackHolder, TaskRunnerCallbackHolder, ValidationInterfaceCallbackHolder, ValidationInterfaceWrapper};
    use log::LevelFilter;
    use tempdir::TempDir;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
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


    fn create_context(queue: &Arc<(Mutex<VecDeque<Event>>, Condvar)>) -> Context {
        ContextBuilder::new()
            .chain_type(ChainType::REGTEST)
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
            .unwrap()
    }

    fn setup_validation_interface(context: &Context) -> ValidationInterfaceWrapper {
        let validation_interface =
            ValidationInterfaceWrapper::new(Box::new(ValidationInterfaceCallbackHolder {
                block_checked: Box::new(|| {
                    log::info!("Block checked!");
                }),
            }));
        register_validation_interface(&validation_interface, &context).unwrap();
        validation_interface
    }

    fn testing_setup() -> Context {
        setup_logging();
        let queue = Arc::new((Mutex::new(VecDeque::<Event>::new()), Condvar::new()));
        runtime(queue.clone());
        let context = create_context(&queue);
        context
    }

    fn read_block_data() -> Vec<String> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(line.unwrap());
        }
        lines
    }

    #[test]
    fn test_process_data() {
        let block_data = read_block_data();
        let temp_dir = TempDir::new("test_chainman_regtest").unwrap();
        let data_dir = temp_dir.path();

        let context: Context = testing_setup();
        let validation_interface = setup_validation_interface(&context);
        let chainman = ChainstateManager::new(data_dir.to_str().unwrap(), false, &context).unwrap();
        chainman.import_blocks().unwrap();

        for block_hex in block_data.iter() {
            let block = Block::try_from(block_hex.as_str()).unwrap();
            chainman.validate_block(&block).unwrap();
        }
        chainman.flush().unwrap();

        let cursor = chainman.chainstate_coins_cursor().unwrap();
        let mut iter = 0;
        let mut size = 0;
        for (out_point, coin) in cursor {
            size += std::mem::size_of_val(&out_point) + std::mem::size_of_val(&coin);
            iter += 1;
        }
        log::info!("Iterated through all {} chainstate coin entires, totaling {} in size", iter, size);

        log::info!("emptied validation queue");

        unregister_validation_interface(&validation_interface, &context).unwrap();
    }
}
