#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use env_logger::Builder;
    use libbitcoinkernel_sys::{
        execute_event, register_validation_interface, set_logging_callback, unregister_validation_interface, Block, BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager, ChainstateManagerOptions, Context, ContextBuilder, Event, KernelError, KernelNotificationInterfaceCallbackHolder, TaskRunnerCallbackHolder, ValidationInterfaceCallbackHolder, ValidationInterfaceWrapper
    };
    use log::LevelFilter;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Condvar, Mutex, Once};
    use std::thread;
    use tempdir::TempDir;

    static START: Once = Once::new();
    type Queue = Arc<(Mutex<VecDeque<Event>>, Condvar)>;

    enum TaskRunnerType {
        Threaded,
        Immediate,
        None,
    }

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
                execute_event(event).unwrap();
                log::trace!("executed runtime event!");
            }
        });
    }

    fn empty_queue(queue: Arc<(Mutex<VecDeque<Event>>, Condvar)>) {
        log::trace!("Emptying the processing queue...");
        let (lock, _) = &*queue;
        let mut queue = lock.lock().unwrap();
        while let Some(event) = queue.pop_front() {
            execute_event(event).unwrap();
        }
        log::trace!("Processing queue emptied.");
    }

    fn immediate_taskrunner() -> TaskRunnerCallbackHolder {
        TaskRunnerCallbackHolder {
            tr_insert: Box::new(move |event| {
                execute_event(event).unwrap();
            }),
            tr_flush: Box::new(|| {
                return;
            }),
            tr_size: Box::new(|| {
                return 0;
            }),
        }
    }

    fn threaded_taskrunner(queue: Queue) -> TaskRunnerCallbackHolder {
        TaskRunnerCallbackHolder {
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
        }
    }

    fn create_context(queue: Option<Queue>) -> Context {
        let mut builder = ContextBuilder::new()
            .chain_type(ChainType::REGTEST)
            .unwrap()
            .kn_callbacks(Box::new(KernelNotificationInterfaceCallbackHolder {
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
            .unwrap();
        if let Some(queue) = queue {
            builder = builder
                .tr_callbacks(Box::new(threaded_taskrunner(queue.clone())))
                .unwrap();
        } else {
            builder = builder
                .tr_callbacks(Box::new(immediate_taskrunner()))
                .unwrap();
        }
        builder.build().unwrap()
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

    fn testing_setup(
        task_runner_type: TaskRunnerType,
    ) -> (Context, Option<ValidationInterfaceWrapper>, String) {
        START.call_once(|| {
            setup_logging();
        });
        let (context, validation_interface) = match task_runner_type {
            TaskRunnerType::Threaded => {
                let queue = Arc::new((Mutex::new(VecDeque::<Event>::new()), Condvar::new()));
                runtime(queue.clone());
                let context = create_context(Some(queue.clone()));
                let validation_interface = setup_validation_interface(&context);
                (context, Some(validation_interface))
            }
            TaskRunnerType::Immediate => {
                let context = create_context(None);
                let validation_interface = setup_validation_interface(&context);
                (context, Some(validation_interface))
            }
            TaskRunnerType::None => {
                let context = create_context(None);
                (context, None)
            }
        };

        let temp_dir = TempDir::new("test_chainman_regtest").unwrap();
        let data_dir = temp_dir.path();
        (
            context,
            validation_interface,
            data_dir.to_str().unwrap().to_string(),
        )
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
    fn test_reindex() {
        let (context, validation_interface, data_dir) = testing_setup(TaskRunnerType::Threaded);
        let blocks_dir = data_dir.clone() + "/blocks";
        {
            let block_data = read_block_data();

            let chainman = ChainstateManager::new(
                ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
                BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
                &context).unwrap();
            chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();
            for block_hex in block_data.iter() {
                let block = Block::try_from(block_hex.as_str()).unwrap();
                chainman.process_block(&block).unwrap();
            }
        }

        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
            BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
            &context).unwrap();
        chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();
        chainman.import_blocks().unwrap();
        unregister_validation_interface(&validation_interface.unwrap(), &context).unwrap();
    }

    #[test]
    fn test_invalid_block() {
        let (context, validation_interface, data_dir) = testing_setup(TaskRunnerType::Threaded);
        let blocks_dir = data_dir.clone() + "/blocks";
        for _ in 0..10 {
            let chainman = ChainstateManager::new(
                ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
                BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
                &context).unwrap();
            chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();

            // Not a block
            let block = Block::try_from("deadbeef");
            assert!(matches!(block, Err(KernelError::Internal(_))));
            drop(block);

            // Invalid block
            let block_1 = Block::try_from(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000",
            )
            .unwrap();
            let res = chainman.process_block(&block_1);
            assert!(!res.unwrap());
        }
        unregister_validation_interface(&validation_interface.unwrap(), &context).unwrap();
    }

    #[test]
    fn test_scan_tx() {
        #[derive(Debug)]
        struct Input {
            prevout: Vec<u8>,
            script_sig: Vec<u8>,
            witness: Vec<Vec<u8>>,
        }

        #[derive(Debug)]
        struct ScanTxHelper {
            ins: Vec<Input>,
            outs: Vec<Vec<u8>>,
        }

        let (context, _, data_dir) = testing_setup(TaskRunnerType::None);
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
            BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
            &context).unwrap();
        chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();

        for block_hex in block_data.iter() {
            let block = Block::try_from(block_hex.as_str()).unwrap();
            chainman.process_block(&block).unwrap();
        }

        let block_index_tip = chainman.get_block_index_tip().unwrap();
        let raw_block_tip: Vec<u8> = chainman.read_block_data(&block_index_tip).unwrap().into();
        let undo_tip = chainman.read_undo_data(&block_index_tip).unwrap();
        let block_tip: bitcoin::Block = deserialize(&raw_block_tip).unwrap();
        // Should be the same size minus the coinbase transaction
        assert_eq!(block_tip.txdata.len() - 1, undo_tip.n_tx_undo);

        let block_index_tip_prev = block_index_tip.prev().unwrap();
        let raw_block: Vec<u8> = chainman.read_block_data(&block_index_tip_prev).unwrap().into();
        let undo = chainman.read_undo_data(&block_index_tip_prev).unwrap();
        let block: bitcoin::Block = deserialize(&raw_block).unwrap();
        // Should be the same size minus the coinbase transaction
        assert_eq!(block.txdata.len() - 1, undo.n_tx_undo);

        for i in 0..(block.txdata.len()-1) {
            let transaction_undo_size: u64 = undo.get_get_transaction_undo_size(i.try_into().unwrap()).unwrap();
            let transaction_input_size: u64 = block.txdata[i+1].input.len().try_into().unwrap();
            assert_eq!(transaction_input_size, transaction_undo_size);
            let mut helper = ScanTxHelper {
                ins: vec![],
                outs: block.txdata[i+1].output.iter().map(|output| { output.script_pubkey.to_bytes()}).collect(),
            };
            for j in 0..transaction_input_size {
                helper.ins.push(Input {
                    prevout: undo.get_prevout_by_index(i as u64, j).unwrap().script_pubkey,
                    script_sig: block.txdata[i+1].input[j as usize].script_sig.to_bytes(),
                    witness: block.txdata[i+1].input[j as usize].witness.to_vec(),
                });
            }
            println!("helper: {:?}", helper);
        }
    }

    #[test]
    fn test_process_data() {
        let (context, validation_interface, data_dir) = testing_setup(TaskRunnerType::Immediate);
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
            BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
            &context).unwrap();
        chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();

        for block_hex in block_data.iter() {
            let block = Block::try_from(block_hex.as_str()).unwrap();
            chainman.process_block(&block).unwrap();
        }

        unregister_validation_interface(&validation_interface.unwrap(), &context).unwrap();
    }

    #[test]
    fn test_validate_any() {
        let (context, validation_interface, data_dir) = testing_setup(TaskRunnerType::Immediate);
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
            BlockManagerOptions::new(&context, &blocks_dir).unwrap(),
            &context).unwrap();
        chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();

        chainman.import_blocks().unwrap();
        unregister_validation_interface(&validation_interface.unwrap(), &context).unwrap();
        let block_2 = Block::try_from(block_data[1].clone().as_str()).unwrap();
        chainman.process_block(&block_2).unwrap();
    }
}
