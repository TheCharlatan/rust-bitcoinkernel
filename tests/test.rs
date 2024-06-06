#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use env_logger::Builder;
    use libbitcoinkernel_sys::{
        execute_event, register_validation_interface, set_logging_callback, unregister_validation_interface, verify, Block, BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager, ChainstateManagerOptions, Context, ContextBuilder, Event, KernelError, KernelNotificationInterfaceCallbackHolder, TaskRunnerCallbackHolder, ValidationInterfaceCallbackHolder, ValidationInterfaceWrapper, VERIFY_ALL_PRE_TAPROOT
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

    #[test]
    fn script_verify_test() {
        // a random old-style transaction from the blockchain
        verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0
        ).unwrap();

        // a random segwit transaction from the blockchain using P2SH
        verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            1900000, 0
        ).unwrap();

        // a random segwit transaction from the blockchain using native segwit
        verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0
        ).unwrap();

        // a random old-style transaction from the blockchain - WITH WRONG SIGNATURE for the address
        assert!(verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ff",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0
        ).is_err());

        // a random segwit transaction from the blockchain using P2SH - WITH WRONG AMOUNT
        assert!(verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            900000, 0).is_err());

        // a random segwit transaction from the blockchain using native segwit - WITH WRONG SEGWIT
        assert!(verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58f",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0
        ).is_err());
    }

    fn verify_test(spent: &str, spending: &str, amount: i64, input: u32) -> Result<(), KernelError> {
        verify(
            hex::decode(spent).unwrap().as_slice(),
            Some(amount),
            hex::decode(spending).unwrap().as_slice(),
            input,
            Some(VERIFY_ALL_PRE_TAPROOT),
            None,
        )
    }
}
