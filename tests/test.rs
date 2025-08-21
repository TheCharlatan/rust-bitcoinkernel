#[cfg(test)]
mod tests {
    use bitcoin::consensus::deserialize;
    use bitcoinkernel::{
        Block, BlockHash, BlockSpentOutputs, ChainParams, ChainType, ChainstateManager,
        ChainstateManagerOptions, Coin, Context, ContextBuilder, KernelError,
        KernelNotificationInterfaceCallbacks, Log, Logger, ScriptPubkey, Transaction,
        TransactionSpentOutputs, TxOut, ValidationInterfaceCallbacks,
    };
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Once};
    use tempdir::TempDir;

    struct TestLog {}

    impl Log for TestLog {
        fn log(&self, message: &str) {
            log::info!(
                target: "libbitcoinkernel", 
                "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
        }
    }

    static START: Once = Once::new();
    static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

    fn setup_logging() {
        let mut builder = env_logger::Builder::from_default_env();
        builder.filter(None, log::LevelFilter::Debug).init();

        unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(TestLog {}).unwrap()) };
    }

    fn create_context() -> Context {
        let builder = ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .kn_callbacks(Box::new(KernelNotificationInterfaceCallbacks {
                kn_block_tip: Box::new(|_state, _block_tip, _verification_progress| {
                    log::info!("Received block tip.");
                }),
                kn_header_tip: Box::new(|_state, height, timestamp, _presync| {
                    assert!(timestamp > 0);
                    log::info!(
                        "Received header tip at height {} and time {}",
                        height,
                        timestamp
                    );
                }),
                kn_progress: Box::new(|_state, progress, _resume_possible| {
                    log::info!("Made progress: {}", progress);
                }),
                kn_warning_set: Box::new(|_warning, message| {
                    log::info!("Received warning: {message}");
                }),
                kn_warning_unset: Box::new(|_warning| {
                    log::info!("Unsetting warning.");
                }),
                kn_flush_error: Box::new(|message| {
                    log::info!("Flush error! {message}");
                }),
                kn_fatal_error: Box::new(|message| {
                    log::info!("Fatal Error! {message}");
                }),
            }))
            .validation_interface(Box::new(ValidationInterfaceCallbacks {
                block_checked: Box::new(|_block, _mode, _result| {
                    log::info!("Block checked!");
                }),
            }));
        builder.build().unwrap()
    }

    fn testing_setup() -> (Arc<Context>, String) {
        START.call_once(|| {
            setup_logging();
        });
        let context = Arc::new(create_context());

        let temp_dir = TempDir::new("test_chainman_regtest").unwrap();
        let data_dir = temp_dir.path();
        (context, data_dir.to_str().unwrap().to_string())
    }

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap().to_vec());
        }
        lines
    }

    #[test]
    fn test_reindex() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        {
            let block_data = read_block_data();

            let chainman = ChainstateManager::new(
                ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
            )
            .unwrap();
            for raw_block in block_data.iter() {
                let block = Block::try_from(raw_block.as_slice()).unwrap();
                let (accepted, new_block) = chainman.process_block(&block);
                assert!(accepted);
                assert!(new_block);
            }
        }

        let chainman_opts = ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .set_wipe_db(false, true);

        let chainman = ChainstateManager::new(chainman_opts).unwrap();
        chainman.import_blocks().unwrap();
        drop(chainman);
    }

    #[test]
    fn test_invalid_block() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        for _ in 0..10 {
            let chainman = ChainstateManager::new(
                ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
            )
            .unwrap();

            // Not a block
            let block = Block::try_from(hex::decode("deadbeef").unwrap().as_slice());
            assert!(matches!(block, Err(KernelError::Internal(_))));
            drop(block);

            // Invalid block
            let block_1 = Block::try_from(hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000").unwrap().as_slice()
            )
            .unwrap();
            let (accepted, new_block) = chainman.process_block(&block_1);
            assert!(!accepted);
            assert!(!new_block);
        }
    }

    #[test]
    fn test_scan_tx() {
        #[allow(dead_code)]
        #[derive(Debug)]
        struct Input {
            height: u32,
            prevout: Vec<u8>,
            script_sig: Vec<u8>,
            witness: Vec<Vec<u8>>,
        }

        #[derive(Debug)]
        struct ScanTxHelper {
            ins: Vec<Input>,
            #[allow(dead_code)]
            outs: Vec<Vec<u8>>,
        }

        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
        )
        .unwrap();

        for raw_block in block_data.iter() {
            let block = Block::try_from(raw_block.as_slice()).unwrap();
            let (accepted, new_block) = chainman.process_block(&block);
            assert!(accepted);
            assert!(new_block);
        }

        let active_chain = chainman.active_chain();

        for (height, block_index) in active_chain.iter().enumerate() {
            assert_eq!(height, block_index.height().try_into().unwrap());
        }

        let block_index_tip = active_chain.tip();

        let raw_block_tip: Vec<u8> = chainman
            .read_block_data(&block_index_tip)
            .unwrap()
            .consensus_encode()
            .unwrap();

        let spent_outputs_tip = chainman.read_spent_outputs(&block_index_tip).unwrap();
        let block_tip: bitcoin::Block = deserialize(&raw_block_tip).unwrap();
        // Should be the same size minus the coinbase transaction
        assert_eq!(block_tip.txdata.len() - 1, spent_outputs_tip.count());

        let block_index_tip_prev = block_index_tip.prev().unwrap();
        let raw_block: Vec<u8> = chainman
            .read_block_data(&block_index_tip_prev)
            .unwrap()
            .try_into()
            .unwrap();

        let spent_outputs = chainman.read_spent_outputs(&block_index_tip_prev).unwrap();
        let block: bitcoin::Block = deserialize(&raw_block).unwrap();
        // Should be the same size minus the coinbase transaction
        assert_eq!(block.txdata.len() - 1, spent_outputs.count());

        for i in 0..(block.txdata.len() - 1) {
            let tx_spent_outputs = spent_outputs.transaction_spent_outputs(i).unwrap();
            let coins_spent_count = tx_spent_outputs.count();
            let transaction_input_size = block.txdata[i + 1].input.len();

            assert_eq!(transaction_input_size, coins_spent_count);
            let mut helper = ScanTxHelper {
                ins: vec![],
                outs: block.txdata[i + 1]
                    .output
                    .iter()
                    .map(|output| output.script_pubkey.to_bytes())
                    .collect(),
            };
            for j in 0..transaction_input_size {
                let coin = tx_spent_outputs.coin(j).unwrap();
                helper.ins.push(Input {
                    height: coin.confirmation_height(),
                    prevout: coin.output().unwrap().script_pubkey().to_bytes(),
                    script_sig: block.txdata[i + 1].input[j].script_sig.to_bytes(),
                    witness: block.txdata[i + 1].input[j].witness.to_vec(),
                });
            }
            println!("helper: {:?}", helper);
        }
    }

    #[test]
    fn test_process_data() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
        )
        .unwrap();

        for raw_block in block_data.iter() {
            let block = Block::try_from(raw_block.as_slice()).unwrap();
            let (accepted, new_block) = chainman.process_block(&block);
            assert!(accepted);
            assert!(new_block);
        }
    }

    #[test]
    fn test_validate_any() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
        )
        .unwrap();

        chainman.import_blocks().unwrap();
        let block_2 = Block::try_from(block_data[1].clone().as_slice()).unwrap();
        let (accepted, new_block) = chainman.process_block(&block_2);
        assert!(!accepted);
        assert!(!new_block);
    }

    #[test]
    fn test_logger() {
        let (_, _) = testing_setup();

        let logger_1 = Some(Logger::new(TestLog {}).unwrap());
        let logger_2 = Some(Logger::new(TestLog {}).unwrap());
        let logger_3 = Some(Logger::new(TestLog {}).unwrap());

        drop(logger_1);

        drop(logger_2);

        drop(logger_3);
    }

    #[test]
    fn test_reftype_deref() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_out = TxOut::new(&script, 1000);

        let script_ref = tx_out.script_pubkey();

        let bytes = script_ref.to_bytes();

        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_reftype_as_ref() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_out = TxOut::new(&script, 1000);

        let script_ref = tx_out.script_pubkey();

        let script_as_ref: &ScriptPubkey = script_ref.as_ref();

        let bytes = script_as_ref.to_bytes();

        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_reftype_to_owned() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_out = TxOut::new(&script, 1000);

        let script_ref = tx_out.script_pubkey();
        let owned_script = script_ref.to_owned();

        let bytes1 = script_ref.to_bytes();
        let bytes2 = owned_script.to_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1, script_data);
    }

    #[test]
    fn test_reftype_generic_function() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_out = TxOut::new(&script, 1000);

        let script_ref = tx_out.script_pubkey();

        fn process_script<T: AsRef<ScriptPubkey>>(script: T) -> Vec<u8> {
            script.as_ref().to_bytes()
        }

        let bytes = process_script(script_ref);
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_to_owned_survives_drop() {
        let owned_script = {
            let script_data = vec![0x76, 0xa9, 0x14];
            let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
            let tx_out = TxOut::new(&script, 1000);
            let script_ref = tx_out.script_pubkey();
            script_ref.to_owned()
        };

        let bytes = owned_script.to_bytes();
        assert_eq!(bytes, vec![0x76, 0xa9, 0x14]);
    }

    #[test]
    fn test_chain_operations() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();

        let chainman = ChainstateManager::new(
            ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
        )
        .unwrap();

        for raw_block in block_data.iter() {
            let block = Block::try_from(raw_block.as_slice()).unwrap();
            let (accepted, new_block) = chainman.process_block(&block);
            assert!(accepted);
            assert!(new_block);
        }

        let chain = chainman.active_chain();

        let genesis = chain.genesis();
        assert_eq!(genesis.height(), 0);
        let genesis_hash = genesis.block_hash();

        let tip = chain.tip();
        let tip_height = tip.height();
        let tip_hash = tip.block_hash();

        assert!(tip_height > 0);
        assert_ne!(genesis_hash.hash, tip_hash.hash);

        let genesis_via_height = chain.at_height(0).unwrap();
        assert_eq!(genesis_via_height.height(), 0);
        assert_eq!(genesis_via_height.block_hash().hash, genesis_hash.hash);

        let tip_via_height = chain.at_height(tip_height as usize).unwrap();
        assert_eq!(tip_via_height.height(), tip_height);
        assert_eq!(tip_via_height.block_hash().hash, tip_hash.hash);

        let invalid_entry = chain.at_height(9999);
        assert!(invalid_entry.is_none());

        assert!(chain.contains(&genesis));
        assert!(chain.contains(&tip));

        let mut current = genesis;
        let mut height_counter = 0;

        loop {
            assert_eq!(current.height(), height_counter);
            assert!(chain.contains(&current));

            if let Some(next_entry) = chain.next(&current) {
                assert_eq!(next_entry.height(), height_counter + 1);
                current = next_entry;
                height_counter += 1;
            } else {
                break;
            }
        }

        assert_eq!(height_counter, tip_height);
        assert_eq!(current.block_hash().hash, tip_hash.hash);
    }

    #[test]
    fn test_traits() {
        fn is_sync<T: Sync>() {}
        fn is_send<T: Send>() {}
        is_sync::<ScriptPubkey>();
        is_send::<ScriptPubkey>();
        is_sync::<ChainParams>(); // compiles only if true
        is_send::<ChainParams>();
        is_sync::<TxOut>();
        is_send::<TxOut>();
        is_sync::<Transaction>();
        is_send::<Transaction>();
        is_sync::<Context>();
        is_send::<Context>();
        is_sync::<Block>();
        is_send::<Block>();
        is_sync::<BlockSpentOutputs>();
        is_send::<BlockSpentOutputs>();
        is_sync::<TransactionSpentOutputs>();
        is_send::<TransactionSpentOutputs>();
        is_sync::<Coin>();
        is_send::<Coin>();
        is_sync::<ChainstateManager>();
        is_send::<ChainstateManager>();
        is_sync::<BlockHash>();
        is_send::<BlockHash>();
        // is_sync::<Rc<u8>>(); // won't compile, kept as a failure case.
        // is_send::<Rc<u8>>(); // won't compile, kept as a failure case.
    }
}
