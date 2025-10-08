#![no_main]

use std::sync::{Arc, Once};

use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;

use bitcoinkernel::{
    disable_logging,
    notifications::types::{BlockValidationStateExt, BlockValidationStateRef},
    Block, ChainType, ChainstateManager, ChainstateManagerOptions, Context, ContextBuilder,
    KernelError, ValidationMode,
};

fn create_context(chain_type: ChainType) -> Arc<Context> {
    Arc::new(
        ContextBuilder::new()
            .chain_type(chain_type)
            .with_block_tip_notification(|_state, _block_index, _verification_progress| {})
            .with_header_tip_notification(|_state, _height, _timestamp, _presync| {})
            .with_progress_notification(|_title, _progress, _resume_possible| {})
            .with_warning_set_notification(|_warning, _message| {})
            .with_warning_unset_notification(|_warning| {})
            .with_flush_error_notification(|_message| {})
            .with_fatal_error_notification(|_message| {})
            .with_block_checked_validation(|_block, state: BlockValidationStateRef<'_>| {
                assert!(state.mode() != ValidationMode::InternalError)
            })
            .build()
            .unwrap(),
    )
}

#[derive(Debug, Arbitrary)]
pub enum FuzzChainType {
    MAINNET,
    TESTNET,
    REGTEST,
    SIGNET,
}

impl Into<ChainType> for FuzzChainType {
    fn into(self) -> ChainType {
        match self {
            FuzzChainType::MAINNET => ChainType::Mainnet,
            FuzzChainType::TESTNET => ChainType::Testnet,
            FuzzChainType::REGTEST => ChainType::Regtest,
            FuzzChainType::SIGNET => ChainType::Signet,
        }
    }
}

#[derive(Debug, Arbitrary)]
pub struct ChainstateManagerInput {
    pub data_dir: String,
    pub chain_type: FuzzChainType,
    pub blocks: Vec<Vec<u8>>,
    pub wipe_block_index: bool,
    pub wipe_chainstate_index: bool,
    pub block_tree_db_in_memory: bool,
    pub chainstate_db_in_memory: bool,
    pub worker_threads: i32,
}

static INIT: Once = Once::new();

fuzz_target!(|data: ChainstateManagerInput| {
    INIT.call_once(|| {
        disable_logging();
    });

    let context = create_context(data.chain_type.into());
    // Sanitize the input string by removing dots and slashes
    let sanitized_string: String = data
        .data_dir
        .chars()
        .filter(|c| *c != '.' && *c != '/')
        .take(60)
        .collect();

    let data_dir = format!("/tmp/rust_kernel_fuzz/{}", sanitized_string);
    let blocks_dir = format!("{}/blocks", data_dir);
    let chainman_opts = match ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir) {
        Ok(opts) => opts,
        Err(KernelError::CStringCreationFailed(_)) => return,
        Err(err) => panic!("this should never happen: {}", err),
    }
    .set_wipe_db(data.wipe_block_index, data.wipe_chainstate_index)
    .set_block_tree_db_in_memory(data.block_tree_db_in_memory)
    .set_chainstate_db_in_memory(data.chainstate_db_in_memory);
    chainman_opts.set_worker_threads(data.worker_threads);
    let chainman = match ChainstateManager::new(chainman_opts) {
        Err(KernelError::Internal(_)) => {
            return;
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(data_dir);
            panic!("this should never happen: {}", err);
        }
        Ok(chainman) => chainman,
    };

    if let Err(err) = chainman.import_blocks() {
        let _ = std::fs::remove_dir_all(data_dir);
        panic!("this should never happen: {}", err);
    }

    for block in data.blocks {
        if let Ok(block) = Block::try_from(block.as_slice()) {
            let _ = chainman.process_block(&block);
        }
    }
    drop(chainman);
    let _ = std::fs::remove_dir_all(data_dir);
});
