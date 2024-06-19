#![no_main]

use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;

use libbitcoinkernel_sys::{
    Block, BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager, ChainstateManagerOptions, Context, ContextBuilder, KernelNotificationInterfaceCallbackHolder
};

fn create_context(chain_type: ChainType) -> Context {
    ContextBuilder::new()
        .chain_type(chain_type)
        .unwrap()
        .kn_callbacks(Box::new(KernelNotificationInterfaceCallbackHolder {
            kn_block_tip: Box::new(|_state, _block_index| {}),
            kn_header_tip: Box::new(|_state, _height, _timestamp, _presync| {}),
            kn_progress: Box::new(|_title, _progress, _resume_possible| {}),
            kn_warning_set: Box::new(|_warning, _message| {}),
            kn_warning_unset: Box::new(|_warning| {}),
            kn_flush_error: Box::new(|_message| {}),
            kn_fatal_error: Box::new(|_message| {}),
        }))
        .unwrap()
        .build()
        .unwrap()
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
            FuzzChainType::MAINNET => ChainType::MAINNET,
            FuzzChainType::TESTNET => ChainType::TESTNET,
            FuzzChainType::REGTEST => ChainType::REGTEST,
            FuzzChainType::SIGNET => ChainType::SIGNET,
        }
    }
}

#[derive(Debug, Arbitrary)]
pub struct ChainstateManagerInput {
    pub data_dir: String,
    pub chain_type: FuzzChainType,
    pub block: String,
    pub wipe_block_index: bool,
    pub wipe_chainstate_index: bool,
}

fuzz_target!(|data: ChainstateManagerInput| {
    let context = create_context(data.chain_type.into());
    // Sanitize the input string by removing dots and slashes
    let sanitized_string: String = data.data_dir.chars().filter(|c| *c != '.' && *c != '/').collect();

    // Limit the length of the sanitized string to avoid excessively long paths
    let max_length = 255; // Adjust as necessary
    let limited_string = if sanitized_string.len() > max_length {
        &sanitized_string[..max_length]
    } else {
        &sanitized_string
    };

    let data_dir = format!("/mnt/tmp/kernel/{}", limited_string);
    let blocks_dir = format!("{}/blocks", data_dir);
    let chainman_opts = match ChainstateManagerOptions::new(&context, &data_dir) {
        Ok(opts) => opts,
        Err(libbitcoinkernel_sys::KernelError::CStringCreationFailed(_)) => return,
        Err(err) => panic!("this should never happen: {}", err),
    };
    let blockman_opts = BlockManagerOptions::new(&context, &blocks_dir).unwrap();
    let chainman = ChainstateManager::new(chainman_opts, blockman_opts, &context).unwrap();

    match chainman.load_chainstate(ChainstateLoadOptions::new().set_reindex(data.wipe_block_index).unwrap().set_wipe_chainstate_db(data.wipe_chainstate_index).unwrap())
    {
        Err(libbitcoinkernel_sys::KernelError::Internal(_)) => {}
        Err(err) => {
            let _ = std::fs::remove_dir_all(data_dir);
            panic!("this should never happen: {}", err);
        }
        _ => {}
    }
    if let Err(err) = chainman.import_blocks()
    {
        let _ = std::fs::remove_dir_all(data_dir);
        panic!("this should never happen: {}", err);
    }
    if let Ok(block) = Block::try_from(data.block.as_str()) {
        let _ = chainman.process_block(&block);
    }
    drop(chainman);
    let _ = std::fs::remove_dir_all(data_dir);
});
