#![no_main]

use libfuzzer_sys::fuzz_target;

use libbitcoinkernel_sys::{
    BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager,
    ChainstateManagerOptions, Context, ContextBuilder, KernelError,
    KernelNotificationInterfaceCallbackHolder, LogCallback, Logger,
};

fn create_context() -> Context {
    ContextBuilder::new()
        .chain_type(ChainType::REGTEST)
        .unwrap()
        .kn_callbacks(Box::new(KernelNotificationInterfaceCallbackHolder {
            kn_block_tip: Box::new(|_state, _block_index| {}),
            kn_header_tip: Box::new(|_state, _height, _timestamp, _presync| {}),
            kn_progress: Box::new(|_title, _progress, _resume_possible| {}),
            kn_warning: Box::new(|_warning| {}),
            kn_flush_error: Box::new(|_message| {}),
            kn_fatal_error: Box::new(|_message| {}),
        }))
        .unwrap()
        .build()
        .unwrap()
}

fuzz_target!(|data: &[u8]| {
    let context = create_context();
    if let Ok(s) = std::str::from_utf8(data) {
        let data_dir = "/mnt/tmp/kernel".to_string() + s;
        let blocks_dir = data_dir.clone() + "/blocks";
        let chainman_opts = ChainstateManagerOptions::new(&context, &data_dir).unwrap();
        let blockman_opts = BlockManagerOptions::new(&context, &blocks_dir).unwrap();
        let chainman = ChainstateManager::new(
            chainman_opts,
            blockman_opts,
            &context,
        ).unwrap();
        chainman.load_chainstate(ChainstateLoadOptions::new()).unwrap();

    }
});
