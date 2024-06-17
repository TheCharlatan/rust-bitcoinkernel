#![no_main]

use libfuzzer_sys::fuzz_target;

use libbitcoinkernel_sys::{
    BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager,
    ChainstateManagerOptions, Context, ContextBuilder, KernelNotificationInterfaceCallbackHolder,
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
        // Sanitize the input string by removing dots and slashes
        let sanitized_string: String = s.chars().filter(|c| *c != '.' && *c != '/').collect();

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
            Err(_) => return,
        };
        let blockman_opts = match BlockManagerOptions::new(&context, &blocks_dir) {
            Ok(opts) => opts,
            Err(_) => return,
        };
        let chainman = match ChainstateManager::new(chainman_opts, blockman_opts, &context) {
            Ok(chainman) => chainman,
            Err(_) => return,
        };
        if chainman
            .load_chainstate(ChainstateLoadOptions::new())
            .is_err()
        {
            return;
        }
    }
});
