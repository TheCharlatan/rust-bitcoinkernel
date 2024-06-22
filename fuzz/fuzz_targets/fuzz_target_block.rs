#![no_main]

use libbitcoinkernel_sys::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::try_from(data) {
        let block_serialized: Vec<u8> = block.into();
        assert!(data.len() >= block_serialized.len());
    }
});
