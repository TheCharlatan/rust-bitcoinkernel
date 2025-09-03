// Copyright (c) 2023-present The Bitcoin Kernel developers
// Licensed under the MIT License. See LICENSE file in the project root.

#![no_main]

use bitcoinkernel::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::try_from(data) {
        let block_serialized: Vec<u8> = block.try_into().unwrap();
        assert!(data.len() >= block_serialized.len());
    }
});
