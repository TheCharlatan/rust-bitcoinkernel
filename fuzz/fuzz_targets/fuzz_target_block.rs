#![no_main]

use libbitcoinkernel_sys::Block;
use libfuzzer_sys::fuzz_target;

fn vec_to_hex_string(data: &[u8]) -> String {
    let mut hex_string = String::with_capacity(data.len() * 2);
    for byte in data {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(block) = Block::try_from(s) {
            let block_serialized: Vec<u8> = block.into();
            let block_string: String = vec_to_hex_string(&block_serialized);
            assert!(block_string == s.to_lowercase()[..block_string.len()]);
        }
    }
});
