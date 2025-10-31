#![no_main]

use bitcoinkernel::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = Block::try_from(data) else {
        return;
    };

    let serialized: Vec<u8> = block.try_into().unwrap();
    let roundtrip =
        Block::try_from(serialized.as_slice()).expect("Serialized block should deserialize");
    let reserialized: Vec<u8> = roundtrip.try_into().unwrap();

    assert_eq!(
        serialized, reserialized,
        "Serialization must be stable across roundtrips"
    );
});
