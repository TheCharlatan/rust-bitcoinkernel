#![no_main]
use bitcoinkernel::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(transaction) = Transaction::try_from(data) else {
        return;
    };

    let serialized: Vec<u8> = transaction.try_into().unwrap();

    let roundtrip = Transaction::try_from(serialized.as_slice())
        .expect("Serialized transaction should deserialize");

    let reserialized: Vec<u8> = roundtrip.try_into().unwrap();

    assert_eq!(
        serialized, reserialized,
        "Serialization must be stable across roundtrips"
    );
});
