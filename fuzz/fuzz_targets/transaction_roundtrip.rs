#![no_main]
use bitcoinkernel::{prelude::*, Transaction};
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

    let tx = Transaction::try_from(data).unwrap();

    assert_eq!(tx.inputs().count(), tx.input_count());
    assert_eq!(tx.outputs().count(), tx.output_count());

    for (i, input) in tx.inputs().enumerate().take(10) {
        if let Ok(indexed_input) = tx.input(i) {
            let op1 = input.outpoint();
            let op2 = indexed_input.outpoint();
            assert_eq!(op1.txid(), op2.txid());
            assert_eq!(op1.index(), op2.index());
        }
    }

    for (i, output) in tx.outputs().enumerate().take(10) {
        if let Ok(indexed_output) = tx.output(i) {
            assert_eq!(output.value(), indexed_output.value());
        }
    }
});
