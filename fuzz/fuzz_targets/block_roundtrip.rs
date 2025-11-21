#![no_main]

use bitcoinkernel::{prelude::*, Block, Transaction};
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

    let block = Block::try_from(data).unwrap();

    let tx_count = block.transaction_count();
    assert_eq!(tx_count, block.transactions().count());

    for (i, tx) in block.transactions().enumerate().take(1000) {
        if let Ok(indexed_tx) = block.transaction(i) {
            assert_eq!(tx.txid(), indexed_tx.txid());
        }

        assert_eq!(tx.inputs().count(), tx.input_count());
        assert_eq!(tx.outputs().count(), tx.output_count());

        for (j, input) in tx.inputs().enumerate().take(10) {
            if let Ok(indexed_input) = tx.input(j) {
                let op1 = input.outpoint();
                let op2 = indexed_input.outpoint();
                assert_eq!(op1.txid(), op2.txid());
                assert_eq!(op1.index(), op2.index());
                assert_eq!(op1.is_null(), op2.is_null());
            }
        }

        for (j, output) in tx.outputs().enumerate().take(10) {
            if let Ok(indexed_output) = tx.output(j) {
                assert_eq!(output.value(), indexed_output.value());
                assert_eq!(
                    output.script_pubkey().to_bytes(),
                    indexed_output.script_pubkey().to_bytes()
                );
            }
        }

        // Sanity check that transactions extracted from blocks are valid on their own
        if let Ok(tx_bytes) = tx.consensus_encode() {
            let standalone_tx = Transaction::try_from(tx_bytes.as_slice())
                .expect("Transaction valid in block should parse standalone");
            assert_eq!(tx.txid(), standalone_tx.txid());
            assert_eq!(tx.input_count(), standalone_tx.input_count());
            assert_eq!(tx.output_count(), standalone_tx.output_count());
        }
    }
});
