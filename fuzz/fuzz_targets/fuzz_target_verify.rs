#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use libbitcoinkernel_sys::{verify, Utxo};

#[derive(Debug, Arbitrary)]
pub struct UtxoWrapper {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
pub struct VerifyInput {
    pub script_pubkey: Vec<u8>,
    pub amount: Option<i64>,
    pub tx_to: Vec<u8>,
    pub input_index: u32,
    pub flags: Option<u32>,
    pub spent_outputs: Option<Vec<UtxoWrapper>>,
}

fuzz_target!(|data: VerifyInput| {
    // Call the verify function with the fuzzed inputs
    let spent_outputs: Option<Vec<Utxo>> = data.spent_outputs.as_ref().map(|vec| {
        vec.iter()
            .map(|utxo| Utxo {
                value: utxo.value,
                script_pubkey: &utxo.script_pubkey,
            })
            .collect()
    });
    let spent_outputs_ref = spent_outputs.as_deref();

    let _ = verify(
        &data.script_pubkey,
        data.amount,
        &data.tx_to,
        data.input_index,
        data.flags,
        spent_outputs_ref,
    );
});
