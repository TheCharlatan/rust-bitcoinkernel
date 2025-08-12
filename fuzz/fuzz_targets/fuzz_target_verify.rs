#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use bitcoinkernel::{verify, ScriptPubkey, Transaction, TxOut};

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
    pub input_index: usize,
    pub flags: Option<u32>,
    pub spent_outputs: Vec<UtxoWrapper>,
}

fuzz_target!(|data: VerifyInput| {
    // Call the verify function with the fuzzed inputs
    let spent_outputs: Vec<TxOut> = data
        .spent_outputs
        .iter()
        .map(|utxo| {
            let script_pubkey = ScriptPubkey::try_from(utxo.script_pubkey.as_slice()).unwrap();
            TxOut::new(&script_pubkey, utxo.value)
        })
        .collect();

    let script_pubkey = ScriptPubkey::try_from(data.script_pubkey.as_slice()).unwrap();
    let transaction = if let Ok(res) = Transaction::try_from(data.tx_to.as_slice()) {
        res
    } else {
        return;
    };

    let _ = verify(
        &script_pubkey,
        data.amount,
        &transaction,
        data.input_index,
        data.flags,
        &spent_outputs,
    );
});
