#![no_main]

use libfuzzer_sys::fuzz_target;

use libbitcoinkernel_sys::{verify, Utxo};

fuzz_target!(|data: &[u8]| {
    // To ensure we have enough data to split for different parameters, we'll use some slicing logic
    if data.len() < 16 {
        return; // Not enough data to split into meaningful parts
    }

    // Split the data into parts for each parameter
    let (script_pubkey, rest) = data.split_at(data.len() / 3);
    let (tx_to, remaining) = rest.split_at(rest.len() / 2);

    // Extract fixed-size parts for amount, input_index, and flags
    let amount = if remaining.len() >= 8 {
        Some(i64::from_le_bytes([
            remaining[0],
            remaining[1],
            remaining[2],
            remaining[3],
            remaining[4],
            remaining[5],
            remaining[6],
            remaining[7],
        ]))
    } else {
        None
    };

    let input_index = if remaining.len() >= 12 {
        u32::from_le_bytes([remaining[8], remaining[9], remaining[10], remaining[11]])
    } else {
        0
    };

    let flags = if remaining.len() >= 16 {
        Some(u32::from_le_bytes([
            remaining[12],
            remaining[13],
            remaining[14],
            remaining[15],
        ]))
    } else {
        None
    };

    // Create some dummy spent_outputs if there is enough remaining data
    let spent_outputs_vec = if remaining.len() > 24 {
        vec![Utxo {
            value: i64::from_le_bytes([
                remaining[16],
                remaining[17],
                remaining[18],
                remaining[19],
                remaining[20],
                remaining[21],
                remaining[22],
                remaining[23],
            ]),
            script_pubkey: &remaining[24..],
        }]
    } else {
        vec![]
    };

    let spent_outputs = if spent_outputs_vec.is_empty() {
        None
    } else {
        Some(&spent_outputs_vec[..])
    };

    // Call the verify function with the fuzzed inputs
    let _ = verify(
        script_pubkey,
        amount,
        tx_to,
        input_index,
        flags,
        spent_outputs,
    );
});
