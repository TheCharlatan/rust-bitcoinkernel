use bitcoin::Script;
use bitcoinkernel::{
    verify, KernelError, ScriptDebugCallbackHolder, ScriptDebugger, ScriptPubkey, Transaction,
    VERIFY_ALL_PRE_TAPROOT,
};

fn verify_test(spent: &str, spending: &str, amount: i64, input: u32) -> Result<(), KernelError> {
    let outputs = vec![];
    let spent_script_pubkey =
        ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
    let spending_tx = Transaction::try_from(hex::decode(spending).unwrap().as_slice()).unwrap();
    verify(
        &spent_script_pubkey,
        Some(amount),
        &spending_tx,
        input,
        Some(VERIFY_ALL_PRE_TAPROOT),
        &outputs,
    )
}

fn main() {
    let debug_cb = Box::new(
        |stack: Vec<Vec<u8>>, script: Vec<u8>, pos: u32, altstack: Vec<Vec<u8>>| {
            println!("\nMain Stack ({} items, top last):", stack.len());
            if stack.is_empty() {
                println!("  <empty>");
            } else {
                for (i, item) in stack.iter().enumerate() {
                    if item.is_empty() {
                        println!("  {}: <empty>", i);
                    } else {
                        println!("  {}: 0x{}", i, hex::encode(item));
                        // If the data might be ASCII, show it
                        if item.iter().all(|&c| c >= 32 && c <= 126) {
                            println!("     ASCII: \"{}\"", String::from_utf8_lossy(item));
                        }
                    }
                }
            }
            
            if !altstack.is_empty() {
                println!("\nAlt Stack ({} items, top last):", altstack.len());
                for (i, item) in altstack.iter().enumerate() {
                    if item.is_empty() {
                        println!("  {}: <empty>", i);
                    } else {
                        println!("  {}: 0x{}", i, hex::encode(item));
                    }
                }
            }
            
            let script = Script::from_bytes(&script);
            println!("Script:");
            println!("  Decoded:");
            for (i, op) in script.instructions().enumerate() {
                match op {
                    Ok(instruction) => {
                        if i as u32 == pos {
                            print!("  > ");
                        } else {
                            print!("    ");
                        }
                        println!("{:?}", instruction);
                    }
                    Err(e) => println!("    Error decoding instruction: {}", e),
                }
            }
        },
    );

    let holder = Box::new(ScriptDebugCallbackHolder {
        script_debug: debug_cb,
    });
    let _debugger = ScriptDebugger::new(holder);

    // a random old-style transaction from the blockchain
    verify_test (
        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
        0, 0
    ).unwrap();
}
