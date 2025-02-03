use std::env;
use std::fmt;
use std::process;
use std::sync::Arc;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{PrivateKey, XOnlyPublicKey};
use bitcoinkernel::{
    BlockManagerOptions, ChainType, ChainstateLoadOptions, ChainstateManager,
    ChainstateManagerOptions, Context, ContextBuilder, KernelError, Log, Logger,
};
use env_logger::Builder;
use log::LevelFilter;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{
    calculate_shared_secret, calculate_tweak_data, get_pubkey_from_input,
};

struct MainLog {}

impl Log for MainLog {
    fn log(&self, message: &str) {
        log::info!(
            target: "libbitcoinkernel", 
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    }
}

fn setup_logging() -> Result<Logger<MainLog>, KernelError> {
    let mut builder = Builder::from_default_env();
    builder.filter(None, LevelFilter::Info).init();
    Logger::new(MainLog {})
}

fn create_context() -> Arc<Context> {
    Arc::new(
        ContextBuilder::new()
            .chain_type(ChainType::REGTEST)
            .build()
            .unwrap(),
    )
}

fn vec_to_hex_string(data: &Vec<u8>) -> String {
    let mut hex_string = String::with_capacity(data.len() * 2);
    for byte in data {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    hex_string
}

#[derive(Debug, Clone)]
struct Input {
    prevout: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    prevout_data: (Vec<u8>, u32),
}

#[derive(Debug, Clone)]
struct ScanTxHelper {
    ins: Vec<Input>,
    outs: Vec<Vec<u8>>,
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prevout: {}, ", vec_to_hex_string(&self.prevout))?;
        write!(f, "script_sig: {}, ", vec_to_hex_string(&self.script_sig))?;
        for witness_elem in self.witness.iter() {
            write!(f, "witness: {}, ", vec_to_hex_string(&witness_elem))?;
        }
        write!(
            f,
            "prevout txid: {}, ",
            bitcoin::Txid::from_slice(&self.prevout_data.0).unwrap()
        )?;
        write!(f, "prevout n: {}, ", self.prevout_data.1)
    }
}

impl fmt::Display for ScanTxHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for input in self.ins.iter() {
            write!(f, "input: {}\n", input)?;
        }
        for output in self.outs.iter() {
            write!(f, "output: {}\n", vec_to_hex_string(&output))?;
        }
        write!(f, "")
    }
}

// silent payment txid:
// 4282b1727f0ebb0c035e8306c2c09764b5b637d63ae5249f7d0d1968a1554231
// silent payment tx:
// 02000000000102bbbd77f0d8c5cbc2ccc39f0501828ad4ac3a6a933393876cae5a7e49bd5341230100000000fdffffff94e299c837e0e00644b9123d80c052159443907f663e746be7fe1e6c32c3ee9b0100000000fdffffff0218e0f50500000000225120d7bf24e13daf4d6ce0ac7a34ecefb4122f070a1561e8659d4071c52edb7c1cb300e1f505000000002251207ef15780916ae0f29a0bd34e48e1a0e817e7731b82f3009cfa89c87602cf1b2b02473044022014680d9a963868b03d25f84bd81af87e127f9d7990166dad5e1dd71be8797e3402205f79713b4faaff7184fb25d0976a37970f8d6b23f95d4041180a35aa291fc8dc012102a9dfaeeebad1f7ebca371a6f02e63a8b0de287c1b0608edc259c60583a03496e0247304402201f09ecdb89f311c3ad8b6d89a040a5796f83c9db2597962969392a3d9a5be46d022052243418a89831ca0e5ddd7ae575d787178126d8495f890414ab8b4d2a1b19d80121035368c752d3ee31d9570180a1ba285659af106f9430811ec58e3b86cf26c208f100000000
// silent payment to address:
// sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz
// spend key:
// cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11
// scan key:
// cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24

fn parse_keys() -> (Receiver, SecretKey) {
    let original = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

    let spend_key =
        PrivateKey::from_wif("cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11").unwrap();
    let scan_key =
        PrivateKey::from_wif("cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24").unwrap();

    let secp = Secp256k1::new();
    let public_spend_key: secp256k1::PublicKey = spend_key.public_key(&secp).inner;
    let public_scan_key: secp256k1::PublicKey = scan_key.public_key(&secp).inner;

    let label = Label::new(spend_key.inner, 0);
    let receiver = Receiver::new(0, public_scan_key, public_spend_key, label, false).unwrap();
    println!("Receiver address: {}", receiver.get_receiving_address());
    println!("Actual adress:    {}", original);
    (receiver, scan_key.inner)
}

fn scan_tx(receiver: &Receiver, secret_scan_key: &SecretKey, scan_tx_helper: ScanTxHelper) {
    let input_pub_keys: Vec<PublicKey> = scan_tx_helper
        .ins
        .iter()
        .filter_map(|input| {
            get_pubkey_from_input(&input.script_sig, &input.witness, &input.prevout).unwrap()
        })
        .collect();
    let pubkeys_ref: Vec<&PublicKey> = input_pub_keys.iter().collect();
    let outpoints_data: Vec<_> = scan_tx_helper
        .ins
        .iter()
        .map(|input| {
            let txid = bitcoin::Txid::from_slice(&input.prevout_data.0)
                .unwrap()
                .to_string();
            (txid, input.prevout_data.1)
        })
        .collect();
    let tweak_data = calculate_tweak_data(&pubkeys_ref, &outpoints_data).unwrap();
    let ecdh_shared_secret = calculate_shared_secret(tweak_data, *secret_scan_key).unwrap();
    let pubkeys_to_check: Vec<XOnlyPublicKey> = scan_tx_helper
        .outs
        .iter()
        .filter_map(|script_pubkey| {
            if let Ok(res) = XOnlyPublicKey::from_slice(&script_pubkey[2..]) {
                Some(res)
            } else {
                None
            }
        })
        .collect();
    if let Ok(res) = receiver.scan_transaction(&ecdh_shared_secret, pubkeys_to_check) {
        println!("\nres: {:?}\n", res);
    }
}

fn scan_txs(chainman: &ChainstateManager) {
    let (receiver, secret_scan_key) = parse_keys();
    let mut block_index = chainman.get_block_index_tip();
    loop {
        if block_index.height() <= 1 {
            break;
        }
        let undo = chainman.read_undo_data(&block_index).unwrap();
        let raw_block: Vec<u8> = chainman.read_block_data(&block_index).unwrap().into();
        let block: bitcoin::Block = deserialize(&raw_block).unwrap();
        // Should be the same size minus the coinbase transaction
        assert_eq!(block.txdata.len() - 1, undo.n_tx_undo);

        for i in 0..(block.txdata.len() - 1) {
            let transaction_undo_size: u64 = undo.get_transaction_undo_size(i.try_into().unwrap());
            let transaction_input_size: u64 = block.txdata[i + 1].input.len().try_into().unwrap();
            assert_eq!(transaction_input_size, transaction_undo_size);
            let mut scan_tx_helper = ScanTxHelper {
                ins: vec![],
                outs: block.txdata[i + 1]
                    .output
                    .iter()
                    .map(|output| output.script_pubkey.to_bytes())
                    .collect(),
            };
            for j in 0..transaction_input_size {
                scan_tx_helper.ins.push(Input {
                    prevout: undo
                        .get_prevout_by_index(i as u64, j)
                        .unwrap()
                        .get_script_pubkey()
                        .get(),
                    script_sig: block.txdata[i + 1].input[j as usize].script_sig.to_bytes(),
                    witness: block.txdata[i + 1].input[j as usize].witness.to_vec(),
                    prevout_data: (
                        block.txdata[i + 1].input[j as usize]
                            .previous_output
                            .txid
                            .to_byte_array()
                            .to_vec(),
                        block.txdata[i + 1].input[j as usize].previous_output.vout,
                    ),
                });
            }
            scan_tx(&receiver, &secret_scan_key, scan_tx_helper.clone());
            println!("helper: {:?}", scan_tx_helper);
        }
        block_index = match block_index.prev() {
            Ok(block_index_prev) => block_index_prev,
            Err(_) => break,
        };
    }
    log::info!("scanned txs!");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_data_dir>", args[0]);
        process::exit(1);
    }

    let _ = setup_logging().unwrap();
    let context = create_context();
    let data_dir = args[1].clone();
    let blocks_dir = data_dir.clone() + "/blocks";
    let chainman = ChainstateManager::new(
        ChainstateManagerOptions::new(&context, &data_dir).unwrap(),
        BlockManagerOptions::new(&context, &data_dir, &blocks_dir).unwrap(),
        ChainstateLoadOptions::new(),
        Arc::clone(&context),
    )
    .unwrap();
    chainman.import_blocks().unwrap();
    scan_txs(&chainman);
}
