use crate::constants::*;
use crate::{c_helpers, KernelError, ScriptPubkey, ScriptVerifyStatus, Transaction, TxOut};
use libbitcoinkernel_sys::*;

pub const VERIFY_NONE: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NONE;

pub const VERIFY_P2SH: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH;

pub const VERIFY_DERSIG: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG;

pub const VERIFY_NULLDUMMY: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY;

pub const VERIFY_CHECKLOCKTIMEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY;

pub const VERIFY_CHECKSEQUENCEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY;

pub const VERIFY_WITNESS: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS;

pub const VERIFY_TAPROOT: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT;

pub const VERIFY_ALL: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_ALL;

pub const VERIFY_ALL_PRE_TAPROOT: btck_ScriptVerificationFlags = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// A collection of errors that may occur during script verification
#[derive(Debug)]
pub enum ScriptVerifyError {
    TxInputIndex,
    TxSizeMismatch,
    TxDeserialize,
    InvalidFlags,
    InvalidFlagsCombination,
    SpentOutputsMismatch,
    SpentOutputsRequired,
    Invalid,
}

/// Verifies a transaction input against its corresponding output script.
///
/// # Arguments
/// * `script_pubkey` - The output script to verify against
/// * `amount` - Needs to be set if the segwit flag is set
/// * `tx_to` - The transaction containing the input to verify
/// * `input_index` - The index of the input within `tx_to` to verify
/// * `flags` - Defaults to all if none
/// * `spent_output` - The outputs being spent by this transaction
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * [`KernelError::ScriptVerify`] an error describing the failure
pub fn verify(
    script_pubkey: &ScriptPubkey,
    amount: Option<i64>,
    tx_to: &Transaction,
    input_index: usize,
    flags: Option<u32>,
    spent_outputs: &[TxOut],
) -> Result<(), KernelError> {
    let input_count = tx_to.input_count();

    if input_index >= input_count {
        return Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex));
    }

    if !spent_outputs.is_empty() && spent_outputs.len() != input_count {
        return Err(KernelError::ScriptVerify(
            ScriptVerifyError::SpentOutputsMismatch,
        ));
    }

    let kernel_flags = if let Some(flag) = flags {
        if (flag & !VERIFY_ALL) != 0 {
            return Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags));
        }
        flag
    } else {
        VERIFY_ALL
    };

    let status = ScriptVerifyStatus::Ok;
    let kernel_amount = amount.unwrap_or_default();
    let kernel_spent_outputs: Vec<*const btck_TransactionOutput> = spent_outputs
        .iter()
        .map(|utxo| utxo.inner as *const btck_TransactionOutput)
        .collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null_mut()
    } else {
        kernel_spent_outputs.as_ptr() as *mut *const btck_TransactionOutput
    };

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.inner,
            kernel_amount,
            tx_to.inner,
            spent_outputs_ptr,
            spent_outputs.len(),
            input_index as u32,
            kernel_flags,
            &mut status.into(),
        )
    };

    let script_status = ScriptVerifyStatus::try_from(status).map_err(|_| {
        KernelError::Internal(format!("Invalid script verify status: {:?}", status))
    })?;

    if !c_helpers::verification_passed(ret) {
        let err = match script_status {
            ScriptVerifyStatus::ErrorInvalidFlagsCombination => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            ScriptVerifyStatus::ErrorSpentOutputsRequired => {
                ScriptVerifyError::SpentOutputsRequired
            }
            _ => ScriptVerifyError::Invalid,
        };
        Err(KernelError::ScriptVerify(err))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_script_verification_bit_positions() {
        assert_eq!(VERIFY_P2SH, 1 << 0);
        assert_eq!(VERIFY_DERSIG, 1 << 2);
        assert_eq!(VERIFY_NULLDUMMY, 1 << 4);
        assert_eq!(VERIFY_CHECKLOCKTIMEVERIFY, 1 << 9);
        assert_eq!(VERIFY_CHECKSEQUENCEVERIFY, 1 << 10);
        assert_eq!(VERIFY_WITNESS, 1 << 11);
        assert_eq!(VERIFY_TAPROOT, 1 << 17);
    }

    #[test]
    fn test_script_verification_flags_constants() {
        assert_eq!(VERIFY_NONE, BTCK_SCRIPT_VERIFICATION_FLAGS_NONE);
        assert_eq!(VERIFY_P2SH, BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH);
        assert_eq!(VERIFY_DERSIG, BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG);
        assert_eq!(VERIFY_NULLDUMMY, BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY);
        assert_eq!(
            VERIFY_CHECKLOCKTIMEVERIFY,
            BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY
        );
        assert_eq!(
            VERIFY_CHECKSEQUENCEVERIFY,
            BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY
        );
        assert_eq!(VERIFY_WITNESS, BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS);
        assert_eq!(VERIFY_TAPROOT, BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT);
        assert_eq!(VERIFY_ALL, BTCK_SCRIPT_VERIFICATION_FLAGS_ALL);
    }

    #[test]
    fn test_script_verification_flags_combining() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        assert!(flags & VERIFY_P2SH != 0);
        assert!(flags & VERIFY_WITNESS != 0);
        assert!(flags & VERIFY_TAPROOT == 0);

        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_P2SH != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_DERSIG != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_NULLDUMMY != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_CHECKLOCKTIMEVERIFY != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_CHECKSEQUENCEVERIFY != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_WITNESS != 0);
        assert!(VERIFY_ALL_PRE_TAPROOT & VERIFY_TAPROOT == 0);

        assert!(VERIFY_ALL & VERIFY_P2SH != 0);
        assert!(VERIFY_ALL & VERIFY_DERSIG != 0);
        assert!(VERIFY_ALL & VERIFY_NULLDUMMY != 0);
        assert!(VERIFY_ALL & VERIFY_CHECKLOCKTIMEVERIFY != 0);
        assert!(VERIFY_ALL & VERIFY_CHECKSEQUENCEVERIFY != 0);
        assert!(VERIFY_ALL & VERIFY_WITNESS != 0);
        assert!(VERIFY_ALL & VERIFY_TAPROOT != 0);
    }

    #[test]
    fn test_verify_input_validation() {
        let script_data =
            hex::decode("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac").unwrap();
        let script_pubkey = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_hex = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        let tx = Transaction::try_from(hex::decode(tx_hex).unwrap().as_slice()).unwrap();
        let dummy_output = TxOut::new(&script_pubkey, 100000);

        // tx_index out of bounds
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            999,
            Some(VERIFY_ALL_PRE_TAPROOT),
            std::slice::from_ref(&dummy_output),
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex))
        ));

        let wrong_spent_outputs = vec![dummy_output.clone(), dummy_output.clone()];

        // two transaction outputs for one input
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &wrong_spent_outputs,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::SpentOutputsMismatch
            ))
        ));

        // Test Invalid flags
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(0xFFFFFFFF),
            std::slice::from_ref(&dummy_output),
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags))
        ));
    }

    #[test]
    fn script_verify_test() {
        // a random old-style transaction from the blockchain
        verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0
        ).unwrap();

        // a random segwit transaction from the blockchain using P2SH
        verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            1900000, 0
        ).unwrap();

        // a random segwit transaction from the blockchain using native segwit
        verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0
        ).unwrap();

        // a random old-style transaction from the blockchain - WITH WRONG SIGNATURE for the address
        assert!(verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ff",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0
        ).is_err());

        // a random segwit transaction from the blockchain using P2SH - WITH WRONG AMOUNT
        assert!(verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            900000, 0).is_err());

        // a random segwit transaction from the blockchain using native segwit - WITH WRONG SEGWIT
        assert!(verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58f",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0
        ).is_err());
    }

    fn verify_test(
        spent: &str,
        spending: &str,
        amount: i64,
        input: usize,
    ) -> Result<(), KernelError> {
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
}
