use libbitcoinkernel_sys::{
    btck_ScriptVerificationFlags, btck_ScriptVerifyStatus, btck_TransactionOutput,
    btck_script_pubkey_verify,
};

use crate::{
    c_helpers,
    constants::{
        BTCK_SCRIPT_VERIFICATION_FLAGS_ALL, BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY,
        BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY, BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG,
        BTCK_SCRIPT_VERIFICATION_FLAGS_NONE, BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY,
        BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH, BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT,
        BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS,
        BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION,
        BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED, BTCK_SCRIPT_VERIFY_STATUS_OK,
    },
    KernelError, ScriptPubkeyExt, TransactionExt, TxOutExt,
};

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
    script_pubkey: &impl ScriptPubkeyExt,
    amount: Option<i64>,
    tx_to: &impl TransactionExt,
    input_index: usize,
    flags: Option<u32>,
    spent_outputs: &[impl TxOutExt],
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
    let kernel_spent_outputs: Vec<*const btck_TransactionOutput> =
        spent_outputs.iter().map(|utxo| utxo.as_ptr()).collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null_mut()
    } else {
        kernel_spent_outputs.as_ptr() as *mut *const btck_TransactionOutput
    };

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.as_ptr(),
            kernel_amount,
            tx_to.as_ptr(),
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

/// Status of script verification operations.
///
/// Indicates the result of verifying a transaction script, including any
/// configuration errors that prevented verification from proceeding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptVerifyStatus {
    /// Script verification completed successfully
    Ok = BTCK_SCRIPT_VERIFY_STATUS_OK,
    /// Invalid combination of verification flags was provided
    ErrorInvalidFlagsCombination = BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION,
    /// Spent outputs are required for this type of verification but were not provided
    ErrorSpentOutputsRequired = BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED,
}

impl From<ScriptVerifyStatus> for btck_ScriptVerifyStatus {
    fn from(status: ScriptVerifyStatus) -> Self {
        status as btck_ScriptVerifyStatus
    }
}

impl From<btck_ScriptVerifyStatus> for ScriptVerifyStatus {
    fn from(value: btck_ScriptVerifyStatus) -> Self {
        match value {
            BTCK_SCRIPT_VERIFY_STATUS_OK => ScriptVerifyStatus::Ok,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyStatus::ErrorInvalidFlagsCombination
            }
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyStatus::ErrorSpentOutputsRequired
            }
            _ => panic!("Unknown script verify status: {}", value),
        }
    }
}

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
