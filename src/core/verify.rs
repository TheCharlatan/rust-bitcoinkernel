use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use libbitcoinkernel_sys::{
    btck_ScriptVerificationFlags, btck_ScriptVerifyStatus, btck_TransactionOutput,
    btck_script_pubkey_verify,
};

use crate::{
    c_helpers,
    ffi::{
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

    let kernel_amount = amount.unwrap_or_default();
    let kernel_spent_outputs: Vec<*const btck_TransactionOutput> =
        spent_outputs.iter().map(|utxo| utxo.as_ptr()).collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null_mut()
    } else {
        kernel_spent_outputs.as_ptr() as *mut *const btck_TransactionOutput
    };

    let mut status = ScriptVerifyStatus::Ok.into();

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.as_ptr(),
            kernel_amount,
            tx_to.as_ptr(),
            spent_outputs_ptr,
            spent_outputs.len(),
            input_index as u32,
            kernel_flags,
            &mut status,
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
enum ScriptVerifyStatus {
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
    InvalidFlags,
    InvalidFlagsCombination,
    SpentOutputsMismatch,
    SpentOutputsRequired,
    Invalid,
}

impl Display for ScriptVerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ScriptVerifyError::TxInputIndex => write!(f, "Transaction input index out of bounds"),
            ScriptVerifyError::InvalidFlags => write!(f, "Invalid verification flags"),
            ScriptVerifyError::InvalidFlagsCombination => {
                write!(f, "Invalid combination of verification flags")
            }
            ScriptVerifyError::SpentOutputsMismatch => write!(f, "Spent outputs mismatch"),
            ScriptVerifyError::SpentOutputsRequired => {
                write!(f, "Spent outputs required for verification")
            }
            ScriptVerifyError::Invalid => write!(f, "Script verification failed"),
        }
    }
}

impl Error for ScriptVerifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_constants() {
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
    fn test_verify_all_pre_taproot() {
        let expected = VERIFY_P2SH
            | VERIFY_DERSIG
            | VERIFY_NULLDUMMY
            | VERIFY_CHECKLOCKTIMEVERIFY
            | VERIFY_CHECKSEQUENCEVERIFY
            | VERIFY_WITNESS;

        assert_eq!(VERIFY_ALL_PRE_TAPROOT, expected);

        assert_eq!(VERIFY_ALL_PRE_TAPROOT & VERIFY_TAPROOT, 0);
    }

    #[test]
    fn test_verification_flag_combinations() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        assert!(flags & VERIFY_P2SH != 0);
        assert!(flags & VERIFY_WITNESS != 0);
        assert!(flags & VERIFY_TAPROOT == 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_verify_all_includes_all_flags() {
        assert!((VERIFY_ALL & VERIFY_P2SH) != 0);
        assert!((VERIFY_ALL & VERIFY_DERSIG) != 0);
        assert!((VERIFY_ALL & VERIFY_NULLDUMMY) != 0);
        assert!((VERIFY_ALL & VERIFY_CHECKLOCKTIMEVERIFY) != 0);
        assert!((VERIFY_ALL & VERIFY_CHECKSEQUENCEVERIFY) != 0);
        assert!((VERIFY_ALL & VERIFY_WITNESS) != 0);
        assert!((VERIFY_ALL & VERIFY_TAPROOT) != 0);
    }

    #[test]
    fn test_script_verify_status_from_kernel() {
        let ok: ScriptVerifyStatus = BTCK_SCRIPT_VERIFY_STATUS_OK.into();
        assert_eq!(ok, ScriptVerifyStatus::Ok);

        let invalid_flags: ScriptVerifyStatus =
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION.into();
        assert_eq!(
            invalid_flags,
            ScriptVerifyStatus::ErrorInvalidFlagsCombination
        );

        let spent_required: ScriptVerifyStatus =
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED.into();
        assert_eq!(
            spent_required,
            ScriptVerifyStatus::ErrorSpentOutputsRequired
        );
    }

    #[test]
    fn test_script_verify_status_to_kernel() {
        let ok: btck_ScriptVerifyStatus = ScriptVerifyStatus::Ok.into();
        assert_eq!(ok, BTCK_SCRIPT_VERIFY_STATUS_OK);

        let invalid_flags: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorInvalidFlagsCombination.into();
        assert_eq!(
            invalid_flags,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION
        );

        let spent_required: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorSpentOutputsRequired.into();
        assert_eq!(
            spent_required,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED
        );
    }

    #[test]
    fn test_script_verify_status_round_trip() {
        let statuses = vec![
            ScriptVerifyStatus::Ok,
            ScriptVerifyStatus::ErrorInvalidFlagsCombination,
            ScriptVerifyStatus::ErrorSpentOutputsRequired,
        ];

        for status in statuses {
            let kernel: btck_ScriptVerifyStatus = status.into();
            let back: ScriptVerifyStatus = kernel.into();
            assert_eq!(status, back);
        }
    }

    #[test]
    #[should_panic(expected = "Unknown script verify status")]
    fn test_script_verify_status_invalid_value() {
        let _: ScriptVerifyStatus = 255.into();
    }

    #[test]
    fn test_script_verify_status_traits() {
        let status1 = ScriptVerifyStatus::Ok;
        let status2 = ScriptVerifyStatus::Ok;

        let cloned = status1.clone();
        assert_eq!(cloned, status2);

        let copied = status1;
        assert_eq!(copied, status2);

        assert_eq!(status1, status2);
        assert_ne!(status1, ScriptVerifyStatus::ErrorInvalidFlagsCombination);

        let debug_str = format!("{:?}", status1);
        assert!(debug_str.contains("Ok"));
    }

    #[test]
    fn test_script_verify_error_debug() {
        let errors = vec![
            ScriptVerifyError::TxInputIndex,
            ScriptVerifyError::InvalidFlags,
            ScriptVerifyError::InvalidFlagsCombination,
            ScriptVerifyError::SpentOutputsMismatch,
            ScriptVerifyError::SpentOutputsRequired,
            ScriptVerifyError::Invalid,
        ];

        for err in errors {
            let debug_str = format!("{:?}", err);
            assert!(!debug_str.is_empty());
        }
    }
}
