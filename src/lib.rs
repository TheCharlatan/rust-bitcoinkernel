#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::NulError;
use std::{fmt, panic};

use crate::core::{ScriptPubkeyExt, TransactionExt, TxOutExt};
use ffi::{
    c_helpers, BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID, BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK, BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV, BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    BTCK_BLOCK_VALIDATION_RESULT_MUTATED, BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    BTCK_BLOCK_VALIDATION_RESULT_UNSET, BTCK_CHAIN_TYPE_MAINNET, BTCK_CHAIN_TYPE_REGTEST,
    BTCK_CHAIN_TYPE_SIGNET, BTCK_CHAIN_TYPE_TESTNET, BTCK_CHAIN_TYPE_TESTNET_4,
    BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD, BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX,
    BTCK_SYNCHRONIZATION_STATE_POST_INIT, BTCK_VALIDATION_MODE_INTERNAL_ERROR,
    BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};
use libbitcoinkernel_sys::*;

pub mod core;
pub mod ffi;
pub mod log;
pub mod notifications;
pub mod state;

/// Serializes data using a C callback function pattern.
///
/// Takes a C function that writes data via a callback and returns the
/// serialized bytes as a Vec<u8>.
fn c_serialize<F>(c_function: F) -> Result<Vec<u8>, KernelError>
where
    F: FnOnce(
        unsafe extern "C" fn(*const std::ffi::c_void, usize, *mut std::ffi::c_void) -> i32,
        *mut std::ffi::c_void,
    ) -> i32,
{
    let mut buffer = Vec::new();

    unsafe extern "C" fn write_callback(
        data: *const std::ffi::c_void,
        len: usize,
        user_data: *mut std::ffi::c_void,
    ) -> i32 {
        panic::catch_unwind(|| {
            let buffer = &mut *(user_data as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            buffer.extend_from_slice(slice);
            c_helpers::to_c_result(true)
        })
        .unwrap_or_else(|_| c_helpers::to_c_result(false))
    }

    let result = c_function(
        write_callback,
        &mut buffer as *mut Vec<u8> as *mut std::ffi::c_void,
    );

    if c_helpers::success(result) {
        Ok(buffer)
    } else {
        Err(KernelError::SerializationFailed)
    }
}

/// A collection of errors emitted by this library
#[derive(Debug)]
pub enum KernelError {
    Internal(String),
    CStringCreationFailed(String),
    InvalidOptions(String),
    OutOfBounds,
    ScriptVerify(ScriptVerifyError),
    SerializationFailed,
    InvalidLength { expected: usize, actual: usize },
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg) => write!(f, "Internal error: {}", msg),
            KernelError::CStringCreationFailed(msg) => {
                write!(f, "C string creation failed: {}", msg)
            }
            KernelError::InvalidOptions(msg) => write!(f, "Invalid options: {}", msg),
            KernelError::OutOfBounds => write!(f, "Out of bounds"),
            KernelError::ScriptVerify(err) => write!(f, "Script verification error: {}", err),
            KernelError::SerializationFailed => write!(f, "Serialization failed"),
            KernelError::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for KernelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KernelError::ScriptVerify(err) => Some(err),
            _ => None,
        }
    }
}

pub use crate::core::{
    verify, Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, BlockTreeEntry, Coin,
    CoinRef, ScriptPubkey, ScriptPubkeyRef, ScriptVerifyError, Transaction, TransactionRef,
    TransactionSpentOutputs, TransactionSpentOutputsRef, TxIn, TxInRef, TxOut, TxOutPoint,
    TxOutPointRef, TxOutRef, Txid, TxidRef,
};

pub use crate::log::{disable_logging, Log, LogCategory, LogLevel, Logger};

pub use crate::notifications::{
    BlockCheckedCallback, BlockTipCallback, BlockValidationResult, BlockValidationStateRef,
    FatalErrorCallback, FlushErrorCallback, HeaderTipCallback, NotificationCallbackRegistry,
    ProgressCallback, SynchronizationState, ValidationCallbackRegistry, ValidationMode, Warning,
    WarningSetCallback, WarningUnsetCallback,
};

pub use crate::state::{
    Chain, ChainParams, ChainType, ChainstateManager, ChainstateManagerBuilder, Context,
    ContextBuilder, ProcessBlockResult,
};

pub use crate::core::verify_flags::{
    VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

pub mod prelude {
    pub use crate::core::{
        BlockHashExt, BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt, TransactionExt,
        TransactionSpentOutputsExt, TxInExt, TxOutExt, TxOutPointExt, TxidExt,
    };
    pub use crate::notifications::BlockValidationStateExt;
}
