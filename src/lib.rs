#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::NulError;
use std::marker::PhantomData;
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
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg)
            | KernelError::CStringCreationFailed(msg)
            | KernelError::InvalidOptions(msg) => write!(f, "{msg}"),
            _ => write!(f, "Error!"),
        }
    }
}

/// Iterator for traversing blocks sequentially from genesis to tip.
pub struct ChainIterator<'a> {
    chain: Chain<'a>,
    current_height: usize,
}

impl<'a> ChainIterator<'a> {
    fn new(chain: Chain<'a>) -> Self {
        Self {
            chain,
            current_height: 0,
        }
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = BlockTreeEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let height = self.current_height;
        self.current_height += 1;
        self.chain.at_height(height)
    }
}

/// Represents a chain instance for querying and traversal.
pub struct Chain<'a> {
    inner: *const btck_Chain,
    marker: PhantomData<&'a ChainstateManager>,
}

impl<'a> Chain<'a> {
    pub unsafe fn from_ptr(ptr: *const btck_Chain) -> Self {
        Chain {
            inner: ptr,
            marker: PhantomData,
        }
    }

    /// Returns the tip (highest block) of the active chain.
    pub fn tip(&self) -> BlockTreeEntry<'a> {
        let ptr = unsafe { btck_chain_get_tip(self.inner) };
        unsafe { BlockTreeEntry::from_ptr(ptr) }
    }

    /// Returns the genesis block (height 0) of the chain.
    pub fn genesis(&self) -> BlockTreeEntry<'a> {
        let ptr = unsafe { btck_chain_get_genesis(self.inner) };
        unsafe { BlockTreeEntry::from_ptr(ptr) }
    }

    /// Returns the block at the specified height, if it exists.
    pub fn at_height(&self, height: usize) -> Option<BlockTreeEntry<'a>> {
        let tip_height = self.height();
        if height > tip_height as usize {
            return None;
        }

        let ptr = unsafe { btck_chain_get_by_height(self.inner, height as i32) };
        if ptr.is_null() {
            return None;
        }

        Some(unsafe { BlockTreeEntry::from_ptr(ptr) })
    }

    /// Checks if the given block entry is part of the active chain.
    pub fn contains(&self, entry: &BlockTreeEntry<'a>) -> bool {
        let result = unsafe { btck_chain_contains(self.inner, entry.as_ptr()) };
        c_helpers::present(result)
    }

    /// Returns an iterator over all blocks from genesis to tip.
    pub fn iter(&self) -> ChainIterator<'a> {
        ChainIterator::new(*self)
    }

    pub fn height(&self) -> i32 {
        self.tip().height()
    }
}

impl<'a> Clone for Chain<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for Chain<'a> {}

pub use crate::core::{
    verify, Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, BlockTreeEntry, Coin,
    CoinRef, ScriptPubkey, ScriptPubkeyRef, ScriptVerifyError, ScriptVerifyStatus, Transaction,
    TransactionRef, TransactionSpentOutputs, TransactionSpentOutputsRef, TxOut, TxOutRef,
};

pub use crate::log::{disable_logging, Log, LogCategory, LogLevel, Logger};

pub use crate::notifications::{
    BlockChecked, BlockTip, BlockValidationResult, FatalError, FlushError, HeaderTip,
    KernelNotificationInterfaceCallbacks, Progress, SynchronizationState,
    ValidationInterfaceCallbacks, ValidationMode, Warning, WarningSet, WarningUnset,
};

pub use crate::state::{
    ChainParams, ChainType, ChainstateManager, ChainstateManagerOptions, Context, ContextBuilder,
};

pub use crate::core::verify_flags::{
    VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

pub mod prelude {
    pub use crate::core::{
        BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt, TransactionExt, TransactionSpentOutputsExt,
        TxOutExt,
    };
}
