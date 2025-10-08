use std::marker::PhantomData;

use libbitcoinkernel_sys::{
    btck_BlockValidationResult, btck_BlockValidationState, btck_SynchronizationState,
    btck_ValidationMode, btck_Warning, btck_block_validation_state_get_block_validation_result,
    btck_block_validation_state_get_validation_mode,
};

use crate::{
    ffi::sealed::{AsPtr, FromPtr},
    BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID, BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK, BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV, BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    BTCK_BLOCK_VALIDATION_RESULT_MUTATED, BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    BTCK_BLOCK_VALIDATION_RESULT_UNSET, BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD,
    BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX, BTCK_SYNCHRONIZATION_STATE_POST_INIT,
    BTCK_VALIDATION_MODE_INTERNAL_ERROR, BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};

/// Current synchronization state of the blockchain.
///
/// Indicates what phase of blockchain synchronization is currently active.
/// Emitted by block tip notifications to track sync progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SynchronizationState {
    /// Currently reindexing the blockchain from disk
    InitReindex = BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX,
    /// Initial block download - syncing from network peers
    InitDownload = BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD,
    /// Synchronization complete - processing new blocks
    PostInit = BTCK_SYNCHRONIZATION_STATE_POST_INIT,
}

impl From<SynchronizationState> for btck_SynchronizationState {
    fn from(state: SynchronizationState) -> Self {
        state as btck_SynchronizationState
    }
}

impl From<btck_SynchronizationState> for SynchronizationState {
    fn from(value: btck_SynchronizationState) -> Self {
        match value {
            BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX => SynchronizationState::InitReindex,
            BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD => SynchronizationState::InitDownload,
            BTCK_SYNCHRONIZATION_STATE_POST_INIT => SynchronizationState::PostInit,
            _ => panic!("Unknown synchronization state: {}", value),
        }
    }
}

/// Warning conditions detected by the kernel during validation.
///
/// These warnings indicate potentially problematic conditions that may
/// require user attention or represent network-wide issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Warning {
    /// Unknown new consensus rules have been activated
    ///
    /// This typically means the software is out of date and doesn't
    /// recognize new consensus rules that have activated on the network.
    UnknownNewRulesActivated = BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,

    /// A chain with significant work contains invalid blocks
    ///
    /// This warning indicates that a substantial amount of computational
    /// work has been expended on a chain that contains invalid blocks.
    LargeWorkInvalidChain = BTCK_WARNING_LARGE_WORK_INVALID_CHAIN,
}

impl From<Warning> for btck_Warning {
    fn from(warning: Warning) -> Self {
        warning as btck_Warning
    }
}

impl From<btck_Warning> for Warning {
    fn from(value: btck_Warning) -> Self {
        match value {
            BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED => Warning::UnknownNewRulesActivated,
            BTCK_WARNING_LARGE_WORK_INVALID_CHAIN => Warning::LargeWorkInvalidChain,
            _ => panic!("Unknown warning: {}", value),
        }
    }
}

/// Result of data structure validation.
///
/// Indicates whether a validated data structure (block, transaction, etc.)
/// is valid, invalid, or encountered an error during processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValidationMode {
    /// The data structure is valid according to consensus rules
    Valid = BTCK_VALIDATION_MODE_VALID,
    /// The data structure is invalid according to consensus rules
    Invalid = BTCK_VALIDATION_MODE_INVALID,
    /// An internal error occurred during validation
    InternalError = BTCK_VALIDATION_MODE_INTERNAL_ERROR,
}

impl From<ValidationMode> for btck_ValidationMode {
    fn from(mode: ValidationMode) -> Self {
        mode as btck_ValidationMode
    }
}

impl From<btck_ValidationMode> for ValidationMode {
    fn from(value: btck_ValidationMode) -> Self {
        match value {
            BTCK_VALIDATION_MODE_VALID => ValidationMode::Valid,
            BTCK_VALIDATION_MODE_INVALID => ValidationMode::Invalid,
            BTCK_VALIDATION_MODE_INTERNAL_ERROR => ValidationMode::InternalError,
            _ => panic!("Unknown validation mode: {}", value),
        }
    }
}

/// Result of block validation.
///
/// Provides information about why a block was accepted or rejected
/// during validation. This gives more specific reasons than just valid/invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BlockValidationResult {
    /// Initial value - block has not yet been validated
    Unset = BTCK_BLOCK_VALIDATION_RESULT_UNSET,
    /// Block is valid according to consensus rules
    Consensus = BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    /// Block was cached as invalid (reason not stored)
    CachedInvalid = BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID,
    /// Block header is invalid (proof of work or timestamp)
    InvalidHeader = BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    /// Block data doesn't match the proof of work commitment
    Mutated = BTCK_BLOCK_VALIDATION_RESULT_MUTATED,
    /// Previous block is not available
    MissingPrev = BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    /// Previous block is invalid
    InvalidPrev = BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV,
    /// Block timestamp is too far in the future
    TimeFuture = BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    /// Block header indicates insufficient work
    HeaderLowWork = BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK,
}

impl From<BlockValidationResult> for btck_BlockValidationResult {
    fn from(result: BlockValidationResult) -> Self {
        result as btck_BlockValidationResult
    }
}

impl From<btck_BlockValidationResult> for BlockValidationResult {
    fn from(value: btck_BlockValidationResult) -> Self {
        match value {
            BTCK_BLOCK_VALIDATION_RESULT_UNSET => BlockValidationResult::Unset,
            BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS => BlockValidationResult::Consensus,
            BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID => BlockValidationResult::CachedInvalid,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER => BlockValidationResult::InvalidHeader,
            BTCK_BLOCK_VALIDATION_RESULT_MUTATED => BlockValidationResult::Mutated,
            BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV => BlockValidationResult::MissingPrev,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV => BlockValidationResult::InvalidPrev,
            BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE => BlockValidationResult::TimeFuture,
            BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK => BlockValidationResult::HeaderLowWork,
            _ => panic!("Unknown block validation result: {}", value),
        }
    }
}

pub trait BlockValidationStateExt: AsPtr<btck_BlockValidationState> {
    fn mode(&self) -> ValidationMode {
        unsafe { btck_block_validation_state_get_validation_mode(self.as_ptr()).into() }
    }

    fn result(&self) -> BlockValidationResult {
        unsafe { btck_block_validation_state_get_block_validation_result(self.as_ptr()).into() }
    }
}

pub struct BlockValidationStateRef<'a> {
    inner: *const btck_BlockValidationState,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for BlockValidationStateRef<'a> {}
unsafe impl<'a> Sync for BlockValidationStateRef<'a> {}

impl<'a> AsPtr<btck_BlockValidationState> for BlockValidationStateRef<'a> {
    fn as_ptr(&self) -> *const btck_BlockValidationState {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockValidationState> for BlockValidationStateRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockValidationState) -> Self {
        BlockValidationStateRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> Copy for BlockValidationStateRef<'a> {}

impl<'a> Clone for BlockValidationStateRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> BlockValidationStateExt for BlockValidationStateRef<'a> {}

#[cfg(test)]
mod tests {
    use libbitcoinkernel_sys::btck_BlockValidationState;

    use crate::{
        ffi::test_utils::test_ref_trait_requirements, notifications::types::BlockValidationStateRef,
    };

    test_ref_trait_requirements!(
        test_block_validation_state_ref_requirements,
        BlockValidationStateRef<'static>,
        btck_BlockValidationState
    );
}
