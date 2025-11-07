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

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Warning::UnknownNewRulesActivated => {
                write!(f, "Unknown new rules activated")
            }
            Warning::LargeWorkInvalidChain => {
                write!(f, "Large work invalid chain")
            }
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

    use crate::ffi::test_utils::test_ref_trait_requirements;

    use super::*;

    test_ref_trait_requirements!(
        test_block_validation_state_ref_requirements,
        BlockValidationStateRef<'static>,
        btck_BlockValidationState
    );

    // SynchronizationState tests
    #[test]
    fn test_synchronization_state_conversions() {
        let init_reindex = SynchronizationState::InitReindex;
        let btck_init_reindex: btck_SynchronizationState = init_reindex.into();
        let back_to_init_reindex: SynchronizationState = btck_init_reindex.into();
        assert_eq!(init_reindex, back_to_init_reindex);

        let init_download = SynchronizationState::InitDownload;
        let btck_init_download: btck_SynchronizationState = init_download.into();
        let back_to_init_download: SynchronizationState = btck_init_download.into();
        assert_eq!(init_download, back_to_init_download);

        let post_init = SynchronizationState::PostInit;
        let btck_post_init: btck_SynchronizationState = post_init.into();
        let back_to_post_init: SynchronizationState = btck_post_init.into();
        assert_eq!(post_init, back_to_post_init);
    }

    #[test]
    fn test_synchronization_state_values() {
        assert_eq!(
            SynchronizationState::InitReindex as u8,
            BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX
        );
        assert_eq!(
            SynchronizationState::InitDownload as u8,
            BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD
        );
        assert_eq!(
            SynchronizationState::PostInit as u8,
            BTCK_SYNCHRONIZATION_STATE_POST_INIT
        );
    }

    #[test]
    fn test_synchronization_state_equality() {
        assert_eq!(
            SynchronizationState::InitReindex,
            SynchronizationState::InitReindex
        );
        assert_ne!(
            SynchronizationState::InitReindex,
            SynchronizationState::InitDownload
        );
        assert_ne!(
            SynchronizationState::InitDownload,
            SynchronizationState::PostInit
        );
    }

    #[test]
    fn test_synchronization_state_clone() {
        let state = SynchronizationState::PostInit;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    // Warning tests
    #[test]
    fn test_warning_conversions() {
        let unknown_rules = Warning::UnknownNewRulesActivated;
        let btck_unknown_rules: btck_Warning = unknown_rules.into();
        let back_to_unknown_rules: Warning = btck_unknown_rules.into();
        assert_eq!(unknown_rules, back_to_unknown_rules);

        let large_work = Warning::LargeWorkInvalidChain;
        let btck_large_work: btck_Warning = large_work.into();
        let back_to_large_work: Warning = btck_large_work.into();
        assert_eq!(large_work, back_to_large_work);
    }

    #[test]
    fn test_warning_values() {
        assert_eq!(
            Warning::UnknownNewRulesActivated as u8,
            BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED
        );
        assert_eq!(
            Warning::LargeWorkInvalidChain as u8,
            BTCK_WARNING_LARGE_WORK_INVALID_CHAIN
        );
    }

    #[test]
    fn test_warning_equality() {
        assert_eq!(
            Warning::UnknownNewRulesActivated,
            Warning::UnknownNewRulesActivated
        );
        assert_ne!(
            Warning::UnknownNewRulesActivated,
            Warning::LargeWorkInvalidChain
        );
    }

    #[test]
    fn test_warning_clone() {
        let warning = Warning::LargeWorkInvalidChain;
        let cloned = warning;
        assert_eq!(warning, cloned);
    }

    // ValidationMode tests
    #[test]
    fn test_validation_mode_conversions() {
        let valid = ValidationMode::Valid;
        let btck_valid: btck_ValidationMode = valid.into();
        let back_to_valid: ValidationMode = btck_valid.into();
        assert_eq!(valid, back_to_valid);

        let invalid = ValidationMode::Invalid;
        let btck_invalid: btck_ValidationMode = invalid.into();
        let back_to_invalid: ValidationMode = btck_invalid.into();
        assert_eq!(invalid, back_to_invalid);

        let internal_error = ValidationMode::InternalError;
        let btck_internal_error: btck_ValidationMode = internal_error.into();
        let back_to_internal_error: ValidationMode = btck_internal_error.into();
        assert_eq!(internal_error, back_to_internal_error);
    }

    #[test]
    fn test_validation_mode_values() {
        assert_eq!(ValidationMode::Valid as u8, BTCK_VALIDATION_MODE_VALID);
        assert_eq!(ValidationMode::Invalid as u8, BTCK_VALIDATION_MODE_INVALID);
        assert_eq!(
            ValidationMode::InternalError as u8,
            BTCK_VALIDATION_MODE_INTERNAL_ERROR
        );
    }

    #[test]
    fn test_validation_mode_equality() {
        assert_eq!(ValidationMode::Valid, ValidationMode::Valid);
        assert_ne!(ValidationMode::Valid, ValidationMode::Invalid);
        assert_ne!(ValidationMode::Invalid, ValidationMode::InternalError);
    }

    #[test]
    fn test_validation_mode_clone() {
        let mode = ValidationMode::Valid;
        let cloned = mode;
        assert_eq!(mode, cloned);
    }

    // BlockValidationResult tests
    #[test]
    fn test_block_validation_result_conversions() {
        let unset = BlockValidationResult::Unset;
        let btck_unset: btck_BlockValidationResult = unset.into();
        let back_to_unset: BlockValidationResult = btck_unset.into();
        assert_eq!(unset, back_to_unset);

        let consensus = BlockValidationResult::Consensus;
        let btck_consensus: btck_BlockValidationResult = consensus.into();
        let back_to_consensus: BlockValidationResult = btck_consensus.into();
        assert_eq!(consensus, back_to_consensus);

        let cached_invalid = BlockValidationResult::CachedInvalid;
        let btck_cached_invalid: btck_BlockValidationResult = cached_invalid.into();
        let back_to_cached_invalid: BlockValidationResult = btck_cached_invalid.into();
        assert_eq!(cached_invalid, back_to_cached_invalid);

        let invalid_header = BlockValidationResult::InvalidHeader;
        let btck_invalid_header: btck_BlockValidationResult = invalid_header.into();
        let back_to_invalid_header: BlockValidationResult = btck_invalid_header.into();
        assert_eq!(invalid_header, back_to_invalid_header);

        let mutated = BlockValidationResult::Mutated;
        let btck_mutated: btck_BlockValidationResult = mutated.into();
        let back_to_mutated: BlockValidationResult = btck_mutated.into();
        assert_eq!(mutated, back_to_mutated);

        let missing_prev = BlockValidationResult::MissingPrev;
        let btck_missing_prev: btck_BlockValidationResult = missing_prev.into();
        let back_to_missing_prev: BlockValidationResult = btck_missing_prev.into();
        assert_eq!(missing_prev, back_to_missing_prev);

        let invalid_prev = BlockValidationResult::InvalidPrev;
        let btck_invalid_prev: btck_BlockValidationResult = invalid_prev.into();
        let back_to_invalid_prev: BlockValidationResult = btck_invalid_prev.into();
        assert_eq!(invalid_prev, back_to_invalid_prev);

        let time_future = BlockValidationResult::TimeFuture;
        let btck_time_future: btck_BlockValidationResult = time_future.into();
        let back_to_time_future: BlockValidationResult = btck_time_future.into();
        assert_eq!(time_future, back_to_time_future);

        let header_low_work = BlockValidationResult::HeaderLowWork;
        let btck_header_low_work: btck_BlockValidationResult = header_low_work.into();
        let back_to_header_low_work: BlockValidationResult = btck_header_low_work.into();
        assert_eq!(header_low_work, back_to_header_low_work);
    }

    #[test]
    fn test_block_validation_result_values() {
        assert_eq!(
            BlockValidationResult::Unset as u32,
            BTCK_BLOCK_VALIDATION_RESULT_UNSET
        );
        assert_eq!(
            BlockValidationResult::Consensus as u32,
            BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS
        );
        assert_eq!(
            BlockValidationResult::CachedInvalid as u32,
            BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID
        );
        assert_eq!(
            BlockValidationResult::InvalidHeader as u32,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER
        );
        assert_eq!(
            BlockValidationResult::Mutated as u32,
            BTCK_BLOCK_VALIDATION_RESULT_MUTATED
        );
        assert_eq!(
            BlockValidationResult::MissingPrev as u32,
            BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV
        );
        assert_eq!(
            BlockValidationResult::InvalidPrev as u32,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV
        );
        assert_eq!(
            BlockValidationResult::TimeFuture as u32,
            BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE
        );
        assert_eq!(
            BlockValidationResult::HeaderLowWork as u32,
            BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK
        );
    }

    #[test]
    fn test_block_validation_result_equality() {
        assert_eq!(
            BlockValidationResult::Consensus,
            BlockValidationResult::Consensus
        );
        assert_ne!(
            BlockValidationResult::Consensus,
            BlockValidationResult::Unset
        );
        assert_ne!(
            BlockValidationResult::InvalidHeader,
            BlockValidationResult::Mutated
        );
    }

    #[test]
    fn test_block_validation_result_clone() {
        let result = BlockValidationResult::Consensus;
        let cloned = result;
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_all_synchronization_states() {
        let states = [
            SynchronizationState::InitReindex,
            SynchronizationState::InitDownload,
            SynchronizationState::PostInit,
        ];

        for state in states {
            let btck_state: btck_SynchronizationState = state.into();
            let back: SynchronizationState = btck_state.into();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn test_all_warnings() {
        let warnings = [
            Warning::UnknownNewRulesActivated,
            Warning::LargeWorkInvalidChain,
        ];

        for warning in warnings {
            let btck_warning: btck_Warning = warning.into();
            let back: Warning = btck_warning.into();
            assert_eq!(warning, back);
        }
    }

    #[test]
    fn test_all_validation_modes() {
        let modes = [
            ValidationMode::Valid,
            ValidationMode::Invalid,
            ValidationMode::InternalError,
        ];

        for mode in modes {
            let btck_mode: btck_ValidationMode = mode.into();
            let back: ValidationMode = btck_mode.into();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn test_all_block_validation_results() {
        let results = [
            BlockValidationResult::Unset,
            BlockValidationResult::Consensus,
            BlockValidationResult::CachedInvalid,
            BlockValidationResult::InvalidHeader,
            BlockValidationResult::Mutated,
            BlockValidationResult::MissingPrev,
            BlockValidationResult::InvalidPrev,
            BlockValidationResult::TimeFuture,
            BlockValidationResult::HeaderLowWork,
        ];

        for result in results {
            let btck_result: btck_BlockValidationResult = result.into();
            let back: BlockValidationResult = btck_result.into();
            assert_eq!(result, back);
        }
    }
}
