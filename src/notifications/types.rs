// Copyright (c) 2023-present The Bitcoin Kernel developers
// Licensed under the MIT License. See LICENSE file in the project root.

use libbitcoinkernel_sys::{
    btck_BlockValidationResult, btck_SynchronizationState, btck_ValidationMode, btck_Warning,
};

use crate::ffi::{
    BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID, BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK, BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV, BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    BTCK_BLOCK_VALIDATION_RESULT_MUTATED, BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    BTCK_BLOCK_VALIDATION_RESULT_UNSET, BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD,
    BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX, BTCK_SYNCHRONIZATION_STATE_POST_INIT,
    BTCK_VALIDATION_MODE_INTERNAL_ERROR, BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synchronization_state_from() {
        assert_eq!(
            btck_SynchronizationState::from(SynchronizationState::InitReindex),
            BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX
        );
        assert_eq!(
            btck_SynchronizationState::from(SynchronizationState::InitDownload),
            BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD
        );
        assert_eq!(
            btck_SynchronizationState::from(SynchronizationState::PostInit),
            BTCK_SYNCHRONIZATION_STATE_POST_INIT
        );
    }

    #[test]
    fn test_synchronization_state_from_reverse() {
        assert_eq!(
            SynchronizationState::from(BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX),
            SynchronizationState::InitReindex
        );
        assert_eq!(
            SynchronizationState::from(BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD),
            SynchronizationState::InitDownload
        );
        assert_eq!(
            SynchronizationState::from(BTCK_SYNCHRONIZATION_STATE_POST_INIT),
            SynchronizationState::PostInit
        );
    }

    #[test]
    fn test_warning_from() {
        assert_eq!(
            btck_Warning::from(Warning::UnknownNewRulesActivated),
            BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED
        );
        assert_eq!(
            btck_Warning::from(Warning::LargeWorkInvalidChain),
            BTCK_WARNING_LARGE_WORK_INVALID_CHAIN
        );
    }

    #[test]
    fn test_warning_from_reverse() {
        assert_eq!(
            Warning::from(BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED),
            Warning::UnknownNewRulesActivated
        );
        assert_eq!(
            Warning::from(BTCK_WARNING_LARGE_WORK_INVALID_CHAIN),
            Warning::LargeWorkInvalidChain
        );
    }

    #[test]
    fn test_validation_mode_from() {
        assert_eq!(
            btck_ValidationMode::from(ValidationMode::Valid),
            BTCK_VALIDATION_MODE_VALID
        );
        assert_eq!(
            btck_ValidationMode::from(ValidationMode::Invalid),
            BTCK_VALIDATION_MODE_INVALID
        );
        assert_eq!(
            btck_ValidationMode::from(ValidationMode::InternalError),
            BTCK_VALIDATION_MODE_INTERNAL_ERROR
        );
    }

    #[test]
    fn test_validation_mode_from_reverse() {
        assert_eq!(
            ValidationMode::from(BTCK_VALIDATION_MODE_VALID),
            ValidationMode::Valid
        );
        assert_eq!(
            ValidationMode::from(BTCK_VALIDATION_MODE_INVALID),
            ValidationMode::Invalid
        );
        assert_eq!(
            ValidationMode::from(BTCK_VALIDATION_MODE_INTERNAL_ERROR),
            ValidationMode::InternalError
        );
    }

    #[test]
    fn test_block_validation_result_from() {
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::Unset),
            BTCK_BLOCK_VALIDATION_RESULT_UNSET
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::Consensus),
            BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::CachedInvalid),
            BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::InvalidHeader),
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::Mutated),
            BTCK_BLOCK_VALIDATION_RESULT_MUTATED
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::MissingPrev),
            BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::InvalidPrev),
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::TimeFuture),
            BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE
        );
        assert_eq!(
            btck_BlockValidationResult::from(BlockValidationResult::HeaderLowWork),
            BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK
        );
    }

    #[test]
    fn test_block_validation_result_from_reverse() {
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_UNSET),
            BlockValidationResult::Unset
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS),
            BlockValidationResult::Consensus
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID),
            BlockValidationResult::CachedInvalid
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER),
            BlockValidationResult::InvalidHeader
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_MUTATED),
            BlockValidationResult::Mutated
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV),
            BlockValidationResult::MissingPrev
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV),
            BlockValidationResult::InvalidPrev
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE),
            BlockValidationResult::TimeFuture
        );
        assert_eq!(
            BlockValidationResult::from(BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK),
            BlockValidationResult::HeaderLowWork
        );
    }

    #[test]
    fn test_block_validation_result_debug() {
        assert_eq!(format!("{:?}", BlockValidationResult::Unset), "Unset");
        assert_eq!(
            format!("{:?}", BlockValidationResult::Consensus),
            "Consensus"
        );
        assert_eq!(
            format!("{:?}", BlockValidationResult::CachedInvalid),
            "CachedInvalid"
        );
        assert_eq!(
            format!("{:?}", BlockValidationResult::InvalidHeader),
            "InvalidHeader"
        );
        assert_eq!(format!("{:?}", BlockValidationResult::Mutated), "Mutated");
        assert_eq!(
            format!("{:?}", BlockValidationResult::MissingPrev),
            "MissingPrev"
        );
        assert_eq!(
            format!("{:?}", BlockValidationResult::InvalidPrev),
            "InvalidPrev"
        );
        assert_eq!(
            format!("{:?}", BlockValidationResult::TimeFuture),
            "TimeFuture"
        );
        assert_eq!(
            format!("{:?}", BlockValidationResult::HeaderLowWork),
            "HeaderLowWork"
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
            BlockValidationResult::InvalidHeader
        );
        assert_ne!(
            BlockValidationResult::Unset,
            BlockValidationResult::Consensus
        );
        assert_ne!(
            BlockValidationResult::MissingPrev,
            BlockValidationResult::InvalidPrev
        );
    }

    #[test]
    fn test_block_validation_result_clone_copy() {
        let original = BlockValidationResult::Consensus;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_block_validation_result_round_trip_conversion() {
        let results = vec![
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
            let raw: btck_BlockValidationResult = result.into();
            let back = BlockValidationResult::from(raw);
            assert_eq!(result, back);
        }
    }

    #[test]
    fn test_block_validation_result_repr_values() {
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
    #[should_panic(expected = "Unknown block validation result")]
    fn test_block_validation_result_from_invalid_value() {
        let _invalid = BlockValidationResult::from(99999);
    }

    #[test]
    fn test_synchronization_state_debug() {
        assert_eq!(
            format!("{:?}", SynchronizationState::InitReindex),
            "InitReindex"
        );
        assert_eq!(
            format!("{:?}", SynchronizationState::InitDownload),
            "InitDownload"
        );
        assert_eq!(format!("{:?}", SynchronizationState::PostInit), "PostInit");
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
    fn test_synchronization_state_clone_copy() {
        let original = SynchronizationState::InitDownload;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_synchronization_state_round_trip_conversion() {
        let states = vec![
            SynchronizationState::InitReindex,
            SynchronizationState::InitDownload,
            SynchronizationState::PostInit,
        ];

        for state in states {
            let raw: btck_SynchronizationState = state.into();
            let back = SynchronizationState::from(raw);
            assert_eq!(state, back);
        }
    }

    #[test]
    fn test_synchronization_state_repr_values() {
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
    #[should_panic(expected = "Unknown synchronization state")]
    fn test_synchronization_state_from_invalid_value() {
        let _invalid = SynchronizationState::from(255);
    }

    #[test]
    fn test_validation_mode_debug() {
        assert_eq!(format!("{:?}", ValidationMode::Valid), "Valid");
        assert_eq!(format!("{:?}", ValidationMode::Invalid), "Invalid");
        assert_eq!(
            format!("{:?}", ValidationMode::InternalError),
            "InternalError"
        );
    }

    #[test]
    fn test_validation_mode_equality() {
        assert_eq!(ValidationMode::Valid, ValidationMode::Valid);
        assert_ne!(ValidationMode::Valid, ValidationMode::Invalid);
        assert_ne!(ValidationMode::Invalid, ValidationMode::InternalError);
    }

    #[test]
    fn test_validation_mode_clone_copy() {
        let original = ValidationMode::Valid;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_validation_mode_round_trip_conversion() {
        let modes = vec![
            ValidationMode::Valid,
            ValidationMode::Invalid,
            ValidationMode::InternalError,
        ];

        for mode in modes {
            let raw: btck_ValidationMode = mode.into();
            let back = ValidationMode::from(raw);
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn test_validation_mode_repr_values() {
        assert_eq!(ValidationMode::Valid as u8, BTCK_VALIDATION_MODE_VALID);
        assert_eq!(ValidationMode::Invalid as u8, BTCK_VALIDATION_MODE_INVALID);
        assert_eq!(
            ValidationMode::InternalError as u8,
            BTCK_VALIDATION_MODE_INTERNAL_ERROR
        );
    }

    #[test]
    #[should_panic(expected = "Unknown validation mode")]
    fn test_validation_mode_from_invalid_value() {
        let _invalid = ValidationMode::from(255);
    }

    #[test]
    fn test_warning_debug() {
        assert_eq!(
            format!("{:?}", Warning::UnknownNewRulesActivated),
            "UnknownNewRulesActivated"
        );
        assert_eq!(
            format!("{:?}", Warning::LargeWorkInvalidChain),
            "LargeWorkInvalidChain"
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
    fn test_warning_clone_copy() {
        let original = Warning::UnknownNewRulesActivated;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_warning_round_trip_conversion() {
        let warnings = vec![
            Warning::UnknownNewRulesActivated,
            Warning::LargeWorkInvalidChain,
        ];

        for warning in warnings {
            let raw: btck_Warning = warning.into();
            let back = Warning::from(raw);
            assert_eq!(warning, back);
        }
    }

    #[test]
    fn test_warning_repr_values() {
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
    #[should_panic(expected = "Unknown warning")]
    fn test_warning_from_invalid_value() {
        let _invalid = Warning::from(255);
    }

    #[test]
    fn test_enum_memory_layout() {
        use std::mem;

        assert_eq!(
            mem::size_of::<BlockValidationResult>(),
            mem::size_of::<u32>()
        );
        assert_eq!(mem::size_of::<SynchronizationState>(), mem::size_of::<u8>());
        assert_eq!(mem::size_of::<ValidationMode>(), mem::size_of::<u8>());
        assert_eq!(mem::size_of::<Warning>(), mem::size_of::<u8>());
    }
}
