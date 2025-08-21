use crate::constants::*;

use libbitcoinkernel_sys::*;

/// Logging categories for Bitcoin Kernel messages.
///
/// Controls which types of log messages are emitted by the kernel library.
/// Categories can be combined to enable multiple types of logging simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogCategory {
    /// All logging categories enabled
    All = BTCK_LOG_CATEGORY_ALL,
    /// Benchmark and performance logging
    Bench = BTCK_LOG_CATEGORY_BENCH,
    /// Block storage operations
    BlockStorage = BTCK_LOG_CATEGORY_BLOCKSTORAGE,
    /// Coin database operations
    CoinDb = BTCK_LOG_CATEGORY_COINDB,
    /// LevelDB operations
    LevelDb = BTCK_LOG_CATEGORY_LEVELDB,
    /// Memory pool operations
    Mempool = BTCK_LOG_CATEGORY_MEMPOOL,
    /// Block pruning operations
    Prune = BTCK_LOG_CATEGORY_PRUNE,
    /// Random number generation
    Rand = BTCK_LOG_CATEGORY_RAND,
    /// Block reindexing operations
    Reindex = BTCK_LOG_CATEGORY_REINDEX,
    /// Block and transaction validation
    Validation = BTCK_LOG_CATEGORY_VALIDATION,
    /// Kernel-specific operations
    Kernel = BTCK_LOG_CATEGORY_KERNEL,
}

impl From<LogCategory> for btck_LogCategory {
    fn from(category: LogCategory) -> Self {
        category as btck_LogCategory
    }
}

impl From<btck_LogCategory> for LogCategory {
    fn from(value: btck_LogCategory) -> Self {
        match value {
            BTCK_LOG_CATEGORY_ALL => LogCategory::All,
            BTCK_LOG_CATEGORY_BENCH => LogCategory::Bench,
            BTCK_LOG_CATEGORY_BLOCKSTORAGE => LogCategory::BlockStorage,
            BTCK_LOG_CATEGORY_COINDB => LogCategory::CoinDb,
            BTCK_LOG_CATEGORY_LEVELDB => LogCategory::LevelDb,
            BTCK_LOG_CATEGORY_MEMPOOL => LogCategory::Mempool,
            BTCK_LOG_CATEGORY_PRUNE => LogCategory::Prune,
            BTCK_LOG_CATEGORY_RAND => LogCategory::Rand,
            BTCK_LOG_CATEGORY_REINDEX => LogCategory::Reindex,
            BTCK_LOG_CATEGORY_VALIDATION => LogCategory::Validation,
            BTCK_LOG_CATEGORY_KERNEL => LogCategory::Kernel,
            _ => panic!("Unknown log category: {}", value),
        }
    }
}

/// Logging levels for controlling message verbosity.
///
/// Determines the minimum severity level of messages that will be logged.
/// Higher levels include all messages from lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Detailed trace information for debugging
    Trace = BTCK_LOG_LEVEL_TRACE,
    /// Debug information for development
    Debug = BTCK_LOG_LEVEL_DEBUG,
    /// General informational messages
    Info = BTCK_LOG_LEVEL_INFO,
}

impl From<LogLevel> for btck_LogLevel {
    fn from(level: LogLevel) -> Self {
        level as btck_LogLevel
    }
}

impl From<btck_LogLevel> for LogLevel {
    fn from(value: btck_LogLevel) -> Self {
        match value {
            BTCK_LOG_LEVEL_TRACE => LogLevel::Trace,
            BTCK_LOG_LEVEL_DEBUG => LogLevel::Debug,
            BTCK_LOG_LEVEL_INFO => LogLevel::Info,
            _ => panic!("Unknown log level: {}", value),
        }
    }
}

/// Bitcoin network chain types.
///
/// Specifies which Bitcoin network the kernel should operate on.
/// Each chain type has different consensus rules and network parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChainType {
    /// Bitcoin mainnet - the production network
    Mainnet = BTCK_CHAIN_TYPE_MAINNET,
    /// Bitcoin testnet - the original test network
    Testnet = BTCK_CHAIN_TYPE_TESTNET,
    /// Bitcoin testnet4 - the newer test network
    Testnet4 = BTCK_CHAIN_TYPE_TESTNET_4,
    /// Bitcoin signet - signed test network
    Signet = BTCK_CHAIN_TYPE_SIGNET,
    /// Regression test network for local development
    Regtest = BTCK_CHAIN_TYPE_REGTEST,
}

impl From<ChainType> for btck_ChainType {
    fn from(chain_type: ChainType) -> Self {
        chain_type as btck_ChainType
    }
}

impl From<btck_ChainType> for ChainType {
    fn from(value: btck_ChainType) -> Self {
        match value {
            BTCK_CHAIN_TYPE_MAINNET => ChainType::Mainnet,
            BTCK_CHAIN_TYPE_TESTNET => ChainType::Testnet,
            BTCK_CHAIN_TYPE_TESTNET_4 => ChainType::Testnet4,
            BTCK_CHAIN_TYPE_SIGNET => ChainType::Signet,
            BTCK_CHAIN_TYPE_REGTEST => ChainType::Regtest,
            _ => panic!("Unknown chain type: {}", value),
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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_log_category_from() {
        assert_eq!(
            btck_LogCategory::from(LogCategory::All),
            BTCK_LOG_CATEGORY_ALL
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Bench),
            BTCK_LOG_CATEGORY_BENCH
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::BlockStorage),
            BTCK_LOG_CATEGORY_BLOCKSTORAGE
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::CoinDb),
            BTCK_LOG_CATEGORY_COINDB
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::LevelDb),
            BTCK_LOG_CATEGORY_LEVELDB
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Mempool),
            BTCK_LOG_CATEGORY_MEMPOOL
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Prune),
            BTCK_LOG_CATEGORY_PRUNE
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Rand),
            BTCK_LOG_CATEGORY_RAND
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Reindex),
            BTCK_LOG_CATEGORY_REINDEX
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Validation),
            BTCK_LOG_CATEGORY_VALIDATION
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Kernel),
            BTCK_LOG_CATEGORY_KERNEL
        );
    }

    #[test]
    fn test_log_category_from_reverse() {
        assert_eq!(LogCategory::from(BTCK_LOG_CATEGORY_ALL), LogCategory::All);
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_BENCH),
            LogCategory::Bench
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_BLOCKSTORAGE),
            LogCategory::BlockStorage
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_COINDB),
            LogCategory::CoinDb
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_LEVELDB),
            LogCategory::LevelDb
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_MEMPOOL),
            LogCategory::Mempool
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_PRUNE),
            LogCategory::Prune
        );
        assert_eq!(LogCategory::from(BTCK_LOG_CATEGORY_RAND), LogCategory::Rand);
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_REINDEX),
            LogCategory::Reindex
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_VALIDATION),
            LogCategory::Validation
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_KERNEL),
            LogCategory::Kernel
        );
    }

    #[test]
    fn test_log_level_from() {
        assert_eq!(btck_LogLevel::from(LogLevel::Trace), BTCK_LOG_LEVEL_TRACE);
        assert_eq!(btck_LogLevel::from(LogLevel::Debug), BTCK_LOG_LEVEL_DEBUG);
        assert_eq!(btck_LogLevel::from(LogLevel::Info), BTCK_LOG_LEVEL_INFO);
    }

    #[test]
    fn test_log_level_from_reverse() {
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_TRACE), LogLevel::Trace);
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_DEBUG), LogLevel::Debug);
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_INFO), LogLevel::Info);
    }

    #[test]
    fn test_chain_type_from() {
        assert_eq!(
            btck_ChainType::from(ChainType::Mainnet),
            BTCK_CHAIN_TYPE_MAINNET
        );
        assert_eq!(
            btck_ChainType::from(ChainType::Testnet),
            BTCK_CHAIN_TYPE_TESTNET
        );
        assert_eq!(
            btck_ChainType::from(ChainType::Testnet4),
            BTCK_CHAIN_TYPE_TESTNET_4
        );
        assert_eq!(
            btck_ChainType::from(ChainType::Signet),
            BTCK_CHAIN_TYPE_SIGNET
        );
        assert_eq!(
            btck_ChainType::from(ChainType::Regtest),
            BTCK_CHAIN_TYPE_REGTEST
        );
    }

    #[test]
    fn test_chain_type_from_reverse() {
        assert_eq!(ChainType::from(BTCK_CHAIN_TYPE_MAINNET), ChainType::Mainnet);
        assert_eq!(ChainType::from(BTCK_CHAIN_TYPE_TESTNET), ChainType::Testnet);
        assert_eq!(
            ChainType::from(BTCK_CHAIN_TYPE_TESTNET_4),
            ChainType::Testnet4
        );
        assert_eq!(ChainType::from(BTCK_CHAIN_TYPE_SIGNET), ChainType::Signet);
        assert_eq!(ChainType::from(BTCK_CHAIN_TYPE_REGTEST), ChainType::Regtest);
    }

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
    fn test_script_verify_status_from() {
        assert_eq!(
            btck_ScriptVerifyStatus::from(ScriptVerifyStatus::Ok),
            BTCK_SCRIPT_VERIFY_STATUS_OK
        );
        assert_eq!(
            btck_ScriptVerifyStatus::from(ScriptVerifyStatus::ErrorInvalidFlagsCombination),
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION
        );
        assert_eq!(
            btck_ScriptVerifyStatus::from(ScriptVerifyStatus::ErrorSpentOutputsRequired),
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED
        );
    }

    #[test]
    fn test_script_verify_status_from_reverse() {
        assert_eq!(
            ScriptVerifyStatus::from(BTCK_SCRIPT_VERIFY_STATUS_OK),
            ScriptVerifyStatus::Ok
        );
        assert_eq!(
            ScriptVerifyStatus::from(BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION),
            ScriptVerifyStatus::ErrorInvalidFlagsCombination
        );
        assert_eq!(
            ScriptVerifyStatus::from(BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED),
            ScriptVerifyStatus::ErrorSpentOutputsRequired
        );
    }

    #[test]
    fn test_round_trip_conversions() {
        for &category in &[
            LogCategory::All,
            LogCategory::Bench,
            LogCategory::BlockStorage,
            LogCategory::CoinDb,
            LogCategory::LevelDb,
            LogCategory::Mempool,
            LogCategory::Prune,
            LogCategory::Rand,
            LogCategory::Reindex,
            LogCategory::Validation,
            LogCategory::Kernel,
        ] {
            let raw: btck_LogCategory = category.into();
            let back = LogCategory::from(raw);
            assert_eq!(category, back);
        }

        for &chain_type in &[
            ChainType::Mainnet,
            ChainType::Testnet,
            ChainType::Testnet4,
            ChainType::Signet,
            ChainType::Regtest,
        ] {
            let raw: btck_ChainType = chain_type.into();
            let back = ChainType::from(raw);
            assert_eq!(chain_type, back);
        }

        for &result in &[
            BlockValidationResult::Unset,
            BlockValidationResult::Consensus,
            BlockValidationResult::CachedInvalid,
            BlockValidationResult::InvalidHeader,
            BlockValidationResult::Mutated,
            BlockValidationResult::MissingPrev,
            BlockValidationResult::InvalidPrev,
            BlockValidationResult::TimeFuture,
            BlockValidationResult::HeaderLowWork,
        ] {
            let raw: btck_BlockValidationResult = result.into();
            let back = BlockValidationResult::from(raw);
            assert_eq!(result, back);
        }
    }
}
